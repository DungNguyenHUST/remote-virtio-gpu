/**
 * Copyright (c) 2021  Panasonic Corporation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <time.h>

#define XXH_INLINE_ALL
#include <rvgpu-renderer/cache/rvgpu-renderer-cache.h>

/*
 * Limit RAM memory reserved for cached resources
 */
#define RAM_CACHE_MEMORY_LIMIT (100 * 1024 * 1024)

/*
 * Number of entries in RAM hash table.
 * Bigger size --> lower possibility of hash collisions.
 */
#define RAM_HASH_TABLE_SIZE 2048

/*
 * Number of entries in FS hash table.
 * Bigger size --> lower possibility of hash collisions.
 */
#define FS_HASH_TABLE_SIZE 4096

/*
 * Directory with rvgpu-renderer cache
 */
#define CACHE_DIR "/opt/rvgpu-renderer/cache/"

/**
 * @brief RAM cache hash table entry
 */
struct ram_cache_entry {
	XXH64_hash_t hash;
	struct res_data res;
	uint64_t last_usage;

	LIST_ENTRY(ram_cache_entry) cache_entry_node;
};

/**
 * @brief RAM cache structure
 */
struct ram_cache {
	LIST_HEAD(, ram_cache_entry) table[RAM_HASH_TABLE_SIZE];
	size_t total_size;
	size_t limit;
};

/**
 * @brief FS cache hash table entry
 */
struct fs_cache_entry {
	XXH64_hash_t hash;
	size_t size;
	time_t last_usage;

	LIST_ENTRY(fs_cache_entry) cache_entry_node;
};

/**
 * @brief FS cache structure
 */
struct fs_cache {
	LIST_HEAD(, fs_cache_entry) table[FS_HASH_TABLE_SIZE];
	size_t total_size;
	size_t limit;
};

/**
 * @brief Cache hash table structure
 */
struct cache {
	struct ram_cache ram_cache;
	struct fs_cache fs_cache;
	XXH64_hash_t hash_to_add;
};

/**
 * @brief Get current timestamp
 * @return uint64_t timestamp value in microseconds
 */
static uint64_t get_timestamp(void)
{
	struct timespec time;
	uint64_t timestamp;

	clock_gettime(CLOCK_REALTIME, &time);
	timestamp = time.tv_sec * 1e6 + time.tv_nsec / 1e3;

	return timestamp;
}

/**
 * @brief Get file size
 * @param filename - full path to file
 * @return size_t - file size
 */
static size_t get_file_size(char *filename)
{
	struct stat st;

	return (stat(filename, &st) == 0) ? st.st_size : 0;
}

/**
 * @brief Recursively create directories
 */
static void create_cache_dir(void)
{
	size_t path_len = strlen(CACHE_DIR) + 1;
	char dir[path_len];

	memcpy(dir, CACHE_DIR, path_len);

	for (char *p = strchr(dir + 1, '/'); p; p = strchr(p + 1, '/')) {
		*p = '\0';
		if (mkdir(dir, 0755) == -1) {
			if (errno != EEXIST)
				err(1, "mkdir");
		}
		*p = '/';
	}
}

/**
 * @brief Write resource to file
 * @param hash - hash of resource
 * @param res - resource to be dumped into memory
 */
static void add_res_file(XXH64_hash_t hash, const struct res_data *res,
			 time_t *timestamp)
{
	const size_t file_path_size = strlen(CACHE_DIR) + HASH_SIZE;
	char path[file_path_size];
	char canonical_hash[HASH_SIZE];
	FILE *file = NULL;
	size_t dir_path_size = strlen(CACHE_DIR);
	struct stat st;

	hash_to_canonical(hash, canonical_hash);

	memcpy(path, CACHE_DIR, dir_path_size);
	memcpy(path + dir_path_size, canonical_hash, HASH_SIZE);

	file = fopen(path, "wb");

	if (file == NULL) {
		warnx("failed to open file %s", path);
		return;
	}

	if (fwrite(res->data, 1, res->size, file) != res->size) {
		warnx("failed to write resource %s", path);
		fclose(file);
		remove(path);
		return;
	}

	fclose(file);

	if (stat(path, &st) != 0)
		errx(1, "file doesn't exist %s", path);

	*timestamp = st.st_atime;
}

/**
 * @brief Remove resource file
 * @param hash - hash of resource
 */
static void remove_res_file(XXH64_hash_t hash)
{
	char path[strlen(CACHE_DIR) + HASH_SIZE];
	char canonical_hash[HASH_SIZE];
	size_t dir_path_size = strlen(CACHE_DIR);

	hash_to_canonical(hash, canonical_hash);

	memcpy(path, CACHE_DIR, dir_path_size);
	memcpy(path + dir_path_size, canonical_hash, HASH_SIZE);

	remove(path);
}

/**
 * @brief Remove oldest resource from RAM
 * @param cache - ptr to RAM cache structure
 */
static void remove_oldest_resource_on_ram(struct ram_cache *cache)
{
	uint64_t timestamp = -1;
	struct ram_cache_entry *current = NULL, *to_remove = NULL;

	for (int i = 0; i < RAM_HASH_TABLE_SIZE; i++) {
		LIST_FOREACH(current, &cache->table[i], cache_entry_node)
		{
			if (current->last_usage < timestamp) {
				timestamp = current->last_usage;
				to_remove = current;
			}
		}
	}

	if (to_remove == NULL)
		err(1, "hash mismatch on oldest resourse removal");

	cache->total_size -= to_remove->res.size;

	free(to_remove->res.data);
	LIST_REMOVE(to_remove, cache_entry_node);
	free(to_remove);
}

/**
 * @brief Remove oldest resource from FS
 * @param cache - ptr to FS cache structure
 */
static void remove_oldest_resource_on_fs(struct fs_cache *cache)
{
	time_t timestamp = 0;
	struct fs_cache_entry *current = NULL, *to_remove = NULL;

	for (int i = 0; i < FS_HASH_TABLE_SIZE; i++) {
		LIST_FOREACH(current, &cache->table[i], cache_entry_node)
		{
			if (!timestamp) {
				timestamp = current->last_usage;
				to_remove = current;
			}
			if (current->last_usage < timestamp) {
				timestamp = current->last_usage;
				to_remove = current;
			}
		}
	}

	if (to_remove == NULL)
		err(1, "hash mismatch on oldest resourse removal");

	remove_res_file(to_remove->hash);
	cache->total_size -= to_remove->size;

	LIST_REMOVE(to_remove, cache_entry_node);
	free(to_remove);
}

/**
 * @brief Read cache from fs and load it to RAM
 * @param cache - ptr to cache structure
 */
static void load_fs_cache(struct fs_cache *cache)
{
	struct dirent *dp;
	char file_path[strlen(CACHE_DIR) + HASH_SIZE];
	struct stat st;
	size_t table_index;

	DIR *dir = opendir(CACHE_DIR);

	if (!dir)
		err(1, "open cache dir");

	memcpy(file_path, CACHE_DIR, strlen(CACHE_DIR));

	while ((dp = readdir(dir)) != NULL) {
		struct fs_cache_entry *current = NULL, *entry = NULL;

		if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
			continue;

		memcpy(file_path + strlen(CACHE_DIR), dp->d_name, HASH_SIZE);

		if (stat(file_path, &st) != 0)
			errx(1, "no such file %s", file_path);

		if (st.st_size == 0 || st.st_size > MAX_RES_SIZE) {
			warnx("corrupted resource file %s, size %ld", file_path,
			      st.st_size);
			remove(file_path);
			continue;
		}

		current = malloc(sizeof(struct fs_cache_entry));
		assert(current);

		canonical_to_hash(dp->d_name, &current->hash);
		current->size = st.st_size;
		cache->total_size += current->size;
		current->last_usage = st.st_atime;

		table_index = current->hash % FS_HASH_TABLE_SIZE;

		LIST_INSERT_HEAD(&cache->table[table_index], current,
				 cache_entry_node);
	}
	closedir(dir);
}

/**
 * @brief Add resource to RAM
 * @param cache - ptr to ram cache structure
 * @param hash - hash of the resource
 * @param res - res that will be added
 * @param own_memory - own resource memory, or allocate new memory for it
 * @return true if resurce added, false if resource already in cache
 */
static bool ram_add_resource(struct ram_cache *cache, XXH64_hash_t hash,
			     const struct res_data *res, bool own_memory)
{
	struct ram_cache_entry *current = NULL, *entry = NULL;
	size_t table_index;

	table_index = hash % RAM_HASH_TABLE_SIZE;

	LIST_FOREACH(entry, &cache->table[table_index], cache_entry_node)
	{
		if (entry->hash == hash) {
			current = entry;
			break;
		}
	}

	if (current)
		return false;

	while (cache->total_size + res->size > cache->limit)
		remove_oldest_resource_on_ram(cache);

	current = malloc(sizeof(struct ram_cache_entry));
	assert(current);

	current->hash = hash;
	current->res.size = res->size;
	current->last_usage = get_timestamp();

	if (own_memory) {
		current->res.data = res->data;
	} else {
		current->res.data = malloc(current->res.size);
		if (current->res.data == NULL)
			err(1, "malloc");

		memcpy(current->res.data, res->data, res->size);
	}

	cache->total_size += current->res.size;

	LIST_INSERT_HEAD(&cache->table[table_index], current, cache_entry_node);

	return true;
}

/**
 * @brief Add resource to FS
 * @param cache - ptr to FS cache structure
 * @param hash - hash of the resource
 * @param res - res that will be added
 */
static void fs_add_resource(struct fs_cache *cache, XXH64_hash_t hash,
			    const struct res_data *res)
{
	struct fs_cache_entry *current = NULL, *entry = NULL;
	size_t table_index;

	table_index = hash % FS_HASH_TABLE_SIZE;

	if (res->size == 0 || res->size > MAX_RES_SIZE) {
		warnx("bad file size %ld", res->size);
		return;
	}

	LIST_FOREACH(entry, &cache->table[table_index], cache_entry_node)
	{
		if (entry->hash == hash) {
			current = entry;
			break;
		}
	}

	if (current)
		return;

	while (cache->total_size + res->size > cache->limit)
		remove_oldest_resource_on_fs(cache);

	current = malloc(sizeof(struct fs_cache_entry));
	assert(current);

	current->hash = hash;
	current->size = res->size;
	cache->total_size += current->size;

	add_res_file(hash, res, &current->last_usage);

	LIST_INSERT_HEAD(&cache->table[table_index], current, cache_entry_node);
}

/**
 * @brief Get resource from RAM
 * @param cache - ptr to ram cache structure
 * @param hash - hash of the resource
 * @param res - res stucture to be filled
 */
static void ram_get_resource(struct ram_cache *cache, XXH64_hash_t hash,
			     struct res_data *res)
{
	size_t table_index;
	struct ram_cache_entry *current = NULL, *entry = NULL;

	table_index = hash % RAM_HASH_TABLE_SIZE;

	LIST_FOREACH(entry, &cache->table[table_index], cache_entry_node)
	{
		if (entry->hash == hash) {
			current = entry;
			break;
		}
	}
	if (current == NULL) {
		res->data = NULL;
		res->size = 0;
		return;
	}

	res->data = current->res.data;
	res->size = current->res.size;
	current->last_usage = get_timestamp();
}

/**
 * @brief Get resource from FS
 * @param cache - ptr to fs cache structure
 * @param hash - hash of the resource
 * @param res - res stucture to be filled
 */
static void fs_get_resource(struct fs_cache *cache, XXH64_hash_t hash,
			    struct res_data *res)
{
	struct fs_cache_entry *current = NULL, *entry = NULL;
	char file_path[strlen(CACHE_DIR) + HASH_SIZE];
	FILE *file = NULL;
	struct stat st;
	size_t table_index;

	table_index = hash % FS_HASH_TABLE_SIZE;

	LIST_FOREACH(entry, &cache->table[table_index], cache_entry_node)
	{
		if (entry->hash == hash) {
			current = entry;
			break;
		}
	}
	if (current == NULL) {
		res->data = NULL;
		res->size = 0;
		return;
	}

	res->size = current->size;
	res->data = malloc(res->size);
	assert(res->data);

	memcpy(file_path, CACHE_DIR, strlen(CACHE_DIR));
	hash_to_canonical(hash, file_path + strlen(CACHE_DIR));

	file = fopen(file_path, "rb");

	if (file == NULL) {
		warnx("failed to open file %s", file_path);
		remove(file_path);
		LIST_REMOVE(current, cache_entry_node);
		free(current);
		res->data = NULL;
		return;
	}

	if (fread(res->data, 1, res->size, file) != res->size) {
		warnx("failed to read file %s", file_path);
		fclose(file);
		remove(file_path);
		LIST_REMOVE(current, cache_entry_node);
		free(current);
		res->data = NULL;
		return;
	}

	fclose(file);

	if (stat(file_path, &st) != 0)
		errx(1, "file doesn't exist %s", file_path);

	current->last_usage = st.st_atime;
}

void hash_to_canonical(XXH64_hash_t hash, char *canonical_hash)
{
	XXH64_canonical_t hcbe64;

	XXH64_canonicalFromHash(&hcbe64, hash);
	const unsigned char *const p = (const unsigned char *)&hcbe64;

	for (int idx = 0; idx < 8; idx++)
		snprintf(&canonical_hash[2 * idx], 3, "%02x", p[idx]);

	canonical_hash[HASH_SIZE - 1] = '\0';
}

void canonical_to_hash(const char *canonical_hash, XXH64_hash_t *hash)
{
	XXH64_canonical_t canonical;
	char str1[2] = {0}, str2[2] = {0};

	for (int i = 0; i < 8; i++) {
		str1[0] = canonical_hash[2 * i];
		str2[0] = canonical_hash[2 * i + 1];
		canonical.digest[i] =
		    (strtol(str1, NULL, 16) << 4) | strtol(str2, NULL, 16);
	}

	*hash = XXH64_hashFromCanonical(&canonical);
}

struct cache *cache_init(size_t cache_size)
{
	struct cache *cache = calloc(1, sizeof(*cache));
	struct stat st;

	assert(cache);
	for (int i = 0; i < RAM_HASH_TABLE_SIZE; i++)
		LIST_INIT(&cache->ram_cache.table[i]);

	for (int i = 0; i < FS_HASH_TABLE_SIZE; i++)
		LIST_INIT(&cache->fs_cache.table[i]);

	cache->ram_cache.limit = RAM_CACHE_MEMORY_LIMIT;
	cache->fs_cache.limit = cache_size * 1024 * 1024;

	if ((stat(CACHE_DIR, &st) == 0))
		load_fs_cache(&cache->fs_cache);
	else
		create_cache_dir();

	return cache;
}

void cache_free(struct cache *cache)
{
	for (int i = 0; i < RAM_HASH_TABLE_SIZE; i++) {
		while (!LIST_EMPTY(&cache->ram_cache.table[i])) {
			struct ram_cache_entry *current =
			    LIST_FIRST(&cache->ram_cache.table[i]);
			free(current->res.data);
			LIST_REMOVE(current, cache_entry_node);
			free(current);
		}
	}

	for (int i = 0; i < FS_HASH_TABLE_SIZE; i++) {
		while (!LIST_EMPTY(&cache->fs_cache.table[i])) {
			struct fs_cache_entry *current =
			    LIST_FIRST(&cache->fs_cache.table[i]);
			LIST_REMOVE(current, cache_entry_node);
			free(current);
		}
	}

	free(cache);
}

void cache_add_resource(struct cache *cache, const char *canonical_hash,
			const struct res_data *res)
{
	XXH64_hash_t hash;

	if (canonical_hash == NULL)
		hash = cache->hash_to_add;
	else
		canonical_to_hash(canonical_hash, &hash);

	if (ram_add_resource(&cache->ram_cache, hash, res, false))
		fs_add_resource(&cache->fs_cache, hash, res);
}

void cache_get_resource(struct cache *cache, const char *canonical_hash,
			struct res_data *res)
{
	XXH64_hash_t hash;

	canonical_to_hash(canonical_hash, &hash);

	ram_get_resource(&cache->ram_cache, hash, res);

	if (res->data)
		return;

	fs_get_resource(&cache->fs_cache, hash, res);

	if (res->data == NULL)
		cache->hash_to_add = hash;
	else
		ram_add_resource(&cache->ram_cache, hash, res, true);
}
