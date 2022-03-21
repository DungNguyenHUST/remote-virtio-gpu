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
#include <err.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/queue.h>

#include <rvgpu-proxy/gpu/rvgpu-gpu-device.h>

#define XXH_INLINE_ALL
#include <rvgpu-proxy/cache/rvgpu-cache.h>

/*
 * Limit memory reserved for cached resources
 */
#define CACHE_MEMORY_LIMIT (32 * 1024 * 1024)

/*
 * Number of entries in hash table.
 * Bigger size --> lower possibility of hash collisions.
 */
#define HASH_TABLE_SIZE 2048

/**
 * @brief Cache hash table entry
 */
struct cache_entry {
	XXH64_hash_t hash;
	size_t user_count;
	struct res_data res;

	LIST_ENTRY(cache_entry) cache_entry_node;
};

/**
 * @brief Cache hash table structure
 */
struct hash_table {
	LIST_HEAD(, cache_entry) cache[HASH_TABLE_SIZE];
	size_t total_size;
	size_t limit;
	size_t host_count;
	XXH64_hash_t res_to_free;
	pthread_mutex_t mtx;
	pthread_cond_t cond;
};

/**
 * @brief Remove pending resource from hash table
 * @param table - ptr to hash table
 */
static void remove_unused_entry(struct hash_table *table)
{
	size_t table_index;
	struct cache_entry *current = NULL, *entry = NULL;

	if (table->res_to_free == 0)
		return;

	table_index = table->res_to_free % HASH_TABLE_SIZE;

	LIST_FOREACH(entry, &table->cache[table_index], cache_entry_node)
	{
		if (entry->hash == table->res_to_free) {
			current = entry;
			break;
		}
	}

	if (current == NULL)
		err(1, "hash mismatch");

	table->total_size -= current->res.size;
	free(current->res.data);
	LIST_REMOVE(current, cache_entry_node);
	free(current);

	table->res_to_free = 0;

	pthread_cond_signal(&table->cond);
}

/**
 * @brief Wait for input events from rvgpu-renderer on resource socket
 * @param b - pointer to RVGPU backend
 * @param revents - events received on poll
 */
int wait_resource_events(struct rvgpu_backend *b, short int *revents)
{
	short int events[b->plugin_v1.ctx.scanout_num];

	memset(revents, 0, sizeof(short int) * b->plugin_v1.ctx.scanout_num);
	memset(events, POLLIN,
	       sizeof(short int) * b->plugin_v1.ctx.scanout_num);

	return b->plugin_v1.ops.rvgpu_ctx_poll(&b->plugin_v1.ctx, RESOURCE, -1,
					       events, revents);
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

struct cache *cache_init(struct rvgpu_backend *b)
{
	struct cache *cache;
	struct hash_table *table;

	cache = malloc(sizeof(*cache));
	assert(cache);

	table = calloc(1, sizeof(*table));
	assert(table);

	for (int i = 0; i < HASH_TABLE_SIZE; i++)
		LIST_INIT(&table->cache[i]);

	if (pthread_cond_init(&table->cond, NULL))
		err(1, "pthread_cond_init");
	if (pthread_mutex_init(&table->mtx, NULL))
		err(1, "pthread_mutex_init");

	table->limit = CACHE_MEMORY_LIMIT;
	table->host_count = b->plugin_v1.ctx.scanout_num;

	cache->hash_table = table;
	cache->backend = b;

	return cache;
}

void cache_free(struct cache *cache)
{
	struct hash_table *table = cache->hash_table;

	cache_reset(cache);

	pthread_cond_destroy(&table->cond);
	pthread_mutex_destroy(&table->mtx);

	free(table);
	free(cache);
}

void cache_reset(struct cache *cache)
{
	struct hash_table *table = cache->hash_table;

	pthread_mutex_lock(&table->mtx);

	for (int i = 0; i < HASH_TABLE_SIZE; i++) {
		while (!LIST_EMPTY(&table->cache[i])) {
			struct cache_entry *current =
			    LIST_FIRST(&table->cache[i]);
			free(current->res.data);
			LIST_REMOVE(current, cache_entry_node);
			free(current);
		}
	}

	table->res_to_free = 0;
	table->total_size = 0;

	pthread_mutex_unlock(&table->mtx);
}

void cache_add_resource(struct cache *cache, const struct res_in_data *res)
{
	size_t offset = 0, res_size = 0;
	struct hash_table *table = cache->hash_table;
	struct cache_entry *current = NULL, *entry = NULL;
	size_t table_index = res->hash % HASH_TABLE_SIZE;

	for (int i = 0; i < res->niov; i++)
		res_size += res->iov[i].iov_len;

	pthread_mutex_lock(&table->mtx);

	if (table->res_to_free == res->hash)
		table->res_to_free = 0;

	LIST_FOREACH(entry, &table->cache[table_index], cache_entry_node)
	{
		if (entry->hash == res->hash) {
			current = entry;
			break;
		}
	}

	if (current) {
		current->user_count += table->host_count;
		/*
		 * in case we already added 1 resource with the same hash,
		 * wait until rvgpu-renderer consumes it
		 */
		while (current->user_count / table->host_count > 1)
			pthread_cond_wait(&table->cond, &table->mtx);

		pthread_mutex_unlock(&table->mtx);
		return;
	}

	current = malloc(sizeof(*current));
	assert(current);

	current->hash = res->hash;
	current->user_count = table->host_count;
	current->res.size = res_size;

	current->res.data = malloc(current->res.size);
	if (current->res.data == NULL)
		err(1, "malloc");

	for (int i = 0; i < res->niov; i++) {
		memcpy(current->res.data + offset, res->iov[i].iov_base,
		       res->iov[i].iov_len);
		offset += res->iov[i].iov_len;
	}

	table->total_size += current->res.size;

	LIST_INSERT_HEAD(&table->cache[table_index], current, cache_entry_node);

	/*
	 * in case resource limit is reached, wait
	 */
	while (table->total_size > table->limit)
		pthread_cond_wait(&table->cond, &table->mtx);

	pthread_mutex_unlock(&table->mtx);
}

void cache_get_resource(struct cache *cache, const char *canonical_hash,
			struct res_data *res)
{
	XXH64_hash_t hash;
	size_t table_index;
	struct cache_entry *current = NULL, *entry = NULL;
	struct hash_table *table = cache->hash_table;

	canonical_to_hash(canonical_hash, &hash);

	table_index = hash % HASH_TABLE_SIZE;

	pthread_mutex_lock(&table->mtx);

	remove_unused_entry(table);

	LIST_FOREACH(entry, &table->cache[table_index], cache_entry_node)
	{
		if (entry->hash == hash) {
			current = entry;
			break;
		}
	}
	if (current == NULL) {
		warnx("hash mismatch %s", canonical_hash);
		if (res) {
			res->data = NULL;
			res->size = 0;
		}

		pthread_mutex_unlock(&table->mtx);
		return;
	}

	if (res) {
		res->data = current->res.data;
		res->size = current->res.size;
	}
	if (--current->user_count == 0)
		table->res_to_free = hash;

	if (current->user_count == table->host_count)
		pthread_cond_signal(&table->cond);

	pthread_mutex_unlock(&table->mtx);
}

void cache_event(struct cache *cache, struct rvgpu_res_message_header *req,
		 struct rvgpu_scanout *s)
{
	if (req->type == RVGPU_RES_REQ) {
		struct res_data res;

		cache_get_resource(cache, req->hash, &res);

		if (res.size == 0)
			return;

		int ret = s->plugin_v1.ops.rvgpu_send(s, RESOURCE, res.data,
						      res.size);

		if (ret != res.size)
			err(1, "Short write");
	} else if (req->type == RVGPU_RES_NOT) {
		cache_get_resource(cache, req->hash, NULL);
	} else {
		err(1, "Protocol mismatch");
	}
}
