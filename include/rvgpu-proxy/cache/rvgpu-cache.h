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

#ifndef RVGPU_CACHE_H
#define RVGPU_CACHE_H

#include <inttypes.h>
#include <stdio.h>
#include <sys/uio.h>

#include <librvgpu/rvgpu-plugin.h>
#include <librvgpu/rvgpu-protocol.h>

#include <rvgpu-proxy/cache/xxhash/xxhash.h>

/*
 * Max number of chunks is a max number of lines (1080p) multiplied by 2
 * (in case 1 line is in 2 backings) + 1 for header + 1 for trailer
 */
#define MAX_CHUNKS_NUM 2162

struct hash_table;

/**
 * @brief Structure with caching related entries
 */
struct cache {
	struct hash_table *hash_table;
	struct rvgpu_backend *backend;
};

/**
 * @brief Struct that contains res and hash, used as input to cache table
 */
struct res_in_data {
	XXH64_hash_t hash;
	int niov;
	struct iovec iov[MAX_CHUNKS_NUM];
};

/**
 * @brief Resource. Used as output from cache table
 */
struct res_data {
	void *data;
	size_t size;
};

/**
 * @brief Convert numeric hash to canonical form
 *
 * @param hash - numeric hash
 *
 * @param canonical_hash - hash in canonical form to be filled
 */
void hash_to_canonical(XXH64_hash_t hash, char *canonical_hash);

/**
 * @brief Convert canonical form of hash to numeric
 *
 * @param canonical_hash - hash in canonical form
 *
 * @param hash - numeric hash ptr to be filled
 */
void canonical_to_hash(const char *canonical_hash, XXH64_hash_t *hash);

/**
 * @brief Init cache related structures and memory
 *
 * @param b - pointer to RVGPU backend
 *
 * @return - initialized cache structure
 */
struct cache *cache_init(struct rvgpu_backend *b);

/**
 * @brief Free cache related memory
 *
 * @param cache - ptr to cache struct
 */
void cache_free(struct cache *cache);

/**
 * @brief Reset cache and hash table
 *
 * @param cache - ptr to cache struct
 */
void cache_reset(struct cache *cache);

/**
 * @brief Add resource to cache hash table
 *
 * @param cache - ptr to cache struct
 * @param res - resource to be added to cache
 */
void cache_add_resource(struct cache *cache, const struct res_in_data *res);

/**
 * @brief Get resource from cache hash table (remove if no users)
 *
 * @param cache - ptr to cache struct
 * @param canonical_hash - hash of the resource to be retrieved
 * @param res - resource struct to be filled
 */
void cache_get_resource(struct cache *cache, const char *canonical_hash,
			struct res_data *res);

/**
 * @brief Resource routine that handles cache requests from rvgpu-renderer
 * @param cache - ptr to cache struct
 * @param req - cache request
 * @param s - scanout which initialized the request
 */
void cache_event(struct cache *cache, struct rvgpu_res_message_header *req,
		 struct rvgpu_scanout *s);

/**
 * @brief Wait for input events from rvgpu-renderer on resource socket
 * @param b - rvgpu plugin for network communication
 * @param revents - events received on poll
 */
int wait_resource_events(struct rvgpu_backend *b, short int *revents);

#endif /* RVGPU_CACHE_H */
