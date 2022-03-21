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

#ifndef RVGPU_RENDERER_CACHE_H
#define RVGPU_RENDERER_CACHE_H

#include <inttypes.h>
#include <stdio.h>

#define RVGPU_RENDERER_MIN_CACHE_SIZE_MB 64u
#define RVGPU_RENDERER_MAX_CACHE_SIZE_MB 2048u

#include <librvgpu/rvgpu-protocol.h>

#include <rvgpu-proxy/cache/xxhash/xxhash.h>

/*
 * Maximum supported size of resource
 */
#define MAX_RES_SIZE (3840 * 1080 * 4)

struct cache;

/**
 * @brief Resource. Used as output from cache table
 */
struct res_data {
	void *data;
	size_t size;
};

/**
 * @brief Convert numeric hash to canonical form
 * @param hash - numeric hash
 * @param canonical_hash - hash in canonical form to be filled
 */
void hash_to_canonical(XXH64_hash_t hash, char *canonical_hash);

/**
 * @brief Convert canonical form of hash to numeric
 * @param canonical_hash - hash in canonical form
 * @param hash - numeric hash ptr to be filled
 */
void canonical_to_hash(const char *canonical_hash, XXH64_hash_t *hash);

/**
 * @brief Init cache related structures and memory
 * @param cache_size - maximum size of cache on FS in Mb
 * @return - initialized cache structure
 */
struct cache *cache_init(size_t cache_size);

/**
 * @brief Free cache related memory
 * @param cache - ptr to cache struct
 */
void cache_free(struct cache *cache);

/**
 * @brief Add resource to cache hash table
 * @param cache - ptr to cache struct
 * @param hash - hash of resource
 * @param res - resource to be added to cache
 */
void cache_add_resource(struct cache *cache, const char *hash,
			const struct res_data *res);

/**
 * @brief Get resource from cache hash table (remove if no users)
 * @param cache - ptr to cache struct
 * @param canonical_hash - hash of the resource to be retrieved
 * @param res - resource struct to be filled
 */
void cache_get_resource(struct cache *cache, const char *canonical_hash,
			struct res_data *res);

#endif /* RVGPU_RENDERER_CACHE_H */
