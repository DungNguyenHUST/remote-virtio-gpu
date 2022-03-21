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

#ifndef RVGPU_OFFLOAD_H
#define RVGPU_OFFLOAD_H

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>

#include <rvgpu-renderer/cache/rvgpu-renderer-cache.h>
#include <rvgpu-renderer/zmq/rvgpu-zmq.h>

#define RECOVERY_INBUFSIZE (1024u * 1024u * 100u)
#define SKIP_THRESHOLD 16600 // 16.6msec
#define TIMESTAMPS_NUM 4

struct thread_shared_res {
	int tee_pipe[2];
	struct timespec latest_time;
	struct timespec force_draw_time[TIMESTAMPS_NUM];
	pthread_mutex_t mtx;
	struct zmq_state *zmq;
	struct cache *cache;
	int res_socket;
	bool split_resources;
};

void *offload_thread_func(void *arg);

#endif /* RVGPU_OFFLOAD_H */
