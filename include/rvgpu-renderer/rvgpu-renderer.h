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

#ifndef RVGPU_RENDERER_H
#define RVGPU_RENDERER_H

#include <stdbool.h>
#include <stdio.h>

#include <rvgpu-renderer/renderer/rvgpu-egl.h>
#include <rvgpu-renderer/renderer/rvgpu-offload.h>
#include <rvgpu-renderer/zmq/rvgpu-zmq.h>

#define MIN_PORT_NUMBER 1
#define MAX_PORT_NUMBER 65535

#define BACKEND_COLOR 0x00FF0033
#define BACKLOG 5 /* Passed to listen() as max connections */

struct rvgpu_pr_state;
struct rvgpu_scanout_params;

/**
 * @brief Additional params for virtio-gpu protocol handling module
 */
struct rvgpu_pr_params {
	FILE *capset;    /**< file for capset dumping */
	FILE *timestamp; /**< file  for timestamp dumping */
	const struct rvgpu_scanout_params *sp; /**< scanout params */
	size_t nsp;			       /**< number of scanouts */
	bool inprof;			       /**< enable init profiling */
	bool split_resources;		       /**< get resources separately */
	size_t fs_cache_size; /**< max size of cached on FS resources */
};

/**
 * @brief Initialize protocol
 * @param e pointer to initialized egl state
 * @param zmq pointer to zmq state
 * @param params protocol params
 * @param tsr pointer to skip late OpenGL commands state
 * @return initialized protocol state
 */
struct rvgpu_pr_state *rvgpu_pr_init(struct rvgpu_egl_state *e,
				     struct zmq_state *zmq,
				     const struct rvgpu_pr_params *params,
				     struct thread_shared_res *tsr,
				     int res_socket);

/** Dispatch protocol events */
unsigned int rvgpu_pr_dispatch(struct rvgpu_pr_state *p);

/** Free protocol resources */
void rvgpu_pr_free(struct rvgpu_pr_state *p);

/** Initialize GBM frontend */
struct rvgpu_egl_state *rvgpu_gbm_init(const char *device, const char *seat,
				       FILE *events_out);

/** Initialize Wayland frontend */
struct rvgpu_egl_state *rvgpu_wl_init(bool fullscreen, bool translucent,
				      FILE *events_out);

#endif /* RVGPU_RENDERER_H */
