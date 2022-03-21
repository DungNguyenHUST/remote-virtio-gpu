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

#ifndef RVGPU_ZMQ_H
#define RVGPU_ZMQ_H

#include <zmq.h>

#define RVGPU_RENDERER_MIN_ZMQ_RATE 1u
#define RVGPU_RENDERER_MAX_ZMQ_RATE 1000000u
#define RVGPU_RENDERER_DEFAULT_ZMQ_RATE 1000000u

#define RVGPU_RENDERER_MIN_ZMQ_RECOVERY_MS 0u
#define RVGPU_RENDERER_MAX_ZMQ_RECOVERY_MS 10000u
#define RVGPU_RENDERER_DEFAULT_ZMQ_RECOVERY_MS 500u

#define RVGPU_RENDERER_ZMQ_BUFFER_SIZE (1 << 25)
#define RVGPU_RENDERER_ZMQ_HWM 0

struct zmq_state {
	void *ctx;
	void *socket;
};

struct zmq_params {
	struct zmq_state *st;
	char *zmq_addr;
	unsigned int zmq_rate;
	unsigned int zmq_recovery_ms;
};

struct zmq_state *zmq_init_subscriber(char *addr, unsigned int zmq_rate,
				      unsigned int zmq_recovery_ms);

/** Macro to convert POSIX poll events to ZeroMQ events */
#define to_zmq_ev(events)                                                      \
	(((events)&POLLIN ? ZMQ_POLLIN : 0) |                                  \
	 ((events)&POLLOUT ? ZMQ_POLLOUT : 0) |                                \
	 ((events)&POLLERR ? ZMQ_POLLERR : 0))

#endif /* RVGPU_ZMQ_H */
