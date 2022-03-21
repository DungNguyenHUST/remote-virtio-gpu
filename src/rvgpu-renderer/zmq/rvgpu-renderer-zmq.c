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
#include <fcntl.h>
#include <pgm/messages.h>
#include <pgm/pgm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <unistd.h>
#include <zmq.h>

#include <rvgpu-generic/rvgpu-utils.h>
#include <rvgpu-renderer/zmq/rvgpu-zmq.h>

void log_handler(const int log_level, const char *message, void *closure)
{
	(void)log_level;
	(void)closure;

	info("rvgpu-rendere zmq: %s\n", message);
}

struct zmq_state *zmq_init_subscriber(char *addr, unsigned int zmq_rate,
				      unsigned int zmq_recovery_ms)
{
	struct zmq_state *zmq = calloc(1, sizeof(*zmq));

	assert(zmq);
	const int buf_size = RVGPU_RENDERER_ZMQ_BUFFER_SIZE;
	const int hwm = RVGPU_RENDERER_ZMQ_HWM;

	if (!zmq_has("pgm"))
		errx(1, "libzmq seems to be compiled without PGM support");

	pgm_log_set_handler(log_handler, NULL);

	zmq->ctx = zmq_ctx_new();
	if (!zmq->ctx)
		err(1, "zmq_ctx_new error: %s", zmq_strerror(errno));

	zmq->socket = zmq_socket(zmq->ctx, ZMQ_SUB);
	if (!zmq->socket)
		err(1, "zmq_socket error: %s", zmq_strerror(errno));

	if (zmq_setsockopt(zmq->socket, ZMQ_SNDBUF, &buf_size,
			   sizeof(buf_size))) {
		err(1, "can't set ZMQ_SNDBUF option: %s", zmq_strerror(errno));
	}

	if (zmq_setsockopt(zmq->socket, ZMQ_RCVBUF, &buf_size,
			   sizeof(buf_size))) {
		err(1, "can't set ZMQ_SNDBUF option: %s", zmq_strerror(errno));
	}

	if (zmq_setsockopt(zmq->socket, ZMQ_RATE, &zmq_rate,
			   sizeof(zmq_rate))) {
		err(1, "can't set ZMQ_RATE option: %s", zmq_strerror(errno));
	}

	if (zmq_setsockopt(zmq->socket, ZMQ_RCVHWM, &hwm, sizeof(hwm)))
		err(1, "can't set ZMQ_RCVHWM option: %s", zmq_strerror(errno));

	if (zmq_setsockopt(zmq->socket, ZMQ_SUBSCRIBE, NULL, 0)) {
		err(1, "can't set ZMQ_SUBSCRIBE option: %s",
		    zmq_strerror(errno));
	}

	if (zmq_setsockopt(zmq->socket, ZMQ_RECOVERY_IVL, &zmq_recovery_ms,
			   sizeof(zmq_recovery_ms))) {
		err(1, "can't set ZMQ_RECOVERY_IVL option: %s",
		    zmq_strerror(errno));
	}

	if (zmq_connect(zmq->socket, addr))
		err(1, "zmq_connect error: %s", zmq_strerror(errno));

	return zmq;
}
