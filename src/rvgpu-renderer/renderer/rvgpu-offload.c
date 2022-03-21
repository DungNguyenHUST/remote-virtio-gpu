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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <unistd.h>

#include <rvgpu-generic/rvgpu-sanity.h>
#include <rvgpu-renderer/renderer/rvgpu-egl.h>
#include <rvgpu-renderer/renderer/rvgpu-offload.h>
#include <rvgpu-renderer/virgl/rvgpu-virgl.h>
#include <librvgpu/rvgpu-protocol.h>

struct offload_state {
	uint8_t *buffer[2];
	size_t bufcurlen[2];
	size_t bufpos[2];
	struct timespec prev_force_draw;
	struct timespec latest_time;
	unsigned int time_index;
	int spl_pipe[2];
	bool split_res;
	void *res_buffer;
	struct thread_shared_res *tsr;
};

static int offload_readbuf(struct offload_state *p, int fd, size_t size)
{
	struct pollfd pfd;
	int stream = (fd == 0) ? COMMAND : RESOURCE;

	pfd.fd = fd;
	pfd.events = POLLIN;

	poll(&pfd, 1, -1);

	if (pfd.revents & POLLIN) {
		ssize_t len =
		    splice(fd, NULL, p->spl_pipe[PIPE_WRITE], NULL, size, 0);

		if (len <= 0)
			return 0;

		ssize_t size = tee(p->spl_pipe[PIPE_READ],
				   p->tsr->tee_pipe[PIPE_WRITE], len, 0);
		if (size != len)
			return 0;

		ssize_t n = read(p->spl_pipe[PIPE_READ], p->buffer[stream],
				 RECOVERY_INBUFSIZE);
		if (n <= 0)
			return 0;

		p->bufcurlen[stream] = (size_t)n;
		p->bufpos[stream] = 0u;
	}

	if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
		return 0;

	return 1;
}

static int offload_readbuf_zmq(struct offload_state *p)
{
	zmq_pollitem_t pfd[10];

	pfd[0].socket = p->tsr->zmq->socket;
	pfd[0].events = ZMQ_POLLIN;
	pfd[0].fd = -1;

	zmq_poll(pfd, 1, -1);

	if (pfd[0].revents & ZMQ_POLLIN) {
		ssize_t n = zmq_recv(p->tsr->zmq->socket, p->buffer[COMMAND],
				     RECOVERY_INBUFSIZE, 0);
		if (n <= 0)
			return 0;

		p->bufcurlen[COMMAND] = (size_t)n;
		p->bufpos[COMMAND] = 0u;

		if (!p->split_res) {
			if (write(p->tsr->tee_pipe[PIPE_WRITE],
				  p->buffer[COMMAND], n) < n) {
				warn("short write");
				return 0;
			}
		}
	}

	if (pfd[0].revents & ZMQ_POLLERR)
		return 0;

	return 1;
}

static size_t offload_read(struct offload_state *p, void *buf, size_t size,
			   size_t nmemb, int fd)
{
	size_t offset = 0u;
	size_t total = size * nmemb;
	int stream = (fd == 0) ? COMMAND : RESOURCE;

	while (offset < total) {
		size_t avail = p->bufcurlen[stream] - p->bufpos[stream];
		size_t required = 0;

		if (avail > (total - offset))
			avail = (total - offset);

		if (buf) {
			memcpy((char *)buf + offset,
			       &p->buffer[stream][p->bufpos[stream]], avail);
		}
		if (p->split_res && p->tsr->zmq && stream == COMMAND) {
			if (write(p->tsr->tee_pipe[PIPE_WRITE],
				  &p->buffer[stream][p->bufpos[stream]],
				  avail) < avail) {
				warn("short write");
				break;
			}
		}
		offset += avail;
		p->bufpos[stream] += avail;
		if (offset == total)
			break;

		assert(p->bufpos[stream] == p->bufcurlen[stream]);
		if (p->split_res)
			required = total - offset;
		else
			required = RECOVERY_INBUFSIZE;

		/* actually read from input now */
		if (p->tsr->zmq && stream == COMMAND) {
			if (!offload_readbuf_zmq(p))
				break;
		} else {
			if (!offload_readbuf(p, fd, required))
				break;
		}
	}
	return offset / size;
}

static struct offload_state *offload_init(bool split)
{
	struct offload_state *p = calloc(1, sizeof(*p));

	assert(p);
	p->buffer[COMMAND] = malloc(RECOVERY_INBUFSIZE);
	assert(p->buffer[COMMAND]);

	p->buffer[RESOURCE] = malloc(RECOVERY_INBUFSIZE);
	assert(p->buffer[RESOURCE]);

	if (pipe(p->spl_pipe) == -1)
		err(1, "pipe");

	fcntl(p->spl_pipe[PIPE_WRITE], F_SETPIPE_SZ, RECOVERY_INBUFSIZE);

	if (split) {
		p->res_buffer = malloc(MAX_RES_SIZE);
		assert(p->res_buffer);
	}

	return p;
}

static void offload_free(struct offload_state *p)
{
	close(p->spl_pipe[PIPE_READ]);
	close(p->spl_pipe[PIPE_WRITE]);
	free(p->buffer[COMMAND]);
	free(p->buffer[RESOURCE]);
	if (p->res_buffer)
		free(p->res_buffer);
	free(p);
}

/**
 * @brief Request, or get resource from cache and send it further
 * @param state - pointer to offload state structure
 * @param socket - pointer to socket to be used for further communication
 */
static void handle_cached_resource(struct offload_state *state, int *socket)
{
	struct pollfd pfd;
	struct rvgpu_res_message_header res_req = {.type = RVGPU_RES_REQ};
	struct res_data res;

	if (state->tsr->res_socket == 0)
		err(1, "Hash should not be here");

	if (offload_read(state, (void *)res_req.hash, 1, HASH_SIZE, *socket) !=
	    HASH_SIZE) {
		err(1, "Short read");
	}

	cache_get_resource(state->tsr->cache, res_req.hash, &res);

	if (res.data)
		res_req.type = RVGPU_RES_NOT;
	else
		*socket = state->tsr->res_socket;

	/*
	 * send resource request to rvgpu-proxy with resource hash
	 */
	pfd.fd = state->tsr->res_socket;
	pfd.events = POLLOUT;
	poll(&pfd, 1, -1);

	if (pfd.revents & POLLOUT) {
		if (write(state->tsr->res_socket, &res_req, sizeof(res_req)) !=
		    sizeof(res_req)) {
			err(1, "Short write");
		}
	}

	if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
		err(1, "Resource socket error");

	if (res.data) {
		struct rvgpu_patch hdr, trailer;

		hdr.type = RVGPU_PATCH_RES;
		hdr.len = res.size;
		hdr.offset = 0;
		trailer.len = 0;

		/*
		 * fake header rvgpu_patch
		 */
		if (write(state->tsr->tee_pipe[PIPE_WRITE], &hdr,
			  sizeof(struct rvgpu_patch)) !=
		    sizeof(struct rvgpu_patch)) {
			err(1, "Short write");
		}

		if (write(state->tsr->tee_pipe[PIPE_WRITE], res.data,
			  res.size) != res.size) {
			err(1, "Short write");
		}

		/*
		 * fake trailer rvgpu_patch
		 */
		if (write(state->tsr->tee_pipe[PIPE_WRITE], &trailer,
			  sizeof(struct rvgpu_patch)) !=
		    sizeof(struct rvgpu_patch)) {
			err(1, "Short write");
		}
	}
}

static void offload_load_resource(struct offload_state *state)
{
	struct rvgpu_patch header = {0, 0};
	int socket = 0;
	void *res_buf = NULL;
	struct res_data res;

	while (offload_read(state, &header, sizeof(header), 1, socket) == 1) {
		if (header.len == 0)
			break;

		if (header.type == RVGPU_PATCH_HASH) {
			handle_cached_resource(state, &socket);

			if (socket)
				continue;

			break;
		}

		if (socket)
			res_buf = state->res_buffer;

		if (offload_read(state, res_buf, 1, header.len, socket) !=
		    header.len) {
			err(1, "Short read");
		}
		if (socket) {
			res.data = res_buf;
			res.size = header.len;
			cache_add_resource(state->tsr->cache, NULL, &res);
		}
	}
}

void *offload_thread_func(void *arg)
{
	struct rvgpu_header uhdr;
	struct thread_shared_res *tsr = (struct thread_shared_res *)arg;
	struct offload_state *p = offload_init((bool)tsr->res_socket);

	fcntl(tsr->tee_pipe[PIPE_WRITE], F_SETPIPE_SZ, RECOVERY_INBUFSIZE);

	p->tsr = tsr;
	p->split_res = (bool)tsr->res_socket;

	while (offload_read(p, &uhdr, sizeof(uhdr), 1, 0) == 1) {
		union virtio_gpu_cmd r;
		size_t ret;
		struct rvgpu_trailer tr = {{0, 0}};

		memset(&r.hdr, 0, sizeof(r.hdr));
		if (uhdr.size > sizeof(r))
			errx(1, "$Too long read (%u)", uhdr.size);

		ret = offload_read(p, &r, 1, uhdr.size, 0);
		if (ret != uhdr.size)
			errx(1, "$Too short read(%zu < %u)", ret, uhdr.size);

		switch (r.hdr.type) {
		case VIRTIO_GPU_CMD_CTX_CREATE:
		case VIRTIO_GPU_CMD_CTX_DESTROY:
		case VIRTIO_GPU_CMD_RESOURCE_CREATE_2D:
		case VIRTIO_GPU_CMD_RESOURCE_CREATE_3D:
		case VIRTIO_GPU_CMD_SUBMIT_3D:
		case VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D:
		case VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING:
		case VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING:
		case VIRTIO_GPU_CMD_SET_SCANOUT:
		case VIRTIO_GPU_CMD_RESOURCE_FLUSH:
		case VIRTIO_GPU_CMD_RESOURCE_UNREF:
		case VIRTIO_GPU_CMD_CTX_ATTACH_RESOURCE:
		case VIRTIO_GPU_CMD_CTX_DETACH_RESOURCE:
		case VIRTIO_GPU_CMD_GET_CAPSET:
		case VIRTIO_GPU_CMD_GET_CAPSET_INFO:
		case VIRTIO_GPU_CMD_GET_DISPLAY_INFO:
		case VIRTIO_GPU_CMD_UPDATE_CURSOR:
		case VIRTIO_GPU_CMD_MOVE_CURSOR:
			break;
		case VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D:
			offload_load_resource(p);
			break;
		case VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D: {
			if (r.t_h3d.box.w > 1 && r.t_h3d.box.h > 1) {
				if (p->latest_time.tv_sec ==
					p->prev_force_draw.tv_sec &&
				    p->latest_time.tv_nsec ==
					p->prev_force_draw.tv_nsec) {
					offload_load_resource(p);
					break;
				}

				pthread_mutex_lock(&p->tsr->mtx);
				p->tsr->force_draw_time[p->time_index].tv_sec =
				    p->tsr->latest_time.tv_sec;
				p->tsr->force_draw_time[p->time_index].tv_nsec =
				    p->tsr->latest_time.tv_nsec;
				pthread_mutex_unlock(&p->tsr->mtx);

				p->prev_force_draw.tv_sec =
				    p->latest_time.tv_sec;
				p->prev_force_draw.tv_nsec =
				    p->latest_time.tv_nsec;

				if (++(p->time_index) >= TIMESTAMPS_NUM)
					p->time_index = 0;
			}

			offload_load_resource(p);
			break;
		}
		default:
			warnx("Unknown command %d", r.hdr.type);
			return 0;
		}

		if (uhdr.flags & RVGPU_TRAILER) {
			ret = offload_read(p, &tr, sizeof(tr), 1, 0);
			if (ret != 1) {
				errx(1, "$Too short read(%zu < %zu)", ret,
				     sizeof(tr));
			}
			if (r.hdr.type == VIRTIO_GPU_CMD_RESOURCE_FLUSH) {
				pthread_mutex_lock(&p->tsr->mtx);
				p->tsr->latest_time.tv_sec = tr.virtio_recv.sec;
				p->tsr->latest_time.tv_nsec =
				    tr.virtio_recv.nsec;
				pthread_mutex_unlock(&p->tsr->mtx);

				p->latest_time.tv_sec = tr.virtio_recv.sec;
				p->latest_time.tv_nsec = tr.virtio_recv.nsec;
			}
		}

		if (uhdr.flags & RVGPU_TRAILER_EXT) {
			struct rvgpu_trailer_ext trext;

			ret = offload_read(p, &trext, sizeof(trext), 1, 0);
			if (ret != 1) {
				errx(1, "$Too short read(%zu < %zu)", ret,
				     sizeof(trext));
			}
		}
	}

	offload_free(p);

	/* Close the pipe to exit the MainThread. */
	close(tsr->tee_pipe[PIPE_WRITE]);
}
