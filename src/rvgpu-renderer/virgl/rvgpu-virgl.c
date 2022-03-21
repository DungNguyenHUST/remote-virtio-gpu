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
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/virtio_gpu.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>
#include <virglrenderer.h>
#include <zlib.h>
#include <zmq.h>

#include <rvgpu-generic/rvgpu-capset.h>
#include <rvgpu-generic/rvgpu-sanity.h>
#include <rvgpu-generic/rvgpu-utils.h>
#include <rvgpu-renderer/cache/rvgpu-renderer-cache.h>
#include <rvgpu-renderer/renderer/rvgpu-egl.h>
#include <rvgpu-renderer/renderer/rvgpu-offload.h>
#include <rvgpu-renderer/rvgpu-renderer.h>
#include <rvgpu-renderer/virgl/rvgpu-virgl.h>

enum init_profile_state {
	INPROF_NONE,
	INPROF_WAIT_CTX_CREATE,
	INPROF_SAVE_CTX_TIMESTAMP,
	INPROF_WAIT_RESOURCE_FLUSH,
	INPROF_CALCULATE,
};

struct rvgpu_pr_state {
	struct rvgpu_egl_state *egl;
	struct zmq_state *zmq;
	struct rvgpu_pr_params pp;
	uint8_t *buffer[2];
	size_t buftotlen[2];
	size_t bufcurlen[2];
	size_t bufpos[2];
	z_stream strm;
	enum init_profile_state inprof;
	struct rvgpu_ts inprof_ctxtime;
	size_t inprof_read;
	int res_socket;
	bool split_resources;
	struct cache *cache;
	struct thread_shared_res *tsr;
	atomic_uint fence_received, fence_sent;
};

static bool _gl_skip;

static void clear_scanout(struct rvgpu_pr_state *p, struct rvgpu_scanout *s);

static void get_rvgpu_scanout_box(void *box) { rvgpu_egl_get_scanout_box(box); }

static virgl_renderer_gl_context
create_context(void *opaque, int scanout_idx,
	       struct virgl_renderer_gl_ctx_param *params)
{
	(void)scanout_idx;
	struct rvgpu_pr_state *state = (struct rvgpu_pr_state *)opaque;

	return (virgl_renderer_gl_context)rvgpu_egl_create_context(
	    state->egl, params->major_ver, params->minor_ver, params->shared);
}

static void destroy_context(void *opaque, virgl_renderer_gl_context ctx)
{
	struct rvgpu_pr_state *state = (struct rvgpu_pr_state *)opaque;

	rvgpu_egl_destroy_context(state->egl, ctx);
}

static int make_context_current(void *opaque, int scanout_id,
				virgl_renderer_gl_context ctx)
{
	(void)scanout_id;
	struct rvgpu_pr_state *state = (struct rvgpu_pr_state *)opaque;

	return rvgpu_egl_make_context_current(state->egl, ctx);
}

void set_gl_skip(bool set) { _gl_skip = set; }

static bool get_gl_skip(void) { return _gl_skip; }

static void set_swap_skip(bool set) { rvgpu_egl_set_swap_skip(set); }

static void virgl_write_fence(void *opaque, uint32_t fence)
{
	struct rvgpu_pr_state *state = (struct rvgpu_pr_state *)opaque;
	struct rvgpu_res_message_header msg = {.type = RVGPU_FENCE,
					       .fence_id = fence};

	if (fence > state->fence_sent)
		state->fence_sent = fence;

	int res = write(state->res_socket, &msg,
			sizeof(struct rvgpu_res_message_header));
	if (res != sizeof(struct rvgpu_res_message_header))
		errx(1, "Short write");
}

static struct virgl_renderer_callbacks virgl_cbs = {
	.version = 1,
	.write_fence = virgl_write_fence,
	.create_gl_context = create_context,
	.destroy_gl_context = destroy_context,
	.make_current = make_context_current,
#ifdef SKIP_OPENGL_CMDS
	.get_gl_skip = get_gl_skip,
	.set_swap_skip = set_swap_skip,
	.get_rvdds_scanout_box = get_rvgpu_scanout_box,
#endif
};

static int rvgpu_pr_readbuf(struct rvgpu_pr_state *p, int stream)
{
	struct pollfd pfd[MAX_PFD];
	size_t n;
	int timeout = 0;
	struct timespec barrier_delay = {.tv_nsec = 1000};

	if (p->tsr)
		pfd[0].fd = p->tsr->tee_pipe[PIPE_READ];
	else if (stream == RESOURCE)
		pfd[0].fd = p->res_socket;
	else
		pfd[0].fd = 0;

	pfd[0].events = POLLIN;
	n = rvgpu_egl_prepare_events(p->egl, &pfd[1], false, MAX_PFD - 1);
	if (p->fence_received == p->fence_sent)
		timeout = -1;

	while (poll(pfd, n + 1, timeout) == 0 &&
	       (p->fence_received != p->fence_sent)) {
		virgl_renderer_poll();
		clock_nanosleep(CLOCK_MONOTONIC, 0, &barrier_delay, NULL);

		if (p->fence_received == p->fence_sent)
			timeout = -1;
	}
	rvgpu_egl_process_events(p->egl, &pfd[1], false, n);
	if (pfd[0].revents & POLLIN) {
		ssize_t n;

		n = read(pfd[0].fd, p->buffer[stream], p->buftotlen[stream]);
		if (n <= 0)
			return 0;

		p->bufcurlen[stream] = (size_t)n;
		p->bufpos[stream] = 0u;
	}
	for (size_t i = 0; i <= n; i++) {
		if (pfd[i].revents & (POLLERR | POLLHUP | POLLNVAL))
			return 0;
	}
	return 1;
}

static int rvgpu_pr_readbuf_zmq(struct rvgpu_pr_state *p)
{
	zmq_pollitem_t pfd[MAX_PFD];
	size_t n;

	pfd[0].socket = p->zmq->socket;
	pfd[0].events = ZMQ_POLLIN;
	pfd[0].fd = -1;

	n = rvgpu_egl_prepare_events(p->egl, &pfd[1], true, MAX_PFD - 1);
	zmq_poll(pfd, n + 1, -1);
	rvgpu_egl_process_events(p->egl, &pfd[1], true, n);

	if (pfd[0].revents & ZMQ_POLLIN) {
		ssize_t n = zmq_recv(p->zmq->socket, p->buffer[COMMAND],
				     p->buftotlen[COMMAND], 0);
		if (n <= 0)
			return 0;

		p->bufcurlen[COMMAND] = (size_t)n;
		p->bufpos[COMMAND] = 0u;
	}

	for (size_t i = 0; i <= n; i++) {
		if (pfd[i].revents & ZMQ_POLLERR)
			return 0;
	}

	return 1;
}

static size_t rvgpu_pr_read(struct rvgpu_pr_state *p, void *buf, size_t size,
			    size_t nmemb, int stream)
{
	size_t offset = 0u;
	size_t total = size * nmemb;

	if (!p->split_resources)
		stream = COMMAND;

	while (offset < total) {
		size_t avail = p->bufcurlen[stream] - p->bufpos[stream];

		if (avail > (total - offset))
			avail = (total - offset);

		if (buf) {
			memcpy((char *)buf + offset,
			       &p->buffer[stream][p->bufpos[stream]], avail);
		}
		offset += avail;
		p->bufpos[stream] += avail;
		if (offset == total)
			break;

		assert(p->bufpos[stream] == p->bufcurlen[stream]);
		/* actually read from input now */
		if (p->zmq && !(p->tsr) && (stream == COMMAND)) {
			if (!rvgpu_pr_readbuf_zmq(p))
				break;
		} else {
			if (!rvgpu_pr_readbuf(p, stream))
				break;
		}
	}

	if (p->inprof != INPROF_NONE)
		p->inprof_read += total;

	return offset / size;
}

struct rvgpu_pr_state *rvgpu_pr_init(struct rvgpu_egl_state *e,
				     struct zmq_state *zmq,
				     const struct rvgpu_pr_params *params,
				     struct thread_shared_res *tsr,
				     int res_socket)
{
	int ret, buf_size;
	struct rvgpu_pr_state *p = calloc(1, sizeof(*p));

	assert(p);
	buf_size = (tsr) ? RECOVERY_INBUFSIZE : INBUFSIZE;

	p->pp = *params;
	p->egl = e;

	ret = virgl_renderer_init(p, 0, &virgl_cbs);
	assert(ret == 0);

	ret = fcntl(0, F_GETFL);
	if (ret != -1)
		fcntl(0, F_SETFL, ret | O_NONBLOCK);

	p->buffer[COMMAND] = malloc(buf_size);
	assert(p->buffer[COMMAND]);
	p->buftotlen[COMMAND] = buf_size;

	p->buffer[RESOURCE] = malloc(buf_size);
	assert(p->buffer[RESOURCE]);
	p->buftotlen[RESOURCE] = buf_size;

	for (uint32_t i = 0; i < p->pp.nsp; i++) {
		if (p->pp.sp[i].boxed)
			clear_scanout(p, &e->scanouts[i]);
	}

	/* allocate inflate state */
	p->strm.zalloc = Z_NULL;
	p->strm.zfree = Z_NULL;
	p->strm.opaque = Z_NULL;
	p->strm.avail_in = 0;
	p->strm.next_in = Z_NULL;
	ret = inflateInit(&p->strm);
	if (ret != Z_OK)
		warn("inlateInit");

	if (p->pp.inprof)
		p->inprof = INPROF_WAIT_CTX_CREATE;

	if (zmq)
		p->zmq = zmq;

	p->res_socket = res_socket;
	p->split_resources = p->pp.split_resources;

	if (tsr) {
		if (pipe(tsr->tee_pipe) == -1)
			err(1, "pipe");

		pthread_mutex_init(&tsr->mtx, NULL);
		e->use_scissors = true;

		if (p->split_resources)
			tsr->cache = cache_init(p->pp.fs_cache_size);

		if (zmq)
			tsr->zmq = zmq;
		else
			tsr->zmq = NULL;

		p->tsr = tsr;
	} else if (p->split_resources) {
		p->cache = cache_init(p->pp.fs_cache_size);
	}

	return p;
}

void rvgpu_pr_free(struct rvgpu_pr_state *p)
{
	virgl_renderer_force_ctx_0();
	virgl_renderer_cleanup(p);
	inflateEnd(&p->strm);
	if (p->cache)
		cache_free(p->cache);
	if (p->tsr) {
		if (p->tsr->cache)
			cache_free(p->tsr->cache);
		pthread_mutex_destroy(&p->tsr->mtx);
		close(p->tsr->tee_pipe[PIPE_WRITE]);
		close(p->tsr->tee_pipe[PIPE_READ]);
	}
	free(p->buffer[COMMAND]);
	free(p->buffer[RESOURCE]);
	free(p);
}

static void
resource_attach_backing(struct virtio_gpu_resource_attach_backing *r,
			struct virtio_gpu_mem_entry entries[])
{
	size_t length = 0;
	struct iovec *p;
	void *resmem;

	for (unsigned int i = 0; i < r->nr_entries; i++)
		length += entries[i].length;

	if (length == 0)
		errx(1, "invalid length of backing storage");

	p = malloc(sizeof(*p));
	if (p == NULL)
		err(1, "Out of mem");

	resmem = malloc(length);
	if (resmem == NULL)
		err(1, "Out of mem");

	memset(resmem, 0x0, length);

	p->iov_base = resmem;
	p->iov_len = length;

	virgl_renderer_resource_attach_iov(r->resource_id, p, 1);
}

static void load_resource_compressed(struct rvgpu_pr_state *state,
				     struct iovec *p)
{
	struct rvgpu_patch header = {0, 0};
	static uint8_t in[RES_COMPRESS_BUF_MAX_SIZE];
	int ret;

	state->strm.next_out = p[0].iov_base;
	state->strm.avail_out = p[0].iov_len;

	while (rvgpu_pr_read(state, &header, sizeof(header), 1, RESOURCE) ==
	       1) {
		if (header.len == 0)
			break;

		if (rvgpu_pr_read(state, (char *)in, 1, header.len, RESOURCE) !=
		    header.len) {
			err(1, "Short read");
		}

		state->strm.avail_in = header.len;
		state->strm.next_in = in;
		ret = inflate(&state->strm, Z_SYNC_FLUSH);
		assert(ret != Z_STREAM_ERROR); /* state not clobbered */

		if (ret == Z_STREAM_END)
			continue;

		switch (ret) {
		case Z_NEED_DICT:
		case Z_DATA_ERROR:
		case Z_MEM_ERROR:
			warnx("decompress failed");
			(void)inflateEnd(&state->strm);
			return;
		}
	}
}

/**
 * @brief Read hash of resource from cmd socket and send response on res socket
 * @param state - pointer to rvgpu state structure
 * @param stream - pointer to stream type (COMMAND, or RESOURCE) to update it
 * @param res - res_data to be filled in case res is in cache
 */
static void handle_cached_resource(struct rvgpu_pr_state *state, int *stream,
				   struct res_data *res)
{
	struct pollfd pfd;
	struct rvgpu_res_message_header res_req = {.type = RVGPU_RES_REQ};

	if (rvgpu_pr_read(state, (void *)res_req.hash, 1, HASH_SIZE, *stream) !=
	    HASH_SIZE) {
		err(1, "Short read");
	}

	if (state->res_socket == 0)
		err(1, "No resource socket");

	if (res) {
		cache_get_resource(state->cache, res_req.hash, res);

		if (res->data)
			res_req.type = RVGPU_RES_NOT;
		else
			*stream = RESOURCE;
	} else {
		res_req.type = RVGPU_RES_NOT;
	}

	/*
	 * send resource request to rvgpu-proxy with resource hash
	 */
	pfd.fd = state->res_socket;
	pfd.events = POLLOUT;
	poll(&pfd, 1, -1);

	if (pfd.revents & POLLOUT) {
		if (write(state->res_socket, &res_req, sizeof(res_req)) !=
		    sizeof(res_req)) {
			err(1, "Short write");
		}
	}

	if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
		err(1, "Resource socket error");
}

static void skip_resource(struct rvgpu_pr_state *state)
{
	struct rvgpu_patch header = {0, 0};
	int stream = COMMAND;

	while (rvgpu_pr_read(state, &header, sizeof(header), 1, stream) == 1) {
		if (header.len == 0)
			break;
		if (header.type == RVGPU_PATCH_HASH) {
			handle_cached_resource(state, &stream, NULL);
			continue;
		}

		if (rvgpu_pr_read(state, NULL, 1, header.len, stream) !=
		    header.len) {
			err(1, "Short read");
		}
	}
}

static void load_resource_patched(struct rvgpu_pr_state *state, struct iovec *p)
{
	struct rvgpu_patch header = {0, 0};
	int stream = COMMAND;
	uint32_t offset = 0;
	bool offload = false;

	while (rvgpu_pr_read(state, &header, sizeof(header), 1, stream) == 1) {
		if (header.len == 0)
			break;
		if (header.type == RVGPU_PATCH_HASH) {
			struct res_data res = {0, 0};

			offset = header.offset;
			/*
			 * in case of offload thread, resource
			 * socket communication is done there
			 */
			if (state->tsr != NULL) {
				char hash[HASH_SIZE];

				if (rvgpu_pr_read(state, hash, 1, HASH_SIZE,
						  stream) != HASH_SIZE) {
					err(1, "Short read");
				}
				offset = header.offset;
				offload = true;
				continue;
			}

			handle_cached_resource(state, &stream, &res);

			if (res.data) {
				memcpy((char *)p[0].iov_base + offset, res.data,
				       res.size);
				break;
			}
			continue;
		}

		if (stream == COMMAND && !offload)
			offset = header.offset;

		if ((((uint64_t)offset + header.len) > p[0].iov_len))
			errx(1, "Wrong patch format!");

		if (rvgpu_pr_read(state, (char *)p[0].iov_base + offset, 1,
				  header.len, stream) != header.len) {
			err(1, "Short read");
		}

		if (stream == RESOURCE) {
			struct res_data res;

			res.data = (char *)p[0].iov_base + offset;
			res.size = header.len;

			cache_add_resource(state->cache, NULL, &res);
		}
	}
}

static bool load_resource(struct rvgpu_pr_state *state, unsigned int res_id,
			  bool compressed)
{
	struct iovec *p = NULL;
	int iovn = 0;
	bool load = true;

	virgl_renderer_resource_detach_iov(res_id, &p, &iovn);
	if (p == NULL)
		load = false;

	if (load) {
		if (compressed)
			load_resource_compressed(state, p);
		else
			load_resource_patched(state, p);
		virgl_renderer_resource_attach_iov(res_id, p, iovn);
	} else {
		skip_resource(state);
	}
	return load;
}

static void set_scanout(struct rvgpu_pr_state *p,
			struct virtio_gpu_set_scanout *set,
			struct rvgpu_scanout *s)
{
	struct virgl_renderer_resource_info info;
	const struct rvgpu_scanout_params *sp = &s->params;

	if (set->resource_id &&
	    virgl_renderer_resource_get_info(set->resource_id, &info) == 0) {
		struct rvgpu_virgl_params params = {
		    .box = {.x = set->r.x,
			    .y = set->r.y,
			    .w = set->r.width,
			    .h = set->r.height},
		    .tex_id = info.tex_id,
		    .tex = {.w = info.width, .h = info.height},
		    .res_id = set->resource_id,
		    .y0_top = info.flags & 1};
		if (sp->boxed) {
			params.box = sp->box;
		} else if (set->r.width == 0 || set->r.height == 0) {
			params.box.w = info.width;
			params.box.h = info.height;
		}
		if (!sanity_check_resource_rect(&set->r, info.width,
						info.height)) {
			err(1, "Invalid rectangle for set scanout");
		}

		rvgpu_egl_set_scanout(p->egl, s, &params);
	} else {
		clear_scanout(p, s);
	}
}

static void clear_scanout(struct rvgpu_pr_state *p, struct rvgpu_scanout *s)
{
	struct rvgpu_virgl_params params = {
	    .box = {.w = 100, .h = 100},
	    .tex_id = 0,
	};
	if (s->params.boxed)
		params.box = s->params.box;
	rvgpu_egl_set_scanout(p->egl, s, &params);
}

static void dump_capset(struct rvgpu_pr_state *p)
{
	for (unsigned int id = 1;; id++) {
		uint32_t maxver, maxsize;

		virgl_renderer_get_cap_set(id, &maxver, &maxsize);
		if (maxsize == 0 || maxsize >= 1024) {
			warnx("Error while getting capset %u", id);
			break;
		}

		for (unsigned int version = 1; version <= maxver; version++) {
			struct capset hdr = {
			    .id = id, .version = version, .size = maxsize};
			uint8_t data[1024];

			memset(data, 0, maxsize);
			virgl_renderer_fill_caps(id, version, data);
			hdr.size = maxsize;

			if (fwrite(&hdr, sizeof(hdr), 1, p->pp.capset) != 1)
				warn("Error while dumping capset");

			if (fwrite(data, maxsize, 1, p->pp.capset) != 1)
				warn("Error while dumping capset");

			warnx("capset dumped for id %u version %u size %u", id,
			      version, maxsize);
		}
	}
	fflush(p->pp.capset);
	p->pp.capset = NULL;
}

static bool check_rect(uint32_t resource_id, const struct virtio_gpu_rect *r)
{
	struct virgl_renderer_resource_info info;

	if (virgl_renderer_resource_get_info((int)resource_id, &info) != 0)
		return false;

	return sanity_check_resource_rect(r, info.width, info.height);
}

static bool check_box(uint32_t resource_id, const struct virtio_gpu_box *b)
{
	struct virgl_renderer_resource_info info;

	if (virgl_renderer_resource_get_info((int)resource_id, &info) != 0)
		return false;

	return sanity_check_resource_box(b, info.width, info.height,
					 info.depth);
}

static void get_timestamp(struct rvgpu_ts *ts)
{
	struct timespec tv;

	clock_gettime(CLOCK_REALTIME, &tv);
	ts->sec = (int32_t)tv.tv_sec;
	ts->nsec = (int32_t)tv.tv_nsec;
}

static void calculate_and_dump_timestamp(FILE *file,
					 const struct rvgpu_ts *time1,
					 const struct rvgpu_ts *time2)
{
	if (time2 == NULL) {
		fprintf(file, "\t%.4f",
			time1->sec % (60 * 60 * 24) + time1->nsec * 1E-9);
	} else {
		fprintf(file, "\t%3.1f",
			((time2->sec - time1->sec) * 1000) +
			    (time2->nsec - time1->nsec) * 1E-6);
	}
}

static void get_timestamp_ext(struct rvgpu_trailer_ext *te,
			      const struct rvgpu_ts *time, const char name[])
{
	struct rvgpu_ts_ext *tse;

	assert(te->n < MAX_EXT_TIMESTAMPS);
	tse = &te->ts[te->n];

	if (time != NULL)
		tse->time = *time;
	else
		get_timestamp(&tse->time);

	strncpy(tse->name, name, sizeof(tse->name));
	te->n++;
}

static void dump_extended_timestamp(FILE *timestamp,
				    const struct rvgpu_trailer_ext *trext,
				    const struct rvgpu_ts *virtio_rcv_time,
				    const struct rvgpu_ts *recv_time)
{
	for (unsigned int i = 0; i < trext->n; i++) {
		const struct rvgpu_ts_ext *entry = &trext->ts[i];

		if (i == trext->n - 1) {
			/*
			 * Last field is rvgpu end processing time, calculate it
			 * relative to rvgpu_recv time to show time spent
			 * processing
			 */
			calculate_and_dump_timestamp(timestamp, recv_time,
						     &entry->time);
		} else {
			calculate_and_dump_timestamp(timestamp, virtio_rcv_time,
						     &entry->time);
		}
	}
	fprintf(timestamp, "\n");
}

static void dump_timestamp_header(FILE *timestamp,
				  struct rvgpu_trailer_ext *trext)
{
	fprintf(timestamp, "idx\ttype\tvirtio_recv");
	for (unsigned int i = 0; i < trext->n; i++)
		fprintf(timestamp, "\t%.8s", trext->ts[i].name);

	fprintf(timestamp, "\n");
}

static unsigned int rvgpu_serve_vscanout(struct rvgpu_pr_state *pr,
					 struct rvgpu_egl_state *e,
					 unsigned int cmd_type,
					 unsigned int scanout_id,
					 unsigned int res_id)
{
	struct rvgpu_scanout *s;

	switch (cmd_type) {
	case RVGPU_WINDOW_CREATE:
		s = rvgpu_create_vscanout(e, scanout_id);
		set_scanout(
		    pr, &(struct virtio_gpu_set_scanout){.resource_id = res_id},
		    s);
		return res_id;
	case RVGPU_WINDOW_DESTROY:
		s = rvgpu_get_vscanout(e, scanout_id);
		if (s != NULL)
			rvgpu_destroy_vscanout(e, s);
		return 0;
	case RVGPU_WINDOW_UPDATE:
		s = rvgpu_get_vscanout(e, scanout_id);
		if (s != NULL) {
			set_scanout(pr,
				    &(struct virtio_gpu_set_scanout){
					.resource_id = res_id},
				    s);
			return res_id;
		}
		return 0;
	case RVGPU_WINDOW_HIDE:
		/* TODO: hide window */
		return 0;
	case RVGPU_WINDOW_SHOW:
		/* TODO: show window */
		return 0;
	case RVGPU_WINDOW_DESTROYALL:
		rvgpu_destroy_all_vscanouts(e);
		return 0;
	default:
		return 0;
	}
}

static void judge_recover_latency(struct rvgpu_pr_state *p,
				  struct rvgpu_trailer tr)
{
	unsigned long latency;
	struct timespec latest;

	pthread_mutex_lock(&p->tsr->mtx);
	latest.tv_sec = p->tsr->latest_time.tv_sec;
	latest.tv_nsec = p->tsr->latest_time.tv_nsec;

	for (int i = 0; i < TIMESTAMPS_NUM; ++i) {
		if (tr.virtio_recv.sec == p->tsr->force_draw_time[i].tv_sec &&
		    tr.virtio_recv.nsec == p->tsr->force_draw_time[i].tv_nsec) {
			set_gl_skip(false);
			pthread_mutex_unlock(&p->tsr->mtx);
			return;
		}
	}
	pthread_mutex_unlock(&p->tsr->mtx);

	if ((latest.tv_nsec - tr.virtio_recv.nsec) < 0) {
		latest.tv_nsec += 1000000000UL;
		latest.tv_sec -= 1;
	}
	latency = (latest.tv_sec - tr.virtio_recv.sec) * 1000000;
	latency += (latest.tv_nsec - tr.virtio_recv.nsec) / 1000;

	if (latency >= SKIP_THRESHOLD)
		set_gl_skip(true);
	else
		set_gl_skip(false);
}

unsigned int rvgpu_pr_dispatch(struct rvgpu_pr_state *p)
{
	struct rvgpu_header uhdr;
	static bool timestamp_header;

	if (p->inprof == INPROF_CALCULATE) {
		struct rvgpu_ts now;

		get_timestamp(&now);
		now.sec -= p->inprof_ctxtime.sec;
		now.nsec -= p->inprof_ctxtime.nsec;
		if (now.nsec < 0) {
			now.sec--;
			now.nsec += 1000000000;
		}

		warnx("Initialization took %" PRId32 ".%03" PRId32 "s\n"
		      "Traffic is %zuKB, estimation is %.3fs for 1 target\n"
		      "and %.3fs for 4",
		      now.sec, now.nsec / 1000000, p->inprof_read / 1024,
		      p->inprof_read * 8 / (1024.0 * 1024 * 1024),
		      p->inprof_read * 8 * 4 / (1024.0 * 1024 * 1024));

		p->inprof = INPROF_NONE;
	}

	if (p->pp.capset)
		dump_capset(p);

	while (rvgpu_pr_read(p, &uhdr, sizeof(uhdr), 1, COMMAND) == 1) {
		struct iovec *piov;
		union virtio_gpu_cmd r;
		size_t ret;
		int n;
		struct rvgpu_trailer tr = {{0, 0}};
		unsigned int draw = 0;
		bool compressed = false;
		struct rvgpu_ts recv_time;
		enum virtio_gpu_ctrl_type sane;

		memset(&r.hdr, 0, sizeof(r.hdr));
		if (uhdr.size > sizeof(r))
			errx(1, "Too long read (%u)", uhdr.size);

		ret = rvgpu_pr_read(p, &r, 1, uhdr.size, COMMAND);
		if (ret != uhdr.size)
			errx(1, "Too short read(%zu < %u)", ret, uhdr.size);

		get_timestamp(&recv_time);
		if (uhdr.flags & RVGPU_CURSOR)
			sane = sanity_check_gpu_cursor(&r, uhdr.size, false);
		else
			sane = sanity_check_gpu_ctrl(&r, uhdr.size, false);

		if (sane != VIRTIO_GPU_RESP_OK_NODATA)
			errx(1, "insane command issued: %x", (int)r.hdr.type);

		if (uhdr.flags & RVGPU_RES_COMPRESS)
			compressed = true;

		virgl_renderer_force_ctx_0();
		virgl_renderer_poll();
		switch (r.hdr.type) {
		case VIRTIO_GPU_CMD_CTX_CREATE:
			virgl_renderer_context_create(r.hdr.ctx_id,
						      r.c_create.nlen,
						      r.c_create.debug_name);
			if (p->inprof == INPROF_WAIT_CTX_CREATE)
				p->inprof = INPROF_SAVE_CTX_TIMESTAMP;
			break;
		case VIRTIO_GPU_CMD_CTX_DESTROY:
			virgl_renderer_context_destroy(r.hdr.ctx_id);
			break;
		case VIRTIO_GPU_CMD_RESOURCE_CREATE_2D:
			virgl_renderer_resource_create(
			    &(struct virgl_renderer_resource_create_args){
				.handle = r.r_c2d.resource_id,
				.target = 2,
				.format = r.r_c2d.format,
				.bind = 2,
				.width = r.r_c2d.width,
				.height = r.r_c2d.height,
				.depth = 1,
				.array_size = 1,
				.flags = VIRTIO_GPU_RESOURCE_FLAG_Y_0_TOP,
			    },
			    NULL, 0);
			break;
		case VIRTIO_GPU_CMD_RESOURCE_CREATE_3D:
			virgl_renderer_resource_create(
			    &(struct virgl_renderer_resource_create_args){
				.handle = r.r_c3d.resource_id,
				.target = r.r_c3d.target,
				.format = r.r_c3d.format,
				.bind = r.r_c3d.bind,
				.width = r.r_c3d.width,
				.height = r.r_c3d.height,
				.depth = r.r_c3d.depth,
				.array_size = r.r_c3d.array_size,
				.last_level = r.r_c3d.last_level,
				.nr_samples = r.r_c3d.nr_samples,
				.flags = r.r_c3d.flags,
			    },
			    NULL, 0);
			break;
		case VIRTIO_GPU_CMD_SUBMIT_3D:
			virgl_renderer_submit_cmd(r.c_cmdbuf, (int)r.hdr.ctx_id,
						  r.c_submit.size / 4);
			break;
		case VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D:
			if (!load_resource(p, r.t_2h2d.resource_id,
					   compressed)) {
				break;
			}
			if (check_rect(r.t_2h2d.resource_id, &r.t_2h2d.r)) {
				virgl_renderer_transfer_write_iov(
				    r.t_2h2d.resource_id, 0, 0, 0, 0,
				    (struct virgl_box *)&(
					struct virtio_gpu_box){
					.x = r.t_2h2d.r.x,
					.y = r.t_2h2d.r.y,
					.w = r.t_2h2d.r.width,
					.h = r.t_2h2d.r.height,
					.d = 1},
				    r.t_2h2d.offset, NULL, 0);
			} else {
				errx(1, "Invalid rectangle transfer");
			}
			break;
		case VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D:
			if (!load_resource(p, r.t_h3d.resource_id,
					   compressed)) {
				break;
			}
			if (check_box(r.t_h3d.resource_id, &r.t_h3d.box)) {
				virgl_renderer_transfer_write_iov(
				    r.t_h3d.resource_id, r.hdr.ctx_id,
				    (int)r.t_h3d.level, r.t_h3d.stride,
				    r.t_h3d.layer_stride,
				    (struct virgl_box *)&r.t_h3d.box,
				    r.t_h3d.offset, NULL, 0);
			} else {
				errx(1, "Invalid box transfer");
			}
			break;
		case VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D:
			if (check_box(r.t_h3d.resource_id, &r.t_h3d.box)) {
				virgl_renderer_transfer_read_iov(
				    r.t_h3d.resource_id, r.hdr.ctx_id,
				    r.t_h3d.level, r.t_h3d.stride,
				    r.t_h3d.layer_stride,
				    (struct virgl_box *)&r.t_h3d.box,
				    r.t_h3d.offset, NULL, 0);
			} else {
				errx(1, "Invalid box transfer");
			}
			break;
		case VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING:
			resource_attach_backing(&r.r_att, r.r_mem);
			break;
		case VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING:
			virgl_renderer_resource_detach_iov(r.r_det.resource_id,
							   &piov, &n);
			if (piov != NULL && n > 0) {
				free(piov[0].iov_base);
				free(piov);
			}
			break;
		case VIRTIO_GPU_CMD_SET_SCANOUT: {
			struct rvgpu_scanout *s =
			    &p->egl->scanouts[r.s_set.scanout_id];
			if (s->params.enabled)
				set_scanout(p, &r.s_set, s);
			break;
		}
		case VIRTIO_GPU_CMD_RESOURCE_FLUSH:
			/* Call draw function if it's for scanout */
			draw = r.r_flush.resource_id;
			if (p->inprof == INPROF_WAIT_RESOURCE_FLUSH)
				p->inprof = INPROF_CALCULATE;
			break;
		case VIRTIO_GPU_CMD_RESOURCE_UNREF:
			virgl_renderer_resource_detach_iov(
			    r.r_unref.resource_id, &piov, &n);
			if (piov != NULL && n > 0) {
				free(piov[0].iov_base);
				free(piov);
			}
			virgl_renderer_resource_unref(r.r_unref.resource_id);
			break;
		case VIRTIO_GPU_CMD_CTX_ATTACH_RESOURCE:
			virgl_renderer_ctx_attach_resource(r.hdr.ctx_id,
							   r.c_res.resource_id);
			break;
		case VIRTIO_GPU_CMD_CTX_DETACH_RESOURCE:
			virgl_renderer_ctx_detach_resource(r.hdr.ctx_id,
							   r.c_res.resource_id);
			break;
		case VIRTIO_GPU_CMD_GET_CAPSET:
		case VIRTIO_GPU_CMD_GET_CAPSET_INFO:
		case VIRTIO_GPU_CMD_GET_DISPLAY_INFO:
			/* ignore command */
			break;

		case VIRTIO_GPU_CMD_UPDATE_CURSOR:
			if (!p->egl->spawn_support)
				break;
			draw = rvgpu_serve_vscanout(p, p->egl, r.cursor.hot_x,
						    r.cursor.hot_y,
						    r.cursor.resource_id);
			break;
		case VIRTIO_GPU_CMD_MOVE_CURSOR:
			/* TODO: handle cursor */
			break;
		default:
			warnx("Unknown command %d", r.hdr.type);
			return 0;
		}

		if (r.hdr.flags & VIRTIO_GPU_FLAG_FENCE) {
			uint32_t hdr_type = r.hdr.type;
			uint64_t hdr_fence_id = r.hdr.fence_id;

			ret =
			    virgl_renderer_create_fence(hdr_fence_id, hdr_type);

			if (ret != 0) {
				fprintf(stderr, "%s(): err create fence: %s\n",
					__func__, strerror(ret));
			} else {
				if (hdr_fence_id > p->fence_received)
					p->fence_received = hdr_fence_id;
				virgl_renderer_poll();
			}
		}

		if (uhdr.flags & RVGPU_TRAILER) {
			ret = rvgpu_pr_read(p, &tr, sizeof(tr), 1, COMMAND);
			if (ret != 1)
				errx(1, "Too short read(%zu < %zu)", ret,
				     sizeof(tr));

			if (p->inprof == INPROF_SAVE_CTX_TIMESTAMP) {
				p->inprof_ctxtime = tr.virtio_recv;
				p->inprof = INPROF_WAIT_RESOURCE_FLUSH;
			}
			if (p->tsr &&
			    r.hdr.type == VIRTIO_GPU_CMD_RESOURCE_FLUSH) {
				judge_recover_latency(p, tr);
			}
		}

		if (uhdr.flags & RVGPU_TRAILER_EXT) {
			struct rvgpu_trailer_ext trext;

			ret =
			    rvgpu_pr_read(p, &trext, sizeof(trext), 1, COMMAND);
			if (ret != 1)
				errx(1, "Too short read(%zu < %zu)", ret,
				     sizeof(trext));

			if (p->pp.timestamp) {
				get_timestamp_ext(&trext, &recv_time, "rv_rcv");
				get_timestamp_ext(&trext, NULL, "rv_end");

				if (!timestamp_header) {
					timestamp_header = true;
					dump_timestamp_header(p->pp.timestamp,
							      &trext);
				}

				fprintf(p->pp.timestamp, "%" PRIu16 "\t%20s",
					uhdr.idx,
					sanity_cmd_by_type(r.hdr.type));
				calculate_and_dump_timestamp(
				    p->pp.timestamp, &tr.virtio_recv, NULL);
				dump_extended_timestamp(p->pp.timestamp, &trext,
							&tr.virtio_recv,
							&recv_time);
				fflush(p->pp.timestamp);
			}
		}

		if (draw)
			return draw;
	}
	return 0;
}
