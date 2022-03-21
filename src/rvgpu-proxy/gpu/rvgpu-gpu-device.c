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
#include <dlfcn.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/queue.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

#include <linux/virtio_config.h>
#include <linux/virtio_gpu.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_lo.h>

#include <rvgpu-proxy/gpu/rvgpu-gpu-device.h>
#include <rvgpu-proxy/gpu/rvgpu-iov.h>
#include <rvgpu-proxy/gpu/rvgpu-map-guest.h>
#include <rvgpu-proxy/gpu/rvgpu-vqueue.h>

#include <librvgpu/rvgpu-plugin.h>
#include <librvgpu/rvgpu-protocol.h>

#include <rvgpu-generic/rvgpu-capset.h>
#include <rvgpu-generic/rvgpu-sanity.h>

#define XXH_INLINE_ALL
#include <rvgpu-proxy/cache/rvgpu-cache.h>

#define GPU_MAX_CAPDATA 16

#if !defined(VIRTIO_GPU_RESP_ERR_DEVICE_RESET)
#define VIRTIO_GPU_RESP_ERR_DEVICE_RESET 0x1206
#endif

#if !defined(VIRTIO_GPU_F_VSYNC)
#define VIRTIO_GPU_F_VSYNC 5
#endif

#if !defined(VIRTIO_GPU_FLAG_VSYNC)
#define VIRTIO_GPU_FLAG_VSYNC (1 << 2)
#endif

#define VERSION_SYMBOL_NAME "rvgpu_backend_version"

#define GPU_BE_FIND_PLUGIN_VERSION(ver)                                        \
	do {                                                                   \
		uint32_t *ver_ptr =                                            \
		    (uint32_t *)dlsym(plugin, VERSION_SYMBOL_NAME);            \
		if (ver_ptr == NULL)                                           \
			(ver) = 1u;                                            \
		else                                                           \
			(ver) = *ver_ptr;                                      \
	} while (0)
#define GPU_BE_PLUGIN_FIELD(plugin, field) plugin.ops.field
#define GPU_BE_OPS_FIELD(ver, field)                                           \
	GPU_BE_PLUGIN_FIELD(be->plugin_##ver, field)
#define GPU_BE_FIND_SYMBOL_OR_FAIL(ver, symbol)                                \
	do {                                                                   \
		GPU_BE_OPS_FIELD(ver, symbol) =                                \
		    (typeof(GPU_BE_OPS_FIELD(ver, symbol)))(uintptr_t)dlsym(   \
			plugin, #symbol);                                      \
		if (GPU_BE_OPS_FIELD(ver, symbol) == NULL) {                   \
			warnx("failed to find plugin symbol '%s': %s",         \
			      #symbol, dlerror());                             \
			goto err_sym;                                          \
		}                                                              \
	} while (0)

struct gpu_capdata {
	struct capset hdr;
	uint8_t data[1024];
};

struct cmd {
	struct virtio_gpu_ctrl_hdr hdr;
	struct vqueue_request req;

	TAILQ_ENTRY(cmd) cmds;
};

struct async_resp {
	TAILQ_HEAD(, cmd) async_cmds;
	int fence_pipe[2];
};

struct gpu_device {
	int lo_fd;
	int config_fd;
	int kick_fd;
	int vsync_fd;

	size_t max_mem;
	size_t curr_mem;
	const struct gpu_device_params *params;

	uint32_t scanres;
	uint32_t scan_id;
	int wait_vsync;

	unsigned int idx;
	struct gpu_capdata capdata[GPU_MAX_CAPDATA];
	size_t ncapdata;

	z_stream strm;
	struct virtio_gpu_config config;
	pthread_t resource_thread;

	struct vqueue_request ctrl;
	struct vqueue_request cursor;
	struct vqueue vq[2];
	struct rvgpu_backend *backend;
	struct cache *cache;
	struct async_resp *async_resp;
};

static inline uint64_t bit64(unsigned int shift)
{
	return ((uint64_t)1) << shift;
}
static enum reset_state gpu_reset_state;

int rvgpu_init_backends(struct rvgpu_backend *b,
			struct rvgpu_scanout_arguments *scanout_args)
{
	struct rvgpu_ctx *ctx = &b->plugin_v1.ctx;
	void *plugin = b->lib_handle;
	uint32_t version = b->plugin_version;

	for (unsigned int i = 0; i < ctx->scanout_num; i++) {
		struct rvgpu_scanout *be = &b->plugin_v1.scanout[i];

		switch (version) {
		case RVGPU_BACKEND_V1:
			GPU_BE_FIND_SYMBOL_OR_FAIL(v1, rvgpu_init);
			GPU_BE_FIND_SYMBOL_OR_FAIL(v1, rvgpu_destroy);
			GPU_BE_FIND_SYMBOL_OR_FAIL(v1, rvgpu_send);
			GPU_BE_FIND_SYMBOL_OR_FAIL(v1, rvgpu_recv);
			break;
		default:
			err(1, "unsupported backend version: %u\n", version);
			return -1;
		}

		be->plugin_v1.ops.rvgpu_init(ctx, be, scanout_args[i]);
	}

	return 0;
err_sym:
	return -1;
}

int rvgpu_init_ctx(struct rvgpu_backend *b, struct rvgpu_ctx_arguments ctx_args)
{
	struct rvgpu_ctx *ctx = &b->plugin_v1.ctx;
	struct rvgpu_backend *be = b;
	void *plugin = b->lib_handle;
	uint32_t version;

	GPU_BE_FIND_PLUGIN_VERSION(version);

	switch (version) {
	case RVGPU_BACKEND_V1:
		GPU_BE_FIND_SYMBOL_OR_FAIL(v1, rvgpu_ctx_init);
		GPU_BE_FIND_SYMBOL_OR_FAIL(v1, rvgpu_ctx_destroy);
		GPU_BE_FIND_SYMBOL_OR_FAIL(v1, rvgpu_frontend_reset_state);
		GPU_BE_FIND_SYMBOL_OR_FAIL(v1, rvgpu_ctx_wait);
		GPU_BE_FIND_SYMBOL_OR_FAIL(v1, rvgpu_ctx_wakeup);
		GPU_BE_FIND_SYMBOL_OR_FAIL(v1, rvgpu_ctx_poll);
		GPU_BE_FIND_SYMBOL_OR_FAIL(v1, rvgpu_ctx_send);
		GPU_BE_FIND_SYMBOL_OR_FAIL(v1, rvgpu_ctx_transfer_to_host);
		GPU_BE_FIND_SYMBOL_OR_FAIL(v1, rvgpu_ctx_res_create);
		GPU_BE_FIND_SYMBOL_OR_FAIL(v1, rvgpu_ctx_res_find);
		GPU_BE_FIND_SYMBOL_OR_FAIL(v1, rvgpu_ctx_res_destroy);
		break;
	default:
		err(1, "unsupported backend version: %u", version);
	}

	be->plugin_version = version;
	be->plugin_v1.ops.rvgpu_ctx_init(ctx, ctx_args, &backend_reset_state);

	return 0;
err_sym:
	return -1;
}

struct rvgpu_backend *init_backend_rvgpu(struct host_conn *servers)
{
	struct rvgpu_scanout_arguments scanout_args[MAX_HOSTS] = {0};
	struct rvgpu_backend *rvgpu_be;

	rvgpu_be = calloc(1, sizeof(*rvgpu_be));
	if (rvgpu_be == NULL) {
		warnx("failed to allocate backend: %s", strerror(errno));
		goto err_be;
	}

	char str_lib[] = "librvgpu.so";

	/* Flush the current dl error state */
	dlerror();

	rvgpu_be->lib_handle = dlopen(str_lib, RTLD_NOW);
	if (rvgpu_be->lib_handle == NULL) {
		warnx("failed to open backend library '%s': %s", str_lib,
		      dlerror());
		goto err_sym;
	}

	struct rvgpu_ctx_arguments ctx_args = {
	    .conn_tmt_s = servers->conn_tmt_s,
	    .keep_on_render = servers->keep_on_render,
	    .reconn_intv_ms = servers->reconn_intv_ms,
	    .scanout_num = servers->host_cnt,
	    .session_tmt_ms = servers->session_tmt_ms,
	    .pgm = (servers->zmq_cnt > 0) ? true : false,
	};

	if (rvgpu_init_ctx(rvgpu_be, ctx_args)) {
		warnx("failed to init rvgpu ctx");
		goto err_sym;
	}

	for (int i = 0; i < servers->host_cnt; i++) {
		if (ctx_args.pgm) {
			scanout_args[i].zmq.zmq_endpoint =
			    strdup(servers->hosts_zmq[0].zmq_addr);
			scanout_args[i].zmq.zmq_rate = servers->zmq_rate;
			scanout_args[i].zmq.zmq_recovery_ms =
			    servers->zmq_recovery_ms;
		}
		scanout_args[i].tcp.ip = strdup(servers->hosts[i].hostname);
		scanout_args[i].tcp.port = strdup(servers->hosts[i].portnum);
	}

	if (rvgpu_init_backends(rvgpu_be, scanout_args)) {
		warnx("failed to init rvgpu backends");
		goto err_sym;
	}

	return rvgpu_be;
err_sym:
	free(rvgpu_be);
err_be:
	dlclose(rvgpu_be->lib_handle);

	return NULL;
}

void destroy_backend_rvgpu(struct rvgpu_backend *b)
{
	struct rvgpu_ctx *ctx = &b->plugin_v1.ctx;

	for (unsigned int i = 0; i < ctx->scanout_num; i++) {
		struct rvgpu_scanout *s = &b->plugin_v1.scanout[i];

		s->plugin_v1.ops.rvgpu_destroy(ctx, s);
	}
	b->plugin_v1.ops.rvgpu_ctx_destroy(ctx);
	dlclose(b->lib_handle);
}

static void gpu_device_free_res(struct gpu_device *g, struct rvgpu_res *res)
{
	for (unsigned int i = 0; i < res->nbacking; i++) {
		unmap_guest(res->backing[i].iov_base, res->backing[i].iov_len);
		g->curr_mem -= res->backing[i].iov_len;
	}
}

static void gpu_capset_init(struct gpu_device *g, int capset)
{
	g->config.num_capsets = 0u;
	size_t i;

	for (i = 0u; i < GPU_MAX_CAPDATA; i++) {
		struct gpu_capdata *c = &g->capdata[i];

		if (read(capset, &c->hdr, sizeof(c->hdr)) !=
		    (ssize_t)sizeof(c->hdr))
			break;

		if (c->hdr.size > sizeof(c->data)) {
			warnx("too long capset");
			break;
		}
		if (read(capset, c->data, c->hdr.size) !=
		    (ssize_t)c->hdr.size) {
			warn("cannot read capset data");
			break;
		}
		if (c->hdr.id > g->config.num_capsets)
			g->config.num_capsets = c->hdr.id;
	}
	g->ncapdata = i;
}

size_t process_fences(struct gpu_device *g, uint32_t fence_id)
{
	struct async_resp *r = g->async_resp;
	struct virtio_gpu_ctrl_hdr hdr;
	struct cmd *cmd;
	size_t processed = 0;

	TAILQ_FOREACH(cmd, &r->async_cmds, cmds)
	{
		if ((cmd->hdr.fence_id > fence_id) ||
		    (cmd->hdr.flags & VIRTIO_GPU_FLAG_VSYNC))
			continue;

		memcpy(&hdr, &cmd->hdr, sizeof(hdr));
		vqueue_send_response(&g->vq[0], &cmd->req, &hdr, sizeof(hdr));
		TAILQ_REMOVE(&r->async_cmds, cmd, cmds);
		free(cmd);
		processed++;
	}

	return processed;
}

void add_resp(struct gpu_device *g, struct virtio_gpu_ctrl_hdr *hdr,
	      struct vqueue_request *req)
{
	struct async_resp *r = g->async_resp;
	struct cmd *cmd;

	cmd = (struct cmd *)calloc(1, sizeof(*cmd));
	assert(cmd);

	memcpy(&cmd->hdr, hdr, sizeof(*hdr));
	memcpy(&cmd->req, req, sizeof(*req));

	TAILQ_INSERT_TAIL(&r->async_cmds, cmd, cmds);
}

void destroy_async_resp(struct gpu_device *g)
{
	struct async_resp *r = g->async_resp;

	close(r->fence_pipe[PIPE_READ]);
	close(r->fence_pipe[PIPE_WRITE]);

	free(r);
}

struct async_resp *init_async_resp(struct gpu_device *g)
{
	struct async_resp *r;

	r = (struct async_resp *)calloc(1, sizeof(*r));
	assert(r);

	TAILQ_INIT(&r->async_cmds);

	if (pipe(r->fence_pipe) == -1)
		err(1, "pipe creation error");

	return r;
}

static void *resource_thread_func(void *param)
{
	struct gpu_device *g = (struct gpu_device *)param;
	struct cache *cache = (struct cache *)g->cache;
	struct async_resp *r = (struct async_resp *)g->async_resp;
	struct rvgpu_backend *b = g->backend;
	struct rvgpu_res_message_header msg;
	short int revents[MAX_HOSTS];

	while (1) {
		wait_resource_events(b, revents);
		for (int i = 0; i < b->plugin_v1.ctx.scanout_num; i++) {
			if (revents[i] & POLLIN) {
				struct rvgpu_scanout *s =
				    &b->plugin_v1.scanout[i];

				ssize_t ret = s->plugin_v1.ops.rvgpu_recv(
				    s, RESOURCE, &msg, sizeof(msg));
				if (ret != sizeof(msg))
					err(1, "Short read");

				if (msg.type == RVGPU_FENCE) {
					ret =
					    write(r->fence_pipe[PIPE_WRITE],
						  &msg.fence_id,
						  sizeof(msg.fence_id));
					if (ret != sizeof(msg.fence_id))
						warnx("Short write");
				} else {
					cache_event(cache, &msg, s);
				}
			}
		}
	}
}

struct gpu_device *gpu_device_init(int lo_fd, int efd, uint32_t cidx,
				   uint32_t qidx, int capset,
				   const struct gpu_device_params *params,
				   struct rvgpu_backend *b, struct cache *cache)
{
	struct gpu_device *g;
	struct virtio_lo_qinfo q[2];
	pthread_t fence_thread;
	unsigned int i;
	int ret;

	struct virtio_lo_devinfo info = {
	    .nqueues = 2u,
	    .qinfo = q,
	    .device_id = VIRTIO_ID_GPU,
	    .vendor_id = 0x1af4, /* PCI_VENDOR_ID_REDHAT_QUMRANET */
	    .config_size = sizeof(struct virtio_gpu_config),
	    .features = bit64(VIRTIO_GPU_F_VIRGL) | bit64(VIRTIO_F_VERSION_1),
	};
	if (params->framerate)
		info.features |= bit64(VIRTIO_GPU_F_VSYNC);

	g = (struct gpu_device *)calloc(1, sizeof(*g));
	if (!g) {
		warn("not enough memory");
		return NULL;
	}
	g->params = params;
	g->lo_fd = lo_fd;
	g->config_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	g->kick_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	g->config.num_scanouts = params->num_scanouts;
	g->max_mem = params->mem_limit * 1024 * 1024;
	if (capset != -1)
		gpu_capset_init(g, capset);

	info.card_index = params->card_index;
	info.config = (__u8 *)&g->config;
	info.config_kick = g->config_fd;

	for (i = 0u; i < 2u; i++) {
		q[i].kickfd = g->kick_fd;
		q[i].size = 1024u;
	}
	if (ioctl(lo_fd, VIRTIO_LO_ADDDEV, &info))
		err(1, "add virtio-lo-device");

	g->idx = info.idx;
	vqueue_init_request(&g->ctrl, q[0].size);
	vqueue_init_request(&g->cursor, q[1].size);

	for (i = 0u; i < 2u; i++) {
		struct vring *vr = &g->vq[i].vr;

		vr->num = q[i].size;
		vr->desc = (struct vring_desc *)map_guest(
		    lo_fd, q[i].desc, PROT_READ, q[i].size * 16u);
		vr->avail = (struct vring_avail *)map_guest(
		    lo_fd, q[i].avail, PROT_READ, q[i].size * 2u + 6u);
		vr->used = (struct vring_used *)map_guest(
		    lo_fd, q[i].used, PROT_READ | PROT_WRITE,
		    q[i].size * 8u + 6u);
	}

	if (params->framerate) {
		g->vsync_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
		if (g->vsync_fd == -1)
			err(1, "timerfd_create");

		epoll_ctl(efd, EPOLL_CTL_ADD, g->vsync_fd,
			  &(struct epoll_event){.events = EPOLLIN | EPOLLET,
						.data = {.u32 = qidx}});
	} else {
		g->vsync_fd = -1;
	}

	epoll_ctl(
	    efd, EPOLL_CTL_ADD, g->config_fd,
	    &(struct epoll_event){.events = EPOLLIN, .data = {.u32 = cidx}});
	epoll_ctl(
	    efd, EPOLL_CTL_ADD, g->kick_fd,
	    &(struct epoll_event){.events = EPOLLIN, .data = {.u32 = qidx}});

	if (g->params->resource_compression) {
		g->strm.zalloc = Z_NULL;
		g->strm.zfree = Z_NULL;
		g->strm.opaque = Z_NULL;
		ret = deflateInit(&g->strm, g->params->compress_level);
		if (ret != Z_OK)
			warn("deflateInit");
	}

	g->async_resp = init_async_resp(g);
	epoll_ctl(
	    efd, EPOLL_CTL_ADD, g->async_resp->fence_pipe[PIPE_READ],
	    &(struct epoll_event){.events = EPOLLIN, .data = {.u32 = qidx}});

	g->cache = cache;
	g->backend = b;

	if (pthread_create(&g->resource_thread, NULL, resource_thread_func,
			   g) != 0) {
		err(1, "resource thread create");
	}
	return g;
}

void gpu_device_free(struct gpu_device *g)
{
	unsigned int i;

	vqueue_free_request(&g->ctrl);
	vqueue_free_request(&g->cursor);
	for (i = 0u; i < 2u; i++) {
		struct vring *vr = &g->vq[i].vr;

		unmap_guest(vr->desc, vr->num * 16u);
		unmap_guest(vr->avail, vr->num * 2u + 6u);
		unmap_guest(vr->used, vr->num * 8u + 6u);
	}

	close(g->vsync_fd);
	close(g->config_fd);
	close(g->kick_fd);
	if (g->params->resource_compression)
		deflateEnd(&g->strm);
	if (g->backend)
		destroy_backend_rvgpu(g->backend);
	destroy_async_resp(g);

	free(g);
}

void gpu_device_config(struct gpu_device *g)
{
	struct virtio_gpu_config c;
	struct virtio_lo_config cfg = {
	    .idx = g->idx, .config = (__u8 *)&c, .len = sizeof(c)};

	if (ioctl(g->lo_fd, VIRTIO_LO_GCONF, &cfg) != 0)
		return;

	if (c.events_clear) {
		g->config.events_read &= ~c.events_clear;
		cfg.config = (__u8 *)&g->config;
		ioctl(g->lo_fd, VIRTIO_LO_SCONF, &cfg);
	}
}

static unsigned int gpu_device_create_res(struct gpu_device *g,
					  unsigned int resid,
					  const struct rvgpu_res_info *info)
{
	struct rvgpu_backend *b = g->backend;
	struct rvgpu_res *res;

	res = b->plugin_v1.ops.rvgpu_ctx_res_find(&b->plugin_v1.ctx, resid);
	if (res != NULL)
		return VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID;

	if (b->plugin_v1.ops.rvgpu_ctx_res_create(&b->plugin_v1.ctx, info,
						  resid))
		return VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY;

	return VIRTIO_GPU_RESP_OK_NODATA;
}

static unsigned int gpu_device_destroy_res(struct gpu_device *g,
					   unsigned int resid)
{
	struct rvgpu_backend *b = g->backend;
	struct rvgpu_res *res;

	res = b->plugin_v1.ops.rvgpu_ctx_res_find(&b->plugin_v1.ctx, resid);
	if (res == NULL)
		return VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID;

	gpu_device_free_res(g, res);
	b->plugin_v1.ops.rvgpu_ctx_res_destroy(&b->plugin_v1.ctx, resid);
	return VIRTIO_GPU_RESP_OK_NODATA;
}

static void gpu_device_send_compressed(struct gpu_device *g,
				       const struct rvgpu_res *res)
{
	struct rvgpu_backend *b = g->backend;
	enum pipe_type p;

	if (g->params->split_resources)
		p = RESOURCE;
	else
		p = COMMAND;

	for (size_t i = 0u; i < res->nbacking; i++) {
		int flush =
		    (i == (res->nbacking - 1)) ? Z_SYNC_FLUSH : Z_NO_FLUSH;
		g->strm.avail_in = (unsigned int)res->backing[i].iov_len;
		g->strm.next_in = res->backing[i].iov_base;

		do {
			static uint8_t out[RES_COMPRESS_BUF_MAX_SIZE];
			uint32_t deflated_size = 0;
			int ret;

			g->strm.avail_out = RES_COMPRESS_BUF_MAX_SIZE;
			g->strm.next_out = out;
			ret = deflate(&g->strm, flush);
			assert(ret != Z_STREAM_ERROR);
			deflated_size =
			    RES_COMPRESS_BUF_MAX_SIZE - g->strm.avail_out;
			if (deflated_size != 0) {
				struct rvgpu_patch header = {.len =
								 deflated_size};
				if (b->plugin_v1.ops.rvgpu_ctx_send(
					&b->plugin_v1.ctx, &header,
					sizeof(header))) {
					warn("short write");
				}
				if (b->plugin_v1.ops.rvgpu_ctx_send(
					&b->plugin_v1.ctx, &out, header.len)) {
					warn("short write");
				}
			} else {
				break;
			}
		} while (g->strm.avail_out == 0);
	}
}

/**
 * @brief Calculate size of resource
 * @param iovs - vector of pointers with resources
 * @param niov - number of resources pointers
 * @param skip - number of bytes, that should be skipped
 * @return size of resource in bytes
 */
static size_t calculate_res_size(const struct iovec iovs[], size_t niov,
				 size_t skip)
{
	size_t size = 0;
	size_t offset = 0;

	for (size_t i = 0u; i < niov; i++) {
		const struct iovec *iov = &iovs[i];

		if (skip >= iov->iov_len) {
			skip -= iov->iov_len;
		} else {
			size += iov->iov_len - skip;
			skip = 0u;
		}
		offset += iov->iov_len;
	}

	return size;
}

/**
 * @brief Update hash of resource with new chunks of res memory
 * @param iovs - vector of pointers with resources
 * @param niov - number of resources pointers
 * @param skip - number of bytes, that should be skipped
 * @param length - number of bytes for which hash should be calculated
 * @param state - xx64hash state of whole resource
 * @param res_data - resource data struct to be filled
 */
static void add_to_hash(const struct iovec iovs[], size_t niov, size_t skip,
			size_t length, XXH64_state_t *const state,
			struct res_in_data *res_data)
{
	for (size_t i = 0u; i < niov && length > 0u; i++) {
		const struct iovec *iov = &iovs[i];

		if (skip >= iov->iov_len) {
			skip -= iov->iov_len;
		} else {
			size_t l = iov->iov_len - skip;

			if (l > length)
				l = length;

			if (XXH64_update(state, (char *)iov->iov_base + skip,
					 l) == XXH_ERROR)
				err(1, "Hash calculation error");

			res_data->iov[res_data->niov].iov_base =
			    (char *)iov->iov_base + skip;
			res_data->iov[res_data->niov].iov_len = l;
			res_data->niov++;
			if (res_data->niov >= MAX_CHUNKS_NUM)
				err(1, "res buffer overflow");

			skip = 0u;
			length -= l;
		}
	}
}

/**
 * @brief Retrieve resource and calculate it's hash
 * @param res - pointer to gpu resource
 * @param t - pointer to resource info
 * @param res_data - resource data structure to be filled
 */
static void calculate_hash(const struct rvgpu_res *res,
			   const struct rvgpu_res_transfer *t,
			   struct res_in_data *res_data)
{
	XXH64_hash_t seed = 0;
	size_t idx;

	XXH64_state_t *const state = XXH64_createState();

	if (state == NULL)
		err(1, "Failed to init hash lib");

	if (XXH64_reset(state, seed) == XXH_ERROR)
		err(1, "Failed to reset hash state");

	switch (res->info.target) {
	case 0:
		add_to_hash(res->backing, res->nbacking, t->offset, t->w, state,
			    res_data);
		break;
	case 2: {
		uint32_t stride = t->stride;

		if (stride == 0)
			stride = res->info.bpp * res->info.width;

		for (size_t h = 0u; h < t->h; h++) {
			add_to_hash(res->backing, res->nbacking,
				    t->offset + h * stride,
				    t->w * res->info.bpp, state, res_data);
		}
	} break;
	default:
		add_to_hash(res->backing, res->nbacking, t->offset, SIZE_MAX,
			    state, res_data);
	}

	res_data->hash = XXH64_digest(state);

	XXH64_freeState(state);
}

/**
 * @brief Calculate hash of resource and send it on cmd socket
 * @param g - pointer to gpu device
 * @param res - pointer to gpu resource
 * @param t - pointer to resource info
 * @param size - size of resource
 */
static void gpu_device_send_hash(const struct gpu_device *g,
				 const struct rvgpu_res *res,
				 const struct rvgpu_res_transfer *t,
				 size_t size)
{
	struct rvgpu_backend *b = g->backend;
	char hash[HASH_SIZE];
	struct res_in_data res_data;
	struct rvgpu_patch hash_hdr = {
	    .type = RVGPU_PATCH_HASH, .len = HASH_SIZE, .offset = t->offset};
	struct rvgpu_patch hdr;
	struct rvgpu_patch trailer;

	/* reserve one entry for header */
	res_data.niov = 1;

	calculate_hash(res, t, &res_data);

	hdr.type = RVGPU_PATCH_RES;
	hdr.len = size;

	res_data.iov[0].iov_base = &hdr;
	res_data.iov[0].iov_len = sizeof(struct rvgpu_patch);

	trailer.len = 0;
	res_data.iov[res_data.niov].iov_base = &trailer;
	res_data.iov[res_data.niov].iov_len = sizeof(struct rvgpu_patch);
	res_data.niov++;

	cache_add_resource(g->cache, &res_data);

	hash_to_canonical(res_data.hash, hash);

	if (b->plugin_v1.ops.rvgpu_ctx_send(&b->plugin_v1.ctx, &hash_hdr,
					    sizeof(struct rvgpu_patch))) {
		warn("short write");
	}

	if (b->plugin_v1.ops.rvgpu_ctx_send(&b->plugin_v1.ctx, &hash,
					    HASH_SIZE)) {
		warn("short write");
	}
}

static void gpu_device_send_patched(struct gpu_device *g,
				    const struct rvgpu_res *res,
				    const struct rvgpu_res_transfer *t)
{
	struct rvgpu_backend *b = g->backend;
	size_t size = 0;

	if (res->info.target == 0) {
		size = t->w;
	} else if (res->info.target == 2) {
		size = t->w * res->info.bpp * t->h;
	} else {
		size =
		    calculate_res_size(res->backing, res->nbacking, t->offset);
	}
	if (g->params->split_resources && size >= RES_LIMIT) {
		gpu_device_send_hash(g, res, t, size);
		return;
	}
	if (b->plugin_v1.ops.rvgpu_ctx_transfer_to_host(&b->plugin_v1.ctx, t,
							res)) {
		warn("short write");
	}
}

static unsigned int gpu_device_send_res(struct gpu_device *g,
					unsigned int resid,
					const struct rvgpu_res_transfer *t)
{
	struct rvgpu_backend *b = g->backend;
	struct rvgpu_res *res;

	res = b->plugin_v1.ops.rvgpu_ctx_res_find(&b->plugin_v1.ctx, resid);
	if (!res)
		return VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID;

	if (!res->backing)
		return VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER;

	if (g->params->resource_compression) {
		gpu_device_send_compressed(g, res);
		int ret = b->plugin_v1.ops.rvgpu_ctx_send(
		    &b->plugin_v1.ctx, &(struct rvgpu_patch){.len = 0},
		    sizeof(struct rvgpu_patch));
		if (ret)
			warn("short write");
	} else {
		gpu_device_send_patched(g, res, t);
	}

	return VIRTIO_GPU_RESP_OK_NODATA;
}

static unsigned int gpu_device_attach(struct gpu_device *g, unsigned int resid,
				      struct virtio_gpu_mem_entry mem[],
				      unsigned int n)
{
	struct rvgpu_backend *b = g->backend;
	struct rvgpu_res *res;
	unsigned int i;
	size_t sentsize = 0u;

	res = b->plugin_v1.ops.rvgpu_ctx_res_find(&b->plugin_v1.ctx, resid);
	if (!res)
		return VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID;

	if (res->backing)
		return VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER;

	res->backing = calloc(n, sizeof(struct iovec));
	if (!res->backing) {
		warn("Out of memory on attach");
		return VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY;
	}
	res->nbacking = n;
	for (i = 0u; i < n; i++) {
		res->backing[i].iov_base =
		    map_guest(g->lo_fd, mem[i].addr, PROT_READ, mem[i].length);
		res->backing[i].iov_len = mem[i].length;
		sentsize += mem[i].length;
	}
	if (g->max_mem != 0 && (g->curr_mem + sentsize) > g->max_mem) {
		for (i = 0u; i < n; i++) {
			unmap_guest(res->backing[i].iov_base,
				    res->backing[i].iov_len);
		}
		warnx("Out of memory on attach");
		free(res->backing);
		res->backing = NULL;
		res->nbacking = 0u;
		return VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY;
	}

	g->curr_mem += sentsize;

	return VIRTIO_GPU_RESP_OK_NODATA;
}

static unsigned int gpu_device_detach(struct gpu_device *g, unsigned int resid)
{
	struct rvgpu_backend *b = g->backend;
	struct rvgpu_res *res;
	unsigned int i;

	res = b->plugin_v1.ops.rvgpu_ctx_res_find(&b->plugin_v1.ctx, resid);
	if (!res)
		return VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID;

	if (!res->backing)
		return VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER;

	for (i = 0u; i < res->nbacking; i++) {
		unmap_guest(res->backing[i].iov_base, res->backing[i].iov_len);
		g->curr_mem -= res->backing[i].iov_len;
	}
	free(res->backing);
	res->backing = NULL;
	res->nbacking = 0u;
	return VIRTIO_GPU_RESP_OK_NODATA;
}

static void gpu_device_capset_info(struct gpu_device *g, unsigned int index,
				   struct virtio_gpu_resp_capset_info *ci)
{
	ci->capset_id = 0u;
	ci->capset_max_version = 0u;
	ci->capset_max_size = 0u;

	for (size_t i = 0u; i < g->ncapdata; i++) {
		const struct gpu_capdata *c = &g->capdata[i];

		if ((index + 1) == c->hdr.id) {
			ci->capset_id = c->hdr.id;
			if (c->hdr.version > ci->capset_max_version)
				ci->capset_max_version = c->hdr.version;

			if (c->hdr.size > ci->capset_max_size)
				ci->capset_max_size = c->hdr.size;
		}
	}
}

static struct gpu_capdata *gpu_device_find_capset(struct gpu_device *g,
						  unsigned int capset_id,
						  unsigned int capset_version)
{
	if (capset_version) {
		for (size_t i = 0u; i < g->ncapdata; i++) {
			struct gpu_capdata *cd = &g->capdata[i];

			if (capset_id == cd->hdr.id &&
			    capset_version == cd->hdr.version) {
				return cd;
			}
		}
	} else {
		struct gpu_capdata *cp = NULL;
		uint32_t version = 0u;

		for (size_t i = 0u; i < g->ncapdata; i++) {
			struct gpu_capdata *cd = &g->capdata[i];

			if (capset_id == cd->hdr.id &&
			    cd->hdr.version > version) {
				version = cd->hdr.version;
				cp = cd;
			}
		}
		return cp;
	}
	return NULL;
}

static size_t gpu_device_capset(struct gpu_device *g, unsigned int capset_id,
				unsigned int capset_version,
				struct virtio_gpu_resp_capset *c)
{
	struct gpu_capdata *cd =
	    gpu_device_find_capset(g, capset_id, capset_version);
	if (cd) {
		c->hdr.type = VIRTIO_GPU_RESP_OK_CAPSET;
		memcpy(c->capset_data, cd->data, cd->hdr.size);
		return sizeof(*c) + cd->hdr.size;
	}

	c->hdr.type = VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER;
	return sizeof(c->hdr);
}

static uint64_t gpu_device_read_vsync(struct gpu_device *g)
{
	uint64_t res = 0;
	ssize_t n;

	if (g->vsync_fd == -1)
		return 1;

	n = read(g->vsync_fd, &res, sizeof(res));

	if (n == -1 && errno == EAGAIN)
		res = 0u;
	else if (n != (ssize_t)sizeof(res))
		err(1, "Invalid vsync read");

	return res;
}

static void get_timestamp(struct rvgpu_ts *ts)
{
	struct timespec tv;

	clock_gettime(CLOCK_REALTIME, &tv);
	ts->sec = (int32_t)tv.tv_sec;
	ts->nsec = (int32_t)tv.tv_nsec;
}

static void get_timestamp_ext(struct rvgpu_trailer_ext *te, struct rvgpu_ts *ts,
			      const char name[])
{
	struct rvgpu_ts_ext *tse;

	assert(te->n < MAX_EXT_TIMESTAMPS);

	tse = &te->ts[te->n];
	if (ts != NULL)
		tse->time = *ts;
	else
		get_timestamp(&tse->time);

	strncpy(tse->name, name, sizeof(tse->name));
	te->n++;
}

void backend_reset_state(struct rvgpu_ctx *ctx, enum reset_state state)
{
	gpu_reset_state = state;
}

static unsigned long delta_time_nsec(struct timespec start,
				     struct timespec stop)
{
	return (unsigned long)((stop.tv_sec - start.tv_sec) * 1000000000 +
			       (stop.tv_nsec - start.tv_nsec));
}

static void set_timer(int timerfd, unsigned long framerate,
		      unsigned long vsync_time)
{
	struct itimerspec ts = {{0}};

	if (framerate > 0) {
		unsigned long vsync_delta = 0, rate = 1000000000UL / framerate;

		if (vsync_time > 0) {
			if ((vsync_time - rate) < rate)
				vsync_delta = vsync_time - rate;
		}

		ts.it_value.tv_nsec = rate - vsync_delta;
	}

	if (timerfd_settime(timerfd, 0, &ts, NULL) == -1)
		fprintf(stderr, "Failed to set timerfd: %s\n", strerror(errno));
}

size_t gpu_device_serve_vsync(struct gpu_device *g)
{
	struct async_resp *r = g->async_resp;
	struct virtio_gpu_ctrl_hdr hdr;
	struct cmd *cmd;
	size_t processed = 0;

	TAILQ_FOREACH(cmd, &r->async_cmds, cmds)
	{
		if (cmd->hdr.flags & VIRTIO_GPU_FLAG_VSYNC) {
			memcpy(&hdr, &cmd->hdr, sizeof(hdr));
			vqueue_send_response(&g->vq[0], &cmd->req, &hdr,
					     sizeof(hdr));
			TAILQ_REMOVE(&r->async_cmds, cmd, cmds);
			free(cmd);
			processed++;
		}
	}
	return processed;
}

static int gpu_device_serve_fences(struct gpu_device *g)
{
	struct async_resp *r = g->async_resp;
	struct pollfd pfd;
	int processed = 0;
	uint32_t fence_id;

	pfd.fd = r->fence_pipe[PIPE_READ];
	pfd.events = POLLIN;

	while (poll(&pfd, 1, 0) > 0) {
		if (pfd.revents & POLLIN) {
			int rc = read(r->fence_pipe[PIPE_READ], &fence_id,
				      sizeof(fence_id));
			if (rc != sizeof(fence_id))
				warnx("read error: %d", rc);

			processed += process_fences(g, fence_id);
		}
	}
	return processed;
}

static void gpu_device_trigger_vsync(struct gpu_device *g,
				     struct virtio_gpu_ctrl_hdr *hdr,
				     struct vqueue_request *req,
				     unsigned int flags,
				     struct timespec vsync_ts)
{
	if (!(flags & VIRTIO_GPU_FLAG_VSYNC))
		return;

	hdr->flags |= VIRTIO_GPU_FLAG_VSYNC;
	/* use padding bytes to pass scanout_id to virtio-gpu driver */
	hdr->padding = g->scan_id;
	add_resp(g, hdr, req);

	if ((!vsync_ts.tv_sec) && (!vsync_ts.tv_nsec)) {
		set_timer(g->vsync_fd, g->params->framerate, 0);
	} else {
		struct timespec now;

		clock_gettime(CLOCK_REALTIME, &now);
		set_timer(g->vsync_fd, g->params->framerate,
			  delta_time_nsec(vsync_ts, now));
	}

	g->wait_vsync = 1;
}

static void gpu_device_serve_ctrl(struct gpu_device *g)
{
	struct rvgpu_backend *b = g->backend;
	int kick = 0;
	static bool reset;
	static struct timespec vsync_ts;

	union {
		struct virtio_gpu_ctrl_hdr hdr;
		struct virtio_gpu_resp_display_info rdi;
		struct virtio_gpu_resp_capset_info ci;
		struct virtio_gpu_resp_capset c;
		uint8_t data[4096];
	} resp;
	memset(&resp.hdr, 0, sizeof(resp.hdr));
	if (g->wait_vsync) {
		if (gpu_device_read_vsync(g) > 0u) {
			g->wait_vsync = 0;
			kick += gpu_device_serve_vsync(g);
			set_timer(g->vsync_fd, 0, 0);
		}
	}
	kick += gpu_device_serve_fences(g);
	while (vqueue_get_request(g->lo_fd, &g->vq[0], &g->ctrl)) {
		size_t resp_len = sizeof(resp.hdr);
		union virtio_gpu_cmd r;
		struct rvgpu_header rhdr = {
		    .size = (uint32_t)iov_size(g->ctrl.r, g->ctrl.nr),
		    .idx = 0,
		    .flags = 0,
		};
		struct rvgpu_trailer trailer = {.virtio_recv = {0, 0}};
		struct rvgpu_ts krnl_time;

		if (g->params->timestamp) {
			rhdr.idx = g->ctrl.idx;
			rhdr.flags = RVGPU_IDX | RVGPU_TRAILER;
			get_timestamp(&trailer.virtio_recv);
		}
		if (g->params->timestamp_ex)
			rhdr.flags |= RVGPU_TRAILER_EXT;

		if (g->params->resource_compression)
			rhdr.flags |= RVGPU_RES_COMPRESS;

		copy_from_iov(g->ctrl.r, g->ctrl.nr, &r, sizeof(r));

		resp.hdr.flags = 0;
		resp.hdr.fence_id = 0;
		resp.hdr.type = sanity_check_gpu_ctrl(&r, rhdr.size, true);

		if (resp.hdr.type == VIRTIO_GPU_RESP_OK_NODATA) {
			size_t i;

			krnl_time = trailer.virtio_recv;

			if (r.hdr.flags & VIRTIO_GPU_FLAG_FENCE) {
				resp.hdr.flags = VIRTIO_GPU_FLAG_FENCE;
				resp.hdr.fence_id = r.hdr.fence_id;
				resp.hdr.ctx_id = r.hdr.ctx_id;
				add_resp(g, &resp.hdr, &g->ctrl);
			} else {
				if (r.hdr.fence_id != 0) {
					krnl_time.sec =
					    (int32_t)(r.hdr.fence_id >> 32);
					krnl_time.nsec =
					    (int32_t)r.hdr.fence_id;
				}
			}

			if (g->params->debug) {
				warnx("got request type %s",
				      sanity_cmd_by_type(r.hdr.type));
			}

			if (b->plugin_v1.ops.rvgpu_ctx_send(
				&b->plugin_v1.ctx, &rhdr, sizeof(rhdr))) {
				warn("short write");
			}
			for (i = 0u; i < g->ctrl.nr; i++) {
				struct iovec *iov = &g->ctrl.r[i];

				if (b->plugin_v1.ops.rvgpu_ctx_send(
					&b->plugin_v1.ctx, iov->iov_base,
					iov->iov_len)) {
					warn("short write");
				}
			}

			/* command is sane, parse it */
			switch (r.hdr.type) {
			case VIRTIO_GPU_CMD_GET_DISPLAY_INFO:
				memcpy(
				    resp.rdi.pmodes, g->params->dpys,
				    g->params->num_scanouts *
					sizeof(struct virtio_gpu_display_one));
				resp.hdr.type = VIRTIO_GPU_RESP_OK_DISPLAY_INFO;
				resp_len = sizeof(resp.rdi);
				break;
			case VIRTIO_GPU_CMD_RESOURCE_CREATE_2D:
				resp.hdr.type = gpu_device_create_res(
				    g, r.r_c2d.resource_id,
				    &(struct rvgpu_res_info){
					.target = 2,
					.depth = 1,
					.array_size = 1,
					.format = r.r_c2d.format,
					.width = r.r_c2d.width,
					.height = r.r_c2d.height,
					.flags =
					    VIRTIO_GPU_RESOURCE_FLAG_Y_0_TOP,
				    });
				break;
			case VIRTIO_GPU_CMD_RESOURCE_CREATE_3D:
				resp.hdr.type = gpu_device_create_res(
				    g, r.r_c3d.resource_id,
				    &(struct rvgpu_res_info){
					.target = r.r_c3d.target,
					.width = r.r_c3d.width,
					.height = r.r_c3d.height,
					.depth = r.r_c3d.depth,
					.array_size = r.r_c3d.array_size,
					.format = r.r_c3d.format,
					.flags = r.r_c3d.flags,
					.last_level = r.r_c3d.last_level,
				    });
				break;
			case VIRTIO_GPU_CMD_RESOURCE_UNREF:
				resp.hdr.type = gpu_device_destroy_res(
				    g, r.r_unref.resource_id);
				break;
			case VIRTIO_GPU_CMD_SET_SCANOUT:
				if (r.s_set.scanout_id == 0)
					g->scanres = r.s_set.resource_id;
				g->scan_id = r.s_set.scanout_id;
				break;
			case VIRTIO_GPU_CMD_RESOURCE_FLUSH:
				if (r.r_flush.resource_id == g->scanres) {
					if (gpu_device_read_vsync(g) == 0) {
						gpu_device_trigger_vsync(
						    g, &resp.hdr, &g->ctrl,
						    r.hdr.flags, vsync_ts);
						clock_gettime(CLOCK_REALTIME,
							      &vsync_ts);
					}
				}
				break;
			case VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D:
				resp.hdr.type = gpu_device_send_res(
				    g, r.t_2h2d.resource_id,
				    &(struct rvgpu_res_transfer){
					.x = r.t_2h2d.r.x,
					.y = r.t_2h2d.r.y,
					.w = r.t_2h2d.r.width,
					.h = r.t_2h2d.r.height,
					.offset = r.t_2h2d.offset,
					.d = 1,
				    });
				break;
			case VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D:
				resp.hdr.type = gpu_device_send_res(
				    g, r.t_h3d.resource_id,
				    &(struct rvgpu_res_transfer){
					.x = r.t_h3d.box.x,
					.y = r.t_h3d.box.y,
					.z = r.t_h3d.box.z,
					.w = r.t_h3d.box.w,
					.h = r.t_h3d.box.h,
					.d = r.t_h3d.box.d,
					.level = r.t_h3d.level,
					.stride = r.t_h3d.stride,
					.offset = r.t_h3d.offset,
				    });
				break;
			case VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING:
				resp.hdr.type = gpu_device_attach(
				    g, r.r_att.resource_id, r.r_mem,
				    r.r_att.nr_entries);
				break;
			case VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING:
				resp.hdr.type =
				    gpu_device_detach(g, r.r_det.resource_id);
				break;
			case VIRTIO_GPU_CMD_GET_CAPSET_INFO:
				gpu_device_capset_info(
				    g, r.capset_info.capset_index, &resp.ci);
				resp.hdr.type = VIRTIO_GPU_RESP_OK_CAPSET_INFO;
				resp_len = sizeof(resp.ci);
				break;
			case VIRTIO_GPU_CMD_GET_CAPSET:
				resp_len = gpu_device_capset(
				    g, r.capset.capset_id,
				    r.capset.capset_version, &resp.c);
				break;
			default:
				break;
			}
			if (g->params->timestamp) {
				if (g->backend->plugin_v1.ops.rvgpu_ctx_send(
					&g->backend->plugin_v1.ctx, &trailer,
					sizeof(trailer))) {
					warn("short write");
				}
			}
			if (g->params->timestamp_ex) {
				struct rvgpu_trailer_ext trailer_ext = {
				    .n = 0,
				};
				get_timestamp_ext(&trailer_ext, &krnl_time,
						  "kernel");
				get_timestamp_ext(&trailer_ext, NULL, "send");
				if (b->plugin_v1.ops.rvgpu_ctx_send(
					&b->plugin_v1.ctx, &trailer_ext,
					sizeof(trailer_ext))) {
					warn("short write");
				}
			}
		} else if (g->params->debug) {
			if (rhdr.size < sizeof(r.hdr)) {
				warnx("Too short command in stream");
			} else {
				warnx("Sanity check fail in %s",
				      sanity_cmd_by_type(r.hdr.type));
			}
		}
		if (gpu_reset_state) {
			resp.hdr.type = VIRTIO_GPU_RESP_ERR_DEVICE_RESET;
			reset = true;
		}
		if ((!(resp.hdr.flags & VIRTIO_GPU_FLAG_FENCE)) &&
		    (!(resp.hdr.flags & VIRTIO_GPU_FLAG_VSYNC))) {
			vqueue_send_response(&g->vq[0], &g->ctrl, &resp,
					     resp_len);
			kick++;
		}
	}
	if (kick) {
		struct virtio_lo_kick k = {
		    .idx = g->idx,
		    .qidx = 0,
		};
		if (ioctl(g->lo_fd, VIRTIO_LO_KICK, &k) != 0)
			warn("ctrl kick failed");
	}
	if (reset) {
		struct rvgpu_ctx *ctx = &b->plugin_v1.ctx;

		if (gpu_reset_state == GPU_RESET_NONE) {
			reset = false;
			b->plugin_v1.ops.rvgpu_ctx_wait(ctx, GPU_RESET_NONE);

		} else if (gpu_reset_state == GPU_RESET_TRUE) {
			b->plugin_v1.ops.rvgpu_frontend_reset_state(
			    ctx, GPU_RESET_INITIATED);
			gpu_reset_state = GPU_RESET_INITIATED;
			b->plugin_v1.ops.rvgpu_ctx_wakeup(ctx);
		}
	}
}

static void gpu_device_serve_cursor(struct gpu_device *g)
{
	struct rvgpu_backend *b = g->backend;
	int kick = 0;
	bool flush = false;

	while (vqueue_get_request(g->lo_fd, &g->vq[1], &g->cursor)) {
		union virtio_gpu_cmd r;
		struct virtio_gpu_ctrl_hdr resp = {.flags = 0, .fence_id = 0};
		size_t cmdsize = iov_size(g->cursor.r, g->cursor.nr);
		struct rvgpu_header rhdr = {
		    .size = (uint32_t)cmdsize,
		    .idx = 0,
		    .flags = RVGPU_CURSOR,
		};
		struct rvgpu_trailer trailer = {.virtio_recv = {0, 0}};
		struct rvgpu_ts krnl_time;

		if (g->params->timestamp) {
			rhdr.idx = g->ctrl.idx;
			rhdr.flags |= RVGPU_IDX | RVGPU_TRAILER;
			get_timestamp(&trailer.virtio_recv);
		}
		if (g->params->timestamp_ex)
			rhdr.flags |= RVGPU_TRAILER_EXT;

		copy_from_iov(g->cursor.r, g->cursor.nr, &r, sizeof(r));

		resp.type = sanity_check_gpu_cursor(&r, cmdsize, true);
		if (resp.type == VIRTIO_GPU_RESP_OK_NODATA) {
			krnl_time = trailer.virtio_recv;
			if (r.hdr.flags & VIRTIO_GPU_FLAG_FENCE) {
				resp.flags = VIRTIO_GPU_FLAG_FENCE;
				resp.fence_id = r.hdr.fence_id;
				resp.ctx_id = r.hdr.ctx_id;
			} else if (r.hdr.fence_id != 0) {
				krnl_time.sec = (int32_t)(r.hdr.fence_id >> 32);
				krnl_time.nsec = (int32_t)r.hdr.fence_id;
			}

			if (g->params->debug) {
				warnx("got cursor request type %s",
				      sanity_cmd_by_type(r.hdr.type));
			}
			if (b->plugin_v1.ops.rvgpu_ctx_send(
				&b->plugin_v1.ctx, &rhdr, sizeof(rhdr))) {
				warn("short write");
			}
			for (unsigned int i = 0u; i < g->cursor.nr; i++) {
				struct iovec *iov = &g->cursor.r[i];

				if (b->plugin_v1.ops.rvgpu_ctx_send(
					&b->plugin_v1.ctx, iov->iov_base,
					iov->iov_len)) {
					warn("short write");
				}
			}

			switch (r.hdr.type) {
			case VIRTIO_GPU_CMD_UPDATE_CURSOR:
				flush = true;
				break;
			default:
			case VIRTIO_GPU_CMD_MOVE_CURSOR:
				break;
			}
			if (g->params->timestamp) {
				if (b->plugin_v1.ops.rvgpu_ctx_send(
					&b->plugin_v1.ctx, &trailer,
					sizeof(trailer))) {
					warn("short write");
				}
			}
			if (g->params->timestamp_ex) {
				struct rvgpu_trailer_ext trailer_ext = {
				    .n = 0,
				};
				get_timestamp_ext(&trailer_ext, &krnl_time,
						  "kernel");
				get_timestamp_ext(&trailer_ext, NULL, "send");

				if (b->plugin_v1.ops.rvgpu_ctx_send(
					&b->plugin_v1.ctx, &trailer_ext,
					sizeof(trailer_ext))) {
					warn("short write");
				}
			}
		} else if (g->params->debug) {
			if (cmdsize < sizeof(r.hdr)) {
				warnx("Too short command in cursor stream");
			} else {
				warnx("Sanity check fail in cursor command %s",
				      sanity_cmd_by_type(r.hdr.type));
			}
		}
		vqueue_send_response(&g->vq[1], &g->cursor, &resp,
				     sizeof(resp));
		kick = 1;
	}
	if (kick) {
		struct virtio_lo_kick k = {
		    .idx = g->idx,
		    .qidx = 1,
		};
		if (ioctl(g->lo_fd, VIRTIO_LO_KICK, &k) != 0)
			warn("cursor kick failed");
	}
}

void gpu_device_serve(struct gpu_device *g)
{
	uint64_t ev;
	ssize_t ret;

	ret = read(g->kick_fd, &ev, sizeof(ev));
	if (ret > 0 && ret != (ssize_t)sizeof(ev))
		err(1, "wrong read from eventfd");

	gpu_device_serve_ctrl(g);
	gpu_device_serve_cursor(g);
}
