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
#include <netdb.h>
#include <pgm/messages.h>
#include <pgm/pgm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>
#include <zmq.h>

#include <rvgpu-generic/rvgpu-utils.h>

#include <librvgpu/rvgpu-plugin.h>
#include <librvgpu/rvgpu.h>

struct zmq_poll_entries {
	zmq_pollitem_t *ses_timer;
	zmq_pollitem_t *recon_timer;
	zmq_pollitem_t *cmd_host;
	zmq_pollitem_t *cmd_pipe_in;
	zmq_pollitem_t *res_host;
	zmq_pollitem_t *res_pipe_in;
};

int init_zmq_scanout(struct rvgpu_ctx *ctx, struct rvgpu_scanout *scanout,
		     struct rvgpu_scanout_arguments *args)
{
	struct ctx_priv *ctx_priv = (struct ctx_priv *)ctx->priv;
	struct sc_priv *sc_priv = (struct sc_priv *)scanout->priv;

	struct vgpu_host *cmd = &ctx_priv->cmd[ctx_priv->cmd_count];
	struct vgpu_host *res = &ctx_priv->res[ctx_priv->res_count];

	if (!ctx_priv->zmq) {
		cmd->zmq = &args->zmq;
		cmd->host_p[PIPE_WRITE] =
		    sc_priv->pipes[COMMAND].rcv_pipe[PIPE_WRITE];
		cmd->host_p[PIPE_READ] =
		    sc_priv->pipes[COMMAND].snd_pipe[PIPE_READ];
		ctx_priv->cmd_count++;
		ctx_priv->zmq = true;
	}

	res->tcp = &args->tcp;
	res->host_p[PIPE_WRITE] = sc_priv->pipes[RESOURCE].rcv_pipe[PIPE_WRITE];
	res->host_p[PIPE_READ] = sc_priv->pipes[RESOURCE].snd_pipe[PIPE_READ];
	res->vpgu_p[PIPE_WRITE] = sc_priv->pipes[RESOURCE].snd_pipe[PIPE_WRITE];
	res->vpgu_p[PIPE_READ] = sc_priv->pipes[RESOURCE].rcv_pipe[PIPE_READ];
	ctx_priv->res_count++;

	return 0;
}

static void log_handler(const int log_level, const char *message, void *closure)
{
	(void)log_level;
	(void)closure;

	info("librvgpu zmq: %s\n", message);
}

void zmq_close_publisher(struct vgpu_host *host)
{
	zmq_close(host->zmq_socket);
	zmq_ctx_term(host->zmq_ctx);
}

int zmq_init_publisher(struct vgpu_host *host)
{
	struct zmq_host *args = (struct zmq_host *)host->zmq;

	if (!zmq_has("pgm")) {
		warnx("libzmq has been compiled without PGM support");
		return -1;
	}

	/*
	 * ZereMQ prints messages directly to stdout.
	 * To avoid this setup a custom log hander.
	 */
	pgm_log_set_handler(log_handler, NULL);

	host->zmq_ctx = zmq_ctx_new();
	if (!host->zmq_ctx) {
		warnx("zmq_ctx_new error: %s", zmq_strerror(errno));
		zmq_ctx_term(host->zmq_ctx);
		return -1;
	}

	const int buf_size = LIBRVGPU_ZMQ_BUF_SIZE;
	const int hwm = LIBRVGPU_ZMQ_HWM;
	const int no_drop = 1;

	host->zmq_socket = zmq_socket(host->zmq_ctx, ZMQ_PUB);
	if (!host->zmq_socket) {
		warnx("zmq_socket error: %s", zmq_strerror(errno));
		zmq_ctx_term(host->zmq_ctx);
		return -1;
	}

	if (zmq_setsockopt(host->zmq_socket, ZMQ_RATE, &args->zmq_rate,
			   sizeof(args->zmq_rate))) {
		warnx("can't set ZMQ_RATE option: %s", zmq_strerror(errno));
		zmq_close(host->zmq_socket);
		zmq_ctx_term(host->zmq_ctx);
		return -1;
	}

	if (zmq_setsockopt(host->zmq_socket, ZMQ_SNDBUF, &buf_size,
			   sizeof(buf_size))) {
		warnx("can't set ZMQ_SNDBUF option: %s", zmq_strerror(errno));
		zmq_close(host->zmq_socket);
		zmq_ctx_term(host->zmq_ctx);
		return -1;
	}

	if (zmq_setsockopt(host->zmq_socket, ZMQ_RCVBUF, &buf_size,
			   sizeof(buf_size))) {
		warnx("can't set ZMQ_RCVBUF option: %s", zmq_strerror(errno));
		zmq_close(host->zmq_socket);
		zmq_ctx_term(host->zmq_ctx);
		return -1;
	}

	if (zmq_setsockopt(host->zmq_socket, ZMQ_XPUB_NODROP, &no_drop,
			   sizeof(no_drop))) {
		warnx("can't set ZMQ_XPUB_NODROP option: %s",
		      zmq_strerror(errno));
		zmq_close(host->zmq_socket);
		zmq_ctx_term(host->zmq_ctx);
		return -1;
	}

	if (zmq_setsockopt(host->zmq_socket, ZMQ_SNDHWM, &hwm, sizeof(hwm))) {
		warnx("can't set ZMQ_SNDHWM option: %s", zmq_strerror(errno));
		zmq_close(host->zmq_socket);
		zmq_ctx_term(host->zmq_ctx);
		return -1;
	}

	if (zmq_setsockopt(host->zmq_socket, ZMQ_RECOVERY_IVL,
			   &args->zmq_recovery_ms,
			   sizeof(args->zmq_recovery_ms))) {
		warnx("can't set ZMQ_RECOVERY_IVL option: %s",
		      zmq_strerror(errno));
		zmq_close(host->zmq_socket);
		zmq_ctx_term(host->zmq_ctx);
		return -1;
	}

	if (zmq_bind(host->zmq_socket, args->zmq_endpoint)) {
		warnx("zmq_bind error: %s", zmq_strerror(errno));
		zmq_close(host->zmq_socket);
		zmq_ctx_term(host->zmq_ctx);
		return -1;
	}

	return 0;
}

unsigned int get_pointers_zmq(struct ctx_priv *ctx, struct zmq_pollitem_t *pfd,
			      struct zmq_pollitem_t **ses_timer,
			      struct zmq_pollitem_t **recon_timer,
			      struct zmq_pollitem_t **cmd_host,
			      struct zmq_pollitem_t **cmd_pipe,
			      struct zmq_pollitem_t **res_host,
			      struct zmq_pollitem_t **res_pipe)
{
	unsigned int pfd_count = 0;
	/* set pointers as following. Ex: for 2 targets
	 * 0 - session timer
	 * 1 - recconnect timer
	 * 2 - command host 0
	 * 3 - command host 1
	 * 4 - command pipe in 0
	 * 5 - command pipe in 1
	 * 6 - res host 0
	 * 7 - res host 1
	 * 8 - res pipe in 0
	 * 9 - res pipe in 1
	 */
	*ses_timer = &pfd[pfd_count];
	pfd_count++;
	*recon_timer = &pfd[pfd_count];
	pfd_count++;
	*cmd_host = &pfd[pfd_count];
	pfd_count += ctx->cmd_count;
	*cmd_pipe = &pfd[pfd_count];
	pfd_count += ctx->cmd_count;
	*res_host = &pfd[pfd_count];
	pfd_count += ctx->res_count;
	*res_pipe = &pfd[pfd_count];
	pfd_count += ctx->res_count;

	return pfd_count;
}

unsigned int set_pfd_zmq(struct ctx_priv *ctx, struct vgpu_host *vhost[],
			 zmq_pollitem_t *pfd, struct zmq_poll_entries *p_entry)
{
	unsigned int pfd_count = get_pointers_zmq(
	    ctx, pfd, &p_entry->ses_timer, &p_entry->recon_timer,
	    &p_entry->cmd_host, &p_entry->cmd_pipe_in, &p_entry->res_host,
	    &p_entry->res_pipe_in);
	/* Timer to detect hung sessions */
	p_entry->ses_timer->fd = init_timer();
	p_entry->ses_timer->socket = NULL;
	p_entry->ses_timer->events = ZMQ_POLLIN;

	/* Timer to do the reconnection attempts */
	p_entry->recon_timer->fd = init_timer();
	p_entry->recon_timer->socket = NULL;
	p_entry->recon_timer->events = ZMQ_POLLIN;

	/* set command pfd */
	for (unsigned int i = 0; i < ctx->cmd_count; i++) {
		p_entry->cmd_host[i].fd = -1;
		p_entry->cmd_host[i].socket = ctx->cmd[i].zmq_socket;
		p_entry->cmd_host[i].events = ZMQ_POLLIN;
		vhost[i] = &ctx->cmd[i];
		vhost[i]->zmq_pfd = &p_entry->cmd_host[i];
	}

	/* set command pipe pfd */
	for (unsigned int i = 0; i < ctx->cmd_count; i++) {
		p_entry->cmd_pipe_in[i].fd = ctx->cmd[i].host_p[PIPE_READ];
		p_entry->cmd_pipe_in[i].socket = NULL;
		p_entry->cmd_pipe_in[i].events = ZMQ_POLLIN;
	}

	/* set resource host pfd */
	for (unsigned int i = 0; i < ctx->res_count; i++) {
		p_entry->res_host[i].fd = ctx->res[i].sock;
		p_entry->res_host[i].socket = NULL;
		p_entry->res_host[i].events = ZMQ_POLLIN;
		vhost[i + ctx->cmd_count] = &ctx->res[i];
		vhost[i + ctx->cmd_count]->zmq_pfd = &p_entry->res_host[i];
	}

	/* set resource pipe pfd */
	for (unsigned int i = 0; i < ctx->res_count; i++) {
		p_entry->res_pipe_in[i].fd = ctx->res[i].host_p[PIPE_READ];
		p_entry->res_pipe_in[i].socket = NULL;
		p_entry->res_pipe_in[i].events = ZMQ_POLLIN;
	}

	return pfd_count;
}

unsigned int get_input_ev_zmq(zmq_pollitem_t *pipe_in, unsigned int count)
{
	unsigned int in_pipes = 0;

	for (unsigned int i = 0; i < count; i++) {
		if (pipe_in[i].revents & ZMQ_POLLIN)
			in_pipes++;
	}
	return in_pipes;
}

void disable_input_zmq(zmq_pollitem_t *pipe_in, unsigned int count)
{
	for (unsigned int i = 0; i < count; i++)
		pipe_in[i].events &= ~ZMQ_POLLIN;
}

void enable_input_zmq(zmq_pollitem_t *pipe_in, unsigned int count)
{
	for (unsigned int i = 0; i < count; i++)
		pipe_in[i].events |= ZMQ_POLLIN;
}

void set_in_out_zmq(zmq_pollitem_t *host, unsigned int count)
{
	for (unsigned int i = 0; i < count; i++)
		host[i].events = ZMQ_POLLIN | ZMQ_POLLOUT;
}

unsigned int handle_host_comm_zmq(struct rvgpu_ctx *ctx,
				  struct vgpu_host *vhost[],
				  struct zmq_poll_entries *p_entry)
{
	struct ctx_priv *ctx_priv = (struct ctx_priv *)ctx->priv;
	zmq_pollitem_t *cmd_host = p_entry->cmd_host;
	zmq_pollitem_t *pipe_in = p_entry->cmd_pipe_in;
	char in_buf[PGM_BUF_SIZE];
	unsigned int sent = 0;
	ssize_t len;
	int ret;

	for (unsigned int i = 0; i < ctx_priv->cmd_count; i++) {
		if (cmd_host[i].revents & ZMQ_POLLOUT) {
			len = read(pipe_in[i].fd, in_buf, PGM_BUF_SIZE);
			ret = zmq_send(cmd_host[i].socket, in_buf, len, 0);
			if (ret != len) {
				warnx("Short write %d:%lu", ret, len);
				process_reset_backend(ctx, GPU_RESET_TRUE);
				set_timer(p_entry->recon_timer->fd,
					  ctx_priv->args.reconn_intv_ms);
			}
			cmd_host[i].events &= ~ZMQ_POLLOUT;
			sent++;
		}
		if (cmd_host[i].revents & ZMQ_POLLIN) {
			ret = zmq_recv(cmd_host[i].socket, in_buf, PGM_BUF_SIZE,
				       0);
			if (ret == -1) {
				warnx("rd: spile error %s", strerror(errno));
				process_reset_backend(ctx, GPU_RESET_TRUE);
				set_timer(p_entry->recon_timer->fd,
					  ctx_priv->args.reconn_intv_ms);
			} else {
				len = write(ctx_priv->cmd[i].host_p[PIPE_WRITE],
					    in_buf, ret);
				if (ret != len)
					warnx("Short write %d:%lu", ret, len);
			}
		}
	}
	return sent;
}

bool resource_err_zmq(struct ctx_priv *ctx, zmq_pollitem_t *res_host,
		      struct vgpu_host *vhost[], int *act_ses)
{
	bool hung = false;

	for (unsigned int i = 0; i < ctx->res_count; i++) {
		if ((res_host[i].fd > 0) &&
		    (res_host[i].revents & ZMQ_POLLERR)) {
			close_conn(vhost[i]);
			hung = true;
			*act_ses -= 1;
		}
	}
	return hung;
}

unsigned int handle_host_res_zmq(struct rvgpu_ctx *ctx,
				 struct vgpu_host *vhost[],
				 struct zmq_poll_entries *p_entry, int devnull)
{
	struct ctx_priv *ctx_priv = (struct ctx_priv *)ctx->priv;
	zmq_pollitem_t *res_host = p_entry->res_host;
	zmq_pollitem_t *pipe_in = p_entry->res_pipe_in;
	unsigned int sent = 0;

	for (unsigned int i = 0; i < ctx_priv->res_count; i++) {
		if (res_host[i].revents & ZMQ_POLLERR) {
			close_conn(vhost[i]);
			process_reset_backend(ctx, GPU_RESET_TRUE);
			set_timer(p_entry->recon_timer->fd,
				  ctx_priv->args.reconn_intv_ms);
		}
		if (res_host[i].revents & ZMQ_POLLOUT) {
			int ret = splice(pipe_in[i].fd, NULL, res_host[i].fd,
					 NULL, PIPE_SIZE, 0);
			if (ret == -1) {
				warnx("wr: spile error %s", strerror(errno));
				close_conn(vhost[i]);
				process_reset_backend(ctx, GPU_RESET_TRUE);
				set_timer(p_entry->recon_timer->fd,
					  ctx_priv->args.reconn_intv_ms);
			}
			res_host[i].events &= ~ZMQ_POLLOUT;
			sent++;
		}
		if (res_host[i].revents & ZMQ_POLLIN) {
			int ret = splice(res_host[i].fd, NULL,
					 ctx_priv->res[i].host_p[PIPE_WRITE],
					 NULL, PIPE_SIZE, 0);
			if (ret == -1) {
				disconnect(vhost, ctx_priv->cmd_count,
					   ctx_priv->res_count, i);
				process_reset_backend(ctx, GPU_RESET_TRUE);
				set_timer(p_entry->recon_timer->fd,
					  ctx_priv->args.reconn_intv_ms);
			}
		}
		if (res_host[i].fd < 0)
			splice(pipe_in[i].fd, NULL, devnull, NULL, PIPE_SIZE,
			       SPLICE_F_NONBLOCK);
	}
	return sent;
}

void handle_resources_zmq(struct rvgpu_ctx *ctx, struct vgpu_host *vhost[],
			  struct zmq_poll_entries p_entry, int devnull,
			  unsigned int act_ses)
{
	struct ctx_priv *ctx_priv = (struct ctx_priv *)ctx->priv;
	static bool timer_set;
	unsigned int ret;

	if (!act_ses) {
		flush_input_pipes(ctx_priv, devnull, RESOURCE);
		enable_input_zmq(p_entry.res_pipe_in, ctx_priv->res_count);
		return;
	}
	ret = get_input_ev_zmq(p_entry.res_pipe_in, ctx_priv->res_count);
	if (ret == act_ses) {
		disable_input_zmq(p_entry.res_pipe_in, ctx_priv->res_count);
		set_in_out_zmq(p_entry.res_host, ctx_priv->res_count);
		if (!timer_set) {
			set_timer(p_entry.ses_timer->fd,
				  ctx_priv->args.session_tmt_ms);
			timer_set = true;
			return;
		}
	}

	ret = handle_host_res_zmq(ctx, vhost, &p_entry, devnull);
	if (ret)
		enable_input_zmq(p_entry.res_pipe_in, ctx_priv->res_count);
	if (ret == act_ses) {
		set_timer(p_entry.ses_timer->fd, 0);
		timer_set = false;
	}
}

void handle_commands_zmq(struct rvgpu_ctx *ctx, struct vgpu_host *vhost[],
			 struct zmq_poll_entries p_entry, int devnull,
			 unsigned int act_ses)
{
	struct ctx_priv *ctx_priv = (struct ctx_priv *)ctx->priv;
	unsigned int ret;

	if (!act_ses) {
		flush_input_pipes(ctx_priv, devnull, COMMAND);
		enable_input_zmq(p_entry.cmd_pipe_in, ctx_priv->cmd_count);
		return;
	}
	ret = get_input_ev_zmq(p_entry.cmd_pipe_in, ctx_priv->cmd_count);
	if (ret == ctx_priv->cmd_count) {
		disable_input_zmq(p_entry.cmd_pipe_in, ctx_priv->cmd_count);
		set_in_out_zmq(p_entry.cmd_host, ctx_priv->cmd_count);
		return;
	}

	ret = handle_host_comm_zmq(ctx, vhost, &p_entry);
	if (ret)
		enable_input_zmq(p_entry.cmd_pipe_in, ctx_priv->cmd_count);
}

void *thread_conn_zmq(void *arg)
{
	struct rvgpu_ctx *ctx = (struct rvgpu_ctx *)arg;
	struct ctx_priv *ctx_priv = (struct ctx_priv *)ctx->priv;
	struct rvgpu_ctx_arguments *conn_args = &ctx_priv->args;
	struct vgpu_host *vhost[MAX_HOSTS];
	struct zmq_pollitem_t pfd[MAX_HOSTS * SOCKET_NUM + TIMERS_CNT];
	struct zmq_poll_entries p_entry;
	unsigned int pfd_count;
	int devnull;

	devnull = open("/dev/null", O_WRONLY);
	assert(devnull != -1);

	if (wait_scanouts_init(ctx_priv)) {
		warnx("Scanouts hasn't been initialized");
		return NULL;
	}

	if (zmq_init_publisher(ctx_priv->cmd)) {
		warnx("zmq_init_publisher error");
		return NULL;
	}

	connect_hosts(ctx_priv->res, ctx_priv->res_count,
		      conn_args->conn_tmt_s);

	pfd_count = set_pfd_zmq(ctx_priv, vhost, pfd, &p_entry);
	assert(pfd_count < MAX_HOSTS * SOCKET_NUM);

	unsigned int act_ses = ctx_priv->res_count;

	while (!ctx_priv->interrupted) {
		zmq_poll(pfd, pfd_count, -1);

		/* Check for hung sessions */
		if (p_entry.ses_timer->revents == ZMQ_POLLIN) {
			if (sessions_hung(ctx_priv, &vhost[ctx_priv->cmd_count],
					  &act_ses, ctx_priv->res_count)) {
				process_reset_backend(ctx, GPU_RESET_TRUE);
				set_timer(p_entry.recon_timer->fd,
					  conn_args->reconn_intv_ms);
			}
			set_timer(p_entry.ses_timer->fd, 0);
		}
		/* Try to reconnect */
		if (p_entry.recon_timer->revents == ZMQ_POLLIN) {
			if (sessions_reconnect(ctx, &vhost[ctx_priv->cmd_count],
					       p_entry.recon_timer->fd,
					       ctx_priv->res_count)) {
				set_timer(p_entry.recon_timer->fd, 0);
				set_timer(p_entry.ses_timer->fd, 0);
				act_ses = ctx_priv->res_count;
			}
		}
		/*
		 * For PGM additionally check state of resource hosts.
		 */
		if (resource_err_zmq(ctx_priv, p_entry.res_host,
				     &vhost[ctx_priv->cmd_count], &act_ses)) {
			process_reset_backend(ctx, GPU_RESET_TRUE);
			set_timer(p_entry.recon_timer->fd,
				  conn_args->reconn_intv_ms);
		}
		/* Handle commands */
		handle_commands_zmq(ctx, vhost, p_entry, devnull, act_ses);
		/* Handle resources */
		handle_resources_zmq(ctx, &vhost[ctx_priv->cmd_count], p_entry,
				     devnull, act_ses);
	}

	/* Release resources */
	for (unsigned int i = 0; i < ctx_priv->cmd_count; i++)
		zmq_close_publisher(ctx_priv->cmd);
	for (unsigned int i = 0; i < ctx_priv->res_count; i++)
		close(ctx_priv->res[i].sock);
	close(p_entry.recon_timer->fd);
	close(p_entry.ses_timer->fd);
	close(devnull);
	return NULL;
}
