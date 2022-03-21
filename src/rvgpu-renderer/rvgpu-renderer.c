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
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <rvgpu-generic/rvgpu-sanity.h>
#include <rvgpu-generic/rvgpu-utils.h>
#include <rvgpu-renderer/renderer/rvgpu-egl.h>
#include <rvgpu-renderer/rvgpu-renderer.h>
#include <rvgpu-renderer/zmq/rvgpu-zmq.h>

#include <linux/virtio_gpu.h>

static sig_atomic_t reset_fps;

static void usage(void)
{
	static const char program_name[] = "rvgpu-renderer";

	info("Usage: %s [options]\n", program_name);
	info("\t-a\t\tenable translucent mode on Wayland\n");
	info("\t-B color\tcolor of initial screen in RGBA format");
	info("(default is 0x%x)\n", BACKEND_COLOR);
	info("\t-c capset\tdump capset into file\n");
	info("\t-b box\t\toverride scanout box (format WxH@X,Y)\n");
	info("\t-i ID\t\tset scanout window ID (for IVI shell)\n");
	info("\t-I\t\tenable initialization profiling\n");
	info("\t-g card\t\tuse GBM mode on card (/dev/dri/cardN)\n");
	info("\t-S seat\t\tspecify seat for input in GBM mode\n");
	info("\t-f\t\tRun in fullscreen mode\n");
	info("\t-p port\t\tport for listening\n");
	info("\t-v\t\tRun in vsync mode (eglSwapInterval 1)\n");
	info("\t-t file\t\tdump timestamp into file\n");
	info("\t-d\t\tdump framerate upon SIGHUP\n");
	info("\t-Z address\tEndpoint address for ZeroMQ protocol\n");
	info("\t\t\te.g 'epgm://192.168.7.1;224.0.0.1:5555'\n");
	info("\t\t\te.g 'pgm://127.0.0.1;224.0.0.1:5555'\n");
	info("\t-r\t\tspecify ZeroMQ rate limit in kilobits ");
	info("(default is %d)\n", RVGPU_RENDERER_DEFAULT_ZMQ_RATE);
	info("\t-L interval\tZeroMQ recovery interval (default is %d)\n",
	     RVGPU_RENDERER_DEFAULT_ZMQ_RECOVERY_MS);
	info("\t-m\t\tReduce memory use by skipping late OpenGL commands\n");
	info("\t-C\t\tMax size of memory reserved for FS caching in MB.\n");
	info("\t\t\tWorks only in case the same feature enabled on ");
	info("rvgpu-proxy side\n");
	info("\t-h\t\tShow this message\n");
}

/* Signal handler to reap zombie processes */
static void wait_for_child(int sig)
{
	(void)sig;
	while (waitpid(-1, NULL, WNOHANG) > 0)
		;
}

/* Signal handler to measure framerate */
static void count_fps(int sig)
{
	(void)sig;
	reset_fps = 1;
}

static FILE *listen_conn(uint16_t port_nr, int *res_socket,
			 struct zmq_params *zmq_p)
{
	int sock, newsock = -1;
	struct sigaction sa;
	struct sockaddr_in server_addr = {0};
	int reuseaddr = 1; /* True */
	int fin_wait = 1;  /* FIN wait timeout */
	pid_t pid = 0;

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == -1)
		err(1, "socket");

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuseaddr,
		       sizeof(int)) == -1) {
		err(1, "setsockopt");
	}

	if (setsockopt(sock, SOL_TCP, TCP_LINGER2, &fin_wait, sizeof(int)) ==
	    -1) {
		err(1, "setsockopt");
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(port_nr);

	if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) ==
	    -1) {
		err(1, "bind");
	}

	if (listen(sock, BACKLOG) == -1)
		err(1, "listen");

	sa.sa_handler = wait_for_child;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1)
		err(1, "sigaction");

	while (1) {
		if (!zmq_p) {
			newsock = accept4(sock, NULL, NULL, SOCK_NONBLOCK);
			if (newsock == -1)
				err(1, "accept");
		}

		*res_socket = accept4(sock, NULL, NULL, SOCK_NONBLOCK);
		if (*res_socket == -1)
			err(1, "accept");

		if (pid > 0) {
			kill(pid, SIGTERM);
			/*
			 * sleep for 100 ms until all child resources
			 * will be freed
			 */
			usleep(100 * 1000);
		}

		pid = fork();
		switch (pid) {
		case 0: /* In child process */
		{
			if (!zmq_p) {
				FILE *ret;

				close(sock);
				dup2(newsock, 0);
				ret = fdopen(newsock, "w");
				setvbuf(ret, NULL, _IOFBF, BUFSIZ);
				return ret;
			}

			close(sock);
			zmq_p->st = zmq_init_subscriber(zmq_p->zmq_addr,
							zmq_p->zmq_rate,
							zmq_p->zmq_recovery_ms);
			return NULL;
		}
		case -1: /* fork failed */
			err(1, "fork");
		default: /* Parent process */
			if (newsock > 0)
				close(newsock);
			if (*res_socket > 0)
				close(*res_socket);
		}
	}

	close(sock);
	return NULL;
}

int main(int argc, char **argv)
{
	struct rvgpu_pr_state *pr;
	struct rvgpu_egl_state *egl;
	struct rvgpu_scanout_params sp[VIRTIO_GPU_MAX_SCANOUTS], *cp = &sp[0];
	struct rvgpu_pr_params pp = {
	    .sp = sp,
	    .nsp = VIRTIO_GPU_MAX_SCANOUTS,
	};
	struct zmq_params zmq_p = {
	    .zmq_rate = RVGPU_RENDERER_DEFAULT_ZMQ_RATE,
	    .zmq_recovery_ms = RVGPU_RENDERER_DEFAULT_ZMQ_RECOVERY_MS,
	};
	struct thread_shared_res *rts = NULL;
	struct rvgpu_egl_params e_params = {
	    .clear_color = BACKEND_COLOR,
	};
	struct timespec time_s;
	char *errstr = NULL;
	const char *carddev = NULL;
	const char *seat = "seat0";
	int opt, res, res_socket = 0;
	unsigned int res_id, scanout, frames = 0;
	uint16_t port_nr = 0;
	FILE *input_stream = stdout;
	pthread_t offload_thread;
	bool fullscreen = false, vsync = false, translucent = false,
	     reduce_memory = false, user_specified_scanouts = false,
	     dump_fps = false;

	memset(sp, 0, sizeof(sp));

	while ((opt = getopt(argc, argv,
			     "afhvdmIi:t:c:s:S:b:B:p:g:Z:r:L:C:")) != -1) {
		switch (opt) {
		case 'a':
			translucent = true;
			break;
		case 'B':
			e_params.clear_color =
			    (unsigned int)strtoul(optarg, NULL, 16);
			break;

		case 'c':
			pp.capset = fopen(optarg, "w");
			if (pp.capset == NULL)
				err(1, "cannot open %s for writing", optarg);
			break;
		case 's':
			scanout = (unsigned int)sanity_strtounum(
			    optarg, 0, VIRTIO_GPU_MAX_SCANOUTS - 1, &errstr);
			if (errstr != NULL) {
				warnx("Scanout number should be in [%u..%u]\n",
				      0, VIRTIO_GPU_MAX_SCANOUTS);
				errx(1, "Invalid scanout %s:%s", optarg,
				     errstr);
			}
			cp = &sp[scanout];
			cp->enabled = true;
			user_specified_scanouts = true;
			break;
		case 'b':
			if (sscanf(optarg, "%ux%u@%u,%u", &cp->box.w,
				   &cp->box.h, &cp->box.x, &cp->box.y) != 4) {
				errx(1, "invalid scanout box %s", optarg);
			}
			cp->boxed = true;
			break;
		case 'd':
			dump_fps = true;
			break;
		case 'i':
			cp->id = (uint32_t)sanity_strtounum(
			    optarg, 1, UINT32_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "Invalid IVI id specified %s:%s",
				     optarg, errstr);
			break;
		case 'I':
			pp.inprof = true;
			break;
		case 'g':
			carddev = optarg;
			break;
		case 'S':
			seat = optarg;
			break;
		case 'f':
			fullscreen = true;
			break;
		case 'p':
			port_nr = (uint16_t)sanity_strtounum(
			    optarg, MIN_PORT_NUMBER, MAX_PORT_NUMBER, &errstr);
			if (errstr != NULL) {
				warnx("Port number should be in [%u..%u]\n",
				      MIN_PORT_NUMBER, MAX_PORT_NUMBER);
				errx(1, "Invalid scanout %s:%s", optarg,
				     errstr);
			}
			break;
		case 'v':
			vsync = true;
			break;
		case 't':
			pp.timestamp = fopen(optarg, "w");
			if (pp.timestamp == NULL)
				err(1, "cannot open %s for writing", optarg);
			break;
		case 'Z':
			zmq_p.zmq_addr = optarg;
			break;
		case 'r':
			zmq_p.zmq_rate = (unsigned int)sanity_strtounum(
			    optarg, RVGPU_RENDERER_MIN_ZMQ_RATE,
			    RVGPU_RENDERER_MAX_ZMQ_RATE, &errstr);
			if (errstr != NULL) {
				warnx("ZeroMQ rate should be in [%u..%u]\n",
				      RVGPU_RENDERER_MIN_ZMQ_RATE,
				      RVGPU_RENDERER_MAX_ZMQ_RATE);
				errx(1, "Invalid ZeroMQ rate %s:%s", optarg,
				     errstr);
			}
			break;
		case 'L':
			zmq_p.zmq_recovery_ms = (unsigned int)sanity_strtounum(
			    optarg, RVGPU_RENDERER_MIN_ZMQ_RECOVERY_MS,
			    RVGPU_RENDERER_MAX_ZMQ_RECOVERY_MS, &errstr);
			if (errstr != NULL) {
				warnx("ZeroMQ recovery should be in [%u..%u]\n",
				      RVGPU_RENDERER_MIN_ZMQ_RECOVERY_MS,
				      RVGPU_RENDERER_MAX_ZMQ_RECOVERY_MS);
				errx(1, "Invalid ZeroMQ recovery %s:%s", optarg,
				     errstr);
			}
			break;
		case 'm':
			reduce_memory = true;
			break;
		case 'C':
			pp.split_resources = true;
			pp.fs_cache_size = (unsigned int)sanity_strtounum(
			    optarg, RVGPU_RENDERER_MIN_CACHE_SIZE_MB,
			    RVGPU_RENDERER_MAX_CACHE_SIZE_MB, &errstr);
			if (errstr != NULL) {
				warnx("Cache size should be in [%u..%u]\n",
				      RVGPU_RENDERER_MIN_CACHE_SIZE_MB,
				      RVGPU_RENDERER_MAX_CACHE_SIZE_MB);
				errx(1, "Invalid cache size %s:%s", optarg,
				     errstr);
			}
			break;
		case 'h':
			usage();
			exit(EXIT_SUCCESS);
		default:
			usage();
			exit(EXIT_FAILURE);
		}
	}

	if (!user_specified_scanouts) {
		/* enable all scanouts if no -s option is given */
		for (unsigned int i = 0; i < VIRTIO_GPU_MAX_SCANOUTS; i++)
			sp[i].enabled = true;
	}

	if (zmq_p.zmq_addr) {
		listen_conn(port_nr, &res_socket, &zmq_p);
	} else {
		input_stream = listen_conn(port_nr, &res_socket, NULL);
		assert(input_stream);
	}

#ifdef SKIP_OPENGL_CMDS
	if (reduce_memory) {
		rts = calloc(1, sizeof(*rts));
		rts->res_socket = res_socket;
		rts->split_resources = pp.split_resources;
		res_socket = 0;
	}
#endif

	if (carddev == NULL)
		egl = rvgpu_wl_init(fullscreen, translucent, input_stream);
	else
		egl = rvgpu_gbm_init(carddev, seat, input_stream);

	egl->params = &e_params;

	if (dump_fps) {
		struct sigaction sa = {
		    .sa_handler = count_fps,
		    .sa_flags = SA_RESTART,
		};
		sigemptyset(&sa.sa_mask);
		sigaddset(&sa.sa_mask, SIGHUP);
		if (sigaction(SIGHUP, &sa, NULL) == -1)
			err(1, "sigaction");

		clock_gettime(CLOCK_MONOTONIC, &time_s);
	}

	pr = rvgpu_pr_init(egl, zmq_p.st, &pp, rts, res_socket);

	for (unsigned int i = 0; i < VIRTIO_GPU_MAX_SCANOUTS; i++) {
		struct rvgpu_scanout *s = &egl->scanouts[i];

		s->scanout_id = i;
		s->params = sp[i];
	}

	if (user_specified_scanouts) {
		for (unsigned int i = 0; i < VIRTIO_GPU_MAX_SCANOUTS; i++) {
			if (sp[i].enabled) {
				rvgpu_egl_create_scanout(egl,
							 &egl->scanouts[i]);
				rvgpu_egl_draw(egl, &egl->scanouts[i], false);
			}
		}
	} else {
		/* Create scanout 0, as it is required to exist */
		rvgpu_egl_create_scanout(egl, &egl->scanouts[0]);
		rvgpu_egl_draw(egl, &egl->scanouts[0], false);
	}
	if (rts) {
		res = pthread_create(&offload_thread, NULL, offload_thread_func,
				     rts);
		if (res != 0)
			err(1, "could not create thread");
	}

	while ((res_id = rvgpu_pr_dispatch(pr))) {
		rvgpu_egl_drawall(egl, res_id, vsync);
		frames++;

		if (dump_fps && (reset_fps != 0)) {
			double elapsed;
			struct timespec time_e;

			clock_gettime(CLOCK_MONOTONIC, &time_e);
			elapsed = (time_e.tv_sec - time_s.tv_sec) +
				  (time_e.tv_nsec - time_s.tv_nsec) * 1E-9;
			info("%u frames in %.1f s FPS: %.1f\n", frames, elapsed,
			     frames / elapsed);
			reset_fps = 0;
			frames = 0;
			time_s = time_e;
		}
	}

	if (rts) {
		pthread_cancel(offload_thread);
		res = pthread_join(offload_thread, NULL);
		if (res != 0)
			err(1, "could not join thread");
		free(rts);
	}

	if (pp.capset)
		fclose(pp.capset);

	if (pp.timestamp)
		fclose(pp.timestamp);

	rvgpu_pr_free(pr);
	rvgpu_egl_free(egl);
	fclose(input_stream);

	return EXIT_SUCCESS;
}
