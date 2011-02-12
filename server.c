
/*
 * Copyright 2011 Jeff Garzik
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#define _GNU_SOURCE
#include "autotools-config.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <locale.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <fcntl.h>
#include <string.h>
#include <netdb.h>
#include <stdarg.h>
#include <argp.h>
#include "server.h"

const char *argp_program_version = PACKAGE_VERSION;

enum {
	SFL_FOREGROUND		= (1 << 0),	/* run in foreground */
};

static struct argp_option options[] = {
#if 0
	{ "config", 'C', "FILE", 0,
	  "Read master configuration from FILE" },
#endif
	{ "debug", 'D', "LEVEL", 0,
	  "Set debug output to LEVEL (0 = off, 2 = max)" },
	{ "stderr", 'E', NULL, 0,
	  "Switch the log to standard error" },
	{ "foreground", 'F', NULL, 0,
	  "Run in foreground, do not fork" },
	{ "pid", 'P', "FILE", 0,
	  "Write daemon process id to FILE" },
	{ "strict-free", 1001, NULL, 0,
	  "For memory-checker runs.  When shutting down server, free local "
	  "heap, rather than simply exit(2)ing and letting OS clean up." },
	{ }
};

static const char doc[] =
PROGRAM_NAME " - push-mining proxy daemon";


static error_t parse_opt (int key, char *arg, struct argp_state *state);


static const struct argp argp = { options, parse_opt, NULL, doc };

static bool server_running = true;
static bool dump_stats;
bool use_syslog = true;
static bool strict_free = false;
int debugging = 0;
struct timeval current_time;

struct server srv = {
	.config		= "server.json",
};

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	int v;

	switch(key) {
#if 0
	case 'C':
		srv.config = arg;
		break;
#endif
	case 'D':
		v = atoi(arg);
		if (v < 0 || v > 2) {
			fprintf(stderr, "invalid debug level: '%s'\n", arg);
			argp_usage(state);
		}
		debugging = v;
		break;
	case 'E':
		use_syslog = false;
		break;
	case 'F':
		srv.flags |= SFL_FOREGROUND;
		break;
	case 'P':
		srv.pid_file = strdup(arg);
		break;
	case 1001:			/* --strict-free */
		strict_free = true;
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);	/* too many args */
		break;
	case ARGP_KEY_END:
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static struct client *cli_alloc(void)
{
	struct client *cli;

	cli = calloc(1, sizeof(*cli));
	if (!cli)
		return NULL;
	
	return cli;
}

static void cli_free(struct client *cli)
{
	if (!cli)
		return;
	
	if (cli->ev_mask && (event_del(&cli->ev) < 0))
		applog(LOG_ERR, "TCP cli poll del failed");

	/* clean up network socket */
	if (cli->fd >= 0) {
		if (close(cli->fd) < 0)
			syslogerr("close(2) TCP client socket");
	}

	if (debugging)
		applog(LOG_DEBUG, "client %s ended", cli->addr_host);
	
	free(cli);
}

static void tcp_cli_event(int fd, short events, void *userdata)
{
	struct client *cli = userdata;

	/* FIXME: do something */
	(void) cli;
}

static void tcp_srv_event(int fd, short events, void *userdata)
{
	struct server_socket *sock = userdata;
	socklen_t addrlen = sizeof(struct sockaddr_in6);
	struct client *cli;
	char host[64];
	char port[16];
	int on = 1;

	cli = cli_alloc();
	if (!cli) {
		applog(LOG_ERR, "out of memory");
		server_running = false;
		event_loopbreak();
		return;
	}

	/* receive TCP connection from kernel */
	cli->fd = accept(sock->fd, (struct sockaddr *) &cli->addr, &addrlen);
	if (cli->fd < 0) {
		syslogerr("tcp accept");
		goto err_out;
	}

	srv.stats.tcp_accept++;

	/* mark non-blocking, for upcoming poll use */
	if (fsetflags("tcp client", cli->fd, O_NONBLOCK) < 0)
		goto err_out_fd;

	/* disable delay of small output packets */
	if (setsockopt(cli->fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) < 0)
		applog(LOG_WARNING, "TCP_NODELAY failed: %s",
		       strerror(errno));

	event_set(&cli->ev, cli->fd, EV_READ | EV_PERSIST,
		  tcp_cli_event, cli);

	/* pretty-print incoming cxn info */
	getnameinfo((struct sockaddr *) &cli->addr, addrlen,
		    host, sizeof(host), port, sizeof(port),
		    NI_NUMERICHOST | NI_NUMERICSERV);
	host[sizeof(host) - 1] = 0;
	port[sizeof(port) - 1] = 0;
	applog(LOG_INFO, "client host %s port %s connected%s", host, port,
		false ? " via SSL" : "");

	strcpy(cli->addr_host, host);
	strcpy(cli->addr_port, port);

	if (event_add(&cli->ev, NULL) < 0) {
		applog(LOG_ERR, "unable to ready srv fd for polling");
		goto err_out_fd;
	}
	cli->ev_mask = EV_READ;

	return;

err_out_fd:
err_out:
	cli_free(cli);
}

static int net_write_port(const char *port_file, const char *port_str)
{
	FILE *portf;
	int rc;

	portf = fopen(port_file, "w");
	if (portf == NULL) {
		rc = errno;
		applog(LOG_INFO, "Cannot create port file %s: %s",
		       port_file, strerror(rc));
		return -rc;
	}
	fprintf(portf, "%s\n", port_str);
	fclose(portf);
	return 0;
}

static int net_open_socket(const struct listen_cfg *cfg,
			   int addr_fam, int sock_type, int sock_prot,
			   int addr_len, void *addr_ptr)
{
	struct server_socket *sock;
	int fd, on;
	int rc;

	fd = socket(addr_fam, sock_type, sock_prot);
	if (fd < 0) {
		rc = errno;
		syslogerr("tcp socket");
		return -rc;
	}

	on = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
		syslogerr("setsockopt(SO_REUSEADDR)");
		rc = -errno;
		goto err_out_fd;
	}

	if (bind(fd, addr_ptr, addr_len) < 0) {
		syslogerr("tcp bind");
		rc = -errno;
		goto err_out_fd;
	}

	if (listen(fd, 100) < 0) {
		syslogerr("tcp listen");
		rc = -errno;
		goto err_out_fd;
	}

	rc = fsetflags("tcp server", fd, O_NONBLOCK);
	if (rc)
		goto err_out_fd;

	sock = calloc(1, sizeof(*sock));
	if (!sock) {
		rc = -ENOMEM;
		goto err_out_fd;
	}

	INIT_LIST_HEAD(&sock->sockets_node);

	event_set(&sock->ev, fd, EV_READ | EV_PERSIST,
		  tcp_srv_event, sock);

	sock->fd = fd;
	sock->cfg = cfg;

	if (event_add(&sock->ev, NULL) < 0)
		goto err_out_sock;

	list_add_tail(&sock->sockets_node, &srv.sockets);

	return fd;

err_out_sock:
	free(sock);
err_out_fd:
	close(fd);
	return rc;
}

static int net_open_known(const struct listen_cfg *cfg)
{
	int ipv6_found = 0;
	int rc;
	struct addrinfo hints, *res, *res0;
	char port_str[16];

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	sprintf(port_str, "%d", cfg->port);

	rc = getaddrinfo(cfg->host, port_str, &hints, &res0);
	if (rc) {
		applog(LOG_ERR, "getaddrinfo(%s:%s) failed: %s",
		       cfg->host ? cfg->host : "*",
		       cfg->port, gai_strerror(rc));
		return -EINVAL;
	}

#ifdef __linux__
	/*
	 * We rely on getaddrinfo to discover if the box supports IPv6.
	 * Much easier to sanitize its output than to try to figure what
	 * to put into ai_family.
	 *
	 * These acrobatics are required on Linux because we should bind
	 * to ::0 if we want to listen to both ::0 and 0.0.0.0. Else, we
	 * may bind to 0.0.0.0 by accident (depending on order getaddrinfo
	 * returns them), then bind(::0) fails and we only listen to IPv4.
	 */
	for (res = res0; res; res = res->ai_next) {
		if (res->ai_family == PF_INET6)
			ipv6_found = 1;
	}
#endif

	for (res = res0; res; res = res->ai_next) {
		char listen_host[65], listen_serv[65];

		if (ipv6_found && res->ai_family == PF_INET)
			continue;

		rc = net_open_socket(cfg, res->ai_family, res->ai_socktype,
				     res->ai_protocol, 
				     res->ai_addrlen, res->ai_addr);
		if (rc < 0)
			goto err_out;

		getnameinfo(res->ai_addr, res->ai_addrlen,
			    listen_host, sizeof(listen_host),
			    listen_serv, sizeof(listen_serv),
			    NI_NUMERICHOST | NI_NUMERICSERV);

		applog(LOG_INFO, "Listening on host %s port %s",
		       listen_host, listen_serv);
	}

	freeaddrinfo(res0);

	if (cfg->port_file)
		net_write_port(cfg->port_file, port_str);
	return 0;

err_out:
	freeaddrinfo(res0);
	return rc;
}

/*
 * Find out own hostname.
 * This is needed for:
 *  - finding the local domain and its SRV records
 * Do this before our state machines start ticking, so we can quit with
 * a meaningful message easily.
 */
static char *get_hostname(void)
{
	enum { hostsz = 64 };
	char hostb[hostsz];
	char *ret;

	if (gethostname(hostb, hostsz-1) < 0) {
		applog(LOG_ERR, "get_hostname: gethostname error (%d): %s",
		       errno, strerror(errno));
		exit(1);
	}
	hostb[hostsz-1] = 0;
	if ((ret = strdup(hostb)) == NULL) {
		applog(LOG_ERR, "get_hostname: no core (%ld)",
		       (long)strlen(hostb));
		exit(1);
	}
	return ret;
}

static void term_signal(int signo)
{
	server_running = false;
	event_loopbreak();
}

static void stats_signal(int signo)
{
	dump_stats = true;
	event_loopbreak();
}

#define X(stat) \
	applog(LOG_INFO, "STAT %s %lu", #stat, srv.stats.stat)

static void stats_dump(void)
{
	X(poll);
	X(event);
	X(tcp_accept);
	X(opt_write);
}

#undef X

static int main_loop(void)
{
	int rc = 0;

	while (server_running) {
		event_dispatch();

		if (dump_stats) {
			dump_stats = false;
			stats_dump();
		}
	}
	
	return rc;
}

int main (int argc, char *argv[])
{
	error_t aprc;
	int rc = 1;
	struct list_head *tmpl;

	INIT_LIST_HEAD(&srv.listeners);
	INIT_LIST_HEAD(&srv.sockets);

	/* isspace() and strcasecmp() consistency requires this */
	setlocale(LC_ALL, "C");

	/*
	 * Unfortunately, our initialization order is rather rigid.
	 *
	 * First, parse command line. This way errors in parameters can
	 * be written to stderr, where they belong.
	 */
	aprc = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (aprc) {
		fprintf(stderr, "argp_parse failed: %s\n", strerror(aprc));
		return 1;
	}

	/*
	 * Next, open syslog. From now on, nothing goes to stderr, and
	 * we minimize (or hopefuly eliminate) opening libraries that
	 * do not have a switcheable diagnostic output.
	 */
	if (use_syslog)
		openlog(PROGRAM_NAME, LOG_PID, LOG_LOCAL3);
	if (debugging)
		applog(LOG_INFO, "Debug output enabled");

	srv.evbase_main = event_init();

	/*
	 * Next, read master configuration. This should be done as
	 * early as possible, so that tunables are available.
	 */
	read_config();
	if (!srv.ourhost)
		srv.ourhost = get_hostname();
	else if (debugging)
		applog(LOG_INFO, "Forcing local hostname to %s",
		       srv.ourhost);

	/*
	 * For example, backgrounding and PID file should be done early
	 * (before we do anything that can conflict with other instance),
	 * but not before read_config().
	 */
	if (!(srv.flags & SFL_FOREGROUND) && (daemon(1, !use_syslog) < 0)) {
		syslogerr("daemon");
		goto err_out;
	}

	rc = write_pid_file(srv.pid_file);
	if (rc < 0)
		goto err_out;
	srv.pid_fd = rc;

	/*
	 * properly capture TERM and other signals
	 */
	signal(SIGHUP, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, term_signal);
	signal(SIGTERM, term_signal);
	signal(SIGUSR1, stats_signal);

	/* set up server networking */
	list_for_each(tmpl, &srv.listeners) {
		struct listen_cfg *tmpcfg;

		tmpcfg = list_entry(tmpl, struct listen_cfg, listeners_node);
		rc = net_open_known(tmpcfg);
		if (rc)
			goto err_out_listen;
	}

	applog(LOG_INFO, "initialized");

	rc = main_loop();

	applog(LOG_INFO, "shutting down");

err_out_listen:
	/* we ignore closing sockets, as process exit does that for us */
	unlink(srv.pid_file);
	close(srv.pid_fd);
err_out:
	closelog();
	return rc;
}

