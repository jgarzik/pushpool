#ifndef __SERVER_H__
#define __SERVER_H__

#include <stdbool.h>
#include <event.h>
#include <netinet/in.h>
#include "elist.h"

#define PROGRAM_NAME "pushpoold"

struct client {
	struct sockaddr_in6	addr;		/* inet address */
	char			addr_host[64];	/* ASCII version of inet addr */
	char			addr_port[16];	/* ASCII version of port */
	int			fd;		/* socket */
	struct event		ev;
	short			ev_mask;	/* EV_READ and/or EV_WRITE */
};

struct server_stats {
	unsigned long		poll;		/* number polls */
	unsigned long		event;		/* events dispatched */
	unsigned long		tcp_accept;	/* TCP accepted cxns */
	unsigned long		opt_write;	/* optimistic writes */
};

struct server_socket {
	int			fd;
	const struct listen_cfg	*cfg;
	struct event		ev;
	struct list_head	sockets_node;
};

struct listen_cfg {
	char			*host;
	int			port;
	char			*port_file;
	struct list_head	listeners_node;
};

struct server {
	unsigned long		flags;		/* SFL_xxx above */

	char			*config;	/* master config file */
	char			*pid_file;	/* PID file */
	int			pid_fd;

	struct event_base	*evbase_main;

	char			*ourhost;

	struct list_head	listeners;
	struct list_head	sockets;	/* points into listeners */

	struct server_stats	stats;		/* global statistics */
};

/* config.c */
extern void read_config(void);

/* server.c */
extern bool use_syslog;
extern struct server srv;

/* util.c */
extern void applog(int prio, const char *fmt, ...);
extern int write_pid_file(const char *pid_fn);
extern void syslogerr(const char *prefix);
extern int fsetflags(const char *prefix, int fd, int or_flags);

#endif /* __SERVER_H__ */
