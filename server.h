#ifndef __SERVER_H__
#define __SERVER_H__

/*
 * Copyright 2011 Jeff Garzik
 * Copyright 2009 Red Hat, Inc.
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

#include <stdbool.h>
#include <event.h>
#include <netinet/in.h>
#include <jansson.h>
#include <curl/curl.h>
#include "elist.h"
#include "ubbp.h"
#include "protocol.h"

#define PROGRAM_NAME "pushpoold"

struct tcp_read {
	void			*buf;		/* ptr to storage buffer */
	unsigned int		len;		/* total storage size */
	unsigned int		curlen;		/* amount of buffer in use */
	bool			(*cb)(void *, void *, bool); /* callback*/
	void			*priv;		/* app-private callback arg */
	struct list_head	node;
};

struct tcp_read_state {
	struct list_head	q;		/* read queue */
	int			fd;		/* network socket fd */
	void			*priv;		/* app-specific data */
};

struct client {
	struct sockaddr_in6	addr;		/* inet address */
	char			addr_host[64];	/* ASCII version of inet addr */
	char			addr_port[16];	/* ASCII version of port */
	int			fd;		/* socket */
	struct event		ev;
	short			ev_mask;	/* EV_READ and/or EV_WRITE */

	struct tcp_read_state	rst;

	bool			logged_in;

	struct ubbp_header	ubbp;

	void			*msg;
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

	CURL			*curl;

	char			*ourhost;

	char			*rpc_url;
	char			*rpc_userpass;

	struct list_head	listeners;
	struct list_head	sockets;	/* points into listeners */

	struct server_stats	stats;		/* global statistics */
};

/* config.c */
extern void read_config(void);

/* msg.c */
extern bool cli_op_login(struct client *cli, const json_t *obj,
			 unsigned int msgsz);
extern bool cli_op_config(struct client *cli, const json_t *obj);
extern bool cli_op_work_get(struct client *cli, unsigned int msgsz);
extern bool cli_op_work_submit(struct client *cli, unsigned int msgsz);

/* server.c */
extern int debugging;
extern bool use_syslog;
extern struct server srv;
extern bool cjson_encode(unsigned char op, const char *obj_unc,
		  void **msg_out, size_t *msglen_out);
extern bool cjson_encode_obj(unsigned char op, const json_t *obj,
		  void **msg_out, size_t *msglen_out);
extern bool cli_send_msg(struct client *cli, const void *msg, size_t msg_len);
extern bool cli_send_hdronly(struct client *cli, unsigned char op);
extern bool cli_send_obj(struct client *cli, unsigned char op, const json_t *obj);
extern bool cli_send_err(struct client *cli, unsigned char op,
		  int err_code, const char *err_msg);

/* util.c */
extern void applog(int prio, const char *fmt, ...);
extern int write_pid_file(const char *pid_fn);
extern void syslogerr(const char *prefix);
extern int fsetflags(const char *prefix, int fd, int or_flags);
extern json_t *json_rpc_call(CURL *curl, const char *url,
		      const char *userpass, const char *rpc_req);
extern char *bin2hex(unsigned char *p, size_t len);
extern bool hex2bin(unsigned char *p, const char *hexstr, size_t len);

#endif /* __SERVER_H__ */
