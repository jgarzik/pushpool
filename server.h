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

#include "autotools-config.h"

#include <stdbool.h>
#include <event.h>
#include <evhttp.h>
#include <netinet/in.h>
#include <jansson.h>
#include <curl/curl.h>
#include <libmemcached/memcached.h>
#include "elist.h"
#include "ubbp.h"
#include "protocol.h"
#include "anet.h"
#include "htab.h"

#define PROGRAM_NAME "pushpoold"

#if defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#include <machine/endian.h>
#define le32toh OSSwapLittleToHostInt32
#define htole32 OSSwapHostToLittleInt32
#define bswap_32 OSSwapInt32
#elif defined(HAVE_SYS_ENDIAN_H)
#include <sys/endian.h>
#define bswap_32 bswap32
#else
#include <byteswap.h>
#include <endian.h>
#endif

#ifndef MIN
#define	MIN(a,b) (((a)<(b))?(a):(b))
#endif
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#if LIBMEMCACHED_VERSION_HEX < 0x00036000
typedef memcached_return memcached_return_t;
#endif
#if JANSSON_MAJOR_VERSION >= 2
#define JSON_LOADS(str, err_ptr) json_loads((str), 0, (err_ptr))
#else
#define JSON_LOADS(str, err_ptr) json_loads((str), (err_ptr))
#endif

struct hist;

struct client {
	struct sockaddr_in6	addr;		/* inet address */
	char			addr_host[64];	/* ASCII version of inet addr */
	char			addr_port[16];	/* ASCII version of port */
	int			fd;		/* socket */
	struct event		ev;
	short			ev_mask;	/* EV_READ and/or EV_WRITE */

	struct tcp_read_state	rst;

	bool			logged_in;
	char			auth_user[33];	/* authenticated username */

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
	struct evhttp		*http;
	struct elist_head	sockets_node;
};

enum listen_protocol {
	LP_BC_BINARY,
	LP_HTTP_JSON,
};

struct listen_cfg {
	char			*host;
	int			port;
	char			*port_file;
	enum listen_protocol	proto;
	struct elist_head	listeners_node;
	char			*proxy;
};

struct genlist {
	void			*data;
	size_t			data_len;
	struct elist_head	node;
};

struct server_db_ops {
	char	* (*pwdb_lookup)(const char *user);
	bool	(*sharelog)(const char *rem_host, const char *username,
			    const char *our_result, const char *upstream_result,
			    const char *reason, const char *solution);
	bool	(*open)(void);
	void	(*close)(void);
};

enum server_db_eng {
	SDB_SQLITE,
	SDB_MYSQL,
	SDB_POSTGRESQL,
};

struct server {
	unsigned long		flags;		/* SFL_xxx above */

	char			*config;	/* master config file */
	char			*pid_file;	/* PID file */
	int			pid_fd;

	char			*req_log;	/* client request log */
	int			req_fd;

	char			*share_log;	/* client share log */
	int			share_fd;

	struct event_base	*evbase_main;

	CURL			*curl;

	char			*ourhost;

	char			*rpc_url;
	char			*rpc_userpass;
	json_t			*easy_target;

	enum server_db_eng	db_eng;
	struct server_db_ops	*db_ops;

	char			*db_host;
	int			db_port;
	char			*db_name;
	char			*db_username;
	char			*db_password;
	bool			db_sharelog;
	char			*db_stmt_pwdb;
	char			*db_stmt_sharelog;
	void			*db_cxn;

	struct hist		*hist;
	unsigned char		last_prevhash[32];
	unsigned char		cur_prevhash[32];
    unsigned char   cur_target[32];

	struct htab		*workers;
	struct elist_head	work_log;
    bool    initiate_lp_flush;
	unsigned int		work_expire;
	char			*work_expire_str;

	unsigned int		cred_expire;

	struct elist_head	lp_waiters;
	bool			disable_lp;
	bool			disable_roll_ntime;

	memcached_st		*mc;

	struct elist_head	listeners;
	struct elist_head	sockets;	/* points into listeners */

	struct server_stats	stats;		/* global statistics */

    bool            scrypt;
};

/* config.c */
extern void read_config(void);

/* msg.c */
extern char *pwdb_lookup(const char *user);
extern void worker_log_expire(time_t expire_time);
extern bool cli_op_login(struct client *cli, const json_t *obj,
			 unsigned int msgsz);
extern bool cli_op_config(struct client *cli, const json_t *obj);
extern bool cli_op_work_get(struct client *cli, unsigned int msgsz);
extern bool cli_op_work_submit(struct client *cli, unsigned int msgsz);
extern bool msg_json_rpc(struct evhttp_request *req, json_t *jreq,
			 const char *username,
			 void **reply, unsigned int *reply_len);
extern void hist_free(struct hist *hist);
extern struct hist *hist_alloc(void);
extern bool hist_add(struct hist *hist, const unsigned char *hash);
extern bool hist_lookup(struct hist *hist, const unsigned char *hash);

/* server.c */
extern int debugging;
extern bool use_syslog;
extern struct server srv;
extern void sharelog(const char *rem_host, const char *username,
		     const char *, const char *,
		     const char *, const char *);
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
extern unsigned char * g_base64_decode (const char *text, size_t *out_len);

/* db-*.c */
#ifdef HAVE_SQLITE3
extern struct server_db_ops sqlite_db_ops;
#endif
#ifdef HAVE_MYSQL
extern struct server_db_ops mysql_db_ops;
#endif
#ifdef HAVE_POSTGRESQL
extern struct server_db_ops postgresql_db_ops;
#endif

#endif /* __SERVER_H__ */
