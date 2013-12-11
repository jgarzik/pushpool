
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "autotools-config.h"

#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <jansson.h>
#include "server.h"

#define EASY_TARGET "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000"

static char *read_commented_file(const char *fn)
{
	char linebuf[512], *line;
	struct stat st;
	char *data = NULL;

	FILE *f = fopen(fn, "r");
	if (!f) {
		applog(LOG_ERR, "config file(%s): %s", fn, strerror(errno));
		goto err_out;
	}

	/* allocate buffer the size of the file (+1 nul byte) */
	if (fstat(fileno(f), &st)) {
		applog(LOG_ERR, "stat config file(%s): %s", fn,strerror(errno));
		goto err_out_close;
	}

	data = calloc(1, st.st_size + 1);
	if (!data)
		goto err_out_close;

	/* read file line by line */
	while ((line = fgets(linebuf, sizeof(linebuf), f)) != NULL) {
		int i;
		size_t linelen;
		bool is_comment;

		if (!memchr(line, '\n', sizeof(linebuf))) {
			applog(LOG_ERR, "config file(%s) line too long", fn);
			goto err_out_close;
		}

		linelen = strlen(line);

		/* scan for line matching regex '^\s*#' */
		is_comment = true;
		for (i = 0; i < linelen; i++) {
			int ch;

			ch = line[i];

			if (isspace(ch)) {
				/* do nothing */
			} else if (ch == '#')
				break;
			else {
				is_comment = false;
				break;
			}
		}

		/* if it's not a comment, add it to our data buffer */
		if (!is_comment)
			strcat(data, line);
	}

	fclose(f);

	return data;

err_out_close:
	fclose(f);
err_out:
	free(data);
	return NULL;
}

static void parse_listen(const json_t *listeners)
{
	int i, len;

	len = json_array_size(listeners);

	for (i = 0; i < len; i++) {
		json_t *obj;
		const char *host_str, *proto_str, *proxy_str;
		int port;
		struct listen_cfg *lc;

		obj = json_array_get(listeners, i);

		host_str = json_string_value(json_object_get(obj, "host"));
		if (host_str && (!*host_str || !strcmp(host_str, "*")))
			host_str = NULL;

		port = json_integer_value(json_object_get(obj, "port"));
		if (port < 1 || port > 65535) {
			applog(LOG_WARNING, "invalid listen config: port");
			continue;
		}

		proxy_str = json_string_value(json_object_get(obj, "proxy"));
		if (proxy_str && !*proxy_str)
			proxy_str = NULL;

		lc = calloc(1, sizeof(*lc));
		if (!lc) {
			applog(LOG_ERR, "OOM");
			exit(1);
		}

		lc->proto = LP_BC_BINARY;
		proto_str = json_string_value(json_object_get(obj, "protocol"));
		if (proto_str) {
			if (!strcmp(proto_str, "http-json"))
				lc->proto = LP_HTTP_JSON;
			else if (!strcmp(proto_str, "binary"))
				lc->proto = LP_BC_BINARY;
		}

		INIT_ELIST_HEAD(&lc->listeners_node);

		if (host_str)
			lc->host = strdup(host_str);
		lc->port = port;
		if (proxy_str)
			lc->proxy = strdup(proxy_str);

		elist_add_tail(&lc->listeners_node, &srv.listeners);
	}
}

static void parse_memcached_server(const json_t *obj)
{
	const json_t *tmp;
	const char *host;
	int port = -1;

	if (!json_is_object(obj))
		return;

	host = json_string_value(json_object_get(obj, "host"));
	if (!host || !*host)
		host = "127.0.0.1";

	tmp = json_object_get(obj, "port");
	if (json_is_integer(tmp)) {
		port = json_integer_value(tmp);
		if (port < 1 || port > 65535) {
			applog(LOG_ERR, "invalid memcached port");
			exit(1);
		}
	} else
		port = 11211;

	memcached_server_add(srv.mc, host, port);
}

static void parse_memcached(const json_t *obj)
{
	json_t *servers;

	if (!json_is_object(obj)) {
		/* No memcached config so don't use it. */
		memcached_free(srv.mc);
		srv.mc = NULL;
		return;
	}

	servers = json_object_get(obj, "servers");
	if (json_is_array(servers)) {
		unsigned int i, size = json_array_size(servers);

		for (i = 0; i < size; i++) {
			json_t *server_obj;

			server_obj = json_array_get(servers, i);
			parse_memcached_server(server_obj);
		}
	}
}

static void parse_database(const json_t *db_obj)
{
	const json_t *tmp;
	const char *db_host, *db_name, *db_un, *db_pw, *db_st_pwdb, *db_st_sharelog, *tmp_str;
	int db_port = -1;

	if (!json_is_object(db_obj))
		return;

	tmp_str = json_string_value(json_object_get(db_obj, "engine"));
	if (tmp_str) {
		if (0) {
#ifdef HAVE_SQLITE3 /**/
		} else if (!strcmp(tmp_str, "sqlite3")) {
			srv.db_eng = SDB_SQLITE;
			srv.db_ops = &sqlite_db_ops;
#endif
#ifdef HAVE_MYSQL
		} else if (!strcmp(tmp_str, "mysql")) {
			srv.db_eng = SDB_MYSQL;
			srv.db_ops = &mysql_db_ops;
#endif
#ifdef HAVE_POSTGRESQL
		} else if (!strcmp(tmp_str, "postgresql")) {
			srv.db_eng = SDB_POSTGRESQL;
			srv.db_ops = &postgresql_db_ops;
#endif
		} else {
			applog(LOG_ERR, "invalid database.engine");
			exit(1);
		}
	}

	db_host = json_string_value(json_object_get(db_obj, "host"));
	tmp = json_object_get(db_obj, "port");
	if (json_is_integer(tmp)) {
		db_port = json_integer_value(tmp);
		if (db_port < 1 || db_port > 65535) {
			applog(LOG_ERR, "invalid database port");
			exit(1);
		}
	}

	db_name = json_string_value(json_object_get(db_obj, "name"));
	db_un = json_string_value(json_object_get(db_obj, "username"));
	db_pw = json_string_value(json_object_get(db_obj, "password"));
	srv.db_sharelog = (json_is_true(json_object_get(db_obj, "sharelog"))) ?
		true : false;

	switch (srv.db_eng) {

	case SDB_SQLITE:
		if (db_host || db_port >= 0 || db_un || db_pw) {
			applog(LOG_ERR, "sqlite does not support database host"
			       ", port, username or password");
			exit(1);
		}
		if (!db_name || (*db_name != '/')) {
			applog(LOG_ERR, "missing or invalid database.name");
			exit(1);
		}

		srv.db_name = strdup(db_name);
		break;

	default:
		if (!db_host)
			db_host = "localhost";
		if (db_port < 0)
			db_port = -1;
		if (!db_name || !db_un || !db_pw) {
			applog(LOG_ERR, "missing database name, user or pass");
			exit(1);
		}

		srv.db_host = strdup(db_host);
		srv.db_port = db_port;
		srv.db_name = strdup(db_name);
		srv.db_username = strdup(db_un);
		srv.db_password = strdup(db_pw);
		break;
	}

	db_st_pwdb = json_string_value(json_object_get(db_obj, "stmt.pwdb"));
	if (db_st_pwdb)
		srv.db_stmt_pwdb = strdup(db_st_pwdb);
	db_st_sharelog = json_string_value(
		json_object_get(db_obj, "stmt.sharelog"));
	if (db_st_sharelog)
		srv.db_stmt_sharelog = strdup(db_st_sharelog);
}

void read_config(void)
{
	json_t *jcfg, *cred_expire, *tmp_json;
	json_error_t err;
	const char *tmp_str, *rpcuser, *rpcpass;
	char *file_data;

	file_data = read_commented_file(srv.config);
	if (!file_data)
		exit(1);

	jcfg = JSON_LOADS(file_data, &err);

	free(file_data);

	if (!jcfg) {
		applog(LOG_ERR, "%s: JSON parse failed", srv.config);
		exit(1);
	}

	if (!json_is_object(jcfg)) {
		applog(LOG_ERR, "top-level JSON value not an object");
		exit(1);
	}

	parse_listen(json_object_get(jcfg, "listen"));
	parse_database(json_object_get(jcfg, "database"));
	parse_memcached(json_object_get(jcfg, "memcached"));

	if (elist_empty(&srv.listeners)) {
		applog(LOG_ERR, "error: no listen addresses specified");
		exit(1);
	}

	tmp_str = json_string_value(json_object_get(jcfg, "pid"));
	if (tmp_str)
		srv.pid_file = strdup(tmp_str);

	tmp_str = json_string_value(json_object_get(jcfg, "forcehost"));
	if (tmp_str)
		srv.ourhost = strdup(tmp_str);

	tmp_str = json_string_value(json_object_get(jcfg, "log.requests"));
	if (tmp_str) {
		srv.req_log = strdup(tmp_str);
		srv.req_fd = open(srv.req_log,
				  O_WRONLY | O_CREAT | O_APPEND, 0666);
		if (srv.req_fd < 0) {
			syslogerr(srv.req_log);
			exit(1);
		}
	}

	tmp_str = json_string_value(json_object_get(jcfg, "log.shares"));
	if (tmp_str) {
		srv.share_log = strdup(tmp_str);
		srv.share_fd = open(srv.share_log,
				  O_WRONLY | O_CREAT | O_APPEND, 0666);
		if (srv.share_fd < 0) {
			syslogerr(srv.share_log);
			exit(1);
		}
	}

	if (json_is_true(json_object_get(jcfg, "longpoll.disable")))
		srv.disable_lp = true;

	cred_expire = json_object_get(jcfg, "auth.cred_cache.expire");
	if (json_is_integer(cred_expire))
		srv.cred_expire = json_integer_value(cred_expire);

	tmp_str = json_string_value(json_object_get(jcfg, "rpc.url"));
	if (!tmp_str) {
		applog(LOG_ERR, "error: no RPC URL specified");
		exit(1);
	}
	srv.rpc_url = strdup(tmp_str);

	rpcuser = json_string_value(json_object_get(jcfg, "rpc.user"));
	rpcpass = json_string_value(json_object_get(jcfg, "rpc.pass"));
	if (!rpcuser || !rpcpass) {
		applog(LOG_ERR, "error: no RPC user and/or password specified");
		exit(1);
	}
	if (asprintf(&srv.rpc_userpass, "%s:%s", rpcuser, rpcpass) < 0) {
		applog(LOG_ERR, "OOM");
		exit(1);
	}

	if (json_is_true(json_object_get(jcfg, "rpc.target.rewrite")))
		srv.easy_target = json_string(EASY_TARGET);

	tmp_json = json_object_get(jcfg, "work.expire");
	if (json_is_integer(tmp_json))
		srv.work_expire = json_integer_value(tmp_json);

	if (!srv.pid_file) {
		if (!(srv.pid_file = strdup("/var/run/pushpoold.pid"))) {
			applog(LOG_ERR, "no core");
			exit(1);
		}
	}

	if (json_is_true(json_object_get(jcfg, "roll.ntime.disable")))
		srv.disable_roll_ntime = true;
	else
	if (asprintf(&srv.work_expire_str, "expire=%d", srv.work_expire) < 0) {
		applog(LOG_ERR, "OOM");
		exit(1);
	}

	if (json_is_true(json_object_get(jcfg, "scrypt")))
		srv.scrypt = true;

	json_decref(jcfg);
}

