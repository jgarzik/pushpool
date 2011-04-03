
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

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <syslog.h>
#include <jansson.h>
#include "server.h"

#define EASY_TARGET "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000"

#define DEFAULT_STMT_PWDB \
	"SELECT password FROM pool_worker WHERE username = ?"

static void parse_listen(const json_t *listeners)
{
	int i, len;

	len = json_array_size(listeners);

	for (i = 0; i < len; i++) {
		json_t *obj;
		const char *host_str, *proto_str;
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

		INIT_LIST_HEAD(&lc->listeners_node);

		if (host_str)
			lc->host = strdup(host_str);
		lc->port = port;

		list_add_tail(&lc->listeners_node, &srv.listeners);
	}
}

static void parse_database(const json_t *db_obj)
{
	const json_t *tmp;
	const char *db_host, *db_name, *db_un, *db_pw, *db_st_pwdb, *tmp_str;
	int db_port = -1;

	if (!json_is_object(db_obj))
		return;

	tmp_str = json_string_value(json_object_get(db_obj, "engine"));
	if (tmp_str) {
		if (!strcmp(tmp_str, "sqlite3"))
			srv.db_eng = SDB_SQLITE;
		else {
			applog(LOG_ERR, "invalid database.engine");
			exit(1);
		}
	}

	db_host = json_string_value(json_object_get(db_obj, "host"));
	tmp = json_object_get(db_obj, "port");
	if (json_is_integer(tmp))
		db_port = json_integer_value(tmp);

	db_name = json_string_value(json_object_get(db_obj, "name"));
	db_un = json_string_value(json_object_get(db_obj, "username"));
	db_pw = json_string_value(json_object_get(db_obj, "password"));

	switch (srv.db_eng) {

	case SDB_SQLITE:
		if (db_host || db_port >= 0 || db_un || db_pw) {
			applog(LOG_ERR, "sqlite does not support database host, port, username or password");
			exit(1);
		}
		if (!db_name || (*db_name != '/')) {
			applog(LOG_ERR, "missing or invalid database.name");
			exit(1);
		}

		srv.db_name = strdup(db_name);
		break;

	}

	db_st_pwdb = json_string_value(json_object_get(db_obj, "stmt.pwdb"));
	if (!db_st_pwdb)
		db_st_pwdb = DEFAULT_STMT_PWDB;
	srv.db_stmt_pwdb = strdup(db_st_pwdb);
}

void read_config(void)
{
	json_t *jcfg, *cred_expire;
	json_error_t err;
	const char *tmp_str, *rpcuser, *rpcpass;

	jcfg = json_load_file(srv.config, &err);
	if (!jcfg) {
		applog(LOG_ERR, "failed to load %s", srv.config);
		exit(1);
	}

	if (!json_is_object(jcfg)) {
		applog(LOG_ERR, "top-level JSON value not an object");
		exit(1);
	}

	parse_listen(json_object_get(jcfg, "listen"));
	parse_database(json_object_get(jcfg, "database"));

	if (list_empty(&srv.listeners)) {
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

	if (!srv.pid_file) {
		if (!(srv.pid_file = strdup("/var/run/pushpoold.pid"))) {
			applog(LOG_ERR, "no core");
			exit(1);
		}
	}

	json_decref(jcfg);
}

