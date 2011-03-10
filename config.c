
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

void read_config(void)
{
	json_t *jcfg;
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

	tmp_str = json_string_value(json_object_get(jcfg, "database.path"));
	if (!tmp_str) {
		applog(LOG_ERR, "error: no db path specified");
		exit(1);
	}
	srv.db_path = strdup(tmp_str);

	if (!srv.pid_file) {
		if (!(srv.pid_file = strdup("/var/run/pushpoold.pid"))) {
			applog(LOG_ERR, "no core");
			exit(1);
		}
	}

	json_decref(jcfg);
}

