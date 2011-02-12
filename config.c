
/*
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

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <jansson.h>
#include "server.h"

static void parse_listen(const json_t *listeners)
{
	int i, len;

	len = json_array_size(listeners);

	for (i = 0; i < len; i++) {
		json_t *obj;
		const char *host_str, *port_str;
		int port;
		struct listen_cfg *lc;

		obj = json_array_get(listeners, i);

		host_str = json_string_value(json_object_get(obj, "host"));
		port_str = json_string_value(json_object_get(obj, "port"));
		if (!port_str) {
			applog(LOG_WARNING, "invalid listen config: port");
			continue;
		}
		port = atoi(port_str);
		if (port < 1 || port > 65535) {
			applog(LOG_WARNING, "invalid listen config: port");
			continue;
		}

		lc = calloc(1, sizeof(*lc));
		if (!lc) {
			applog(LOG_ERR, "OOM");
			exit(1);
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
	const char *tmp_str;

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

	if (!srv.pid_file) {
		if (!(srv.pid_file = strdup("/var/run/pushpoold.pid"))) {
			applog(LOG_ERR, "no core");
			exit(1);
		}
	}

	json_decref(jcfg);
}

