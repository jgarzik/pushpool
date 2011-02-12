
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
#include <unistd.h>
#include <string.h>
#include <jansson.h>
#include "server.h"

static const char *bc_err_str[] = {
	[BC_ERR_NONE] = "no error (success)",
	[BC_ERR_INVALID] = "invalid parameter",
	[BC_ERR_AUTH] = "auth failed: invalid user or pass",
	[BC_ERR_CONFIG] = "invalid configuration",
	[BC_ERR_RPC] = "upstream RPC problem",
	[BC_ERR_WORK_REJECT] = "work submit rejected upstream",
	[BC_ERR_INTERNAL] = "internal server err",
};

static bool checkauth(const char *user, const char *pass)
{
	if (!user || !pass)
		return false;
	
	if (!strcmp(user, "testuser") &&
	    !strcmp(pass, "testpass"))
		return true;
	
	return false;
}

static bool cli_config(struct client *cli, const json_t *cfg)
{
	/* FIXME */
	return false;
}
	
bool cli_op_login(struct client *cli, const json_t *obj)
{
	const char *user, *pass;
	json_t *cfg, *resobj, *res_cfgobj;
	int version, err_code = BC_ERR_INTERNAL;
	bool rc;

	/* verify client protocol version */
	version = json_integer_value(json_object_get(obj, "version"));
	if (version < 1 || version > 1) {
		err_code = BC_ERR_INVALID;
		goto err_out;
	}

	user = json_string_value(json_object_get(obj, "user"));
	pass = json_string_value(json_object_get(obj, "pass"));

	/* validate username / password */
	if (!checkauth(user, pass)) {
		err_code = BC_ERR_AUTH;
		goto err_out;
	}

	/* apply requested configuration options */
	cfg = json_object_get(obj, "config");
	if (json_is_object(cfg) && !cli_config(cli, cfg)) {
		err_code = BC_ERR_CONFIG;
		goto err_out;
	}

	/* build result object, describing server setup */
	res_cfgobj = json_object();
	resobj = json_object();
	if (json_object_set_new(resobj, "version", json_integer(1)) ||
	    json_object_set_new(resobj, "server-name",
	    			json_string(PACKAGE)) ||
	    json_object_set_new(resobj, "server-version",
	    			json_string(VERSION)) ||
	    json_object_set_new(resobj, "config", res_cfgobj)) {
		json_decref(res_cfgobj);
		goto err_out_resobj;
	}

	rc = cli_send_obj(cli, BC_OP_LOGIN_RESP, resobj);

	json_decref(resobj);

	return rc;

err_out_resobj:
	json_decref(resobj);
err_out:
	cli_send_err(cli, BC_OP_LOGIN_RESP, err_code, bc_err_str[err_code]);
	return false;
}

bool cli_op_config(struct client *cli, const json_t *cfg)
{
	json_t *res;
	bool rc;

	/* apply requested configuration options */
	if (json_is_object(cfg) && !cli_config(cli, cfg)) {
		cli_send_err(cli, BC_OP_CONFIG_RESP, BC_ERR_CONFIG,
			     bc_err_str[BC_ERR_CONFIG]);
		return false;
	}

	/* build result object, describing configuration.
	 * this is the 'config' object returned from
	 * BC_OP_LOGIN_RESP
	 */
	res = json_object();

	rc = cli_send_obj(cli, BC_OP_CONFIG_RESP, res);

	json_decref(res);

	return rc;
}

static bool jobj_binary(const json_t *obj, const char *key,
			void *buf, size_t buflen)
{
	const char *hexstr;
	json_t *tmp;

	tmp = json_object_get(obj, key);
	if (!tmp) {
		return false;
	}
	hexstr = json_string_value(tmp);
	if (!hexstr) {
		return false;
	}
	if (!hex2bin(buf, hexstr, buflen))
		return false;

	return true;
}

static bool work_decode(const json_t *val, struct bc_work *work)
{
	if (!jobj_binary(val, "midstate",
			 work->midstate, sizeof(work->midstate))) {
		goto err_out;
	}

	if (!jobj_binary(val, "data", work->data, sizeof(work->data))) {
		goto err_out;
	}

	if (!jobj_binary(val, "hash1", work->hash1, sizeof(work->hash1))) {
		goto err_out;
	}

	if (!jobj_binary(val, "target", work->target, sizeof(work->target))) {
		goto err_out;
	}

	return true;

err_out:
	return false;
}

static unsigned int rpcid = 1;

bool cli_op_work_get(struct client *cli, unsigned int msgsz)
{
	json_t *val;
	char s[128];
	int err_code = BC_ERR_INVALID;
	struct ubbp_header *msg_hdr;
	struct bc_work work;
	void *raw_msg;
	size_t msg_len;
	bool rc;

	sprintf(s, "{\"method\": \"getwork\", \"params\": [], \"id\":%u}\r\n",
		rpcid++);

	if (msgsz > 0)
		return false;

	/* issue JSON-RPC request */
	val = json_rpc_call(srv.curl, srv.rpc_url, srv.rpc_userpass, s);
	if (!val) {
		err_code = BC_ERR_RPC;
		goto err_out;
	}

	/* decode result into work state struct */
	rc = work_decode(val, &work);

	json_decref(val);

	if (!rc) {
		err_code = BC_ERR_RPC;
		goto err_out;
	}

	/* alloc new message buffer */
	msg_len = sizeof(struct ubbp_header) + sizeof(struct bc_work);

	raw_msg = calloc(1, msg_len);
	if (!raw_msg) {
		err_code = BC_ERR_INTERNAL;
		goto err_out;
	}

	/* build BC_OP_WORK message: hdr + bc_work */
	msg_hdr = raw_msg;
	memcpy(msg_hdr->magic, PUSHPOOL_UBBP_MAGIC, 4);
	msg_hdr->op_size = htole32(UBBP_OP_SIZE(BC_OP_WORK,
						sizeof(struct bc_work)));
	memcpy(raw_msg + sizeof(struct ubbp_header),
	       &work, sizeof(struct bc_work));

	rc = cli_send_msg(cli, raw_msg, msg_len);

	free(raw_msg);

	return rc;

err_out:
	cli_send_err(cli, BC_OP_RESP_ERR, err_code, bc_err_str[err_code]);
	return false;
}

static bool submit_work(CURL *curl, void *data, bool *json_result)
{
	char *hexstr = NULL;
	json_t *val;
	char s[345];
	bool rc = false;

	/* build hex string */
	hexstr = bin2hex(data, 128);
	if (!hexstr) {
		fprintf(stderr, "submit_work OOM\n");
		goto out;
	}

	/* build JSON-RPC request */
	sprintf(s,
	      "{\"method\": \"getwork\", \"params\": [ \"%s\" ], \"id\":1}\r\n",
		hexstr);

	/* issue JSON-RPC request */
	val = json_rpc_call(curl, srv.rpc_url, srv.rpc_userpass, s);
	if (!val) {
		fprintf(stderr, "submit_work json_rpc_call failed\n");
		goto out;
	}

	*json_result = json_is_true(json_object_get(val, "result"));
	rc = true;

	json_decref(val);

out:
	free(hexstr);
	return rc;
}

bool cli_op_work_submit(struct client *cli, unsigned int msgsz)
{
	int err_code = BC_ERR_INVALID;
	bool json_res = false;

	if (msgsz != 128)
		goto err_out;
	if (!submit_work(srv.curl, cli->msg, &json_res)) {
		err_code = BC_ERR_RPC;
		goto err_out;
	}
	if (!json_res) {
		err_code = BC_ERR_WORK_REJECT;
		goto err_out;
	}

	return cli_send_hdronly(cli, BC_OP_RESP_OK);

err_out:
	cli_send_err(cli, BC_OP_RESP_ERR, err_code, bc_err_str[err_code]);
	return false;
}

