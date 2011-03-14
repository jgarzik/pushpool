
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
#include <byteswap.h>
#include <openssl/sha.h>
#include <syslog.h>
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

char *pwdb_lookup(const char *user)
{
	static const char *sql =
		"SELECT password FROM pool_worker WHERE username = ?";
	sqlite3_stmt *stmt = NULL;
	int rc, step = 0;
	char *password = NULL;

	if (!user)
		return NULL;

	step++;
	rc = sqlite3_prepare_v2(srv.db, sql, strlen(sql), &stmt, NULL);
	if (rc != SQLITE_OK)
		goto err_out;

	step++;
	rc = sqlite3_bind_text(stmt, 1, user, strlen(user), SQLITE_STATIC);
	if (rc != SQLITE_OK)
		goto err_out;

	step++;
	rc = sqlite3_step(stmt);
	if (rc == SQLITE_ROW)
		password = strdup((char *)sqlite3_column_text(stmt, 0));
	else if (rc != SQLITE_DONE)
		goto err_out;

	sqlite3_finalize(stmt);
	return password;

err_out:
	applog(LOG_ERR, "pwdb sql step %d failed: %s",
	       step, sqlite3_errmsg(srv.db));
	sqlite3_finalize(stmt);
	return NULL;
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

static json_t *get_work(const char *auth_user)
{
	char s[80];
	json_t *val, *result;

	sprintf(s, "{\"method\": \"getwork\", \"params\": [], \"id\":%u}\r\n",
		rpcid++);

	/* issue JSON-RPC request */
	val = json_rpc_call(srv.curl, srv.rpc_url, srv.rpc_userpass, s);
	if (!val)
		return NULL;

	result = json_object_get(val, "result");
	if (!json_is_object(result)) {
		json_decref(val);
		return NULL;
	}

	/* rewrite target (pool server mode), if requested in config file */
	if (srv.easy_target)
		json_object_set(result, "target", srv.easy_target);

	return val;
}

static int check_hash(const char *remote_host, const char *auth_user,
		      const char *data_str, const char **reason_out)
{
	unsigned char hash[SHA256_DIGEST_LENGTH], hash1[SHA256_DIGEST_LENGTH];
	uint32_t *hash32 = (uint32_t *) hash;
	unsigned char data[128];
	uint32_t *data32 = (uint32_t *) data;
	bool rc;
	int i;

	rc = hex2bin(data, data_str, sizeof(data));
	if (!rc) {
		applog(LOG_ERR, "check_hash hex2bin failed");
		return -1;		/* error; failure */
	}

	for (i = 0; i < 128/4; i++)
		data32[i] = bswap_32(data32[i]);

	SHA256(data, 80, hash1);
	SHA256(hash1, SHA256_DIGEST_LENGTH, hash);

	if (hash32[7] != 0) {
		*reason_out = "H-not-zero";
		return 0;		/* work is invalid */
	}

	if (hist_lookup(srv.hist, hash)) {
		*reason_out = "duplicate";
		return 0;		/* work is invalid */
	}
	if (!hist_add(srv.hist, hash)) {
		applog(LOG_ERR, "hist_add OOM");
		return -1;		/* error; failure */
	}

	return 1;			/* work is valid */
}

static bool submit_work(const char *remote_host, const char *auth_user,
			CURL *curl, const char *hexstr, bool *json_result)
{
	json_t *val;
	char s[256 + 80];
	bool rc = false;
	int check_rc;
	const char *reason = NULL;

	/* validate submitted work */
	check_rc = check_hash(remote_host, auth_user, hexstr, &reason);
	if (check_rc < 0)	/* internal failure */
		goto out;
	if (check_rc == 0) {	/* invalid hash */
		*json_result = false;
		sharelog(remote_host, auth_user, "N", "n/a", reason, hexstr);
		return true;
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

	sharelog(remote_host, auth_user,
		 srv.easy_target ? "Y" : *json_result ? "Y" : "N",
		 *json_result ? "Y" : "N", NULL, hexstr);

	if (debugging > 1)
		applog(LOG_INFO, "[%s] PROOF-OF-WORK submitted upstream.  "
		       "Result: %s",
		       remote_host,
		       *json_result ? "TRUE" : "false");

	json_decref(val);

	if (*json_result)
		applog(LOG_INFO, "PROOF-OF-WORK found");

	/* if pool server mode, return success even if result==false */
	if (srv.easy_target)
		*json_result = true;

out:
	return rc;
}

static bool submit_bin_work(const char *remote_host, const char *auth_user,
			    CURL *curl, void *data, bool *json_result)
{
	char *hexstr = NULL;
	bool rc = false;

	/* build hex string */
	hexstr = bin2hex(data, 128);
	if (!hexstr) {
		fprintf(stderr, "submit_work OOM\n");
		goto out;
	}

	rc = submit_work(remote_host, auth_user, curl, hexstr, json_result);

	free(hexstr);

out:
	return rc;
}

static bool cli_config(struct client *cli, const json_t *cfg)
{
	/* FIXME */
	return false;
}

bool cli_op_login(struct client *cli, const json_t *obj, unsigned int msgsz)
{
	char user[33];
	char *pass;
	json_t *cfg, *resobj, *res_cfgobj;
	int version, err_code = BC_ERR_INTERNAL;
	bool rc;
	SHA256_CTX ctx;
	unsigned char md[SHA256_DIGEST_LENGTH];

	/* verify client protocol version */
	version = json_integer_value(json_object_get(obj, "version"));
	if (version < 1 || version > 1) {
		err_code = BC_ERR_INVALID;
		goto err_out;
	}

	/* read username, and retrieve associated password from database */
	strncpy(user, json_string_value(json_object_get(obj, "user")),
		sizeof(user));
	user[sizeof(user) - 1] = 0;

	pass = pwdb_lookup(user);
	if (!pass) {
		applog(LOG_WARNING, "unknown user %s", user);
		err_code = BC_ERR_AUTH;
		goto err_out;
	}

	/* calculate sha256(login JSON packet + user password) */
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, cli->msg, msgsz - SHA256_DIGEST_LENGTH);
	SHA256_Update(&ctx, pass, strlen(pass));
	SHA256_Final(md, &ctx);

	free(pass);

	/* compare sha256 sum with LOGIN msg trailer */
	if (memcmp(md, cli->msg + (msgsz - SHA256_DIGEST_LENGTH),
		   SHA256_DIGEST_LENGTH)) {
		applog(LOG_WARNING, "invalid password for user %s", user);
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

	if (rc) {
		strcpy(cli->auth_user, user);
		cli->logged_in = true;
	}

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

bool cli_op_work_get(struct client *cli, unsigned int msgsz)
{
	json_t *val;
	int err_code = BC_ERR_INVALID;
	struct ubbp_header *msg_hdr;
	struct bc_work work;
	void *raw_msg;
	size_t msg_len;
	bool rc;

	if (msgsz > 0)
		return false;

	/* obtain work from upstream server */
	val = get_work(cli->auth_user);
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

bool cli_op_work_submit(struct client *cli, unsigned int msgsz)
{
	int err_code = BC_ERR_INVALID;
	bool json_res = false;

	if (msgsz != 128)
		goto err_out;
	if (!submit_bin_work(cli->addr_host, cli->auth_user,
			     srv.curl, cli->msg, &json_res)) {
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

static json_t *json_rpc_errobj(int code, const char *msg)
{
	json_t *err;

	err = json_object();
	if (!err)
		return NULL;

	json_object_set_new(err, "code", json_integer(code));
	json_object_set_new(err, "message", json_string(msg));

	return err;
}

bool msg_json_rpc(struct evhttp_request *req, json_t *jreq,
		  const char *username,
		  void **reply, unsigned int *reply_len)
{
	const char *method;
	json_t *params, *id, *resp;
	char *resp_str;
	bool rc = false;
	unsigned int n_params;

	method = json_string_value(json_object_get(jreq, "method"));
	params = json_object_get(jreq, "params");
	n_params = json_array_size(params);
	id = json_object_get(jreq, "id");

	resp = json_object();
	if (!resp)
		return false;
	json_object_set(resp, "id", id);

	if (!method || strcmp(method, "getwork")) {
		json_object_set_new(resp, "result", json_null());
		json_object_set_new(resp, "error",
				    json_rpc_errobj(-1, "method not getwork"));
		goto out;
	}

	/* get new work */
	if (n_params == 0) {
		json_t *val, *result;

		/* obtain work from upstream server */
		val = get_work(username);
		if (!val) {
			json_object_set_new(resp, "result", json_null());
			json_object_set_new(resp, "error",
				    json_rpc_errobj(-2, "upstream RPC error"));
			goto out;
		}

		result = json_object_get(val, "result");
		if (!result) {
			json_object_set_new(resp, "result", json_null());
			json_object_set_new(resp, "error",
				    json_rpc_errobj(-5, "upstrm RPC corrupt"));
			goto out;
		}

		/* use work directly as 'result' in response to client */
		json_object_set_new(resp, "result", json_deep_copy(result));
		json_object_set_new(resp, "error", json_null());

		json_decref(val);
	}

	/* submit solution */
	else {
		json_t *soln;
		const char *soln_str;
		size_t soln_len;
		bool rpc_rc = false, json_result = false;

		soln = json_array_get(params, 0);
		soln_str = json_string_value(soln);
		soln_len = strlen(soln_str);
		if (!soln_str || soln_len < (80*2) || soln_len > (128*2)) {
			json_object_set_new(resp, "result", json_null());
			json_object_set_new(resp, "error",
				    json_rpc_errobj(-3, "invalid solution"));
			goto out;
		}

		rpc_rc = submit_work(req->remote_host, username, srv.curl,
				     soln_str, &json_result);

		if (rpc_rc) {
			json_object_set_new(resp, "result",
				json_result ? json_true() : json_false());
			json_object_set_new(resp, "error", json_null());
		} else {
			json_object_set_new(resp, "result", json_null());
			json_object_set_new(resp, "error",
				    json_rpc_errobj(-4, "upstream RPC error"));
		}
	}

out:
	resp_str = json_dumps(resp, JSON_COMPACT);
	if (!resp_str)
		goto out_decref;

	*reply = resp_str;
	*reply_len = strlen(resp_str);

	rc = true;

out_decref:
	json_decref(resp);
	return rc;
}

