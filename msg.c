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

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <jansson.h>
#include <openssl/sha.h>
#include <syslog.h>
#include "server.h"
#include "scrypt.h"

struct worker {
	char			username[64 + 1];

	struct elist_head	log;
};

struct work_ent {
	char			data[128];

	time_t			timestamp;

	struct elist_head	log_node;
	struct elist_head	srv_log_node;
};

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
	char *pass = NULL;
	char cred_key[256];
	uint32_t out_flags;
	size_t out_len;
	memcached_return_t rc;

	if (srv.mc) {
		snprintf(cred_key, sizeof(cred_key),
			 "/pushpoold/cred_cache/%s", user);

		pass = memcached_get(srv.mc, cred_key, strlen(cred_key),
				     &out_len, &out_flags, &rc);
		if (rc == MEMCACHED_SUCCESS)
			return pass;		/* may be NULL, for negative caching */
	}

	pass = srv.db_ops->pwdb_lookup(user);

	if (srv.mc) {
		rc = memcached_set(srv.mc, cred_key, strlen(cred_key) ,
				   pass,
				   pass ? strlen(pass) + 1 : 0,
				   srv.cred_expire, 0);
		if (rc != MEMCACHED_SUCCESS)
			applog(LOG_WARNING, "memcached store(%s) failed: %s",
			       cred_key, memcached_strerror(srv.mc, rc));
	}

	return pass;
}

void worker_log_expire(time_t expire_time)
{
	struct work_ent *ent, *iter;

	elist_for_each_entry_safe(ent, iter, &srv.work_log, srv_log_node) {
		if (ent->timestamp > expire_time)
			break;

		elist_del(&ent->srv_log_node);
		elist_del(&ent->log_node);
		free(ent);
	}
}

static void worker_log(const char *username, const unsigned char *data)
{
	struct worker *worker;
	struct work_ent *ent;
	time_t now = time(NULL);

	worker = htab_get(srv.workers, username);
	if (!worker) {
		worker = calloc(1, sizeof(*worker));
		if (!worker)
			return;

		strncpy(worker->username, username, sizeof(worker->username));
		INIT_ELIST_HEAD(&worker->log);

		if (!htab_put(srv.workers, worker->username, worker))
			return;
	}

	ent = calloc(1, sizeof(*ent));
	if (!ent)
		return;

	memcpy(ent->data, data, sizeof(ent->data));
	ent->timestamp = now;
	INIT_ELIST_HEAD(&ent->log_node);
	INIT_ELIST_HEAD(&ent->srv_log_node);

	elist_add_tail(&ent->log_node, &worker->log);
	elist_add_tail(&ent->srv_log_node, &srv.work_log);

	worker_log_expire(now - srv.work_expire);
}

static const char *work_in_log(const char *username, const unsigned char *data)
{
	struct worker *worker;
	struct work_ent *ent;

	worker = htab_get(srv.workers, username);
	if (!worker)
		return "unknown-user";

	elist_for_each_entry(ent, &worker->log, log_node) {
		/* check submitted block matches sent block,
		 * excluding timestamp and nonce
		 */
		if (!memcmp(ent->data, data, 68) && !memcmp(ent->data + 72, data + 72, 4))
		{
			/* verify timestamp is within reasonable range
			*/
			uint32_t timestampSent = ntohl(*(uint32_t*)(ent->data + 68));
			uint32_t timestampRcvd = ntohl(*(uint32_t*)(     data + 68));
			if (timestampRcvd == timestampSent)
				return NULL;
			if (srv.disable_roll_ntime)
				return "time-invalid";
			time_t now = time(NULL);
			if (timestampRcvd < now - 300)
				return "time-too-old";
			if (timestampRcvd > now + 7200)
				return "time-too-new";
			return NULL;
		}
	}

	return "unknown-work";
}

static const char *stale_work(const unsigned char *data)
{
	if (!memcmp(data + 4, srv.cur_prevhash, sizeof(srv.cur_prevhash)))
		return NULL;
	if (!memcmp(data + 4, srv.last_prevhash, sizeof(srv.last_prevhash)))
		return "prevhash-stale";
	return "prevhash-wrong";
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
	unsigned char data[128];
	const char *data_str;
	json_t *val, *result;

	sprintf(s, "{\"method\": \"getwork\", \"params\": [], \"id\":%u}\r\n",
		rpcid++);

	/* issue JSON-RPC request */
	val = json_rpc_call(srv.curl, srv.rpc_url, srv.rpc_userpass, s);
	if (!val)
		return NULL;

	/* decode data field, implicitly verifying 'result' is an object */
	result = json_object_get(val, "result");
	data_str = json_string_value(json_object_get(result, "data"));
	if (!data_str ||
	    !hex2bin(data, data_str, sizeof(data))) {
		json_decref(val);
		return NULL;
	}

	if (memcmp(data + 4, srv.cur_prevhash, sizeof(srv.cur_prevhash)))
	{
		/* store two most recently seen prevhash (last, and current) */
		memcpy(srv.last_prevhash, srv.cur_prevhash, sizeof(srv.last_prevhash));
		memcpy(srv.cur_prevhash, data + 4, sizeof(srv.cur_prevhash));
	}

	/* log work unit as having been sent to associated worker */
	worker_log(auth_user, data);

	/* rewrite target (pool server mode), if requested in config file */
	if (srv.easy_target)
		json_object_set(result, "target", srv.easy_target);

	return val;
}

void fake_get_work(void)
{
    char s[80];
    unsigned char data[128];
    unsigned char target[32];
    const char *data_str, *target_str;
    json_t *val, *result;

    sprintf(s, "{\"method\": \"getwork\", \"params\": [], \"id\":%u}\r\n",rpcid++);

/* issue JSON-RPC request */
    val = json_rpc_call(srv.curl, srv.rpc_url, srv.rpc_userpass, s);
    if (!val)
        return;

/* decode data field, implicitly verifying 'result' is an object */
    result = json_object_get(val, "result");
    data_str = json_string_value(json_object_get(result, "data"));
    if (!data_str ||
        !hex2bin(data, data_str, sizeof(data))) {
        json_decref(val);
        return;
    }

    if (memcmp(data + 4, srv.cur_prevhash, sizeof(srv.cur_prevhash)))
    {
/* store two most recently seen prevhash (last, and current) */
    memcpy(srv.last_prevhash, srv.cur_prevhash, sizeof(srv.last_prevhash));
    memcpy(srv.cur_prevhash, data + 4, sizeof(srv.cur_prevhash));

    target_str = json_string_value(json_object_get(result, "target"));
    if (!target_str ||
        !hex2bin(target, target_str, sizeof(target))) {
        json_decref(val);
        return;
        }
    memcpy(srv.cur_target, target, sizeof(srv.cur_target));
    if (debugging > 0)
        applog(LOG_INFO, "new block, target %s", target_str);
    srv.initiate_lp_flush = true;
}
json_decref(val);
return;
}



static int check_hash(const char *remote_host, const char *auth_user,
		      const char *data_str, const char **reason_out)
{
	unsigned char hash[SHA256_DIGEST_LENGTH], hash1[SHA256_DIGEST_LENGTH];
	uint32_t *hash32 = (uint32_t *) hash;
	unsigned char data[128];
	uint32_t *data32 = (uint32_t *) data;
	bool rc, better_hash = false;
	int i;

	rc = hex2bin(data, data_str, sizeof(data));
	if (!rc) {
		applog(LOG_ERR, "check_hash hex2bin failed");
		return -1;		/* error; failure */
	}

	*reason_out = stale_work(data);
	if (*reason_out)
		return 0;		/* work is invalid */
	*reason_out = work_in_log(auth_user, data);
	if (*reason_out)
		return 0;		/* work is invalid */

	for (i = 0; i < 128/4; i++)
		data32[i] = bswap_32(data32[i]);

    if (srv.scrypt) {
	    scrypt_1024_1_1_256(data, hash);
    } else {
	    SHA256(data, 80, hash1);
	    SHA256(hash1, SHA256_DIGEST_LENGTH, hash);
    }

	if (hash32[7] != 0) {
		*reason_out = "H-not-zero";
		return 0;		/* work is invalid */
	}
	if (hash[27] == 0)
		better_hash = true;

	if (hist_lookup(srv.hist, hash)) {
		*reason_out = "duplicate";
		return 0;		/* work is invalid */
	}
	if (!hist_add(srv.hist, hash)) {
		applog(LOG_ERR, "hist_add OOM");
		return -1;		/* error; failure */
	}

	return better_hash ? 2 : 1;			/* work is valid */
}

static bool submit_work(const char *remote_host, const char *auth_user,
			CURL *curl, const char *hexstr, const char **reason)
{
	json_t *val;
	char s[256 + 80];
	bool rc = false;
	int check_rc;
	*reason = NULL;

	/* validate submitted work */
	check_rc = check_hash(remote_host, auth_user, hexstr, reason);
	if (check_rc < 0)	/* internal failure */
		goto out;
	if (check_rc == 0) {	/* invalid hash */
		sharelog(remote_host, auth_user, "N", NULL, *reason, hexstr);
		return true;
	}

	/* if hash is sufficient for share, but not target,
	 * don't bother submitting to bitcoind
	 */
	if (srv.easy_target && check_rc == 1) {
		*reason = NULL;
		sharelog(remote_host, auth_user, "Y", NULL, NULL, hexstr);
		return true;
	}

	/* build JSON-RPC request */
	sprintf(s,
	      "{\"method\": \"getwork\", \"params\": [ \"%s\" ], \"id\":1}\r\n",
		hexstr);

	/* issue JSON-RPC request */
	val = json_rpc_call(curl, srv.rpc_url, srv.rpc_userpass, s);
	if (!val) {
		applog(LOG_ERR, "submit_work json_rpc_call failed");
		goto out;
	}

	*reason = json_is_true(json_object_get(val, "result")) ? NULL : "unknown";
	rc = true;

	sharelog(remote_host, auth_user,
		 srv.easy_target ? "Y" : *reason ? "N" : "Y",
		 *reason ? "N" : "Y", NULL, hexstr);

	if (debugging > 1)
		applog(LOG_INFO, "[%s] PROOF-OF-WORK submitted upstream.  "
		       "Result: %s",
		       remote_host,
		       *reason ? "false" : "TRUE");

	json_decref(val);

	if (!*reason)
		applog(LOG_INFO, "PROOF-OF-WORK found");

	/* if pool server mode, return success even if result==false */
	if (srv.easy_target)
		*reason = NULL;

out:
	return rc;
}

static bool submit_bin_work(const char *remote_host, const char *auth_user,
			    CURL *curl, void *data, const char **reason)
{
	char *hexstr = NULL;
	bool rc = false;

	/* build hex string */
	hexstr = bin2hex(data, 128);
	if (!hexstr) {
		applog(LOG_ERR, "submit_work OOM");
		goto out;
	}

	rc = submit_work(remote_host, auth_user, curl, hexstr, reason);

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
	const char *reason;

	if (msgsz != 128)
		goto err_out;
	if (!submit_bin_work(cli->addr_host, cli->auth_user,
			     srv.curl, cli->msg, &reason)) {
		err_code = BC_ERR_RPC;
		goto err_out;
	}
	if (reason) {
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
		const char *soln_str, *reason;
		size_t soln_len;
		bool rpc_rc = false;

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
				     soln_str, &reason);

		if (rpc_rc) {
			json_object_set_new(resp, "result",
				reason ? json_false() : json_true());
			if (reason)
				evhttp_add_header(req->output_headers, "X-Reject-Reason", reason);
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

