
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "autotools-config.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <locale.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <fcntl.h>
#include <string.h>
#include <zlib.h>
#include <netdb.h>
#include <stdarg.h>

#include <openssl/sha.h>
#include <argp.h>
#include "server.h"

const char *argp_program_version = PACKAGE_VERSION;

enum {
	CLI_RD_TIMEOUT		= 30,
	CLI_MAX_MSG		= (1 * 1024 * 1024),

	SFL_FOREGROUND		= (1 << 0),	/* run in foreground */
};

static struct argp_option options[] = {
	{ "config", 'c', "FILE", 0,
	  "Read master configuration from FILE (default: server.json)" },
	{ "debug", 'D', "LEVEL", 0,
	  "Set debug output to LEVEL (0 = off, 2 = max)" },
	{ "stderr", 'E', NULL, 0,
	  "Switch the log to standard error" },
	{ "foreground", 'F', NULL, 0,
	  "Run in foreground, do not fork" },
	{ "pid", 'P', "FILE", 0,
	  "Write daemon process id to FILE" },
    { "scrypt", 1002, NULL, 0,
      "Use scrypt for hashing function" },
	{ "strict-free", 1001, NULL, 0,
	  "For memory-checker runs.  When shutting down server, free local "
	  "heap, rather than simply exit(2)ing and letting OS clean up." },
	{ }
};

static const char doc[] =
PROGRAM_NAME " - push-mining proxy daemon";


static error_t parse_opt (int key, char *arg, struct argp_state *state);


static const struct argp argp = { options, parse_opt, NULL, doc };

static bool server_running = true;
static bool dump_stats;
static bool reopen_logs;
static bool trigger_lp_flush;
bool use_syslog = true;
static bool strict_free = false;
int debugging = 0;
struct timeval current_time;

struct server srv = {
	.config		= "server.json",
	.pid_fd		= -1,
	.req_fd		= -1,
	.share_fd	= -1,

#if defined(HAVE_SQLITE3)
	.db_eng		= SDB_SQLITE,
	.db_ops		= &sqlite_db_ops,
#elif defined(HAVE_MYSQL)
	.db_eng		= SDB_MYSQL,
	.db_ops		= &mysql_db_ops,
#elif defined(HAVE_POSTGRESQL)
	.db_eng		= SDB_POSTGRESQL,
	.db_ops		= &postgresql_db_ops,
#else
#error("No valid database engines defined")
#endif
	.db_port	= -1,

	.cred_expire	= 75,
	.work_expire	= 120,
    .scrypt         = false,
};

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	int v;

	switch(key) {
	case 'c':
		srv.config = arg;
		break;
	case 'D':
		v = atoi(arg);
		if (v < 0 || v > 2) {
			fprintf(stderr, "invalid debug level: '%s'\n", arg);
			argp_usage(state);
		}
		debugging = v;
		break;
	case 'E':
		use_syslog = false;
		break;
	case 'F':
		srv.flags |= SFL_FOREGROUND;
		break;
	case 'P':
		srv.pid_file = strdup(arg);
		break;
	case 1001:			/* --strict-free */
		strict_free = true;
		break;
    case 1002:          /* --scrypt */
        srv.scrypt = true;
        break;
	case ARGP_KEY_ARG:
		argp_usage(state);	/* too many args */
		break;
	case ARGP_KEY_END:
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static json_t *cjson_decode(void *buf, size_t buflen)
{
	json_t *obj = NULL;
	json_error_t err;
	void *obj_unc = NULL;
	unsigned long dest_len;
	void *comp_p;
	uint32_t unc_len;
	unsigned char zero = 0;

	if (buflen < 6)
		return NULL;

	/* look at first 32 bits of buffer, which contains uncompressed len */
	unc_len = le32toh(*((uint32_t *)buf));
	if (unc_len > CLI_MAX_MSG)
		return NULL;

	/* alloc buffer for uncompressed data */
	obj_unc = malloc(unc_len + 1);
	if (!obj_unc)
		return NULL;
	dest_len = unc_len;

	/* decompress buffer (excluding first 32 bits) */
	comp_p = buf + 4;
	if (uncompress(obj_unc, &dest_len, comp_p, buflen - 4) != Z_OK)
		goto out;
	if (dest_len != unc_len)
		goto out;
	memcpy(obj_unc + unc_len, &zero, 1);	/* null terminate */

	/* attempt JSON decode of buffer */
	obj = JSON_LOADS(obj_unc, &err);

out:
	free(obj_unc);

	return obj;
}

bool cjson_encode(unsigned char op, const char *obj_unc,
		  void **buf_out, size_t *buflen_out)
{
	void *obj_comp, *raw_msg = NULL;
	uint32_t *obj_clen;
	struct ubbp_header *msg_hdr;
	unsigned long comp_len;
	size_t payload_len;
	size_t unc_len = strlen(obj_unc);

	*buf_out = NULL;
	*buflen_out = 0;

	/* create buffer for entire msg (header + contents), assuming
	 * a worst case where compressed data may be slightly larger than
	 * input data
	 */
	raw_msg = calloc(1, unc_len + 64);
	if (!raw_msg)
		goto err_out;

	/* get ptr to uncompressed-length value, which follows header */
	obj_clen = raw_msg + sizeof(struct ubbp_header);

	/* get ptr to compressed data area, which follows hdr & uncompr. len */
	obj_comp = raw_msg + sizeof(struct ubbp_header) + sizeof(uint32_t);

	/* compress data */
	comp_len = unc_len + 64 -
		(sizeof(struct ubbp_header) + sizeof(uint32_t));
	if (compress2(obj_comp, &comp_len,
		      (Bytef *) obj_unc, unc_len, 9) != Z_OK)
		goto err_out;

	/* fill in UBBP message header */
	msg_hdr = raw_msg;
	memcpy(msg_hdr->magic, PUSHPOOL_UBBP_MAGIC, 4);
	payload_len = sizeof(uint32_t) + comp_len;
	msg_hdr->op_size = htole32(UBBP_OP_SIZE(op, payload_len));

	/* fill in uncompressed length */
	*obj_clen = htole32(unc_len);

	/* return entire message */
	*buf_out = raw_msg;
	*buflen_out = sizeof(struct ubbp_header) + payload_len;

	return true;

err_out:
	free(raw_msg);
	return false;
}

bool cjson_encode_obj(unsigned char op, const json_t *obj,
		      void **buf_out, size_t *buflen_out)
{
	char *obj_unc;
	bool rc;

	*buf_out = NULL;
	*buflen_out = 0;

	/* encode JSON object to flat string */
	obj_unc = json_dumps(obj, JSON_COMPACT | JSON_SORT_KEYS);
	if (!obj_unc)
		return false;

	/* build message, with compressed JSON payload */
	rc = cjson_encode(op, obj_unc, buf_out, buflen_out);

	free(obj_unc);

	return rc;
}

static void cli_free(struct client *cli)
{
	if (!cli)
		return;

	if (cli->ev_mask && (event_del(&cli->ev) < 0))
		applog(LOG_ERR, "TCP cli poll del failed");

	/* clean up network socket */
	if (cli->fd >= 0) {
		if (close(cli->fd) < 0)
			syslogerr("close(2) TCP client socket");
	}

	if (debugging)
		applog(LOG_DEBUG, "client %s ended", cli->addr_host);

	tcp_read_free(&cli->rst);

	free(cli->msg);

	memset(cli, 0, sizeof(*cli));	/* poison */
	free(cli);
}

static struct client *cli_alloc(int fd, struct sockaddr_in6 *addr,
				socklen_t addrlen, bool have_http)
{
	struct client *cli;

	cli = calloc(1, sizeof(*cli));
	if (!cli)
		return NULL;

	cli->fd = fd;
	memcpy(&cli->addr, addr, addrlen);
	tcp_read_init(&cli->rst, cli->fd, cli);

	return cli;
}

bool cli_send_msg(struct client *cli, const void *msg, size_t msg_len)
{
	ssize_t wrc;

	/* send packet to client.  fail on all cases where
	 * message is not transferred entirely into the
	 * socket buffer on this write(2) call
	 */
	wrc = write(cli->fd, msg, msg_len);

	return (wrc == msg_len);
}

bool cli_send_hdronly(struct client *cli, unsigned char op)
{
	struct ubbp_header hdr;

	memcpy(&hdr.magic, PUSHPOOL_UBBP_MAGIC, 4);
	hdr.op_size = htole32(UBBP_OP_SIZE(op, 0));

	return cli_send_msg(cli, &hdr, sizeof(hdr));
}

bool cli_send_obj(struct client *cli, unsigned char op, const json_t *obj)
{
	void *raw_msg = NULL;
	size_t msg_len;
	bool rc = false;

	/* create compressed message packet */
	if (!cjson_encode_obj(op, obj, &raw_msg, &msg_len))
		goto out;

	rc = cli_send_msg(cli, raw_msg, msg_len);

out:
	free(raw_msg);
	return rc;
}

bool cli_send_err(struct client *cli, unsigned char op,
		  int err_code, const char *err_msg)
{
	char *s = NULL;
	void *raw_msg = NULL;
	size_t msg_len;
	bool rc = false;

	/* build JSON error string, strangely similar to JSON-RPC */
	if (asprintf(&s, "{ \"error\" : { \"code\":%d, \"message\":\"%s\"}}",
		     err_code, err_msg) < 0) {
		applog(LOG_ERR, "OOM");
		return false;
	}

	/* create compressed message packet */
	if (!cjson_encode(op, s, &raw_msg, &msg_len))
		goto out;

	rc = cli_send_msg(cli, raw_msg, msg_len);

out:
	free(raw_msg);
	free(s);
	return rc;
}

static bool cli_msg(struct client *cli)
{
	uint32_t op = UBBP_OP(cli->ubbp.op_size);
	uint32_t size = UBBP_SIZE(cli->ubbp.op_size);
	json_t *obj = NULL;
	bool rc = false;

	/* LOGIN must always be first msg from client */
	if (!cli->logged_in && (op != BC_OP_LOGIN))
		return false;
	else if (cli->logged_in && (op == BC_OP_LOGIN))
		return false;

	/* decode JSON messages, for opcodes that require it */
	switch (op) {
	case BC_OP_LOGIN:
	case BC_OP_CONFIG: {
		uint32_t cjson_len = size;

		/* LOGIN is special; it has a sha256 digest
		 * following the compressed JSON bytes
		 */
		if (op == BC_OP_LOGIN) {
			if (size <= SHA256_DIGEST_LENGTH)
				return false;
			cjson_len -= SHA256_DIGEST_LENGTH;
		}

		obj = cjson_decode(cli->msg, cjson_len);
		if (!json_is_object(obj))
			goto out;
		break;
	}

	default:
		/* do nothing */
		break;
	}

	/* message processing, determined by opcode */
	switch (op) {
	case BC_OP_NOP:
		if (size > 0)
			break;
		rc = cli_send_hdronly(cli, BC_OP_NOP);
		break;
	case BC_OP_LOGIN:
		rc = cli_op_login(cli, obj, size);
		break;
	case BC_OP_CONFIG:
		rc = cli_op_config(cli, obj);
		break;
	case BC_OP_WORK_GET:
		rc = cli_op_work_get(cli, size);
		break;
	case BC_OP_WORK_SUBMIT:
		rc = cli_op_work_submit(cli, size);
		break;

	default:
		/* invalid op.  fall through to function return stmt */
		break;
	}

out:
	json_decref(obj);

	return rc;
}

static bool cli_read_msg(void *rst_priv, void *priv,
			 unsigned int buflen, bool success)
{
	struct client *cli = rst_priv;
	if (!success)
		return false;

	return cli_msg(cli);
}

static bool cli_read_hdr(void *rst_priv, void *priv,
			 unsigned int buflen, bool success)
{
	struct client *cli = rst_priv;
	uint32_t size;

	if (!success)
		return false;

	if (memcmp(cli->ubbp.magic, PUSHPOOL_UBBP_MAGIC, 4))
		return false;
	cli->ubbp.op_size = le32toh(cli->ubbp.op_size);
	size = UBBP_SIZE(cli->ubbp.op_size);
	if (size > CLI_MAX_MSG)
		return false;

	if (size == 0)
		return cli_msg(cli);

	cli->msg = malloc(size);
	if (!cli->msg)
		return false;

	return tcp_read(&cli->rst, cli->msg, size, cli_read_msg, NULL);
}

static void tcp_cli_event(int fd, short events, void *userdata)
{
	struct client *cli = userdata;
	bool ok = true;

	if (events & EV_READ)
		ok = tcp_read_runq(&cli->rst);
	if (events & EV_TIMEOUT)
		ok = false;

	if (!ok)
		cli_free(cli);
}

static void tcp_srv_event(int fd, short events, void *userdata)
{
	struct server_socket *sock = userdata;
	struct sockaddr_in6 addr;
	socklen_t addrlen = sizeof(struct sockaddr_in6);
	struct client *cli = NULL;
	char host[64];
	char port[16];
	int cli_fd, on = 1;
	struct timeval timeout = { CLI_RD_TIMEOUT, 0 };

	/* receive TCP connection from kernel */
	cli_fd = accept(sock->fd, (struct sockaddr *) &addr, &addrlen);
	if (cli_fd < 0) {
		syslogerr("tcp accept");
		goto err_out;
	}

	srv.stats.tcp_accept++;

	cli = cli_alloc(cli_fd, &addr, addrlen, true);
	if (!cli) {
		applog(LOG_ERR, "OOM");
		close(cli_fd);
		return;
	}

	/* mark non-blocking, for upcoming poll use */
	if (fsetflags("tcp client", cli->fd, O_NONBLOCK) < 0)
		goto err_out_fd;

	/* disable delay of small output packets */
	if (setsockopt(cli->fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) < 0)
		applog(LOG_WARNING, "TCP_NODELAY failed: %s",
		       strerror(errno));

	/* turn on TCP keep-alive */
	on = 1;
	if (setsockopt(cli->fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on)) < 0)
		applog(LOG_WARNING, "SO_KEEPALIVE failed: %s",
		       strerror(errno));

	event_set(&cli->ev, cli->fd, EV_READ | EV_PERSIST,
		  tcp_cli_event, cli);

	/* pretty-print incoming cxn info */
	getnameinfo((struct sockaddr *) &cli->addr, addrlen,
		    host, sizeof(host), port, sizeof(port),
		    NI_NUMERICHOST | NI_NUMERICSERV);
	host[sizeof(host) - 1] = 0;
	port[sizeof(port) - 1] = 0;
	applog(LOG_INFO, "client host %s port %s connected%s", host, port,
		false ? " via SSL" : "");

	strcpy(cli->addr_host, host);
	strcpy(cli->addr_port, port);

	if (event_add(&cli->ev, &timeout) < 0) {
		applog(LOG_ERR, "unable to ready cli fd for polling");
		goto err_out_fd;
	}
	cli->ev_mask = EV_READ;

	if (!tcp_read(&cli->rst, &cli->ubbp, sizeof(cli->ubbp),
		      cli_read_hdr, NULL))
		goto err_out_fd;

	return;

err_out_fd:
err_out:
	cli_free(cli);
}

static bool valid_auth_hdr(const char *hdr, char *username_out)
{
	char *t_type = NULL;
	char *t_b64 = NULL;
	char *t_userpass = NULL, *colon, *user, *pass;
	char *pass_db = NULL;
	bool rc = false;
	size_t hdrlen = strlen(hdr);
	size_t bin_len = 0;
	void *bin = NULL;

	t_type = calloc(1, hdrlen + 1);
	t_b64 = calloc(1, hdrlen + 1);
	t_userpass = calloc(1, hdrlen + 1);
	if (!t_type || !t_b64 || !t_userpass)
		goto out;
	if (sscanf(hdr, "%s %s", t_type, t_b64) != 2)
		goto out;

	/* auth type Basic */
	if (strcasecmp(t_type, "basic"))
		goto out;

	/* decode base64 token */
	bin = g_base64_decode(t_b64, &bin_len);
	if (!bin)
		goto out;
	if (bin_len > hdrlen)		/* impossible */
		goto out;
	memcpy(t_userpass, bin, bin_len);

	/* split user:pass */
	colon = strchr(t_userpass, ':');
	if (!colon)
		goto out;
	*colon = 0;
	user = t_userpass;
	pass = colon + 1;

	/* password database authentication check */
	pass_db = pwdb_lookup(user);
	if (!pass_db || (strcmp(pass, pass_db) && *pass_db != '\0'))
		goto out;

	rc = true;
	strncpy(username_out, user, 64);
	username_out[64] = 0;

out:
	free(pass_db);
	free(bin);
	free(t_type);
	free(t_b64);
	free(t_userpass);
	return rc;
}

static void reqlog(const char *rem_host, const char *username,
		   const char *uri)
{
	struct timeval tv = { };
	char *f;
	ssize_t wrc;
	struct tm tm;

	if (srv.req_fd < 0)
		return;

	gettimeofday(&tv, NULL);
	gmtime_r(&tv.tv_sec, &tm);

	if (asprintf(&f, "[%d-%02d-%02d %02d:%02d:%02d.%llu] %s %s \"%s\"\n",
		tm.tm_year + 1900,
		tm.tm_mon + 1,
		tm.tm_mday,
		tm.tm_hour,
		tm.tm_min,
		tm.tm_sec,
		(unsigned long long) tv.tv_usec,
	        (rem_host && *rem_host) ? rem_host : "-",
	        (username && *username) ? username : "-",
	        (uri && *uri) ? uri : "") < 0)
		return;

	wrc = write(srv.req_fd, f, strlen(f));
	if (wrc != strlen(f))
		syslogerr(srv.req_log);

	free(f);
}

void sharelog(const char *rem_host, const char *username,
	      const char *our_result, const char *upstream_result,
	      const char *reason, const char *solution)
{
	struct timeval tv = { };
	char *f;
	ssize_t wrc;
	struct tm tm;

	if (srv.db_sharelog && srv.db_ops->sharelog != NULL)
		srv.db_ops->sharelog(rem_host, username, our_result,
				     upstream_result, reason, solution);

	if (srv.share_fd < 0)
		return;

	gettimeofday(&tv, NULL);
	gmtime_r(&tv.tv_sec, &tm);

	if (asprintf(&f, "[%d-%02d-%02d %02d:%02d:%02.6f] %s %s %s %s %s %s\n",
		tm.tm_year + 1900,
		tm.tm_mon + 1,
		tm.tm_mday,
		tm.tm_hour,
		tm.tm_min,
		tm.tm_sec +
		tv.tv_usec/1000000.0,
	        (rem_host && *rem_host) ? rem_host : "-",
	        (username && *username) ? username : "-",
	        (our_result && *our_result) ? our_result : "-",
	        (upstream_result && *upstream_result) ? upstream_result : "-",
	        (reason && *reason) ? reason : "-",
		(solution && *solution) ? solution : "-") < 0)
		return;

	wrc = write(srv.share_fd, f, strlen(f));
	if (wrc != strlen(f))
		syslogerr(srv.share_log);

	free(f);
}

static void http_handle_req(struct evhttp_request *req, bool longpoll)
{
	const char *clen_str, *auth;
	char *body_str;
	char username[65] = "";
	void *body, *reply = NULL;
	int clen = 0;
	unsigned int reply_len = 0;
	json_t *jreq;
	json_error_t jerr;
	bool rc;
	struct evbuffer *evbuf;

	auth = evhttp_find_header(req->input_headers, "Authorization");
	if (!auth) {
		reqlog(req->remote_host, username, req->uri);
		evhttp_add_header(req->output_headers, "WWW-Authenticate", "Basic realm=\"pushpool\"");
		evhttp_send_reply(req, 401, "not authorized", NULL);
		return;
	}
	if (!valid_auth_hdr(auth, username)) {
		reqlog(req->remote_host, username, req->uri);
		evhttp_send_reply(req, 403, "access forbidden", NULL);
		return;
	}

	if (!longpoll) {
		clen_str = evhttp_find_header(req->input_headers, "Content-Length");
		if (clen_str)
			clen = atoi(clen_str);
		if (clen < 1 || clen > 999999) {
			reqlog(req->remote_host, username, req->uri);
			evhttp_send_reply(req, HTTP_BADREQUEST, "invalid args", NULL);
			return;
		}

		if (EVBUFFER_LENGTH(req->input_buffer) != clen)
			goto err_out_bad_req;
		body = EVBUFFER_DATA(req->input_buffer);
		body_str = strndup(body, clen);
		if (!body_str)
			goto err_out_bad_req;
	} else /* long polling */
		body_str = strdup("{\"method\":\"getwork\",\"params\":[],\"id\":1}");

	jreq = JSON_LOADS(body_str, &jerr);

	free(body_str);

	if (!jreq)
		goto err_out_bad_req;

	rc = msg_json_rpc(req, jreq, username, &reply, &reply_len);

	json_decref(jreq);

	if (!rc)
		goto err_out_bad_req;

	evbuf = evbuffer_new();
	if (!evbuf) {
		free(reply);
		goto err_out_bad_req;
	}
	if (evbuffer_add(evbuf, reply, reply_len)) {
		evbuffer_free(evbuf);
		free(reply);
		goto err_out_bad_req;
	}

	free(reply);

	evhttp_add_header(req->output_headers,
			  "Content-Type", "application/json");
	if (!longpoll && !srv.disable_lp)
		evhttp_add_header(req->output_headers, "X-Long-Polling", "/LP");
	if (!srv.disable_roll_ntime)
		evhttp_add_header(req->output_headers, "X-Roll-NTime", srv.work_expire_str);
	evhttp_send_reply(req, HTTP_OK, "ok", evbuf);

	evbuffer_free(evbuf);

	return;

err_out_bad_req:
	evhttp_send_reply(req, HTTP_BADREQUEST, "invalid args", NULL);
}

static void flush_lp_waiters(void)
{
	struct genlist *tmp, *iter;

	elist_for_each_entry_safe(tmp, iter, &srv.lp_waiters, node) {
		struct evhttp_request *req;

		req = tmp->data;
		http_handle_req(req, true);

		elist_del(&tmp->node);
		memset(tmp, 0, sizeof(*tmp));
		free(tmp);
	}
}

static void __http_srv_event(struct evhttp_request *req, void *arg,
			     bool longpoll)
{
	struct server_socket *sock = arg;
	const char *auth;
	char username[65] = "";

	/* copy X-Forwarded-For header to remote_host, if a trusted proxy provides it */
	if (sock->cfg->proxy && !strcmp(req->remote_host, sock->cfg->proxy)) {
		const char *hdr;
		hdr = evhttp_find_header(req->input_headers, "X-Forwarded-For");
		if (hdr) {
			free(req->remote_host);
			req->remote_host = strdup(hdr);
		}
	}

	/* validate user authorization */
	auth = evhttp_find_header(req->input_headers, "Authorization");
	if (!auth) {
		reqlog(req->remote_host, username, req->uri);
		evhttp_add_header(req->output_headers, "WWW-Authenticate", "Basic realm=\"pushpool\"");
		evhttp_send_reply(req, 401, "not authorized", NULL);
		return;
	}
	if (!valid_auth_hdr(auth, username)) {
		reqlog(req->remote_host, username, req->uri);
		evhttp_send_reply(req, 403, "access forbidden", NULL);
		return;
	}

	reqlog(req->remote_host, username, req->uri);

	/* if longpoll, don't respond now, queue onto list for later */
	if (longpoll) {
		struct genlist *gl = calloc(1, sizeof(*gl));
		if (!gl)
			return;

		gl->data = req;
		INIT_ELIST_HEAD(&gl->node);

		elist_add_tail(&gl->node, &srv.lp_waiters);
	}

	/* otherwise, handle immediately */
	else
		http_handle_req(req, false);
}

static void http_srv_event(struct evhttp_request *req, void *arg)
{
	__http_srv_event(req, arg, false);
}

static void http_srv_event_lp(struct evhttp_request *req, void *arg)
{
	__http_srv_event(req, arg, true);
}

static int net_write_port(const char *port_file, const char *port_str)
{
	FILE *portf;
	int rc;

	portf = fopen(port_file, "w");
	if (portf == NULL) {
		rc = errno;
		applog(LOG_INFO, "Cannot create port file %s: %s",
		       port_file, strerror(rc));
		return -rc;
	}
	fprintf(portf, "%s\n", port_str);
	fclose(portf);
	return 0;
}

static void net_sock_free(struct server_socket *sock)
{
	if (!sock)
		return;

	elist_del_init(&sock->sockets_node);

	if (sock->http)
		evhttp_free(sock->http);
	else
		event_del(&sock->ev);

	if (sock->fd >= 0)
		close(sock->fd);

	memset(sock, 0, sizeof(*sock));	/* poison */
	free(sock);
}

static void net_close(void)
{
	struct server_socket *sock, *iter;
	struct listen_cfg *cfg, *citer;

	elist_for_each_entry_safe(sock, iter, &srv.sockets, sockets_node) {
		net_sock_free(sock);
	}

	elist_for_each_entry_safe(cfg, citer, &srv.listeners, listeners_node) {
		elist_del_init(&cfg->listeners_node);
		free(cfg->host);
		free(cfg->port_file);
		memset(cfg, 0, sizeof(*cfg)); /* poison */
		free(cfg);
	}
}

static int net_open_socket(const struct listen_cfg *cfg,
			   int addr_fam, int sock_type, int sock_prot,
			   int addr_len, void *addr_ptr)
{
	struct server_socket *sock;
	int fd, on;
	int rc;
	bool have_http = (cfg->proto == LP_HTTP_JSON);

	fd = socket(addr_fam, sock_type, sock_prot);
	if (fd < 0) {
		rc = errno;
		syslogerr("tcp socket");
		return -rc;
	}

	on = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
		syslogerr("setsockopt(SO_REUSEADDR)");
		rc = -errno;
		goto err_out_fd;
	}

	if (bind(fd, addr_ptr, addr_len) < 0) {
		syslogerr("tcp bind");
		rc = -errno;
		goto err_out_fd;
	}

	if (listen(fd, 100) < 0) {
		syslogerr("tcp listen");
		rc = -errno;
		goto err_out_fd;
	}

	rc = fsetflags("tcp server", fd, O_NONBLOCK);
	if (rc)
		goto err_out_fd;

	sock = calloc(1, sizeof(*sock));
	if (!sock) {
		rc = -ENOMEM;
		goto err_out_fd;
	}

	INIT_ELIST_HEAD(&sock->sockets_node);

	sock->fd = fd;
	sock->cfg = cfg;

	if (have_http) {
		sock->http = evhttp_new(srv.evbase_main);
		if (!sock->http)
			goto err_out_sock;

		if (evhttp_accept_socket(sock->http, fd) < 0) {
			evhttp_free(sock->http);
			goto err_out_sock;
		}

		evhttp_set_cb(sock->http, "/",
			      http_srv_event, sock);
		if (!srv.disable_lp)
			evhttp_set_cb(sock->http, "/LP",
				      http_srv_event_lp,sock);
	} else {
		event_set(&sock->ev, fd, EV_READ | EV_PERSIST,
			  tcp_srv_event, sock);

		if (event_add(&sock->ev, NULL) < 0)
			goto err_out_sock;
	}

	elist_add_tail(&sock->sockets_node, &srv.sockets);

	return fd;

err_out_sock:
	free(sock);
err_out_fd:
	close(fd);
	return rc;
}

static int net_open_known(const struct listen_cfg *cfg)
{
	int ipv6_found = 0;
	int rc;
	struct addrinfo hints, *res, *res0;
	char port_str[16];

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	sprintf(port_str, "%d", cfg->port);

	rc = getaddrinfo(cfg->host, port_str, &hints, &res0);
	if (rc) {
		applog(LOG_ERR, "getaddrinfo(%s:%s) failed: %s",
		       cfg->host ? cfg->host : "*",
		       cfg->port, gai_strerror(rc));
		return -EINVAL;
	}

#ifdef __linux__
	/*
	 * We rely on getaddrinfo to discover if the box supports IPv6.
	 * Much easier to sanitize its output than to try to figure what
	 * to put into ai_family.
	 *
	 * These acrobatics are required on Linux because we should bind
	 * to ::0 if we want to listen to both ::0 and 0.0.0.0. Else, we
	 * may bind to 0.0.0.0 by accident (depending on order getaddrinfo
	 * returns them), then bind(::0) fails and we only listen to IPv4.
	 */
	for (res = res0; res; res = res->ai_next) {
		if (res->ai_family == PF_INET6)
			ipv6_found = 1;
	}
#endif

	for (res = res0; res; res = res->ai_next) {
		char listen_host[65], listen_serv[65];

		if (ipv6_found && res->ai_family == PF_INET)
			continue;

		rc = net_open_socket(cfg, res->ai_family, res->ai_socktype,
				     res->ai_protocol,
				     res->ai_addrlen, res->ai_addr);
		if (rc < 0)
			goto err_out;

		getnameinfo(res->ai_addr, res->ai_addrlen,
			    listen_host, sizeof(listen_host),
			    listen_serv, sizeof(listen_serv),
			    NI_NUMERICHOST | NI_NUMERICSERV);

		applog(LOG_INFO, "Listening on host %s port %s",
		       listen_host, listen_serv);
	}

	freeaddrinfo(res0);

	if (cfg->port_file)
		net_write_port(cfg->port_file, port_str);
	return 0;

err_out:
	freeaddrinfo(res0);
	return rc;
}

/*
 * Find out own hostname.
 * This is needed for:
 *  - finding the local domain and its SRV records
 * Do this before our state machines start ticking, so we can quit with
 * a meaningful message easily.
 */
static char *get_hostname(void)
{
	enum { hostsz = 64 };
	char hostb[hostsz];
	char *ret;

	if (gethostname(hostb, hostsz-1) < 0) {
		applog(LOG_ERR, "get_hostname: gethostname error (%d): %s",
		       errno, strerror(errno));
		exit(1);
	}
	hostb[hostsz-1] = 0;
	if ((ret = strdup(hostb)) == NULL) {
		applog(LOG_ERR, "get_hostname: no core (%ld)",
		       (long)strlen(hostb));
		exit(1);
	}
	return ret;
}

static void term_signal(int signo)
{
	server_running = false;
	event_loopbreak();
}

static int log_reopen(int fd, const char *fn)
{
	if (!fn || !*fn)
		return -1;

	if ((fd >= 0) && (close(fd) < 0))
		syslogerr(fn);

	fd = open(fn, O_WRONLY | O_CREAT | O_APPEND, 0666);
	if (fd < 0)
		syslogerr(fn);

	return fd;
}

static void usr1_signal(int signo)
{
	if (debugging)
		applog(LOG_INFO, "USR1 signal received, flushing LP waiters");

	trigger_lp_flush = true;
	event_loopbreak();
}

static void hup_signal(int signo)
{
	applog(LOG_INFO, "HUP signal received, reopening logs");

	reopen_logs = true;
	event_loopbreak();
}

static void stats_signal(int signo)
{
	dump_stats = true;
	event_loopbreak();
}

#define X(stat) \
	applog(LOG_INFO, "STAT %s %lu", #stat, srv.stats.stat)

static void stats_dump(void)
{
	X(poll);
	X(event);
	X(tcp_accept);
	X(opt_write);
}

#undef X

static int main_loop(void)
{
	int rc = 0;

	while (server_running) {
		event_dispatch();

		if (dump_stats) {
			dump_stats = false;
			stats_dump();
		}
		if (reopen_logs) {
			reopen_logs = false;
			srv.req_fd = log_reopen(srv.req_fd, srv.req_log);
			srv.share_fd = log_reopen(srv.share_fd, srv.share_log);
		}
		if (trigger_lp_flush) {
			trigger_lp_flush = false;
			fake_get_work();
		}
	}

	return rc;
}

int main (int argc, char *argv[])
{
	error_t aprc;
	int rc = 1;
	struct elist_head *tmpl;

	INIT_ELIST_HEAD(&srv.listeners);
	INIT_ELIST_HEAD(&srv.sockets);
	INIT_ELIST_HEAD(&srv.work_log);
	INIT_ELIST_HEAD(&srv.lp_waiters);

	/* isspace() and strcasecmp() consistency requires this */
	setlocale(LC_ALL, "C");

	/*
	 * Unfortunately, our initialization order is rather rigid.
	 *
	 * First, parse command line. This way errors in parameters can
	 * be written to stderr, where they belong.
	 */
	aprc = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (aprc) {
		fprintf(stderr, "argp_parse failed: %s\n", strerror(aprc));
		return 1;
	}

	/*
	 * Next, open syslog. From now on, nothing goes to stderr, and
	 * we minimize (or hopefuly eliminate) opening libraries that
	 * do not have a switcheable diagnostic output.
	 */
	if (use_syslog)
		openlog(PROGRAM_NAME, LOG_PID, LOG_LOCAL3);
	if (debugging)
		applog(LOG_INFO, "Debug output enabled");

	srv.evbase_main = event_init();

	/* must initialize memcached_st obj prior to reading config */
	srv.mc = memcached_create(NULL);
	if (!srv.mc) {
		applog(LOG_ERR, "memcached init failed");
		goto err_out;
	}
	memcached_behavior_set(srv.mc, MEMCACHED_BEHAVIOR_BINARY_PROTOCOL, 1);

	/*
	 * Next, read master configuration. This should be done as
	 * early as possible, so that tunables are available.
	 */
	read_config();
	if (!srv.ourhost)
		srv.ourhost = get_hostname();
	else if (debugging)
		applog(LOG_INFO, "Forcing local hostname to %s",
		       srv.ourhost);

	/*
	 * For example, backgrounding and PID file should be done early
	 * (before we do anything that can conflict with other instance),
	 * but not before read_config().
	 */
	if (!(srv.flags & SFL_FOREGROUND) && (daemon(1, !use_syslog) < 0)) {
		syslogerr("daemon");
		goto err_out;
	}

	rc = write_pid_file(srv.pid_file);
	if (rc < 0)
		goto err_out;
	srv.pid_fd = rc;

	srv.hist = hist_alloc();
	if (!srv.hist)
		goto err_out;

	/*
	 * properly capture TERM and other signals
	 */
	signal(SIGUSR1, usr1_signal);
	signal(SIGHUP, hup_signal);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, term_signal);
	signal(SIGTERM, term_signal);
	signal(SIGUSR2, stats_signal);

	srv.curl = curl_easy_init();
	if (!srv.curl) {
		applog(LOG_ERR, "CURL init failed");
		goto err_out;
	}

	srv.workers = htab_str_new(false, true);
	if (!srv.workers) {
		applog(LOG_ERR, "htab init failed");
		goto err_out;
	}

	/* set up server networking */
	elist_for_each(tmpl, &srv.listeners) {
		struct listen_cfg *tmpcfg;

		tmpcfg = elist_entry(tmpl, struct listen_cfg, listeners_node);
		rc = net_open_known(tmpcfg);
		if (rc)
			goto err_out_listen;
	}

	if (!srv.db_ops->open())
		goto err_out_listen;

    if (srv.scrypt)
	    applog(LOG_INFO, "initialized scrypt");
    else
	    applog(LOG_INFO, "initialized SHA256");

	rc = main_loop();

	applog(LOG_INFO, "shutting down");

	srv.db_ops->close();

err_out_listen:
	/* we ignore closing sockets, as process exit does that for us */
	unlink(srv.pid_file);
	close(srv.pid_fd);
err_out:
	closelog();

	if (strict_free) {
		flush_lp_waiters();
		hist_free(srv.hist);
		net_close();
		curl_easy_cleanup(srv.curl);
		curl_global_cleanup();

		if (srv.req_fd >= 0)
			close(srv.req_fd);
		free(srv.req_log);

		if (srv.share_fd >= 0)
			close(srv.share_fd);
		free(srv.share_log);

		if (srv.pid_fd >= 0)
			close(srv.pid_fd);
		free(srv.pid_file);

		free(srv.ourhost);
		free(srv.rpc_url);
		free(srv.rpc_userpass);
		json_decref(srv.easy_target);

		free(srv.db_host);
		free(srv.db_name);
		free(srv.db_username);
		free(srv.db_password);
		free(srv.db_stmt_pwdb);
		free(srv.db_stmt_sharelog);

		worker_log_expire(time(NULL) + 1);
		htab_free(srv.workers);

		if (srv.mc)
			memcached_free(srv.mc);

		event_base_free(srv.evbase_main);
	}

	return rc;
}

