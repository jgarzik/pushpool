
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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <curl/curl.h>
#include "server.h"

void applog(int prio, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (use_syslog) {
		vsyslog(prio, fmt, ap);
	} else {
		char *f = NULL;
		struct timeval tv = { };
		struct tm tm;

		gettimeofday(&tv, NULL);
		gmtime_r(&tv.tv_sec, &tm);

		if (asprintf(&f, "[%d-%02d-%02d %02d:%02d:%02.6f] %s\n",
			 tm.tm_year + 1900,
			 tm.tm_mon + 1,
			 tm.tm_mday,
			 tm.tm_hour,
			 tm.tm_min, tm.tm_sec + tv.tv_usec / 1000000.0,
			 fmt) > 0)
			vfprintf(stderr, f, ap); /* atomic write to stderr */
		free(f);
	}
	va_end(ap);
}

int write_pid_file(const char *pid_fn)
{
	char str[32], *s;
	size_t bytes;
	int fd;
	struct flock lock;
	int err;

	/* build file data */
	sprintf(str, "%u\n", (unsigned int) getpid());

	/* open non-exclusively (works on NFS v2) */
	fd = open(pid_fn, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		err = errno;

		applog(LOG_ERR, "Cannot open PID file %s: %s",
			 pid_fn, strerror(err));
		return -err;
	}

	/* lock */
	memset(&lock, 0, sizeof(lock));
	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	if (fcntl(fd, F_SETLK, &lock) != 0) {
		err = errno;
		if (err == EAGAIN) {
			applog(LOG_ERR, "PID file %s is already locked",
				 pid_fn);
		} else {
			applog(LOG_ERR, "Cannot lock PID file %s: %s",
				 pid_fn, strerror(err));
		}
		close(fd);
		return -err;
	}

	/* write file data */
	bytes = strlen(str);
	s = str;
	while (bytes > 0) {
		ssize_t rc = write(fd, s, bytes);
		if (rc < 0) {
			err = errno;
			applog(LOG_ERR, "PID number write failed: %s",
				 strerror(err));
			goto err_out;
		}

		bytes -= rc;
		s += rc;
	}

	/* make sure file data is written to disk */
	if (fsync(fd) < 0) {
		err = errno;
		applog(LOG_ERR, "PID file fsync failed: %s", strerror(err));
		goto err_out;
	}

	return fd;

err_out:
	unlink(pid_fn);
	close(fd);
	return -err;
}

void syslogerr(const char *prefix)
{
	applog(LOG_ERR, "%s: %s", prefix, strerror(errno));
}

int fsetflags(const char *prefix, int fd, int or_flags)
{
	int flags, old_flags, rc;

	/* get current flags */
	old_flags = fcntl(fd, F_GETFL);
	if (old_flags < 0) {
		applog(LOG_ERR, "%s F_GETFL: %s", prefix, strerror(errno));
		return -errno;
	}

	/* add or_flags */
	rc = 0;
	flags = old_flags | or_flags;

	/* set new flags */
	if (flags != old_flags)
		if (fcntl(fd, F_SETFL, flags) < 0) {
			applog(LOG_ERR, "%s F_SETFL: %s", prefix,
				 strerror(errno));
			rc = -errno;
		}

	return rc;
}

struct data_buffer {
	void		*buf;
	size_t		len;
};

struct upload_buffer {
	const void	*buf;
	size_t		len;
};

static void databuf_free(struct data_buffer *db)
{
	if (!db)
		return;

	free(db->buf);

	memset(db, 0, sizeof(*db));
}

static size_t all_data_cb(const void *ptr, size_t size, size_t nmemb,
			  void *user_data)
{
	struct data_buffer *db = user_data;
	size_t len = size * nmemb;
	size_t oldlen, newlen;
	void *newmem;
	static const unsigned char zero;

	oldlen = db->len;
	newlen = oldlen + len;

	newmem = realloc(db->buf, newlen + 1);
	if (!newmem)
		return 0;

	db->buf = newmem;
	db->len = newlen;
	memcpy(db->buf + oldlen, ptr, len);
	memcpy(db->buf + newlen, &zero, 1);	/* null terminate */

	return len;
}

static size_t upload_data_cb(void *ptr, size_t size, size_t nmemb,
			     void *user_data)
{
	struct upload_buffer *ub = user_data;
	int len = size * nmemb;

	if (len > ub->len)
		len = ub->len;

	if (len) {
		memcpy(ptr, ub->buf, len);
		ub->buf += len;
		ub->len -= len;
	}

	return len;
}

json_t *json_rpc_call(CURL *curl, const char *url,
		      const char *userpass, const char *rpc_req)
{
	json_t *val, *err_val, *res_val;
	int rc;
	struct data_buffer all_data = { };
	struct upload_buffer upload_data;
	json_error_t err = { };
	struct curl_slist *headers = NULL;
	char len_hdr[64];
	char curl_err_str[CURL_ERROR_SIZE];

	/* it is assumed that 'curl' is freshly [re]initialized at this pt */

	if (debugging > 1)
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_ENCODING, "");
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, all_data_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &all_data);
	curl_easy_setopt(curl, CURLOPT_READFUNCTION, upload_data_cb);
	curl_easy_setopt(curl, CURLOPT_READDATA, &upload_data);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_err_str);
	if (userpass) {
		curl_easy_setopt(curl, CURLOPT_USERPWD, userpass);
		curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
	}
	curl_easy_setopt(curl, CURLOPT_POST, 1);

	if (debugging > 1)
		printf("JSON protocol request:\n%s\n", rpc_req);

	upload_data.buf = rpc_req;
	upload_data.len = strlen(rpc_req);
	sprintf(len_hdr, "Content-Length: %lu",
		(unsigned long) upload_data.len);

	headers = curl_slist_append(headers,
		"Content-type: application/json");
	headers = curl_slist_append(headers, len_hdr);
	headers = curl_slist_append(headers, "Expect:"); /* disable Expect hdr*/

	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	rc = curl_easy_perform(curl);
	if (rc) {
		applog(LOG_ERR, "HTTP request failed: %s", curl_err_str);
		goto err_out;
	}

	val = JSON_LOADS(all_data.buf, &err);
	if (!val) {
		applog(LOG_ERR, "JSON decode failed(%d): %s", err.line, err.text);
		goto err_out;
	}

	if (debugging > 1) {
		char *s = json_dumps(val, JSON_INDENT(3));
		printf("JSON protocol response:\n%s\n", s);
		free(s);
	}

	/* JSON-RPC valid response returns a non-null 'result',
	 * and a null 'error'.
	 */
	res_val = json_object_get(val, "result");
	err_val = json_object_get(val, "error");

	if (!res_val || json_is_null(res_val) ||
	    (err_val && !json_is_null(err_val))) {
		char *s;

		if (err_val)
			s = json_dumps(err_val, JSON_INDENT(3));
		else
			s = strdup("(unknown reason)");

		applog(LOG_ERR, "JSON-RPC call failed: %s", s);

		free(s);

		goto err_out;
	}

	databuf_free(&all_data);
	curl_slist_free_all(headers);
	curl_easy_reset(curl);
	return val;

err_out:
	databuf_free(&all_data);
	curl_slist_free_all(headers);
	curl_easy_reset(curl);
	return NULL;
}

char *bin2hex(unsigned char *p, size_t len)
{
	int i;
	char *s = malloc((len * 2) + 1);
	if (!s)
		return NULL;

	for (i = 0; i < len; i++)
		sprintf(s + (i * 2), "%02x", (unsigned int) p[i]);

	return s;
}

bool hex2bin(unsigned char *p, const char *hexstr, size_t len)
{
	while (*hexstr && len) {
		char hex_byte[3];
		unsigned int v;

		if (!hexstr[1]) {
			applog(LOG_ERR, "hex2bin str truncated");
			return false;
		}

		hex_byte[0] = hexstr[0];
		hex_byte[1] = hexstr[1];
		hex_byte[2] = 0;

		if (sscanf(hex_byte, "%x", &v) != 1) {
			applog(LOG_ERR, "hex2bin sscanf '%s' failed",
				hex_byte);
			return false;
		}

		*p = (unsigned char) v;

		p++;
		hexstr += 2;
		len--;
	}

	return (len == 0 && *hexstr == 0) ? true : false;
}

/* gbase64.c - Base64 encoding/decoding
 *
 *  Copyright (C) 2006 Alexander Larsson <alexl@redhat.com>
 *  Copyright (C) 2000-2003 Ximian Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * This is based on code in camel, written by:
 *    Michael Zucchi <notzed@ximian.com>
 *    Jeffrey Stedfast <fejj@ximian.com>
 */


/**
 * SECTION:base64
 * @title: Base64 Encoding
 * @short_description: encodes and decodes data in Base64 format
 *
 * Base64 is an encoding that allows a sequence of arbitrary bytes to be
 * encoded as a sequence of printable ASCII characters. For the definition
 * of Base64, see <ulink url="http://www.ietf.org/rfc/rfc1421.txt">RFC
 * 1421</ulink> or <ulink url="http://www.ietf.org/rfc/rfc2045.txt">RFC
 * 2045</ulink>. Base64 is most commonly used as a MIME transfer encoding
 * for email.
 *
 * GLib supports incremental encoding using g_base64_encode_step() and
 * g_base64_encode_close(). Incremental decoding can be done with
 * g_base64_decode_step(). To encode or decode data in one go, use
 * g_base64_encode() or g_base64_decode(). To avoid memory allocation when
 * decoding, you can use g_base64_decode_inplace().
 *
 * Support for Base64 encoding has been added in GLib 2.12.
 */

static const char base64_alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const unsigned char mime_base64_rank[256] = {
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255, 62,255,255,255, 63,
   52, 53, 54, 55, 56, 57, 58, 59, 60, 61,255,255,255,  0,255,255,
  255,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
   15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,255,255,255,255,255,
  255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
   41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
};

/**
 * g_base64_decode_step:
 * @in: binary input data
 * @len: max length of @in data to decode
 * @out: output buffer
 * @state: Saved state between steps, initialize to 0
 * @save: Saved state between steps, initialize to 0
 *
 * Incrementally decode a sequence of binary data from its Base-64 stringified
 * representation. By calling this function multiple times you can convert
 * data in chunks to avoid having to have the full encoded data in memory.
 *
 * The output buffer must be large enough to fit all the data that will
 * be written to it. Since base64 encodes 3 bytes in 4 chars you need
 * at least: (@len / 4) * 3 + 3 bytes (+ 3 may be needed in case of non-zero
 * state).
 *
 * Return value: The number of bytes of output that was written
 *
 * Since: 2.12
 **/
static size_t
g_base64_decode_step (const char  *in,
                      size_t         len,
                      unsigned char       *out,
                      int         *state,
                      unsigned int        *save)
{
  const unsigned char *inptr;
  unsigned char *outptr;
  const unsigned char *inend;
  unsigned char c, rank;
  unsigned char last[2];
  unsigned int v;
  int i;

  if (len <= 0)
    return 0;

  inend = (const unsigned char *)in+len;
  outptr = out;

  /* convert 4 base64 bytes to 3 normal bytes */
  v=*save;
  i=*state;
  inptr = (const unsigned char *)in;
  last[0] = last[1] = 0;
  while (inptr < inend)
    {
      c = *inptr++;
      rank = mime_base64_rank [c];
      if (rank != 0xff)
        {
          last[1] = last[0];
          last[0] = c;
          v = (v<<6) | rank;
          i++;
          if (i==4)
            {
              *outptr++ = v>>16;
              if (last[1] != '=')
                *outptr++ = v>>8;
              if (last[0] != '=')
                *outptr++ = v;
              i=0;
            }
        }
    }

  *save = v;
  *state = i;

  return outptr - out;
}

/**
 * g_base64_decode:
 * @text: zero-terminated string with base64 text to decode
 * @out_len: The length of the decoded data is written here
 *
 * Decode a sequence of Base-64 encoded text into binary data
 *
 * Return value: a newly allocated buffer containing the binary data
 *               that @text represents. The returned buffer must
 *               be freed with g_free().
 *
 * Since: 2.12
 */
unsigned char *
g_base64_decode (const char *text,
                 size_t       *out_len)
{
  unsigned char *ret;
  size_t input_length;
  int state = 0;
  unsigned int save = 0;

  input_length = strlen (text);

  /* We can use a smaller limit here, since we know the saved state is 0,
     +1 used to avoid calling calloc(0), and hence retruning NULL */
  ret = calloc(1, ((input_length / 4) * 3 + 1));

  *out_len = g_base64_decode_step (text, input_length, ret, &state, &save);

  return ret;
}

