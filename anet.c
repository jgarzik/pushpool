
/*
 * Copyright 2011 Red Hat, Inc.
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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "server.h"

void tcp_read_init(struct tcp_read_state *rst, int fd, void *priv)
{
	memset(rst, 0, sizeof(*rst));

	rst->fd = fd;
	rst->priv = priv;
	INIT_ELIST_HEAD(&rst->q);
}

void tcp_read_free(struct tcp_read_state *rst)
{
	struct tcp_read *rd, *tmp;
	bool ok = true;

	elist_for_each_entry_safe(rd, tmp, &rst->q, node) {
		elist_del(&rd->node);

		if (rd->cb)
			ok = rd->cb(rst->priv, rd->priv, 0, false);

		free(rd);
	}

	free(rst->slop);

	memset(rst, 0, sizeof(*rst));	/* poison */
}

bool tcp_read(struct tcp_read_state *rst,
		     void *buf, unsigned int buflen,
		     bool (*cb)(void *rst_priv, void *priv,
		     		unsigned int buflen, bool success),
		     void *priv)
{
	struct tcp_read *rd;

	rd = calloc(1, sizeof(*rd));
	if (!rd)
		return false;

	rd->buf = buf;
	rd->len = buflen;
	rd->cb = cb;
	rd->priv = priv;
	INIT_ELIST_HEAD(&rd->node);

	elist_add_tail(&rd->node, &rst->q);

	return true;
}

bool tcp_read_inf(struct tcp_read_state *rst,
		     void *buf, unsigned int buflen,
		     int (*check_compl_cb)(void *, void *,
		     			   unsigned int, unsigned int *),
		     bool (*cb)(void *rst_priv, void *priv,
		     		unsigned int buflen, bool success),
		     void *priv)
{
	struct tcp_read *rd;

	rd = calloc(1, sizeof(*rd));
	if (!rd)
		return false;

	rd->buf = buf;
	rd->len = buflen;
	rd->check_compl_cb = check_compl_cb;
	rd->cb = cb;
	rd->priv = priv;
	INIT_ELIST_HEAD(&rd->node);

	elist_add_tail(&rd->node, &rst->q);

	return true;
}

static bool tcp_read_slop_append(struct tcp_read_state *rst, const void *buf,
				 unsigned int buflen)
{
	void *new_slop;
	unsigned int new_slop_len, old_slop_len;

	old_slop_len = rst->slop_len;
	new_slop_len = old_slop_len + buflen;

	new_slop = realloc(rst->slop, new_slop_len);
	if (!new_slop)
		return false;

	memcpy(new_slop + old_slop_len, buf, buflen);

	rst->slop = new_slop;
	rst->slop_len = new_slop_len;

	return true;
}

static int tcp_read_exec(struct tcp_read_state *rst, struct tcp_read *rd)
{
	ssize_t rrc;
	unsigned int to_read;
	int ok = true;

	/* process any bytes left over from last read(2) */
	to_read = rd->len - rd->curlen;
	if (rst->slop) {
		void *new_slop = NULL;
		unsigned int new_slop_len = 0;
		unsigned int slop_read = MIN(to_read, rst->slop_len);

		memcpy(rd->buf + rd->curlen, rst->slop, slop_read);

		if (slop_read < rst->slop_len) {
			new_slop_len = rst->slop_len - slop_read;
			new_slop = malloc(new_slop_len);
			if (!new_slop)
				return 0;

			memcpy(new_slop, rst->slop + slop_read, new_slop_len);

			free(rst->slop);
			rst->slop = new_slop;
			rst->slop_len = new_slop_len;
		} else {
			free(rst->slop);
			rst->slop = NULL;
			rst->slop_len = 0;
		}

		rd->curlen += slop_read;
	}

	/* if buffer not yet empty, read(2) data from socket buffer */
	to_read = rd->len - rd->curlen;
	if (to_read > 0) {
		rrc = read(rst->fd, rd->buf + rd->curlen, to_read);

		if (rrc < 0) {			/* error */
			if (errno == EAGAIN)
				return -1;

			return 0;
		}
		if (rrc == 0)		/* end of file (net disconnect) */
			return 0;

		rd->curlen += rrc;		/* partial completion */
	}

	/* if we use a callback to determine completion, call it */
	if (rd->check_compl_cb) {
		unsigned int overflow = 0;
		int compl_rc = rd->check_compl_cb(rst->priv, rd->priv,
						  rd->curlen, &overflow);
		if (compl_rc < 0)		/* error */
			return 0;
		if (compl_rc == 0)		/* incomplete, wait for more */
			return -1;

		if (overflow) {
			void *p = rd->buf + rd->curlen - overflow;
			if (!tcp_read_slop_append(rst, p, overflow))
				return -1;
			rd->curlen -= overflow;
		}
	}

	/* otherwise, buffer-full indicates completion */
	else {
		if (rd->curlen < rd->len)	/* incomplete, wait for more */
			return -1;
	}

	/* full read completion; call callback and remove from list */

	if (rd->cb)
		ok = rd->cb(rst->priv, rd->priv, rd->curlen, true);

	elist_del(&rd->node);

	memset(rd, 0, sizeof(*rd));	/* poison */
	free(rd);

	return ok ? 1 : 0;
}

bool tcp_read_runq(struct tcp_read_state *rst)
{
	struct tcp_read *rd, *tmp;
	bool ok = true;

	elist_for_each_entry_safe(rd, tmp, &rst->q, node) {
		int rc;

		rc = tcp_read_exec(rst, rd);
		if (rc < 0)
			break;
		if (rc == 0) {
			ok = false;
			break;
		}
	}

	return ok;
}

