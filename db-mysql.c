
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

#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sqlite3.h>
#include "server.h"

/* resolve conflicts with elist.h */
#undef list_add
#include <mysql.h>

static char *my_pwdb_lookup(const char *user)
{
	MYSQL *db = srv.db_cxn;
	MYSQL_RES *res;
	MYSQL_ROW row;
	unsigned long *lengths, pass_len;
	char *password = NULL, *sql;
	int myrc;

	if (strchr(user, '\''))
		return NULL;

	if (asprintf(&sql, srv.db_stmt_pwdb, user) < 0)
		return NULL;

	myrc = mysql_query(db, sql);

	free(sql);

	if (myrc) {
		applog(LOG_ERR, "mysql query failed: %s", mysql_error(db));
		return NULL;
	}

	res = mysql_store_result(db);
	if (!res) {
		applog(LOG_ERR, "no mysql results: %s", mysql_error(db));
		return NULL;
	}

	row = mysql_fetch_row(res);
	if (!row || !row[0])
		goto out;

	lengths = mysql_fetch_lengths(res);
	pass_len = lengths[0];
	if (!pass_len)
		goto out;

	password = malloc(pass_len + 1);
	if (!password)
		goto out;
	
	memcpy(password, row[0], pass_len);
	password[pass_len] = 0;

out:
	mysql_free_result(res);
	return password;
}

static bool my_open(void)
{
	MYSQL *db;

	if (mysql_library_init(0, NULL, NULL))
		goto err_out;

	db = mysql_init(NULL);
	if (!db)
		goto err_out_lib;

	mysql_ssl_set(db, NULL, NULL, NULL, NULL, NULL);
	if (!mysql_real_connect(db, srv.db_host, srv.db_username,
				srv.db_password, srv.db_name,
				srv.db_port > 0 ? srv.db_port : 0,
				NULL, 0))
		goto err_out_db;

	srv.db_cxn = db;
	return true;

err_out_db:
	mysql_close(db);
err_out_lib:
	mysql_library_end();
err_out:
	return false;
}

static void my_close(void)
{
	MYSQL *db = srv.db_cxn;

	mysql_close(db);
	mysql_library_end();
}

struct server_db_ops mysql_db_ops = {
	.pwdb_lookup	= my_pwdb_lookup,
	.open		= my_open,
	.close		= my_close,
};

