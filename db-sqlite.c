
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

#ifdef HAVE_SQLITE3

#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <sqlite3.h>
#include "server.h"

#define DEFAULT_STMT_PWDB \
	"SELECT password FROM pool_worker WHERE username = ?"
#define DEFAULT_STMT_SHARELOG \
	"insert into shares (time,rem_host, username, our_result, upstream_result, reason, solution) \
	values(?,?,?,?,?,?,?)"

static char *sql_pwdb_lookup(const char *user)
{
	sqlite3 *db = srv.db_cxn;
	sqlite3_stmt *stmt = NULL;
	int rc, step = 0;
	char *password = NULL;

	if (debugging > 1)
		applog(LOG_DEBUG, "pw lookup for %s", user ? user : "(null)");

	if (!user)
		return NULL;

	step++;
	rc = sqlite3_prepare_v2(db, srv.db_stmt_pwdb,
				strlen(srv.db_stmt_pwdb), &stmt, NULL);
	if (rc != SQLITE_OK)
		goto err_out;

	step++;
	if (sqlite3_bind_parameter_count(stmt)) {
		rc = sqlite3_bind_text(stmt, 1, user, strlen(user), SQLITE_STATIC);
		if (rc != SQLITE_OK)
			goto err_out;
	}

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
	       step, sqlite3_errmsg(db));
	sqlite3_finalize(stmt);
	return NULL;
}

static bool sql_sharelog(const char *rem_host, const char *username,
			 const char *our_result, const char *upstream_result,
			 const char *reason, const char *solution)
{
	struct timeval tv = { };
	sqlite3_stmt *stmt = NULL;
	int rc, i;
	const char *bind_values[] = { NULL, rem_host, username,
		our_result, upstream_result,
		reason, solution
	};

	gettimeofday(&tv, NULL);

	rc = sqlite3_prepare_v2(srv.db_cxn, srv.db_stmt_sharelog,
				-1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		applog(LOG_ERR, "sql_sharelog(prepare) failed: %s",
		       sqlite3_errmsg(srv.db_cxn));
		goto out;
	}

	i = 0;
	rc = sqlite3_bind_int64(stmt, i + 1, tv.tv_sec);
	if (rc != SQLITE_OK) {
		applog(LOG_ERR, "sql_sharelog: bind(%d) failed: %s",
		       i + 1, sqlite3_errmsg(srv.db_cxn));
		goto out;
	}
	for (i = 1; i < ARRAY_SIZE(bind_values); i++) {
		rc = sqlite3_bind_text(stmt, i + 1, bind_values[i],
				       -1, SQLITE_STATIC);
		if (rc != SQLITE_OK) {
			applog(LOG_ERR, "sql_sharelog: bind(%d) failed: %s",
			       i + 1, sqlite3_errmsg(srv.db_cxn));
			goto out;
		}
	}
	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		applog(LOG_ERR, "sql_sharelog: execute failed: %s",
		       sqlite3_errmsg(srv.db_cxn));
		goto out;
	}
out:
	sqlite3_finalize(stmt);

	return true;
}

static bool sql_open(void)
{
	sqlite3 *db;
	int sqlrc = sqlite3_open_v2(srv.db_name, &db,
				SQLITE_OPEN_READWRITE, NULL);
	if (sqlrc != SQLITE_OK) {
		applog(LOG_ERR, "sqlite3_open(%s) failed: %d",
		       srv.db_name, sqlrc);
		return false;
	}

	srv.db_cxn = db;
	if (srv.db_stmt_pwdb == NULL || !*srv.db_stmt_pwdb)
		srv.db_stmt_pwdb = strdup(DEFAULT_STMT_PWDB);
	if (srv.db_stmt_sharelog == NULL || !*srv.db_stmt_sharelog)
		srv.db_stmt_sharelog = strdup(DEFAULT_STMT_SHARELOG);
	return true;
}

static void sql_close(void)
{
	sqlite3 *db = srv.db_cxn;
	if (sqlite3_close(db) != SQLITE_OK)
		applog(LOG_WARNING, "db close failed");
}

struct server_db_ops sqlite_db_ops = {
	.pwdb_lookup	= sql_pwdb_lookup,
	.sharelog	= sql_sharelog,
	.open		= sql_open,
	.close		= sql_close,
};

#endif /* HAVE_SQLITE3 */
