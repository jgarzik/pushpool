
/*
 * Copyright 2011 Shane Wegner
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

#ifdef HAVE_POSTGRESQL

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <libpq-fe.h>

#include "server.h"

static char *pg_pwdb_lookup(const char *user)
{
	char *pw = NULL;
	PGresult *res;
	const char *paramvalues[] = { user };
	res =
	    PQexecParams(srv.db_cxn, srv.db_stmt_pwdb, 1, NULL,
			 paramvalues, NULL, NULL, 0);
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		applog(LOG_ERR, "pg_pwdb_lookup query failed: %s",
		       PQerrorMessage(srv.db_cxn));
		goto out;
	}
	if (PQnfields(res) != 1 || PQntuples(res) < 1)
		goto out;
	pw = strdup(PQgetvalue(res, 0, 0));
out:
	PQclear(res);
	return pw;
}

static void pg_close(void)
{
	PQfinish(srv.db_cxn);
}

static bool pg_open(void)
{
	char *portstr = NULL;
	if (srv.db_port > 0)
		if (asprintf(&portstr, "%d", srv.db_port) < 0)
			return false;
	srv.db_cxn = PQsetdbLogin(srv.db_host, portstr, NULL, NULL,
				  srv.db_name, srv.db_username,
				  srv.db_password);
	free(portstr);
	if (PQstatus(srv.db_cxn) != CONNECTION_OK) {
		applog(LOG_ERR, "failed to connect to postgresql: %s",
		       PQerrorMessage(srv.db_cxn));
		pg_close();
		return false;
	}
	return true;
}

struct server_db_ops postgresql_db_ops = {
	.pwdb_lookup	= pg_pwdb_lookup,
	.open		= pg_open,
	.close		= pg_close,
};

#endif
