
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
#include <jansson.h>
#include "server.h"


bool cli_op_login(struct client *cli, json_t *obj)
{
	/* FIXME */
	return false;
}

bool cli_op_config(struct client *cli, json_t *obj)
{
	/* FIXME */
	return false;
}

bool cli_op_getwork(struct client *cli)
{
	/* FIXME */
	return false;
}

bool cli_op_solution(struct client *cli)
{
	/* FIXME */
	return false;
}

