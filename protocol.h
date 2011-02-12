#ifndef __PROTOCOL_H__
#define __PROTOCOL_H__

#define PUSHPOOL_UBBP_MAGIC "PMIN"

struct bc_work {
	unsigned char	data[128];
	unsigned char	hash1[64];
	unsigned char	midstate[32];
	unsigned char	target[32];
};

/*
 * Client/message UBBP messages
 *
 * Key to packet abbreviations:
 * HDR: Only the UBBP header.  No payload.
 * BIN: Payload is binary message data
 * JSON: Payload is zlib-compressed JSON message
 *
 * If JSON response includes 'error' in object, that indicates failure.
 */
enum {
	/* client or server originated; and receive NOP as response */
	BC_OP_NOP		= 0,	/* HDR; no-op */

	/* client-originated messages */
	BC_OP_LOGIN		= 1,	/* JSON; login */
					/* Ret: BC_OP_LOGIN_RESP */

	BC_OP_CONFIG		= 2,	/* JSON; config */
					/* Ret: BC_OP_CONFIG_RESP */

	BC_OP_WORK_GET		= 3,	/* HDR; getwork */
					/* Ret: BC_OP_WORK, BC_OP_RESP_ERR */

	BC_OP_WORK_SUBMIT	= 4,	/* BIN; work solution */
					/* Ret: BC_OP_RESP_OK, BC_OP_RESP_ERR */

	/* server-originated messages */
	BC_OP_RESP_OK		= 100,	/* HDR; general success response */
	BC_OP_RESP_ERR		= 101,	/* JSON; general failure response */
	BC_OP_LOGIN_RESP	= 102,	/* JSON; login response */
	BC_OP_CONFIG_RESP	= 103,	/* JSON; config response */
	BC_OP_WORK		= 104,	/* BIN; work unit */
};

/* error codes returned in response messages */
enum {
	BC_ERR_NONE		= 0,	/* no error (success) */
	BC_ERR_INVALID		= 1,	/* invalid parameter */
	BC_ERR_AUTH		= 2,	/* invalid user or pass */
	BC_ERR_CONFIG		= 3,	/* invalid configuration */
	BC_ERR_RPC		= 4,	/* upstream RPC problem */
	BC_ERR_WORK_REJECT	= 5,	/* work submit rejected upstrm*/
	BC_ERR_INTERNAL		= 6,	/* internal server err */
};

#endif /* __PROTOCOL_H__ */
