#ifndef __ANET_H__
#define __ANET_H__

#include <stdbool.h>
#include "elist.h"

struct tcp_read {
	void			*buf;		/* ptr to storage buffer */
	unsigned int		len;		/* total storage size */
	unsigned int		curlen;		/* amount of buffer in use */
	int			(*check_compl_cb)(void *, void *,
						unsigned int, unsigned int *);
							/* read-inf cb */
	bool			(*cb)(void *, void *,
				      unsigned int, bool); /* callback*/
	void			*priv;		/* app-private callback arg */
	struct elist_head	node;
};

struct tcp_read_state {
	struct elist_head	q;		/* read queue */
	int			fd;		/* network socket fd */
	void			*priv;		/* app-specific data */

	void			*slop;
	unsigned int		slop_len;
};

extern void tcp_read_init(struct tcp_read_state *rst, int fd, void *priv);
extern void tcp_read_free(struct tcp_read_state *rst);
extern bool tcp_read(struct tcp_read_state *rst,
		     void *buf, unsigned int buflen,
		     bool (*cb)(void *rst_priv, void *priv,
	     			      unsigned int, bool success),
		     void *priv);
extern bool tcp_read_inf(struct tcp_read_state *rst,
		     void *buf, unsigned int buflen,
		     int (*check_compl_cb)(void *, void *,
		     			   unsigned int, unsigned int *),
		     bool (*cb)(void *rst_priv, void *priv,
	     			      unsigned int, bool success),
		     void *priv);
extern bool tcp_read_runq(struct tcp_read_state *rst);

#endif /* __ANET_H__ */
