
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include "elist.h"

enum {
	HIST_LOG_SZ	= 10000,
	HIST_TBL_SZ	= (HIST_LOG_SZ * 2) - 1,
};

struct hist_entry {
	unsigned char		hash[SHA256_DIGEST_LENGTH];

	struct elist_head	log_node;
	struct elist_head	tbl_node;
};

struct hist_bucket {
	struct elist_head	chain;
};

struct hist {
	struct hist_bucket	tbl[HIST_TBL_SZ];
	struct elist_head	log;
	unsigned int		log_sz;
};

static void hist_expire(struct hist *hist)
{
	struct hist_entry *ent;

	ent = elist_entry(hist->log.next, struct hist_entry, log_node);

	elist_del_init(&ent->log_node);
	elist_del_init(&ent->tbl_node);

	hist->log_sz--;

	memset(ent, 0, sizeof(*ent));	/* poison */
	free(ent);
}

bool hist_add(struct hist *hist, const unsigned char *hash)
{
	struct hist_entry *ent;
	uint32_t hash32 = *((const uint32_t *) hash);
	int bucket = hash32 % HIST_TBL_SZ;

	ent = calloc(1, sizeof(*ent));
	if (!ent)
		return false;

	memcpy(ent->hash, hash, SHA256_DIGEST_LENGTH);
	INIT_ELIST_HEAD(&ent->log_node);
	INIT_ELIST_HEAD(&ent->tbl_node);

	/* add to log */
	elist_add_tail(&ent->log_node, &hist->log);
	hist->log_sz++;

	/* add to hash table */
	elist_add_tail(&ent->tbl_node, &hist->tbl[bucket].chain);

	/* expire old entries */
	while (hist->log_sz > HIST_LOG_SZ)
		hist_expire(hist);

	return true;
}

bool hist_lookup(struct hist *hist, const unsigned char *hash)
{
	struct hist_entry *ent;
	uint32_t hash32 = *((const uint32_t *) hash);
	int bucket = hash32 % HIST_TBL_SZ;

	elist_for_each_entry(ent, &hist->tbl[bucket].chain, tbl_node) {
		if (!memcmp(hash, ent->hash, SHA256_DIGEST_LENGTH))
			return true;
	}

	return false;
}

void hist_free(struct hist *hist)
{
	if (!hist)
		return;

	while (hist->log_sz > 0)
		hist_expire(hist);

	memset(hist, 0, sizeof(*hist));		/* poison */
	free(hist);
}

struct hist *hist_alloc(void)
{
	struct hist *hist;
	int i;

	hist = calloc(1, sizeof(*hist));
	if (!hist)
		return NULL;

	for (i = 0; i < HIST_TBL_SZ; i++)
		INIT_ELIST_HEAD(&hist->tbl[i].chain);

	INIT_ELIST_HEAD(&hist->log);

	return hist;
}

