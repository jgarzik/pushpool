
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "elist.h"
#include "htab.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

struct htab_entry {
	void			*key;
	void			*value;
	unsigned long		hash;
	struct elist_head	chain_node;
};

struct htab_bucket {
	struct elist_head	chain;
};

struct htab {
	htab_hash_fn		hash_fn;
	htab_cmp_fn		cmp_fn;
	htab_free_fn		free_key_fn;
	htab_free_fn		free_value_fn;

	unsigned int		prime_idx;
	struct htab_bucket	*buckets;

	unsigned int		n_ent;
};

static const unsigned int primes[] = {
	5,
	/* 13, 23, 53, 97, */
	/* 193, 389, */ 769,
	/* 1543, 3079, */ 6151,
	/* 12289, 24593, */ 49157,
	98317, 196613, 393241, 786433, 1572869, 3145739, 6291469,
	12582917, 25165843, 50331653, 100663319, 201326611, 402653189,
	805306457, 1610612741
};

static inline unsigned int htab_sz(const struct htab *htab)
{
	return primes[htab->prime_idx];
}

static void htab_init_buckets(struct htab_bucket *buckets, int sz)
{
	int i;

	for (i = 0; i < sz; i++) {
		INIT_ELIST_HEAD(&buckets[i].chain);
	}
}

unsigned int htab_size(struct htab *htab)
{
	return htab->n_ent;
}

struct htab *htab_new(htab_hash_fn hash_fn,
		      htab_cmp_fn cmp_fn,
		      htab_free_fn free_key_fn,
		      htab_free_fn free_value_fn)
{
	struct htab *htab;
	int n_buckets;

	/* allocate & init htab struct */
	htab = calloc(1, sizeof(*htab));
	if (!htab)
		return NULL;

	htab->hash_fn = hash_fn;
	htab->cmp_fn = cmp_fn;
	htab->free_key_fn = free_key_fn;
	htab->free_value_fn = free_value_fn;

	n_buckets = htab_sz(htab);

	/* alloc & init hash table buckets */
	htab->buckets = calloc(n_buckets, sizeof(struct htab_bucket));
	if (!htab->buckets) {
		free(htab);
		return NULL;
	}

	htab_init_buckets(htab->buckets, n_buckets);

	return htab;
}

struct htab *htab_str_new(bool free_key, bool free_value)
{
	return htab_new(htab_str_hash, htab_str_cmp,
			free_key ? free : NULL,
			free_value ? free : NULL);
}

static void htab_free_ent(struct htab *htab, struct htab_entry *ent)
{
	if (!htab || !ent)
		return;

	/* call destructors */
	if (htab->free_key_fn)
		htab->free_key_fn(ent->key);
	if (htab->free_value_fn)
		htab->free_value_fn(ent->value);

	/* remove ourselves from the hash chain */
	elist_del(&ent->chain_node);

	/* delete hash entry */
	free(ent);

	/* account for entry's disapperance */
	htab->n_ent--;
}

static void htab_clear(struct htab *htab)
{
	struct htab_entry *ent, *iter;
	unsigned int bucket;

	/* remove each hash entry from each hash chain in each bucket */
	for (bucket = 0; bucket < htab_sz(htab); bucket++) {
		elist_for_each_entry_safe(ent, iter,
				 &htab->buckets[bucket].chain, chain_node) {
			htab_free_ent(htab, ent);
		}
	}
}

void htab_free(struct htab *htab)
{
	if (!htab)
		return;

	/* free all hash entries */
	htab_clear(htab);

	/* free hash table */
	free(htab->buckets);
	free(htab);
}

static bool htab_need_resize(const struct htab *htab)
{
	unsigned int sz = htab_sz(htab);
	unsigned int threshold = (sz * 2) / 3;

	/* if we exceed 2/3 total table size... */
	return (htab->n_ent > threshold);
}

static bool htab_resize(struct htab *htab)
{
	unsigned int old_sz, new_sz;
	struct htab_bucket *new_buckets;
	unsigned int bucket;

	/* calc old and new hash table sizes */
	old_sz = htab_sz(htab);
	new_sz = primes[htab->prime_idx + 1];

	/* alloc & init new table */
	new_buckets = calloc(new_sz, sizeof(struct htab_bucket));
	if (!new_buckets)
		return false;

	htab_init_buckets(new_buckets, new_sz);

	/* iterate through old table, moving each entry */
	for (bucket = 0; bucket < old_sz; bucket++) {
		struct htab_entry *ent, *iter;

		elist_for_each_entry_safe(ent, iter,
					 &htab->buckets[bucket].chain,
					 chain_node) {
			unsigned int new_bucket;

			elist_del_init(&ent->chain_node);

			new_bucket = ent->hash % new_sz;

			elist_add_tail(&ent->chain_node,
				      &new_buckets[new_bucket].chain);
		}
	}

	/* replace old table with new one */
	free(htab->buckets);
	htab->prime_idx++;
	htab->buckets = new_buckets;

	return true;
}

bool htab_put(struct htab *htab, void *key, void *value)
{
	struct htab_entry *ent;
	unsigned long hash = htab->hash_fn(key);
	unsigned int bucket = hash % htab_sz(htab);

	/* optionally resize table */
	if (htab_need_resize(htab) && !htab_resize(htab))
		return false;

	/* alloc * init hash entry */
	ent = calloc(1, sizeof(*ent));
	if (!ent)
		return false;

	ent->key = key;
	ent->value = value;
	ent->hash = hash;
	INIT_ELIST_HEAD(&ent->chain_node);

	/* add hash entry to bucket's chain */
	elist_add(&ent->chain_node, &htab->buckets[bucket].chain);

	/* account for additional hash entry */
	htab->n_ent++;

	return true;
}

void *htab_get(struct htab *htab, const void *key)
{
	struct htab_entry *ent;
	unsigned long hash = htab->hash_fn(key);
	unsigned int bucket = hash % htab_sz(htab);

	/* search bucket's chain for key, returning first value found */
	elist_for_each_entry(ent, &htab->buckets[bucket].chain, chain_node) {
		if ((ent->hash == hash) &&
		    (htab->cmp_fn(ent->key, key) == 0))
			return ent->value;
	}

	return NULL;
}

bool htab_del(struct htab *htab, const void *key)
{
	struct htab_entry *ent, *iter;
	unsigned long hash = htab->hash_fn(key);
	unsigned int bucket = hash % htab_sz(htab);
	bool found = false;

	/* search bucket's chain for key, deleting all matching entries */
	elist_for_each_entry_safe(ent, iter,
				 &htab->buckets[bucket].chain, chain_node) {
		if ((ent->hash == hash) &&
		    (htab->cmp_fn(ent->key, key) == 0)) {
			htab_free_ent(htab, ent);
			found = true;
		}
	}

	return found;
}

void htab_foreach(struct htab *htab, htab_iter_fn iter_fn, void *userdata)
{
	int i;

	for (i = 0; i < htab_sz(htab); i++) {
		struct htab_entry *ent, *iter;

		elist_for_each_entry_safe(ent, iter,
				         &htab->buckets[i].chain, chain_node) {
			iter_fn(ent->key, ent->value, userdata);
		}
	}
}

/* "djb2"-derived hash function */
unsigned long htab_djb_hash(unsigned long hash, const void *_buf, size_t buflen)
{
	const unsigned char *buf = _buf;
	int c;

	while (buflen > 0) {
		c = *buf++;
		buflen--;

		hash = ((hash << 5) + hash) ^ c; /* hash * 33 ^ c */
	}

	return hash;
}

unsigned long htab_ulong_hash(const void *buf)
{
	const unsigned long *v = buf;

	return *v;
}

int htab_ulong_cmp(const void *data1, const void *data2)
{
	const unsigned long *v1 = data1;
	const unsigned long *v2 = data2;

	return (*v1) - (*v2);
}

unsigned long htab_int_hash(const void *buf)
{
	const unsigned int *v = buf;

	return *v;
}

int htab_int_cmp(const void *data1, const void *data2)
{
	const unsigned int *v1 = data1;
	const unsigned int *v2 = data2;

	return (*v1) - (*v2);
}

unsigned long htab_str_hash(const void *buf)
{
	const char *s = buf;

	return htab_djb_hash(5381, s, strlen(s));
}

int htab_str_cmp(const void *data1, const void *data2)
{
	return strcmp(data1, data2);
}
