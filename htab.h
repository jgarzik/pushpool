#ifndef __HTAB_H__
#define __HTAB_H__

struct htab;

typedef unsigned long (*htab_hash_fn)(const void *data);
typedef int (*htab_cmp_fn)(const void *data1, const void *data2);
typedef void (*htab_free_fn)(void *);

extern struct htab *htab_new(htab_hash_fn hash_fn,
			     htab_cmp_fn cmp_fn,
			     htab_free_fn free_key_fn,
			     htab_free_fn free_value_fn);
extern void htab_free(struct htab *htab);

extern bool htab_del(struct htab *htab, const void *key);
extern void *htab_get(struct htab *htab, const void *key);
extern bool htab_put(struct htab *htab, void *key, void *value);

/* hash functions available to library users */
extern unsigned long htab_direct_hash(const void *buf);
extern unsigned long htab_str_hash(const void *buf);
/* "djb2"-derived hash function */
extern unsigned long htab_djb_hash(unsigned long hash, const void *_buf, size_t buflen);

/* comparison functions available to library users */
extern int htab_str_cmp(const void *data1, const void *data2);

#endif /* __HTAB_H__ */
