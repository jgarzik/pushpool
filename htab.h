#ifndef __HTAB_H__
#define __HTAB_H__

#include <sys/types.h>

struct htab;

typedef unsigned long (*htab_hash_fn)(const void *data);
typedef int (*htab_cmp_fn)(const void *data1, const void *data2);
typedef void (*htab_free_fn)(void *);
typedef void (*htab_iter_fn)(void *key, void *value, void *userdata);

extern struct htab *htab_new(htab_hash_fn hash_fn,
			     htab_cmp_fn cmp_fn,
			     htab_free_fn free_key_fn,
			     htab_free_fn free_value_fn);
extern struct htab *htab_str_new(bool free_key, bool free_value);
extern void htab_free(struct htab *htab);
extern unsigned int htab_size(struct htab *htab);

extern bool htab_del(struct htab *htab, const void *key);
extern void *htab_get(struct htab *htab, const void *key);
extern bool htab_put(struct htab *htab, void *key, void *value);

extern void htab_foreach(struct htab *htab, htab_iter_fn iter_fn,
			 void *userdata);

/* hash functions available to library users */
extern unsigned long htab_ulong_hash(const void *buf);
extern unsigned long htab_int_hash(const void *buf);
extern unsigned long htab_str_hash(const void *buf);

/* "djb2"-derived hash function */
extern unsigned long htab_djb_hash(unsigned long hash, const void *_buf, size_t buflen);

/* comparison functions available to library users */
extern int htab_str_cmp(const void *data1, const void *data2);
extern int htab_ulong_cmp(const void *data1, const void *data2);
extern int htab_int_cmp(const void *data1, const void *data2);

#endif /* __HTAB_H__ */
