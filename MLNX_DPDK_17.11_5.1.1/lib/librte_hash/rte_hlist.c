
#include <string.h>

#include <rte_common.h>
#include <rte_eal_memconfig.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_errno.h>
#include <rte_log.h>

#include "rte_hlist.h"

TAILQ_HEAD(rte_hlist_list, rte_tailq_entry);

static struct rte_tailq_elem rte_hlist_tailq = {
	.name = "RTE_HLIST",
};
EAL_REGISTER_TAILQ(rte_hlist_tailq)

hash_sig_t
rte_hlist_hash(const struct rte_hlist_table *h, const void *key)
{
	/* calc hash result by key */
	return h->hash_func(key, h->key_len, h->init_val);
}

static inline int
__rte_hlist_extend_list_table(struct rte_hlist_table *h)
{
	struct rte_hlist_head_entry *new;
	uint32_t dsize = (h->bucket_mask + 1) << 1;

	new = (struct rte_hlist_head_entry *)rte_realloc(h->t,
				sizeof(struct rte_hlist_head_entry) * dsize, 0);
	if (NULL == new) {
		rte_errno = ENOMEM;
		return -rte_errno;
	}
	memset(((char *)new)+sizeof(struct rte_hlist_head_entry)*(dsize>>1),
		0, sizeof(struct rte_hlist_head_entry)*(dsize>>1));

	/* new head that first element prev points to must be adjusted */
	h->t = new;
	h->entries *= 2;
	h->bucket_shift += 1;
	h->bucket_mask = dsize - 1;

	return 0;
}

static inline uint32_t
__rte_hlist_find_pre_unsplited_list(
	const struct rte_hlist_table *h, uint32_t idx)
{
	struct rte_hlist_head_entry *n_he;
	uint32_t gap = (h->bucket_shift > h->t[idx].bucket_shift) ?
		(h->bucket_shift - h->t[idx].bucket_shift) : 0;
	uint32_t i;
	uint32_t p_idx = idx;

	/* If the shift number is not zero, just return the one from input. */
	for (i=0; i<=gap; i++) {
		p_idx = idx & HLIST_CALC_PREVIOUS_BUCKET_MASK(h->bucket_mask, i);
		n_he = &h->t[p_idx];
		if (n_he->bucket_shift != 0)
			break;
	}

	return p_idx;
}

static inline int
__rte_hlist_split_one_list(const struct rte_hlist_table *h,
	uint32_t idx)
{
	struct rte_hlist_node_entry *pos;
	struct rte_hlist_node_entry *tp;
	struct rte_hlist_head_entry *he = &h->t[idx];
	struct rte_hlist_head_entry *n_he;
	uint32_t new_idx;
	uint32_t sh;
	uint32_t sh_gap_mul;
	uint32_t i = 0;

	if (h->bucket_shift <= he->bucket_shift) {
		rte_errno = EINVAL;
		return -rte_errno;
	}

	/* adjust the '(elm)->field.le_prev' of first element to the new head */
	LIST_MOVE_TO_NEW_HEAD(&he->head, &he->head, next);

	/* TAILQ is easy for lists combining when shrinking the table, but a lillte
	 * more memory will be costed for each head.
	 * No need to re-calculate the hash value.
	 */
	LIST_FOREACH_SAFE(pos, &he->head, next, tp) {
		new_idx = pos->d.sig & h->bucket_mask;
		if (new_idx != idx) {
			LIST_REMOVE(pos, next);
			he->entries_in_bucket--;
			n_he = &h->t[new_idx];
			LIST_INSERT_HEAD(&n_he->head, pos, next);
			n_he->entries_in_bucket++;
		}
	}

	/* old_mask to speed up: [0, old_mask+1, 2(old_mask+1) ... <mask] | idx */
	do {i++;} while (h->bucket_mask >> i);
	sh = i - (h->bucket_shift - he->bucket_shift);
	sh_gap_mul = 1 << (h->bucket_shift - he->bucket_shift);
	for (i=0; i<sh_gap_mul; i++) {
		new_idx = (i << sh) | idx;
		h->t[new_idx].bucket_shift = h->bucket_shift;
	}

	return 0;
}

static inline int
__rte_hlist_find_node_entry(struct rte_hlist_table *h,
	const void *key, hash_sig_t sig, struct rte_hlist_node_entry **p)
{
	uint32_t idx;
	uint32_t n_idx;
	struct rte_hlist_head_entry *he;
	struct rte_hlist_head_entry *n_he;
	struct rte_hlist_node_entry *pos;
	uint32_t matched = FALSE;
	int ret;

	if ((NULL == h) || (NULL == key) || (NULL == p)) {
		rte_errno = EINVAL;
		return -rte_errno;
	}

	idx = sig & h->bucket_mask;
	he = &h->t[idx];

	/* When the entries linked to the list reach upper limit, we try to
	 * extend the length of the head array. Then we just split this list.
	 * Others will be checked and splitted when being accessed.
	 * Shift number also needs to be checked in case of extra extending.
	 */
	if ((he->entries_in_bucket > h->entries_per_bucket) &&
		(he->bucket_shift == h->bucket_shift)) {
		/* If the list operation failed, it returns nothing even if matched */
		ret = __rte_hlist_extend_list_table(h);
		if (ret < 0) {
			RTE_LOG(ERR, HASH, "Failed to extend the list table %d\n", ret);
			goto exit;
		}
	}

	if (he->bucket_shift < h->bucket_shift) {
		uint32_t p_idx = __rte_hlist_find_pre_unsplited_list(h, idx);

		/* No matter how many times extending is done, one splitting is enough.
		 * If shift is 0, then the 'oldest' list that is not splitted
		 * should be splitted(no matter if any entry in). If not zero, just try
		 * to split this list and try to move entries into the new one.
		 */
		ret = __rte_hlist_split_one_list(h, p_idx);
		if (ret < 0) {
			RTE_LOG(ERR, HASH, "Failed to split the bucket %d\n", ret);
			goto exit;
		}
	}

	/* Need to re-do since the mask & pointer may change if extended */
	n_idx = sig & h->bucket_mask;
	n_he = &h->t[n_idx];

	/* Lazy way: just split the list that being accessed.
	 * After splitting, only one list needs to be traversed.
	 */
	if (n_he->entries_in_bucket > 0) {
		LIST_FOREACH(pos, &n_he->head, next) {
			if (pos->d.sig == sig)
				/* the key comparison could be optimized later */
				if (!memcmp(pos->key, key, h->key_len)) {
					matched = TRUE;
					break;
				}
		}
	}

	if (TRUE == matched) {
		*p = pos;
		/* The head index will always be the calculated one because of splitting */
		ret = n_idx;
	} else {
		*p = NULL;
		ret = -ENOENT;
	}

exit:
	return ret;
}

static inline struct rte_hlist_data_element *
__rte_hlist_add_key_with_hash_data(struct rte_hlist_table *h,
	const void *key, hash_sig_t sig, void *data, uint16_t len, uint8_t cus)
{
	int idx;
	struct rte_hlist_head_entry *he;
	struct rte_hlist_node_entry *pos;

	idx = __rte_hlist_find_node_entry(h, key, sig, &pos);
	if (idx >= 0) {
		pos->d.flags &= (~HLIST_DATA_NEW_ENTRY);
		return &pos->d;
	}
	else if ((idx < 0) && (idx != -ENOENT))
		return NULL;

	/* All the fields will be written */
	pos = rte_malloc(NULL,
		sizeof(struct rte_hlist_node_entry) + h->key_len, 0);
	if (NULL == pos) {
		RTE_LOG(ERR, HASH, "Failed to allocate new list node\n");
		return NULL;
	}

	pos->d.sig = sig;
	/* should be optimized if the key length is small */
	rte_memcpy(pos->key, key, h->key_len);
	/* user should be responsible for the data no matter how many bytes
	   the length is. */
	if (cus == TRUE) {
		pos->d.extra_data = data;
		pos->d.flags = HLIST_DATA_CUSTOM_EXTRA_DATA;
		h->custom_entries++;
	} else {
		if ((data != NULL) && (len != 0)) {
			pos->d.flags = HLIST_DATA_INLINE;
			switch (len) {
			case 1:
				pos->d.v8 = *(uint8_t *)data;
				break;
			case 2:
				pos->d.v16 = *(uint16_t *)data;
				break;
			case 4:
				pos->d.v32 = *(uint32_t *)data;
				break;
			case 8:
				pos->d.v64 = *(uint64_t *)data;
				break;
			default:
				pos->d.extra_data = rte_malloc(NULL, len, 0);
				if (NULL == pos->d.extra_data) {
					rte_free(pos);
					rte_errno = ENOMEM;
					return NULL;
				} else {
					rte_memcpy(pos->d.extra_data, data, len);
					pos->d.flags = HLIST_DATA_ALLOC_WITH_SIZE(len);
				}
			}
		} else {
			pos->d.extra_data = data;
			pos->d.flags = HLIST_DATA_NOT_EXIST;
		}
	}
	pos->d.flags |= HLIST_DATA_NEW_ENTRY;
	idx = sig & h->bucket_mask;
	he = &h->t[idx];
	LIST_INSERT_HEAD(&he->head, pos, next);
	he->entries_in_bucket++;

	return &pos->d;
}

struct rte_hlist_data_element *
rte_hlist_add_key(struct rte_hlist_table *h, const void *key)
{
	RETURN_IF_TRUE_ERRNO(((h == NULL) || (key == NULL)), NULL, -EINVAL);

	return __rte_hlist_add_key_with_hash_data(h, key,
			rte_hlist_hash(h, key), NULL, 0, FALSE);
}

struct rte_hlist_data_element *
rte_hlist_add_key_data(struct rte_hlist_table *h,
	const void *key, void *data)
{
	RETURN_IF_TRUE_ERRNO(((h == NULL) || (key == NULL)), NULL, -EINVAL);

	return __rte_hlist_add_key_with_hash_data(h, key,
			rte_hlist_hash(h, key), data, 0, TRUE);
}

struct rte_hlist_data_element *
rte_hlist_add_key_data_len(struct rte_hlist_table *h,
	const void *key, void *data, uint16_t len, uint8_t cus)
{
	RETURN_IF_TRUE_ERRNO(((h == NULL) || (key == NULL)), NULL, -EINVAL);

	return __rte_hlist_add_key_with_hash_data(h, key,
			rte_hlist_hash(h, key), data, len, cus);
}

struct rte_hlist_data_element *
rte_hlist_add_key_with_hash_data(struct rte_hlist_table *h,
	const void *key, hash_sig_t sig, void *data)
{
	RETURN_IF_TRUE_ERRNO(((h == NULL) || (key == NULL)), NULL, -EINVAL);

	return __rte_hlist_add_key_with_hash_data(h, key, sig, data, 0, TRUE);
}

struct rte_hlist_data_element *
rte_hlist_add_key_with_hash_data_len(
	struct rte_hlist_table *h, const void *key, hash_sig_t sig,
	void *data, uint16_t len, uint8_t cus)
{
	RETURN_IF_TRUE_ERRNO(((h == NULL) || (key == NULL)), NULL, -EINVAL);

	return __rte_hlist_add_key_with_hash_data(h, key, sig, data, len, cus);
}

static inline int
__rte_hlist_del_key_with_hash_return_data(
	struct rte_hlist_table *h, const void *key,
	hash_sig_t sig, void **data)
{
	struct rte_hlist_node_entry *pos;
	int idx = __rte_hlist_find_node_entry(h, key, sig, &pos);
	if (idx < 0)
		return idx;

	*data = NULL;
	if (HLIST_DATA_CUSTOM_EXTRA_DATA & pos->d.flags) {
		*data = pos->d.extra_data;
		h->custom_entries--;
	} else if (HLIST_DATA_IS_ALLOCATED(&pos->d)) {
		rte_free(pos->d.extra_data);
	}

	LIST_REMOVE(pos, next);
	rte_free(pos);
	h->t[idx].entries_in_bucket--;

	return 0;
}

static inline int
__rte_hlist_del_key_with_hash(struct rte_hlist_table *h,
	const void *key, hash_sig_t sig)
{
	struct rte_hlist_node_entry *pos;
	int idx;

	/* Currently there will be some 'false positive' to extend the lists head
	 * and split this list. e.g. only one more entry in the list to be
	 * moved to another list after extending and if it is the one to be removed,
	 * then there will be no entry in the 'brother' list after deletion. But
	 * the length of the lists head array is extended after searching. It is not
	 * a bug but not graceful enough right now. (Only for compact)
	 */
	idx = __rte_hlist_find_node_entry(h, key, sig, &pos);
	if (idx < 0)
		return idx;

	if (HLIST_DATA_CUSTOM_EXTRA_DATA & pos->d.flags) {
		if (NULL == h->free_func) {
			rte_errno = EBUSY;
			return -rte_errno;
		} else {
			h->free_func(pos->d.extra_data);
			h->custom_entries--;
		}
	} else if (HLIST_DATA_IS_ALLOCATED(&pos->d)) {
		rte_free(pos->d.extra_data);
	}

	LIST_REMOVE(pos, next);
	rte_free(pos);
	h->t[idx].entries_in_bucket--;

	return 0;
}

static inline int
__rte_hlist_del_entry_fast_return_data(struct rte_hlist_table *h,
	struct rte_hlist_data_element *de, void **data)
{
	struct rte_hlist_node_entry *pos;
	struct rte_hlist_head_entry *he;
	uint32_t idx = de->sig & h->bucket_mask;
	int ret;

	pos = container_of(de, struct rte_hlist_node_entry, d);
	he = &h->t[idx];

	/* Splitting will ensure that the head and the first element pointers
	   are consistent, or else the deletion will cause memory corruption */
	if (he->bucket_shift < h->bucket_shift) {
		uint32_t p_idx = __rte_hlist_find_pre_unsplited_list(h, idx);

		ret = __rte_hlist_split_one_list(h, p_idx);
		if (ret < 0) {
			RTE_LOG(ERR, HASH, "Failed to split the bucket %d\n", ret);
			return ret;
		}
	}

	if (HLIST_DATA_CUSTOM_EXTRA_DATA & pos->d.flags) {
		*data = pos->d.extra_data;
		h->custom_entries--;
	} else if (HLIST_DATA_IS_ALLOCATED(&pos->d)) {
		rte_free(pos->d.extra_data);
	}
	LIST_REMOVE(pos, next);
	rte_free(pos);
	he->entries_in_bucket--;

	return 0;
}

int
rte_hlist_del_key(struct rte_hlist_table *h, const void *key)
{
	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);

	return __rte_hlist_del_key_with_hash(h, key, rte_hlist_hash(h, key));
}

int
rte_hlist_del_key_return_data(struct rte_hlist_table *h,
	const void *key, void **data)
{
	RETURN_IF_TRUE(((h == NULL) || (key == NULL) || (data == NULL)), -EINVAL);

	return __rte_hlist_del_key_with_hash_return_data(h, key,
			rte_hlist_hash(h, key), data);
}

int
rte_hlist_del_entry_fast_return_data(struct rte_hlist_table *h,
	struct rte_hlist_data_element *de, void **data)
{
	RETURN_IF_TRUE(((h == NULL) || (key == NULL) || (data == NULL)), -EINVAL);

	return __rte_hlist_del_entry_fast_return_data(h, de, data);
}

struct rte_hlist_data_element *
rte_hlist_lookup_with_hash(struct rte_hlist_table *h,
	const void *key, hash_sig_t sig)
{
	struct rte_hlist_node_entry *p;
	int idx;

	idx = __rte_hlist_find_node_entry(h, key, sig, &p);
	if (idx < 0)
		return NULL;

	return &p->d;
}

struct rte_hlist_data_element *
rte_hlist_lookup(struct rte_hlist_table *h, const void *key)
{
	RETURN_IF_TRUE_ERRNO(((h == NULL) || (key == NULL)), NULL, -EINVAL);

	return rte_hlist_lookup_with_hash(h, key, rte_hlist_hash(h, key));
}

static inline int
__rte_hlist_clear_all_entries(struct rte_hlist_table *h, uint8_t force)
{
	uint32_t size;
	uint32_t i;
	struct rte_hlist_head_entry *he;
	struct rte_hlist_node_entry *pos;
	struct rte_hlist_node_entry *tp;

	if (NULL == h) {
		rte_errno = EINVAL;
		return -rte_errno;
	}

	if ((FALSE == force) && (h->custom_entries) && (NULL == h->free_func)) {
		rte_errno = EBUSY;
		return -rte_errno;
	}

	size = h->bucket_mask + 1;
	for (i=0; i<size; i++) {
		he = &h->t[i];
		if (he->entries_in_bucket > 0) {
			LIST_MOVE_TO_NEW_HEAD(&he->head, &he->head, next);
			LIST_FOREACH_SAFE(pos, &he->head, next, tp) {
				if (HLIST_DATA_IS_ALLOCATED(&pos->d)) {
					rte_free(pos->d.extra_data);
				} else if (HLIST_DATA_CUSTOM_EXTRA_DATA & pos->d.flags) {
					h->custom_entries--;
					if (NULL != h->free_func)
						h->free_func(pos->d.extra_data);
				}
				LIST_REMOVE(pos, next);
				rte_free(pos);
				he->entries_in_bucket--;
			}
		}
	}

	return 0;
}

int
rte_hlist_clear_all_entries_with_cb(struct rte_hlist_table *h,
	rte_hlist_free_fn fn)
{
	rte_hlist_free_fn saved_fn;
	int ret;

	RETURN_IF_TRUE((h == NULL), -EINVAL);
	saved_fn = h->free_func;
	h->free_func = fn;
	ret = __rte_hlist_clear_all_entries(h, TRUE);
	h->free_func = saved_fn;

	return ret;
}

struct rte_hlist_table *
rte_hlist_create(const struct rte_hlist_params *params)
{
	struct rte_hlist_table *ht = NULL;
	struct rte_tailq_entry *te;
	char hash_name[RTE_HLIST_NAMESIZE];
	struct rte_hlist_list *hlist_list;
	uint32_t table_size;

	hlist_list = RTE_TAILQ_CAST(rte_hlist_tailq.head,
				       rte_hlist_list);

	/* Error checking of parameters. */
	if ((!rte_is_power_of_2(params->entries)) ||
			(!rte_is_power_of_2(params->entries_per_bucket)) ||
			(params->entries == 0) ||
			(params->entries_per_bucket == 0) ||
			(params->entries_per_bucket > params->entries) ||
			(params->entries > RTE_HLIST_ENTRIES_MAX) ||
			(params->entries_per_bucket > RTE_HLIST_ENTRIES_PER_BUCKET_MAX)){
		rte_errno = EINVAL;
		return NULL;
	}

	snprintf(hash_name, sizeof(hash_name), "HLIST_%s", params->name);

	rte_rwlock_write_lock(RTE_EAL_TAILQ_RWLOCK);

	/* guarantee there's no existing */
	TAILQ_FOREACH(te, hlist_list, next) {
		ht = (struct rte_hlist_table *)te->data;
		if (strncmp(params->name, ht->name, RTE_HLIST_NAMESIZE) == 0)
			break;
	}
	ht = NULL;
	if (te != NULL) {
		rte_errno = EEXIST;
		goto exit;
	}

	te = rte_zmalloc("HLIST_TAILQ_ENTRY", sizeof(struct rte_tailq_entry), 0);
	if (te == NULL) {
		RTE_LOG(ERR, HASH, "Failed to allocate tailq entry for hlist\n");
		goto exit;
	}

	/* Allocate memory for table. */
	ht = (struct rte_hlist_table *)rte_zmalloc_socket(hash_name,
			sizeof(struct rte_hlist_table), 0, params->socket_id);
	if (ht == NULL) {
		RTE_LOG(ERR, HASH, "Failed to allocate hlist table\n");
		rte_free(te);
		goto exit;
	}

	table_size = params->entries / params->entries_per_bucket;
	ht->t = rte_zmalloc_socket(NULL,
			sizeof(struct rte_hlist_head_entry) * table_size,
			0, params->socket_id);
	if (ht->t == NULL) {
		RTE_LOG(ERR, HASH, "Failed to allocate hlist head table\n");
		rte_free(te);
		rte_free(ht);
		goto exit;
	}

	/* Because HLIST_HEAD_INIT is to initialize the value to zero, skip it
	 * here to accelerate the initialization stage. */

	/* Set up hash table context. */
	snprintf(ht->name, sizeof(ht->name), "%s", params->name);
	ht->entries = params->entries;
	ht->entries_per_bucket = params->entries_per_bucket;
	/* since table size is a power of 2 */
	ht->bucket_mask = table_size - 1;
	ht->key_len = params->key_len;

	if (params->hash_func != NULL) {
		ht->hash_func = params->hash_func;
		ht->init_val = params->init_val;
	}
	else {
		ht->hash_func = RTE_HLIST_FUNC_DEFAULT;
		ht->init_val = RTE_HLIST_INIT_VAL_DEFAULT;
	}

	/* not mandatory for the free function */
	ht->free_func = params->free_func;

	te->data = (void *)ht;

	TAILQ_INSERT_TAIL(hlist_list, te, next);

exit:
	rte_rwlock_write_unlock(RTE_EAL_TAILQ_RWLOCK);

	return ht;
}

int rte_hlist_free(struct rte_hlist_table *h)
{
	struct rte_tailq_entry *te;
	struct rte_hlist_list *hlist_list;

	if (h == NULL) {
		rte_errno = EINVAL;
		return -rte_errno;
	}

	hlist_list = RTE_TAILQ_CAST(rte_hlist_tailq.head, rte_hlist_list);

	rte_rwlock_write_lock(RTE_EAL_TAILQ_RWLOCK);

	/* find out tailq entry */
	TAILQ_FOREACH(te, hlist_list, next) {
		if (te->data == (void *)h)
			break;
	}

	if (te == NULL) {
		rte_rwlock_write_unlock(RTE_EAL_TAILQ_RWLOCK);

		rte_errno = EEXIST;
		return -rte_errno;
	}

	TAILQ_REMOVE(hlist_list, te, next);

	rte_rwlock_write_unlock(RTE_EAL_TAILQ_RWLOCK);

	(void)__rte_hlist_clear_all_entries(h, TRUE);
	rte_free(h);
	rte_free(te);

	return 0;
}

