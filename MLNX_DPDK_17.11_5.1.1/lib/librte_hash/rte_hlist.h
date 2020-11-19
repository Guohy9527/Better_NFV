
#ifndef _RTE_HLIST_H_
#define _RTE_HLIST_H_

/**
 * @file
 *
 *
 *
 *
 *
 *
 */


#include <stdint.h>

#include <errno.h>

/* To enable the deletion when iterating the list */
#ifndef LIST_FOREACH_SAFE
#define LIST_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = ((head)->lh_first);				\
		(var) && ((tvar) = ((var)->field.le_next), 1);		\
		(var) = (tvar))
#endif

#define LIST_MOVE_TO_NEW_HEAD(new, old, field) do {			\
	if (((new)->lh_first = (old)->lh_first) != NULL)		\
		(new)->lh_first->field.le_prev = &(new)->lh_first;	\
} while (/*CONSTCOND*/0)

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_config.h>
#ifndef RTE_HLIST_FUNC_DEFAULT
#if defined(RTE_ARCH_X86) || defined(RTE_MACHINE_CPUFLAG_CRC32)
#include <rte_hash_crc.h>
/** Default hlist hash function if none is specified. */
#define RTE_HLIST_FUNC_DEFAULT		rte_hash_crc
#else
#include <rte_jhash.h>
#define RTE_HLIST_FUNC_DEFAULT		rte_jhash
#endif
#endif

#ifndef RTE_HLIST_INIT_VAL_DEFAULT
/** Initialising value used when calculating hash. */
#define RTE_HLIST_INIT_VAL_DEFAULT	0xFFFFFFFF
#endif

/* Macro to enable/disable run-time checking of function parameters */
#if defined(RTE_LIBRTE_HASH_DEBUG)
#define RETURN_IF_TRUE(cond, retval) do {				\
	if (cond)							\
		return retval;						\
} while (0)

#define RETURN_IF_TRUE_ERRNO(cond, retval, err) do {			\
		if (cond) {						\
			rte_errno = err;				\
			return retval;					\
		}							\
	} while (0)
#else
#define RETURN_IF_TRUE(cond, retval)
#define RETURN_IF_TRUE_ERRNO(cond, retval, err)
#endif

/** Maximum size of string for naming the hlist table. */
#define RTE_HLIST_NAMESIZE			32

/** The maximum number of entries in the hlist table that is supported. */
#define RTE_HLIST_ENTRIES_MAX			(1 << 24)

/** The maximum number of entries in each list that is supported. */
#define RTE_HLIST_ENTRIES_PER_BUCKET_MAX	128

/** Calculate the previous mask before splitting */
#define HLIST_CALC_PREVIOUS_BUCKET_MASK(v, s)	((((v)+1) >> (s)) - 1)

/** Flag bits for the data stored */
#define HLIST_DATA_NEW_ENTRY			(0x80000000)
#define HLIST_DATA_CUSTOM_EXTRA_DATA		(0x40000000)
#define HLIST_DATA_INLINE			(0x20000000)
#define HLIST_DATA_ALLOC_WITH_SIZE(s)		(0x10000000 | ((0x0fffffff) & (s)))
#define HLIST_DATA_IS_ALLOCATED(d)		!!((d)->flags & 0x10000000)
#define HLIST_DATA_NOT_EXIST			(0x00000000)

/** Signature of key that is stored internally. */
typedef uint32_t hash_sig_t;

/** Type of function that can be used for calculating the hash value. */
typedef uint32_t (*rte_hlist_calc_fn)(const void *key, uint32_t key_len, uint32_t init_val);

/** Type of function that is used to free the data from customer. */
typedef void (*rte_hlist_free_fn)(void *p);

/** Parameters used when creating hash list table. */
struct rte_hlist_params {
	const char *name;		/**< Name of the hash table. */
	uint32_t entries;		/**< Total number of entries. */
	uint32_t entries_per_bucket;	/**< Number of entries in a bucket. */
	uint32_t key_len;		/**< Length of the key to be calcuated. */
	int socket_id;			/**< Socket to allocate memory on. */
	rte_hlist_calc_fn hash_func;	/**< The hash function to calcuate. */
	rte_hlist_free_fn free_func;	/**< The function to free the custom data. */
	uint32_t init_val;		/**< For initializing hash function. */
};

/** Data element structure for future use */
struct rte_hlist_data_element {
	union {				/**< Union for data, pointer or inline */
		void *extra_data;
		uint64_t v64;
		uint32_t v32;
		uint16_t v16;
		uint8_t v8;
	};
	uint32_t sig;			/**< Calcuated hash value. */
	uint32_t flags;			/**< Flag bits of the data store. */
};

/** Node element structure on the LIST of the link */
struct rte_hlist_node_entry {
	LIST_ENTRY(rte_hlist_node_entry) next;	/**< Next element pointer. */
	struct rte_hlist_data_element d;	/**< Data element inside this noed. */
	char key[];				/**< Copied and stored key. */
};

/** Head of all the nodes with the same hash value */
struct rte_hlist_head_entry {
	LIST_HEAD(, rte_hlist_node_entry) head;	/**< Head for each hash list. */
	uint16_t entries_in_bucket; 		/**< Current items in the list. */
	uint16_t bucket_shift;			/**< Shift number for extension */
};

/** The hlist table structure. */
struct rte_hlist_table {
	char name[RTE_HLIST_NAMESIZE];	/**< Name of the hash. */
	uint32_t entries;		/**< Total number of entries. */
	uint32_t entries_per_bucket;	/**< Number of entries in a list. */
	uint32_t custom_entries;	/**< Number of entries with data from customer. */
	uint16_t key_len;		/**< Length of the key. */
	uint16_t bucket_shift;		/**< Shift number of the whole table. */
	uint32_t bucket_mask;		/**< To find which list the key is in. */
	rte_hlist_calc_fn hash_func;	/**< The hash function to calcuate. */
	rte_hlist_free_fn free_func;	/**< The function to free the custom data*/
	uint32_t init_val;		/**< For initializing hash function. */
	char *map;			/**< Reserved for fast shrinking of the table. */

	/**< A flat and extendible table of all lists. */
	struct rte_hlist_head_entry *t;
};

/**
 * Calc a hash value by key.
 * This operation is not multi-thread safe.
 *
 * @param h
 *   Hlist table to look in.
 * @param key
 *   Key to calc.
 * @return
 *   - hash value
 */
hash_sig_t
rte_hlist_hash(const struct rte_hlist_table *h, const void *key);

/**
 * Add a key to an existing hash list without data. This operation is not
 * multi-thread safe and should only be called from one thread.
 *
 * @param h
 *   Hlist table to add the key to.
 * @param key
 *   Key to add to the hlist table.
 * @return
 *   - NULL pointer if failed to add the key, check the variable rte_errno for
 *     more error information.
 *   - A data element pointer with useful information for future use.
 */
struct rte_hlist_data_element *
rte_hlist_add_key(struct rte_hlist_table *h, const void *key);

/**
 * Add a key to an existing hash list with customer data. This operation is not
 * multi-thread safe and should only be called from one thread.
 *
 * @param h
 *   Hlist table to add the key to.
 * @param key
 *   Key to add to the hlist table.
 * @param data
 *   Customer data pointer, and it is the caller's responsibility not to release
 *   it if the data area will be accessed later.
 * @return
 *   - NULL pointer if failed to add the key, check the variable rte_errno for
 *     more error information.
 *   - A data element pointer with useful information for future use.
 */
struct rte_hlist_data_element *
rte_hlist_add_key_data(struct rte_hlist_table *h, const void *key, void *data);

/**
 * Add a key to an existing hash list with customer data. This operation is not
 * multi-thread safe and should only be called from one thread.
 *
 * @param h
 *   Hlist table to add the key to.
 * @param key
 *   Key to add to the hlist table.
 * @param data
 *   Customer data pointer, and it is the caller's responsibility not to release
 *   it if the data area will be accessed later.
 * @param len
 *   The length of the customer's data.
 * @param cus
 *   The allocation attribute of the data. If yes, it is the customer's
 *   responsibility to hold/release the data, or else, a copy of the data will
 *   be held and the data pointer is free to release or re-use.
 * @return
 *   - NULL pointer if failed to add the key, check the variable rte_errno for
 *     more error information.
 *   - A data element pointer with useful information for future use.
 */
struct rte_hlist_data_element *
rte_hlist_add_key_data_len(struct rte_hlist_table *h, const void *key, void *data, uint16_t len, uint8_t cus);

/**
 * Add a key to an existing hash list with customer data. This operation is not
 * multi-thread safe and should only be called from one thread.
 *
 * @param h
 *   Hlist table to add the key to.
 * @param key
 *   Key to add to the hlist table. 
 * @param sig
 *   Precomputed hash value for 'key'.
 * @param data
 *   Customer data pointer, and it is the caller's responsibility not to release
 *   it if the data area will be accessed later.
 * @return
 *   - NULL pointer if failed to add the key, check the variable rte_errno for
 *     more error information.
 *   - A data element pointer with useful information for future use.
 */
struct rte_hlist_data_element *
rte_hlist_add_key_with_hash_data(struct rte_hlist_table *h, const void *key, hash_sig_t sig, void *data);

/**
 * Add a key to an existing hash list with customer data. This operation is not
 * multi-thread safe and should only be called from one thread.
 *
 * @param h
 *   Hlist table to add the key to.
 * @param key
 *   Key to add to the hlist table.
 * @param sig
 *   Precomputed hash value for 'key'.
 * @param data
 *   Customer data pointer.
 * @param len
 *   The length of the customer's data.
 * @param cus
 *   The allocation attribute of the data. If yes, it is the customer's
 *   responsibility to hold/release the data, or else, a copy of the data will
 *   be held and the data pointer is free to release or re-use.
 * @return
 *   - NULL pointer if failed to add the key, check the variable rte_errno for
 *     more error information.
 *   - A data element pointer with useful information for future use.
 */
struct rte_hlist_data_element *
rte_hlist_add_key_with_hash_data_len(struct rte_hlist_table *h, const void *key, hash_sig_t sig, void *data, uint16_t len, uint8_t cus);

/**
 * Remove a key from an existing hlist table. This operation is not multi-thread
 * safe and should only be called from one thread.
 *
 * @param h
 *   Hlist table to remove the key from.
 * @param key
 *   Key to remove from the hlist table.
 * @return
 *   - -EINVAL if the parameters are invalid.
 *   - -ENOMEM if failed to extend the lists head.
 *   - -ENOENT if the key is not found.
 *   - -EBUSY if there is custom data but without custom free fuction.
 *   - zero for success.
 */
int
rte_hlist_del_key(struct rte_hlist_table *h, const void *key);

/**
 * Remove a key from an existing hlist table, and return the data pointer to the
 * customer if any but without trying to free it. This operation is not
 * multi-thread safe and should only be called from one thread.
 *
 * @param h
 *   Hlist table to remove the key from.
 * @param key
 *   Key to remove from the hlist table.
 * @param data
 *   Output containing a pointer to the data.
 * @return
 *   - -EINVAL if the parameters are invalid.
 *   - -ENOMEM if failed to extend the lists head.
 *   - -ENOENT if the key is not found.
 *   - zero for success.
 */
int
rte_hlist_del_key_return_data(struct rte_hlist_table *h, const void *key, void **data);

/**
 * Remove an entry from an existing hlist table, and return the data pointer to
 * the customer if any but without trying to free it. User should ensure the
 * integrity of the entry. This operation is not multi-thread safe and should
 * only be called from one thread.
 *
 * @param h
 *   Hlist table to remove the key from.
 * @param de
 *   Data element to be removed from the hlist table.
 * @param data
 *   Output containing a pointer to the data.
 * @return
 *   - -EINVAL if the parameters are invalid.
 *   - zero for success.
 */
int
rte_hlist_del_entry_fast_return_data(struct rte_hlist_table *h, struct rte_hlist_data_element *de, void **data);

/**
 * Find a key in the hlist table.
 * This operation is not multi-thread safe.
 *
 * @param h
 *   Hlist table to look in.
 * @param key
 *   Key to find.
 * @return
 *   - NULL if failed to search the key in the hlist. Check the rte_errno for
 *     more error information.
 *     -EINVAL if the parameters are invalid.
 *     -ENOMEM if failed to extend the lists head.
 *     -ENOENT if the key is not found.
 *   - A data element pointer with useful information for future use.
 */
struct rte_hlist_data_element *
rte_hlist_lookup(struct rte_hlist_table *h, const void *key);

/**
 * Find a key in the hlist table.
 * This operation is not multi-thread safe.
 *
 * @param h
 *   Hlist table to look in.
 * @param key
 *   Key to find.
 * @param sig
 *   Precomputed hash value for 'key'.
 * @return
 *   - NULL if failed to search the key in the hlist. Check the rte_errno for
 *     more error information.
 *     -EINVAL if the parameters are invalid.
 *     -ENOMEM if failed to extend the lists head.
 *     -ENOENT if the key is not found.
 *   - A data element pointer with useful information for future use.
 */
struct rte_hlist_data_element *
rte_hlist_lookup_with_hash(struct rte_hlist_table *h, const void *key, hash_sig_t sig);

/**
 * Check if the data entry is a new one.
 * This operation is not multi-thread safe.
 *
 * @param d
 *   Pointer to the data entry.
 * @return
 *   No is 0 and Yes is 1.
 */
static inline uint32_t
rte_hlist_entry_is_new(struct rte_hlist_data_element *d)
{
	return !!(d->flags & HLIST_DATA_NEW_ENTRY);
}

/**
 * Append customer data to the data element.
 * This operation is not multi-thread safe.
 *
 * @param h
 *   Hlist table to look in.
 * @param d
 *   Pointer to the data entry.
 * @param data
 *   Data address to be append.
 * @return
 *   - -EINVAL if the parameters are invalid.
 *   - -EEXIST if there is alreay some data.
 *   - 0 if succeed.
 */
static inline int
rte_hlist_entry_append_custom_data(struct rte_hlist_table *h, struct rte_hlist_data_element *d, void *data)
{
	if ((NULL==h) || (NULL==d) || (NULL==data))
		return -EINVAL;

	if ((d->flags & (~HLIST_DATA_NEW_ENTRY)) != HLIST_DATA_NOT_EXIST)
		return -EEXIST;

	d->extra_data = data;
	d->flags |= HLIST_DATA_CUSTOM_EXTRA_DATA;
	h->custom_entries++;
	return 0;
}

/**
 * Create a new hlist table. This operation is not multi-thread safe.
 *
 * @param params
 *	 Parameters used in creation of hlist table.
 *
 * @return
 *	 Pointer to hlist table structure that is used in future hlist table
 *	 operations, or NULL on error with error code set in rte_errno.
 */
struct rte_hlist_table *
rte_hlist_create(const struct rte_hlist_params *params);

/**
 * Free all memory used by a hlist table. Note, this will force to try to
 * release all the customer's data before it cleans the memories of the table.
 *
 * @param h
 *   Hlist table to deallocate.
 * @return
 *   - 0 if succeed.
 *   - -EINVAL if the parameters are invalid.
 *   - -EEXIST if the hlist doesn't exist.
 */
int rte_hlist_free(struct rte_hlist_table *h);

/**
 * Free all entries in the hash list table, and the customer's data could be
 * handled by the callback function (optional).
 *
 * @param h
 *   Hlist table to deallocate.
 * @param fn
 *   Callback function for the customer data handling.
 * @return
 *   - 0 if succeed.
 *   - -EINVAL if the parameters are invalid.
 *   - -EBUSY if the hlist doesn't exist.
 */
int rte_hlist_clear_all_entries_with_cb(struct rte_hlist_table *h, rte_hlist_free_fn fn);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_HLIST_H_ */
