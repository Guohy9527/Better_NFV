/*-
 *   BSD LICENSE
 *
 *   Copyright 2018 Mellanox.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of 6WIND S.A. nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include <string.h>

#include <rte_eal.h>
#include <rte_malloc.h>
#include <rte_debug.h>
#include <rte_debug.h>

#include "rte_qpool.h"

static inline void
rte_qpool_init(struct rte_qpool *pool, size_t size)
{
	pool->size = size;
	LIST_INIT(&pool->link);
	rte_spinlock_init(&pool->lock);
}

void *
rte_qpool_malloc(struct rte_qpool *pool, size_t size)
{
	struct rte_qpool_trunk *trunk;
	struct rte_qpool_entry *entry;
	size_t row, col;
	int idx = -1;
	int row_avail = 0;

	if (!pool->size)
		rte_qpool_init(pool, size);
	else if (pool->size != size)
		rte_panic("Trying to alloc different size from pool\n");
	if (!pool->no_lock)
		rte_spinlock_lock(&pool->lock);
	/* Locate free trunk */
	trunk = LIST_FIRST(&pool->link);
	if (!trunk) {
		trunk = rte_malloc_socket(__func__,
					  sizeof(*trunk) +
					  (size + sizeof(*entry)) *
					  sizeof(trunk->avail) * 8,
					  RTE_CACHE_LINE_SIZE, rte_socket_id());
		trunk->avail[0] = -1LU - 1;
		for (row = 1; row < RTE_DIM(trunk->avail); row++)
			trunk->avail[row] = -1LU;
		LIST_INSERT_HEAD(&pool->link, trunk, free);
		pool->n_trunk++;
#ifdef POOL_DEBUG
		pool->trunk_new++;
		pool->trunk_avail++;
#endif
		idx = 0;
	} else {
		/* Locate free entry in trunk */
		for (row = 0; row < RTE_DIM(trunk->avail); row++) {
			if (idx == -1 && trunk->avail[row]) {
				/* Reuse from this row */
				col = __builtin_ctzll(trunk->avail[row]);
				trunk->avail[row] &= ~(1LU << col);
				idx = row * 8 * sizeof(trunk->avail[0]) + col;
			}
			if (trunk->avail[row])
				row_avail = 1;
		}
		RTE_ASSERT(idx != -1);
		/* Remove trunk w/o free entry from avail list*/
		if (unlikely(!row_avail)) {
			LIST_REMOVE(trunk, free);
			trunk->free.le_prev = NULL;
#ifdef POOL_DEBUG
			pool->trunk_full++;
			pool->trunk_avail--;
#endif
		}
	}
	RTE_ASSERT(idx >= 0 && idx < (int)sizeof(trunk->avail) * 8);
	/* Record trunk address into entry */
	entry = RTE_PTR_ADD(trunk + 1, idx * (size + sizeof(*entry)));
#ifdef POOL_DEBUG
	RTE_ASSERT((entry->idx & 0x8000) == 0);
	RTE_ASSERT(entry->seq == 0);
	RTE_ASSERT(!entry->trunk || entry->trunk == trunk);
	idx |= 0x8000;
	entry->trunk = trunk;
	entry->seq = pool->entry_malloc;
	RTE_LOG(DEBUG, VSWITCH, "Qpool malloc: %lu\n", entry->seq);
	pool->entry_malloc++;
#endif
	entry->idx = idx;
	pool->n_entry++;
	if (!pool->no_lock)
		rte_spinlock_unlock(&pool->lock);
	return entry->data;
}

void *
rte_qpool_zalloc(struct rte_qpool *pool, size_t size)
{
	void *entry = rte_qpool_malloc(pool, size);

	if (entry)
		memset(entry, 0, size);
	return entry;
}

void
rte_qpool_free(struct rte_qpool *pool, void *ptr)
{
	struct rte_qpool_trunk *trunk;
	struct rte_qpool_entry *entry;
	size_t row, col, offset;
	uint16_t idx;

	/* Locate free trunk */
	entry = RTE_PTR_SUB(ptr, sizeof(*entry));
	idx = entry->idx;
#ifdef POOL_DEBUG
	RTE_LOG(INFO, VSWITCH, "Qpool free: %lu\n", entry->seq);
	RTE_ASSERT(idx & 0x8000);
	RTE_ASSERT(entry->trunk);
	RTE_ASSERT(entry->trunk);
	idx &= ~0x8000;
	entry->idx = idx;
	entry->seq = 0;
	pool->entry_free++;
#endif
	RTE_ASSERT(idx < sizeof(trunk->avail) * 8);
	offset = sizeof(*trunk) + idx * (pool->size + sizeof(*entry));
	trunk = RTE_PTR_SUB(entry, offset);
#ifdef POOL_DEBUG
	RTE_ASSERT(trunk == entry->trunk);
	entry->trunk = NULL;
#endif
	row = idx / sizeof(trunk->avail[0]) / 8;
	col = idx % (sizeof(trunk->avail[0]) * 8);
	if (!pool->no_lock)
		rte_spinlock_lock(&pool->lock);
	/* Locate entry */
	RTE_ASSERT((trunk->avail[row] & (1LU << col)) == 0);
	/* Set stats to free */
	trunk->avail[row] |= (1LU << col);
	/* Add a full trunk to free list */
	if (!trunk->free.le_prev) {
		LIST_INSERT_HEAD(&pool->link, trunk, free);
#ifdef POOL_DEBUG
		pool->trunk_full--;
		pool->trunk_avail++;
#endif
	} else if (!pool->no_trunk_free) {
		/* Free completely free trunk */
		for (row = 0; row < RTE_DIM(trunk->avail); row++) {
			if (trunk->avail[row] != -1LU)
				break;
		}
		if (row == RTE_DIM(trunk->avail)) {
			LIST_REMOVE(trunk, free);
			rte_free(trunk);
			pool->n_trunk--;
#ifdef POOL_DEBUG
			pool->trunk_avail++;
			pool->trunk_free++;
#endif
		}
	}
	pool->n_entry--;
	if (!pool->no_lock)
		rte_spinlock_unlock(&pool->lock);
}

void
rte_qpool_dump(struct rte_qpool *pool, const char *name, int clear)
{
	size_t n = sizeof(((struct rte_qpool_trunk *)(void *)0)->avail) * 8;

	printf("Pool %s entry size %lu usage: %ld/%ld(%ld * %lu)\n",
	       name, pool->size, pool->n_entry,
	       pool->n_trunk * n, pool->n_trunk, n);
	if (clear) {
		pool->n_trunk = 0;
		pool->n_entry = 0;
	}
}
