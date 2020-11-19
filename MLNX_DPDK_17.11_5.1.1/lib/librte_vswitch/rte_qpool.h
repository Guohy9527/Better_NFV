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

#ifndef RTE_QPOOL_H_
#define RTE_QPOOL_H_

#include <unistd.h>

#include <rte_spinlock.h>

// #define POOL_DEBUG 1

struct rte_qpool_trunk {
	uint64_t avail[6]; /* Bitmap of free entries. */
	LIST_ENTRY(rte_qpool_trunk) free;
	/* No tracking to trunk fully used. */
} __rte_cache_aligned;

struct rte_qpool_entry {
	uint16_t idx;
#ifdef POOL_DEBUG
	uint64_t seq;
	struct rte_qpool_trunk *trunk;
#endif
	uint8_t data[0];
};

/* For control thread only. */
struct rte_qpool {
	rte_spinlock_t lock;
	size_t size; /* Entry size including a trunk pointer */
	LIST_HEAD(free, rte_qpool_trunk) link; /* Free trunk list */
	int64_t n_entry;
	int64_t n_trunk;
	int no_lock:1;
	int no_trunk_free:1;
#ifdef POOL_DEBUG
	int64_t entry_malloc;
	int64_t entry_free;
	int64_t trunk_new;
	int64_t trunk_avail;
	int64_t trunk_full;
	int64_t trunk_free;
#endif
};

void *rte_qpool_malloc(struct rte_qpool *pool, size_t size);
void *rte_qpool_zalloc(struct rte_qpool *pool, size_t size);
void rte_qpool_free(struct rte_qpool *pool, void *entry);
void rte_qpool_dump(struct rte_qpool *pool, const char *name, int clear);

#endif /* RTE_QPOOL_H_ */

