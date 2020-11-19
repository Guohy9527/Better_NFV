/*-
 *   BSD LICENSE
 *
 *   Copyright 2015 6WIND S.A.
 *   Copyright 2015 Mellanox.
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

#ifndef RTE_PMD_MLX5_DEFS_H_
#define RTE_PMD_MLX5_DEFS_H_

#include <rte_ethdev.h>

#include "mlx5_autoconf.h"

/* Reported driver name. */
#define MLX5_DRIVER_NAME "net_mlx5"

/* Maximum number of simultaneous MAC addresses. */
#define MLX5_MAX_MAC_ADDRESSES 128

/* Maximum number of simultaneous VLAN filters. */
#define MLX5_MAX_VLAN_IDS 128

/*
 * Request TX completion every time descriptors reach this threshold since
 * the previous request. Must be a power of two for performance reasons.
 */
#define MLX5_TX_COMP_THRESH 32

/*
 * Request TX completion every time the total number of WQEBBs used for inlining
 * packets exceeds the size of WQ divided by this divisor. Better to be power of
 * two for performance.
 */
#define MLX5_TX_COMP_THRESH_INLINE_DIV (1 << 3)

/*
 * Size of per-queue MR cache table. If LKEY search fails on the cache, PMD will
 * continue lookup in larger binary tree.
 */
#ifndef MLX5_MR_CACHE_N
#define MLX5_MR_CACHE_N 8
#endif

/*
 * If defined, only use software counters. The PMD will never ask the hardware
 * for these, and many of them won't be available.
 */
#ifndef MLX5_PMD_SOFT_COUNTERS
#define MLX5_PMD_SOFT_COUNTERS 1
#endif

/* Alarm timeout. */
#define MLX5_ALARM_TIMEOUT_US 100000

/* Maximum number of extended statistics counters. */
#define MLX5_MAX_XSTATS 32

/* Maximum Packet headers size (L2+L3+L4) for TSO. */
#define MLX5_MAX_TSO_HEADER 192

/* Default minimum number of Tx queues for vectorized Tx. */
#define MLX5_VPMD_MIN_TXQS 4

/* Threshold of buffer replenishment for vectorized Rx. */
#define MLX5_VPMD_RXQ_RPLNSH_THRESH(n) \
	(RTE_MIN(MLX5_VPMD_RX_MAX_BURST, (unsigned int)(n) >> 2))

/* Maximum size of burst for vectorized Rx. */
#define MLX5_VPMD_RX_MAX_BURST 64U

/*
 * Maximum size of burst for vectorized Tx. This is related to the maximum size
 * of Enhanced MPW (eMPW) WQE as vectorized Tx is supported with eMPW.
 * Careful when changing, large value can cause WQE DS to overlap.
 */
#define MLX5_VPMD_TX_MAX_BURST        32U

/* Number of packets vectorized Rx can simultaneously process in a loop. */
#define MLX5_VPMD_DESCS_PER_LOOP      4

/* Supported RSS */
#define MLX5_RSS_HF_MASK (~(ETH_RSS_IP | ETH_RSS_UDP | ETH_RSS_TCP))

/* Timeout in seconds to get a valid link status. */
#define MLX5_LINK_STATUS_TIMEOUT 10

/* Reserved address space for UAR mapping. */
#define MLX5_UAR_SIZE (1ULL << 32)

/* Offset of reserved UAR address space to hugepage memory. Offset is used here
 * to minimize possibility of address next to hugepage being used by other code
 * in either primary or secondary process, failing to map TX UAR would make TX
 * packets invisible to HW.
 */
#define MLX5_UAR_OFFSET (1ULL << 32)

/* First entry must be NULL for comparison. */
#define MLX5_MR_LOOKUP_TABLE_PAD 1

/* Log 2 of the default number of strides per WQE for Multi-Packet RQ. */
#define MLX5_MPRQ_STRIDE_NUM_N 6U

/* Two-byte shift is disabled for Multi-Packet RQ. */
#define MLX5_MPRQ_TWO_BYTE_SHIFT 0

/*
 * Minimum size of packet to be memcpy'd instead of being attached as an
 * external buffer.
 */
#define MLX5_MPRQ_MEMCPY_DEFAULT_LEN 128

/* Minimum number Rx queues to enable Multi-Packet RQ. */
#define MLX5_MPRQ_MIN_RXQS 12

/* Cache size of mempool for Multi-Packet RQ. */
#define MLX5_MPRQ_MP_CACHE_SZ 32U

#endif /* RTE_PMD_MLX5_DEFS_H_ */