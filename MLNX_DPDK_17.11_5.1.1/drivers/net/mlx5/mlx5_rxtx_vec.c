/*-
 *   BSD LICENSE
 *
 *   Copyright 2017 6WIND S.A.
 *   Copyright 2017 Mellanox.
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

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* Verbs header. */
/* ISO C doesn't support unnamed structs/unions, disabling -pedantic. */
#ifdef PEDANTIC
#pragma GCC diagnostic ignored "-Wpedantic"
#endif
#include <infiniband/verbs.h>
#include <infiniband/mlx5dv.h>
#ifdef PEDANTIC
#pragma GCC diagnostic error "-Wpedantic"
#endif

#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_prefetch.h>

#include "mlx5.h"
#include "mlx5_utils.h"
#include "mlx5_rxtx.h"
#include "mlx5_rxtx_vec.h"
#include "mlx5_autoconf.h"
#include "mlx5_defs.h"
#include "mlx5_prm.h"

#if defined RTE_ARCH_X86_64
#include "mlx5_rxtx_vec_sse.h"
#elif defined RTE_ARCH_ARM64
#include "mlx5_rxtx_vec_neon.h"
#else
#error "This should not be compiled if SIMD instructions are not supported."
#endif

/**
 * Count the number of packets having same ol_flags and same metadata (if
 * PKT_TX_METADATA is set in ol_flags), and calculate cs_flags.
 *
 * @param pkts
 *   Pointer to array of packets.
 * @param pkts_n
 *   Number of packets.
 * @param cs_flags
 *   Pointer of flags to be returned.
 * @param metadata
 *   Pointer of metadata to be returned.
 * @param txq_offloads
 *   Offloads enabled on Tx queue
 *
 * @return
 *   Number of packets having same ol_flags.
 */
static inline unsigned int
txq_calc_offload(struct rte_mbuf **pkts, uint16_t pkts_n, uint8_t *cs_flags,
		 rte_be32_t *metadata, const uint64_t txq_offloads)
{
	unsigned int pos;
	const uint64_t cksum_ol_mask =
		PKT_TX_IP_CKSUM | PKT_TX_TCP_CKSUM |
		PKT_TX_UDP_CKSUM | PKT_TX_TUNNEL_GRE |
		PKT_TX_TUNNEL_VXLAN | PKT_TX_OUTER_IP_CKSUM;
	rte_be32_t p0_metadata, pn_metadata;

	if (!pkts_n)
		return 0;
	p0_metadata = pkts[0]->ol_flags & PKT_TX_METADATA ?
			pkts[0]->udata32 : 0;
	/* Count the number of packets having same offload parameters. */
	for (pos = 1; pos < pkts_n; ++pos) {
		/* Check if packet has same checksum flags. */
		if ((txq_offloads & MLX5_VEC_TX_CKSUM_OFFLOAD_CAP) &&
		    ((pkts[pos]->ol_flags ^ pkts[0]->ol_flags) & cksum_ol_mask))
			break;
		/* Check if packet has same metadata. */
		if (txq_offloads & DEV_TX_OFFLOAD_MATCH_METADATA) {
			pn_metadata = pkts[pos]->ol_flags & PKT_TX_METADATA ?
					pkts[pos]->udata32 : 0;
			if (pn_metadata != p0_metadata)
				break;
		}
	}
	*cs_flags = txq_ol_cksum_to_cs(pkts[0]);
	*metadata = p0_metadata;
	return pos;
}

/**
 * DPDK callback for vectorized TX.
 *
 * @param dpdk_txq
 *   Generic pointer to TX queue structure.
 * @param[in] pkts
 *   Packets to transmit.
 * @param pkts_n
 *   Number of packets in array.
 *
 * @return
 *   Number of packets successfully transmitted (<= pkts_n).
 */
uint16_t
mlx5_tx_burst_raw_vec(void *dpdk_txq, struct rte_mbuf **pkts,
		      uint16_t pkts_n)
{
	struct mlx5_txq_data *txq = (struct mlx5_txq_data *)dpdk_txq;
	uint16_t nb_tx = 0;

	while (pkts_n > nb_tx) {
		uint16_t n;
		uint16_t ret;

		n = RTE_MIN((uint16_t)(pkts_n - nb_tx), MLX5_VPMD_TX_MAX_BURST);
		ret = txq_burst_v(txq, &pkts[nb_tx], n, 0, 0);
		nb_tx += ret;
		if (!ret)
			break;
	}
	return nb_tx;
}

/**
 * DPDK callback for vectorized TX with multi-seg packets and offload.
 *
 * @param dpdk_txq
 *   Generic pointer to TX queue structure.
 * @param[in] pkts
 *   Packets to transmit.
 * @param pkts_n
 *   Number of packets in array.
 *
 * @return
 *   Number of packets successfully transmitted (<= pkts_n).
 */
uint16_t
mlx5_tx_burst_vec(void *dpdk_txq, struct rte_mbuf **pkts, uint16_t pkts_n)
{
	struct mlx5_txq_data *txq = (struct mlx5_txq_data *)dpdk_txq;
	uint16_t nb_tx = 0;

	while (pkts_n > nb_tx) {
		uint8_t cs_flags = 0;
		uint16_t n;
		uint16_t ret;
		rte_be32_t metadata = 0;

		/* Transmit multi-seg packets in the head of pkts list. */
		if ((txq->offloads & DEV_TX_OFFLOAD_MULTI_SEGS) &&
		    NB_SEGS(pkts[nb_tx]) > 1)
			nb_tx += txq_scatter_v(txq,
					       &pkts[nb_tx],
					       pkts_n - nb_tx);
		n = RTE_MIN((uint16_t)(pkts_n - nb_tx), MLX5_VPMD_TX_MAX_BURST);
		if (txq->offloads & DEV_TX_OFFLOAD_MULTI_SEGS)
			n = txq_count_contig_single_seg(&pkts[nb_tx], n);
		if (txq->offloads & (MLX5_VEC_TX_CKSUM_OFFLOAD_CAP |
				     DEV_TX_OFFLOAD_MATCH_METADATA))
			n = txq_calc_offload(&pkts[nb_tx], n,
					     &cs_flags, &metadata,
					     txq->offloads);
		ret = txq_burst_v(txq, &pkts[nb_tx], n, cs_flags, metadata);
		nb_tx += ret;
		if (!ret)
			break;
	}
	return nb_tx;
}

/**
 * Skip error packets.
 *
 * @param rxq
 *   Pointer to RX queue structure.
 * @param[out] pkts
 *   Array to store received packets.
 * @param pkts_n
 *   Maximum number of packets in array.
 *
 * @return
 *   Number of packets successfully received (<= pkts_n).
 */
static uint16_t
rxq_handle_pending_error(struct mlx5_rxq_data *rxq, struct rte_mbuf **pkts,
			 uint16_t pkts_n)
{
	uint16_t n = 0;
	unsigned int i;
#ifdef MLX5_PMD_SOFT_COUNTERS
	uint32_t err_bytes = 0;
#endif

	for (i = 0; i < pkts_n; ++i) {
		struct rte_mbuf *pkt = pkts[i];

		if (pkt->packet_type == RTE_PTYPE_ALL_MASK) {
#ifdef MLX5_PMD_SOFT_COUNTERS
			err_bytes += PKT_LEN(pkt);
#endif
			rte_pktmbuf_free_seg(pkt);
		} else {
			pkts[n++] = pkt;
		}
	}
	rxq->stats.idropped += (pkts_n - n);
#ifdef MLX5_PMD_SOFT_COUNTERS
	/* Correct counters of errored completions. */
	rxq->stats.ipackets -= (pkts_n - n);
	rxq->stats.ibytes -= err_bytes;
#endif
	return n;
}

/**
 * DPDK callback for vectorized RX.
 *
 * @param dpdk_rxq
 *   Generic pointer to RX queue structure.
 * @param[out] pkts
 *   Array to store received packets.
 * @param pkts_n
 *   Maximum number of packets in array.
 *
 * @return
 *   Number of packets successfully received (<= pkts_n).
 */
uint16_t
mlx5_rx_burst_vec(void *dpdk_rxq, struct rte_mbuf **pkts, uint16_t pkts_n)
{
	struct mlx5_rxq_data *rxq = dpdk_rxq;
	uint16_t nb_rx;
	uint64_t err = 0;

	nb_rx = rxq_burst_v(rxq, pkts, pkts_n, &err);
	if (unlikely(err))
		nb_rx = rxq_handle_pending_error(rxq, pkts, nb_rx);
	return nb_rx;
}

/**
 * Check Tx queue flags are set for raw vectorized Tx.
 *
 * @param dev
 *   Pointer to Ethernet device.
 *
 * @return
 *   1 if supported, negative errno value if not.
 */
int __attribute__((cold))
mlx5_check_raw_vec_tx_support(struct rte_eth_dev *dev)
{
	uint64_t offloads = dev->data->dev_conf.txmode.offloads;

	/* Doesn't support any offload. */
	if (offloads)
		return -ENOTSUP;
	return 1;
}

/**
 * Check a device can support vectorized TX.
 *
 * @param dev
 *   Pointer to Ethernet device.
 *
 * @return
 *   1 if supported, negative errno value if not.
 */
int __attribute__((cold))
mlx5_check_vec_tx_support(struct rte_eth_dev *dev)
{
	struct priv *priv = dev->data->dev_private;
	uint64_t offloads = dev->data->dev_conf.txmode.offloads;

	if (!priv->config.tx_vec_en ||
	    priv->txqs_n > MLX5_VPMD_MIN_TXQS ||
	    priv->config.mps != MLX5_MPW_ENHANCED ||
	    offloads & ~MLX5_VEC_TX_OFFLOAD_CAP)
		return -ENOTSUP;
	return 1;
}

/**
 * Check a RX queue can support vectorized RX.
 *
 * @param rxq
 *   Pointer to RX queue.
 *
 * @return
 *   1 if supported, negative errno value if not.
 */
int __attribute__((cold))
mlx5_rxq_check_vec_support(struct mlx5_rxq_data *rxq)
{
	struct mlx5_rxq_ctrl *ctrl =
		container_of(rxq, struct mlx5_rxq_ctrl, rxq);

	if (mlx5_mprq_enabled(ETH_DEV(ctrl->priv)))
		return -ENOTSUP;
	if (!ctrl->priv->config.rx_vec_en || rxq->sges_n != 0)
		return -ENOTSUP;
	return 1;
}

/**
 * Check a device can support vectorized RX.
 *
 * @param dev
 *   Pointer to Ethernet device.
 *
 * @return
 *   1 if supported, negative errno value if not.
 */
int __attribute__((cold))
mlx5_check_vec_rx_support(struct rte_eth_dev *dev)
{
	struct priv *priv = dev->data->dev_private;
	uint16_t i;

	if (!priv->config.rx_vec_en)
		return -ENOTSUP;
	if (mlx5_mprq_enabled(dev))
		return -ENOTSUP;
	/* All the configured queues should support. */
	for (i = 0; i < priv->rxqs_n; ++i) {
		struct mlx5_rxq_data *rxq = (*priv->rxqs)[i];

		if (!rxq)
			continue;
		if (mlx5_rxq_check_vec_support(rxq) < 0)
			break;
	}
	if (i != priv->rxqs_n)
		return -ENOTSUP;
	return 1;
}