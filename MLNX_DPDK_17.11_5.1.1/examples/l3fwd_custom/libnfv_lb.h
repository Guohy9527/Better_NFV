#ifndef __LIBNFV_LB_H__
#define __LIBNFV_LB_H__

#include<stdio.h>
#include<stdlib.h>

#include <rte_flow.h>
#include <rte_cycles.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf_ptype.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_errno.h>
#include <rte_common.h>
#include "l3fwd.h"


#define BURST_DECTION 1

struct mlx5_cqe {
    #if (RTE_CACHE_LINE_SIZE == 128)
        uint8_t padding[64];
    #endif
    uint8_t pkt_info;
    uint8_t rsvd0;
    uint16_t wqe_id;
    uint8_t rsvd5[8];
    uint32_t rx_hash_res;
    uint8_t rx_hash_type;
    uint8_t rsvd1[11];
    uint16_t hdr_type_etc;
    uint16_t vlan_info;
    uint8_t rsvd2[4];
    uint32_t metadata;
    uint8_t rsvd3[4];
    uint32_t byte_cnt;
    uint64_t timestamp;
    uint32_t sop_drop_qpn;
    uint16_t wqe_counter;
    uint8_t rsvd4;
    uint8_t op_own;
};

struct data_from_driver{
		unsigned int nic_rq_ci;
		volatile struct mlx5_cqe * nic_cq;
		uint16_t nic_q_n;
		uint16_t nic_wqe_pi;
		uint16_t nic_wqe_ci;
		uint16_t nic_counter;
		double	cpu_load;
		uint64_t str_tsc,diff_tsc,sum_idle_tsc,pre_tsc;
		unsigned int idle_flag;
};

int nfv_lb_burst_detection(struct data_from_driver * nic_rxq_data);

void
flow_item_spec_size(const struct rte_flow_item *item, size_t *size, size_t *pad);

void
flow_action_conf_size(const struct rte_flow_action *action, size_t *size, size_t *pad);

int
lcore_flow_complain(struct rte_flow_error *error);

struct lcore_flow *
lcore_flow_new(const struct rte_flow_attr *attr,
            const struct rte_flow_item *pattern,
            const struct rte_flow_action *actions);

int
lcore_flow_create(uint16_t port_id, uint16_t lcore_id,
		 const struct rte_flow_attr *attr,
		 const struct rte_flow_item *pattern,
		 const struct rte_flow_action *actions);

int
lcore_flow_destroy(uint16_t port_id, uint16_t lcore_id, uint32_t n, const uint32_t *rule);

int
generate_ipv4_flow(uint16_t port_id, uint16_t lcore_id, uint16_t rx_q,
		uint32_t src_ip, uint32_t src_mask,
		uint32_t dest_ip, uint32_t dest_mask);

int port_flow_flush(uint16_t port_id);

void nfv_lb_init_fdir(void);

#endif