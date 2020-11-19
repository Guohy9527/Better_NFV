/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018 Mellanox Technologies, Ltd
 */

#ifndef RTE_PMD_MLX5_FLOW_H_
#define RTE_PMD_MLX5_FLOW_H_

#include <netinet/in.h>
#include <sys/queue.h>
#include <stdalign.h>
#include <stdint.h>
#include <string.h>

#include <rte_mtr.h>

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

#include "mlx5.h"
#include "mlx5_devx_cmds.h"
#include "mlx5_prm.h"

#define __DR__

/* Cannot enable __DR__ if mlx5dv has no support for it */
#ifndef HAVE_MLX5DV_DR
#ifdef __DR__
#undef __DR__
#pragma message "Direct rules (DR) are not supported, disabling."
#endif
#endif

/* Flow table levels. */
#define MLX5_FLOW_TABLE_LEVEL_ROOT 0
#define MLX5_FLOW_TABLE_LEVEL_METER 1024
#define MLX5_FLOW_TABLE_LEVEL_SUFFIX 4096

/* Pattern outer Layer bits. */
#define MLX5_FLOW_LAYER_OUTER_L2 (1u << 0)
#define MLX5_FLOW_LAYER_OUTER_L3_IPV4 (1u << 1)
#define MLX5_FLOW_LAYER_OUTER_L3_IPV6 (1u << 2)
#define MLX5_FLOW_LAYER_OUTER_L4_UDP (1u << 3)
#define MLX5_FLOW_LAYER_OUTER_L4_TCP (1u << 4)
#define MLX5_FLOW_LAYER_OUTER_VLAN (1u << 5)

/* Pattern inner Layer bits. */
#define MLX5_FLOW_LAYER_INNER_L2 (1u << 6)
#define MLX5_FLOW_LAYER_INNER_L3_IPV4 (1u << 7)
#define MLX5_FLOW_LAYER_INNER_L3_IPV6 (1u << 8)
#define MLX5_FLOW_LAYER_INNER_L4_UDP (1u << 9)
#define MLX5_FLOW_LAYER_INNER_L4_TCP (1u << 10)
#define MLX5_FLOW_LAYER_INNER_VLAN (1u << 11)

/* Pattern tunnel Layer bits. */
#define MLX5_FLOW_LAYER_VXLAN (1u << 12)
#define MLX5_FLOW_LAYER_VXLAN_GPE (1u << 13)
#define MLX5_FLOW_LAYER_GRE (1u << 14)
#define MLX5_FLOW_LAYER_MPLS (1u << 15)

/* General pattern items bits. */
#define MLX5_FLOW_ITEM_L3_VXLAN (1u << 16)

/* Pattern MISC bits. */
#define MLX5_FLOW_LAYER_ICMP (1u << 17)
#define MLX5_FLOW_LAYER_ICMPV6 (1u << 18)

#define MLX5_FLOW_LAYER_GRE_OPT_KEY (1u << 19)

#define MLX5_FLOW_ITEM_PORT_ID (1u << 20)

#define MLX5_FLOW_ITEM_METADATA_0 (1u << 21)
#define MLX5_FLOW_ITEM_METADATA_1 (1u << 22)
#define MLX5_FLOW_ITEM_METADATA_2 (1u << 23)
#define MLX5_FLOW_ITEM_METADATA_3 (1u << 24)

#define MLX5_FLOW_ITEM_METADATA(id) (MLX5_FLOW_ITEM_METADATA_0 << (id))

/* Outer Masks. */
#define MLX5_FLOW_LAYER_OUTER_L3 \
	(MLX5_FLOW_LAYER_OUTER_L3_IPV4 | MLX5_FLOW_LAYER_OUTER_L3_IPV6)
#define MLX5_FLOW_LAYER_OUTER_L4 \
	(MLX5_FLOW_LAYER_OUTER_L4_UDP | MLX5_FLOW_LAYER_OUTER_L4_TCP)
#define MLX5_FLOW_LAYER_OUTER \
	(MLX5_FLOW_LAYER_OUTER_L2 | MLX5_FLOW_LAYER_OUTER_L3 | \
	 MLX5_FLOW_LAYER_OUTER_L4)

/* Tunnel Masks. */
#define MLX5_FLOW_LAYER_TUNNEL \
	(MLX5_FLOW_LAYER_VXLAN | MLX5_FLOW_LAYER_VXLAN_GPE | \
	 MLX5_FLOW_LAYER_GRE | MLX5_FLOW_LAYER_MPLS)

/* Inner Masks. */
#define MLX5_FLOW_LAYER_INNER_L3 \
	(MLX5_FLOW_LAYER_INNER_L3_IPV4 | MLX5_FLOW_LAYER_INNER_L3_IPV6)
#define MLX5_FLOW_LAYER_INNER_L4 \
	(MLX5_FLOW_LAYER_INNER_L4_UDP | MLX5_FLOW_LAYER_INNER_L4_TCP)
#define MLX5_FLOW_LAYER_INNER \
	(MLX5_FLOW_LAYER_INNER_L2 | MLX5_FLOW_LAYER_INNER_L3 | \
	 MLX5_FLOW_LAYER_INNER_L4)

/* Actions */
#define MLX5_FLOW_ACTION_DROP (1u << 0)
#define MLX5_FLOW_ACTION_QUEUE (1u << 1)
#define MLX5_FLOW_ACTION_RSS (1u << 2)
#define MLX5_FLOW_ACTION_FLAG (1u << 3)
#define MLX5_FLOW_ACTION_MARK (1u << 4)
#define MLX5_FLOW_ACTION_COUNT (1u << 5)
#define MLX5_FLOW_ACTION_PORT_ID (1u << 6)
#define MLX5_FLOW_ACTION_OF_POP_VLAN (1u << 7)
#define MLX5_FLOW_ACTION_OF_PUSH_VLAN (1u << 8)
#define MLX5_FLOW_ACTION_OF_SET_VLAN_VID (1u << 9)
#define MLX5_FLOW_ACTION_OF_SET_VLAN_PCP (1u << 10)
#define MLX5_FLOW_ACTION_SET_IPV4_SRC (1u << 11)
#define MLX5_FLOW_ACTION_SET_IPV4_DST (1u << 12)
#define MLX5_FLOW_ACTION_SET_IPV6_SRC (1u << 13)
#define MLX5_FLOW_ACTION_SET_IPV6_DST (1u << 14)
#define MLX5_FLOW_ACTION_SET_TP_SRC (1u << 15)
#define MLX5_FLOW_ACTION_SET_TP_DST (1u << 16)
#define MLX5_FLOW_ACTION_JUMP (1u << 17)
#define MLX5_FLOW_ACTION_SET_TTL (1u << 18)
#define MLX5_FLOW_ACTION_DEC_TTL (1u << 19)
#define MLX5_FLOW_ACTION_SET_MAC_SRC (1u << 20)
#define MLX5_FLOW_ACTION_SET_MAC_DST (1u << 21)
#define MLX5_FLOW_ACTION_VXLAN_ENCAP (1u << 22)
#define MLX5_FLOW_ACTION_VXLAN_DECAP (1u << 23)
#define MLX5_FLOW_ACTION_NVGRE_ENCAP (1u << 24)
#define MLX5_FLOW_ACTION_NVGRE_DECAP (1u << 25)
#define MLX5_FLOW_ACTION_RAW_ENCAP (1u << 26)
#define MLX5_FLOW_ACTION_RAW_DECAP (1u << 27)
#define MLX5_FLOW_ACTION_INC_TCP_SEQ (1u << 28)
#define MLX5_FLOW_ACTION_DEC_TCP_SEQ (1u << 29)
#define MLX5_FLOW_ACTION_INC_TCP_ACK (1u << 30)
#define MLX5_FLOW_ACTION_DEC_TCP_ACK (1u << 31)
#define MLX5_FLOW_ACTION_METER (1ULL << 32)
#define MLX5_FLOW_ACTION_VNI_PRESENT (1ul << 33)
#define MLX5_FLOW_ACTION_MODIFY_REG (1ul << 34)
#define MLX5_FLOW_ACTION_PF (1ul << 35)
#define MLX5_FLOW_ACTION_SET_META_0 (1ul << 36)
#define MLX5_FLOW_ACTION_SET_META_1 (1ul << 37)
#define MLX5_FLOW_ACTION_SET_META_2 (1ul << 38)
#define MLX5_FLOW_ACTION_SET_META_3 (1ul << 39)

#define MLX5_FLOW_ACTION_SET_META(id) (MLX5_FLOW_ACTION_SET_META_0 << (id))

#define MLX5_FLOW_ESWITCH_FATE_ACTIONS \
	(MLX5_FLOW_ACTION_DROP | MLX5_FLOW_ACTION_PORT_ID | \
	 MLX5_FLOW_ACTION_PF | MLX5_FLOW_ACTION_JUMP)

#define MLX5_FLOW_FATE_ACTIONS \
	(MLX5_FLOW_ACTION_DROP | MLX5_FLOW_ACTION_QUEUE | \
	 MLX5_FLOW_ACTION_RSS | MLX5_FLOW_ACTION_JUMP)

#define MLX5_FLOW_ENCAP_ACTIONS	(MLX5_FLOW_ACTION_VXLAN_ENCAP | \
				 MLX5_FLOW_ACTION_NVGRE_ENCAP | \
				 MLX5_FLOW_ACTION_RAW_ENCAP)

#define MLX5_FLOW_DECAP_ACTIONS	(MLX5_FLOW_ACTION_VXLAN_DECAP | \
				 MLX5_FLOW_ACTION_NVGRE_DECAP | \
				 MLX5_FLOW_ACTION_RAW_DECAP)

#define MLX5_FLOW_MODIFY_ACTIONS (MLX5_FLOW_ACTION_SET_IPV4_SRC | \
				  MLX5_FLOW_ACTION_SET_IPV4_DST | \
				  MLX5_FLOW_ACTION_SET_IPV6_SRC | \
				  MLX5_FLOW_ACTION_SET_IPV6_DST | \
				  MLX5_FLOW_ACTION_SET_TP_SRC | \
				  MLX5_FLOW_ACTION_SET_TP_DST | \
				  MLX5_FLOW_ACTION_SET_TTL | \
				  MLX5_FLOW_ACTION_DEC_TTL | \
				  MLX5_FLOW_ACTION_SET_MAC_SRC | \
				  MLX5_FLOW_ACTION_SET_MAC_DST | \
				  MLX5_FLOW_ACTION_INC_TCP_SEQ | \
				  MLX5_FLOW_ACTION_DEC_TCP_SEQ | \
				  MLX5_FLOW_ACTION_INC_TCP_ACK | \
				  MLX5_FLOW_ACTION_DEC_TCP_ACK | \
				  MLX5_FLOW_ACTION_SET_META_0 | \
				  MLX5_FLOW_ACTION_SET_META_1 | \
				  MLX5_FLOW_ACTION_SET_META_2 | \
				  MLX5_FLOW_ACTION_SET_META_3)

#ifndef IPPROTO_MPLS
#define IPPROTO_MPLS 137
#endif

/* UDP port numbers for VxLAN. */
#define MLX5_UDP_PORT_VXLAN 4789
#define MLX5_UDP_PORT_VXLAN_GPE 4790

/* Priority reserved for default flows. */
#define MLX5_FLOW_PRIO_RSVD ((uint32_t)-1)

/*
* Number of sub priorities.
 * For each kind of pattern matching i.e. L2, L3, L4 to have a correct
 * matching on the NIC (firmware dependent) L4 most have the higher priority
 * followed by L3 and ending with L2.
 */
#define MLX5_PRIORITY_MAP_L2 2
#define MLX5_PRIORITY_MAP_L3 1
#define MLX5_PRIORITY_MAP_L4 0
#define MLX5_PRIORITY_MAP_MAX 3

/* Valid layer type for IPV4 RSS. */
#define MLX5_IPV4_LAYER_TYPES \
	(ETH_RSS_IPV4 | ETH_RSS_FRAG_IPV4 | \
	 ETH_RSS_NONFRAG_IPV4_TCP | ETH_RSS_NONFRAG_IPV4_UDP | \
	 ETH_RSS_NONFRAG_IPV4_OTHER)

/* IBV hash source bits  for IPV4. */
#define MLX5_IPV4_IBV_RX_HASH (IBV_RX_HASH_SRC_IPV4 | IBV_RX_HASH_DST_IPV4)

/* Valid layer type for IPV6 RSS. */
#define MLX5_IPV6_LAYER_TYPES \
	(ETH_RSS_IPV6 | ETH_RSS_FRAG_IPV6 | ETH_RSS_NONFRAG_IPV6_TCP | \
	 ETH_RSS_NONFRAG_IPV6_UDP | ETH_RSS_IPV6_EX  | ETH_RSS_IPV6_TCP_EX | \
	 ETH_RSS_IPV6_UDP_EX | ETH_RSS_NONFRAG_IPV6_OTHER)

/* IBV hash source bits  for IPV6. */
#define MLX5_IPV6_IBV_RX_HASH (IBV_RX_HASH_SRC_IPV6 | IBV_RX_HASH_DST_IPV6)

/* Max number of actions per DV flow. */
#define MLX5_DV_MAX_NUMBER_OF_ACTIONS 8

/* Initial value of the entries in the hash list table */
#define MLX5_TAG_LIST_INIT_NUM		4096

/* Number of entries per hash list */
#define MLX5_TAG_LIST_ENTRY_PER_LIST	8

enum mlx5_flow_drv_type {
	MLX5_FLOW_TYPE_MIN,
	MLX5_FLOW_TYPE_DV,
	MLX5_FLOW_TYPE_VERBS,
	MLX5_FLOW_TYPE_MAX,
};

/* Matcher PRM representation */
struct mlx5_flow_dv_match_params {
	size_t size;
	/**< Size of match value. Do NOT split size and key! */
	union {
		uint32_t buf[MLX5_ST_SZ_DW(fte_match_param)];
		uint64_t buf_64[MLX5_ST_SZ_DW(fte_match_param) / 2];
		/* 64 bit align as defined in mlx5dv_flow_match_parameters */
	};
	/**< Matcher value. This value is used as the mask or as a key. */
};

#define MLX5_DV_MAX_NUMBER_OF_ACTIONS 8
#define MLX5_ENCAP_MAX_LEN 132

/* Matcher structure. */
struct mlx5_flow_dv_matcher {
	LIST_ENTRY(mlx5_flow_dv_matcher) next;
	/* Pointer to the next element. */
	rte_atomic32_t refcnt; /**< Reference counter. */
	void *matcher_object; /**< Pointer to DV matcher */
	uint16_t crc; /**< CRC of key. */
	uint16_t priority; /**< Priority of matcher. */
	uint8_t transfer; /**< 1 if the flow is transfer. */
	uint8_t egress; /**< Egress matcher. */
	uint8_t mtr_sfx_tbl;
	/**< Matcher is on suffix table of a flow with meter */
	uint32_t group; /**< The matcher group. */
	struct mlx5_flow_dv_match_params mask; /**< Matcher mask. */
};

/* Encap/decap resource structure. */
struct mlx5_flow_dv_encap_decap_resource {
	LIST_ENTRY(mlx5_flow_dv_encap_decap_resource) next;
	/* Pointer to next element. */
	rte_atomic32_t refcnt; /**< Reference counter. */
	void *verbs_action;
	/**< Verbs encap/decap action object. */
	uint8_t buf[MLX5_ENCAP_MAX_LEN];
	size_t size;
	uint8_t reformat_type;
	uint8_t ft_type;
	uint8_t transfer; /**< 1 if the flow is transfer. */
	uint8_t ingress;
	uint8_t mtr_sfx_tbl;
	uint64_t flags;
};

/* Tag resource structure. */
struct mlx5_flow_dv_tag_resource {
	/* Pointer to next element. */
	rte_atomic32_t refcnt; /**< Reference counter. */
	void *action;
	/**< Verbs tag action object. */
	uint32_t tag; /**< the tag value. */
};

#define MLX5_MODIFY_NUM 16

/* Modify resource structure. */
struct mlx5_flow_dv_modify_resource {
	LIST_ENTRY(mlx5_flow_dv_modify_resource) next;
	/* Pointer to next element. */
	rte_atomic32_t refcnt; /**< Reference counter. */
	void *action;
	/**< Verbs modify action object. */
	uint32_t modify_num;
	uint32_t table;
	uint8_t transfer; /**< 1 if the flow is transfer. */
	uint8_t ingress;
	uint8_t mtr_sfx_tbl;
	struct mlx5_modification_cmd modis[MLX5_MODIFY_NUM];
	
};


/* DV flows structure. */
struct mlx5_flow_dv {
	uint64_t hash_fields; /**< Fields that participate in the hash. */
	/* Flow DV api: */
	struct mlx5_flow_dv_match_params value;
	/**< Holds the value that the packet is compared to. */
	struct mlx5_flow_dv_match_params extra_value;
	/**< Holds a value that the packet is compared to. */
#ifdef HAVE_IBV_FLOW_DV_SUPPORT
#ifdef __DR__
	uint64_t sfxt_action_flags; /**< the sfxt table flags. */
#else
	struct mlx5dv_flow_action_attr actions[MLX5_DV_MAX_NUMBER_OF_ACTIONS];
#endif
	/**< Action list. */
#endif
	int actions_n; /**< number of actions. */
	uint32_t flow_id; /**< Flow ID index. */
	struct mlx5_flow_handle *handle;
};

/* Verbs specification header. */
struct ibv_spec_header {
	enum ibv_flow_spec_type type;
	uint16_t size;
};

/** Handles information leading to a drop fate. */
struct mlx5_flow_verbs {
	LIST_ENTRY(mlx5_flow_verbs) next;
	unsigned int size; /**< Size of the attribute. */
	struct {
		struct ibv_flow_attr *attr;
		/**< Pointer to the Specification buffer. */
		uint8_t *specs; /**< Pointer to the specifications. */
	};
	struct ibv_flow *flow; /**< Verbs flow pointer. */
	struct mlx5_hrxq *hrxq; /**< Hash Rx queue object. */
	uint64_t hash_fields; /**< Verbs hash Rx queue hash fields. */
};

/** Device flow structure. */
struct mlx5_flow {
	LIST_ENTRY(mlx5_flow) next;
	struct rte_flow *flow; /**< Pointer to the main flow. */
	uint64_t layers;
	/**< Bit-fields of present layers, see MLX5_FLOW_LAYER_*. */
	union {
#ifdef HAVE_IBV_FLOW_DV_SUPPORT
		struct mlx5_flow_dv dv;
#endif
		struct mlx5_flow_verbs verbs;
	};
};

struct mlx5_devx_counter_set;

/* Counters information. */
struct mlx5_flow_counter {
	LIST_ENTRY(mlx5_flow_counter) next; /**< Pointer to the next counter. */
	uint32_t shared:1; /**< Share counter ID with other flow rules. */
	uint32_t devx_cnt:1;
	uint32_t devx_reuse:1; /**< Devx object managed by external. */
	uint32_t ref_cnt:29; /**< Reference counter. */
	uint32_t id; /**< Counter ID. */
#if defined(HAVE_IBV_DEVICE_COUNTERS_SET_V42)
	struct ibv_counter_set *cs; /**< Holds the counters for the rule. */
#elif defined(HAVE_IBV_DEVICE_COUNTERS_SET_V45)
	struct ibv_counters *cs; /**< Holds the counters for the rule. */
#endif
	struct mlx5_devx_counter_set *dcs;
	uint64_t hits; /**< Number of packets matched by the rule. */
	uint64_t bytes; /**< Number of bytes matched by the rule. */
	void *action; /**< Holds a pointer to the DR action. */
};

struct _rte_flow_action_rss {
	enum rte_eth_hash_function func; /**< RSS hash function to apply. */
	uint32_t level;
	uint64_t types; /**< Specific RSS hash types (see ETH_RSS_*). */
	uint32_t key_len; /**< Hash key length in bytes. */
	uint32_t queue_num; /**< Number of entries in @p queue. */
	const uint8_t *key; /**< Hash key. */
	const uint16_t *queue; /**< Queue indices to use. */
};

struct rte_flow_handle {
	TAILQ_ENTRY(rte_flow_handle) next; /**< must be the first. */
	enum mlx5_flow_drv_type drv_type; /**< Driver type. */
	struct mlx5_flow_counter *counter; /**< Holds flow counter. */
	struct mlx5_flow_meter *meter;
	/**< The flow meter used by this flow. */
	struct mlx5_flow_handle *dev_handles;
	uint64_t actions;
	/**< Bit-fields of detected actions, see MLX5_FLOW_ACTION_*. */
	uint16_t queue_num;  /**< Number of entries in @p queue. */
	void *meta_reg_action; /**< Pointer to reg rewrite action. */
	uint16_t (*queue)[]; /**< Destination queues to redirect traffic to. */
};

/* Flow structure. */
struct rte_flow {
	TAILQ_ENTRY(rte_flow) next;
	uint16_t port;
	/**< Pointer to the next flow structure. Must be the first. */
	enum mlx5_flow_drv_type drv_type; /**< Drvier type. */
	struct _rte_flow_action_rss rss;/**< RSS context. */
	uint8_t key[MLX5_RSS_HASH_KEY_LEN]; /**< RSS hash key. */
	uint16_t (*queue)[]; /**< Destination queues to redirect traffic to. */
	LIST_HEAD(dev_flows, mlx5_flow) dev_flows;
	/**< Device flows that are part of the flow. */
	uint64_t actions;
	/**< Bit-fields of detected actions, see MLX5_FLOW_ACTION_*. */
	struct mlx5_fdir *fdir; /**< Pointer to associated FDIR if any. */
	uint32_t tunnel; /** Tunnel type as RTE_PTYPE_TUNNEL_XXX. */
	uint32_t group; /**< The group index. */
	uint8_t transfer; /**< 1 if the flow is transfer. */
	uint8_t ingress; /**< 1 if the flow is ingress. */
	struct rte_flow_handle *handle;
	/**< Pointer to he list of handles. */
};

/* Flow counter query MR. */
struct mlx5_flow_counter_query_mr {
	SLIST_ENTRY(mlx5_flow_counter_query_mr) next;
	void *addr; /**< Buffer address. */
	uint64_t length; /**< addr length. */
	struct mlx5dv_devx_umem *umem; /**< umem object. */
	struct mlx5_devx_mkey *mkey; /**< mkey object. */
};

/* Flow counter query MR. */
struct mlx5_flow_bulk_counters {
	SLIST_ENTRY(mlx5_flow_bulk_counters) next;
	void *obj; /**< Pointer to the devx object. */
	uint32_t id; /**< The base id. */
	struct mlx5_dcs free_list;
	uint32_t num_of_counters; /**< Holds the total num of coutners. */
	uint32_t current_index; /**< The first free counter index. */
	uint32_t free_count; /**< Num of free counters. */
};

/* srTCM PRM flow meter parameters (as defined in the PRM). */
enum {
	MLX5_FLOW_COLOR_RED = 0,
	MLX5_FLOW_COLOR_YELLOW,
	MLX5_FLOW_COLOR_GREEN,
	MLX5_FLOW_COLOR_UNDEFINED,
};

#define MLX5_SRTCM_CBS_MAX (0xFF * (1ULL << 0x1F))
#define MLX5_SRTCM_CIR_MAX (8 * (1ULL << 30) * 0xFF)
#define MLX5_SRTCM_EBS_MAX 0
#define MLX5_MAN_WIDTH 8

struct mlx5_flow_meter_srtcm_rfc2697_prm {
	/* green_saturation_value = cbs_mantissa * 2^cbs_exponent */
	uint32_t cbs_exponent:5;
	uint32_t cbs_mantissa:8;
	/* cir = 8G * cir_mantissa * 1/(2^cir_exponent) Bytes/Sec */
	uint32_t cir_exponent:5;
	uint32_t cir_mantissa:8;
	/* yellow _saturation_value = ebs_mantissa * 2^ebs_exponent */
	uint32_t ebs_exponent:5;
	uint32_t ebs_mantissa:8;
};

/* Flow meter state */
#define MLX5_FLOW_METER_DISABLE 0
#define MLX5_FLOW_METER_ENABLE 1

/* Flow meter structure */
struct mlx5_flow_meter_profile {
	TAILQ_ENTRY(mlx5_flow_meter_profile) next;
	/**< Pointer to the next flow meter structure. */
	uint32_t meter_profile_id;
	struct rte_mtr_meter_profile profile;
	union {
		struct mlx5_flow_meter_srtcm_rfc2697_prm srtcm_prm;
	};
	uint32_t use_c; /* Use count. */
};

/* Modify this value if enum rte_mtr_color changes. */
#define RTE_MTR_DROPPED (RTE_MTR_COLORS)

struct mlx5_flow_policer_stats {
	/* Last counter obj is the drop counter. */
	struct mlx5_devx_counter_set dcs[RTE_MTR_COLORS + 1];
	uint64_t stats_mask;
};

#if defined(HAVE_MLX5DV_DR) && defined(__DR__)
struct mlx5_meter_tbls_by_domain {
	struct mlx5dv_dr_table *tbl;
	struct mlx5dv_dr_matcher *any_matcher;
	struct mlx5dv_dr_matcher *color_matcher;
	struct mlx5dv_dr_action *jump_actn;
	struct mlx5dv_dr_rule *policer_rules[RTE_MTR_DROPPED + 1];
};

struct mlx5_meter_tbls_dv {
	uint32_t use_c;
	/* Current implementation - meter can be used by a single table */
	const struct mlx5_flow_meter *fm;
	struct mlx5_meter_tbls_by_domain egress;
	struct mlx5_meter_tbls_by_domain ingress;
	struct mlx5_meter_tbls_by_domain transfer;
	struct mlx5dv_dr_action *drop_actn;
	struct mlx5dv_dr_action *count_actns[RTE_MTR_DROPPED + 1];
	uint32_t fmp[MLX5_ST_SZ_DW(flow_meter_parameters)];
	size_t fmp_size;
	struct mlx5dv_dr_action *meter_action;
};
#endif

struct mlx5_flow_meter {
	TAILQ_ENTRY(mlx5_flow_meter) next;
	uint32_t meter_id;
	struct rte_mtr_params params;
	struct mlx5_flow_meter_profile *profile;
	struct rte_flow_attr attr;
	uint32_t metadata_reg_c_idx;
	uint64_t modifiable_fields;
	uint32_t egress_group_id;
	uint32_t ingress_group_id;
	/* The group ID this meter is associated with */
	struct mlx5_meter_tbls_dv *mfts; /* Flow table created for this meter */
	struct mlx5_flow_policer_stats policer_stats;
	uint32_t use_c; /* Use count. */
	uint32_t active_state:1;
	uint32_t shared:1;
};

/* Stack strutcture. */
struct mlx5_flow_stack {
	uint32_t *empty;
	uint32_t base_index;
	uint32_t *curr;
	uint32_t *last;
};

struct mlx5_flow_stack *mlx5_flow_stack_alloc(void);
void mlx5_flow_stack_release(struct mlx5_flow_stack *stack);
uint32_t mlx5_flow_id_get(struct mlx5_flow_stack *stack);
void mlx5_flow_id_release(struct mlx5_flow_stack *stack, uint32_t value);

/* Flow interface */
typedef int (*mlx5_flow_validate_t)(struct rte_eth_dev *dev,
				    const struct rte_flow_attr *attr,
				    const struct rte_flow_item items[],
				    const struct rte_flow_action actions[],
				    struct rte_flow_error *error);
typedef struct mlx5_flow *(*mlx5_flow_prepare_t)
	(const struct rte_flow_attr *attr, const struct rte_flow_item items[],
	 const struct rte_flow_action actions[], struct rte_flow_error *error);
typedef int (*mlx5_flow_translate_t)(struct rte_eth_dev *dev,
				     struct mlx5_flow *dev_flow,
				     const struct rte_flow_attr *attr,
				     const struct rte_flow_item items[],
				     const struct rte_flow_action actions[],
				     struct rte_flow_error *error);
typedef int (*mlx5_flow_apply_t)(struct rte_eth_dev *dev, struct rte_flow *flow,
				 struct rte_flow_error *error);
typedef void (*mlx5_flow_remove_t)(struct rte_eth_dev *dev,
				   struct rte_flow *flow);
typedef void (*mlx5_flow_destroy_t)(struct rte_eth_dev *dev,
				    struct rte_flow *flow);
typedef int (*mlx5_flow_query_t)(struct rte_eth_dev *dev,
				 struct rte_flow *flow,
				 const struct rte_flow_action *actions,
				 void *data,
				 struct rte_flow_error *error);
typedef struct mlx5_flow_bulk_counters * (*mlx5_flow_counter_alloc_t)(
		struct rte_eth_dev *dev,
		uint32_t *start_index,
		uint32_t *blk_sz,
		struct rte_flow_error *error);
typedef int (*mlx5_flow_counter_free_t)(struct rte_eth_dev *dev,
					struct mlx5_flow_bulk_counters *bulk);
typedef int (*mlx5_flow_counter_query_t)(struct rte_eth_dev *dev,
					 int counter_id, void *counter_obj,
					 uint32_t count,
					 struct rte_flow_count_value *buf,
					 int buf_count,
					 rte_flow_cb_fn cb, void *cb_arg,
					 struct rte_flow_error *error);
typedef int (*mlx5_flow_sync_t)(struct rte_eth_dev *dev,
				struct rte_flow_error *error);
typedef struct mlx5_meter_tbls_dv *(*mlx5_flow_create_mtr_tbls_t)
					    (struct rte_eth_dev *dev,
					     const struct mlx5_flow_meter *fm);
typedef int (*mlx5_flow_destroy_mtr_tbls_t)(struct rte_eth_dev *dev,
					   struct mlx5_meter_tbls_dv *tbls);
typedef int (*mlx5_flow_create_policer_rules_t)
					(struct rte_eth_dev *dev,
					 struct mlx5_flow_meter *fm,
					 const struct rte_flow_attr *attr);
typedef int (*mlx5_flow_destroy_policer_rules_t)
					(struct rte_eth_dev *dev,
					 struct mlx5_flow_meter *fm,
					 const struct rte_flow_attr *attr);
struct mlx5_flow_driver_ops {
	mlx5_flow_validate_t validate;
	mlx5_flow_prepare_t prepare;
	mlx5_flow_translate_t translate;
	mlx5_flow_apply_t apply;
	mlx5_flow_remove_t remove;
	mlx5_flow_destroy_t destroy;
	mlx5_flow_query_t query;
	mlx5_flow_counter_alloc_t counter_alloc;
	mlx5_flow_counter_free_t counter_free;
	mlx5_flow_counter_query_t counter_query;
	mlx5_flow_sync_t sync;
	mlx5_flow_create_mtr_tbls_t create_mtr_tbls;
	mlx5_flow_destroy_mtr_tbls_t destroy_mtr_tbls;
	mlx5_flow_create_policer_rules_t create_policer_rules;
	mlx5_flow_destroy_policer_rules_t destroy_policer_rules;
};

/* mlx5_flow.c */

extern rte_flow_cb_fn mlx5_flow_batch_async_callback;

uint64_t mlx5_flow_hashfields_adjust(struct mlx5_flow *dev_flow, int tunnel,
				     uint64_t layer_types,
				     uint64_t hash_fields, int decap);
uint32_t mlx5_flow_adjust_priority(struct rte_eth_dev *dev, int32_t priority,
				   uint32_t subpriority);
int mlx5_flow_validate_action_count(struct rte_eth_dev *dev,
				    const struct rte_flow_attr *attr,
				    struct rte_flow_error *error);
int mlx5_flow_validate_action_drop(uint64_t action_flags,
				   const struct rte_flow_attr *attr,
				   struct rte_flow_error *error);
int mlx5_flow_validate_action_flag(uint64_t action_flags,
				   const struct rte_flow_attr *attr,
				   struct rte_flow_error *error);
int mlx5_flow_validate_action_mark(const struct rte_flow_action *action,
				   uint64_t action_flags,
				   const struct rte_flow_attr *attr,
				   struct rte_flow_error *error);
int mlx5_flow_validate_action_queue(const struct rte_flow_action *action,
				    uint64_t action_flags,
				    struct rte_eth_dev *dev,
				    const struct rte_flow_attr *attr,
				    struct rte_flow_error *error);
int mlx5_flow_validate_action_rss(const struct rte_flow_action *action,
				  uint64_t action_flags,
				  struct rte_eth_dev *dev,
				  const struct rte_flow_attr *attr,
				  struct rte_flow_error *error);
int mlx5_flow_validate_attributes(struct rte_eth_dev *dev,
				  const struct rte_flow_attr *attributes,
				  struct rte_flow_error *error);
int mlx5_flow_item_acceptable(const struct rte_flow_item *item,
			      const uint8_t *mask,
			      const uint8_t *nic_mask,
			      unsigned int size,
			      struct rte_flow_error *error);
int mlx5_flow_validate_item_eth(const struct rte_flow_item *item,
				uint64_t item_flags,
				struct rte_flow_error *error);
int mlx5_flow_validate_item_gre(const struct rte_flow_item *item,
				uint64_t item_flags,
				uint8_t target_protocol,
				struct rte_flow_error *error);
int mlx5_flow_validate_item_gre_opt_key(const struct rte_flow_item *item,
					uint64_t item_flags,
					struct rte_flow_error *error);
int mlx5_flow_validate_item_ipv4(const struct rte_flow_item *item,
				 uint64_t item_flags,
				 struct rte_flow_error *error);
int mlx5_flow_validate_item_ipv6(const struct rte_flow_item *item,
				 uint64_t item_flags,
				 struct rte_flow_error *error);
int mlx5_flow_validate_item_mpls(const struct rte_flow_item *item,
				 uint64_t item_flags,
				 uint8_t target_protocol,
				 struct rte_flow_error *error);
int mlx5_flow_validate_item_tcp(const struct rte_flow_item *item,
				uint64_t item_flags,
				uint8_t target_protocol,
				const struct rte_flow_item_tcp *flow_mask,
				struct rte_flow_error *error);
int mlx5_flow_validate_item_udp(const struct rte_flow_item *item,
				uint64_t item_flags,
				uint8_t target_protocol,
				struct rte_flow_error *error);
int mlx5_flow_validate_item_vlan(const struct rte_flow_item *item,
				 uint64_t item_flags,
				 struct rte_flow_error *error);
int mlx5_flow_validate_item_vxlan(const struct rte_flow_item *item,
				  uint64_t item_flags,
				  struct rte_flow_error *error);
int mlx5_flow_validate_item_vxlan_gpe(const struct rte_flow_item *item,
				      uint64_t item_flags,
				      struct rte_eth_dev *dev,
				      struct rte_flow_error *error);
int mlx5_flow_validate_item_icmp(const struct rte_flow_item *item,
				 uint64_t item_flags,
				 uint8_t target_protocol,
				 struct rte_flow_error *error);
int mlx5_flow_validate_item_icmpv6(const struct rte_flow_item *item,
				   uint64_t item_flags,
				   uint8_t target_protocol,
				   struct rte_flow_error *error);
const void *mlx5_flow_get_action(const struct rte_flow_action actions[],
				 enum rte_flow_action_type type);
int mlx5_flow_init_meters(struct rte_eth_dev *dev,
			  struct rte_flow_error *error);
int mlx5_flow_fini_meters(struct rte_eth_dev *dev,
			  struct rte_flow_error *error);

/* mlx5_flow_dv.c */

void flow_counter_mr_empty(struct rte_eth_dev *dev);

/* mlx5_flow_meter.c */

int mlx5_flow_meter_init(struct rte_eth_dev *dev);
void mlx5_flow_meter_finit(struct rte_eth_dev *dev);
int mlx5_flow_meter_ops_get(struct rte_eth_dev *dev, void *arg);
int mlx5_flow_meter_profile_verify(struct rte_eth_dev *dev);
struct mlx5_flow_meter_profile *mlx5_flow_meter_profile_find
						(struct priv *priv,
						 uint32_t meter_profile_id);
int mlx5_flow_meter_verify(struct rte_eth_dev *dev);
struct mlx5_flow_meter *mlx5_flow_meter_find(struct priv *priv,
					     uint32_t meter_id);
struct mlx5_flow_meter *mlx5_flow_meter_attach
					(struct priv *priv,
					 uint32_t meter_id,
					 const struct rte_flow_attr *attr);
void mlx5_flow_meter_detach(struct mlx5_flow_meter *fm);

struct rte_hlist_table *mlx5_flow_tags_hlist_create(char *dev_name);
void mlx5_flow_tags_hlist_free(struct rte_hlist_table *h);

#endif /* RTE_PMD_MLX5_FLOW_H_ */
