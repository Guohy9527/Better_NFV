// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2016 6WIND S.A.
 * Copyright 2016 Mellanox Technologies, Ltd
 */

#include <netinet/in.h>
#include <sys/queue.h>
#include <stdalign.h>
#include <stdint.h>
#include <string.h>

/* Verbs header. */
/* ISO C doesn't support unnamed structs/unions, disabling -pedantic. */
#ifdef PEDANTIC
#pragma GCC diagnostic ignored "-Wpedantic"
#endif
#include <infiniband/verbs.h>
#ifdef PEDANTIC
#pragma GCC diagnostic error "-Wpedantic"
#endif

#include <rte_common.h>
#include <rte_ether.h>
#include <rte_eth_ctrl.h>
#include <rte_ethdev_driver.h>
#include <rte_flow.h>
#include <rte_flow_driver.h>
#include <rte_malloc.h>
#include <rte_ip.h>

#include "mlx5.h"
#include "mlx5_defs.h"
#include "mlx5_prm.h"
#include "mlx5_glue.h"
#include "mlx5_flow.h"

/* Dev ops structure defined in mlx5.c */
extern const struct eth_dev_ops mlx5_dev_ops;
extern const struct eth_dev_ops mlx5_dev_ops_isolate;

/** Device flow drivers. */
#ifdef HAVE_IBV_FLOW_DV_SUPPORT
extern const struct mlx5_flow_driver_ops mlx5_flow_dv_drv_ops;
#endif
extern const struct mlx5_flow_driver_ops mlx5_flow_verbs_drv_ops;

const struct mlx5_flow_driver_ops mlx5_flow_null_drv_ops;

const struct mlx5_flow_driver_ops *flow_drv_ops[] = {
	[MLX5_FLOW_TYPE_MIN] = &mlx5_flow_null_drv_ops,
#ifdef HAVE_IBV_FLOW_DV_SUPPORT
	[MLX5_FLOW_TYPE_DV] = &mlx5_flow_dv_drv_ops,
#endif
	[MLX5_FLOW_TYPE_VERBS] = &mlx5_flow_verbs_drv_ops,
	[MLX5_FLOW_TYPE_MAX] = &mlx5_flow_null_drv_ops
};

enum mlx5_expansion {
	MLX5_EXPANSION_ROOT,
	MLX5_EXPANSION_ROOT_OUTER,
	MLX5_EXPANSION_ROOT_ETH_VLAN,
	MLX5_EXPANSION_ROOT_OUTER_ETH_VLAN,
	MLX5_EXPANSION_OUTER_ETH,
	MLX5_EXPANSION_OUTER_ETH_VLAN,
	MLX5_EXPANSION_OUTER_VLAN,
	MLX5_EXPANSION_OUTER_IPV4,
	MLX5_EXPANSION_OUTER_IPV4_UDP,
	MLX5_EXPANSION_OUTER_IPV4_TCP,
	MLX5_EXPANSION_OUTER_IPV6,
	MLX5_EXPANSION_OUTER_IPV6_UDP,
	MLX5_EXPANSION_OUTER_IPV6_TCP,
	MLX5_EXPANSION_VXLAN,
	MLX5_EXPANSION_VXLAN_GPE,
	MLX5_EXPANSION_GRE,
	MLX5_EXPANSION_MPLS,
	MLX5_EXPANSION_ETH,
	MLX5_EXPANSION_ETH_VLAN,
	MLX5_EXPANSION_VLAN,
	MLX5_EXPANSION_IPV4,
	MLX5_EXPANSION_IPV4_UDP,
	MLX5_EXPANSION_IPV4_TCP,
	MLX5_EXPANSION_IPV6,
	MLX5_EXPANSION_IPV6_UDP,
	MLX5_EXPANSION_IPV6_TCP,
};

/** Supported expansion of items. */
static const struct rte_flow_expand_node mlx5_support_expansion[] = {
	[MLX5_EXPANSION_ROOT] = {
		.next = RTE_FLOW_EXPAND_RSS_NEXT(MLX5_EXPANSION_ETH,
						 MLX5_EXPANSION_IPV4,
						 MLX5_EXPANSION_IPV6),
		.type = RTE_FLOW_ITEM_TYPE_END,
	},
	[MLX5_EXPANSION_ROOT_OUTER] = {
		.next = RTE_FLOW_EXPAND_RSS_NEXT(MLX5_EXPANSION_OUTER_ETH,
						 MLX5_EXPANSION_OUTER_IPV4,
						 MLX5_EXPANSION_OUTER_IPV6),
		.type = RTE_FLOW_ITEM_TYPE_END,
	},
	[MLX5_EXPANSION_ROOT_ETH_VLAN] = {
		.next = RTE_FLOW_EXPAND_RSS_NEXT(MLX5_EXPANSION_ETH_VLAN),
		.type = RTE_FLOW_ITEM_TYPE_END,
	},
	[MLX5_EXPANSION_ROOT_OUTER_ETH_VLAN] = {
		.next = RTE_FLOW_EXPAND_RSS_NEXT(MLX5_EXPANSION_OUTER_ETH_VLAN),
		.type = RTE_FLOW_ITEM_TYPE_END,
	},
	[MLX5_EXPANSION_OUTER_ETH] = {
		.next = RTE_FLOW_EXPAND_RSS_NEXT(MLX5_EXPANSION_OUTER_IPV4,
						 MLX5_EXPANSION_OUTER_IPV6,
						 MLX5_EXPANSION_MPLS),
		.type = RTE_FLOW_ITEM_TYPE_ETH,
		.rss_types = 0,
	},
	[MLX5_EXPANSION_OUTER_ETH_VLAN] = {
		.next = RTE_FLOW_EXPAND_RSS_NEXT(MLX5_EXPANSION_OUTER_VLAN),
		.type = RTE_FLOW_ITEM_TYPE_ETH,
		.rss_types = 0,
	},
	[MLX5_EXPANSION_OUTER_VLAN] = {
		.next = RTE_FLOW_EXPAND_RSS_NEXT(MLX5_EXPANSION_OUTER_IPV4,
						 MLX5_EXPANSION_OUTER_IPV6),
		.type = RTE_FLOW_ITEM_TYPE_VLAN,
	},
	[MLX5_EXPANSION_OUTER_IPV4] = {
		.next = RTE_FLOW_EXPAND_RSS_NEXT
			(MLX5_EXPANSION_OUTER_IPV4_UDP,
			 MLX5_EXPANSION_OUTER_IPV4_TCP,
			 MLX5_EXPANSION_GRE),
		.type = RTE_FLOW_ITEM_TYPE_IPV4,
		.rss_types = ETH_RSS_IPV4 | ETH_RSS_FRAG_IPV4 |
			ETH_RSS_NONFRAG_IPV4_OTHER,
	},
	[MLX5_EXPANSION_OUTER_IPV4_UDP] = {
		.next = RTE_FLOW_EXPAND_RSS_NEXT(MLX5_EXPANSION_VXLAN,
						 MLX5_EXPANSION_VXLAN_GPE),
		.type = RTE_FLOW_ITEM_TYPE_UDP,
		.rss_types = ETH_RSS_NONFRAG_IPV4_UDP,
	},
	[MLX5_EXPANSION_OUTER_IPV4_TCP] = {
		.type = RTE_FLOW_ITEM_TYPE_TCP,
		.rss_types = ETH_RSS_NONFRAG_IPV4_TCP,
	},
	[MLX5_EXPANSION_OUTER_IPV6] = {
		.next = RTE_FLOW_EXPAND_RSS_NEXT
			(MLX5_EXPANSION_OUTER_IPV6_UDP,
			 MLX5_EXPANSION_OUTER_IPV6_TCP),
		.type = RTE_FLOW_ITEM_TYPE_IPV6,
		.rss_types = ETH_RSS_IPV6 | ETH_RSS_FRAG_IPV6 |
			ETH_RSS_NONFRAG_IPV6_OTHER,
	},
	[MLX5_EXPANSION_OUTER_IPV6_UDP] = {
		.next = RTE_FLOW_EXPAND_RSS_NEXT(MLX5_EXPANSION_VXLAN,
						 MLX5_EXPANSION_VXLAN_GPE),
		.type = RTE_FLOW_ITEM_TYPE_UDP,
		.rss_types = ETH_RSS_NONFRAG_IPV6_UDP,
	},
	[MLX5_EXPANSION_OUTER_IPV6_TCP] = {
		.type = RTE_FLOW_ITEM_TYPE_TCP,
		.rss_types = ETH_RSS_NONFRAG_IPV6_TCP,
	},
	[MLX5_EXPANSION_VXLAN] = {
		.next = RTE_FLOW_EXPAND_RSS_NEXT(MLX5_EXPANSION_ETH,
						 MLX5_EXPANSION_IPV4),
		.type = RTE_FLOW_ITEM_TYPE_VXLAN,
	},
	[MLX5_EXPANSION_VXLAN_GPE] = {
		.next = RTE_FLOW_EXPAND_RSS_NEXT(MLX5_EXPANSION_ETH,
						 MLX5_EXPANSION_IPV4,
						 MLX5_EXPANSION_IPV6),
		.type = RTE_FLOW_ITEM_TYPE_VXLAN_GPE,
	},
	[MLX5_EXPANSION_GRE] = {
		.next = RTE_FLOW_EXPAND_RSS_NEXT(MLX5_EXPANSION_IPV4),
		.type = RTE_FLOW_ITEM_TYPE_GRE,
	},
	[MLX5_EXPANSION_MPLS] = {
		.next = RTE_FLOW_EXPAND_RSS_NEXT(MLX5_EXPANSION_IPV4,
						 MLX5_EXPANSION_IPV6),
		.type = RTE_FLOW_ITEM_TYPE_MPLS,
	},
	[MLX5_EXPANSION_ETH] = {
		.next = RTE_FLOW_EXPAND_RSS_NEXT(MLX5_EXPANSION_IPV4,
						 MLX5_EXPANSION_IPV6),
		.type = RTE_FLOW_ITEM_TYPE_ETH,
	},
	[MLX5_EXPANSION_ETH_VLAN] = {
		.next = RTE_FLOW_EXPAND_RSS_NEXT(MLX5_EXPANSION_VLAN),
		.type = RTE_FLOW_ITEM_TYPE_ETH,
	},
	[MLX5_EXPANSION_VLAN] = {
		.next = RTE_FLOW_EXPAND_RSS_NEXT(MLX5_EXPANSION_IPV4,
						 MLX5_EXPANSION_IPV6),
		.type = RTE_FLOW_ITEM_TYPE_VLAN,
	},
	[MLX5_EXPANSION_IPV4] = {
		.next = RTE_FLOW_EXPAND_RSS_NEXT(MLX5_EXPANSION_IPV4_UDP,
						 MLX5_EXPANSION_IPV4_TCP),
		.type = RTE_FLOW_ITEM_TYPE_IPV4,
		.rss_types = ETH_RSS_IPV4 | ETH_RSS_FRAG_IPV4 |
			ETH_RSS_NONFRAG_IPV4_OTHER,
	},
	[MLX5_EXPANSION_IPV4_UDP] = {
		.type = RTE_FLOW_ITEM_TYPE_UDP,
		.rss_types = ETH_RSS_NONFRAG_IPV4_UDP,
	},
	[MLX5_EXPANSION_IPV4_TCP] = {
		.type = RTE_FLOW_ITEM_TYPE_TCP,
		.rss_types = ETH_RSS_NONFRAG_IPV4_TCP,
	},
	[MLX5_EXPANSION_IPV6] = {
		.next = RTE_FLOW_EXPAND_RSS_NEXT(MLX5_EXPANSION_IPV6_UDP,
						 MLX5_EXPANSION_IPV6_TCP),
		.type = RTE_FLOW_ITEM_TYPE_IPV6,
		.rss_types = ETH_RSS_IPV6 | ETH_RSS_FRAG_IPV6 |
			ETH_RSS_NONFRAG_IPV6_OTHER,
	},
	[MLX5_EXPANSION_IPV6_UDP] = {
		.type = RTE_FLOW_ITEM_TYPE_UDP,
		.rss_types = ETH_RSS_NONFRAG_IPV6_UDP,
	},
	[MLX5_EXPANSION_IPV6_TCP] = {
		.type = RTE_FLOW_ITEM_TYPE_TCP,
		.rss_types = ETH_RSS_NONFRAG_IPV6_TCP,
	},
};

/* Convert FDIR request to Generic flow. */
struct mlx5_fdir {
	struct rte_flow_attr attr;
	struct rte_flow_item items[4];
	struct rte_flow_item_eth l2;
	struct rte_flow_item_eth l2_mask;
	union {
		struct rte_flow_item_ipv4 ipv4;
		struct rte_flow_item_ipv6 ipv6;
	} l3;
	union {
		struct rte_flow_item_ipv4 ipv4;
		struct rte_flow_item_ipv6 ipv6;
	} l3_mask;
	union {
		struct rte_flow_item_udp udp;
		struct rte_flow_item_tcp tcp;
	} l4;
	union {
		struct rte_flow_item_udp udp;
		struct rte_flow_item_tcp tcp;
	} l4_mask;
	struct rte_flow_action actions[2];
	struct rte_flow_action_queue queue;
};

/* Map of Verbs to Flow priority with 8 Verbs priorities. */
static const uint32_t priority_map_2[][MLX5_PRIORITY_MAP_MAX] = {
	{ 0, 1, 2 }, { 3, 4, 5 },
};

/* Map of Verbs to Flow priority with 16 Verbs priorities. */
static const uint32_t priority_map_5[][MLX5_PRIORITY_MAP_MAX] = {
	{ 0, 1, 2 }, { 3, 4, 5 }, { 6, 7, 8 },
	{ 9, 10, 11 }, { 12, 13, 14 },
};

/* Tunnel information. */
struct mlx5_flow_tunnel_info {
	uint64_t tunnel; /**< Tunnel bit (see MLX5_FLOW_*). */
	uint32_t ptype; /**< Tunnel Ptype (see RTE_PTYPE_*). */
};

#ifdef RTE_LIBRTE_MLX5_FLOW_CACHE
static struct mlx5_flow_tunnel_info tunnels_info[] = {
	{
		.tunnel = MLX5_FLOW_LAYER_VXLAN,
		.ptype = RTE_PTYPE_TUNNEL_VXLAN | RTE_PTYPE_L4_UDP,
	},
	{
		.tunnel = MLX5_FLOW_LAYER_VXLAN_GPE,
		.ptype = RTE_PTYPE_TUNNEL_VXLAN_GPE | RTE_PTYPE_L4_UDP,
	},
	{
		.tunnel = MLX5_FLOW_LAYER_GRE,
		.ptype = RTE_PTYPE_TUNNEL_GRE,
	},
	{
		.tunnel = MLX5_FLOW_LAYER_MPLS | MLX5_FLOW_LAYER_OUTER_L4_UDP,
		.ptype = RTE_PTYPE_TUNNEL_MPLS_IN_GRE | RTE_PTYPE_L4_UDP,
	},
	{
		.tunnel = MLX5_FLOW_LAYER_MPLS,
		.ptype = RTE_PTYPE_TUNNEL_MPLS_IN_GRE,
	},
};
#endif

#ifndef RTE_LIBRTE_MLX5_FLOW_CACHE
struct rte_flow *gflow;
uint32_t gflow_size;
#define MLX5_MAX_RSS_QUEUES ETH_RSS_RETA_SIZE_512
struct mlx5_flow_handle {
	struct mlx5_flow_handle *next;
	/**< pointer to the next handle. Must be must be first. */
	uint8_t drv_type; /**< The driver type must be second. */
};
#endif

/* Stack strutcture. */
//struct mlx5_flow_stack {
//	uint32_t (*empty)[];
//	uint32_t base_index;
//	uint32_t *curr;
//	uint32_t *last;
//};
#define MLX5_FLOW_MIN_STACK_SIZE 256
struct
mlx5_flow_stack *mlx5_flow_stack_alloc(void)
{
	struct mlx5_flow_stack *stack;
	uint32_t *mem;

	mem = rte_zmalloc("", MLX5_FLOW_MIN_STACK_SIZE * sizeof(uint32_t), 0);
	if (!mem) {
		DRV_LOG(ERR, "cannot allocate mem for flow id stack array\n");
		return NULL;
	}
	stack = rte_zmalloc("", sizeof(*stack), 0);
	if (!stack) {
		DRV_LOG(ERR, "cannot allocate mem for flow id stack\n");
		rte_free(mem);
		return NULL;
	}
	stack->empty = mem;
	stack->curr = mem;
	stack->last = mem + MLX5_FLOW_MIN_STACK_SIZE;
	stack->base_index = 0;
	return stack;
}

void mlx5_flow_stack_release(struct mlx5_flow_stack *stack)
{
	rte_free(stack->empty);
	rte_free(stack);
}

static uint32_t
flow_mark_bit_index(const void *data, __rte_unused uint32_t data_len,
               __rte_unused uint32_t init_val)
{
	return (rte_be_to_cpu_32(*(const uint32_t *)data));
}

struct rte_hlist_table *mlx5_flow_tags_hlist_create(char *dev_name)
{
	char list_name[RTE_HLIST_NAMESIZE / 2];

	struct rte_hlist_params hp = {
		.name = NULL,
		.entries = MLX5_TAG_LIST_INIT_NUM,
		.entries_per_bucket = MLX5_TAG_LIST_ENTRY_PER_LIST,
		.key_len = sizeof(uint32_t),
		.hash_func = flow_mark_bit_index,
		.free_func = rte_free,
		.init_val = 0,
	};
	hp.socket_id = rte_socket_id();

	snprintf(list_name, sizeof(list_name),
		"%s_tag_list", dev_name);
	hp.name = list_name;

	return rte_hlist_create(&hp);
}

void mlx5_flow_tags_hlist_free(struct rte_hlist_table *h)
{
	(void)rte_hlist_free(h);
}

uint32_t mlx5_flow_id_get(struct mlx5_flow_stack *stack)
{
	if (stack->curr == stack->empty)
		return ++stack->base_index;
	return (*(--stack->curr));
}

void mlx5_flow_id_release(struct mlx5_flow_stack *stack, uint32_t value)
{
	if (stack->curr == stack->last) {
		uint32_t size;
		uint32_t size2;
		uint32_t *mem;

		size = stack->curr - stack->empty;
		size2 = size * size;
		mem = rte_zmalloc("", size2 * sizeof(uint32_t), 0);
		memcpy(mem, stack->empty, size * sizeof(uint32_t));
		rte_free(stack->empty);
		stack->empty = mem;
		stack->curr = mem + size;
		stack->last = mem + size2;
	}
	*stack->curr = value;
	stack->curr++;
}

/**
 * Discover the maximum number of priority available.
 *
 * @param[in] dev
 *   Pointer to the Ethernet device structure.
 *
 * @return
 *   number of supported flow priority on success, a negative errno
 *   value otherwise and rte_errno is set.
 */
int
mlx5_flow_discover_priorities(struct rte_eth_dev *dev)
{
	struct priv *priv = dev->data->dev_private;
	struct {
		struct ibv_flow_attr attr;
		struct ibv_flow_spec_eth eth;
		struct ibv_flow_spec_action_drop drop;
	} flow_attr = {
		.attr = {
			.num_of_specs = 2,
			.port = (uint8_t)priv->ibv_port,
		},
		.eth = {
			.type = IBV_FLOW_SPEC_ETH,
			.size = sizeof(struct ibv_flow_spec_eth),
		},
		.drop = {
			.size = sizeof(struct ibv_flow_spec_action_drop),
			.type = IBV_FLOW_SPEC_ACTION_DROP,
		},
	};
	struct ibv_flow *flow;
	struct mlx5_hrxq *drop = mlx5_hrxq_drop_new(dev);
	uint16_t vprio[] = { 8, 16 };
	int i;
	int priority = 0;

	if (!drop) {
		rte_errno = ENOTSUP;
		return -rte_errno;
	}
	for (i = 0; i != RTE_DIM(vprio); i++) {
		flow_attr.attr.priority = vprio[i] - 1;
		flow = mlx5_glue->create_flow(drop->qp, &flow_attr.attr);
		if (!flow)
			break;
		claim_zero(mlx5_glue->destroy_flow(flow));
		priority = vprio[i];
	}
	mlx5_hrxq_drop_release(dev);
	switch (priority) {
	case 8:
		priority = RTE_DIM(priority_map_2);
		break;
	case 16:
		priority = RTE_DIM(priority_map_5);
		break;
	default:
		rte_errno = ENOTSUP;
		DRV_LOG(ERR,
			"port %u verbs maximum priority: %d expected 8/16",
			dev->data->port_id, priority);
		return -rte_errno;
	}
	DRV_LOG(INFO, "port %u flow maximum priority: %d",
		dev->data->port_id, priority);
	return priority;
}

/**
 * Adjust flow priority based on the highest layer and the request priority.
 *
 * @param[in] dev
 *   Pointer to the Ethernet device structure.
 * @param[in] priority
 *   The rule base priority.
 * @param[in] subpriority
 *   The priority based on the items.
 *
 * @return
 *   The new priority.
 */
uint32_t mlx5_flow_adjust_priority(struct rte_eth_dev *dev, int32_t priority,
				   uint32_t subpriority)
{
	uint32_t res = 0;
	struct priv *priv = dev->data->dev_private;

	switch (priv->config.flow_prio) {
	case RTE_DIM(priority_map_2):
		res = priority_map_2[priority][subpriority];
		break;
	case RTE_DIM(priority_map_5):
		res = priority_map_5[priority][subpriority];
		break;
	}
	return  res;
}

/**
 * Verify the @p item specifications (spec, last, mask) are compatible with the
 * NIC capabilities.
 *
 * @param[in] item
 *   Item specification.
 * @param[in] mask
 *   @p item->mask or flow default bit-masks.
 * @param[in] nic_mask
 *   Bit-masks covering supported fields by the NIC to compare with user mask.
 * @param[in] size
 *   Bit-masks size in bytes.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_flow_item_acceptable(const struct rte_flow_item *item,
			  const uint8_t *mask,
			  const uint8_t *nic_mask,
			  unsigned int size,
			  struct rte_flow_error *error)
{
	unsigned int i;

	assert(nic_mask);
	for (i = 0; i < size; ++i)
		if ((nic_mask[i] | mask[i]) != nic_mask[i])
			return rte_flow_error_set(error, ENOTSUP,
						  RTE_FLOW_ERROR_TYPE_ITEM,
						  item,
						  "mask enables non supported"
						  " bits");
	if (!item->spec && (item->mask || item->last))
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "mask/last without a spec is not"
					  " supported");
	if (item->spec && item->last) {
		uint8_t spec[size];
		uint8_t last[size];
		unsigned int i;
		int ret;

		for (i = 0; i < size; ++i) {
			spec[i] = ((const uint8_t *)item->spec)[i] & mask[i];
			last[i] = ((const uint8_t *)item->last)[i] & mask[i];
		}
		ret = memcmp(spec, last, size);
		if (ret != 0)
			return rte_flow_error_set(error, EINVAL,
						  RTE_FLOW_ERROR_TYPE_ITEM,
						  item,
						  "range is not valid");
	}
	return 0;
}

/**
 * Adjust the hash fields according to the @p flow information.
 *
 * @param[in] dev_flow.
 *   Pointer to the mlx5_flow.
 * @param[in] tunnel
 *   1 when the hash field is for a tunnel item.
 * @param[in] layer_types
 *   ETH_RSS_* types.
 * @param[in] hash_fields
 *   Item hash fields.
 * @param[in] decap
 *   Tunnel decap action.
 *
 * @return
 *   The hash fileds that should be used.
 */
uint64_t
mlx5_flow_hashfields_adjust(struct mlx5_flow *dev_flow,
			    int tunnel __rte_unused, uint64_t layer_types,
			    uint64_t hash_fields, int decap)
{
	struct rte_flow *flow = dev_flow->flow;
#ifdef HAVE_IBV_DEVICE_TUNNEL_SUPPORT
	int rss_request_inner = flow->rss.level >= 1;

	if (tunnel && !decap) { /* For tunnel. */
		if (rss_request_inner)
			hash_fields |= IBV_RX_HASH_INNER;
		else
			return 0;
	} else if (rss_request_inner || (decap && !tunnel)) {
		return 0;
	}
#endif
	/* Check if requested layer matches RSS hash fields. */
	if (!(flow->rss.types & layer_types))
		return 0;
	return hash_fields;
}

#ifdef RTE_LIBRTE_MLX5_FLOW_CACHE
/**
 * Lookup and set the ptype in the data Rx part.  A single Ptype can be used,
 * if several tunnel rules are used on this queue, the tunnel ptype will be
 * cleared.
 *
 * @param rxq_ctrl
 *   Rx queue to update.
 */
static void
flow_rxq_tunnel_ptype_update(struct mlx5_rxq_ctrl *rxq_ctrl)
{
	unsigned int i;
	uint32_t tunnel_ptype = 0;

	/* Look up for the ptype to use. */
	for (i = 0; i != MLX5_FLOW_TUNNEL; ++i) {
		if (!rxq_ctrl->flow_tunnels_n[i])
			continue;
		if (!tunnel_ptype) {
			tunnel_ptype = tunnels_info[i].ptype;
		} else {
			tunnel_ptype = RTE_PTYPE_TUNNEL_MASK;
			break;
		}
	}
	rxq_ctrl->rxq.tunnel = tunnel_ptype ? tunnel_ptype :
					      RTE_PTYPE_TUNNEL_MASK;
}

/**
 * Set the Rx queue flags (Mark/Flag and Tunnel Ptypes) according to the devive
 * flow.
 *
 * @param[in] dev
 *   Pointer to the Ethernet device structure.
 * @param[in] dev_flow
 *   Pointer to device flow structure.
 */
static void
flow_drv_rxq_flags_set(struct rte_eth_dev *dev, struct mlx5_flow *dev_flow)
{
	struct priv *priv = dev->data->dev_private;
	struct rte_flow *flow = dev_flow->flow;
	const int mark = !!(flow->actions &
			    (MLX5_FLOW_ACTION_FLAG | MLX5_FLOW_ACTION_MARK));
	const int tunnel = !!(dev_flow->layers & MLX5_FLOW_LAYER_TUNNEL);
	unsigned int i;

	for (i = 0; i != flow->rss.queue_num; ++i) {
		int idx = (*flow->queue)[i];
		struct mlx5_rxq_ctrl *rxq_ctrl =
			container_of((*priv->rxqs)[idx],
				     struct mlx5_rxq_ctrl, rxq);

		if (mark) {
			rxq_ctrl->rxq.mark = 1;
			rxq_ctrl->flow_mark_n++;
		}
		if (tunnel) {
			unsigned int j;

			/* Increase the counter matching the flow. */
			for (j = 0; j != MLX5_FLOW_TUNNEL; ++j) {
				if ((tunnels_info[j].tunnel &
				     dev_flow->layers) ==
				    tunnels_info[j].tunnel) {
					rxq_ctrl->flow_tunnels_n[j]++;
					break;
				}
			}
			flow_rxq_tunnel_ptype_update(rxq_ctrl);
		}
	}
}

/**
 * Set the Rx queue flags (Mark/Flag and Tunnel Ptypes) for a flow
 *
 * @param[in] dev
 *   Pointer to the Ethernet device structure.
 * @param[in] flow
 *   Pointer to flow structure.
 */
static void
flow_rxq_flags_set(struct rte_eth_dev *dev, struct rte_flow *flow)
{
	struct mlx5_flow *dev_flow;

	LIST_FOREACH(dev_flow, &flow->dev_flows, next)
		flow_drv_rxq_flags_set(dev, dev_flow);
}
#else
static void
flow_rxq_flags_set(struct rte_eth_dev *dev, struct rte_flow *flow)
{
	struct priv *priv = dev->data->dev_private;
	struct rte_flow_handle *flow_handle = flow->handle;
	const int mark = !!(flow->actions &
			    (MLX5_FLOW_ACTION_FLAG | MLX5_FLOW_ACTION_MARK));
	unsigned int i;

	for (i = 0; i != flow->rss.queue_num; ++i) {
		int idx = (*flow->queue)[i];
		struct mlx5_rxq_ctrl *rxq_ctrl =
			container_of((*priv->rxqs)[idx],
				     struct mlx5_rxq_ctrl, rxq);

		(*flow_handle->queue)[i] = idx;
		if (mark) {
			rxq_ctrl->rxq.mark = 1;
			rxq_ctrl->flow_mark_n++;
		}
	}

}
#endif

#ifdef RTE_LIBRTE_MLX5_FLOW_CACHE
/**
 * Clear the Rx queue flags (Mark/Flag and Tunnel Ptype) associated with the
 * device flow if no other flow uses it with the same kind of request.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param[in] dev_flow
 *   Pointer to the device flow.
 */
static void
flow_drv_rxq_flags_trim(struct rte_eth_dev *dev, struct mlx5_flow *dev_flow)
{
	struct priv *priv = dev->data->dev_private;
	struct rte_flow *flow = dev_flow->flow;
	const int mark = !!(flow->actions &
			    (MLX5_FLOW_ACTION_FLAG | MLX5_FLOW_ACTION_MARK));
	const int tunnel = !!(dev_flow->layers & MLX5_FLOW_LAYER_TUNNEL);
	unsigned int i;

	assert(dev->data->dev_started);
	for (i = 0; i != flow->rss.queue_num; ++i) {
		int idx = (*flow->queue)[i];
		struct mlx5_rxq_ctrl *rxq_ctrl =
			container_of((*priv->rxqs)[idx],
				     struct mlx5_rxq_ctrl, rxq);

		if (mark) {
			rxq_ctrl->flow_mark_n--;
			rxq_ctrl->rxq.mark = !!rxq_ctrl->flow_mark_n;
		}
		if (tunnel) {
			unsigned int j;

			/* Decrease the counter matching the flow. */
			for (j = 0; j != MLX5_FLOW_TUNNEL; ++j) {
				if ((tunnels_info[j].tunnel &
				     dev_flow->layers) ==
				    tunnels_info[j].tunnel) {
					rxq_ctrl->flow_tunnels_n[j]--;
					break;
				}
			}
			flow_rxq_tunnel_ptype_update(rxq_ctrl);
		}
	}
}

/**
 * Clear the Rx queue flags (Mark/Flag and Tunnel Ptype) associated with the
 * @p flow if no other flow uses it with the same kind of request.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param[in] flow
 *   Pointer to the flow.
 */
static void
flow_rxq_flags_trim(struct rte_eth_dev *dev, struct rte_flow *flow)
{
	struct mlx5_flow *dev_flow;

	LIST_FOREACH(dev_flow, &flow->dev_flows, next)
		flow_drv_rxq_flags_trim(dev, dev_flow);
}
#else
/**
 * Clear the Rx queue flags (Mark/Flag and Tunnel Ptype) associated with the
 * @p flow if no other flow uses it with the same kind of request.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param[in] flow
 *   Pointer to the flow.
 */
static void
flow_rxq_flags_trim_handle(struct rte_eth_dev *dev, struct rte_flow_handle *flow)
{
	struct priv *priv = dev->data->dev_private;
	const int mark = !!(flow->actions &
			    (MLX5_FLOW_ACTION_FLAG | MLX5_FLOW_ACTION_MARK));
	unsigned int i;

	assert(dev->data->dev_started);
	for (i = 0; i != flow->queue_num; ++i) {
		int idx = (*flow->queue)[i];
		struct mlx5_rxq_ctrl *rxq_ctrl =
			container_of((*priv->rxqs)[idx],
				     struct mlx5_rxq_ctrl, rxq);

		if (mark) {
			rxq_ctrl->flow_mark_n--;
			rxq_ctrl->rxq.mark = !!rxq_ctrl->flow_mark_n;
		}
	}
}
#endif

/**
 * Clear the Mark/Flag and Tunnel ptype information in all Rx queues.
 *
 * @param dev
 *   Pointer to Ethernet device.
 */
static void
flow_rxq_flags_clear(struct rte_eth_dev *dev)
{
	struct priv *priv = dev->data->dev_private;
	unsigned int i;

	for (i = 0; i != priv->rxqs_n; ++i) {
		struct mlx5_rxq_ctrl *rxq_ctrl;
		unsigned int j;

		if (!(*priv->rxqs)[i])
			continue;
		rxq_ctrl = container_of((*priv->rxqs)[i],
					struct mlx5_rxq_ctrl, rxq);
		rxq_ctrl->flow_mark_n = 0;
		rxq_ctrl->rxq.mark = 0;
		for (j = 0; j != MLX5_FLOW_TUNNEL; ++j)
			rxq_ctrl->flow_tunnels_n[j] = 0;
		rxq_ctrl->rxq.tunnel = RTE_PTYPE_TUNNEL_MASK;
	}
}

/*
 * Validate the flag action.
 *
 * @param[in] action_flags
 *   Bit-fields that holds the actions detected until now.
 * @param[in] attr
 *   Attributes of flow that includes this action.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_flow_validate_action_flag(uint64_t action_flags,
			       const struct rte_flow_attr *attr,
			       struct rte_flow_error *error)
{
	if (action_flags & MLX5_FLOW_ACTION_DROP)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION, NULL,
					  "can't drop and flag in same flow");
	if (action_flags & MLX5_FLOW_ACTION_MARK)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION, NULL,
					  "can't mark and flag in same flow");
	if (action_flags & MLX5_FLOW_ACTION_FLAG)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION, NULL,
					  "can't have 2 flag"
					  " actions in same flow");
	if (attr->egress)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ATTR_EGRESS, NULL,
					  "flag action not supported for "
					  "egress");
	return 0;
}

/*
 * Validate the mark action.
 *
 * @param[in] action
 *   Pointer to the queue action.
 * @param[in] action_flags
 *   Bit-fields that holds the actions detected until now.
 * @param[in] attr
 *   Attributes of flow that includes this action.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_flow_validate_action_mark(const struct rte_flow_action *action,
			       uint64_t action_flags,
			       const struct rte_flow_attr *attr,
			       struct rte_flow_error *error)
{
	const struct rte_flow_action_mark *mark = action->conf;

	if (!mark)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION,
					  action,
					  "configuration cannot be null");
	if (mark->id >= MLX5_FLOW_MARK_MAX)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION_CONF,
					  &mark->id,
					  "mark id must in 0 <= id < "
					  RTE_STR(MLX5_FLOW_MARK_MAX));
	if (action_flags & MLX5_FLOW_ACTION_DROP)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION, NULL,
					  "can't drop and mark in same flow");
	if (action_flags & MLX5_FLOW_ACTION_FLAG)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION, NULL,
					  "can't flag and mark in same flow");
	if (action_flags & MLX5_FLOW_ACTION_MARK)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION, NULL,
					  "can't have 2 mark actions in same"
					  " flow");
	if (attr->egress)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ATTR_EGRESS, NULL,
					  "mark action not supported for "
					  "egress");
	return 0;
}

/*
 * Validate the drop action.
 *
 * @param[in] action_flags
 *   Bit-fields that holds the actions detected until now.
 * @param[in] attr
 *   Attributes of flow that includes this action.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_ernno is set.
 */
int
mlx5_flow_validate_action_drop(uint64_t action_flags,
			       const struct rte_flow_attr *attr,
			       struct rte_flow_error *error)
{
	if (action_flags & MLX5_FLOW_ACTION_FLAG)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION, NULL,
					  "can't drop and flag in same flow");
	if (action_flags & MLX5_FLOW_ACTION_MARK)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION, NULL,
					  "can't drop and mark in same flow");
	if (action_flags & MLX5_FLOW_FATE_ACTIONS)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION, NULL,
					  "can't have 2 fate actions in"
					  " same flow");
	if (attr->egress)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ATTR_EGRESS, NULL,
					  "drop action not supported for "
					  "egress");
	return 0;
}

/*
 * Validate the queue action.
 *
 * @param[in] action
 *   Pointer to the queue action.
 * @param[in] action_flags
 *   Bit-fields that holds the actions detected until now.
 * @param[in] dev
 *   Pointer to the Ethernet device structure.
 * @param[in] attr
 *   Attributes of flow that includes this action.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_ernno is set.
 */
int
mlx5_flow_validate_action_queue(const struct rte_flow_action *action,
				uint64_t action_flags,
				struct rte_eth_dev *dev,
				const struct rte_flow_attr *attr,
				struct rte_flow_error *error)
{
	struct priv *priv = dev->data->dev_private;
	const struct rte_flow_action_queue *queue = action->conf;

	if (action_flags & MLX5_FLOW_FATE_ACTIONS)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION, NULL,
					  "can't have 2 fate actions in"
					  " same flow");
	if (queue->index >= priv->rxqs_n)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION_CONF,
					  &queue->index,
					  "queue index out of range");
	if (!(*priv->rxqs)[queue->index])
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION_CONF,
					  &queue->index,
					  "queue is not configured");
	if (attr->egress)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ATTR_EGRESS, NULL,
					  "queue action not supported for "
					  "egress");
	return 0;
}

/*
 * Validate the rss action.
 *
 * @param[in] action
 *   Pointer to the queue action.
 * @param[in] action_flags
 *   Bit-fields that holds the actions detected until now.
 * @param[in] dev
 *   Pointer to the Ethernet device structure.
 * @param[in] attr
 *   Attributes of flow that includes this action.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_ernno is set.
 */
int
mlx5_flow_validate_action_rss(const struct rte_flow_action *action,
			      uint64_t action_flags,
			      struct rte_eth_dev *dev,
			      const struct rte_flow_attr *attr,
			      struct rte_flow_error *error)
{
	struct priv *priv = dev->data->dev_private;
	const struct rte_flow_action_rss *rss = action->conf;
	unsigned int i;

	if (!rss)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION, NULL,
					  "RSS queues not specified");
	if (action_flags & MLX5_FLOW_FATE_ACTIONS)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION, NULL,
					  "can't have 2 fate actions"
					  " in same flow");
/*
	if (rss->func != RTE_ETH_HASH_FUNCTION_DEFAULT &&
	    rss->func != RTE_ETH_HASH_FUNCTION_TOEPLITZ)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ACTION_CONF,
					  &rss->func,
					  "RSS hash function not supported");
*/
#ifdef HAVE_IBV_DEVICE_TUNNEL_SUPPORT
	if (rss->rss_conf->rss_level > 1 ||
	    (priv->vf && rss->rss_conf->rss_level > 0))
#else
	if (rss->rss_conf->rss_level > 0)
#endif
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ACTION_CONF,
					  &rss->rss_conf->rss_level,
					  "tunnel RSS is not supported");
	/* allow RSS key_len 0 in case of NULL (default) RSS key. */
	if (rss->rss_conf->rss_key_len == 0 &&
	    rss->rss_conf->rss_key != NULL)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ACTION_CONF,
					  &rss->rss_conf->rss_key_len,
					  "RSS hash key length 0");
	if (rss->rss_conf->rss_key_len > 0 &&
	    rss->rss_conf->rss_key_len < MLX5_RSS_HASH_KEY_LEN)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ACTION_CONF,
					  &rss->rss_conf->rss_key_len,
					  "RSS hash key too small");
	if (rss->rss_conf->rss_key_len > MLX5_RSS_HASH_KEY_LEN)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ACTION_CONF,
					  &rss->rss_conf->rss_key_len,
					  "RSS hash key too large");
	if (rss->num > priv->config.ind_table_max_size)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ACTION_CONF,
					  &rss->num,
					  "number of queues too large");
	if (rss->num == 0)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ACTION_CONF,
					  &rss->num,
					  "no queues were provided for RSS");
	if (rss->rss_conf->rss_hf & MLX5_RSS_HF_MASK)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ACTION_CONF,
					  &rss->rss_conf->rss_hf,
					  "some RSS protocols are not"
					  " supported");
	for (i = 0; i != rss->num; ++i) {
		if ((!(priv->rxqs)) || (!(*priv->rxqs)[rss->queue[i]]))
			return rte_flow_error_set
				(error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION_CONF,
				 &rss->queue[i], "queue is not configured");
	}
	if (attr->egress)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ATTR_EGRESS, NULL,
					  "rss action not supported for "
					  "egress");
	return 0;
}

/*
 * Validate the count action.
 *
 * @param[in] dev
 *   Pointer to the Ethernet device structure.
 * @param[in] attr
 *   Attributes of flow that includes this action.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_ernno is set.
 */
int
mlx5_flow_validate_action_count(struct rte_eth_dev *dev __rte_unused,
				const struct rte_flow_attr *attr,
				struct rte_flow_error *error)
{
	if (attr->egress)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ATTR_EGRESS, NULL,
					  "count action not supported for "
					  "egress");
	return 0;
}

/**
 * Verify the @p attributes will be correctly understood by the NIC and store
 * them in the @p flow if everything is correct.
 *
 * @param[in] dev
 *   Pointer to the Ethernet device structure.
 * @param[in] attributes
 *   Pointer to flow attributes
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_flow_validate_attributes(struct rte_eth_dev *dev,
			      const struct rte_flow_attr *attributes,
			      struct rte_flow_error *error)
{
	struct priv *priv = dev->data->dev_private;
	/*
	 * in isolated mode, user can use all verbs' priorities.
	 * in non-isolated mode, the last (lowest) priorities reserved for
	 * control flows.
	 */
	uint32_t priority_max = priv->isolated ?
				priv->config.flow_prio - 1 :
				priv->config.flow_prio - 2;

	//if (attributes->group)
	//	return rte_flow_error_set(error, ENOTSUP,
	//				  RTE_FLOW_ERROR_TYPE_ATTR_GROUP,
	//				  NULL, "groups is not supported");
	if (attributes->priority != MLX5_FLOW_PRIO_RSVD &&
	    attributes->priority > priority_max)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ATTR_PRIORITY,
					  NULL, "priority out of range");
	if (attributes->egress)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ATTR_EGRESS, NULL,
					  "egress is not supported");
	if (attributes->transfer)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ATTR_TRANSFER,
					  NULL, "transfer is not supported");
	if (!attributes->ingress)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ATTR_INGRESS,
					  NULL,
					  "ingress attribute is mandatory");
	return 0;
}

/**
 * Validate ICMP6 echo item.
 *
 * @param[in] item
 *   Item specification.
 * @param[in] item_flags
 *   Bit-fields that holds the items detected until now.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_flow_validate_item_icmpv6(const struct rte_flow_item *item,
			       uint64_t item_flags,
			       uint8_t target_protocol,
			       struct rte_flow_error *error)
{
	const struct rte_flow_item_icmpv6 *mask = item->mask;
	const int tunnel = !!(item_flags & MLX5_FLOW_LAYER_TUNNEL);
	const uint64_t l3m = tunnel ? MLX5_FLOW_LAYER_INNER_L3 :
				      MLX5_FLOW_LAYER_OUTER_L3;
	const uint64_t l4m = tunnel ? MLX5_FLOW_LAYER_INNER_L4 :
				      MLX5_FLOW_LAYER_OUTER_L4;
	int ret;

	if (target_protocol != 0xff && target_protocol != 58)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "protocol filtering not compatible"
					  " with ICMP6 layer");
	if (!(item_flags & l3m))
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "L3 is mandatory to filter on ICMP");
	if (item_flags & l4m)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "multiple L4 layers not supported");
	if (!mask)
		mask = &rte_flow_item_icmpv6_mask;
	ret = mlx5_flow_item_acceptable
		(item, (const uint8_t *)mask,
		 (const uint8_t *)&rte_flow_item_icmp_mask,
		 sizeof(struct rte_flow_item_icmp), error);
	if (ret < 0)
		return ret;
	return 0;
}

/**
 * Validate ICMP item.
 *
 * @param[in] item
 *   Item specification.
 * @param[in] item_flags
 *   Bit-fields that holds the items detected until now.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_flow_validate_item_icmp(const struct rte_flow_item *item,
			     uint64_t item_flags,
			     uint8_t target_protocol,
			     struct rte_flow_error *error)
{
	const struct rte_flow_item_icmp *mask = item->mask;
	const int tunnel = !!(item_flags & MLX5_FLOW_LAYER_TUNNEL);
	const uint64_t l3m = tunnel ? MLX5_FLOW_LAYER_INNER_L3 :
				      MLX5_FLOW_LAYER_OUTER_L3;
	const uint64_t l4m = tunnel ? MLX5_FLOW_LAYER_INNER_L4 :
				      MLX5_FLOW_LAYER_OUTER_L4;
	int ret;

	if (target_protocol != 0xff && target_protocol != IPPROTO_ICMP)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "protocol filtering not compatible"
					  " with ICMP layer");
	if (!(item_flags & l3m))
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "L3 is mandatory to filter on ICMP");
	if (item_flags & l4m)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "multiple L4 layers not supported");
	if (!mask)
		mask = &rte_flow_item_icmp_mask;
	ret = mlx5_flow_item_acceptable
		(item, (const uint8_t *)mask,
		 (const uint8_t *)&rte_flow_item_icmp_mask,
		 sizeof(struct rte_flow_item_icmp), error);
	if (ret < 0)
		return ret;
	return 0;
}


/**
 * Validate Ethernet item.
 *
 * @param[in] item
 *   Item specification.
 * @param[in] item_flags
 *   Bit-fields that holds the items detected until now.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_flow_validate_item_eth(const struct rte_flow_item *item,
			    uint64_t item_flags,
			    struct rte_flow_error *error)
{
	const struct rte_flow_item_eth *mask = item->mask;
	const struct rte_flow_item_eth nic_mask = {
		.dst.addr_bytes = "\xff\xff\xff\xff\xff\xff",
		.src.addr_bytes = "\xff\xff\xff\xff\xff\xff",
		.type = RTE_BE16(0xffff),
	};
	int ret;
	int tunnel = !!(item_flags & MLX5_FLOW_LAYER_TUNNEL);
	const uint64_t ethm = tunnel ? MLX5_FLOW_LAYER_INNER_L2	:
				       MLX5_FLOW_LAYER_OUTER_L2;
	const uint64_t l34m = tunnel ? (MLX5_FLOW_LAYER_INNER_L3 |
					MLX5_FLOW_LAYER_INNER_L4) :
				       (MLX5_FLOW_LAYER_OUTER_L3 |
					MLX5_FLOW_LAYER_OUTER_L4);
	const uint64_t vlanm = tunnel ? MLX5_FLOW_LAYER_INNER_VLAN :
					MLX5_FLOW_LAYER_OUTER_VLAN;

	if (item_flags & ethm)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "multiple L2 layers not supported");
	if (item_flags & l34m)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "L2 layer cannot follow L3/L4 layer");
	if (item_flags & vlanm)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "Ethernet cannot follow VLAN");
	if (!mask)
		mask = &rte_flow_item_eth_mask;
	ret = mlx5_flow_item_acceptable(item, (const uint8_t *)mask,
					(const uint8_t *)&nic_mask,
					sizeof(struct rte_flow_item_eth),
					error);
	return ret;
}

/**
 * Validate VLAN item.
 *
 * @param[in] item
 *   Item specification.
 * @param[in] item_flags
 *   Bit-fields that holds the items detected until now.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_flow_validate_item_vlan(const struct rte_flow_item *item,
			     uint64_t item_flags,
			     struct rte_flow_error *error)
{
	const struct rte_flow_item_vlan *spec = item->spec;
	const struct rte_flow_item_vlan *mask = item->mask;
	const struct rte_flow_item_vlan nic_mask = {
		.tci = RTE_BE16(0x0fff),
		.tpid = RTE_BE16(0xffff),
	};
	uint16_t vlan_tag = 0;
	const int tunnel = !!(item_flags & MLX5_FLOW_LAYER_TUNNEL);
	int ret;
	const uint64_t l34m = tunnel ? (MLX5_FLOW_LAYER_INNER_L3 |
					MLX5_FLOW_LAYER_INNER_L4) :
				       (MLX5_FLOW_LAYER_OUTER_L3 |
					MLX5_FLOW_LAYER_OUTER_L4);
	const uint64_t vlanm = tunnel ? MLX5_FLOW_LAYER_INNER_VLAN :
					MLX5_FLOW_LAYER_OUTER_VLAN;

	if (item_flags & vlanm)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "multiple VLAN layers not supported");
	else if ((item_flags & l34m) != 0)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "L2 layer cannot follow L3/L4 layer");
	if (!mask)
		mask = &rte_flow_item_vlan_mask;
	ret = mlx5_flow_item_acceptable(item, (const uint8_t *)mask,
					(const uint8_t *)&nic_mask,
					sizeof(struct rte_flow_item_vlan),
					error);
	if (ret)
		return ret;
	if (spec) {
		vlan_tag = spec->tci;
		vlan_tag &= mask->tci;
	}
	/*
	 * From verbs perspective an empty VLAN is equivalent
	 * to a packet without VLAN layer.
	 */
	if (!vlan_tag)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM_SPEC,
					  item->spec,
					  "VLAN cannot be empty");
	return 0;
}

/**
 * Validate IPV4 item.
 *
 * @param[in] item
 *   Item specification.
 * @param[in] item_flags
 *   Bit-fields that holds the items detected until now.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_flow_validate_item_ipv4(const struct rte_flow_item *item,
			     uint64_t item_flags,
			     struct rte_flow_error *error)
{
	const struct rte_flow_item_ipv4 *mask = item->mask;
	const struct rte_flow_item_ipv4 nic_mask = {
		.hdr = {
			.src_addr = RTE_BE32(0xffffffff),
			.dst_addr = RTE_BE32(0xffffffff),
			.type_of_service = 0xff,
			.next_proto_id = 0xff,
		},
	};
	const int tunnel = !!(item_flags & MLX5_FLOW_LAYER_TUNNEL);
	const uint64_t l3m = tunnel ? MLX5_FLOW_LAYER_INNER_L3 :
				      MLX5_FLOW_LAYER_OUTER_L3;
	const uint64_t l4m = tunnel ? MLX5_FLOW_LAYER_INNER_L4 :
				      MLX5_FLOW_LAYER_OUTER_L4;
	int ret;

	if (item_flags & l3m)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "multiple L3 layers not supported");
	else if (item_flags & l4m)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "L3 cannot follow an L4 layer.");
	if (!mask)
		mask = &rte_flow_item_ipv4_mask;
	else if (mask->hdr.next_proto_id != 0 &&
		 mask->hdr.next_proto_id != 0xff)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM_MASK, mask,
					  "partial mask is not supported"
					  " for protocol");
	ret = mlx5_flow_item_acceptable(item, (const uint8_t *)mask,
					(const uint8_t *)&nic_mask,
					sizeof(struct rte_flow_item_ipv4),
					error);
	if (ret < 0)
		return ret;
	return 0;
}

/**
 * Validate IPV6 item.
 *
 * @param[in] item
 *   Item specification.
 * @param[in] item_flags
 *   Bit-fields that holds the items detected until now.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_flow_validate_item_ipv6(const struct rte_flow_item *item,
			     uint64_t item_flags,
			     struct rte_flow_error *error)
{
	const struct rte_flow_item_ipv6 *mask = item->mask;
	const struct rte_flow_item_ipv6 nic_mask = {
		.hdr = {
			.src_addr =
				"\xff\xff\xff\xff\xff\xff\xff\xff"
				"\xff\xff\xff\xff\xff\xff\xff\xff",
			.dst_addr =
				"\xff\xff\xff\xff\xff\xff\xff\xff"
				"\xff\xff\xff\xff\xff\xff\xff\xff",
			.vtc_flow = RTE_BE32(0xffffffff),
			.proto = 0xff,
			.hop_limits = 0xff,
		},
	};
	const int tunnel = !!(item_flags & MLX5_FLOW_LAYER_TUNNEL);
	const uint64_t l3m = tunnel ? MLX5_FLOW_LAYER_INNER_L3 :
				      MLX5_FLOW_LAYER_OUTER_L3;
	const uint64_t l4m = tunnel ? MLX5_FLOW_LAYER_INNER_L4 :
				      MLX5_FLOW_LAYER_OUTER_L4;
	int ret;

	if (item_flags & l3m)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "multiple L3 layers not supported");
	else if (item_flags & l4m)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "L3 cannot follow an L4 layer.");
	if (!mask)
		mask = &rte_flow_item_ipv6_mask;
	ret = mlx5_flow_item_acceptable(item, (const uint8_t *)mask,
					(const uint8_t *)&nic_mask,
					sizeof(struct rte_flow_item_ipv6),
					error);
	if (ret < 0)
		return ret;
	return 0;
}

/**
 * Validate UDP item.
 *
 * @param[in] item
 *   Item specification.
 * @param[in] item_flags
 *   Bit-fields that holds the items detected until now.
 * @param[in] target_protocol
 *   The next protocol in the previous item.
 * @param[in] flow_mask
 *   mlx5 flow-specific (DV, verbs, etc.) supported header fields mask.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_flow_validate_item_udp(const struct rte_flow_item *item,
			    uint64_t item_flags,
			    uint8_t target_protocol,
			    struct rte_flow_error *error)
{
	const struct rte_flow_item_udp *mask = item->mask;
	const int tunnel = !!(item_flags & MLX5_FLOW_LAYER_TUNNEL);
	const uint64_t l3m = tunnel ? MLX5_FLOW_LAYER_INNER_L3 :
				      MLX5_FLOW_LAYER_OUTER_L3;
	const uint64_t l4m = tunnel ? MLX5_FLOW_LAYER_INNER_L4 :
				      MLX5_FLOW_LAYER_OUTER_L4;
	int ret;

	if (target_protocol != 0xff && target_protocol != IPPROTO_UDP)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "protocol filtering not compatible"
					  " with UDP layer");
	if (!(item_flags & l3m))
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "L3 is mandatory to filter on L4");
	if (item_flags & l4m)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "multiple L4 layers not supported");
	if (!mask)
		mask = &rte_flow_item_udp_mask;
	ret = mlx5_flow_item_acceptable
		(item, (const uint8_t *)mask,
		 (const uint8_t *)&rte_flow_item_udp_mask,
		 sizeof(struct rte_flow_item_udp), error);
	if (ret < 0)
		return ret;
	return 0;
}

/**
 * Validate TCP item.
 *
 * @param[in] item
 *   Item specification.
 * @param[in] item_flags
 *   Bit-fields that holds the items detected until now.
 * @param[in] target_protocol
 *   The next protocol in the previous item.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_flow_validate_item_tcp(const struct rte_flow_item *item,
			    uint64_t item_flags,
			    uint8_t target_protocol,
			    const struct rte_flow_item_tcp *flow_mask,
			    struct rte_flow_error *error)
{
	const struct rte_flow_item_tcp *mask = item->mask;
	const int tunnel = !!(item_flags & MLX5_FLOW_LAYER_TUNNEL);
	const uint64_t l3m = tunnel ? MLX5_FLOW_LAYER_INNER_L3 :
				      MLX5_FLOW_LAYER_OUTER_L3;
	const uint64_t l4m = tunnel ? MLX5_FLOW_LAYER_INNER_L4 :
				      MLX5_FLOW_LAYER_OUTER_L4;
	int ret;

	assert(flow_mask);
	if (target_protocol != 0xff && target_protocol != IPPROTO_TCP)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "protocol filtering not compatible"
					  " with TCP layer");
	if (!(item_flags & l3m))
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "L3 is mandatory to filter on L4");
	if (item_flags & l4m)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "multiple L4 layers not supported");
	if (!mask)
		mask = &rte_flow_item_tcp_mask;
	ret = mlx5_flow_item_acceptable
		(item, (const uint8_t *)mask,
		 (const uint8_t *)flow_mask,
		 sizeof(struct rte_flow_item_tcp), error);
	if (ret < 0)
		return ret;
	return 0;
}

/**
 * Validate VXLAN item.
 *
 * @param[in] item
 *   Item specification.
 * @param[in] item_flags
 *   Bit-fields that holds the items detected until now.
 * @param[in] target_protocol
 *   The next protocol in the previous item.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_flow_validate_item_vxlan(const struct rte_flow_item *item,
			      uint64_t item_flags,
			      struct rte_flow_error *error)
{
	const struct rte_flow_item_vxlan *spec = item->spec;
	const struct rte_flow_item_vxlan *mask = item->mask;
	int ret;
	union vni {
		uint32_t vlan_id;
		uint8_t vni[4];
	} id = { .vlan_id = 0, };
	uint32_t vlan_id = 0;


	if (item_flags & MLX5_FLOW_LAYER_TUNNEL)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "multiple tunnel layers not"
					  " supported");
	/*
	 * Verify only UDPv4 is present as defined in
	 * https://tools.ietf.org/html/rfc7348
	 */
	if (!(item_flags & MLX5_FLOW_LAYER_OUTER_L4_UDP))
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "no outer UDP layer found");
	if (!mask)
		mask = &rte_flow_item_vxlan_mask;
	ret = mlx5_flow_item_acceptable
		(item, (const uint8_t *)mask,
		 (const uint8_t *)&rte_flow_item_vxlan_mask,
		 sizeof(struct rte_flow_item_vxlan),
		 error);
	if (ret < 0)
		return ret;
	if (spec) {
		memcpy(&id.vni[1], spec->vni, 3);
		vlan_id = id.vlan_id;
		memcpy(&id.vni[1], mask->vni, 3);
		vlan_id &= id.vlan_id;
	}
	if (!(item_flags & MLX5_FLOW_LAYER_OUTER))
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "VXLAN tunnel must be fully defined");
	return 0;
}

/**
 * Validate VXLAN_GPE item.
 *
 * @param[in] item
 *   Item specification.
 * @param[in] item_flags
 *   Bit-fields that holds the items detected until now.
 * @param[in] priv
 *   Pointer to the private data structure.
 * @param[in] target_protocol
 *   The next protocol in the previous item.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_flow_validate_item_vxlan_gpe(const struct rte_flow_item *item,
				  uint64_t item_flags,
				  struct rte_eth_dev *dev __rte_unused,
				  struct rte_flow_error *error)
{
	//struct priv *priv = dev->data->dev_private;
	const struct rte_flow_item_vxlan_gpe *spec = item->spec;
	const struct rte_flow_item_vxlan_gpe *mask = item->mask;
	int ret;
	union vni {
		uint32_t vlan_id;
		uint8_t vni[4];
	} id = { .vlan_id = 0, };
	uint32_t vlan_id = 0;
/*
	if (!priv->config.l3_vxlan_en)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "L3 VXLAN is not enabled by device"
					  " parameter and/or not configured in"
					  " firmware");
*/
	if (item_flags & MLX5_FLOW_LAYER_TUNNEL)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "multiple tunnel layers not"
					  " supported");
	/*
	 * Verify only UDPv4 is present as defined in
	 * https://tools.ietf.org/html/rfc7348
	 */
	if (!(item_flags & MLX5_FLOW_LAYER_OUTER_L4_UDP))
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "no outer UDP layer found");
	if (!mask)
		mask = &rte_flow_item_vxlan_gpe_mask;
	ret = mlx5_flow_item_acceptable
		(item, (const uint8_t *)mask,
		 (const uint8_t *)&rte_flow_item_vxlan_gpe_mask,
		 sizeof(struct rte_flow_item_vxlan_gpe),
		 error);
	if (ret < 0)
		return ret;
	if (spec) {
		if (spec->protocol)
			return rte_flow_error_set(error, ENOTSUP,
						  RTE_FLOW_ERROR_TYPE_ITEM,
						  item,
						  "VxLAN-GPE protocol"
						  " not supported");
		memcpy(&id.vni[1], spec->vni, 3);
		vlan_id = id.vlan_id;
		memcpy(&id.vni[1], mask->vni, 3);
		vlan_id &= id.vlan_id;
	}
	if (!(item_flags & MLX5_FLOW_LAYER_OUTER))
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "VXLAN-GPE tunnel must be fully"
					  " defined");
	return 0;
}
/**
 * Validate GRE Key item.
 *
 * @param[in] item
 *   Item specification.
 * @param[in] item_flags
 *   Bit flags to mark detected items.
 * @param[in] target_protocol
 *   The next protocol in the previous item.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_flow_validate_item_gre_opt_key(const struct rte_flow_item *item,
				    uint64_t item_flags,
				    struct rte_flow_error *error)
{
	const struct rte_flow_item_gre_opt_key *mask = item->mask;
	int ret = 0;

	if (item_flags & MLX5_FLOW_LAYER_GRE_OPT_KEY)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "Multiple GRE key not support");
	if (!(item_flags & MLX5_FLOW_LAYER_GRE))
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "No preceding GRE header");
	if (item_flags & MLX5_FLOW_LAYER_INNER)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "GRE key following a wrong item");
	if (!mask)
		mask = &rte_flow_item_gre_opt_key_mask;
	ret = mlx5_flow_item_acceptable
		(item, (const uint8_t *)mask,
		 (const uint8_t *)&rte_flow_item_gre_opt_key_mask,
		 sizeof(struct rte_flow_item_gre_opt_key), error);
	return ret;
}

/**
 * Validate GRE item.
 *
 * @param[in] item
 *   Item specification.
 * @param[in] item_flags
 *   Bit flags to mark detected items.
 * @param[in] target_protocol
 *   The next protocol in the previous item.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_flow_validate_item_gre(const struct rte_flow_item *item,
			    uint64_t item_flags,
			    uint8_t target_protocol,
			    struct rte_flow_error *error)
{
	const struct rte_flow_item_gre *spec __rte_unused = item->spec;
	const struct rte_flow_item_gre *mask = item->mask;
	int ret;
	const struct rte_flow_item_gre nic_mask = {
		.c_rsvd0_ver = RTE_BE16(0xB000),
		.protocol = RTE_BE16(UINT16_MAX),
	};

	if (target_protocol != 0xff && target_protocol != IPPROTO_GRE)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "protocol filtering not compatible"
					  " with this GRE layer");
	if (item_flags & MLX5_FLOW_LAYER_TUNNEL)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "multiple tunnel layers not"
					  " supported");
	if (!(item_flags & MLX5_FLOW_LAYER_OUTER_L3))
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "L3 Layer is missing");
	if (!mask)
		mask = &rte_flow_item_gre_mask;
	ret = mlx5_flow_item_acceptable
		(item, (const uint8_t *)mask,
		 (const uint8_t *)&nic_mask,
		 sizeof(struct rte_flow_item_gre), error);
	if (ret < 0)
		return ret;
#ifndef HAVE_MLX5DV_DR
#ifndef HAVE_IBV_DEVICE_MPLS_SUPPORT
	if (spec && (spec->protocol & mask->protocol))
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "without MPLS support the"
					  " specification cannot be used for"
					  " filtering");
#endif
#endif
	return 0;
}

/**
 * Validate MPLS item.
 *
 * @param[in] item
 *   Item specification.
 * @param[in] item_flags
 *   Bit-fields that holds the items detected until now.
 * @param[in] target_protocol
 *   The next protocol in the previous item.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_flow_validate_item_mpls(const struct rte_flow_item *item __rte_unused,
			     uint64_t item_flags __rte_unused,
			     uint8_t target_protocol __rte_unused,
			     struct rte_flow_error *error)
{
#ifdef HAVE_IBV_DEVICE_MPLS_SUPPORT
	const struct rte_flow_item_mpls *mask = item->mask;
	int ret;

	if (target_protocol != 0xff && target_protocol != IPPROTO_MPLS)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "protocol filtering not compatible"
					  " with MPLS layer");
	/* Multi-tunnel isn't allowed but MPLS over GRE is an exception. */
	if ((item_flags & MLX5_FLOW_LAYER_TUNNEL) &&
	    !(item_flags & MLX5_FLOW_LAYER_GRE))
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "multiple tunnel layers not"
					  " supported");
	if (!mask)
		mask = &rte_flow_item_mpls_mask;
	ret = mlx5_flow_item_acceptable
		(item, (const uint8_t *)mask,
		 (const uint8_t *)&rte_flow_item_mpls_mask,
		 sizeof(struct rte_flow_item_mpls), error);
	if (ret < 0)
		return ret;
	return 0;
#endif
	return rte_flow_error_set(error, ENOTSUP,
				  RTE_FLOW_ERROR_TYPE_ITEM, item,
				  "MPLS is not supported by Verbs, please"
				  " update.");
}

static int
flow_null_validate(struct rte_eth_dev *dev __rte_unused,
		   const struct rte_flow_attr *attr __rte_unused,
		   const struct rte_flow_item items[] __rte_unused,
		   const struct rte_flow_action actions[] __rte_unused,
		   struct rte_flow_error *error __rte_unused)
{
	rte_errno = ENOTSUP;
	return -rte_errno;
}

static struct mlx5_flow *
flow_null_prepare(const struct rte_flow_attr *attr __rte_unused,
		  const struct rte_flow_item items[] __rte_unused,
		  const struct rte_flow_action actions[] __rte_unused,
		  struct rte_flow_error *error __rte_unused)
{
	rte_errno = ENOTSUP;
	return NULL;
}

static int
flow_null_translate(struct rte_eth_dev *dev __rte_unused,
		    struct mlx5_flow *dev_flow __rte_unused,
		    const struct rte_flow_attr *attr __rte_unused,
		    const struct rte_flow_item items[] __rte_unused,
		    const struct rte_flow_action actions[] __rte_unused,
		    struct rte_flow_error *error __rte_unused)
{
	rte_errno = ENOTSUP;
	return -rte_errno;
}

static int
flow_null_apply(struct rte_eth_dev *dev __rte_unused,
		struct rte_flow *flow __rte_unused,
		struct rte_flow_error *error __rte_unused)
{
	rte_errno = ENOTSUP;
	return -rte_errno;
}

static void
flow_null_remove(struct rte_eth_dev *dev __rte_unused,
		 struct rte_flow *flow __rte_unused)
{
}

static void
flow_null_destroy(struct rte_eth_dev *dev __rte_unused,
		  struct rte_flow *flow __rte_unused)
{
}

static int
flow_null_query(struct rte_eth_dev *dev __rte_unused,
		struct rte_flow *flow __rte_unused,
		const struct rte_flow_action *actions __rte_unused,
		void *data __rte_unused,
		struct rte_flow_error *error __rte_unused)
{
	rte_errno = ENOTSUP;
	return -rte_errno;
}

/* Void driver to protect from null pointer reference. */
const struct mlx5_flow_driver_ops mlx5_flow_null_drv_ops = {
	.validate = flow_null_validate,
	.prepare = flow_null_prepare,
	.translate = flow_null_translate,
	.apply = flow_null_apply,
	.remove = flow_null_remove,
	.destroy = flow_null_destroy,
	.query = flow_null_query,
};

/**
 * Select flow driver type according to flow attributes and device
 * configuration.
 *
 * @param[in] dev
 *   Pointer to the dev structure.
 * @param[in] attr
 *   Pointer to the flow attributes.
 *
 * @return
 *   flow driver type, MLX5_FLOW_TYPE_MAX otherwise.
 */
static enum mlx5_flow_drv_type
flow_get_drv_type(struct rte_eth_dev *dev, const struct rte_flow_attr *attr)
{
	struct priv *priv = dev->data->dev_private;
	enum mlx5_flow_drv_type type = MLX5_FLOW_TYPE_MAX;

	(void)attr;
	type = priv->config.dv_flow_en ? MLX5_FLOW_TYPE_DV :
					 MLX5_FLOW_TYPE_VERBS;
	return type;
}

#define flow_get_drv_ops(type) flow_drv_ops[type]

/**
 * Flow driver validation API. This abstracts calling driver specific functions.
 * The type of flow driver is determined according to flow attributes.
 *
 * @param[in] dev
 *   Pointer to the dev structure.
 * @param[in] attr
 *   Pointer to the flow attributes.
 * @param[in] items
 *   Pointer to the list of items.
 * @param[in] actions
 *   Pointer to the list of actions.
 * @param[out] error
 *   Pointer to the error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_ernno is set.
 */
static inline int
flow_drv_validate(struct rte_eth_dev *dev,
		  const struct rte_flow_attr *attr,
		  const struct rte_flow_item items[],
		  const struct rte_flow_action actions[],
		  struct rte_flow_error *error)
{
	struct priv *priv = dev->data->dev_private;
	const struct mlx5_flow_driver_ops *fops;
	enum mlx5_flow_drv_type type = flow_get_drv_type(dev, attr);

	if (attr->transfer && !priv->config.dv_eswitch_en)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ATTR,
					  NULL,
					  "transfer is not supported");
	fops = flow_get_drv_ops(type);
	return fops->validate(dev, attr, items, actions, error);
}

/**
 * Flow driver preparation API. This abstracts calling driver specific
 * functions. Parent flow (rte_flow) should have driver type (drv_type). It
 * calculates the size of memory required for device flow, allocates the memory,
 * initializes the device flow and returns the pointer.
 *
 * @note
 *   This function initializes device flow structure such as dv, or verbs in
 *   struct mlx5_flow. However, it is caller's responsibility to initialize the
 *   rest. For example, adding returning device flow to flow->dev_flow list and
 *   setting backward reference to the flow should be done out of this function.
 *   layers field is not filled either.
 *
 * @param[in] attr
 *   Pointer to the flow attributes.
 * @param[in] items
 *   Pointer to the list of items.
 * @param[in] actions
 *   Pointer to the list of actions.
 * @param[out] error
 *   Pointer to the error structure.
 *
 * @return
 *   Pointer to device flow on success, otherwise NULL and rte_ernno is set.
 */
static inline struct mlx5_flow *
flow_drv_prepare(const struct rte_flow *flow,
		 const struct rte_flow_attr *attr,
		 const struct rte_flow_item items[],
		 const struct rte_flow_action actions[],
		 struct rte_flow_error *error)
{
	const struct mlx5_flow_driver_ops *fops;
	enum mlx5_flow_drv_type type = flow->drv_type;

	assert(type > MLX5_FLOW_TYPE_MIN && type < MLX5_FLOW_TYPE_MAX);
	fops = flow_get_drv_ops(type);
	return fops->prepare(attr, items, actions, error);
}

/**
 * Flow driver translation API. This abstracts calling driver specific
 * functions. Parent flow (rte_flow) should have driver type (drv_type). It
 * translates a generic flow into a driver flow. flow_drv_prepare() must
 * precede.
 *
 * @note
 *   dev_flow->layers could be filled as a result of parsing during translation
 *   if needed by flow_drv_apply(). dev_flow->flow->actions can also be filled
 *   if necessary. As a flow can have multiple dev_flows by RSS flow expansion,
 *   flow->actions could be overwritten even though all the expanded dev_flows
 *   have the same actions.
 *
 * @param[in] dev
 *   Pointer to the rte dev structure.
 * @param[in, out] dev_flow
 *   Pointer to the mlx5 flow.
 * @param[in] attr
 *   Pointer to the flow attributes.
 * @param[in] items
 *   Pointer to the list of items.
 * @param[in] actions
 *   Pointer to the list of actions.
 * @param[out] error
 *   Pointer to the error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_ernno is set.
 */
static inline int
flow_drv_translate(struct rte_eth_dev *dev, struct mlx5_flow *dev_flow,
		   const struct rte_flow_attr *attr,
		   const struct rte_flow_item items[],
		   const struct rte_flow_action actions[],
		   struct rte_flow_error *error)
{
	const struct mlx5_flow_driver_ops *fops;
	enum mlx5_flow_drv_type type = dev_flow->flow->drv_type;

	assert(type > MLX5_FLOW_TYPE_MIN && type < MLX5_FLOW_TYPE_MAX);
	fops = flow_get_drv_ops(type);
	return fops->translate(dev, dev_flow, attr, items, actions, error);
}

/**
 * Flow driver apply API. This abstracts calling driver specific functions.
 * Parent flow (rte_flow) should have driver type (drv_type). It applies
 * translated driver flows on to device. flow_drv_translate() must precede.
 *
 * @param[in] dev
 *   Pointer to Ethernet device structure.
 * @param[in, out] flow
 *   Pointer to flow structure.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static inline int
flow_drv_apply(struct rte_eth_dev *dev, struct rte_flow *flow,
	       struct rte_flow_error *error)
{
	const struct mlx5_flow_driver_ops *fops;
	enum mlx5_flow_drv_type type = flow->drv_type;

	assert(type > MLX5_FLOW_TYPE_MIN && type < MLX5_FLOW_TYPE_MAX);
	fops = flow_get_drv_ops(type);
	return fops->apply(dev, flow, error);
}

/**
 * Flow driver remove API. This abstracts calling driver specific functions.
 * Parent flow (rte_flow) should have driver type (drv_type). It removes a flow
 * on device. All the resources of the flow should be freed by calling
 * flow_drv_destroy().
 *
 * @param[in] dev
 *   Pointer to Ethernet device.
 * @param[in, out] flow
 *   Pointer to flow structure.
 */
#ifdef RTE_LIBRTE_MLX5_FLOW_CACHE
static inline void
flow_drv_remove(struct rte_eth_dev *dev, struct rte_flow *flow)
{
	const struct mlx5_flow_driver_ops *fops;
	enum mlx5_flow_drv_type type = flow->drv_type;

	assert(type > MLX5_FLOW_TYPE_MIN && type < MLX5_FLOW_TYPE_MAX);
	fops = flow_get_drv_ops(type);
	fops->remove(dev, flow);
}
#endif

/**
 * Flow driver destroy API. This abstracts calling driver specific functions.
 * Parent flow (rte_flow) should have driver type (drv_type). It removes a flow
 * on device and releases resources of the flow.
 *
 * @param[in] dev
 *   Pointer to Ethernet device.
 * @param[in, out] flow
 *   Pointer to flow structure.
 */
static inline void
flow_drv_destroy(struct rte_eth_dev *dev, void *flow)
{
	const struct mlx5_flow_driver_ops *fops;
#ifdef RTE_LIBRTE_MLX5_FLOW_CACHE
	enum mlx5_flow_drv_type type = ((struct rte_flow *)flow)->drv_type;
#else
	enum mlx5_flow_drv_type type =
		((struct rte_flow_handle *)flow)->drv_type;
#endif
	assert(type > MLX5_FLOW_TYPE_MIN && type < MLX5_FLOW_TYPE_MAX);
	fops = flow_get_drv_ops(type);
	fops->destroy(dev, flow);
}

/**
 * Validate a flow supported by the NIC.
 *
 * @see rte_flow_validate()
 * @see rte_flow_ops
 */
int
mlx5_flow_validate(struct rte_eth_dev *dev,
		   const struct rte_flow_attr *attr,
		   const struct rte_flow_item items[],
		   const struct rte_flow_action actions[],
		   struct rte_flow_error *error)
{
	int ret;

	ret = flow_drv_validate(dev, attr, items, actions, error);
	if (ret < 0)
		return ret;
	return 0;
}

/**
 * Get requested action from the action list.
 *
 * @param[in] actions
 *   Pointer to the list of actions.
 * @param[in] type
 *   Requested action.
 *
 * @return
 *   Void pointer to the action if exist, else return NULL.
 */
const void *
mlx5_flow_get_action(const struct rte_flow_action actions[],
		     enum rte_flow_action_type type)
{
	for (; actions->type != RTE_FLOW_ACTION_TYPE_END; actions++)
		if (actions->type == type)
			return actions->conf;
	return NULL;
}

static unsigned int
find_graph_root(const struct rte_flow_item pattern[],
		const struct rte_flow_action actions[],
		uint32_t rss_level)
{
	const struct rte_flow_item *item;
	const struct rte_flow_action *action;
	unsigned int has_vlan = 0;

	for (action = actions; action->type != RTE_FLOW_ACTION_TYPE_END;
	     action++) {
		if (action->type == RTE_FLOW_ACTION_TYPE_RAW_DECAP ||
		    action->type == RTE_FLOW_ACTION_TYPE_NVGRE_DECAP ||
		    action->type == RTE_FLOW_ACTION_TYPE_VXLAN_DECAP ||
		    action->type == RTE_FLOW_ACTION_TYPE_TUNNEL_L3_DECAP) {
			rss_level = 1;
			break;
		}
	}
	for (item = pattern; item->type != RTE_FLOW_ITEM_TYPE_END; item++) {
		if (item->type == RTE_FLOW_ITEM_TYPE_VLAN) {
			has_vlan = 1;
			break;
		}
	}
	if (has_vlan)
		return rss_level < 1 ? MLX5_EXPANSION_ROOT_ETH_VLAN :
				       MLX5_EXPANSION_ROOT_OUTER_ETH_VLAN;
	return rss_level < 1 ? MLX5_EXPANSION_ROOT :
			       MLX5_EXPANSION_ROOT_OUTER;
}

/**
 * Create a flow and add it to @p list.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param list
 *   Pointer to a TAILQ flow list.
 * @param[in] attr
 *   Flow rule attributes.
 * @param[in] items
 *   Pattern specification (list terminated by the END pattern item).
 * @param[in] actions
 *   Associated actions (list terminated by the END action).
 * @param[out] error
 *   Perform verbose error reporting if not NULL.
 *
 * @return
 *   A flow on success, NULL otherwise and rte_errno is set.
 */
static struct rte_flow *
flow_list_create(struct rte_eth_dev *dev, struct mlx5_flows *list,
		 const struct rte_flow_attr *attr,
		 const struct rte_flow_item items[],
		 const struct rte_flow_action actions[],
		 struct rte_flow_error *error)
{
	struct rte_flow *flow = NULL;
	struct mlx5_flow *dev_flow;
	const struct rte_flow_action_rss *rss;
	union {
		struct rte_flow_expand_rss buf;
		uint8_t buffer[2048];
	} expand_buffer;
	struct rte_flow_expand_rss *buf = &expand_buffer.buf;
	int ret;
	uint32_t i;
	uint32_t flow_size;
	uint32_t queue_size;
	uint16_t queue_num;
#ifndef RTE_LIBRTE_MLX5_FLOW_CACHE
	struct mlx5_flow_handle *temp_handle;
#endif

	ret = flow_drv_validate(dev, attr, items, actions, error);
	if (ret < 0)
		return NULL;
	rss = (const struct rte_flow_action_rss *)
		mlx5_flow_get_action(actions, RTE_FLOW_ACTION_TYPE_RSS);
	if (rss) {
		queue_size = RTE_ALIGN_CEIL(rss->num * sizeof(uint16_t),
					    sizeof(void *));
		queue_num = rss->num;
	} else {
		queue_size = RTE_ALIGN_CEIL(sizeof(uint16_t), sizeof(void *));
		queue_num = 1;
	}
#ifdef RTE_LIBRTE_MLX5_FLOW_CACHE
	flow_size = sizeof(struct rte_flow);
	flow = rte_calloc(__func__, 1, flow_size + queue_size, 0);
	flow->port = dev->data->port_id;
#else
	if (!gflow) {
		flow_size = sizeof(struct rte_flow) +
			RTE_ALIGN_CEIL(MLX5_MAX_RSS_QUEUES * sizeof(uint16_t),
				       sizeof(void *));
		gflow = rte_calloc(__func__, 1, flow_size, 0);
		gflow_size = flow_size;
		LIST_INIT(&gflow->dev_flows);
	} else 
	  	memset(gflow, 0, gflow_size);
	flow = gflow;
#endif
	if (!flow) {
		rte_flow_error_set(error, ENOMEM,
				   RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
				   "Unable to allocate memory.");
		return NULL;
	}
	flow->handle = rte_calloc(__func__, 1, sizeof(struct rte_flow_handle) +
				  queue_size, 0);
	if (!flow->handle) {
#ifdef RTE_LIBRTE_MLX5_FLOW_CACHE
		rte_free(flow);
#endif
		rte_flow_error_set(error, ENOMEM,
				   RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
				   "Unable to allocate memory.");
		return NULL;
	}
	flow->drv_type = flow_get_drv_type(dev, attr);
	flow->handle->drv_type = flow->drv_type;
	assert(flow->drv_type > MLX5_FLOW_TYPE_MIN &&
	       flow->drv_type < MLX5_FLOW_TYPE_MAX);
	flow->queue = (void *)(flow + 1);
	flow->handle->queue = (void *)(flow->handle + 1);
	flow->handle->queue_num = queue_num;
	flow->transfer = attr->transfer;
#ifdef RTE_LIBRTE_MLX5_FLOW_CACHE
	LIST_INIT(&flow->dev_flows);
#else
	flow->handle->dev_handles = NULL;
#endif
	if (rss && rss->rss_conf->rss_hf) {
		unsigned int graph_root;

		graph_root = find_graph_root(items, actions,
					     rss->rss_conf->rss_level);
		ret = rte_flow_expand_rss(buf, sizeof(expand_buffer.buffer),
					  items, rss->rss_conf->rss_hf,
					  mlx5_support_expansion,
					  graph_root);
		assert(ret > 0 &&
		       (unsigned int)ret < sizeof(expand_buffer.buffer));
	} else {
		buf->entries = 1;
		buf->entry[0].pattern = (void *)(uintptr_t)items;
	}
	for (i = 0; i < buf->entries; ++i) {
		dev_flow = flow_drv_prepare(flow, attr, buf->entry[i].pattern,
					    actions, error);
		if (!dev_flow)
			goto error;
		dev_flow->flow = flow;
		LIST_INSERT_HEAD(&flow->dev_flows, dev_flow, next);
#ifdef RTE_LIBRTE_MLX5_FLOW_CACHE
#else
		temp_handle = flow->handle->dev_handles;
		if (flow->drv_type == MLX5_FLOW_TYPE_DV) {
			flow->handle->dev_handles = dev_flow->dv.handle;
			dev_flow->dv.handle->next = temp_handle;
		}
#endif
		ret = flow_drv_translate(dev, dev_flow, attr,
					 buf->entry[i].pattern,
					 actions, error);
		if (ret < 0)
			goto error;
#ifdef RTE_LIBRTE_MLX5_FLOW_CACHE
#else
		if (dev->data->dev_started) {
			ret = flow_drv_apply(dev, flow, error);
			if (ret < 0)
				goto error;
			LIST_REMOVE(dev_flow, next);
		} else {
			rte_flow_error_set(error, EPERM,
				   RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
				   "Device must be started.");
			goto error;
		}
#endif
	}
#ifdef RTE_LIBRTE_MLX5_FLOW_CACHE
	if (dev->data->dev_started) {
		ret = flow_drv_apply(dev, flow, error);
		if (ret < 0)
			goto error;
	}
#endif
	flow_rxq_flags_set(dev, flow);
#ifdef RTE_LIBRTE_MLX5_FLOW_CACHE
	TAILQ_INSERT_TAIL(list, flow, next);
	return flow;
#else
	if (flow->drv_type == MLX5_FLOW_TYPE_DV) {
		TAILQ_INSERT_TAIL(list, flow->handle, next);
		return (struct rte_flow*)flow->handle;
	} else {
		TAILQ_INSERT_TAIL(list, (struct rte_flow_handle *)flow, next);
		return flow;
	}
#endif
error:
	ret = rte_errno; /* Save rte_errno before cleanup. */
	assert(flow);
#ifdef RTE_LIBRTE_MLX5_FLOW_CACHE
	flow_drv_destroy(dev, flow);
#else
	flow_drv_destroy(dev, flow->handle);
#endif
	rte_free(flow->handle);
#ifdef RTE_LIBRTE_MLX5_FLOW_CACHE
	rte_free(flow);
#endif
	rte_errno = ret; /* Restore rte_errno. */
	return NULL;
}

/**
 * Create a flow.
 *
 * @see rte_flow_create()
 * @see rte_flow_ops
 */
struct rte_flow *
mlx5_flow_create(struct rte_eth_dev *dev,
		 const struct rte_flow_attr *attr,
		 const struct rte_flow_item items[],
		 const struct rte_flow_action actions[],
		 struct rte_flow_error *error)
{
	return flow_list_create(dev,
				&((struct priv *)dev->data->dev_private)->flows,
				attr, items, actions, error);
}

/**
 * Destroy a flow in a list.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param list
 *   Pointer to a TAILQ flow list.
 * @param[in] flow
 *   Flow to destroy.
 */
static void
flow_list_destroy(struct rte_eth_dev *dev, struct mlx5_flows *list,
		  void *flow)
{
#ifdef RTE_LIBRTE_MLX5_FLOW_CACHE
	assert(((struct rte_flow *)flow)->port == dev->data->port_id);
	/*
	 * Update RX queue flags only if port is started, otherwise it is
	 * already clean.
	 */
	if (dev->data->dev_started)
		flow_rxq_flags_trim(dev, (struct rte_flow *)flow);
#else
	flow_rxq_flags_trim_handle(dev, (struct rte_flow_handle *)flow);
#endif
	flow_drv_destroy(dev, flow);
#ifdef RTE_LIBRTE_MLX5_FLOW_CACHE
	struct rte_flow *f = (struct rte_flow *)flow;
	TAILQ_REMOVE(list, (struct rte_flow *)flow, next);
	rte_free(f->fdir);
	rte_free(f->handle);
#else
	TAILQ_REMOVE(list, (struct rte_flow_handle *)flow, next);
#endif
	rte_free(flow);
}

/**
 * Destroy all flows.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param list
 *   Pointer to a TAILQ flow list.
 */
void
mlx5_flow_list_flush(struct rte_eth_dev *dev, struct mlx5_flows *list)
{
	while (!TAILQ_EMPTY(list)) {
#ifdef RTE_LIBRTE_MLX5_FLOW_CACHE
		struct rte_flow *flow;
#else
		struct rte_flow_handle *flow;
#endif

		flow = TAILQ_FIRST(list);
		flow_list_destroy(dev, list, flow);
	}
}

/**
 * Remove all flows.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param list
 *   Pointer to a TAILQ flow list.
 */
void
mlx5_flow_stop(struct rte_eth_dev *dev,
	       struct mlx5_flows *list __rte_unused)
{
#ifdef RTE_LIBRTE_MLX5_FLOW_CACHE
	struct rte_flow *flow;

	TAILQ_FOREACH(flow, list, next)
		flow_drv_remove(dev, flow);
#endif
	flow_rxq_flags_clear(dev);
}

/**
 * Add all flows.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param list
 *   Pointer to a TAILQ flow list.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_flow_start(struct rte_eth_dev *dev __rte_unused,
		struct mlx5_flows *list __rte_unused)
{
#ifdef RTE_LIBRTE_MLX5_FLOW_CACHE
	struct rte_flow *flow;
	struct rte_flow_error error;
	int ret = 0;

	TAILQ_FOREACH(flow, list, next) {
		ret = flow_drv_apply(dev, flow, &error);
		if (ret < 0)
			goto error;
		flow_rxq_flags_set(dev, flow);
	}
	return 0;
error:
	ret = rte_errno; /* Save rte_errno before cleanup. */
	mlx5_flow_stop(dev, list);
	rte_errno = ret; /* Restore rte_errno. */
	return -rte_errno;
#endif
	return 0;	
}

/**
 * Verify the flow list is empty
 *
 * @param dev
 *  Pointer to Ethernet device.
 *
 * @return the number of flows not released.
 */
int
mlx5_flow_verify(struct rte_eth_dev *dev)
{
	struct priv *priv = dev->data->dev_private;
#ifdef RTE_LIBRTE_MLX5_FLOW_CACHE
	struct rte_flow *flow;
#else
	struct rte_flow_handle *flow;
#endif
	int ret = 0;

	TAILQ_FOREACH(flow, &priv->flows, next) {
		DRV_LOG(DEBUG, "port %u flow %p still referenced",
			dev->data->port_id, (void *)flow);
		++ret;
	}
	return ret;
}

/**
 * Enable a control flow configured from the control plane.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param eth_spec
 *   An Ethernet flow spec to apply.
 * @param eth_mask
 *   An Ethernet flow mask to apply.
 * @param vlan_spec
 *   A VLAN flow spec to apply.
 * @param vlan_mask
 *   A VLAN flow mask to apply.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_ctrl_flow_vlan(struct rte_eth_dev *dev,
		    struct rte_flow_item_eth *eth_spec,
		    struct rte_flow_item_eth *eth_mask,
		    struct rte_flow_item_vlan *vlan_spec,
		    struct rte_flow_item_vlan *vlan_mask)
{
	struct priv *priv = dev->data->dev_private;
	const struct rte_flow_attr attr = {
		.ingress = 1,
		.priority = MLX5_FLOW_PRIO_RSVD,
	};
	struct rte_flow_item items[] = {
		{
			.type = RTE_FLOW_ITEM_TYPE_ETH,
			.spec = eth_spec,
			.last = NULL,
			.mask = eth_mask,
		},
		{
			.type = (vlan_spec) ? RTE_FLOW_ITEM_TYPE_VLAN :
					      RTE_FLOW_ITEM_TYPE_END,
			.spec = vlan_spec,
			.last = NULL,
			.mask = vlan_mask,
		},
		{
			.type = RTE_FLOW_ITEM_TYPE_END,
		},
	};
	struct rte_eth_rss_conf rss_conf = {
		.rss_key = priv->rss_conf.rss_key,
		.rss_key_len = priv->rss_conf.rss_key_len,
		.rss_level = 0,
		.rss_hf = priv->rss_conf.rss_hf,
	};
	struct rte_flow_action_rss *action_rss;
	struct rte_flow_action actions[2];
	struct rte_flow *flow;
	struct rte_flow_error error;
	unsigned int i;

	if (!priv->reta_idx_n) {
		rte_errno = EINVAL;
		return -rte_errno;
	}
	action_rss = malloc(sizeof(*action_rss) +
			    sizeof(*action_rss->queue) * priv->reta_idx_n);
	action_rss->rss_conf = &rss_conf;
	action_rss->num = priv->reta_idx_n;
	for (i = 0; i != priv->reta_idx_n; ++i)
		action_rss->queue[i] = (*priv->reta_idx)[i];
	actions[0].type = RTE_FLOW_ACTION_TYPE_RSS;
	actions[0].conf = action_rss;
	actions[1].type = RTE_FLOW_ACTION_TYPE_END;
	flow = flow_list_create(dev, &priv->ctrl_flows,
				&attr, items, actions, &error);
	free(action_rss);
	if (!flow) {
		DRV_LOG(DEBUG,
			"Failed to create ctrl flow: rte_errno(%d),"
			" type(%d), message(%s)\n",
			rte_errno, error.type,
			error.message ? error.message : " (no stated reason)");
		return -rte_errno;
	}
	return 0;
}

/**
 * Enable a flow control configured from the control plane.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param eth_spec
 *   An Ethernet flow spec to apply.
 * @param eth_mask
 *   An Ethernet flow mask to apply.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_ctrl_flow(struct rte_eth_dev *dev,
	       struct rte_flow_item_eth *eth_spec,
	       struct rte_flow_item_eth *eth_mask)
{
	return mlx5_ctrl_flow_vlan(dev, eth_spec, eth_mask, NULL, NULL);
}

/**
 * Destroy a flow.
 *
 * @see rte_flow_destroy()
 * @see rte_flow_ops
 */
int
mlx5_flow_destroy(struct rte_eth_dev *dev,
		  struct rte_flow *flow,
		  struct rte_flow_error *error __rte_unused)
{
	struct priv *priv = dev->data->dev_private;

	flow_list_destroy(dev, &priv->flows, flow);
	return 0;
}

/**
 * Destroy all flows.
 *
 * @see rte_flow_flush()
 * @see rte_flow_ops
 */
int
mlx5_flow_flush(struct rte_eth_dev *dev,
		struct rte_flow_error *error __rte_unused)
{
	struct priv *priv = dev->data->dev_private;

	mlx5_flow_list_flush(dev, &priv->flows);
	return 0;
}

/**
 * Isolated mode.
 *
 * @see rte_flow_isolate()
 * @see rte_flow_ops
 */
int
mlx5_flow_isolate(struct rte_eth_dev *dev,
		  int enable,
		  struct rte_flow_error *error)
{
	struct priv *priv = dev->data->dev_private;

	if (dev->data->dev_started) {
		rte_flow_error_set(error, EBUSY,
				   RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   NULL,
				   "port must be stopped first");
		return -rte_errno;
	}
	priv->isolated = !!enable;
	if (enable)
		dev->dev_ops = &mlx5_dev_ops_isolate;
	else
		dev->dev_ops = &mlx5_dev_ops;
	return 0;
}

/**
 * Query a flow.
 *
 * @see rte_flow_query()
 * @see rte_flow_ops
 */
static int
flow_drv_query(struct rte_eth_dev *dev,
	       struct rte_flow *flow,
	       const struct rte_flow_action *actions,
	       void *data,
	       struct rte_flow_error *error)
{
	const struct mlx5_flow_driver_ops *fops;
	enum mlx5_flow_drv_type ftype = flow->drv_type;

	assert(ftype > MLX5_FLOW_TYPE_MIN && ftype < MLX5_FLOW_TYPE_MAX);
	fops = flow_get_drv_ops(ftype);

	return fops->query(dev, flow, actions, data, error);
}

/**
 * Query a flow.
 *
 * @see rte_flow_query()
 * @see rte_flow_ops
 */
int
mlx5_flow_query(struct rte_eth_dev *dev,
		struct rte_flow *flow,
		const struct rte_flow_action *actions,
		void *data,
		struct rte_flow_error *error)
{
	int ret;

	ret = flow_drv_query(dev, flow, actions, data, error);
	if (ret < 0)
		return ret;
	return 0;
}

/**
 * Legacy method of flow query.
 *
 * @see rte_flow_query()
 * @see rte_flow_ops
 */
int
mlx5_flow_query_legacy(struct rte_eth_dev *dev,
		       struct rte_flow *flow,
		       enum rte_flow_action_type type,
		       void *data,
		       struct rte_flow_error *error)
{
	struct rte_flow_action actions[] = {
		{ .type = type },
		{ .type = RTE_FLOW_ACTION_TYPE_END },
	};

	return mlx5_flow_query(dev, flow, actions, data, error);
}

static void *
mlx5_flow_counter_alloc(struct rte_eth_dev *dev, uint32_t *start_index,
			uint32_t *blk_sz, struct rte_flow_error *error)
{
	return (void *)mlx5_flow_dv_drv_ops.counter_alloc
		(dev, start_index, blk_sz, error);
}

static int
mlx5_flow_counter_free(struct rte_eth_dev *dev, void *obj,
		       struct rte_flow_error *error __rte_unused)
{
	return mlx5_flow_dv_drv_ops.counter_free(dev, obj);
}

rte_flow_cb_fn mlx5_flow_batch_async_callback;

static int
mlx5_flow_counter_query(struct rte_eth_dev *dev,
			int counter_id, void *counter_obj, uint32_t count,
			struct rte_flow_count_value *buf, int buf_count,
			rte_flow_cb_fn cb, void *cb_arg,
			struct rte_flow_error *error)
{
	return mlx5_flow_dv_drv_ops.counter_query(dev, counter_id, counter_obj,
						  count, buf, buf_count,
						  cb, cb_arg, error);
}

static int
mlx5_flow_sync(struct rte_eth_dev *dev, struct rte_flow_error *error)
{
	return mlx5_flow_dv_drv_ops.sync(dev, error);
}

/**
 * Convert a flow director filter to a generic flow.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param fdir_filter
 *   Flow director filter to add.
 * @param attributes
 *   Generic flow parameters structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
flow_fdir_filter_convert(struct rte_eth_dev *dev,
			 const struct rte_eth_fdir_filter *fdir_filter,
			 struct mlx5_fdir *attributes)
{
	struct priv *priv = dev->data->dev_private;
	const struct rte_eth_fdir_input *input = &fdir_filter->input;
	const struct rte_eth_fdir_masks *mask =
		&dev->data->dev_conf.fdir_conf.mask;

	/* Validate queue number. */
	if (fdir_filter->action.rx_queue >= priv->rxqs_n) {
		DRV_LOG(ERR, "port %u invalid queue number %d",
			dev->data->port_id, fdir_filter->action.rx_queue);
		rte_errno = EINVAL;
		return -rte_errno;
	}
	attributes->attr.ingress = 1;
	attributes->items[0] = (struct rte_flow_item) {
		.type = RTE_FLOW_ITEM_TYPE_ETH,
		.spec = &attributes->l2,
		.mask = &attributes->l2_mask,
	};
	switch (fdir_filter->action.behavior) {
	case RTE_ETH_FDIR_ACCEPT:
		attributes->actions[0] = (struct rte_flow_action){
			.type = RTE_FLOW_ACTION_TYPE_QUEUE,
			.conf = &attributes->queue,
		};
		break;
	case RTE_ETH_FDIR_REJECT:
		attributes->actions[0] = (struct rte_flow_action){
			.type = RTE_FLOW_ACTION_TYPE_DROP,
		};
		break;
	default:
		DRV_LOG(ERR, "port %u invalid behavior %d",
			dev->data->port_id,
			fdir_filter->action.behavior);
		rte_errno = ENOTSUP;
		return -rte_errno;
	}
	attributes->queue.index = fdir_filter->action.rx_queue;
	/* Handle L3. */
	switch (fdir_filter->input.flow_type) {
	case RTE_ETH_FLOW_NONFRAG_IPV4_UDP:
	case RTE_ETH_FLOW_NONFRAG_IPV4_TCP:
	case RTE_ETH_FLOW_NONFRAG_IPV4_OTHER:
		attributes->l3.ipv4.hdr = (struct ipv4_hdr){
			.src_addr = input->flow.ip4_flow.src_ip,
			.dst_addr = input->flow.ip4_flow.dst_ip,
			.time_to_live = input->flow.ip4_flow.ttl,
			.type_of_service = input->flow.ip4_flow.tos,
		};
		attributes->l3_mask.ipv4.hdr = (struct ipv4_hdr){
			.src_addr = mask->ipv4_mask.src_ip,
			.dst_addr = mask->ipv4_mask.dst_ip,
			.time_to_live = mask->ipv4_mask.ttl,
			.type_of_service = mask->ipv4_mask.tos,
			.next_proto_id = mask->ipv4_mask.proto,
		};
		attributes->items[1] = (struct rte_flow_item){
			.type = RTE_FLOW_ITEM_TYPE_IPV4,
			.spec = &attributes->l3,
			.mask = &attributes->l3_mask,
		};
		break;
	case RTE_ETH_FLOW_NONFRAG_IPV6_UDP:
	case RTE_ETH_FLOW_NONFRAG_IPV6_TCP:
	case RTE_ETH_FLOW_NONFRAG_IPV6_OTHER:
		attributes->l3.ipv6.hdr = (struct ipv6_hdr){
			.hop_limits = input->flow.ipv6_flow.hop_limits,
			.proto = input->flow.ipv6_flow.proto,
		};

		memcpy(attributes->l3.ipv6.hdr.src_addr,
		       input->flow.ipv6_flow.src_ip,
		       RTE_DIM(attributes->l3.ipv6.hdr.src_addr));
		memcpy(attributes->l3.ipv6.hdr.dst_addr,
		       input->flow.ipv6_flow.dst_ip,
		       RTE_DIM(attributes->l3.ipv6.hdr.src_addr));
		memcpy(attributes->l3_mask.ipv6.hdr.src_addr,
		       mask->ipv6_mask.src_ip,
		       RTE_DIM(attributes->l3_mask.ipv6.hdr.src_addr));
		memcpy(attributes->l3_mask.ipv6.hdr.dst_addr,
		       mask->ipv6_mask.dst_ip,
		       RTE_DIM(attributes->l3_mask.ipv6.hdr.src_addr));
		attributes->items[1] = (struct rte_flow_item){
			.type = RTE_FLOW_ITEM_TYPE_IPV6,
			.spec = &attributes->l3,
			.mask = &attributes->l3_mask,
		};
		break;
	default:
		DRV_LOG(ERR, "port %u invalid flow type%d",
			dev->data->port_id, fdir_filter->input.flow_type);
		rte_errno = ENOTSUP;
		return -rte_errno;
	}
	/* Handle L4. */
	switch (fdir_filter->input.flow_type) {
	case RTE_ETH_FLOW_NONFRAG_IPV4_UDP:
		attributes->l4.udp.hdr = (struct udp_hdr){
			.src_port = input->flow.udp4_flow.src_port,
			.dst_port = input->flow.udp4_flow.dst_port,
		};
		attributes->l4_mask.udp.hdr = (struct udp_hdr){
			.src_port = mask->src_port_mask,
			.dst_port = mask->dst_port_mask,
		};
		attributes->items[2] = (struct rte_flow_item){
			.type = RTE_FLOW_ITEM_TYPE_UDP,
			.spec = &attributes->l4,
			.mask = &attributes->l4_mask,
		};
		break;
	case RTE_ETH_FLOW_NONFRAG_IPV4_TCP:
		attributes->l4.tcp.hdr = (struct tcp_hdr){
			.src_port = input->flow.tcp4_flow.src_port,
			.dst_port = input->flow.tcp4_flow.dst_port,
		};
		attributes->l4_mask.tcp.hdr = (struct tcp_hdr){
			.src_port = mask->src_port_mask,
			.dst_port = mask->dst_port_mask,
		};
		attributes->items[2] = (struct rte_flow_item){
			.type = RTE_FLOW_ITEM_TYPE_TCP,
			.spec = &attributes->l4,
			.mask = &attributes->l4_mask,
		};
		break;
	case RTE_ETH_FLOW_NONFRAG_IPV6_UDP:
		attributes->l4.udp.hdr = (struct udp_hdr){
			.src_port = input->flow.udp6_flow.src_port,
			.dst_port = input->flow.udp6_flow.dst_port,
		};
		attributes->l4_mask.udp.hdr = (struct udp_hdr){
			.src_port = mask->src_port_mask,
			.dst_port = mask->dst_port_mask,
		};
		attributes->items[2] = (struct rte_flow_item){
			.type = RTE_FLOW_ITEM_TYPE_UDP,
			.spec = &attributes->l4,
			.mask = &attributes->l4_mask,
		};
		break;
	case RTE_ETH_FLOW_NONFRAG_IPV6_TCP:
		attributes->l4.tcp.hdr = (struct tcp_hdr){
			.src_port = input->flow.tcp6_flow.src_port,
			.dst_port = input->flow.tcp6_flow.dst_port,
		};
		attributes->l4_mask.tcp.hdr = (struct tcp_hdr){
			.src_port = mask->src_port_mask,
			.dst_port = mask->dst_port_mask,
		};
		attributes->items[2] = (struct rte_flow_item){
			.type = RTE_FLOW_ITEM_TYPE_TCP,
			.spec = &attributes->l4,
			.mask = &attributes->l4_mask,
		};
		break;
	case RTE_ETH_FLOW_NONFRAG_IPV4_OTHER:
	case RTE_ETH_FLOW_NONFRAG_IPV6_OTHER:
		break;
	default:
		DRV_LOG(ERR, "port %u invalid flow type%d",
			dev->data->port_id, fdir_filter->input.flow_type);
		rte_errno = ENOTSUP;
		return -rte_errno;
	}
	return 0;
}

#define FLOW_FDIR_CMP(f1, f2, fld) \
	memcmp(&(f1)->fld, &(f2)->fld, sizeof((f1)->fld))

/**
 * Compare two FDIR flows. If items and actions are identical, the two flows are
 * regarded as same.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param f1
 *   FDIR flow to compare.
 * @param f2
 *   FDIR flow to compare.
 *
 * @return
 *   Zero on match, 1 otherwise.
 */
#ifdef RTE_LIBRTE_MLX5_FLOW_CACHE
static int
flow_fdir_cmp(const struct mlx5_fdir *f1, const struct mlx5_fdir *f2)
{
	if (FLOW_FDIR_CMP(f1, f2, attr) ||
	    FLOW_FDIR_CMP(f1, f2, l2) ||
	    FLOW_FDIR_CMP(f1, f2, l2_mask) ||
	    FLOW_FDIR_CMP(f1, f2, l3) ||
	    FLOW_FDIR_CMP(f1, f2, l3_mask) ||
	    FLOW_FDIR_CMP(f1, f2, l4) ||
	    FLOW_FDIR_CMP(f1, f2, l4_mask) ||
	    FLOW_FDIR_CMP(f1, f2, actions[0].type))
		return 1;
	if (f1->actions[0].type == RTE_FLOW_ACTION_TYPE_QUEUE &&
	    FLOW_FDIR_CMP(f1, f2, queue))
		return 1;
	return 0;
}
#endif

/**
 * Search device flow list to find out a matched FDIR flow.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param fdir_flow
 *   FDIR flow to lookup.
 *
 * @return
 *   Pointer of flow if found, NULL otherwise.
 */
static struct rte_flow *
flow_fdir_filter_lookup(struct rte_eth_dev *dev __rte_unused,
			struct mlx5_fdir *fdir_flow __rte_unused)
{
#ifdef RTE_LIBRTE_MLX5_FLOW_CACHE
	struct priv *priv = dev->data->dev_private;
	struct rte_flow *flow = NULL;

	assert(fdir_flow);
	TAILQ_FOREACH(flow, &priv->flows, next) {
		if (flow->fdir && !flow_fdir_cmp(flow->fdir, fdir_flow)) {
			DRV_LOG(DEBUG, "port %u found FDIR flow %p",
				dev->data->port_id, (void *)flow);
			break;
		}
	}
	return flow;
#endif
	return NULL;
}

/**
 * Add new flow director filter and store it in list.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param fdir_filter
 *   Flow director filter to add.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
flow_fdir_filter_add(struct rte_eth_dev *dev,
		     const struct rte_eth_fdir_filter *fdir_filter)
{
	struct priv *priv = dev->data->dev_private;
	struct mlx5_fdir *fdir_flow;
	struct rte_flow *flow;
	int ret;

	fdir_flow = rte_zmalloc(__func__, sizeof(*fdir_flow), 0);
	if (!fdir_flow) {
		rte_errno = ENOMEM;
		return -rte_errno;
	}
	ret = flow_fdir_filter_convert(dev, fdir_filter, fdir_flow);
	if (ret)
		goto error;
	flow = flow_fdir_filter_lookup(dev, fdir_flow);
	if (flow) {
		rte_errno = EEXIST;
		goto error;
	}
	flow = flow_list_create(dev, &priv->flows, &fdir_flow->attr,
				fdir_flow->items, fdir_flow->actions, NULL);
	if (!flow)
		goto error;
	assert(!flow->fdir);
	flow->fdir = fdir_flow;
	DRV_LOG(DEBUG, "port %u created FDIR flow %p",
		dev->data->port_id, (void *)flow);
	return 0;
error:
	rte_free(fdir_flow);
	return -rte_errno;
}

/**
 * Delete specific filter.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param fdir_filter
 *   Filter to be deleted.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
flow_fdir_filter_delete(struct rte_eth_dev *dev,
			const struct rte_eth_fdir_filter *fdir_filter)
{
	struct priv *priv = dev->data->dev_private;
	struct rte_flow *flow;
	struct mlx5_fdir fdir_flow = {
		.attr.group = 0,
	};
	int ret;

	ret = flow_fdir_filter_convert(dev, fdir_filter, &fdir_flow);
	if (ret)
		return -rte_errno;
	flow = flow_fdir_filter_lookup(dev, &fdir_flow);
	if (!flow) {
		rte_errno = ENOENT;
		return -rte_errno;
	}
	flow_list_destroy(dev, &priv->flows, flow);
	DRV_LOG(DEBUG, "port %u deleted FDIR flow %p",
		dev->data->port_id, (void *)flow);
	return 0;
}

/**
 * Update queue for specific filter.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param fdir_filter
 *   Filter to be updated.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
flow_fdir_filter_update(struct rte_eth_dev *dev,
			const struct rte_eth_fdir_filter *fdir_filter)
{
	int ret;

	ret = flow_fdir_filter_delete(dev, fdir_filter);
	if (ret)
		return ret;
	return flow_fdir_filter_add(dev, fdir_filter);
}

/**
 * Flush all filters.
 *
 * @param dev
 *   Pointer to Ethernet device.
 */
static void
flow_fdir_filter_flush(struct rte_eth_dev *dev)
{
	struct priv *priv = dev->data->dev_private;

	mlx5_flow_list_flush(dev, &priv->flows);
}

/**
 * Get flow director information.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param[out] fdir_info
 *   Resulting flow director information.
 */
static void
flow_fdir_info_get(struct rte_eth_dev *dev, struct rte_eth_fdir_info *fdir_info)
{
	struct rte_eth_fdir_masks *mask =
		&dev->data->dev_conf.fdir_conf.mask;

	fdir_info->mode = dev->data->dev_conf.fdir_conf.mode;
	fdir_info->guarant_spc = 0;
	rte_memcpy(&fdir_info->mask, mask, sizeof(fdir_info->mask));
	fdir_info->max_flexpayload = 0;
	fdir_info->flow_types_mask[0] = 0;
	fdir_info->flex_payload_unit = 0;
	fdir_info->max_flex_payload_segment_num = 0;
	fdir_info->flex_payload_limit = 0;
	memset(&fdir_info->flex_conf, 0, sizeof(fdir_info->flex_conf));
}

/**
 * Deal with flow director operations.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param filter_op
 *   Operation to perform.
 * @param arg
 *   Pointer to operation-specific structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
flow_fdir_ctrl_func(struct rte_eth_dev *dev, enum rte_filter_op filter_op,
		    void *arg)
{
	enum rte_fdir_mode fdir_mode =
		dev->data->dev_conf.fdir_conf.mode;

	if (filter_op == RTE_ETH_FILTER_NOP)
		return 0;
	if (fdir_mode != RTE_FDIR_MODE_PERFECT &&
	    fdir_mode != RTE_FDIR_MODE_PERFECT_MAC_VLAN) {
		DRV_LOG(ERR, "port %u flow director mode %d not supported",
			dev->data->port_id, fdir_mode);
		rte_errno = EINVAL;
		return -rte_errno;
	}
	switch (filter_op) {
	case RTE_ETH_FILTER_ADD:
		return flow_fdir_filter_add(dev, arg);
	case RTE_ETH_FILTER_UPDATE:
		return flow_fdir_filter_update(dev, arg);
	case RTE_ETH_FILTER_DELETE:
		return flow_fdir_filter_delete(dev, arg);
	case RTE_ETH_FILTER_FLUSH:
		flow_fdir_filter_flush(dev);
		break;
	case RTE_ETH_FILTER_INFO:
		flow_fdir_info_get(dev, arg);
		break;
	default:
		DRV_LOG(DEBUG, "port %u unknown operation %u",
			dev->data->port_id, filter_op);
		rte_errno = EINVAL;
		return -rte_errno;
	}
	return 0;
}

static const struct rte_flow_ops mlx5_flow_ops = {
	.validate = mlx5_flow_validate,
	.create = mlx5_flow_create,
	.destroy = mlx5_flow_destroy,
	.flush = mlx5_flow_flush,
	.isolate = mlx5_flow_isolate,
	.query = mlx5_flow_query_legacy,
	._query = mlx5_flow_query,
	.counter_alloc = mlx5_flow_counter_alloc,
	.counter_free = mlx5_flow_counter_free,
	.counter_query = mlx5_flow_counter_query,
	.sync = mlx5_flow_sync,
};

/**
 * Manage filter operations.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param filter_type
 *   Filter type.
 * @param filter_op
 *   Operation to perform.
 * @param arg
 *   Pointer to operation-specific structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_dev_filter_ctrl(struct rte_eth_dev *dev,
		     enum rte_filter_type filter_type,
		     enum rte_filter_op filter_op,
		     void *arg)
{
	switch (filter_type) {
	case RTE_ETH_FILTER_GENERIC:
		if (filter_op != RTE_ETH_FILTER_GET) {
			rte_errno = EINVAL;
			return -rte_errno;
		}
		*(const void **)arg = &mlx5_flow_ops;
		return 0;
	case RTE_ETH_FILTER_FDIR:
		return flow_fdir_ctrl_func(dev, filter_op, arg);
	default:
		DRV_LOG(ERR, "port %u filter type (%d) not supported",
			dev->data->port_id, filter_type);
		rte_errno = ENOTSUP;
		return -rte_errno;
	}
	return 0;
}

struct mlx5_meter_tbls_dv *
mlx5_flow_create_mtr_tbls(struct rte_eth_dev *dev,
			  const struct mlx5_flow_meter *fm)
{
	const struct rte_flow_attr attr	= {.transfer = 0, };

	if (flow_get_drv_type(dev, &attr) == MLX5_FLOW_TYPE_DV)
		return mlx5_flow_dv_drv_ops.create_mtr_tbls(dev, fm);

	DRV_LOG(ERR,
		"port %u flow metering is not supported", dev->data->port_id);
	rte_errno = ENOTSUP;
	return NULL;
}

int
mlx5_flow_destroy_mtr_tbls(struct rte_eth_dev *dev,
			   struct mlx5_meter_tbls_dv *tbls)
{
	struct rte_flow_attr attr = { .transfer = 0 };

	if (!tbls)
		return 0;
	if (flow_get_drv_type(dev, &attr) == MLX5_FLOW_TYPE_DV)
		return mlx5_flow_dv_drv_ops.destroy_mtr_tbls(dev, tbls);
	return 0;
}

int
mlx5_flow_create_policer_rules(struct rte_eth_dev *dev,
			       struct mlx5_flow_meter *fm,
			       const struct rte_flow_attr *attr)
{
	if (flow_get_drv_type(dev, attr) == MLX5_FLOW_TYPE_DV)
		return mlx5_flow_dv_drv_ops.create_policer_rules(dev, fm, attr);
	DRV_LOG(ERR,
		"port %u flow policing is not supported", dev->data->port_id);
	return -ENOTSUP;
}

int
mlx5_flow_destroy_policer_rules(struct rte_eth_dev *dev,
				struct mlx5_flow_meter *fm,
				const struct rte_flow_attr *attr)
{
	if (flow_get_drv_type(dev, attr) == MLX5_FLOW_TYPE_DV)
		return mlx5_flow_dv_drv_ops.destroy_policer_rules
							(dev, fm, attr);
	DRV_LOG(ERR,
		"port %u flow policing is not supported", dev->data->port_id);
	return -ENOTSUP;
}
