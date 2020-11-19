// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2018 Mellanox Technologies, Ltd
 */

#include <sys/queue.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

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

#include <rte_common.h>
#include <rte_ether.h>
#include <rte_eth_ctrl.h>
#include <rte_ethdev_driver.h>
#include <rte_flow.h>
#include <rte_flow_driver.h>
#include <rte_malloc.h>
#include <rte_ip.h>
#include <rte_gre.h>

#include "mlx5.h"
#include "mlx5_defs.h"
#include "mlx5_prm.h"
#include "mlx5_glue.h"
#include "mlx5_flow.h"

#ifdef HAVE_IBV_FLOW_DV_SUPPORT

struct mlx5_flow_handle {
	struct mlx5_flow_handle *next;
	/**< pointer to the next handle. must be first */
	uint8_t drv_type; 
	/**< The driver type must be second. */
	uint64_t actions; /**< The actions connected to the flow. */
	struct mlx5_hrxq *hrxq; /**< Hash Rx queues. */
	/* Flow DV api: */
	struct mlx5_flow_dv_matcher *matcher; /**< Cache to matcher. */
	struct mlx5_flow_dv_matcher *extra_matcher; /**< Cache to matcher. */
	struct mlx5_flow_dv_encap_decap_resource *encap_decap;
	/**< Pointer to encap/decap resource in cache. */
	struct mlx5_flow_dv_tag_resource *tag;
	/**< Pointer to tag resource in cache. */
	struct mlx5_flow_dv_modify_resource *modify;
	/**< Pointer to modify resource in cache. */
	void *flow; /**< Installed flow. */
	uint32_t flow_id; /**< Flow ID index. */
#ifdef HAVE_IBV_FLOW_DV_SUPPORT
#ifdef __DR__
	struct mlx5dv_dr_action *jump_action;
	struct mlx5dv_dr_action *meter_action;
	void *sfxt_flow; /**< Installed sfxt flow. */
	struct mlx5_flow_dv_matcher *sfxt_matcher;
	/**< Cache to sfxt matcher. */
	struct mlx5dv_dr_action *sfxt_jump_action;
	struct mlx5dv_dr_action *port_id_action;
#endif
#endif
};

#if defined(HAVE_MLX5DV_DR) && defined(__DR__)
static int
flow_d_create_policer_rules(struct rte_eth_dev *dev,
			    struct mlx5_flow_meter *fm,
			    const struct rte_flow_attr *attr);
static int
flow_d_destroy_policer_rules(struct rte_eth_dev *dev,
			     struct mlx5_flow_meter *fm,
			     const struct rte_flow_attr *attr);
static int
rte_col_2_mlx5_col(enum rte_mtr_color rcol)
{
	switch (rcol) {
	case RTE_MTR_GREEN:
		return MLX5_FLOW_COLOR_GREEN;
	case RTE_MTR_YELLOW:
		return MLX5_FLOW_COLOR_YELLOW;
	case RTE_MTR_RED:
		return MLX5_FLOW_COLOR_RED;
	default:
		break;
	}
	return MLX5_FLOW_COLOR_UNDEFINED;
}

#endif

enum modify_reg {
	REG_A,
	REG_B,
	REG_C_0,
	REG_C_1,
	REG_C_2,
	REG_C_3,
	REG_C_4,
	REG_C_5,
	REG_C_6,
	REG_C_7,
};

enum modify_reg metaid2reg[] = {
					[0] = REG_A,
					[1] = REG_C_2,
					[2] = REG_C_3,
					[3] = REG_C_4,
				};

struct field_modify_info {
	int bits;
	enum mlx5_modification_field outer_type;
	enum mlx5_modification_field inner_type;
};

struct field_modify_info modify_eth[] = {
	{4 * 8, MLX5_MODI_OUT_DMAC_47_16, MLX5_MODI_IN_DMAC_47_16},
	{2 * 8, MLX5_MODI_OUT_DMAC_15_0, MLX5_MODI_IN_DMAC_15_0},
	{4 * 8, MLX5_MODI_OUT_SMAC_47_16, MLX5_MODI_IN_SMAC_47_16},
	{2 * 8, MLX5_MODI_OUT_SMAC_15_0, MLX5_MODI_IN_SMAC_15_0},
	{2 * 8, MLX5_MODI_OUT_ETHERTYPE, MLX5_MODI_IN_ETHERTYPE},
	{0, 0, 0},
};

struct field_modify_info modify_ipv4[] = {
	{1 * 8, 0, 0}, /* Ver,len. */
	{1 * 8, MLX5_MODI_OUT_IP_DSCP, MLX5_MODI_IN_IP_DSCP},
	{2 * 8, 0, 0}, /* Data length. */
	{4 * 8, 0, 0}, /* Fragment info. */
	{1 * 8, MLX5_MODI_OUT_IPV4_TTL, MLX5_MODI_IN_IPV4_TTL},
	{3 * 8, 0, 0}, /* Protocol and checksum. */
	{4 * 8, MLX5_MODI_OUT_SIPV4, MLX5_MODI_IN_SIPV4},
	{4 * 8, MLX5_MODI_OUT_DIPV4, MLX5_MODI_IN_DIPV4},
	{0, 0, 0},
};

struct field_modify_info modify_ipv6[] = {
	{6 * 8, 0, 0}, /* Ver... */
	{2 * 8, MLX5_MODI_OUT_IPV6_HOPLIMIT, MLX5_MODI_IN_IPV6_HOPLIMIT},
	{4 * 8, MLX5_MODI_OUT_SIPV6_127_96, MLX5_MODI_IN_SIPV6_127_96},
	{4 * 8, MLX5_MODI_OUT_SIPV6_95_64, MLX5_MODI_IN_SIPV6_95_64},
	{4 * 8, MLX5_MODI_OUT_SIPV6_63_32, MLX5_MODI_IN_SIPV6_63_32},
	{4 * 8, MLX5_MODI_OUT_SIPV6_31_0, MLX5_MODI_IN_SIPV6_31_0},
	{4 * 8, MLX5_MODI_OUT_DIPV6_127_96, MLX5_MODI_IN_DIPV6_127_96},
	{4 * 8, MLX5_MODI_OUT_DIPV6_95_64, MLX5_MODI_IN_DIPV6_95_64},
	{4 * 8, MLX5_MODI_OUT_DIPV6_63_32, MLX5_MODI_IN_DIPV6_63_32},
	{4 * 8, MLX5_MODI_OUT_DIPV6_31_0, MLX5_MODI_IN_DIPV6_31_0},
	{0, 0, 0},
};

struct field_modify_info modify_udp[] = {
	{2 * 8, MLX5_MODI_OUT_UDP_SPORT, MLX5_MODI_IN_UDP_SPORT},
	{2 * 8, MLX5_MODI_OUT_UDP_DPORT, MLX5_MODI_IN_UDP_DPORT},
	{4 * 8, 0, 0}, /* Length and checksum. */
	{0, 0, 0},
};

struct field_modify_info modify_tcp[] = {
	{2 * 8, MLX5_MODI_OUT_TCP_SPORT, MLX5_MODI_IN_TCP_SPORT},
	{2 * 8, MLX5_MODI_OUT_TCP_DPORT, MLX5_MODI_IN_TCP_DPORT},
	{4 * 8, MLX5_MODI_OUT_TCP_SEQ_NUM, MLX5_MODI_IN_TCP_SEQ_NUM},
	{4 * 8, MLX5_MODI_OUT_TCP_ACK_NUM, MLX5_MODI_IN_TCP_ACK_NUM},
	{1 * 8, 0, 0}, /* data offset. */
	{1 * 8, MLX5_MODI_OUT_TCP_FLAGS, MLX5_MODI_IN_TCP_FLAGS},
	{6 * 8, 0, 0}, /* Window, checksum and urgent pointer. */
	{0, 0, 0},
};

struct modify_header {
	struct field_modify_info *fields;
	const void *default_mask;
};

struct modify_header modify_headers[] = {
	[RTE_FLOW_ITEM_TYPE_ETH] = {
		.fields = modify_eth, .default_mask = &rte_flow_item_eth_mask},
	[RTE_FLOW_ITEM_TYPE_IPV4] = {
		.fields = modify_ipv4,
		.default_mask = &rte_flow_item_ipv4_mask
	},
	[RTE_FLOW_ITEM_TYPE_IPV6] = {
		.fields = modify_ipv6,
		.default_mask = &rte_flow_item_ipv6_mask
	},
	[RTE_FLOW_ITEM_TYPE_UDP] = {
		.fields = modify_udp,
		.default_mask = &rte_flow_item_udp_mask
	},
	[RTE_FLOW_ITEM_TYPE_TCP] = {
		.fields = modify_tcp,
		.default_mask = &rte_flow_item_tcp_mask
	},
};

#ifndef RTE_LIBRTE_MLX5_FLOW_CACHE
struct mlx5_flow *sflow;
#endif

/**
 * Acquire the synchronizing object to protect multithreaded access
 * to shared dv context. Lock occurs only if context is actually
 * shared, i.e. we have multiport IB device and representors are
 * created.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 */
static void
flow_d_shared_lock(struct rte_eth_dev *dev)
{
	struct priv *priv = dev->data->dev_private;
	struct mlx5_ibv_shared *sh = priv->sh;

	if (sh->dv_refcnt > 1) {
		int ret;

		ret = pthread_mutex_lock(&sh->dv_mutex);
		assert(!ret);
		(void)ret;
	}
}

static void
flow_d_shared_unlock(struct rte_eth_dev *dev)
{
	struct priv *priv = dev->data->dev_private;
	struct mlx5_ibv_shared *sh = priv->sh;

	if (sh->dv_refcnt > 1) {
		int ret;

		ret = pthread_mutex_unlock(&sh->dv_mutex);
		assert(!ret);
		(void)ret;
	}
}
/**
 * Validate META item.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] item
 *   Item specification.
 *
 * @param[in] attr
 *   Attributes of flow that includes this item.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
flow_dv_validate_item_meta(struct rte_eth_dev *dev __rte_unused,
			   const struct rte_flow_item *item,
			   const struct rte_flow_attr *attr __rte_unused,
			   struct rte_flow_error *error,
			   uint64_t item_flags)
{
	const struct rte_flow_item_meta *spec = item->spec;
	const struct rte_flow_item_meta *mask = item->mask;
	const struct rte_flow_item_meta nic_mask = {
		.data = RTE_BE32(UINT32_MAX),
	};
	int ret;
	uint64_t offloads = dev->data->dev_conf.txmode.offloads;

	if (!(offloads & DEV_TX_OFFLOAD_MATCH_METADATA))
		return rte_flow_error_set(error, EPERM,
					  RTE_FLOW_ERROR_TYPE_ITEM,
					  NULL,
					  "match on metadata offload "
					  "configuration is off for this port");
	if (!spec)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM,
					  item->spec,
					  "data cannot be empty");
	if (!spec->data)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM,
					  NULL,
					  "data cannot be zero");
	if (!mask)
		mask = &rte_flow_item_meta_mask;
	ret = mlx5_flow_item_acceptable(item, (const uint8_t *)mask,
					(const uint8_t *)&nic_mask,
					sizeof(struct rte_flow_item_meta),
					error);
	if (ret < 0)
		return ret;
	if (item_flags & MLX5_FLOW_ITEM_METADATA(0))
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM,
					  item->spec,
					  "Duplicate meta data item ID");
	return 0;
}


/**
 * Validate META EXT item.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] item
 *   Item specification.
 *
 * @param[in] attr
 *   Attributes of flow that includes this item.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
flow_dv_validate_item_meta_ext(struct rte_eth_dev *dev __rte_unused,
			       const struct rte_flow_item *item,
			       const struct rte_flow_attr *attr __rte_unused,
			       struct rte_flow_error *error,
			       uint64_t item_flags)
{
	const struct rte_flow_item_meta_ext *spec = item->spec;
	const struct rte_flow_item_meta_ext *mask = item->mask;
	const struct rte_flow_item_meta_ext nic_mask = {
		.id = UINT64_MAX,
		.data = RTE_BE32(UINT32_MAX),
	};
	int ret;
	uint64_t offloads = dev->data->dev_conf.txmode.offloads;

	if (!(offloads & DEV_TX_OFFLOAD_MATCH_METADATA))
		return rte_flow_error_set(error, EPERM,
					  RTE_FLOW_ERROR_TYPE_ITEM,
					  NULL,
					  "match on metadata offload "
					  "configuration is off for this port");
	if (!spec)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM,
					  item->spec,
					  "data cannot be empty");
	if (!spec->data)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM,
					  NULL,
					  "data cannot be zero");
	if (!mask)
		mask = &rte_flow_item_meta_ext_mask;
	ret = mlx5_flow_item_acceptable(item, (const uint8_t *)mask,
					(const uint8_t *)&nic_mask,
					sizeof(struct rte_flow_item_meta_ext),
					error);
	if (ret < 0)
		return ret;
	if (mask->id != UINT64_MAX)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ITEM,
					  item->mask,
					  "Cannot match wildcard mask on meta id");
	if (spec->id > 3)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ITEM,
					  item->spec,
					  "Cannot match meta ID > 3");
	if (item_flags & MLX5_FLOW_ITEM_METADATA(spec->id))
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM,
					  item->spec,
					  "Duplicate meta data item ID");


	return 0;
}

/*
 * Validate the port_id action.
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
static int
flow_dv_validate_action_port_id(struct rte_eth_dev *dev,
				const struct rte_flow_attr *attr,
				const struct rte_flow_action *actions,
				uint64_t action_flags __rte_unused,
				struct rte_flow_error *error)
{
	const struct rte_flow_action_port_id *port_id;
	uint16_t port;
	uint16_t esw_domain_id;
	uint16_t act_port_domain_id;
	int ret;

	if (!attr->transfer)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
					  NULL,
					  "port id action is valid in transfer"
					  " mode only");
	if (!actions || !actions->conf)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ACTION_CONF,
					  NULL,
					  "port id action parameters must be"
					  " specified");
	if (action_flags & MLX5_FLOW_FATE_ACTIONS)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION, NULL,
					  "can have only one fate actions in"
					  " a flow");
	ret = mlx5_port_to_eswitch_info(dev->data->port_id,
					&esw_domain_id, NULL);
	if (ret < 0)
		return rte_flow_error_set(error, -ret,
					  RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
					  NULL,
					  "failed to obtain eswitch info");
	port_id = actions->conf;
	port = port_id->original ? dev->data->port_id : port_id->id;
	ret = mlx5_port_to_eswitch_info(port, &act_port_domain_id, NULL);
	if (ret)
		return rte_flow_error_set
				(error, -ret,
				 RTE_FLOW_ERROR_TYPE_ACTION_CONF, port_id,
				 "failed to obtain eswitch port-id for port");
	if (act_port_domain_id != esw_domain_id)
		return rte_flow_error_set
				(error, -ret,
				 RTE_FLOW_ERROR_TYPE_ACTION, NULL,
				 "port does not belong to"
				 " eswitch being configured");
	return 0;
}

/*
 * Validate the direct traffic to a PF action.
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
static int
flow_dv_validate_action_pf(struct rte_eth_dev *dev,
			   const struct rte_flow_attr *attr,
			   uint64_t action_flags,
			   struct rte_flow_error *error)
{
	uint16_t esw_domain_id;
	int ret;

	if (!attr->transfer)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
					  NULL,
					  "phys port action is valid in transfer"
					  " mode only");
	if (action_flags & MLX5_FLOW_FATE_ACTIONS)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION, NULL,
					  "can have only one fate actions in"
					  " a flow");
	ret = mlx5_port_to_eswitch_info(dev->data->port_id,
					&esw_domain_id, NULL);
	if (ret < 0)
		return rte_flow_error_set(error, -ret,
					  RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
					  NULL,
					  "failed to obtain eswitch info");
	return 0;
}



/**
 * Validate the meter action.
 *
 * @param[in] action
 *   Pointer to the meter action.
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
static int
mlx5_flow_validate_action_meter(struct rte_eth_dev *dev,
				const struct rte_flow_action *action,
				const struct rte_flow_attr *attr,
				struct rte_flow_error *error)
{
	struct priv *priv = dev->data->dev_private;
	const struct rte_flow_action_meter *am = action->conf;
	struct mlx5_flow_meter *fm = mlx5_flow_meter_find(priv, am->mtr_id);

	if (!priv->config.devx)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
					  NULL,
					  "meter action not supported");
	if (!fm)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION, NULL,
					  "Meter not found");
	if (!(fm->attr.transfer == attr->transfer ||
	      (!fm->attr.ingress && !attr->ingress && attr->egress) ||
	      (!fm->attr.egress && !attr->egress && attr->ingress)))
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION, NULL,
					  "Flow attributes are either invalid "
					  "or have a conflict with current "
					  "meter attributes");
	return 0;
}

/**
 * Validate the L2 encap action.
 *
 * @param[in] action_flags
 *   Holds the actions detected until now.
 * @param[in] action
 *   Pointer to the encap action.
 * @param[in] attr
 *   Pointer to flow attributes
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
flow_dv_validate_action_l2_encap(uint64_t action_flags,
				 const struct rte_flow_action *action,
				 const struct rte_flow_attr *attr,
				 struct rte_flow_error *error)
{
	if (!(action->conf))
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION, action,
					  "configuration cannot be null");
	if (action_flags & MLX5_FLOW_ACTION_DROP)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION, NULL,
					  "can't drop and encap in same flow");
	if (action_flags & (MLX5_FLOW_ENCAP_ACTIONS | MLX5_FLOW_DECAP_ACTIONS))
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION, NULL,
					  "can only have a single encap or"
					  " decap action in a flow");
	if (!attr->transfer && attr->ingress)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ATTR_INGRESS,
					  NULL,
					  "encap action not supported for "
					  "ingress");
	return 0;
}

/**
 * Validate the L2 decap action.
 *
 * @param[in] action_flags
 *   Holds the actions detected until now.
 * @param[in] attr
 *   Pointer to flow attributes
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
flow_dv_validate_action_l2_decap(uint64_t action_flags,
				 const struct rte_flow_attr *attr,
				 struct rte_flow_error *error)
{
	if (action_flags & MLX5_FLOW_ACTION_DROP)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION, NULL,
					  "can't drop and decap in same flow");
	if (action_flags & (MLX5_FLOW_ENCAP_ACTIONS | MLX5_FLOW_DECAP_ACTIONS))
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION, NULL,
					  "can only have a single encap or"
					  " decap action in a flow");
	if (attr->egress)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ATTR_EGRESS,
					  NULL,
					  "decap action not supported for "
					  "egress");
	return 0;
}

/**
 * Validate the raw encap action.
 *
 * @param[in] action_flags
 *   Holds the actions detected until now.
 * @param[in] action
 *   Pointer to the encap action.
 * @param[in] attr
 *   Pointer to flow attributes
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
flow_dv_validate_action_raw_encap(uint64_t action_flags,
				  const struct rte_flow_action *action,
				  const struct rte_flow_attr *attr,
				  struct rte_flow_error *error)
{
	if (!(action->conf))
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION, action,
					  "configuration cannot be null");
	if (action_flags & MLX5_FLOW_ACTION_DROP)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION, NULL,
					  "can't drop and encap in same flow");
	if (action_flags & MLX5_FLOW_ENCAP_ACTIONS)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION, NULL,
					  "can only have a single encap"
					  " action in a flow");
	/* encap without preceding decap is not supported for ingress */
	if (!attr->transfer && attr->ingress &&
	    !(action_flags & MLX5_FLOW_ACTION_RAW_DECAP))
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ATTR_INGRESS,
					  NULL,
					  "encap action not supported for "
					  "ingress");
	return 0;
}

/**
 * Validate the raw decap action.
 *
 * @param[in] action_flags
 *   Holds the actions detected until now.
 * @param[in] action
 *   Pointer to the encap action.
 * @param[in] attr
 *   Pointer to flow attributes
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
flow_dv_validate_action_raw_decap(uint64_t action_flags,
				  const struct rte_flow_action *action,
				  const struct rte_flow_attr *attr,
				  struct rte_flow_error *error)
{
	if (action_flags & MLX5_FLOW_ACTION_DROP)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION, NULL,
					  "can't drop and decap in same flow");
	if (action_flags & MLX5_FLOW_ENCAP_ACTIONS)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION, NULL,
					  "can't have encap action before"
					  " decap action");
	if (action_flags & MLX5_FLOW_DECAP_ACTIONS)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION, NULL,
					  "can only have a single decap"
					  " action in a flow");
	/* decap action is valid on egress only if it is followed by encap */
	if (attr->egress) {
		for (; action->type != RTE_FLOW_ACTION_TYPE_END &&
		       action->type != RTE_FLOW_ACTION_TYPE_RAW_ENCAP;
		       action++) {
		}
		if (action->type != RTE_FLOW_ACTION_TYPE_RAW_ENCAP)
			return rte_flow_error_set
					(error, ENOTSUP,
					 RTE_FLOW_ERROR_TYPE_ATTR_EGRESS,
					 NULL, "decap action not supported"
					 " for egress");
	}
	return 0;
}

/**
 * Validate the set meta action.
 *
 * @param[in] action_flags
 *   Holds the actions detected until now.
 * @param[in] action
 *   Pointer to the set meta action.
 * @param[in] attr
 *   Pointer to flow attributes
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
flow_dv_validate_action_set_meta(uint64_t action_flags,
				  const struct rte_flow_action *action,
				  const struct rte_flow_attr *attr,
				  struct rte_flow_error *error)
{
	const struct rte_flow_action_set_meta *m = action->conf;

	if (!(action->conf))
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION, action,
					  "configuration cannot be null");
	if (action_flags & MLX5_FLOW_ACTION_DROP)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION, NULL,
					  "can't drop and modify in same flow");
	if (attr->ingress && (m->id == 0))
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ATTR_INGRESS,
					  NULL,
					  "Cannot set meta data 0 in ingress");
	if (m->id > 3)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ACTION,
					  NULL,
					  "Cannot set meta data ID > 3");
	if (action_flags & MLX5_FLOW_ACTION_SET_META(m->id))
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION, NULL,
					  "Duplicate set meta actions");
	return 0;
}
/**
 * Find existing tag resource or create and register a new one.
 *
 * @param dev[in, out]
 *   Pointer to rte_eth_dev structure.
 * @param[in, out] resource
 *   Pointer to tag resource.
 * @parm[in, out] dev_flow
 *   Pointer to the dev_flow.
 * @param[out] error
 *   pointer to error structure.
 *
 * @return
 *   0 on success otherwise -errno and errno is set.
 */
static int __rte_unused
flow_dv_tag_resource_register
			(struct rte_eth_dev *dev,
			 struct mlx5_flow_dv_tag_resource *resource,
			 struct mlx5_flow *dev_flow,
			 struct rte_flow_error *error)
{
	struct priv *priv = dev->data->dev_private;
	struct mlx5_ibv_shared *sh = priv->sh;
	struct rte_hlist_data_element *de;
	struct mlx5_flow_dv_tag_resource *cache_resource;

	/* Lookup a matching resource from cache. */
	de = rte_hlist_add_key_data_len(sh->tag_table,
		&resource->tag, resource, sizeof(struct mlx5_flow_dv_tag_resource), 0);
	if (NULL == de)
		return rte_flow_error_set(error, ENOMEM,
					  RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
					  NULL, "cannot insert the tag");

#ifdef HAVE_MLX5DV_DR
	/* Register new  resource. */
	cache_resource = (struct mlx5_flow_dv_tag_resource *)de->extra_data;
	if (!cache_resource)
		return rte_flow_error_set(error, ENOMEM,
					  RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
					  "cannot allocate or find resource memory");
	if (rte_hlist_entry_is_new(de)) {
		cache_resource->action = mlx5dv_dr_action_create_tag(resource->tag);
		if (!cache_resource->action) {
			rte_free(cache_resource);
			rte_hlist_del_key(sh->tag_table, &resource->tag);
			return rte_flow_error_set(error, ENOMEM,
						  RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
						  NULL, "cannot create action");
		}
		rte_atomic32_init(&cache_resource->refcnt);
	} else {
		DRV_LOG(DEBUG, "tag resource %p: refcnt %d++",
			(void *)cache_resource,
			rte_atomic32_read(&cache_resource->refcnt));
	}
	rte_atomic32_inc(&cache_resource->refcnt);
	dev_flow->dv.handle->tag = cache_resource;

	return 0;
#else
	return rte_flow_error_set(error, ENOTSUP,
				  RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
				  "direct rules are not supported");
#endif /* HAVE_MLX5DV_DR */
}

/**
 * Find existing encap/decap resource or create and register a new one.
 *
 * @param dev[in, out]
 *   Pointer to rte_eth_dev structure.
 * @param[in, out] resource
 *   Pointer to encap/decap resource.
 * @parm[in, out] dev_flow
 *   Pointer to the dev_flow.
 * @param[out] error
 *   pointer to error structure.
 *
 * @return
 *   0 on success otherwise -errno and errno is set.
 */
static int
flow_dv_encap_decap_resource_register
			(struct rte_eth_dev *dev,
			 struct mlx5_flow_dv_encap_decap_resource *resource,
			 struct mlx5_flow *dev_flow,
			 struct rte_flow_error *error)
{
	struct priv *priv = dev->data->dev_private;
	struct mlx5_ibv_shared *sh = priv->sh;
	struct mlx5_flow_dv_encap_decap_resource *cache_resource;
#ifdef HAVE_MLX5DV_DR
	struct rte_flow *flow = dev_flow->flow;
	struct mlx5dv_dr_domain *domain;

	resource->flags = flow->group ? 0 : 1;
	resource->ingress = flow->ingress;
	resource->transfer = flow->transfer;
	if (flow->transfer)
		domain = sh->fdb_domain;
	else
		domain = flow->ingress ? sh->rx_domain : sh->tx_domain;
#endif
	/* Lookup a matching resource from cache. */
	LIST_FOREACH(cache_resource, &sh->encaps_decaps, next) {
		if (resource->reformat_type == cache_resource->reformat_type &&
		    resource->ingress == cache_resource->ingress &&
		    resource->transfer == cache_resource->transfer &&
		    resource->size == cache_resource->size &&
		    resource->flags == cache_resource->flags &&
		    !memcmp((const void *)resource->buf,
			    (const void *)cache_resource->buf,
			    resource->size)) {
			DRV_LOG(DEBUG, "encap/decap resource %p: refcnt %d++",
				(void *)cache_resource,
				rte_atomic32_read(&cache_resource->refcnt));
			rte_atomic32_inc(&cache_resource->refcnt);
			dev_flow->dv.handle->encap_decap = cache_resource;
			return 0;
		}
	}
#ifdef HAVE_MLX5DV_DR
	/* Register new encap/decap resource. */
	cache_resource = rte_calloc(__func__, 1, sizeof(*cache_resource), 0);
	if (!cache_resource)
		return rte_flow_error_set(error, ENOMEM,
					  RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
					  "cannot allocate resource memory");
	*cache_resource = *resource;
	cache_resource->verbs_action = mlx5dv_dr_action_create_packet_reformat
		(domain, cache_resource->flags, cache_resource->reformat_type,
		 cache_resource->size,
		 cache_resource->size ? cache_resource->buf :  NULL);

	if (!cache_resource->verbs_action) {
		rte_free(cache_resource);
		return rte_flow_error_set(error, ENOMEM,
					  RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
					  NULL, "cannot create action");
	}
	rte_atomic32_init(&cache_resource->refcnt);
	rte_atomic32_inc(&cache_resource->refcnt);
	LIST_INSERT_HEAD(&sh->encaps_decaps, cache_resource, next);
	dev_flow->dv.handle->encap_decap = cache_resource;
	DRV_LOG(DEBUG, "new encap/decap resource %p: refcnt %d++",
		(void *)cache_resource,
		rte_atomic32_read(&cache_resource->refcnt));
	return 0;
#else
	return rte_flow_error_set(error, ENOTSUP,
				  RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				  NULL, "direct rules are not supported");
#endif /* HAVE_MLX5DV_DR */
}

/**
 * Get the size of specific rte_flow_item_type
 *
 * @param[in] item_type
 *   Tested rte_flow_item_type.
 *
 * @return
 *   sizeof struct item_type, 0 if void or irrelevant.
 */
static size_t
flow_dv_get_item_len(const enum rte_flow_item_type item_type)
{
	size_t retval;

	switch (item_type) {
	case RTE_FLOW_ITEM_TYPE_ETH:
		retval = sizeof(struct rte_flow_item_eth);
		break;
	case RTE_FLOW_ITEM_TYPE_VLAN:
		retval = sizeof(struct rte_flow_item_vlan);
		break;
	case RTE_FLOW_ITEM_TYPE_IPV4:
		retval = sizeof(struct rte_flow_item_ipv4);
		break;
	case RTE_FLOW_ITEM_TYPE_IPV6:
		retval = sizeof(struct rte_flow_item_ipv6);
		break;
	case RTE_FLOW_ITEM_TYPE_UDP:
		retval = sizeof(struct rte_flow_item_udp);
		break;
	case RTE_FLOW_ITEM_TYPE_TCP:
		retval = sizeof(struct rte_flow_item_tcp);
		break;
	case RTE_FLOW_ITEM_TYPE_VXLAN:
		retval = sizeof(struct rte_flow_item_vxlan);
		break;
	case RTE_FLOW_ITEM_TYPE_GRE:
		retval = sizeof(struct rte_flow_item_gre);
		break;
	case RTE_FLOW_ITEM_TYPE_NVGRE:
		retval = sizeof(struct rte_flow_item_nvgre);
		break;
	case RTE_FLOW_ITEM_TYPE_VXLAN_GPE:
		retval = sizeof(struct rte_flow_item_vxlan_gpe);
		break;
	case RTE_FLOW_ITEM_TYPE_MPLS:
		retval = sizeof(struct rte_flow_item_mpls);
		break;
	case RTE_FLOW_ITEM_TYPE_VOID: /* Fall through. */
	default:
		retval = 0;
		break;
	}
	return retval;
}

#define MLX5_ENCAP_IPV4_VERSION		0x40
#define MLX5_ENCAP_IPV4_IHL_MIN		0x05
#define MLX5_ENCAP_IPV4_TTL_DEF		0x40
#define MLX5_ENCAP_IPV6_VTC_FLOW	0x60000000
#define MLX5_ENCAP_IPV6_HOP_LIMIT	0xff
#define MLX5_ENCAP_VXLAN_FLAGS		0x08000000
#define MLX5_ENCAP_VXLAN_GPE_FLAGS	0x04

/**
 * Convert the encap action data from list of rte_flow_item to raw buffer
 *
 * @param[in] items
 *   Pointer to rte_flow_item objects list.
 * @param[out] buf
 *   Pointer to the output buffer.
 * @param[out] size
 *   Pointer to the output buffer size.
 * @param[out] error
 *   Pointer to the error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
flow_dv_convert_encap_data(const struct rte_flow_item *items, uint8_t *buf,
			   size_t *size, struct rte_flow_error *error)
{
	struct ether_hdr *eth = NULL;
	struct vlan_hdr *vlan = NULL;
	struct ipv4_hdr *ipv4 = NULL;
	struct ipv6_hdr *ipv6 = NULL;
	struct udp_hdr *udp = NULL;
	struct vxlan_hdr *vxlan = NULL;
	struct vxlan_gpe_hdr *vxlan_gpe = NULL;
	struct gre_hdr *gre = NULL;
	size_t len;
	size_t temp_size = 0;

	if (!items)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION,
					  NULL, "invalid empty data");
	for (; items->type != RTE_FLOW_ITEM_TYPE_END; items++) {
		len = flow_dv_get_item_len(items->type);
		if (len + temp_size > MLX5_ENCAP_MAX_LEN)
			return rte_flow_error_set(error, EINVAL,
						  RTE_FLOW_ERROR_TYPE_ACTION,
						  (void *)items->type,
						  "items total size is too big"
						  " for encap action");
		rte_memcpy((void *)&buf[temp_size], items->spec, len);
		switch (items->type) {
		case RTE_FLOW_ITEM_TYPE_ETH:
			eth = (struct ether_hdr *)&buf[temp_size];
			break;
		case RTE_FLOW_ITEM_TYPE_VLAN:
			vlan = (struct vlan_hdr *)&buf[temp_size];
			if (!eth)
				return rte_flow_error_set(error, EINVAL,
						RTE_FLOW_ERROR_TYPE_ACTION,
						(void *)items->type,
						"eth header not found");
			if (!eth->ether_type)
				eth->ether_type = RTE_BE16(ETHER_TYPE_VLAN);
			vlan->vlan_tci = ((const struct rte_flow_item_vlan *)
					  items->spec)->tci;
			vlan->eth_proto = 0;
			break;
		case RTE_FLOW_ITEM_TYPE_IPV4:
			ipv4 = (struct ipv4_hdr *)&buf[temp_size];
			if (!vlan && !eth)
				return rte_flow_error_set(error, EINVAL,
						RTE_FLOW_ERROR_TYPE_ACTION,
						(void *)items->type,
						"neither eth nor vlan"
						" header found");
			if (vlan && !vlan->eth_proto)
				vlan->eth_proto = RTE_BE16(ETHER_TYPE_IPv4);
			else if (eth && !eth->ether_type)
				eth->ether_type = RTE_BE16(ETHER_TYPE_IPv4);
			if (!ipv4->version_ihl)
				ipv4->version_ihl = MLX5_ENCAP_IPV4_VERSION |
						    MLX5_ENCAP_IPV4_IHL_MIN;
			if (!ipv4->time_to_live)
				ipv4->time_to_live = MLX5_ENCAP_IPV4_TTL_DEF;
			break;
		case RTE_FLOW_ITEM_TYPE_IPV6:
			ipv6 = (struct ipv6_hdr *)&buf[temp_size];
			if (!vlan && !eth)
				return rte_flow_error_set(error, EINVAL,
						RTE_FLOW_ERROR_TYPE_ACTION,
						(void *)items->type,
						"neither eth nor vlan"
						" header found");
			if (vlan && !vlan->eth_proto)
				vlan->eth_proto = RTE_BE16(ETHER_TYPE_IPv6);
			else if (eth && !eth->ether_type)
				eth->ether_type = RTE_BE16(ETHER_TYPE_IPv6);
			if (!ipv6->vtc_flow)
				ipv6->vtc_flow =
					RTE_BE32(MLX5_ENCAP_IPV6_VTC_FLOW);
			if (!ipv6->hop_limits)
				ipv6->hop_limits = MLX5_ENCAP_IPV6_HOP_LIMIT;
			break;
		case RTE_FLOW_ITEM_TYPE_UDP:
			udp = (struct udp_hdr *)&buf[temp_size];
			if (!ipv4 && !ipv6)
				return rte_flow_error_set(error, EINVAL,
						RTE_FLOW_ERROR_TYPE_ACTION,
						(void *)items->type,
						"ip header not found");
			if (ipv4 && !ipv4->next_proto_id)
				ipv4->next_proto_id = IPPROTO_UDP;
			else if (ipv6 && !ipv6->proto)
				ipv6->proto = IPPROTO_UDP;
			break;
		case RTE_FLOW_ITEM_TYPE_VXLAN:
			vxlan = (struct vxlan_hdr *)&buf[temp_size];
			if (!udp)
				return rte_flow_error_set(error, EINVAL,
						RTE_FLOW_ERROR_TYPE_ACTION,
						(void *)items->type,
						"udp header not found");
			if (!udp->dst_port)
				udp->dst_port = RTE_BE16(MLX5_UDP_PORT_VXLAN);
			if (!vxlan->vx_flags)
				vxlan->vx_flags =
					RTE_BE32(MLX5_ENCAP_VXLAN_FLAGS);
			break;
		case RTE_FLOW_ITEM_TYPE_VXLAN_GPE:
			vxlan_gpe = (struct vxlan_gpe_hdr *)&buf[temp_size];
			if (!udp)
				return rte_flow_error_set(error, EINVAL,
						RTE_FLOW_ERROR_TYPE_ACTION,
						(void *)items->type,
						"udp header not found");
			if (!vxlan_gpe->proto)
				return rte_flow_error_set(error, EINVAL,
						RTE_FLOW_ERROR_TYPE_ACTION,
						(void *)items->type,
						"next protocol not found");
			if (!udp->dst_port)
				udp->dst_port =
					RTE_BE16(MLX5_UDP_PORT_VXLAN_GPE);
			if (!vxlan_gpe->vx_flags)
				vxlan_gpe->vx_flags =
						MLX5_ENCAP_VXLAN_GPE_FLAGS;
			break;
		case RTE_FLOW_ITEM_TYPE_GRE:
		case RTE_FLOW_ITEM_TYPE_NVGRE:
			gre = (struct gre_hdr *)&buf[temp_size];
			if (!gre->proto)
				return rte_flow_error_set(error, EINVAL,
						RTE_FLOW_ERROR_TYPE_ACTION,
						(void *)items->type,
						"next protocol not found");
			if (!ipv4 && !ipv6)
				return rte_flow_error_set(error, EINVAL,
						RTE_FLOW_ERROR_TYPE_ACTION,
						(void *)items->type,
						"ip header not found");
			if (ipv4 && !ipv4->next_proto_id)
				ipv4->next_proto_id = IPPROTO_GRE;
			else if (ipv6 && !ipv6->proto)
				ipv6->proto = IPPROTO_GRE;
			break;
		case RTE_FLOW_ITEM_TYPE_VOID:
			break;
		default:
			return rte_flow_error_set(error, EINVAL,
						  RTE_FLOW_ERROR_TYPE_ACTION,
						  (void *)items->type,
						  "unsupported item type");
			break;
		}
		temp_size += len;
	}
	*size = temp_size;
	return 0;
}

/**
 * Convert L2 encap action to DV specification.
 *
 * @param[in] dev
 *   Pointer to rte_eth_dev structure.
 * @param[in] action
 *   Pointer to action structure.
 * @param[in, out] dev_flow
 *   Pointer to the mlx5_flow.
 * @param[out] error
 *   Pointer to the error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
flow_dv_create_action_l2_encap(struct rte_eth_dev *dev,
			       const struct rte_flow_action *action,
			       struct mlx5_flow *dev_flow,
			       bool mtr_sfx,
			       struct rte_flow_error *error)
{
	const struct rte_flow_item *encap_data;
	const struct rte_flow_action_raw_encap *raw_encap_data;
	struct mlx5_flow_dv_encap_decap_resource res = {
		.reformat_type =
			MLX5DV_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TO_L2_TUNNEL,
		.mtr_sfx_tbl = mtr_sfx,
	};

	if (action->type == RTE_FLOW_ACTION_TYPE_RAW_ENCAP) {
		raw_encap_data =
			(const struct rte_flow_action_raw_encap *)action->conf;
		res.size = raw_encap_data->size;
		memcpy(res.buf, raw_encap_data->data, res.size);
	} else {
		if (action->type == RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP)
			encap_data =
				((const struct rte_flow_action_vxlan_encap *)
						action->conf)->definition;
		else
			encap_data =
				((const struct rte_flow_action_nvgre_encap *)
						action->conf)->definition;
		if (flow_dv_convert_encap_data(encap_data, res.buf,
					       &res.size, error))
			return -rte_errno;
	}
	if (flow_dv_encap_decap_resource_register(dev, &res, dev_flow, error))
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION,
					  NULL, "can't create L2 encap action");
	return 0;
}

/**
 * Convert L2 decap action to DV specification.
 *
 * @param[in] dev
 *   Pointer to rte_eth_dev structure.
 * @param[in, out] dev_flow
 *   Pointer to the mlx5_flow.
 * @param[out] error
 *   Pointer to the error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
flow_dv_create_action_l2_decap(struct rte_eth_dev *dev,
			       struct mlx5_flow *dev_flow,
			       bool mtr_sfx,
			       struct rte_flow_error *error)
{
	struct mlx5_flow_dv_encap_decap_resource res = {
		.size = 0,
		.reformat_type =
			MLX5DV_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TUNNEL_TO_L2,
		.ft_type = dev_flow->flow->transfer ?
			   MLX5DV_FLOW_TABLE_TYPE_FDB :
			   MLX5DV_FLOW_TABLE_TYPE_NIC_RX,
		.transfer = dev_flow->flow->transfer,
		.mtr_sfx_tbl = mtr_sfx,

	};

	if (flow_dv_encap_decap_resource_register(dev, &res, dev_flow, error))
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION,
					  NULL, "can't create L2 decap action");
	return 0;
}

/**
 * Convert raw decap/encap (L3 tunnel) action to DV specification.
 *
 * @param[in] dev
 *   Pointer to rte_eth_dev structure.
 * @param[in] action
 *   Pointer to action structure.
 * @param[in, out] dev_flow
 *   Pointer to the mlx5_flow.
 * @param[in] attr
 *   Pointer to the flow attributes.
 * @param[out] error
 *   Pointer to the error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
flow_dv_create_action_raw_encap(struct rte_eth_dev *dev,
				const struct rte_flow_action *action,
				struct mlx5_flow *dev_flow,
				bool mtr_sfx,
				const struct rte_flow_attr *attr,
				struct rte_flow_error *error)
{
	const struct rte_flow_action_raw_encap *encap_data;
	struct mlx5_flow_dv_encap_decap_resource res;
	struct priv *priv = dev->data->dev_private;

	encap_data = (const struct rte_flow_action_raw_encap *)action->conf;
	res.size = encap_data->size;
	memcpy(res.buf, encap_data->data, res.size);
	res.reformat_type = (attr->egress || (attr->transfer && priv->representor)) ?
		MLX5DV_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TO_L3_TUNNEL :
		MLX5DV_FLOW_ACTION_PACKET_REFORMAT_TYPE_L3_TUNNEL_TO_L2;
	res.ft_type = attr->transfer ?
		      MLX5DV_FLOW_TABLE_TYPE_FDB :
		      attr->egress ? MLX5DV_FLOW_TABLE_TYPE_NIC_TX :
		      MLX5DV_FLOW_TABLE_TYPE_NIC_RX;
	res.transfer = attr->transfer;
	res.mtr_sfx_tbl = mtr_sfx;
	if (flow_dv_encap_decap_resource_register(dev, &res, dev_flow, error))
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION,
					  NULL, "can't create encap action");
	return 0;
}

static int
flow_dv_sync(struct rte_eth_dev *dev __rte_unused,
	     struct rte_flow_error *error __rte_unused)
{
#ifdef HAVE_MLX5DV_DR
	struct priv *priv = dev->data->dev_private;
	struct mlx5_ibv_shared *sh = priv->sh;
	uint32_t flags = MLX5DV_DR_DOMAIN_SYNC_FLAGS_SW | MLX5DV_DR_DOMAIN_SYNC_FLAGS_HW;
	int rc;

	if (sh->rx_domain) {
		rc = mlx5dv_dr_domain_sync(sh->rx_domain, flags);
		if (rc)
			return rte_flow_error_set(error, rc,
					RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
					"error sync rx domain");
	}
	if (sh->tx_domain) {
		rc = mlx5dv_dr_domain_sync(sh->tx_domain, flags);
		if (rc)
			return rte_flow_error_set(error, rc,
					RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
					"error sync tx domain");
	}
#endif
	return 0;
}


static struct mlx5_flow_bulk_counters *
flow_dv_bulk_counters_alloc(struct rte_eth_dev *dev, uint32_t *start_index,
			    uint32_t *blk_sz, struct rte_flow_error *error)
{
	struct priv *priv = dev->data->dev_private;
	uint8_t i;
	struct mlx5_flow_bulk_counters *bulk;
	struct mlx5_devx_counter_set dcs;

	bulk = rte_calloc(__func__, 1, sizeof(*bulk), sizeof(uint64_t));
	if (!bulk) {
		rte_flow_error_set(error, ENOMEM,
				   RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   NULL, "failed to allocate counter");
		return NULL;
	};
	for (i = 0x80; i != 0; i = i >> 1) {
		*blk_sz =
		     priv->config.hca_attr.flow_counter_bulk_alloc_bitmap & i;
		if (*blk_sz) {
			bulk->num_of_counters = 128 * (*blk_sz);
			TAILQ_INIT(&bulk->free_list);
			if (!mlx5_devx_cmd_fc_alloc
					(priv->sh->ctx, &dcs, *blk_sz)) {
				bulk->obj = dcs.obj;
				bulk->id = dcs.id;
				*start_index = dcs.id;
				*blk_sz = bulk->num_of_counters;
				return bulk;
			}
		}
	}
	rte_free(bulk);
	rte_flow_error_set(error, ENOMEM,
			RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
			NULL, "failed to allocate counters");
	return NULL;
}

static struct mlx5_devx_counter_set *
flow_dv_counter_alloc(struct rte_eth_dev *dev, uint32_t *index,
		      enum mlx5_counter_type type,
		      struct rte_flow_error *error)
{
	struct priv *priv = dev->data->dev_private;
	struct mlx5_dcs *dcs_list = &priv->dcs;
	struct mlx5_devx_counter_set *dcs;
	struct mlx5_flow_bulk_counters *entry;
	uint32_t blk_sz;
	uint32_t start;

	if (type == MLX5_COUNTER_TYPE_SINGLE) {
		dcs = TAILQ_FIRST(dcs_list);
		if (dcs) {
			TAILQ_REMOVE(dcs_list, dcs, next);
			if (index)
				*index = dcs->id;
			return dcs;
		}
		dcs = rte_calloc(__func__, 1, sizeof(*dcs), 0);
		if (!dcs)
			rte_flow_error_set(error, ENOMEM,
					   RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
					   NULL, "failed to allocate counter");
		if (mlx5_devx_cmd_fc_alloc(priv->sh->ctx, dcs, 0)) {
			
			rte_flow_error_set(error, EINVAL,
					   RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
					   NULL, "failed to allocate counter");
			return NULL;
		}
		dcs->type = MLX5_COUNTER_TYPE_SINGLE;
		if (index)
			*index = dcs->id;
		return dcs;	
	}
	/* Search the existing bulk list for a free counter */
	SLIST_FOREACH(entry, &priv->bulk_dcs, next) {
		if (entry->free_count) {
			dcs = TAILQ_FIRST(&entry->free_list);
			TAILQ_REMOVE(&entry->free_list, dcs, next);
			entry->free_count--;
			return dcs;
		}
		if (entry->current_index < entry->num_of_counters) {
			dcs = rte_calloc(__func__, 1, sizeof(*dcs), 0);
			if (!dcs)
				rte_flow_error_set
					(error, ENOMEM,
					 RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
					 NULL, "failed to allocate counter");
			dcs->type = MLX5_COUNTER_TYPE_BULK;
			dcs->bulk = entry;
			dcs->id = entry->id + entry->current_index;
			entry->current_index++;
			if (index)
				*index = dcs->id;
			return dcs;
		}
	}
	/* No free entry? allocate a new bulk */
	entry = flow_dv_bulk_counters_alloc(dev, &start, &blk_sz, error);
	if (entry) {
		SLIST_INSERT_HEAD(&priv->bulk_dcs, entry, next);
		if (entry->free_count) {
			dcs = TAILQ_FIRST(&entry->free_list);
			TAILQ_REMOVE(&entry->free_list, dcs, next);
			entry->free_count--;
			if (index)
				*index = dcs->id;
			return dcs;
		}
		if (entry->current_index < entry->num_of_counters) {
			dcs = rte_calloc(__func__, 1, sizeof(*dcs), 0);
			if (!dcs)
				rte_flow_error_set
					(error, ENOMEM,
					 RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
					 NULL, "failed to allocate counter");
			dcs->type = MLX5_COUNTER_TYPE_BULK;
			dcs->bulk = entry;
			dcs->id = entry->id + entry->current_index;
			entry->current_index++;
			if (index)
				*index = dcs->id;
			return dcs;
		}
	}
	rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
			   "failed to allocate counter");
	return NULL;
}

static int
flow_dv_counter_free(struct rte_eth_dev *dev,
		     struct mlx5_devx_counter_set *dcs)
{
	struct mlx5_flow_bulk_counters *entry;
	struct priv *priv = dev->data->dev_private;

	if (dcs->type == MLX5_COUNTER_TYPE_BULK) {
		entry = dcs->bulk;
		TAILQ_INSERT_HEAD(&entry->free_list, dcs, next);
		entry->free_count++;
	} else {
		TAILQ_INSERT_HEAD(&priv->dcs, dcs, next);
	}
	return 0;
}

static int
flow_dv_bulk_counter_free(struct rte_eth_dev *dev __rte_unused,
			  struct mlx5_flow_bulk_counters *bulk)
{
	return mlx5dv_devx_obj_destroy(bulk->obj);
}

void
flow_counter_mr_empty(struct rte_eth_dev *dev)
{
	struct priv *priv = dev->data->dev_private;
	struct mlx5_flow_counter_query_mr *entry;
	struct mlx5_flow_counter_query_mr *next;

	entry = SLIST_FIRST(&priv->counter_mr);
	while (entry) {
		next = SLIST_NEXT(entry, next);
		mlx5dv_devx_obj_destroy(entry->mkey->obj);
		rte_free(entry->mkey);
		mlx5dv_devx_umem_dereg(entry->umem);
		rte_free(entry);
		entry = next;
	};
}

#ifndef HAVE_MLX5DV_DR
struct mlx5dv_pd {
	uint32_t pdn;
};
#endif

static struct mlx5_devx_mkey *
flow_counter_mkey_get(struct rte_eth_dev *dev, void *addr, size_t length)
{
	struct priv *priv = dev->data->dev_private;
	struct mlx5_flow_counter_query_mr *entry;
	struct mlx5dv_pd dv_pd;
	struct mlx5dv_obj dv_obj;
	struct mlx5_devx_mkey_attr mkey_attr;

	SLIST_FOREACH(entry, &priv->counter_mr, next) {
		if (entry->addr == addr && entry->length == length)
			return entry->mkey;
	}
	entry = rte_zmalloc_socket(__func__, sizeof(*entry), 0,
				   rte_socket_id());
	if (!entry)
		return NULL;
	entry->umem = mlx5dv_devx_umem_reg(priv->sh->ctx, addr, length,
					   IBV_ACCESS_LOCAL_WRITE);
	if (!entry->umem)
		goto mkey_get_error;
	dv_obj.pd.in = priv->sh->pd;
	dv_obj.pd.out = &dv_pd;
	mlx5dv_init_obj(&dv_obj, MLX5DV_OBJ_PD);	
	mkey_attr.addr = (uintptr_t) addr;
	mkey_attr.size = length;
	mkey_attr.pas_id = entry->umem->umem_id;
	mkey_attr.pd = dv_pd.pdn;
	entry->mkey = mlx5_create_mkey(priv->sh->ctx, &mkey_attr);
	entry->addr = addr;
	entry->length = length;
	SLIST_INSERT_HEAD(&priv->counter_mr, entry, next);
	return entry->mkey;
mkey_get_error:
	rte_free(entry);
	return NULL;
}

static int
flow_dv_counter_query(struct rte_eth_dev *dev,
		      int counter_id, void *counter_obj,
		      uint32_t count, struct rte_flow_count_value *buf,
		      int buf_count, rte_flow_cb_fn cb, void *cb_arg,
		      struct rte_flow_error *error)
{
	struct priv *priv = dev->data->dev_private;
	int ret;
	struct mlx5_flow_bulk_counters *bulk = counter_obj;
	struct mlx5_devx_counter_set dcs = {
			.id = counter_id, .obj = bulk->obj };
	struct mlx5_devx_mkey *mkey;

	mkey = flow_counter_mkey_get(dev, buf, buf_count * sizeof(*buf));
	if (!mkey)
		return rte_flow_error_set(error, ENOENT,
				RTE_FLOW_ERROR_TYPE_ACTION, NULL,
				"unable to register mkey for buffer");
	if (cb && mlx5_flow_batch_async_callback != cb)
		mlx5_flow_batch_async_callback = cb;
	ret = mlx5_devx_cmd_fc_query(&dcs, 0, NULL, NULL, count, mkey->key,
				     buf, cb_arg, priv->sh->devx_comp);
	if (ret)
		return rte_flow_error_set(error, ret,
				RTE_FLOW_ERROR_TYPE_ACTION, NULL,
				"unable query counter range");
	return 0;
}

/**
 * Get or create a flow counter.
 *
 * @param[in] dev
 *   Pointer to the Ethernet device structure.
 * @param[in] shared
 *   Indicate if this counter is shared with other flows.
 * @param[in] id
 *   Counter identifier.
 *
 * @return
 *   A pointer to the counter, NULL otherwise and rte_errno is set.
 */
#ifdef HAVE_IBV_FLOW_DEVX_COUNTERS
static struct mlx5_flow_counter *
flow_dv_counter_new(struct rte_eth_dev *dev, uint32_t shared, uint32_t id,
		    void *handle, const struct rte_flow_count_value *bias,
		    enum mlx5_counter_type type)
{
	struct priv *priv = dev->data->dev_private;
	struct mlx5_flow_counter *cnt = NULL;
	struct mlx5_devx_counter_set *dcs = NULL;
	struct rte_flow_error error;
	int ret;

	if (!priv->config.devx) {
		ret = -EINVAL;
		goto error_exit;
	}
	if (shared) {
		LIST_FOREACH(cnt, &priv->flow_counters, next) {
			if (cnt->shared && cnt->id == id) {
				cnt->ref_cnt++;
				return cnt;
			}
		}
	}
	cnt = rte_calloc(__func__, 1, sizeof(*cnt), 0);
	if (!cnt) {
		ret = -ENOMEM;
		goto error_exit;
	}
	if (handle) {
		dcs = rte_calloc(__func__, 1, sizeof(*dcs), 0);
		if (!dcs) {
			ret = - ENOMEM;
			goto error_exit;
		}
		dcs->bulk = handle;
		dcs->id = id;
		dcs->type = MLX5_COUNTER_TYPE_EXTERNAL;
	} else {
		dcs = flow_dv_counter_alloc(dev, NULL, type, &error);
		if (!dcs) {
			ret = -ENOMEM;
			goto error_exit;
		}
	}
	struct mlx5_flow_counter tmpl = {
			.devx_reuse = !!handle,
			.shared = shared,
			.ref_cnt = 1,
			.devx_cnt = 1,
			.id = id,
			.dcs = dcs,
			.hits = bias->hits,
			.bytes = bias->bytes,
	};
#ifdef HAVE_MLX5DV_DR
	//TODO: should check if action needs to be replaced when using handle.
	if (dcs->type == MLX5_COUNTER_TYPE_SINGLE)
		tmpl.action = mlx5dv_dr_action_create_flow_counter(dcs->obj, 0);
	else {
		struct mlx5_flow_bulk_counters *bulk =
			(struct mlx5_flow_bulk_counters *)dcs->bulk;
		tmpl.action = mlx5dv_dr_action_create_flow_counter
			(bulk->obj, dcs->id - bulk->id);
	}
#endif
	*cnt = tmpl;
	LIST_INSERT_HEAD(&priv->flow_counters, cnt, next);
	return cnt;
error_exit:
	rte_free(cnt);
	rte_free(dcs);
	rte_errno = -ret;
	return NULL;
}
#endif /* HAVE_IBV_FLOW_DEVX_COUNTERS */

/**
 * Release a flow counter.
 *
 * @param[in] dev
 *   Pointer to dev struct.
 * @param[in] counter
 *   Pointer to the counter handler.
 */
static void
flow_dv_counter_release(struct rte_eth_dev *dev,
			struct mlx5_flow_counter *counter)
{
	int ret;

	if (!counter)
		return;
	if (--counter->ref_cnt == 0) {
		if (!counter->devx_reuse) {
			ret = flow_dv_counter_free(dev, counter->dcs);
			if (ret)
				DRV_LOG(ERR,
					"Failed to free devx counters (%d)",
					ret);
		}
#ifdef HAVE_MLX5DV_DR
		mlx5dv_dr_action_destroy(counter->action);
#endif
		if (counter->devx_reuse)
			rte_free(counter->dcs);
		LIST_REMOVE(counter, next);
		rte_free(counter);
	}
}

/**
 * Verify the @p attributes will be correctly understood by the NIC and store
 * them in the @p flow if everything is correct.
 *
 * @param[in] dev
 *   Pointer to dev struct.
 * @param[in] attributes
 *   Pointer to flow attributes
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
flow_dv_validate_attributes(struct rte_eth_dev *dev,
			    const struct rte_flow_attr *attributes,
			    struct rte_flow_error *error)
{
	struct priv *priv = dev->data->dev_private;
	uint32_t group_max = priv->vf ? 0 :
					(attributes->transfer ?
						MLX5_MAX_FDB_TABLES :
						MLX5_MAX_TABLES) - 1;
	/*
	 * in isolated mode, user can use all verbs' priorities.
	 * in non-isolated mode, the last (lowest) priorities reserved for
	 * control flows.
	 */
	uint32_t priority_max = priv->isolated ?
				priv->config.flow_prio - 1 :
				priv->config.flow_prio - 2;

	if (attributes->group > group_max)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ATTR_GROUP,
					  NULL,
					  "group is out of range");
	//if (attributes->group)
	//	return rte_flow_error_set(error, ENOTSUP,
	//				  RTE_FLOW_ERROR_TYPE_ATTR_GROUP,
	//				  NULL,
	//				  "groups is not supported");
	if (attributes->priority != MLX5_FLOW_PRIO_RSVD &&
	    attributes->priority > priority_max)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ATTR_PRIORITY,
					  NULL,
					  "priority out of range");
	if (attributes->transfer) {
		if (!priv->config.dv_eswitch_en)
			return rte_flow_error_set
						(error, ENOTSUP,
						RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
						NULL,
						"eswitch dr is not supported");
		if (!(priv->representor || priv->master))
			return rte_flow_error_set
					(error, EINVAL,
					 RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
					 NULL,
					 "eswitch configurationd can only be"
					 " done by a master or a representor"
					 " device");
		if (attributes->egress)
			return rte_flow_error_set
					(error, ENOTSUP,
					 RTE_FLOW_ERROR_TYPE_ATTR_EGRESS,
					 attributes, "egress is not supported");
		if (attributes->group >= MLX5_MAX_FDB_TABLES)
			return rte_flow_error_set
				       (error, EINVAL,
					RTE_FLOW_ERROR_TYPE_ATTR_TRANSFER,
					NULL,
					"group must be smaller than "
					RTE_STR(MLX5_MAX_FDB_TABLES));
	}
	if (!(attributes->egress ^ attributes->ingress))
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ATTR, NULL,
					  "must specify exactly one of "
					  "ingress or egress");
	return 0;
}

static int __rte_unused
flow_dv_translate_action_port_id(struct rte_eth_dev *dev,
				 const struct rte_flow_action *action,
				 const struct rte_flow_attr *attributes,
				 uint32_t *dst_port_id,
				 struct rte_flow_error *error)
{
	uint32_t port;
	uint16_t port_id;
	int ret;
	const struct rte_flow_action_port_id *conf =
			(const struct rte_flow_action_port_id *)action->conf;

	port = conf->original ? dev->data->port_id : conf->id;
	ret = mlx5_port_to_eswitch_info(port, NULL, &port_id);
	if (ret)
		return rte_flow_error_set(error, -ret,
					  RTE_FLOW_ERROR_TYPE_ACTION,
					  NULL,
					  "No eswitch info was found for port");
	*dst_port_id = port_id;
	(void)attributes;
	(void)error;
	return 0;
}

/**
 * Validate vport item.
 *
 * @param[in] item
 *   Pointer to port private info.
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
static int
flow_dv_validate_item_port_id(struct rte_eth_dev *dev,
			      const struct rte_flow_attr *attr,
			      const struct rte_flow_item *item,
			      uint64_t item_flags,
			      struct rte_flow_error *error)
{
	const struct rte_flow_item_port_id *spec = item->spec;
	const struct rte_flow_item_port_id *mask = item->mask;
	const struct rte_flow_item_port_id switch_mask = {
			.id = 0xffffffff,
	};
	uint16_t esw_domain_id;
	uint16_t item_port_esw_domain_id;
	uint16_t item_port_esw_port_id;
	uint16_t port;
	int ret;

	if (!attr->transfer)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM,
					  NULL,
					  "match on port id is valid for"
					  " eswitch only");
	if (item_flags & MLX5_FLOW_ITEM_PORT_ID)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "multiple source vport are not"
					  " supported");
	if (!mask)
		mask = &switch_mask;
	if (mask->id && mask->id != 0xffffffff)
		return rte_flow_error_set(error, ENOTSUP,
					   RTE_FLOW_ERROR_TYPE_ITEM_MASK,
					   mask,
					   "no support for partial mask on"
					   " \"id\" field");
	ret = mlx5_flow_item_acceptable
				(item, (const uint8_t *)mask,
				 (const uint8_t *)&rte_flow_item_port_id_mask,
				 sizeof(struct rte_flow_item_port_id),
				 error);
	if (ret)
		return ret;
	if (!spec)
		return 0;
	port = mask->id ? spec->id : 0;
	ret = mlx5_port_to_eswitch_info(port, &item_port_esw_domain_id,
					&item_port_esw_port_id);
	if (ret)
		return rte_flow_error_set(error, -ret,
					  RTE_FLOW_ERROR_TYPE_ITEM_SPEC, spec,
					  "failed to obtain eswitch info for"
					  " port");
	ret = mlx5_port_to_eswitch_info(dev->data->port_id,
					&esw_domain_id, NULL);
	if (ret < 0)
		return rte_flow_error_set(error, -ret,
					  RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
					  NULL,
					  "failed to obtain eswitch info");
	if (item_port_esw_domain_id != esw_domain_id)
		return rte_flow_error_set(error, -ret,
					  RTE_FLOW_ERROR_TYPE_ITEM_SPEC, spec,
					  "cannot match on a port from a"
					  " different eswitch");
	return 0;
}

/**
 * Internal validation function. For validating both actions and items.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
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
static int
flow_dv_validate(struct rte_eth_dev *dev, const struct rte_flow_attr *attr,
		 const struct rte_flow_item items[],
		 const struct rte_flow_action actions[],
		 struct rte_flow_error *error)
{
	int ret;
	uint64_t action_flags = 0;
	uint64_t item_flags = 0;
	int tunnel = 0;
	uint8_t next_protocol = 0xff;
	int actions_n = 0;
	int meters_n = 0;
	struct rte_flow_item_tcp nic_dr_supported_tcp_mask = {
		.hdr = { .tcp_flags = 0xFF,
			 .src_port = RTE_BE16(0xFFFF),
			 .dst_port = RTE_BE16(0xFFFF),
		}
	};
	int modify_action = 0;
#ifdef HAVE_IBV_FLOW_DEVX_COUNTERS
	struct priv *priv = dev->data->dev_private;
#endif

	if (items == NULL)
		return -1;
	ret = flow_dv_validate_attributes(dev, attr, error);
	if (ret < 0)
		return ret;
	for (; items->type != RTE_FLOW_ITEM_TYPE_END; items++) {
		tunnel = !!(item_flags & MLX5_FLOW_LAYER_TUNNEL);
		switch (items->type) {
		case RTE_FLOW_ITEM_TYPE_VOID:
			break;
		case RTE_FLOW_ITEM_TYPE_PORT_ID:
			ret = flow_dv_validate_item_port_id
					(dev, attr, items, item_flags, error);
			if (ret < 0)
				return ret;
			item_flags |= MLX5_FLOW_ITEM_PORT_ID;
			break;
		case RTE_FLOW_ITEM_TYPE_ETH:
			ret = mlx5_flow_validate_item_eth(items, item_flags,
							  error);
			if (ret < 0)
				return ret;
			item_flags |= tunnel ? MLX5_FLOW_LAYER_INNER_L2 :
					       MLX5_FLOW_LAYER_OUTER_L2;
			break;
		case RTE_FLOW_ITEM_TYPE_VLAN:
			ret = mlx5_flow_validate_item_vlan(items, item_flags,
							   error);
			if (ret < 0)
				return ret;
			item_flags |= tunnel ? MLX5_FLOW_LAYER_INNER_VLAN :
					       MLX5_FLOW_LAYER_OUTER_VLAN;
			break;
		case RTE_FLOW_ITEM_TYPE_IPV4:
			ret = mlx5_flow_validate_item_ipv4(items, item_flags,
							   error);
			if (ret < 0)
				return ret;
			item_flags |= tunnel ? MLX5_FLOW_LAYER_INNER_L3_IPV4 :
					       MLX5_FLOW_LAYER_OUTER_L3_IPV4;
			if (items->mask != NULL &&
			    ((const struct rte_flow_item_ipv4 *)
			     items->mask)->hdr.next_proto_id) {
				next_protocol =
					((const struct rte_flow_item_ipv4 *)
					 (items->spec))->hdr.next_proto_id;
				next_protocol &=
					((const struct rte_flow_item_ipv4 *)
					 (items->mask))->hdr.next_proto_id;
			} else {
				/* Reset for inner layer. */
				next_protocol = 0xff;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_IPV6:
			ret = mlx5_flow_validate_item_ipv6(items, item_flags,
							   error);
			if (ret < 0)
				return ret;
			item_flags |= tunnel ? MLX5_FLOW_LAYER_INNER_L3_IPV6 :
					       MLX5_FLOW_LAYER_OUTER_L3_IPV6;
			if (items->mask != NULL &&
			    ((const struct rte_flow_item_ipv6 *)
			     items->mask)->hdr.proto) {
				next_protocol =
					((const struct rte_flow_item_ipv6 *)
					 items->spec)->hdr.proto;
				next_protocol &=
					((const struct rte_flow_item_ipv6 *)
					 items->mask)->hdr.proto;
			} else {
				/* Reset for inner layer. */
				next_protocol = 0xff;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_TCP:
			ret = mlx5_flow_validate_item_tcp
						(items, item_flags,
						 next_protocol,
						 &nic_dr_supported_tcp_mask,
						 error);
			if (ret < 0)
				return ret;
			item_flags |= tunnel ? MLX5_FLOW_LAYER_INNER_L4_TCP :
					       MLX5_FLOW_LAYER_OUTER_L4_TCP;
			break;
		case RTE_FLOW_ITEM_TYPE_UDP:
			ret = mlx5_flow_validate_item_udp(items, item_flags,
							  next_protocol,
							  error);
			if (ret < 0)
				return ret;
			item_flags |= tunnel ? MLX5_FLOW_LAYER_INNER_L4_UDP :
					       MLX5_FLOW_LAYER_OUTER_L4_UDP;
			break;
		case RTE_FLOW_ITEM_TYPE_GRE:
		case RTE_FLOW_ITEM_TYPE_NVGRE:
			ret = mlx5_flow_validate_item_gre(items, item_flags,
							  next_protocol, error);
			if (ret < 0)
				return ret;
			item_flags |= MLX5_FLOW_LAYER_GRE;
			break;
		case RTE_FLOW_ITEM_TYPE_VXLAN:
			ret = mlx5_flow_validate_item_vxlan(items, item_flags,
							    error);
			if (ret < 0)
				return ret;
			item_flags |= MLX5_FLOW_LAYER_VXLAN;
			break;
		case RTE_FLOW_ITEM_TYPE_VXLAN_GPE:
			ret = mlx5_flow_validate_item_vxlan_gpe(items,
								item_flags, dev,
								error);
			if (ret < 0)
				return ret;
			item_flags |= MLX5_FLOW_LAYER_VXLAN_GPE;
			break;
		case RTE_FLOW_ITEM_TYPE_META:
			ret = flow_dv_validate_item_meta(dev, items, attr,
							 error, item_flags);
			if (ret < 0)
				return ret;
			item_flags |= MLX5_FLOW_ITEM_METADATA(0);
			break;
		case RTE_FLOW_ITEM_TYPE_META_EXT:
			ret = flow_dv_validate_item_meta_ext(dev, items, attr,
							     error, item_flags);
			if (ret < 0)
				return ret;
			item_flags |= MLX5_FLOW_ITEM_METADATA
			(((const struct rte_flow_item_meta_ext *)
			  (items->spec))->id);
			break;
		case RTE_FLOW_ITEM_TYPE_ICMP:
			ret = mlx5_flow_validate_item_icmp(items, item_flags,
							   next_protocol, error);
			if (ret < 0)
				return ret;
			item_flags |= MLX5_FLOW_LAYER_ICMP;
			break;
		case RTE_FLOW_ITEM_TYPE_ICMPV6:
			ret = mlx5_flow_validate_item_icmpv6(items, item_flags,
							    next_protocol, error);
			if (ret < 0)
				return ret;
			item_flags |= MLX5_FLOW_LAYER_ICMPV6;
			break;
		case RTE_FLOW_ITEM_TYPE_GRE_OPT_KEY:
			ret = mlx5_flow_validate_item_gre_opt_key
				(items, item_flags, error);
			if (ret < 0)
				return ret;
			item_flags |= MLX5_FLOW_LAYER_GRE_OPT_KEY;
			break;
		default:
			return rte_flow_error_set(error, ENOTSUP,
						  RTE_FLOW_ERROR_TYPE_ITEM,
						  NULL, "item not supported");
		}
	}
	for (; actions->type != RTE_FLOW_ACTION_TYPE_END; actions++) {
		if (actions_n == MLX5_DV_MAX_NUMBER_OF_ACTIONS)
			return rte_flow_error_set(error, ENOTSUP,
						  RTE_FLOW_ERROR_TYPE_ACTION,
						  actions, "too many actions");
		switch (actions->type) {
		case RTE_FLOW_ACTION_TYPE_VOID:
			break;
		case RTE_FLOW_ACTION_TYPE_PORT_ID:
			ret = flow_dv_validate_action_port_id
						(dev, attr,
						 actions, action_flags, error);
			if (ret)
				return ret;
			action_flags |= MLX5_FLOW_ACTION_PORT_ID;
			++actions_n;
			break;
		case RTE_FLOW_ACTION_TYPE_PF:
			ret = flow_dv_validate_action_pf
						(dev, attr,
						 action_flags, error);
			if (ret)
				return ret;
			action_flags |= MLX5_FLOW_ACTION_PF;
			++actions_n;
			break;
		case RTE_FLOW_ACTION_TYPE_FLAG:
			ret = mlx5_flow_validate_action_flag(action_flags,
							     attr, error);
			if (ret < 0)
				return ret;
			action_flags |= MLX5_FLOW_ACTION_FLAG;
			++actions_n;
			break;
		case RTE_FLOW_ACTION_TYPE_MARK:
			ret = mlx5_flow_validate_action_mark(actions,
							     action_flags,
							     attr, error);
			if (ret < 0)
				return ret;
			action_flags |= MLX5_FLOW_ACTION_MARK;
			++actions_n;
			break;
		case RTE_FLOW_ACTION_TYPE_DROP:
			ret = mlx5_flow_validate_action_drop(action_flags,
							     attr, error);
			if (ret < 0)
				return ret;
			action_flags |= MLX5_FLOW_ACTION_DROP;
			++actions_n;
			break;
		case RTE_FLOW_ACTION_TYPE_QUEUE:
			ret = mlx5_flow_validate_action_queue(actions,
							      action_flags, dev,
							      attr, error);
			if (ret < 0)
				return ret;
			action_flags |= MLX5_FLOW_ACTION_QUEUE;
			++actions_n;
			break;
		case RTE_FLOW_ACTION_TYPE_RSS:
			ret = mlx5_flow_validate_action_rss(actions,
							    action_flags, dev,
							    attr, error);
			if (ret < 0)
				return ret;
			action_flags |= MLX5_FLOW_ACTION_RSS;
			++actions_n;
			break;
		case RTE_FLOW_ACTION_TYPE_COUNT:
#ifdef HAVE_IBV_FLOW_DEVX_COUNTERS
			if (!priv->config.devx)
#endif
				return rte_flow_error_set
					       (error, ENOTSUP,
						RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
						NULL,
						"count action not supported");
			action_flags |= MLX5_FLOW_ACTION_COUNT;
			++actions_n;
			break;
		case RTE_FLOW_ACTION_TYPE_METER:
			meters_n++;
			ret = mlx5_flow_validate_action_meter(dev, actions,
							      attr, error);
			if (ret < 0)
				return ret;
			action_flags |= MLX5_FLOW_ACTION_METER;
			++actions_n;
			break;
		case RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP:
		case RTE_FLOW_ACTION_TYPE_NVGRE_ENCAP:
			ret = flow_dv_validate_action_l2_encap(action_flags,
							       actions, attr,
							       error);
			if (ret < 0)
				return ret;
			action_flags |= actions->type ==
					RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP ?
					MLX5_FLOW_ACTION_VXLAN_ENCAP :
					MLX5_FLOW_ACTION_NVGRE_ENCAP;
			++actions_n;
			break;
		case RTE_FLOW_ACTION_TYPE_VXLAN_DECAP:
		case RTE_FLOW_ACTION_TYPE_NVGRE_DECAP:
			ret = flow_dv_validate_action_l2_decap(action_flags,
							       attr, error);
			if (ret < 0)
				return ret;
			action_flags |= actions->type ==
					RTE_FLOW_ACTION_TYPE_VXLAN_DECAP ?
					MLX5_FLOW_ACTION_VXLAN_DECAP :
					MLX5_FLOW_ACTION_NVGRE_DECAP;
			++actions_n;
			break;
		case RTE_FLOW_ACTION_TYPE_RAW_ENCAP:
			ret = flow_dv_validate_action_raw_encap(action_flags,
								actions, attr,
								error);
			if (ret < 0)
				return ret;
			action_flags |= MLX5_FLOW_ACTION_RAW_ENCAP;
			++actions_n;
			break;
		case RTE_FLOW_ACTION_TYPE_RAW_DECAP:
			ret = flow_dv_validate_action_raw_decap(action_flags,
								actions, attr,
								error);
			if (ret < 0)
				return ret;
			action_flags |= MLX5_FLOW_ACTION_RAW_DECAP;
			++actions_n;
			break;
		case RTE_FLOW_ACTION_TYPE_JUMP:
			if (((const struct rte_flow_action_jump *)
			     actions->conf)->group >= MLX5_MAX_TABLES)
				return rte_flow_error_set
					(error, ENOTSUP,
					 RTE_FLOW_ERROR_TYPE_ACTION,
					 NULL,
					 "exceed max group id");
			action_flags |= MLX5_FLOW_ACTION_JUMP;
			++actions_n;
			break;
		case RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC:
			action_flags |= MLX5_FLOW_ACTION_SET_IPV4_SRC;
			if (!modify_action) {
				++actions_n;
				modify_action = 1;
			}
			break;
		case RTE_FLOW_ACTION_TYPE_SET_IPV4_DST:
			action_flags |= MLX5_FLOW_ACTION_SET_IPV4_DST;
			if (!modify_action) {
				++actions_n;
				modify_action = 1;
			}
			break;
		case RTE_FLOW_ACTION_TYPE_SET_IPV6_SRC:
			action_flags |= MLX5_FLOW_ACTION_SET_IPV6_SRC;
			if (!modify_action) {
				++actions_n;
				modify_action = 1;
			}
			break;
		case RTE_FLOW_ACTION_TYPE_SET_IPV6_DST:
			action_flags |= MLX5_FLOW_ACTION_SET_IPV6_DST;
			if (!modify_action) {
				++actions_n;
				modify_action = 1;
			}
			break;
		case RTE_FLOW_ACTION_TYPE_SET_TP_SRC:
			action_flags |= MLX5_FLOW_ACTION_SET_TP_SRC;
			if (!modify_action) {
				++actions_n;
				modify_action = 1;
			}
			break;
		case RTE_FLOW_ACTION_TYPE_SET_TP_DST:
			action_flags |= MLX5_FLOW_ACTION_SET_TP_DST;
			if (!modify_action) {
				++actions_n;
				modify_action = 1;
			}
			break;
		case RTE_FLOW_ACTION_TYPE_SET_TTL:
			action_flags |= MLX5_FLOW_ACTION_SET_TTL;
			if (!modify_action) {
				++actions_n;
				modify_action = 1;
			}
			break;
		case RTE_FLOW_ACTION_TYPE_DEC_TTL:
			action_flags |= MLX5_FLOW_ACTION_DEC_TTL;
			if (!modify_action) {
				++actions_n;
				modify_action = 1;
			}
			break;
		case RTE_FLOW_ACTION_TYPE_SET_MAC_SRC:
			action_flags |= MLX5_FLOW_ACTION_SET_MAC_SRC;
			if (!modify_action) {
				++actions_n;
				modify_action = 1;
			}
			break;
		case RTE_FLOW_ACTION_TYPE_SET_MAC_DST:
			action_flags |= MLX5_FLOW_ACTION_SET_MAC_DST;
			if (!modify_action) {
				++actions_n;
				modify_action = 1;
			}
			break;
		case RTE_FLOW_ACTION_TYPE_INC_TCP_SEQ:
			action_flags |= MLX5_FLOW_ACTION_INC_TCP_SEQ;
			if (!modify_action) {
				++actions_n;
				modify_action = 1;
			}
			break;
		case RTE_FLOW_ACTION_TYPE_DEC_TCP_SEQ:
			action_flags |= MLX5_FLOW_ACTION_DEC_TCP_SEQ;
			if (!modify_action) {
				++actions_n;
				modify_action = 1;
			}
			break;
		case RTE_FLOW_ACTION_TYPE_INC_TCP_ACK:
			action_flags |= MLX5_FLOW_ACTION_INC_TCP_ACK;
			if (!modify_action) {
				++actions_n;
				modify_action = 1;
			}
			break;
		case RTE_FLOW_ACTION_TYPE_DEC_TCP_ACK:
			action_flags |= MLX5_FLOW_ACTION_DEC_TCP_ACK;
			if (!modify_action) {
				++actions_n;
				modify_action = 1;
			}
			break;
		case RTE_FLOW_ACTION_TYPE_SET_META:
			ret = flow_dv_validate_action_set_meta(action_flags,
									actions, attr, error);
			if (ret < 0)
				return ret;
			action_flags |= MLX5_FLOW_ACTION_SET_META
			(((const struct rte_flow_action_set_meta *)(actions->conf))->id);
			if (!modify_action) {
				++actions_n;
				modify_action = 1;
			}
			break;
		default:
			return rte_flow_error_set(error, ENOTSUP,
						  RTE_FLOW_ERROR_TYPE_ACTION,
						  actions,
						  "action not supported");
		}
	}
	/* Eswitch has few restrictions on using items and actions */
	if (attr->transfer) {
		if (action_flags & MLX5_FLOW_ACTION_FLAG)
			return rte_flow_error_set(error, ENOTSUP,
						  RTE_FLOW_ERROR_TYPE_ACTION,
						  NULL,
						  "unsupported action FLAG");
		if (action_flags & MLX5_FLOW_ACTION_MARK)
			return rte_flow_error_set(error, ENOTSUP,
						  RTE_FLOW_ERROR_TYPE_ACTION,
						  NULL,
						  "unsupported action MARK");
		if (action_flags & MLX5_FLOW_ACTION_QUEUE)
			return rte_flow_error_set(error, ENOTSUP,
						  RTE_FLOW_ERROR_TYPE_ACTION,
						  NULL,
						  "unsupported action QUEUE");
		if (action_flags & MLX5_FLOW_ACTION_RSS)
			return rte_flow_error_set(error, ENOTSUP,
						  RTE_FLOW_ERROR_TYPE_ACTION,
						  NULL,
						  "unsupported action RSS");
		if (!(action_flags & MLX5_FLOW_ESWITCH_FATE_ACTIONS))
			return rte_flow_error_set(error, EINVAL,
						  RTE_FLOW_ERROR_TYPE_ACTION,
						  actions,
						  "no fate action is found");
	} else {
		if (!(action_flags & MLX5_FLOW_FATE_ACTIONS) && attr->ingress)
			return rte_flow_error_set(error, EINVAL,
						  RTE_FLOW_ERROR_TYPE_ACTION,
						  actions,
						  "no fate action is found");
	}
	if ((action_flags & MLX5_FLOW_ACTION_INC_TCP_SEQ) &&
	    (action_flags & MLX5_FLOW_ACTION_DEC_TCP_SEQ))
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION, actions,
					  "decrease and increase TCP sequence "
					  "number at same time");
	if ((action_flags & MLX5_FLOW_ACTION_INC_TCP_ACK) &&
	    (action_flags & MLX5_FLOW_ACTION_DEC_TCP_ACK))
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION, actions,
					  "decrease and increase TCP "
					  "acknowledgement number at "
					  "same time");
	if ((action_flags & MLX5_FLOW_ACTION_DROP) &&
	    (action_flags & MLX5_FLOW_ACTION_METER))
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION, actions,
					  "can't have meter and drop fate"
					  " action in same flow");
	if (meters_n > 1)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ACTION, actions,
					  "can't have meter more than one"
					  " meter action in same flow");
	return 0;
}

/**
 * Internal preparation function. Allocates the DV flow size,
 * this size is constant.
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
 *   Pointer to mlx5_flow object on success,
 *   otherwise NULL and rte_ernno is set.
 */
static struct mlx5_flow *
flow_dv_prepare(const struct rte_flow_attr *attr __rte_unused,
		const struct rte_flow_item items[] __rte_unused,
		const struct rte_flow_action actions[] __rte_unused,
		struct rte_flow_error *error)
{
	uint32_t size = sizeof(struct mlx5_flow);
	struct mlx5_flow *flow;

#ifdef RTE_LIBRTE_MLX5_FLOW_CACHE
	flow = rte_calloc(__func__, 1, size, 0);
#else
	if (!sflow)
		sflow = rte_calloc(__func__, 1, size, 0);
	else
		memset(sflow, 0, size);
	flow = sflow;
#endif
	if (!flow) {
		rte_flow_error_set(error, ENOMEM,
				   RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
				   "not enough memory to create flow");
		return NULL;
	}
	flow->dv.handle = rte_calloc(__func__, 1,
				     sizeof(struct mlx5_flow_handle), 0);
	if (!flow->dv.handle) {
		rte_flow_error_set(error, ENOMEM,
				   RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
				   "not enough memory to create flow");
		return NULL;
	}
	flow->dv.value.size = MLX5_ST_SZ_DB(fte_match_param);
	flow->dv.extra_value.size = MLX5_ST_SZ_DB(fte_match_param);
	return flow;
}

#ifndef NDEBUG
/**
 * Sanity check for match mask and value. Similar to check_valid_spec() in
 * kernel driver. If unmasked bit is present in value, it returns failure.
 *
 * @param match_mask
 *   pointer to match mask buffer.
 * @param match_value
 *   pointer to match value buffer.
 *
 * @return
 *   0 if valid, -EINVAL otherwise.
 */
static int
flow_dv_check_valid_spec(void *match_mask, void *match_value)
{
	uint8_t *m = match_mask;
	uint8_t *v = match_value;
	unsigned int i;

	for (i = 0; i < MLX5_ST_SZ_DB(fte_match_param); ++i) {
		if (v[i] & ~m[i]) {
			DRV_LOG(ERR,
				"match_value differs from match_criteria"
				" %p[%u] != %p[%u]",
				match_value, i, match_mask, i);
			return -EINVAL;
		}
	}
	return 0;
}
#endif

/**
 * Add Ethernet item to matcher and to the value.
 *
 * @param[in, out] matcher
 *   Flow matcher.
 * @param[in, out] key
 *   Flow matcher value.
 * @param[in] item
 *   Flow pattern to translate.
 * @param[in] inner
 *   Item is inner pattern.
 */
static void
flow_dv_translate_item_eth(void *matcher, void *key,
			   const struct rte_flow_item *item, int inner)
{
	const struct rte_flow_item_eth *eth_m = item->mask;
	const struct rte_flow_item_eth *eth_v = item->spec;
	const struct rte_flow_item_eth nic_mask = {
		.dst.addr_bytes = "\xff\xff\xff\xff\xff\xff",
		.src.addr_bytes = "\xff\xff\xff\xff\xff\xff",
		.type = RTE_BE16(0xffff),
	};
	void *headers_m;
	void *headers_v;
	char *l24_v;
	unsigned int i;

	if (!eth_v)
		return;
	if (!eth_m)
		eth_m = &nic_mask;
	if (inner) {
		headers_m = MLX5_ADDR_OF(fte_match_param, matcher,
					 inner_headers);
		headers_v = MLX5_ADDR_OF(fte_match_param, key, inner_headers);
	} else {
		headers_m = MLX5_ADDR_OF(fte_match_param, matcher,
					 outer_headers);
		headers_v = MLX5_ADDR_OF(fte_match_param, key, outer_headers);
	}
	memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_m, dmac_47_16),
	       &eth_m->dst, sizeof(eth_m->dst));
	/* The value must be in the range of the mask. */
	l24_v = MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v, dmac_47_16);
	for (i = 0; i < sizeof(eth_m->dst); ++i)
		l24_v[i] = eth_m->dst.addr_bytes[i] & eth_v->dst.addr_bytes[i];
	memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_m, smac_47_16),
	       &eth_m->src, sizeof(eth_m->src));
	l24_v = MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v, smac_47_16);
	/* The value must be in the range of the mask. */
	for (i = 0; i < sizeof(eth_m->dst); ++i)
		l24_v[i] = eth_m->src.addr_bytes[i] & eth_v->src.addr_bytes[i];
	MLX5_SET(fte_match_set_lyr_2_4, headers_m, ethertype,
		 rte_be_to_cpu_16(eth_m->type));
	l24_v = MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v, ethertype);
	*(uint16_t *)(l24_v) = eth_m->type & eth_v->type;
}

/**
 * Add VLAN item to matcher and to the value.
 *
 * @param[in, out] matcher
 *   Flow matcher.
 * @param[in, out] key
 *   Flow matcher value.
 * @param[in] item
 *   Flow pattern to translate.
 * @param[in] inner
 *   Item is inner pattern.
 */
static void
flow_dv_translate_item_vlan(void *matcher, void *key,
			    const struct rte_flow_item *item,
			    int inner)
{
	const struct rte_flow_item_vlan *vlan_m = item->mask;
	const struct rte_flow_item_vlan *vlan_v = item->spec;
	const struct rte_flow_item_vlan nic_mask = {
		.tci = RTE_BE16(0x0fff),
		.tpid = RTE_BE16(0xffff),
	};
	void *headers_m;
	void *headers_v;
	uint16_t tci_m;
	uint16_t tci_v;

	if (!vlan_v)
		return;
	if (!vlan_m)
		vlan_m = &nic_mask;
	if (inner) {
		headers_m = MLX5_ADDR_OF(fte_match_param, matcher,
					 inner_headers);
		headers_v = MLX5_ADDR_OF(fte_match_param, key, inner_headers);
	} else {
		headers_m = MLX5_ADDR_OF(fte_match_param, matcher,
					 outer_headers);
		headers_v = MLX5_ADDR_OF(fte_match_param, key, outer_headers);
	}
	tci_m = rte_be_to_cpu_16(vlan_m->tci);
	tci_v = rte_be_to_cpu_16(vlan_m->tci & vlan_v->tci);
	MLX5_SET(fte_match_set_lyr_2_4, headers_m, cvlan_tag, 1);
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, cvlan_tag, 1);
	MLX5_SET(fte_match_set_lyr_2_4, headers_m, first_vid, tci_m);
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, first_vid, tci_v);
	MLX5_SET(fte_match_set_lyr_2_4, headers_m, first_cfi, tci_m >> 12);
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, first_cfi, tci_v >> 12);
	MLX5_SET(fte_match_set_lyr_2_4, headers_m, first_prio, tci_m >> 13);
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, first_prio, tci_v >> 13);
}

/**
 * Add IPV4 item to matcher and to the value.
 *
 * @param[in, out] matcher
 *   Flow matcher.
 * @param[in, out] key
 *   Flow matcher value.
 * @param[in] item
 *   Flow pattern to translate.
 * @param[in] inner
 *   Item is inner pattern.
 */
static void
flow_dv_translate_item_ipv4(void *matcher, void *key,
			    const struct rte_flow_item *item,
			    int inner, int group)
{
	const struct rte_flow_item_ipv4 *ipv4_m = item->mask;
	const struct rte_flow_item_ipv4 *ipv4_v = item->spec;
	const struct rte_flow_item_ipv4 nic_mask = {
		.hdr = {
			.src_addr = RTE_BE32(0xffffffff),
			.dst_addr = RTE_BE32(0xffffffff),
			.type_of_service = 0xff,
			.next_proto_id = 0xff,
		},
	};
	void *headers_m;
	void *headers_v;
	char *l24_m;
	char *l24_v;
	uint8_t tos;

	if (inner) {
		headers_m = MLX5_ADDR_OF(fte_match_param, matcher,
					 inner_headers);
		headers_v = MLX5_ADDR_OF(fte_match_param, key, inner_headers);
	} else {
		headers_m = MLX5_ADDR_OF(fte_match_param, matcher,
					 outer_headers);
		headers_v = MLX5_ADDR_OF(fte_match_param, key, outer_headers);
	}
	if (group == 0)
		MLX5_SET(fte_match_set_lyr_2_4, headers_m, ip_version, 0xf); 
	else
		MLX5_SET(fte_match_set_lyr_2_4, headers_m, ip_version, 0x4);  
	/**< Mask version is set to 4 due to dr limitation >*/
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_version, 4);
	if (!ipv4_v)
		return;
	if (!ipv4_m)
		ipv4_m = &nic_mask;
	l24_m = MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_m,
			     dst_ipv4_dst_ipv6.ipv4_layout.ipv4);
	l24_v = MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
			     dst_ipv4_dst_ipv6.ipv4_layout.ipv4);
	*(uint32_t *)l24_m = ipv4_m->hdr.dst_addr;
	*(uint32_t *)l24_v = ipv4_m->hdr.dst_addr & ipv4_v->hdr.dst_addr;
	l24_m = MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_m,
			  src_ipv4_src_ipv6.ipv4_layout.ipv4);
	l24_v = MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
			  src_ipv4_src_ipv6.ipv4_layout.ipv4);
	*(uint32_t *)l24_m = ipv4_m->hdr.src_addr;
	*(uint32_t *)l24_v = ipv4_m->hdr.src_addr & ipv4_v->hdr.src_addr;
	tos = ipv4_m->hdr.type_of_service & ipv4_v->hdr.type_of_service;
	MLX5_SET(fte_match_set_lyr_2_4, headers_m, ip_ecn,
		 ipv4_m->hdr.type_of_service);
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_ecn, tos);
	MLX5_SET(fte_match_set_lyr_2_4, headers_m, ip_dscp,
		 ipv4_m->hdr.type_of_service >> 2);
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_dscp, tos >> 2);
	MLX5_SET(fte_match_set_lyr_2_4, headers_m, ip_protocol,
		 ipv4_m->hdr.next_proto_id);
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_protocol,
		 ipv4_v->hdr.next_proto_id & ipv4_m->hdr.next_proto_id);
}

/**
 * Add IPV6 item to matcher and to the value.
 *
 * @param[in, out] matcher
 *   Flow matcher.
 * @param[in, out] key
 *   Flow matcher value.
 * @param[in] item
 *   Flow pattern to translate.
 * @param[in] inner
 *   Item is inner pattern.
 */
static void
flow_dv_translate_item_ipv6(void *matcher, void *key,
			    const struct rte_flow_item *item,
			    int inner, int group)
{
	const struct rte_flow_item_ipv6 *ipv6_m = item->mask;
	const struct rte_flow_item_ipv6 *ipv6_v = item->spec;
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
	void *headers_m;
	void *headers_v;
	void *misc_m = MLX5_ADDR_OF(fte_match_param, matcher, misc_parameters);
	void *misc_v = MLX5_ADDR_OF(fte_match_param, key, misc_parameters);
	char *l24_m;
	char *l24_v;
	uint32_t vtc_m;
	uint32_t vtc_v;
	int i;
	int size;

	if (inner) {
		headers_m = MLX5_ADDR_OF(fte_match_param, matcher,
					 inner_headers);
		headers_v = MLX5_ADDR_OF(fte_match_param, key, inner_headers);
	} else {
		headers_m = MLX5_ADDR_OF(fte_match_param, matcher,
					 outer_headers);
		headers_v = MLX5_ADDR_OF(fte_match_param, key, outer_headers);
	}
	if (group == 0)
		MLX5_SET(fte_match_set_lyr_2_4, headers_m, ip_version, 0xf); 
	else
		MLX5_SET(fte_match_set_lyr_2_4, headers_m, ip_version, 0x6);  
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_version, 6);
	if (!ipv6_v)
		return;
	if (!ipv6_m)
		ipv6_m = &nic_mask;
	size = sizeof(ipv6_m->hdr.dst_addr);
	l24_m = MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_m,
			     dst_ipv4_dst_ipv6.ipv6_layout.ipv6);
	l24_v = MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
			     dst_ipv4_dst_ipv6.ipv6_layout.ipv6);
	memcpy(l24_m, ipv6_m->hdr.dst_addr, size);
	for (i = 0; i < size; ++i)
		l24_v[i] = l24_m[i] & ipv6_v->hdr.dst_addr[i];
	l24_m = MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_m,
			     src_ipv4_src_ipv6.ipv6_layout.ipv6);
	l24_v = MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
			     src_ipv4_src_ipv6.ipv6_layout.ipv6);
	memcpy(l24_m, ipv6_m->hdr.src_addr, size);
	for (i = 0; i < size; ++i)
		l24_v[i] = l24_m[i] & ipv6_v->hdr.src_addr[i];
	/* TOS. */
	vtc_m = rte_be_to_cpu_32(ipv6_m->hdr.vtc_flow);
	vtc_v = rte_be_to_cpu_32(ipv6_m->hdr.vtc_flow & ipv6_v->hdr.vtc_flow);
	MLX5_SET(fte_match_set_lyr_2_4, headers_m, ip_ecn, vtc_m >> 20);
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_ecn, vtc_v >> 20);
	MLX5_SET(fte_match_set_lyr_2_4, headers_m, ip_dscp, vtc_m >> 22);
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_dscp, vtc_v >> 22);
	/* Label. */
	if (inner) {
		MLX5_SET(fte_match_set_misc, misc_m, inner_ipv6_flow_label,
			 vtc_m);
		MLX5_SET(fte_match_set_misc, misc_v, inner_ipv6_flow_label,
			 vtc_v);
	} else {
		MLX5_SET(fte_match_set_misc, misc_m, outer_ipv6_flow_label,
			 vtc_m);
		MLX5_SET(fte_match_set_misc, misc_v, outer_ipv6_flow_label,
			 vtc_v);
	}
	/* Protocol. */
	MLX5_SET(fte_match_set_lyr_2_4, headers_m, ip_protocol,
		 ipv6_m->hdr.proto);
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_protocol,
		 ipv6_v->hdr.proto & ipv6_m->hdr.proto);
}

/**
 * Add TCP item to matcher and to the value.
 *
 * @param[in, out] matcher
 *   Flow matcher.
 * @param[in, out] key
 *   Flow matcher value.
 * @param[in] item
 *   Flow pattern to translate.
 * @param[in] inner
 *   Item is inner pattern.
 */
static void
flow_dv_translate_item_tcp(void *matcher, void *key,
			   const struct rte_flow_item *item,
			   int inner)
{
	const struct rte_flow_item_tcp *tcp_m = item->mask;
	const struct rte_flow_item_tcp *tcp_v = item->spec;
	void *headers_m;
	void *headers_v;

	if (inner) {
		headers_m = MLX5_ADDR_OF(fte_match_param, matcher,
					 inner_headers);
		headers_v = MLX5_ADDR_OF(fte_match_param, key, inner_headers);
	} else {
		headers_m = MLX5_ADDR_OF(fte_match_param, matcher,
					 outer_headers);
		headers_v = MLX5_ADDR_OF(fte_match_param, key, outer_headers);
	}
	MLX5_SET(fte_match_set_lyr_2_4, headers_m, ip_protocol, 0xff);
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_protocol, IPPROTO_TCP);
	if (!tcp_v)
		return;
	if (!tcp_m)
		tcp_m = &rte_flow_item_tcp_mask;
	MLX5_SET(fte_match_set_lyr_2_4, headers_m, tcp_sport,
		 rte_be_to_cpu_16(tcp_m->hdr.src_port));
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, tcp_sport,
		 rte_be_to_cpu_16(tcp_v->hdr.src_port & tcp_m->hdr.src_port));
	MLX5_SET(fte_match_set_lyr_2_4, headers_m, tcp_dport,
		 rte_be_to_cpu_16(tcp_m->hdr.dst_port));
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, tcp_dport,
		 rte_be_to_cpu_16(tcp_v->hdr.dst_port & tcp_m->hdr.dst_port));
	MLX5_SET(fte_match_set_lyr_2_4, headers_m, tcp_flags,
		 tcp_m->hdr.tcp_flags);
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, tcp_flags,
		 (tcp_v->hdr.tcp_flags & tcp_m->hdr.tcp_flags));
}

/**
 * Add UDP item to matcher and to the value.
 *
 * @param[in, out] matcher
 *   Flow matcher.
 * @param[in, out] key
 *   Flow matcher value.
 * @param[in] item
 *   Flow pattern to translate.
 * @param[in] inner
 *   Item is inner pattern.
 */
static void
flow_dv_translate_item_udp(void *matcher, void *key,
			   const struct rte_flow_item *item,
			   int inner)
{
	const struct rte_flow_item_udp *udp_m = item->mask;
	const struct rte_flow_item_udp *udp_v = item->spec;
	void *headers_m;
	void *headers_v;

	if (inner) {
		headers_m = MLX5_ADDR_OF(fte_match_param, matcher,
					 inner_headers);
		headers_v = MLX5_ADDR_OF(fte_match_param, key, inner_headers);
	} else {
		headers_m = MLX5_ADDR_OF(fte_match_param, matcher,
					 outer_headers);
		headers_v = MLX5_ADDR_OF(fte_match_param, key, outer_headers);
	}
	MLX5_SET(fte_match_set_lyr_2_4, headers_m, ip_protocol, 0xff);
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_protocol, IPPROTO_UDP);
	if (!udp_v)
		return;
	if (!udp_m)
		udp_m = &rte_flow_item_udp_mask;
	MLX5_SET(fte_match_set_lyr_2_4, headers_m, udp_sport,
		 rte_be_to_cpu_16(udp_m->hdr.src_port));
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, udp_sport,
		 rte_be_to_cpu_16(udp_v->hdr.src_port & udp_m->hdr.src_port));
	MLX5_SET(fte_match_set_lyr_2_4, headers_m, udp_dport,
		 rte_be_to_cpu_16(udp_m->hdr.dst_port));
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, udp_dport,
		 rte_be_to_cpu_16(udp_v->hdr.dst_port & udp_m->hdr.dst_port));
}

/**
 * Add GRE optional Key item to matcher and to the value.
 *
 * @param[in, out] matcher
 *   Flow matcher.
 * @param[in, out] key
 *   Flow matcher value.
 * @param[in] item
 *   Flow pattern to translate.
 * @param[in] inner
 *   Item is inner pattern.
 */
static void
flow_dv_translate_item_gre_opt_key(void *matcher, void *key,
				   const struct rte_flow_item *item)
{
	const struct rte_flow_item_gre_opt_key *key_m = item->mask;
	const struct rte_flow_item_gre_opt_key *key_v = item->spec;
	void *misc_m = MLX5_ADDR_OF(fte_match_param, matcher, misc_parameters);
	void *misc_v = MLX5_ADDR_OF(fte_match_param, key, misc_parameters);

	if (!key_v)
		return;
	if (!key_m)
		key_m = &rte_flow_item_gre_opt_key_mask;
	MLX5_SET(fte_match_set_misc, misc_m, gre_k_present, 1);
	MLX5_SET(fte_match_set_misc, misc_v, gre_k_present, 1);
	MLX5_SET(fte_match_set_misc, misc_m, gre_key_h,
		 rte_be_to_cpu_32(key_m->key) >> 8);
	MLX5_SET(fte_match_set_misc, misc_v, gre_key_h,
		 rte_be_to_cpu_32(key_v->key & key_m->key) >> 8);
	MLX5_SET(fte_match_set_misc, misc_m, gre_key_l,
		 rte_be_to_cpu_32(key_m->key) & 0xFF);
	MLX5_SET(fte_match_set_misc, misc_v, gre_key_l,
		 rte_be_to_cpu_32(key_v->key & key_m->key) & 0xFF);
}

/**
 * Add GRE item to matcher and to the value.
 *
 * @param[in, out] matcher
 *   Flow matcher.
 * @param[in, out] key
 *   Flow matcher value.
 * @param[in] item
 *   Flow pattern to translate.
 * @param[in] inner
 *   Item is inner pattern.
 */
static void
flow_dv_translate_item_gre(void *matcher, void *key,
			   const struct rte_flow_item *item,
			   int inner)
{
	const struct rte_flow_item_gre *gre_m = item->mask;
	const struct rte_flow_item_gre *gre_v = item->spec;
	void *headers_m;
	void *headers_v;
	void *misc_m = MLX5_ADDR_OF(fte_match_param, matcher, misc_parameters);
	void *misc_v = MLX5_ADDR_OF(fte_match_param, key, misc_parameters);
	struct {
		union {
			__extension__
			struct {
				uint16_t version:3;
				uint16_t rsvd0:9;
				uint16_t s_present:1;
				uint16_t k_present:1;
				uint16_t rsvd_bit1:1;
				uint16_t c_present:1;
			};
			uint16_t value;
		};
	} gre_crks_rsvd0_ver_m, gre_crks_rsvd0_ver_v;

	if (inner) {
		headers_m = MLX5_ADDR_OF(fte_match_param, matcher,
					 inner_headers);
		headers_v = MLX5_ADDR_OF(fte_match_param, key, inner_headers);
	} else {
		headers_m = MLX5_ADDR_OF(fte_match_param, matcher,
					 outer_headers);
		headers_v = MLX5_ADDR_OF(fte_match_param, key, outer_headers);
	}
	MLX5_SET(fte_match_set_lyr_2_4, headers_m, ip_protocol, 0xff);
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_protocol, IPPROTO_GRE);
	if (!gre_v)
		return;
	if (!gre_m)
		gre_m = &rte_flow_item_gre_mask;
	MLX5_SET(fte_match_set_misc, misc_m, gre_protocol,
		 rte_be_to_cpu_16(gre_m->protocol));
	MLX5_SET(fte_match_set_misc, misc_v, gre_protocol,
		 rte_be_to_cpu_16(gre_v->protocol & gre_m->protocol));
	gre_crks_rsvd0_ver_m.value = rte_be_to_cpu_16(gre_m->c_rsvd0_ver);
	gre_crks_rsvd0_ver_v.value = rte_be_to_cpu_16(gre_v->c_rsvd0_ver);
	MLX5_SET(fte_match_set_misc, misc_m, gre_c_present,
		 gre_crks_rsvd0_ver_m.c_present);
	MLX5_SET(fte_match_set_misc, misc_v, gre_c_present,
		 gre_crks_rsvd0_ver_v.c_present &
		 gre_crks_rsvd0_ver_m.c_present);
	MLX5_SET(fte_match_set_misc, misc_m, gre_k_present,
		 gre_crks_rsvd0_ver_m.k_present);
	MLX5_SET(fte_match_set_misc, misc_v, gre_k_present,
		 gre_crks_rsvd0_ver_v.k_present &
		 gre_crks_rsvd0_ver_m.k_present);
	MLX5_SET(fte_match_set_misc, misc_m, gre_s_present,
		 gre_crks_rsvd0_ver_m.s_present);
	MLX5_SET(fte_match_set_misc, misc_v, gre_s_present,
		 gre_crks_rsvd0_ver_v.s_present &
		 gre_crks_rsvd0_ver_m.s_present);
}

/**
 * Add NVGRE item to matcher and to the value.
 *
 * @param[in, out] matcher
 *   Flow matcher.
 * @param[in, out] key
 *   Flow matcher value.
 * @param[in] item
 *   Flow pattern to translate.
 * @param[in] inner
 *   Item is inner pattern.
 */
static void
flow_dv_translate_item_nvgre(void *matcher, void *key,
			     const struct rte_flow_item *item,
			     int inner)
{
	const struct rte_flow_item_nvgre *nvgre_m = item->mask;
	const struct rte_flow_item_nvgre *nvgre_v = item->spec;
	void *misc_m = MLX5_ADDR_OF(fte_match_param, matcher, misc_parameters);
	void *misc_v = MLX5_ADDR_OF(fte_match_param, key, misc_parameters);
	const char *tni_flow_id_m = (const char *)nvgre_m->tni;
	const char *tni_flow_id_v = (const char *)nvgre_v->tni;
	char *gre_key_m;
	char *gre_key_v;
	int size;
	int i;

	flow_dv_translate_item_gre(matcher, key, item, inner);
	if (!nvgre_v)
		return;
	if (!nvgre_m)
		nvgre_m = &rte_flow_item_nvgre_mask;
	size = sizeof(nvgre_m->tni) + sizeof(nvgre_m->flow_id);
	gre_key_m = MLX5_ADDR_OF(fte_match_set_misc, misc_m, gre_key_h);
	gre_key_v = MLX5_ADDR_OF(fte_match_set_misc, misc_v, gre_key_h);
	memcpy(gre_key_m, tni_flow_id_m, size);
	for (i = 0; i < size; ++i)
		gre_key_v[i] = gre_key_m[i] & tni_flow_id_v[i];
}

/**
 * Add VXLAN item to matcher and to the value.
 *
 * @param[in, out] matcher
 *   Flow matcher.
 * @param[in, out] key
 *   Flow matcher value.
 * @param[in] item
 *   Flow pattern to translate.
 * @param[in] inner
 *   Item is inner pattern.
 */
static void
flow_dv_translate_item_vxlan(void *matcher, void *key,
			     const struct rte_flow_item *item,
			     int inner)
{
	const struct rte_flow_item_vxlan *vxlan_m = item->mask;
	const struct rte_flow_item_vxlan *vxlan_v = item->spec;
	void *headers_m;
	void *headers_v;
	void *misc_m = MLX5_ADDR_OF(fte_match_param, matcher, misc_parameters);
	void *misc_v = MLX5_ADDR_OF(fte_match_param, key, misc_parameters);
	char *vni_m;
	char *vni_v;
	uint16_t dport;
	int size;
	int i;

	if (inner) {
		headers_m = MLX5_ADDR_OF(fte_match_param, matcher,
					 inner_headers);
		headers_v = MLX5_ADDR_OF(fte_match_param, key, inner_headers);
	} else {
		headers_m = MLX5_ADDR_OF(fte_match_param, matcher,
					 outer_headers);
		headers_v = MLX5_ADDR_OF(fte_match_param, key, outer_headers);
	}
	dport = item->type == RTE_FLOW_ITEM_TYPE_VXLAN ?
		MLX5_UDP_PORT_VXLAN : MLX5_UDP_PORT_VXLAN_GPE;
	if (!MLX5_GET16(fte_match_set_lyr_2_4, headers_v, udp_dport)) {
		MLX5_SET(fte_match_set_lyr_2_4, headers_m, udp_dport, 0xFFFF);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, udp_dport, dport);
	}
	if (!vxlan_v)
		return;
	if (!vxlan_m)
		vxlan_m = &rte_flow_item_vxlan_mask;
	size = sizeof(vxlan_m->vni);
	vni_m = MLX5_ADDR_OF(fte_match_set_misc, misc_m, vxlan_vni);
	vni_v = MLX5_ADDR_OF(fte_match_set_misc, misc_v, vxlan_vni);
	memcpy(vni_m, vxlan_m->vni, size);
	for (i = 0; i < size; ++i)
		vni_v[i] = vni_m[i] & vxlan_v->vni[i];
}

/**
 * Add VXLAN-GPE item to matcher and to the value.
 *
 * @param[in, out] matcher
 *   Flow matcher.
 * @param[in, out] key
 *   Flow matcher value.
 * @param[in] item
 *   Flow pattern to translate.
 * @param[in] inner
 *   Item is inner pattern.
 */
static void
flow_dv_translate_item_vxlan_gpe(void *matcher, void *key,
				 const struct rte_flow_item *item,
				 int inner)
{
	const struct rte_flow_item_vxlan_gpe *vxlan_m = item->mask;
	const struct rte_flow_item_vxlan_gpe *vxlan_v = item->spec;
	void *headers_m;
	void *headers_v;
	void *misc3_m =
		MLX5_ADDR_OF(fte_match_param, matcher, misc_parameters_3);
	void *misc3_v =
		MLX5_ADDR_OF(fte_match_param, key, misc_parameters_3);
	char *vni_m;
	char *vni_v;
	uint16_t dport;
	int size;
	int i;
	uint8_t flags_m = 0xff;
	uint8_t flags_v = 0xc;

	if (inner) {
		headers_m = MLX5_ADDR_OF(fte_match_param, matcher,
					 inner_headers);
		headers_v = MLX5_ADDR_OF(fte_match_param, key, inner_headers);
	} else {
		headers_m = MLX5_ADDR_OF(fte_match_param, matcher,
					 outer_headers);
		headers_v = MLX5_ADDR_OF(fte_match_param, key, outer_headers);
	}
	dport = item->type == RTE_FLOW_ITEM_TYPE_VXLAN ?
		MLX5_UDP_PORT_VXLAN : MLX5_UDP_PORT_VXLAN_GPE;
	if (!MLX5_GET16(fte_match_set_lyr_2_4, headers_v, udp_dport)) {
		MLX5_SET(fte_match_set_lyr_2_4, headers_m, udp_dport, 0xFFFF);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, udp_dport, dport);
	}
	if (!vxlan_v)
		return;
	if (!vxlan_m)
		vxlan_m = &rte_flow_item_vxlan_gpe_mask;
	size = sizeof(vxlan_m->vni);
	vni_m = MLX5_ADDR_OF(fte_match_set_misc3, misc3_m, outer_vxlan_gpe_vni);
	vni_v = MLX5_ADDR_OF(fte_match_set_misc3, misc3_v, outer_vxlan_gpe_vni);
	memcpy(vni_m, vxlan_m->vni, size);
	for (i = 0; i < size; ++i)
		vni_v[i] = vni_m[i] & vxlan_v->vni[i];
	if (vxlan_m->flags) {
		flags_m = vxlan_m->flags;
		flags_v = vxlan_v->flags;
	}
	MLX5_SET(fte_match_set_misc3, misc3_m, outer_vxlan_gpe_flags, flags_m);
	MLX5_SET(fte_match_set_misc3, misc3_v, outer_vxlan_gpe_flags, flags_v);
	MLX5_SET(fte_match_set_misc3, misc3_m, outer_vxlan_gpe_next_protocol,
		 vxlan_m->protocol);
	MLX5_SET(fte_match_set_misc3, misc3_v, outer_vxlan_gpe_next_protocol,
		 vxlan_v->protocol);
}

/**
 * Add Reg item to matcher
 *
 * @param[in, out] matcher
 *   Flow matcher.
 * @param[in, out] key
 *   Flow matcher value.
 * @param[in] reg
 *   Flow pattern to translate.
 */
static void
flow_dv_translate_item_reg(void *matcher, void *key, enum modify_reg reg,
			   uint32_t value, uint32_t mask)
{
	void *misc2_m =
		MLX5_ADDR_OF(fte_match_param, matcher, misc_parameters_2);
	void *misc2_v =
		MLX5_ADDR_OF(fte_match_param, key, misc_parameters_2);


	switch (reg) {
	case REG_A:
		MLX5_SET(fte_match_set_misc2, misc2_m, metadata_reg_a,
				rte_be_to_cpu_32(mask));
		MLX5_SET(fte_match_set_misc2, misc2_v, metadata_reg_a,
				rte_be_to_cpu_32(value));
		break;
	case REG_B:
		MLX5_SET(fte_match_set_misc2, misc2_m, metadata_reg_b,
				 rte_be_to_cpu_32(mask));
		MLX5_SET(fte_match_set_misc2, misc2_v, metadata_reg_b,
				rte_be_to_cpu_32(value));
		break;
	case REG_C_0:
		MLX5_SET(fte_match_set_misc2, misc2_m, metadata_reg_c_0,
				 rte_be_to_cpu_32(mask));
		MLX5_SET(fte_match_set_misc2, misc2_v, metadata_reg_c_0,
				rte_be_to_cpu_32(value));
		break;
	case REG_C_1:
		MLX5_SET(fte_match_set_misc2, misc2_m, metadata_reg_c_1,
				 rte_be_to_cpu_32(mask));
		MLX5_SET(fte_match_set_misc2, misc2_v, metadata_reg_c_1,
				rte_be_to_cpu_32(value));
		break;
	case REG_C_2:
		MLX5_SET(fte_match_set_misc2, misc2_m, metadata_reg_c_2,
				 rte_be_to_cpu_32(mask));
		MLX5_SET(fte_match_set_misc2, misc2_v, metadata_reg_c_2,
				rte_be_to_cpu_32(value));
		break;
	case REG_C_3:
		MLX5_SET(fte_match_set_misc2, misc2_m, metadata_reg_c_3,
				 rte_be_to_cpu_32(mask));
		MLX5_SET(fte_match_set_misc2, misc2_v, metadata_reg_c_3,
				rte_be_to_cpu_32(value));
		break;
	case REG_C_4:
		MLX5_SET(fte_match_set_misc2, misc2_m, metadata_reg_c_4,
				 rte_be_to_cpu_32(mask));
		MLX5_SET(fte_match_set_misc2, misc2_v, metadata_reg_c_4,
				rte_be_to_cpu_32(value));
		break;
	case REG_C_5:
		MLX5_SET(fte_match_set_misc2, misc2_m, metadata_reg_c_5,
				 rte_be_to_cpu_32(mask));
		MLX5_SET(fte_match_set_misc2, misc2_v, metadata_reg_c_5,
				rte_be_to_cpu_32(value));
		break;
	case REG_C_6:
		MLX5_SET(fte_match_set_misc2, misc2_m, metadata_reg_c_6,
				 rte_be_to_cpu_32(mask));
		MLX5_SET(fte_match_set_misc2, misc2_v, metadata_reg_c_6,
				rte_be_to_cpu_32(value));
		break;
	case REG_C_7:
		MLX5_SET(fte_match_set_misc2, misc2_m, metadata_reg_c_7,
				 rte_be_to_cpu_32(mask));
		MLX5_SET(fte_match_set_misc2, misc2_v, metadata_reg_c_7,
				rte_be_to_cpu_32(value));
		break;
	}
}
/**
 *
 * Add META item to matcher
 *
 * @param[in, out] matcher
 *   Flow matcher.
 * @param[in, out] key
 *   Flow matcher value.
 * @param[in] item
 *   Flow pattern to translate.
 * @param[in] inner
 *   Item is inner pattern.
 */
static void
flow_dv_translate_item_meta(void *matcher, void *key,
			    const struct rte_flow_item *item)
{
	const struct rte_flow_item_meta *meta_m;
	const struct rte_flow_item_meta *meta_v;

	meta_m = (const void *)item->mask;
	if (!meta_m)
		meta_m = &rte_flow_item_meta_mask;
	meta_v = (const void *)item->spec;
	flow_dv_translate_item_reg(matcher, key, metaid2reg[0],
			meta_v->data & meta_m->data, meta_m->data);
}
/**
 * Add META item to matcher
 *
 * @param[in, out] matcher
 *   Flow matcher.
 * @param[in, out] key
 *   Flow matcher value.
 * @param[in] item
 *   Flow pattern to translate.
 * @param[in] inner
 *   Item is inner pattern.
 */
static void
flow_dv_translate_item_meta_ext(void *matcher, void *key,
			    const struct rte_flow_item *item)
{
	const struct rte_flow_item_meta_ext *meta_m;
	const struct rte_flow_item_meta_ext *meta_v;

	meta_m = (const void *)item->mask;
	if (!meta_m)
		meta_m = &rte_flow_item_meta_ext_mask;
	meta_v = (const void *)item->spec;
	flow_dv_translate_item_reg(matcher, key, metaid2reg[meta_v->id],
			meta_v->data & meta_m->data, meta_m->data);
}

/**
 * Add ICMPV6 item to matcher and to the value.
 * @param[in] item
 *   Flow pattern to translate.
 * @param[in] inner
 *   Item is inner pattern.
 */
static void
flow_dv_translate_item_icmpv6(void *matcher, void *key,
			      const struct rte_flow_item *item,
			      int inner)
{
	const struct rte_flow_item_icmpv6 *icmpv6_m = item->mask;
	const struct rte_flow_item_icmpv6 *icmpv6_v = item->spec;
	void *headers_m;
	void *headers_v;
	void *misc3_m = MLX5_ADDR_OF(fte_match_param, matcher,
				     misc_parameters_3);
	void *misc3_v = MLX5_ADDR_OF(fte_match_param, key, misc_parameters_3);
	if (inner) {
		headers_m = MLX5_ADDR_OF(fte_match_param, matcher,
					 inner_headers);
		headers_v = MLX5_ADDR_OF(fte_match_param, key, inner_headers);
	} else {
		headers_m = MLX5_ADDR_OF(fte_match_param, matcher,
					 outer_headers);
		headers_v = MLX5_ADDR_OF(fte_match_param, key, outer_headers);
	}
	MLX5_SET(fte_match_set_lyr_2_4, headers_m, ip_protocol, 0xFF);
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_protocol, 58); /* ICMPV6 */
	if (!icmpv6_v)
		return;
	if (!icmpv6_m)
		icmpv6_m = &rte_flow_item_icmpv6_mask;
	MLX5_SET(fte_match_set_misc3, misc3_m, icmpv6_type, icmpv6_m->hdr.icmp_type);
	MLX5_SET(fte_match_set_misc3, misc3_v, icmpv6_type,
		 icmpv6_v->hdr.icmp_type & icmpv6_m->hdr.icmp_type);
	MLX5_SET(fte_match_set_misc3, misc3_m, icmpv6_code, icmpv6_m->hdr.icmp_code);
	MLX5_SET(fte_match_set_misc3, misc3_v, icmpv6_code,
		 icmpv6_v->hdr.icmp_code & icmpv6_m->hdr.icmp_code);
}

/**
 * Add ICMP item to matcher and to the value.
 *
 * @param[in, out] matcher
 *   Flow matcher.
 * @param[in, out] key
 *   Flow matcher value.
 * @param[in] item
 *   Flow pattern to translate.
 * @param[in] inner
 *   Item is inner pattern.
 */
static void
flow_dv_translate_item_icmp(void *matcher, void *key,
			    const struct rte_flow_item *item,
			    int inner)
{
	const struct rte_flow_item_icmp *icmp_m = item->mask;
	const struct rte_flow_item_icmp *icmp_v = item->spec;
	void *headers_m;
	void *headers_v;
	void *misc3_m = MLX5_ADDR_OF(fte_match_param, matcher,
				     misc_parameters_3);
	void *misc3_v = MLX5_ADDR_OF(fte_match_param, key, misc_parameters_3);
	if (inner) {
		headers_m = MLX5_ADDR_OF(fte_match_param, matcher,
					 inner_headers);
		headers_v = MLX5_ADDR_OF(fte_match_param, key, inner_headers);
	} else {
		headers_m = MLX5_ADDR_OF(fte_match_param, matcher,
					 outer_headers);
		headers_v = MLX5_ADDR_OF(fte_match_param, key, outer_headers);
	}
	MLX5_SET(fte_match_set_lyr_2_4, headers_m, ip_protocol, 0xff);
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_protocol, IPPROTO_ICMP);
	if (!icmp_v)
		return;
	if (!icmp_m)
		icmp_m = &rte_flow_item_icmp_mask;
	MLX5_SET(fte_match_set_misc3, misc3_m, icmp_type,
		 icmp_m->hdr.icmp_type);
	MLX5_SET(fte_match_set_misc3, misc3_v, icmp_type,
		 icmp_v->hdr.icmp_type & icmp_m->hdr.icmp_type);
	MLX5_SET(fte_match_set_misc3, misc3_m, icmp_code,
		 icmp_m->hdr.icmp_code);
	MLX5_SET(fte_match_set_misc3, misc3_v, icmp_code,
		 icmp_v->hdr.icmp_code & icmp_m->hdr.icmp_code);
}

/**
 * Add META item to matcher in reg_c
 *
 * @param[in, out] matcher
 *   Flow matcher.
 * @param[in] idx
 *   Index of reg_C to use.
 * @param[in] mask
 *   Mask to use.
 * @param[in] value
 *   Value to use.
 */
static void
flow_dv_translate_item_meta_c(void *matcher, void *key, uint8_t idx,
			      uint32_t mask, uint32_t value)
{
	void *misc2_m =
		MLX5_ADDR_OF(fte_match_param, matcher, misc_parameters_2);
	void *misc2_v =
		MLX5_ADDR_OF(fte_match_param, key, misc_parameters_2);

	RTE_ASSERT(idx < 8);
	/* Registers are numbered from high to low */
	switch (idx) {
	case 0:
		MLX5_SET(fte_match_set_misc2,
			       misc2_m, metadata_reg_c_0, mask);
		MLX5_SET(fte_match_set_misc2,
			       misc2_v, metadata_reg_c_0, (value & mask));
		break;
	case 1:
		MLX5_SET(fte_match_set_misc2,
			       misc2_m, metadata_reg_c_1, mask);
		MLX5_SET(fte_match_set_misc2,
			       misc2_v, metadata_reg_c_1, (value & mask));
		break;
	case 2:
		MLX5_SET(fte_match_set_misc2,
			       misc2_m, metadata_reg_c_2, mask);
		MLX5_SET(fte_match_set_misc2,
			       misc2_v, metadata_reg_c_2, (value & mask));
		break;
	case 3:
		MLX5_SET(fte_match_set_misc2,
			       misc2_m, metadata_reg_c_3, mask);
		MLX5_SET(fte_match_set_misc2,
			       misc2_v, metadata_reg_c_3, (value & mask));
		break;
	case 4:
		MLX5_SET(fte_match_set_misc2,
			       misc2_m, metadata_reg_c_4, mask);
		MLX5_SET(fte_match_set_misc2,
			       misc2_v, metadata_reg_c_4, (value & mask));
		break;
	case 5:
		MLX5_SET(fte_match_set_misc2,
			       misc2_m, metadata_reg_c_5, mask);
		MLX5_SET(fte_match_set_misc2,
			       misc2_v, metadata_reg_c_5, (value & mask));
		break;
	case 6:
		MLX5_SET(fte_match_set_misc2,
			       misc2_m, metadata_reg_c_6, mask);
		MLX5_SET(fte_match_set_misc2,
			       misc2_v, metadata_reg_c_6, (value & mask));
		break;
	case 7:
		MLX5_SET(fte_match_set_misc2,
			       misc2_m, metadata_reg_c_7, mask);
		MLX5_SET(fte_match_set_misc2,
			       misc2_v, metadata_reg_c_7, (value & mask));
		break;
	default:
		break;
	}
}

static uint32_t matcher_zero[MLX5_ST_SZ_DW(fte_match_param)] = { 0 };

#define HEADER_IS_ZERO(match_criteria, headers)				     \
	!(memcmp(MLX5_ADDR_OF(fte_match_param, match_criteria, headers),     \
		 matcher_zero, MLX5_FLD_SZ_BYTES(fte_match_param, headers))) \

/**
 * Calculate flow matcher enable bitmap.
 *
 * @param match_criteria
 *   Pointer to flow matcher criteria.
 *
 * @return
 *   Bitmap of enabled fields.
 */
static uint8_t
flow_dv_matcher_enable(uint32_t *match_criteria)
{
	uint8_t match_criteria_enable;

	match_criteria_enable =
		(!HEADER_IS_ZERO(match_criteria, outer_headers)) <<
		MLX5_MATCH_CRITERIA_ENABLE_OUTER_BIT;
	match_criteria_enable |=
		(!HEADER_IS_ZERO(match_criteria, misc_parameters)) <<
		MLX5_MATCH_CRITERIA_ENABLE_MISC_BIT;
	match_criteria_enable |=
		(!HEADER_IS_ZERO(match_criteria, inner_headers)) <<
		MLX5_MATCH_CRITERIA_ENABLE_INNER_BIT;
	match_criteria_enable |=
		(!HEADER_IS_ZERO(match_criteria, misc_parameters_2)) <<
		MLX5_MATCH_CRITERIA_ENABLE_MISC2_BIT;
	match_criteria_enable |=
		(!HEADER_IS_ZERO(match_criteria, misc_parameters_3)) <<
		MLX5_MATCH_CRITERIA_ENABLE_MISC3_BIT;

	return match_criteria_enable;
}

#ifdef __DR__
/**
 * get meter's suffix table, using existing one otherwise create one.
 *
 * @param dev[in, out]
 *   Pointer to rte_eth_dev structure.
 * @param[in] group_id
 *   group id
 * @param[in] attr
 *   attribute containing the appropriate egress/ingress/transfer flags.
 *
 */
static void *
get_meter_suffix_table(struct rte_eth_dev *dev,
		       const struct rte_flow_attr *attr)
{
	void **tbl;
	void *domain;
	struct priv *priv = dev->data->dev_private;
	struct mlx5_ibv_shared *sh = priv->sh;

	tbl = attr->transfer ? &sh->fdb_meter_suffix_table :
			       attr->egress ? &sh->tx_meter_suffix_table :
					      &sh->rx_meter_suffix_table;
	if (*tbl == NULL) {
		domain = attr->transfer ? sh->fdb_domain :
				      attr->egress ? sh->tx_domain : sh->rx_domain;
		if (domain == NULL) {
			DRV_LOG(ERR, "cannot create meter's suffix table, "
				"domain is NULL");
			return NULL;
		}
		*tbl = mlx5dv_dr_table_create(domain, MLX5_FLOW_TABLE_LEVEL_SUFFIX);
		if (*tbl == NULL)
			DRV_LOG(ERR, "cannot create meter's suffix table");
	}
	return (*tbl);
}

/**
 * get egress/ingress/transfer table, using existing one otherwise create one.
 *
 * @param dev[in, out]
 *   Pointer to rte_eth_dev structure.
 * @param[in] group_id
 *   group id
 * @param[in] attr
 *   attribute containing the appropriate egress/ingress/transfer flags.
 *
 */
static void *
get_egress_ingress_table(struct rte_eth_dev *dev,
			 uint32_t group_id,
			 const struct rte_flow_attr *attr)
{
	void **tbl;
	void *domain;
	struct priv *priv = dev->data->dev_private;
	struct mlx5_ibv_shared *sh = priv->sh;

	tbl = attr->transfer ? &sh->fdb_tables[group_id] :
			     attr->egress ? &sh->tx_tables[group_id] :
					    &sh->rx_tables[group_id];
	if (*tbl == NULL) {
		domain = attr->transfer ? sh->fdb_domain :
				      attr->egress ? sh->tx_domain :
						     sh->rx_domain;
		if (domain)
			*tbl = mlx5dv_dr_table_create
				(domain, group_id * MLX5_FLOW_TABLE_FACTOR);
		if (*tbl == NULL)
			DRV_LOG(ERR,
				"cannot create %s table, group id - %" PRIu32,
				attr->transfer ? "transfer" :
						 attr->egress ? "egress" :
								"ingress",
				group_id);
	}
	return (*tbl);
}

/**
 * Register the flow matcher.
 *
 * @param dev[in, out]
 *   Pointer to rte_eth_dev structure.
 * @param[in, out] matcher
 *   Pointer to flow matcher.
 * @parm[in, out] dev_flow
 *   Pointer to the dev_flow.
 * @param[out] error
 *   pointer to error structure.
 *
 * @return
 *   0 on success otherwise -errno and errno is set.
 */
static int
flow_dr_matcher_register(struct rte_eth_dev *dev,
			 struct mlx5_flow_dv_matcher *matcher,
			 struct mlx5_flow *dev_flow,
			 struct rte_flow_error *error)
{
	struct priv *priv = dev->data->dev_private;
	struct mlx5_ibv_shared *sh = priv->sh;
	struct mlx5_flow_dv_matcher *cache_matcher;
	struct mlx5dv_flow_matcher_attr dv_attr = {
		.type = IBV_FLOW_ATTR_NORMAL,
		.match_mask = (void *)&matcher->mask,
	};
	const struct rte_flow_attr attr = {
		.ingress = matcher->egress ? 0 : 1,
		.egress = matcher->egress,
		.transfer = matcher->transfer,
	};
	uint8_t criteria_enable;
	void *tbl;

	if (matcher->mtr_sfx_tbl)
		tbl = get_meter_suffix_table(dev, &attr);
	else
		tbl = get_egress_ingress_table(dev,
					       matcher->group, &attr);
	if (!tbl)
		return rte_flow_error_set
			(error, rte_errno, RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
			 NULL, "cannot create table");
	/* Lookup from cache. */
	LIST_FOREACH(cache_matcher, &sh->matchers, next) {
		if (matcher->crc == cache_matcher->crc &&
		    matcher->priority == cache_matcher->priority &&
		    matcher->egress == cache_matcher->egress &&
		    matcher->transfer == cache_matcher->transfer &&
		    matcher->group == cache_matcher->group &&
		    matcher->mtr_sfx_tbl == cache_matcher->mtr_sfx_tbl &&
		    !memcmp((const void *)matcher->mask.buf,
			    (const void *)cache_matcher->mask.buf,
			    cache_matcher->mask.size)) {
			DRV_LOG(DEBUG,
				"priority %hd use %s matcher %p: refcnt %d++",
				cache_matcher->priority,
				cache_matcher->transfer ? "fdb" :
				cache_matcher->egress ? "tx" : "rx",
				(void *)cache_matcher,
				rte_atomic32_read(&cache_matcher->refcnt));
			rte_atomic32_inc(&cache_matcher->refcnt);
			if (matcher->mtr_sfx_tbl)
				dev_flow->dv.handle->sfxt_matcher = cache_matcher;
			else
				dev_flow->dv.handle->matcher = cache_matcher;
			return 0;
		}
	}
	/* Register new matcher. */
	cache_matcher = rte_calloc(__func__, 1, sizeof(*cache_matcher), 0);
	if (!cache_matcher)
		return rte_flow_error_set(error, ENOMEM,
					  RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
					  "cannot allocate matcher memory");
	*cache_matcher = *matcher;
	criteria_enable = flow_dv_matcher_enable(cache_matcher->mask.buf);
	dv_attr.priority = matcher->priority;
	if (matcher->egress)
		dv_attr.flags |= IBV_FLOW_ATTR_FLAGS_EGRESS;
	cache_matcher->matcher_object =
		mlx5dv_dr_matcher_create(tbl, matcher->priority, criteria_enable,
					 (void *)(&matcher->mask));
	if (!cache_matcher->matcher_object) {
		rte_free(cache_matcher);
		return rte_flow_error_set(error, ENOMEM,
					  RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
					  NULL, "cannot create matcher");
	}
	rte_atomic32_inc(&cache_matcher->refcnt);
	LIST_INSERT_HEAD(&sh->matchers, cache_matcher, next);
	if (matcher->mtr_sfx_tbl)
		dev_flow->dv.handle->sfxt_matcher = cache_matcher;
	else
		dev_flow->dv.handle->matcher = cache_matcher;
	DRV_LOG(DEBUG, "priority %hd new %s matcher %p: refcnt %d, meter %s",
		cache_matcher->priority,
		cache_matcher->transfer ? "fdb" :
		cache_matcher->egress ? "tx" : "rx",
		(void *)cache_matcher,
		rte_atomic32_read(&cache_matcher->refcnt),
		matcher->mtr_sfx_tbl ? "Yes" : "No");
	return 0;
}

static void
flow_dv_modify_convert_field(struct mlx5_modification_cmd *modis,
			     uint32_t *modify_num,
			     uint32_t type,
			     struct field_modify_info *field,
			     const uint8_t *src,
			     const uint8_t *mask,
			     uint32_t bits_offset,
			     uint8_t inner,
			     uint32_t *dest_pos,
			     const uint8_t *dest_mask,
			     struct field_modify_info *dest,
			     uint8_t dest_inner)
{
	int bits = field->bits;
	uint32_t i = *modify_num;
	int found = 0;
	int j;
	int k;
	int set;

	assert(field);
	assert(src);
	assert(mask);
	/* Scan and generate modification commands for each mask segment. */
	for (j = 0; j < bits; ++j) {
		assert(i < MLX5_MODIFY_NUM);
		set = mask[(bits_offset + j) / 8] & (1 << (j % 8));
		if (set && found && j != bits - 1)
			continue;
		if (set && !found) {
			if (!field->outer_type)
				DRV_LOG(DEBUG,
					"unsupported modification field");
			modis[i].type = type;
			modis[i].src_offset = j;
			modis[i].src_field = inner ? field->inner_type :
						     field->outer_type;
			found = 1;
			continue;
		}
		if ((set && (j == bits - 1)) || (found && !set)) {
			/* Reach end of mask or end of mask segment. */
			modis[i].bits = j - modis[i].src_offset;
			if (j == bits - 1)
				modis[i].bits++;
			if (type == MLX5_MODIFICATION_TYPE_COPY) {
				uint32_t pos = 0;
				uint32_t end = pos + dest->bits / 8;

				/* Lookup target field and offset from mask. */
				while (dest && dest->bits) {
					/* Bypass scanned mask. */
					if (end < *dest_pos) {
						pos = end;
						continue;
					}
					/* Look for mask byte. */
					for (k = 0; k < dest->bits / 8; ++k) {
						if (dest_mask[pos + k])
							break;
					}
					/* Continue if not found. */
					if (k == dest->bits / 8) {
						pos += k;
						continue;
					}
					/* Make sure enough target bits. */
					if (dest->bits / 8 - k < modis[i].bits / 8)
						DRV_LOG(ERR,
							"invalid copy target");
					/* Target found. */
					*dest_pos = pos + modis[i].bits / 8;
					modis[i].dst_field = dest_inner ?
						dest->inner_type :
						dest->outer_type;
					modis[i].dst_offset = k * 8;
					modis[i].data1 = rte_cpu_to_be_32
						(modis[i].data1);
				}
			} else {
				/* Add or edit type. */
				rte_memcpy(&modis[i].data[4 - bits / 8],
					   &src[bits_offset / 8], bits / 8);
			}
			modis[i].data0 = rte_cpu_to_be_32(modis[i].data0);
			found = 0;
			i++;
		}
	}
	if (*modify_num != i)
		*modify_num = i;
}

static int
flow_dv_convert_modify_update(struct rte_flow_item *item,
			      struct mlx5_modification_cmd *modis,
			      uint32_t *modify_num,
			      uint8_t inner, uint32_t type, struct rte_flow_error *error)
{
	struct field_modify_info *field;
	uint32_t bits_offset;

	assert(item);
	for (; item->type != RTE_FLOW_ITEM_TYPE_END; item++) {
		field = modify_headers[item->type].fields;
		if (!field || !field->bits)
			return rte_flow_error_set(error, EINVAL,
						  RTE_FLOW_ERROR_TYPE_ACTION,
						  (void *)item->type,
						  "unsupported modification"
						  " flow item type");
		for (bits_offset = 0; field->bits > 0; field++) {
			flow_dv_modify_convert_field(modis, modify_num,
						     type, field,
						     item->spec,
						     item->mask ? item->mask :
						     modify_headers[item->type]
							.default_mask,
						  bits_offset, inner,
						  NULL, NULL, NULL, 0);
			bits_offset += field->bits;
		}
	}
	if (!modify_num)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION,
					  (void *)item->type,
					  "invalid modification flow item");
	return 0;
}

static void
flow_dv_convert_modify_update_reg(enum modify_reg reg,
				  struct mlx5_modification_cmd *modis,
				  uint32_t *modify_num, rte_be32_t value)
{
	static enum mlx5_modification_field field[] = {
		[REG_A] = MLX5_MODI_META_DATA_REG_A,
		[REG_B] = MLX5_MODI_META_DATA_REG_B,
		[REG_C_0] = MLX5_MODI_META_REG_C_0,
		[REG_C_1] = MLX5_MODI_META_REG_C_1,
		[REG_C_2] = MLX5_MODI_META_REG_C_2,
		[REG_C_3] = MLX5_MODI_META_REG_C_3,
		[REG_C_4] = MLX5_MODI_META_REG_C_4,
		[REG_C_5] = MLX5_MODI_META_REG_C_5,
		[REG_C_6] = MLX5_MODI_META_REG_C_6,
		[REG_C_7] = MLX5_MODI_META_REG_C_7,
	};
	uint32_t i = *modify_num;

	modis[i].type = MLX5_MODIFICATION_TYPE_SET;
	modis[i].src_offset = 0;
	modis[i].src_field = field[reg];
	modis[i].bits = 0;
	modis[i].data1 = value;
	modis[i].data0 = rte_cpu_to_be_32(modis[i].data0);
	i++;
	*modify_num = i;
}

static int
flow_dv_create_cmd_set_ipv4_addr(struct mlx5_modification_cmd *modis,
				 uint32_t *modify_num,
				 const struct rte_flow_action  *action,
				 struct rte_flow_error *error)
{
	struct rte_flow_item_ipv4 ipv4;
	struct rte_flow_item_ipv4 ipv4_mask;
	const struct rte_flow_action_set_ipv4 *conf =
		(const struct rte_flow_action_set_ipv4 *)(action->conf);

	memset(&ipv4_mask, 0, sizeof(ipv4_mask));
	if (action->type == RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC) {
		ipv4_mask.hdr.src_addr = RTE_BE32(UINT32_MAX);
		ipv4.hdr.src_addr = conf->ipv4_addr;
	}
	if (action->type == RTE_FLOW_ACTION_TYPE_SET_IPV4_DST) {
		ipv4_mask.hdr.dst_addr = RTE_BE32(UINT32_MAX);
		ipv4.hdr.dst_addr = conf->ipv4_addr;
	}
	struct rte_flow_item defination[] = {
		{ .type = RTE_FLOW_ITEM_TYPE_IPV4,
		  .spec = &ipv4,
		  .mask = &ipv4_mask },
		{ .type = RTE_FLOW_ITEM_TYPE_END },
	};
	return (flow_dv_convert_modify_update(defination, modis, modify_num, 0,
		MLX5_MODIFICATION_TYPE_SET, error));
}

static int
flow_dv_create_cmd_set_ipv6_addr(struct mlx5_modification_cmd *modis,
				 uint32_t *modify_num,
				 const struct rte_flow_action  *action,
				 struct rte_flow_error *error)
{
	struct rte_flow_item_ipv6 ipv6;
	struct rte_flow_item_ipv6 ipv6_mask;
	const struct rte_flow_action_set_ipv6 *conf =
		(const struct rte_flow_action_set_ipv6 *)(action->conf);

	memset(&ipv6_mask, 0, sizeof(ipv6_mask));
	if (action->type == RTE_FLOW_ACTION_TYPE_SET_IPV6_SRC) {
		memcpy(&ipv6.hdr.src_addr, &conf->ipv6_addr,
				sizeof(ipv6.hdr.src_addr));
		memcpy(&ipv6_mask.hdr.src_addr,
			&rte_flow_item_ipv6_mask.hdr.src_addr,
			sizeof(ipv6.hdr.src_addr));
	}
	if (action->type == RTE_FLOW_ACTION_TYPE_SET_IPV6_DST) {
		memcpy(&ipv6.hdr.dst_addr, &conf->ipv6_addr,
				sizeof(ipv6.hdr.dst_addr));
		memcpy(&ipv6_mask.hdr.dst_addr,
			&rte_flow_item_ipv6_mask.hdr.dst_addr,
			sizeof(ipv6.hdr.dst_addr));
	}
	struct rte_flow_item defination[] = {
		{ .type = RTE_FLOW_ITEM_TYPE_IPV6,
		  .spec = &ipv6,
		  .mask = &ipv6_mask },
		{ .type = RTE_FLOW_ITEM_TYPE_END },
	};
	return (flow_dv_convert_modify_update(defination, modis, modify_num, 0,
		MLX5_MODIFICATION_TYPE_SET, error));
}

static int
flow_dv_create_cmd_set_tp(struct mlx5_modification_cmd *modis,
			  uint32_t *modify_num,
			  const struct rte_flow_action *action,
			  int is_udp,
			  struct rte_flow_error *error)
{
	struct rte_flow_item_udp udp;
	struct rte_flow_item_udp udp_mask;
	struct rte_flow_item_tcp tcp;
	struct rte_flow_item_tcp tcp_mask;
	//struct mlx5_layer_info *tp_info;
	enum rte_flow_item_type tp_type;
	void *tp_spec;
	void *tp_mask;
	const struct rte_flow_action_set_tp *conf =
		(const struct rte_flow_action_set_tp *)(action->conf);

	//tp_info = &parser->o_layer;
	//if (parser->decap.type == RTE_FLOW_ACTION_TYPE_TUNNEL_DECAP ||
	//    parser->decap.type == RTE_FLOW_ACTION_TYPE_TUNNEL_L3_DECAP) {
	//	tp_info = &parser->i_layer;
	//}
	if (is_udp) {
		tp_type = RTE_FLOW_ITEM_TYPE_UDP;
		tp_spec = &udp;
		tp_mask = &udp_mask;
		memset(&udp_mask, 0, sizeof(udp_mask));
		if (action->type == RTE_FLOW_ACTION_TYPE_SET_TP_SRC) {
			udp.hdr.src_port = conf->port;
			udp_mask.hdr.src_port = RTE_BE16(UINT16_MAX);
		} else {
			udp.hdr.dst_port = conf->port;
			udp_mask.hdr.dst_port = RTE_BE16(UINT16_MAX);
		}
	} else {
		tp_type = RTE_FLOW_ITEM_TYPE_TCP;
		tp_spec = &tcp;
		tp_mask = &tcp_mask;
		memset(&tcp_mask, 0, sizeof(tcp_mask));
		if (action->type == RTE_FLOW_ACTION_TYPE_SET_TP_SRC) {
			tcp.hdr.src_port = conf->port;
			tcp_mask.hdr.src_port = RTE_BE16(UINT16_MAX);
		} else {
			tcp.hdr.dst_port = conf->port;
			tcp_mask.hdr.dst_port = RTE_BE16(UINT16_MAX);
		}
	}
	struct rte_flow_item defination[] = {
		{ .type = tp_type,
		  .spec = tp_spec,
		  .mask = tp_mask },
		{ .type = RTE_FLOW_ITEM_TYPE_END },
	};
	return (flow_dv_convert_modify_update(defination, modis, modify_num, 0,
				MLX5_MODIFICATION_TYPE_SET, error));
}


static int
flow_dv_create_cmd_set_ttl(struct mlx5_modification_cmd *modis,
			   uint32_t *modify_num,
			   const struct rte_flow_action *action,
			   int is_ipv4,
			   struct rte_flow_error *error)
{
	void *spec;
	void *mask;
	struct rte_flow_item_ipv4 ipv4;
	struct rte_flow_item_ipv4 ipv4_mask;
	struct rte_flow_item_ipv6 ipv6;
	struct rte_flow_item_ipv6 ipv6_mask;
	const struct rte_flow_action_set_ttl *conf =
		(const struct rte_flow_action_set_ttl *)(action->conf);

	if (is_ipv4) {
		memset(&ipv4_mask, 0, sizeof(ipv4_mask));
		ipv4.hdr.time_to_live = conf->ttl_value;
		ipv4_mask.hdr.time_to_live = 0xFF;
		spec = &ipv4;
		mask = &ipv4_mask;
	} else {
		ipv6.hdr.hop_limits = conf->ttl_value;
		memset(&ipv6_mask, 0, sizeof(ipv6_mask));
		ipv6_mask.hdr.hop_limits = 0xFF;
		spec = &ipv6;
		mask = &ipv6_mask;
	}
	struct rte_flow_item defination[] = {
		{ .type = (is_ipv4 ? RTE_FLOW_ITEM_TYPE_IPV4 :
				RTE_FLOW_ITEM_TYPE_IPV6),
		  .spec = spec, .mask = mask },
		{ .type = RTE_FLOW_ITEM_TYPE_END },
	};
	return (flow_dv_convert_modify_update(defination, modis, modify_num, 0,
				MLX5_MODIFICATION_TYPE_SET, error));
}

static int
flow_dv_create_cmd_dec_ttl(struct mlx5_modification_cmd *modis,
			   uint32_t *modify_num,
			   int is_ipv4,
			   struct rte_flow_error *error)

{
	void *spec;
	void *mask;
	struct rte_flow_item_ipv4 ipv4;
	struct rte_flow_item_ipv4 ipv4_mask;
	struct rte_flow_item_ipv6 ipv6;
	struct rte_flow_item_ipv6 ipv6_mask;

	if (is_ipv4) {
		memset(&ipv4_mask, 0, sizeof(ipv4_mask));
		ipv4.hdr.time_to_live = 0xFF;
		ipv4_mask.hdr.time_to_live = 0xFF;
		spec = &ipv4;
		mask = &ipv4_mask;
	} else {
		ipv6.hdr.hop_limits = 0xFF;
		memset(&ipv6_mask, 0, sizeof(ipv6_mask));
		ipv6_mask.hdr.hop_limits = 0xFF;
		spec = &ipv6;
		mask = &ipv6_mask;
	}
	struct rte_flow_item defination[] = {
		{ .type = (is_ipv4 ? RTE_FLOW_ITEM_TYPE_IPV4 :
				RTE_FLOW_ITEM_TYPE_IPV6),
		  .spec = spec, .mask = mask },
		{ .type = RTE_FLOW_ITEM_TYPE_END },
	};
	return (flow_dv_convert_modify_update(defination, modis, modify_num, 0,
					      MLX5_MODIFICATION_TYPE_ADD, error));
}

static int
flow_dv_create_cmd_set_mac(struct mlx5_modification_cmd *modis,
			   uint32_t *modify_num,
			   const struct rte_flow_action *action,
			   struct rte_flow_error *error)
{
	struct rte_flow_item_eth eth;
	struct rte_flow_item_eth eth_mask;
	const struct rte_flow_action_set_mac *conf =
		(const struct rte_flow_action_set_mac *)(action->conf);

	memset(&eth_mask, 0, sizeof(eth_mask));
	if (action->type == RTE_FLOW_ACTION_TYPE_SET_MAC_SRC) {
		memcpy(&eth.src.addr_bytes, &conf->mac_addr,
				sizeof(eth.src.addr_bytes));
		memcpy(&eth_mask.src.addr_bytes,
			&rte_flow_item_eth_mask.src.addr_bytes,
			sizeof(eth_mask.src.addr_bytes));
	}
	if (action->type == RTE_FLOW_ACTION_TYPE_SET_MAC_DST) {
		memcpy(&eth.dst.addr_bytes, &conf->mac_addr,
				sizeof(eth.dst.addr_bytes));
		memcpy(&eth_mask.dst.addr_bytes,
			&rte_flow_item_eth_mask.dst.addr_bytes,
			sizeof(eth_mask.dst.addr_bytes));
	}
	struct rte_flow_item defination[] = {
		{ .type = RTE_FLOW_ITEM_TYPE_ETH,
		  .spec = &eth,
		  .mask = &eth_mask },
		{ .type = RTE_FLOW_ITEM_TYPE_END },
	};
	return (flow_dv_convert_modify_update(defination, modis, modify_num, 0,
				MLX5_MODIFICATION_TYPE_SET, error));
}

static int
flow_dv_create_cmd_add_tcp_seq(struct mlx5_modification_cmd *modis,
			       uint32_t *modify_num,
			       const struct rte_flow_action *action,
			       struct rte_flow_error *error)
{
	struct rte_flow_item_tcp tcp;
	struct rte_flow_item_tcp tcp_mask;
	const struct rte_flow_action_modify_tcp_seq *conf =
		(const struct rte_flow_action_modify_tcp_seq *)action->conf;
	uint64_t value = rte_be_to_cpu_32(conf->value);

	memset(&tcp_mask, 0, sizeof(tcp_mask));
	RTE_ASSERT((action->type == RTE_FLOW_ACTION_TYPE_INC_TCP_SEQ) ||
		   (action->type == RTE_FLOW_ACTION_TYPE_DEC_TCP_SEQ));
	if (action->type == RTE_FLOW_ACTION_TYPE_DEC_TCP_SEQ)
		/*
		 * The HW has no decrement operation,
		 * but only incremet operation.
		 * To simulate decrement X from Y using incremenet operation
		 * we need to add UINT32_MAX X times to Y,
		 * because each adding of UINT32_MAX causes decrement by 1
		 * for Y.
		 */
		value *= UINT32_MAX;
	tcp.hdr.sent_seq = RTE_BE32((uint32_t)value);
	tcp_mask.hdr.sent_seq = RTE_BE32(UINT32_MAX);
	struct rte_flow_item defination[] = {
		{ .type = RTE_FLOW_ITEM_TYPE_TCP,
		  .spec = &tcp,
		  .mask = &tcp_mask },
		{ .type = RTE_FLOW_ITEM_TYPE_END },
	};
	return (flow_dv_convert_modify_update(defination, modis, modify_num, 0,
					      MLX5_MODIFICATION_TYPE_ADD,
					      error));
}

static int
flow_dv_create_cmd_add_tcp_ack(struct mlx5_modification_cmd *modis,
			       uint32_t *modify_num,
			       const struct rte_flow_action *action,
			       struct rte_flow_error *error)
{
	struct rte_flow_item_tcp tcp;
	struct rte_flow_item_tcp tcp_mask;
	const struct rte_flow_action_modify_tcp_ack *conf =
		(const struct rte_flow_action_modify_tcp_ack *)action->conf;
	uint64_t value = rte_be_to_cpu_32(conf->value);

	memset(&tcp_mask, 0, sizeof(tcp_mask));
	RTE_ASSERT((action->type == RTE_FLOW_ACTION_TYPE_INC_TCP_ACK) ||
		   (action->type == RTE_FLOW_ACTION_TYPE_DEC_TCP_ACK));
	if (action->type == RTE_FLOW_ACTION_TYPE_DEC_TCP_ACK)
		value *= UINT32_MAX;
	tcp.hdr.recv_ack = RTE_BE32((uint32_t)value);
	tcp_mask.hdr.recv_ack = RTE_BE32(UINT32_MAX);
	struct rte_flow_item defination[] = {
		{ .type = RTE_FLOW_ITEM_TYPE_TCP,
		  .spec = &tcp,
		  .mask = &tcp_mask },
		{ .type = RTE_FLOW_ITEM_TYPE_END },
	};
	return (flow_dv_convert_modify_update(defination, modis, modify_num, 0,
					      MLX5_MODIFICATION_TYPE_ADD,
					      error));
}

static int
flow_dv_create_cmd_set_meta(struct mlx5_modification_cmd *modis,
			       uint32_t *modify_num,
			       const struct rte_flow_action *action,
			       struct rte_flow_error *error __rte_unused)
{
	const struct rte_flow_action_set_meta *m = action->conf;

	flow_dv_convert_modify_update_reg
		(metaid2reg[m->id], modis, modify_num, m->data);
	return 0;
}

/**
 * Find existing modify resource or create and register a new one.
 *
 * @param dev[in, out]
 *   Pointer to rte_eth_dev structure.
 * @param[in, out] resource
 *   Pointer to modify resource.
 * @parm[in, out] dev_flow
 *   Pointer to the dev_flow.
 * @param[out] error
 *   pointer to error structure.
 *
 * @return
 *   0 on success otherwise -errno and errno is set.
 */
static int
flow_dv_modify_resource_register
			(struct rte_eth_dev *dev,
			 struct mlx5_flow_dv_modify_resource *resource,
			 struct mlx5_flow *dev_flow,
			 struct rte_flow_error *error)
{
	struct priv *priv = dev->data->dev_private;
	struct mlx5_ibv_shared *sh = priv->sh;
	struct mlx5_flow_dv_modify_resource *cache_resource;
	struct mlx5dv_dr_domain *domain;

	if (resource->transfer)
		domain = sh->fdb_domain;
	else
		domain = resource->ingress ? sh->rx_domain : sh->tx_domain;
	/* Lookup a matching resource from cache. */
	LIST_FOREACH(cache_resource, &sh->modifys, next) {
		if (resource->modify_num == cache_resource->modify_num &&
		    resource->ingress == cache_resource->transfer &&
		    /* Diffrentiate root table. */
		    !!resource->table == !!cache_resource->table &&
		    resource->transfer == cache_resource->transfer &&
		    resource->mtr_sfx_tbl == cache_resource->mtr_sfx_tbl &&
		    !memcmp((const void *)resource->modis,
			    (const void *)cache_resource->modis,
			    resource->modify_num * sizeof(resource->modis[0]))) {
			DRV_LOG(DEBUG, "moodify resource %p: refcnt %d++",
				(void *)cache_resource,
				rte_atomic32_read(&cache_resource->refcnt));
			rte_atomic32_inc(&cache_resource->refcnt);
			dev_flow->dv.handle->modify = cache_resource;
			return 0;
		}
	}
	/* Register new encap/decap resource. */
	cache_resource = rte_calloc(__func__, 1, sizeof(*cache_resource), 0);
	if (!cache_resource)
		return rte_flow_error_set(error, ENOMEM,
					  RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
					  "cannot allocate resource memory");
	*cache_resource = *resource;
	cache_resource->action = mlx5dv_dr_action_create_modify_header
		(domain, resource->table ? 0 : MLX5DV_DR_ACTION_FLAGS_ROOT_LEVEL,
		 cache_resource->modify_num * sizeof(cache_resource->modis[0]),
		 (void *)cache_resource->modis);

	if (!cache_resource->action) {
		rte_free(cache_resource);
		return rte_flow_error_set(error, ENOMEM,
					  RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
					  NULL, "cannot create action");
	}
	rte_atomic32_init(&cache_resource->refcnt);
	rte_atomic32_inc(&cache_resource->refcnt);
	LIST_INSERT_HEAD(&sh->modifys, cache_resource, next);
	dev_flow->dv.handle->modify = cache_resource;
	DRV_LOG(DEBUG, "new modify resource %p: refcnt %d++",
		(void *)cache_resource,
		rte_atomic32_read(&cache_resource->refcnt));
	return 0;
}

/**
 * Create the modify action.
 *
 * @param[in] dev
 *   Pointer to rte_eth_dev structure.
 * @param[in, out] dev_flow
 *   Pointer to the sub flow.
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
static int
flow_dv_create_modify_action(struct rte_eth_dev *dev,
			     struct mlx5_flow *dev_flow,
			     bool mtr_sfx,
			     const struct rte_flow_attr *attr,
			     const struct rte_flow_item items[],
			     const struct rte_flow_action actions[],
			     struct rte_flow_error *error)
{
	const struct rte_flow_action *action = actions;
	int ret = 0;
	struct mlx5_modification_cmd *modis;
	uint32_t *modify_num;
	struct mlx5_flow_dv_modify_resource modify;
	int is_udp = 0;
	int is_ipv4 = 0;

	items = (const void *)items;

	modify.table = attr->group;
	modify.ingress = attr->ingress;
	modify.transfer = attr->transfer;
	modify.mtr_sfx_tbl = mtr_sfx;
	modis = modify.modis;
	modify_num = &modify.modify_num;
	*modify_num = 0;
	is_ipv4 = (dev_flow->layers &
		   MLX5_FLOW_LAYER_OUTER_L3_IPV4) ? 1 : 0;
	for (; action->type != RTE_FLOW_ACTION_TYPE_END; ++action) {
		switch (action->type) {
			case RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC:
			case RTE_FLOW_ACTION_TYPE_SET_IPV4_DST:
				ret = flow_dv_create_cmd_set_ipv4_addr
					(modis,	modify_num, action, error);
				break;
			case RTE_FLOW_ACTION_TYPE_SET_IPV6_SRC:
			case RTE_FLOW_ACTION_TYPE_SET_IPV6_DST:
				ret = flow_dv_create_cmd_set_ipv6_addr
					(modis, modify_num, action, error);
				break;
			case RTE_FLOW_ACTION_TYPE_SET_TP_SRC:
			case RTE_FLOW_ACTION_TYPE_SET_TP_DST:
				is_udp = (dev_flow->layers &
					  MLX5_FLOW_LAYER_OUTER_L4_UDP) ? 1 : 0;
				ret = flow_dv_create_cmd_set_tp
					(modis, modify_num, action, is_udp,
					 error);
				break;
			case RTE_FLOW_ACTION_TYPE_SET_TTL:
				ret = flow_dv_create_cmd_set_ttl
					(modis, modify_num, action, is_ipv4,
					 error);
				break;
			case RTE_FLOW_ACTION_TYPE_DEC_TTL:
				ret = flow_dv_create_cmd_dec_ttl
					(modis, modify_num, is_ipv4, error);
				break;
			case RTE_FLOW_ACTION_TYPE_SET_MAC_SRC:
			case RTE_FLOW_ACTION_TYPE_SET_MAC_DST:
				ret = flow_dv_create_cmd_set_mac
					(modis, modify_num, action, error);
				break;
			case RTE_FLOW_ACTION_TYPE_INC_TCP_SEQ:
			case RTE_FLOW_ACTION_TYPE_DEC_TCP_SEQ:
				ret = flow_dv_create_cmd_add_tcp_seq
					(modis, modify_num, action, error);
				break;
			case RTE_FLOW_ACTION_TYPE_INC_TCP_ACK:
			case RTE_FLOW_ACTION_TYPE_DEC_TCP_ACK:
				ret = flow_dv_create_cmd_add_tcp_ack
					(modis, modify_num, action, error);
				break;
			case RTE_FLOW_ACTION_TYPE_SET_META:
				ret = flow_dv_create_cmd_set_meta
					(modis, modify_num, action, error);
				break;
			default:
				break;
		}
		if (ret)
			return ret;
	}
	
	if (flow_dv_modify_resource_register(dev, &modify, dev_flow, error))
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ACTION,
				NULL,
				"cannot create modify action");
/*
	if (parser->egress)
		table = MLX5_IB_UAPI_FLOW_TABLE_TYPE_NIC_TX;
	else
		table = MLX5_IB_UAPI_FLOW_TABLE_TYPE_NIC_RX;
	parser->flow->modify_verb =
		mlx5dv_create_flow_action_modify_header(parser->priv->ctx,
				parser->modify_num * sizeof(parser->modis[0]),
				(uint64_t *)parser->modis,
				table);
	if (!parser->flow->modify_verb)
		return rte_flow_error_set(parser->error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ACTION,
				NULL,
				"cannot create modify action");
*/
	return 0;

}
/**
 * Add source vport match to the specified matcher.
 *
 * @param[in, out] matcher
 *   Flow matcher.
 * @param[in, out] key
 *   Flow matcher value.
 * @param[in] port
 *   Source vport value to match
 * @param[in] mask
 *   Mask
 */
static void
flow_dv_translate_item_source_vport(void *matcher, void *key,
				    int16_t port, uint16_t mask)
{
	void *misc_m = MLX5_ADDR_OF(fte_match_param, matcher, misc_parameters);
	void *misc_v = MLX5_ADDR_OF(fte_match_param, key, misc_parameters);

	MLX5_SET(fte_match_set_misc, misc_m, source_port, mask);
	MLX5_SET(fte_match_set_misc, misc_v, source_port, port);
}

/**
 * Translate port-id item to eswitch match on  port-id.
 *
 * @param[in] dev
 *   The devich to configure through.
 * @param[in, out] matcher
 *   Flow matcher.
 * @param[in, out] key
 *   Flow matcher value.
 * @param[in] item
 *   Flow pattern to translate.
 *
 * @return
 *   0 on success, a negative errno value otherwise.
 */
static int
flow_dv_eswitch_translate_item_port_id(struct rte_eth_dev *dev,
				       void *matcher, void *key,
				       const struct rte_flow_item *item)
{
	const struct rte_flow_item_port_id *spec = item ? item->spec : NULL;
	const struct rte_flow_item_port_id *mask = item ? item->mask : NULL;
	const struct rte_flow_item_port_id switch_mask = {
			.id = 0xffffffff,
	};
	const struct rte_flow_item_port_id switch_spec = {
			.id = dev->data->port_id,
	};
	uint16_t val, port;
	int ret;

	if (!mask)
		mask = &switch_mask;
	if (!spec)
		spec = &switch_spec;
	port = mask->id ? spec->id : 0;
	ret = mlx5_port_to_eswitch_info(port, NULL, &val);
	if (ret)
		return ret;
	flow_dv_translate_item_source_vport(matcher, key, val, mask->id);
	return 0;
}

/**
 * Fill the flow with DV spec.
 *
 * @param[in] dev
 *   Pointer to rte_eth_dev structure.
 * @param[in, out] dev_flow
 *   Pointer to the sub flow.
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
static int
flow_dr_translate(struct rte_eth_dev *dev,
		  struct mlx5_flow *dev_flow,
		  const struct rte_flow_attr *attr,
		  const struct rte_flow_item items[],
		  const struct rte_flow_action actions[],
		  struct rte_flow_error *error)
{
	const struct rte_flow_action *actions_head = actions;
	struct priv *priv = dev->data->dev_private;
	struct mlx5_ibv_shared *sh = priv->sh;
	struct rte_flow *flow = dev_flow->flow;
	uint64_t item_flags = 0;
	uint64_t action_flags = 0;
	uint64_t *mtr_prfx_action_flags = &action_flags;
	uint64_t *mtr_sfx_action_flags = &action_flags;
	uint64_t *modify_hdr_action_flags = &action_flags;
	uint64_t priority = attr->priority;
	int decap;
	struct mlx5_flow_dv_matcher matcher = {
		.mask = {
			.size = sizeof(matcher.mask.buf),
		},
	};
	int actions_n = 0;
	void *tbl;
	void *tmp;
	struct mlx5_flow_dv_tag_resource tag_resource;
	int modify = 0;
	struct mlx5_modification_cmd *modis;
	uint32_t *modify_num;
	struct mlx5_flow_dv_modify_resource modify_resource;
#ifdef HAVE_IBV_FLOW_DEVX_COUNTERS
	const struct rte_flow_action_count *count;
	const struct rte_flow_count_value value_default = {
		.hits = 0,
		.bytes = 0,
		};
#endif
	const struct rte_flow_action_meter *mtr =
		mlx5_flow_get_action(actions, RTE_FLOW_ACTION_TYPE_METER);
	struct mlx5_flow_meter *fm = NULL;
	int ret;
	const void *port_item = NULL;

	flow->group = attr->group;
	flow->ingress = attr->ingress;
	flow->transfer = attr->transfer;
	if (priority == MLX5_FLOW_PRIO_RSVD)
		priority = priv->config.flow_prio - 1;
	if (mtr) {
		fm = mlx5_flow_meter_attach(priv, mtr->mtr_id, attr);
		if (!fm)
			return rte_flow_error_set(error, rte_errno,
					RTE_FLOW_ERROR_TYPE_ACTION,
					NULL,
					"meter not found or invalid parameters");
		flow->handle->meter = fm;
		/*
		 * Need to split the actions between
		 * the prfx and sfx flow tables.
		 */
		mtr_sfx_action_flags = &dev_flow->dv.sfxt_action_flags;
		/* On egress first modify then encap,
		 * On ingress first decap then modify.
		 * i.e should be on the table other than the one used
		 *      for encap/decap.
		 */
		modify_hdr_action_flags = flow->ingress ?
					  mtr_sfx_action_flags :
					  mtr_sfx_action_flags;
	}
	for (; actions->type != RTE_FLOW_ACTION_TYPE_END; actions++) {
		const struct rte_flow_action_queue *queue;
		const struct rte_flow_action_rss *rss;
		const struct rte_flow_action *action = actions;
		const uint8_t *rss_key;
		const struct rte_flow_action_jump *jump_data;
		uint32_t port_id = 0;
		int stat;

		switch (actions->type) {
		case RTE_FLOW_ACTION_TYPE_VOID:
			break;
		case RTE_FLOW_ACTION_TYPE_FLAG:
			tag_resource.tag = mlx5_flow_mark_set(MLX5_FLOW_MARK_DEFAULT);
			if (flow_dv_tag_resource_register
			      (dev, &tag_resource, dev_flow, error))
				return errno;
			actions_n++;
			*mtr_sfx_action_flags |= MLX5_FLOW_ACTION_FLAG;
			*mtr_prfx_action_flags |= MLX5_FLOW_ACTION_MARK;
			break;
		case RTE_FLOW_ACTION_TYPE_MARK:
			tag_resource.tag = mlx5_flow_mark_set
			      (((const struct rte_flow_action_mark *)
			       (actions->conf))->id);
			if (flow_dv_tag_resource_register
			      (dev, &tag_resource, dev_flow, error))
				return errno;
			actions_n++;
			*mtr_sfx_action_flags |= MLX5_FLOW_ACTION_MARK;
			*mtr_prfx_action_flags |= MLX5_FLOW_ACTION_MARK;
			break;
		case RTE_FLOW_ACTION_TYPE_DROP:
			*mtr_sfx_action_flags |= MLX5_FLOW_ACTION_DROP;
			break;
		case RTE_FLOW_ACTION_TYPE_QUEUE:
			queue = actions->conf;
			flow->rss.queue_num = 1;
			(*flow->queue)[0] = queue->index;
			*mtr_sfx_action_flags |= MLX5_FLOW_ACTION_QUEUE;
			break;
		case RTE_FLOW_ACTION_TYPE_RSS:
			rss = actions->conf;
			if (flow->queue)
				memcpy((*flow->queue), rss->queue,
				       rss->num * sizeof(uint16_t));
			flow->rss.queue_num = rss->num;
			/* NULL RSS key indicates default RSS key. */
			rss_key = !rss->rss_conf->rss_key ?
					rss_hash_default_key :
					rss->rss_conf->rss_key;
			memcpy(flow->key, rss_key, MLX5_RSS_HASH_KEY_LEN);
			/* RSS type 0 indicates default RSS type ETH_RSS_IP. */
			flow->rss.types = !rss->rss_conf->rss_hf ? ETH_RSS_IP : rss->rss_conf->rss_hf;
			flow->rss.level = rss->rss_conf->rss_level;
			*mtr_sfx_action_flags |= MLX5_FLOW_ACTION_RSS;
			break;
		case RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP:
		case RTE_FLOW_ACTION_TYPE_NVGRE_ENCAP:
			if (flow_dv_create_action_l2_encap
						(dev, actions,
						 dev_flow, !!(mtr), error))
				return -rte_errno;
			//dev_flow->dv.actions[actions_n] =
			//	dev_flow->dv.encap_decap->verbs_action;
			actions_n++;
			*mtr_sfx_action_flags |= actions->type ==
					RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP ?
					MLX5_FLOW_ACTION_VXLAN_ENCAP :
					MLX5_FLOW_ACTION_NVGRE_ENCAP;
			break;
		case RTE_FLOW_ACTION_TYPE_VXLAN_DECAP:
		case RTE_FLOW_ACTION_TYPE_NVGRE_DECAP:
			if (flow_dv_create_action_l2_decap(dev, dev_flow,
							   !!(mtr), error))
				return -rte_errno;
			//dev_flow->dv.actions[actions_n] =
			//	dev_flow->dv.encap_decap->verbs_action;
			actions_n++;
			*mtr_prfx_action_flags |= actions->type ==
					RTE_FLOW_ACTION_TYPE_VXLAN_DECAP ?
					MLX5_FLOW_ACTION_VXLAN_DECAP :
					MLX5_FLOW_ACTION_NVGRE_DECAP;
			break;
		case RTE_FLOW_ACTION_TYPE_RAW_ENCAP:
			/* Handle encap with preceding decap. */
			if ((action_flags | *mtr_sfx_action_flags) &
			    MLX5_FLOW_ACTION_RAW_DECAP) {
				if (flow_dv_create_action_raw_encap
						(dev, actions, dev_flow,
						 !!(mtr), attr, error))
					return -rte_errno;
				//dev_flow->dv.actions[actions_n] =
				//	dev_flow->dv.encap_decap->verbs_action;
				if (attr->ingress)
					*mtr_prfx_action_flags |= MLX5_FLOW_ACTION_RAW_ENCAP;
				else
					*mtr_sfx_action_flags |= MLX5_FLOW_ACTION_RAW_ENCAP;
			} else {
				/* Handle encap without preceding decap. */
				if (flow_dv_create_action_l2_encap
						(dev, actions,
						 dev_flow, !!(mtr), error))
					return -rte_errno;
				//dev_flow->dv.actions[actions_n] =
				//	dev_flow->dv.encap_decap->verbs_action;
				*mtr_sfx_action_flags |= MLX5_FLOW_ACTION_RAW_ENCAP;
			}
			actions_n++;
			break;
		case RTE_FLOW_ACTION_TYPE_RAW_DECAP:
			/* Check if this decap is followed by encap. */
			for (; action->type != RTE_FLOW_ACTION_TYPE_END &&
			       action->type != RTE_FLOW_ACTION_TYPE_RAW_ENCAP;
			       action++) {
			}
			/* Handle decap only if it isn't followed by encap. */
			if (action->type != RTE_FLOW_ACTION_TYPE_RAW_ENCAP) {
				if (flow_dv_create_action_l2_decap
							(dev, dev_flow,
							 !!(mtr), error))
					return -rte_errno;
				/* If decap is followed by encap, handle it at encap. */
				*mtr_prfx_action_flags |= MLX5_FLOW_ACTION_RAW_DECAP;
				//dev_flow->dv.actions[actions_n] =
				//	dev_flow->dv.encap_decap->verbs_action;
				actions_n++;
			} else {
				if (attr->ingress)
					*mtr_prfx_action_flags |= MLX5_FLOW_ACTION_RAW_DECAP;
				else
					*mtr_sfx_action_flags |= MLX5_FLOW_ACTION_RAW_DECAP;
			}
			break;
#ifdef HAVE_IBV_FLOW_DEVX_COUNTERS
		case RTE_FLOW_ACTION_TYPE_COUNT:
			if (!flow->handle->counter) {
				if (action->conf) {
					count = action->conf;
					flow->handle->counter =
						flow_dv_counter_new
						(dev, count->shared, count->id,
						 count->handle, &count->bias,
						 MLX5_COUNTER_TYPE_BULK);
				} else
					flow->handle->counter =
						flow_dv_counter_new
						(dev, 0, 0,
						 NULL, &value_default,
						 MLX5_COUNTER_TYPE_SINGLE);
				if (!flow->handle->counter)
					return rte_flow_error_set
						(error, rte_errno,
						 RTE_FLOW_ERROR_TYPE_ACTION,
						 action,
						 "cannot create counter"
						 " object.");
				*mtr_prfx_action_flags |=
					MLX5_FLOW_ACTION_COUNT;
				actions_n++;
			}
			break;
#endif
		case RTE_FLOW_ACTION_TYPE_METER:
			dev_flow->dv.handle->meter_action = fm->mfts->meter_action;
			if (!dev_flow->dv.handle->meter_action)
				return rte_flow_error_set
						(error, rte_errno,
						 RTE_FLOW_ERROR_TYPE_ACTION,
						 action,
						 "cannot create meter"
						 " action.");
			*mtr_prfx_action_flags |= MLX5_FLOW_ACTION_METER;
			actions_n++;
			break;
		case RTE_FLOW_ACTION_TYPE_JUMP:
			jump_data = action->conf;
			tbl = get_egress_ingress_table
						(dev, jump_data->group, attr);
			if (!tbl)
				return rte_flow_error_set
					(error, rte_errno,
					 RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
					 NULL, "cannot create table");
			tmp =
			  (void *)mlx5dv_dr_action_create_dest_table(tbl);
			if (!tmp)
				return rte_flow_error_set
						(error, errno,
						 RTE_FLOW_ERROR_TYPE_ACTION,
						 NULL,
						 "cannot create jump action.");
			if (mtr)
				dev_flow->dv.handle->sfxt_jump_action = tmp;
			else
				dev_flow->dv.handle->jump_action = tmp;
			actions_n++;
			*mtr_sfx_action_flags |= MLX5_FLOW_ACTION_JUMP;
			break;
		case RTE_FLOW_ACTION_TYPE_PORT_ID:
			stat = flow_dv_translate_action_port_id(dev, action,
								attr, &port_id,
								error);
			if (stat)
				return -rte_errno;
#ifdef HAVE_MLX5DV_DR_ESWITCH
			dev_flow->dv.handle->port_id_action =
					mlx5dv_dr_action_create_dest_vport
						    (priv->sh->fdb_domain, port_id);
			if (!dev_flow->dv.handle->port_id_action)
#endif
				return rte_flow_error_set
					      (error, errno,
					       RTE_FLOW_ERROR_TYPE_ACTION, NULL,
					       "cannot create port-id action.");
			*mtr_sfx_action_flags |= MLX5_FLOW_ACTION_PORT_ID;
			actions_n++;
			break;
		case RTE_FLOW_ACTION_TYPE_PF:
#ifdef HAVE_MLX5DV_DR_ESWITCH
			dev_flow->dv.handle->port_id_action =
					mlx5dv_dr_action_create_dest_vport
						    (priv->sh->fdb_domain, 0);
			if (!dev_flow->dv.handle->port_id_action)
#endif
				return rte_flow_error_set
					     (error, errno,
					      RTE_FLOW_ERROR_TYPE_ACTION, NULL,
					      "cannot create PF action.");
			*mtr_sfx_action_flags |= MLX5_FLOW_ACTION_PF;
			actions_n++;
			break;
		case RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC:
			*modify_hdr_action_flags |=
					MLX5_FLOW_ACTION_SET_IPV4_SRC;
			if (!modify) {
				actions_n++;
				modify = 1;
			}
			break;
		case RTE_FLOW_ACTION_TYPE_SET_IPV4_DST:
			*modify_hdr_action_flags |=
					MLX5_FLOW_ACTION_SET_IPV4_DST;
			if (!modify) {
				actions_n++;
				modify = 1;
			}
			break;
		case RTE_FLOW_ACTION_TYPE_SET_IPV6_SRC:
			*modify_hdr_action_flags |=
					MLX5_FLOW_ACTION_SET_IPV6_SRC;
			if (!modify) {
				actions_n++;
				modify = 1;
			}
			break;
		case RTE_FLOW_ACTION_TYPE_SET_IPV6_DST:
			*modify_hdr_action_flags |=
					MLX5_FLOW_ACTION_SET_IPV6_DST;
			if (!modify) {
				actions_n++;
				modify = 1;
			}
			break;
		case RTE_FLOW_ACTION_TYPE_SET_TP_SRC:
			*modify_hdr_action_flags |=
					MLX5_FLOW_ACTION_SET_TP_SRC;
			if (!modify) {
				actions_n++;
				modify = 1;
			}
			break;
		case RTE_FLOW_ACTION_TYPE_SET_TP_DST:
			*modify_hdr_action_flags |=
					MLX5_FLOW_ACTION_SET_TP_DST;
			if (!modify) {
				actions_n++;
				modify = 1;
			}
			break;
		case RTE_FLOW_ACTION_TYPE_SET_TTL:
			*modify_hdr_action_flags |=
					MLX5_FLOW_ACTION_SET_TTL;
			if (!modify) {
				actions_n++;
				modify = 1;
			}
			break;
		case RTE_FLOW_ACTION_TYPE_DEC_TTL:
			*modify_hdr_action_flags |=
					MLX5_FLOW_ACTION_DEC_TTL;
			if (!modify) {
				actions_n++;
				modify = 1;
			}
			break;
		case RTE_FLOW_ACTION_TYPE_SET_MAC_SRC:
			*modify_hdr_action_flags |=
					MLX5_FLOW_ACTION_SET_MAC_SRC;
			if (!modify) {
				actions_n++;
				modify = 1;
			}
			break;
		case RTE_FLOW_ACTION_TYPE_SET_MAC_DST:
			*modify_hdr_action_flags |=
					MLX5_FLOW_ACTION_SET_MAC_DST;
			if (!modify) {
				actions_n++;
				modify = 1;
			}
			break;
		case RTE_FLOW_ACTION_TYPE_INC_TCP_SEQ:
			*modify_hdr_action_flags |=
					MLX5_FLOW_ACTION_INC_TCP_SEQ;
			if (!modify) {
				actions_n++;
				modify = 1;
			}
			break;
		case RTE_FLOW_ACTION_TYPE_DEC_TCP_SEQ:
			*modify_hdr_action_flags |=
					MLX5_FLOW_ACTION_DEC_TCP_SEQ;
			if (!modify) {
				actions_n++;
				modify = 1;
			}
			break;
		case RTE_FLOW_ACTION_TYPE_INC_TCP_ACK:
			*modify_hdr_action_flags |=
					MLX5_FLOW_ACTION_INC_TCP_ACK;
			if (!modify) {
				actions_n++;
				modify = 1;
			}
			break;
		case RTE_FLOW_ACTION_TYPE_DEC_TCP_ACK:
			*modify_hdr_action_flags |=
					MLX5_FLOW_ACTION_DEC_TCP_ACK;
			if (!modify) {
				actions_n++;
				modify = 1;
			}
			break;
		case RTE_FLOW_ACTION_TYPE_SET_META:
			*modify_hdr_action_flags |=
					MLX5_FLOW_ACTION_SET_META
			(((const struct rte_flow_action_set_meta *)(action->conf))->id);
			if (!modify) {
				actions_n++;
				modify = 1;
			}
			break;
		default:
			break;
		}
	}
	if (mtr) {
		/*
		 * WA for 2 issues: in meter we want the encap and count in
		 * the same STE so put both in SFX table, as no meter we want
		 * the count to be after encap so move it to the SFX table.
		 */
		if (*mtr_prfx_action_flags & MLX5_FLOW_ACTION_COUNT) {
			if (attr->egress && (*mtr_sfx_action_flags &
					     MLX5_FLOW_ACTION_RAW_ENCAP)) {
				*mtr_prfx_action_flags &=
					~(uint64_t)MLX5_FLOW_ACTION_COUNT;
				*mtr_sfx_action_flags |=
					(uint64_t)MLX5_FLOW_ACTION_COUNT;
			}
		}
		/*
		 * Flows need a unique ID in order to be recognized in the
		 * suffix table.
		 */
		modify_resource.table = attr->group;
		modify_resource.ingress = attr->ingress;
		modify_resource.transfer = attr->transfer;
		modis = modify_resource.modis;
		modify_num = &modify_resource.modify_num;
		*modify_num = 0;
		dev_flow->dv.handle->flow_id =
			mlx5_flow_id_get(sh->flow_stack);
		flow_dv_convert_modify_update_reg
			(REG_C_5, modis, modify_num,
			 rte_cpu_to_be_32(dev_flow->dv.handle->flow_id));
		if (!flow->handle->meta_reg_action) {
			flow->handle->meta_reg_action = mlx5dv_dr_action_create_modify_header
				(sh->rx_domain, 0, *modify_num * sizeof(modis[0]),
				 (void *)modis);
			if (!flow->handle->meta_reg_action)
				return rte_flow_error_set
						(error, errno,
						 RTE_FLOW_ERROR_TYPE_ACTION,
						 NULL,
						 "cannot create modify header "
						 "action.");
		}
		actions_n++;
		*mtr_prfx_action_flags |= MLX5_FLOW_ACTION_MODIFY_REG;
	}
	flow->actions = *mtr_prfx_action_flags;
	dev_flow->dv.handle->actions = *mtr_prfx_action_flags |
		*mtr_sfx_action_flags;
	decap = !!(dev_flow->dv.handle->actions & MLX5_FLOW_DECAP_ACTIONS);
	/*
	 * Implicitly add matching on source vport index only
	 * for NIC ingress rules when device is in E-Switch configuration.
	 */
	if (attr->ingress && !attr->transfer &&
	    (priv->representor || priv->master)) {
		/* It was validated - we support unidirectional flows only. */
		assert(!attr->egress);
		flow_dv_translate_item_source_vport(matcher.mask.buf,
						    dev_flow->dv.value.buf,
						    priv->vport_id,
						    0xffff);
	}
	for (; items->type != RTE_FLOW_ITEM_TYPE_END; items++) {
		int tunnel = !!(item_flags & MLX5_FLOW_LAYER_TUNNEL);
		void *match_mask = matcher.mask.buf;
		void *match_value = dev_flow->dv.value.buf;

		switch (items->type) {
		case RTE_FLOW_ITEM_TYPE_PORT_ID:
			ret = flow_dv_eswitch_translate_item_port_id
					(dev, match_mask, match_value, items);
			if (ret)
				return rte_flow_error_set
					       (error, EINVAL,
						RTE_FLOW_ERROR_TYPE_ITEM,
						NULL,
						"failed to create a match on"
						" port id");
			item_flags |= MLX5_FLOW_ITEM_PORT_ID;
			port_item = items;
			break;
		case RTE_FLOW_ITEM_TYPE_ETH:
			flow_dv_translate_item_eth(match_mask, match_value,
						   items, tunnel);
			matcher.priority = MLX5_PRIORITY_MAP_L2;
			item_flags |= tunnel ? MLX5_FLOW_LAYER_INNER_L2 :
					       MLX5_FLOW_LAYER_OUTER_L2;
			break;
		case RTE_FLOW_ITEM_TYPE_VLAN:
			flow_dv_translate_item_vlan(match_mask, match_value,
						    items, tunnel);
			matcher.priority = MLX5_PRIORITY_MAP_L2;
			item_flags |= tunnel ? (MLX5_FLOW_LAYER_INNER_L2 |
						MLX5_FLOW_LAYER_INNER_VLAN) :
					       (MLX5_FLOW_LAYER_OUTER_L2 |
						MLX5_FLOW_LAYER_OUTER_VLAN);
			break;
		case RTE_FLOW_ITEM_TYPE_IPV4:
			flow_dv_translate_item_ipv4(match_mask, match_value,
						    items, tunnel, attr->group);
			matcher.priority = MLX5_PRIORITY_MAP_L3;
			dev_flow->dv.hash_fields |=
				mlx5_flow_hashfields_adjust
					(dev_flow, tunnel,
					 MLX5_IPV4_LAYER_TYPES,
					 MLX5_IPV4_IBV_RX_HASH, decap);
			item_flags |= tunnel ? MLX5_FLOW_LAYER_INNER_L3_IPV4 :
					       MLX5_FLOW_LAYER_OUTER_L3_IPV4;
			break;
		case RTE_FLOW_ITEM_TYPE_IPV6:
			flow_dv_translate_item_ipv6(match_mask, match_value,
						    items, tunnel, attr->group);
			matcher.priority = MLX5_PRIORITY_MAP_L3;
			dev_flow->dv.hash_fields |=
				mlx5_flow_hashfields_adjust
					(dev_flow, tunnel,
					 MLX5_IPV6_LAYER_TYPES,
					 MLX5_IPV6_IBV_RX_HASH, decap);
			item_flags |= tunnel ? MLX5_FLOW_LAYER_INNER_L3_IPV6 :
					       MLX5_FLOW_LAYER_OUTER_L3_IPV6;
			break;
		case RTE_FLOW_ITEM_TYPE_TCP:
			flow_dv_translate_item_tcp(match_mask, match_value,
						   items, tunnel);
			matcher.priority = MLX5_PRIORITY_MAP_L4;
			dev_flow->dv.hash_fields |=
				mlx5_flow_hashfields_adjust
					(dev_flow, tunnel, ETH_RSS_TCP,
					 IBV_RX_HASH_SRC_PORT_TCP |
					 IBV_RX_HASH_DST_PORT_TCP, decap);
			item_flags |= tunnel ? MLX5_FLOW_LAYER_INNER_L4_TCP :
					       MLX5_FLOW_LAYER_OUTER_L4_TCP;
			break;
		case RTE_FLOW_ITEM_TYPE_UDP:
			flow_dv_translate_item_udp(match_mask, match_value,
						   items, tunnel);
			matcher.priority = MLX5_PRIORITY_MAP_L4;
			dev_flow->dv.hash_fields |=
				mlx5_flow_hashfields_adjust
					(dev_flow, tunnel, ETH_RSS_UDP,
					 IBV_RX_HASH_SRC_PORT_UDP |
					 IBV_RX_HASH_DST_PORT_UDP, decap);
			item_flags |= tunnel ? MLX5_FLOW_LAYER_INNER_L4_UDP :
					       MLX5_FLOW_LAYER_OUTER_L4_UDP;
			break;
		case RTE_FLOW_ITEM_TYPE_GRE:
			flow_dv_translate_item_gre(match_mask, match_value,
						   items, tunnel);
			matcher.priority = MLX5_PRIORITY_MAP_L2;
			item_flags |= MLX5_FLOW_LAYER_GRE;
			break;
		case RTE_FLOW_ITEM_TYPE_GRE_OPT_KEY:
			flow_dv_translate_item_gre_opt_key(match_mask,
							   match_value, items);
			item_flags |= MLX5_FLOW_LAYER_GRE_OPT_KEY;
			break;
		case RTE_FLOW_ITEM_TYPE_NVGRE:
			flow_dv_translate_item_nvgre(match_mask, match_value,
						     items, tunnel);
			matcher.priority = MLX5_PRIORITY_MAP_L2;
			item_flags |= MLX5_FLOW_LAYER_GRE;
			break;
		case RTE_FLOW_ITEM_TYPE_VXLAN:
			flow_dv_translate_item_vxlan(match_mask, match_value,
						     items, tunnel);
			matcher.priority = MLX5_PRIORITY_MAP_L2;
			item_flags |= MLX5_FLOW_LAYER_VXLAN;
			break;
		case RTE_FLOW_ITEM_TYPE_VXLAN_GPE:
			flow_dv_translate_item_vxlan_gpe(match_mask, match_value,
							 items, tunnel);
			matcher.priority = MLX5_PRIORITY_MAP_L2;
			item_flags |= MLX5_FLOW_LAYER_VXLAN_GPE;
			break;
		case RTE_FLOW_ITEM_TYPE_META:
			flow_dv_translate_item_meta(match_mask, match_value,
						    items);
			item_flags |= MLX5_FLOW_ITEM_METADATA(0);
			break;
		case RTE_FLOW_ITEM_TYPE_META_EXT:
			flow_dv_translate_item_meta_ext(match_mask, match_value,
						    items);
			item_flags |= MLX5_FLOW_ITEM_METADATA
			(((const struct rte_flow_item_meta_ext *)
			  (items->spec))->id);
			break;
		case RTE_FLOW_ITEM_TYPE_ICMP:
			flow_dv_translate_item_icmp(match_mask,
						    match_value,
						    items, tunnel);
			matcher.priority = MLX5_PRIORITY_MAP_L3;
			item_flags |= MLX5_FLOW_LAYER_ICMP;
			break;
		case RTE_FLOW_ITEM_TYPE_ICMPV6:
			flow_dv_translate_item_icmpv6(match_mask,
						     match_value,
						     items, tunnel);
			matcher.priority = MLX5_PRIORITY_MAP_L3;
			item_flags |= MLX5_FLOW_LAYER_ICMPV6;
			break;
		default:
			break;
		}
	}
	/* In transfer mode, add a match on port id if user didn't do it */
	if (attr->transfer && !(item_flags & MLX5_FLOW_ITEM_PORT_ID)) {
		ret = flow_dv_eswitch_translate_item_port_id
						(dev, matcher.mask.buf,
						 dev_flow->dv.value.buf, NULL);
		if (ret)
			return rte_flow_error_set(error, EINVAL,
						  RTE_FLOW_ERROR_TYPE_ITEM,
						  NULL,
						  "failed to create a match on"
						  " port id");
		item_flags |= MLX5_FLOW_ITEM_PORT_ID;
	}
	assert(!flow_dv_check_valid_spec(matcher.mask.buf,
					 dev_flow->dv.value.buf));
	dev_flow->layers = item_flags;
	if (modify == 1) {
		actions_n += 1;
		actions = actions_head;
		if (flow_dv_create_modify_action
			      (dev, dev_flow,
			       !!mtr &&
			       modify_hdr_action_flags == mtr_sfx_action_flags,
			       attr, items, actions, error))
			return -rte_errno;
	}
	dev_flow->dv.actions_n = actions_n;
	/* Register matcher/s. */
	matcher.crc = rte_raw_cksum((const void *)matcher.mask.buf,
				    matcher.mask.size);
	matcher.priority = mlx5_flow_adjust_priority(dev, priority,
						     matcher.priority);
	matcher.egress = attr->egress;
	matcher.transfer = attr->transfer;
	matcher.group = attr->group;
	if (flow_dr_matcher_register(dev, &matcher, dev_flow, error))
		return -rte_errno;
	/* Register meter suffix table matcher */
	if (mtr) {
		memset(matcher.mask.buf, 0, matcher.mask.size);
		if (!(item_flags & MLX5_FLOW_ITEM_PORT_ID) && attr->transfer) {
			ret = flow_dv_eswitch_translate_item_port_id
					(dev, matcher.mask.buf,
					 dev_flow->dv.extra_value.buf, NULL);
			if (ret)
				return rte_flow_error_set(error, EINVAL,
						RTE_FLOW_ERROR_TYPE_ITEM,
						NULL,
						"failed to create a match on"
						" port id");
		}
		if (item_flags & MLX5_FLOW_ITEM_PORT_ID && attr->transfer) {
			ret = flow_dv_eswitch_translate_item_port_id
					(dev, matcher.mask.buf,
					 dev_flow->dv.extra_value.buf,
					 port_item);
			if (ret)
				return rte_flow_error_set(error, EINVAL,
						RTE_FLOW_ERROR_TYPE_ITEM,
						NULL,
						"failed to create a match on"
						" port id");
		}
		flow_dv_translate_item_reg(matcher.mask.buf,
					   dev_flow->dv.extra_value.buf,
					   REG_C_5,
					   rte_cpu_to_be_32
					   (dev_flow->dv.handle->flow_id),
					   0xFFFFFFFF);
		matcher.mtr_sfx_tbl = true;
		if (flow_dr_matcher_register(dev,
					     &matcher, dev_flow, error))
			return -rte_errno;
	}
	return 0;
}


/**
 * Apply the flow to the NIC.
 *
 * @param[in] dev
 *   Pointer to the Ethernet device structure.
 * @param[in, out] flow
 *   Pointer to flow structure.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
flow_dr_create_flow(struct rte_eth_dev *dev,
		    struct rte_flow *flow,
		    struct mlx5_flow_dv *dv,
		    struct mlx5_flow_dv_match_params *value,
		    uint64_t flow_actions,
		    struct rte_flow_error *error)
{
	int n = 0;
	int e = 0;
	struct priv *priv = dev->data->dev_private;
	struct mlx5dv_dr_action *actions[MLX5_DV_MAX_NUMBER_OF_ACTIONS];

	if (flow->ingress && !priv->representor) {
		if (flow_actions & MLX5_FLOW_DECAP_ACTIONS) {
			actions[n] = dv->handle->encap_decap->verbs_action;
			n++;
		}
		if (flow_actions & MLX5_FLOW_MODIFY_ACTIONS) {
			actions[n] = dv->handle->modify->action;
			n++;
		}
		if ((flow_actions & MLX5_FLOW_ACTION_COUNT) &&
		     flow->handle->counter) {
			actions[n] = flow->handle->counter->action;
			n++;
		}
	} else {
		if ((flow_actions & MLX5_FLOW_ACTION_COUNT) &&
		     flow->handle->counter) {
			actions[n] = flow->handle->counter->action;
			n++;
		}
		if (flow->actions & MLX5_FLOW_MODIFY_ACTIONS) {
			actions[n] = dv->handle->modify->action;
			n++;
		}
		if (flow->actions & MLX5_FLOW_ENCAP_ACTIONS) {
			actions[n] = dv->handle->encap_decap->verbs_action;
			n++;
		}
	}
	if (flow->actions & (MLX5_FLOW_ACTION_FLAG |
			     MLX5_FLOW_ACTION_MARK)) {
		actions[n] = dv->handle->tag->action;
		n++;
	}
	if (flow->actions & MLX5_FLOW_ACTION_DROP) {
		if (flow->transfer) {
			actions[n] = mlx5dv_dr_action_create_drop();
		} else {
			if (priv->drop_queue.hrxq)
				e = 1;
			dv->handle->hrxq = mlx5_hrxq_drop_new(dev);
			if (!dv->handle->hrxq)
				return rte_flow_error_set
					     (error, errno,
					      RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
					      NULL,
					      "cannot create drop hash queue");
			if (!e) {
				dv->handle->hrxq->dr_qp_action =
					mlx5dv_dr_action_create_dest_ibv_qp
						(dv->handle->hrxq->qp);
				if (!dv->handle->hrxq->dr_qp_action)
					return rte_flow_error_set
					       (error, errno,
						RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
						NULL,
						"cannot create drop hash queue"
						" action");
			}
			actions[n] = dv->handle->hrxq->dr_qp_action;
		}
		if (!actions[n])
			return rte_flow_error_set
					(error, EINVAL,
					 RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
					 NULL,
					 "failed to create drop action");
		n++;
	} else if (flow->actions &
		   (MLX5_FLOW_ACTION_QUEUE | MLX5_FLOW_ACTION_RSS)) {
		struct mlx5_hrxq *hrxq;

		DRV_LOG(DEBUG, "port %hu: group %u, priority: %hu, flow %p, hash_fields %lx",
			dev->data->port_id, dv->handle->matcher->group,
			dv->handle->matcher->priority, (void *)flow,
			dv->hash_fields);
		hrxq = mlx5_hrxq_get(dev, flow->key,
				     MLX5_RSS_HASH_KEY_LEN,
				     dv->hash_fields,
				     (*flow->queue),
				     flow->rss.queue_num);
		if (!hrxq) {
			hrxq = mlx5_hrxq_new
				(dev, flow->key, MLX5_RSS_HASH_KEY_LEN,
				 dv->hash_fields, (*flow->queue),
				 flow->rss.queue_num);
			if (!hrxq)
				return rte_flow_error_set
					(error, rte_errno,
					 RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
					 "cannot allocate hash queue");
			hrxq->dr_qp_action = mlx5dv_dr_action_create_dest_ibv_qp
				(hrxq->qp);
			if (!hrxq->dr_qp_action) {
				mlx5_hrxq_release(dev, hrxq);
				return rte_flow_error_set
					(error, rte_errno,
					 RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
					 "cannot allocate queue action");
			}

		}
		dv->handle->hrxq = hrxq;
		actions[n] = hrxq->dr_qp_action;
		n++;
	}
	if (flow->actions & MLX5_FLOW_ACTION_MODIFY_REG) {
		actions[n] = flow->handle->meta_reg_action;
		n++;
	}
	if (flow->actions & MLX5_FLOW_ACTION_METER) {
		actions[n] = dv->handle->meter_action;
		n++;
	}
	if (flow->actions & MLX5_FLOW_ACTION_JUMP) {
		actions[n] = dv->handle->jump_action;
		n++;
	}
	if (flow->actions & MLX5_FLOW_ACTION_PORT_ID ||
	    flow->actions & MLX5_FLOW_ACTION_PF) {
		actions[n] = dv->handle->port_id_action;
		n++;
	}
	dv->handle->flow =
		mlx5dv_dr_rule_create(dv->handle->matcher->matcher_object,
				      (void *)value, n, actions);
	if (!dv->handle->flow)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
					  NULL,
					  "hardware refuses to create flow");
	return 0;
}

static void
mlx5_release_hrxq_dv(struct rte_eth_dev *dev, struct mlx5_hrxq *hrxq, uint8_t drop)
{
#ifdef HAVE_MLX5DV_DR
	int res;
	struct mlx5dv_dr_action *dr_qp_action = hrxq->dr_qp_action;
	struct priv *priv = dev->data->dev_private;

	if(drop) {
		mlx5_hrxq_drop_release(dev);
		if (!priv->drop_queue.hrxq)
			mlx5dv_dr_action_destroy(dr_qp_action);
	} else {
		res = mlx5_hrxq_release(dev, hrxq);
		if (!res)
			mlx5dv_dr_action_destroy(dr_qp_action);
	}
#else
	if(drop)
		mlx5_hrxq_drop_release(dev);
	else
		mlx5_hrxq_release(dev, hrxq);

#endif
}

static void
flow_dv_remove(struct rte_eth_dev *dev, struct rte_flow *flow);

/**
 * Apply the flow to the NIC.
 *
 * @param[in] dev
 *   Pointer to the Ethernet device structure.
 * @param[in, out] flow
 *   Pointer to flow structure.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
flow_dr_apply(struct rte_eth_dev *dev, struct rte_flow *flow,
	      struct rte_flow_error *error)
{
	struct mlx5_flow_dv *dv;
	struct mlx5_flow *dev_flow;
	int err;

	flow->handle->actions = 0;
	LIST_FOREACH(dev_flow, &flow->dev_flows, next) {
		dv = &dev_flow->dv;
		if (flow->actions & MLX5_FLOW_ACTION_METER) {
			/* Save overlapping table parameters */
			struct mlx5_flow_dv_matcher *tmp_matcher =
				dev_flow->dv.handle->matcher;
			struct mlx5dv_dr_action *tmp_jump_action =
				dev_flow->dv.handle->jump_action;
			uint64_t flow_actions = flow->actions;

			/* start from suffix table */
			dv->handle->matcher = dev_flow->dv.handle->sfxt_matcher;
			dv->handle->jump_action =
				dev_flow->dv.handle->sfxt_jump_action;
			flow->actions = dv->sfxt_action_flags;
			flow->handle->actions |= flow->actions;
			if (flow->ingress)
				err = flow_dr_create_flow
					(dev, flow, dv,
					 &dv->extra_value,
					 dv->sfxt_action_flags, error);
			else
				err = flow_dr_create_flow
					(dev, flow, dv,
					 &dv->extra_value,
					 dv->sfxt_action_flags, error);
			/* Save flow ID */
			dv->handle->sfxt_flow = dv->handle->flow;
			/* Restore dv original values */
			dv->handle->matcher = tmp_matcher;
			dv->handle->jump_action = tmp_jump_action;
			dv->handle->flow = NULL;
			flow->actions = flow_actions;
			if (err)
				goto error;
		}
		flow->handle->actions |= flow->actions;
		/* Create the flow rule in the prefix table */
		err = flow_dr_create_flow(dev, flow, dv, &dv->value,
					  flow->actions, error);
		if (err)
			goto error;
	}
	return 0;
error:
	err = rte_errno; /* Save rte_errno before cleanup. */
	flow_dv_remove(dev, flow);
	rte_errno = err; /* Restore rte_errno. */
	return -rte_errno;
}
#else

/**
 * Register the flow matcher.
 *
 * @param dev[in, out]
 *   Pointer to rte_eth_dev structure.
 * @param[in, out] matcher
 *   Pointer to flow matcher.
 * @parm[in, out] dev_flow
 *   Pointer to the dev_flow.
 * @param[out] error
 *   pointer to error structure.
 *
 * @return
 *   0 on success otherwise -errno and errno is set.
 */
static int
flow_dv_matcher_register(struct rte_eth_dev *dev,
			 struct mlx5_flow_dv_matcher *matcher,
			 struct mlx5_flow *dev_flow,
			 struct rte_flow_error *error)
{
	struct priv *priv = dev->data->dev_private;
	struct mlx5_flow_dv_matcher *cache_matcher;
	struct mlx5dv_flow_matcher_attr dv_attr = {
		.type = IBV_FLOW_ATTR_NORMAL,
		.match_mask = (void *)&matcher->mask,
	};

	/* Lookup from cache. */
	LIST_FOREACH(cache_matcher, &priv->matchers, next) {
		if (matcher->crc == cache_matcher->crc &&
		    matcher->priority == cache_matcher->priority &&
		    matcher->egress == cache_matcher->egress &&
		    matcher->group == cache_matcher->group &&
		    !memcmp((const void *)matcher->mask.buf,
			    (const void *)cache_matcher->mask.buf,
			    cache_matcher->mask.size)) {
			DRV_LOG(DEBUG,
				"priority %hd use %s matcher %p: refcnt %d++",
				cache_matcher->priority,
				cache_matcher->egress ? "tx" : "rx",
				(void *)cache_matcher,
				rte_atomic32_read(&cache_matcher->refcnt));
			rte_atomic32_inc(&cache_matcher->refcnt);
			dev_flow->dv.matcher = cache_matcher;
			return 0;
		}
	}
	/* Register new matcher. */
	cache_matcher = rte_calloc(__func__, 1, sizeof(*cache_matcher), 0);
	if (!cache_matcher)
		return rte_flow_error_set(error, ENOMEM,
					  RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
					  "cannot allocate matcher memory");
	*cache_matcher = *matcher;
	dv_attr.match_criteria_enable =
		flow_dv_matcher_enable(cache_matcher->mask.buf);
	dv_attr.priority = matcher->priority;
	if (matcher->egress)
		dv_attr.flags |= IBV_FLOW_ATTR_FLAGS_EGRESS;
	cache_matcher->matcher_object =
		mlx5_glue->dv_create_flow_matcher(priv->ctx, &dv_attr);
	if (!cache_matcher->matcher_object) {
		rte_free(cache_matcher);
		return rte_flow_error_set(error, ENOMEM,
					  RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
					  NULL, "cannot create matcher");
	}
	rte_atomic32_inc(&cache_matcher->refcnt);
	LIST_INSERT_HEAD(&priv->matchers, cache_matcher, next);
	dev_flow->dv.handle->matcher = cache_matcher;
	DRV_LOG(DEBUG, "priority %hd new %s matcher %p: refcnt %d",
		cache_matcher->priority,
		cache_matcher->egress ? "tx" : "rx", (void *)cache_matcher,
		rte_atomic32_read(&cache_matcher->refcnt));
	return 0;
}

/**
 * Fill the flow with DV spec.
 *
 * @param[in] dev
 *   Pointer to rte_eth_dev structure.
 * @param[in, out] dev_flow
 *   Pointer to the sub flow.
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
static int
flow_dv_translate(struct rte_eth_dev *dev,
		  struct mlx5_flow *dev_flow,
		  const struct rte_flow_attr *attr,
		  const struct rte_flow_item items[],
		  const struct rte_flow_action actions[],
		  struct rte_flow_error *error)
{
	struct priv *priv = dev->data->dev_private;
	struct rte_flow *flow = dev_flow->flow;
	uint64_t item_flags = 0;
	uint64_t action_flags = 0;
	uint64_t priority = attr->priority;
	struct mlx5_flow_dv_matcher matcher = {
		.mask = {
			.size = sizeof(matcher.mask.buf),
		},
	};
	int actions_n = 0;

	if (priority == MLX5_FLOW_PRIO_RSVD)
		priority = priv->config.flow_prio - 1;
	for (; actions->type != RTE_FLOW_ACTION_TYPE_END; actions++) {
		const struct rte_flow_action_queue *queue;
		const struct rte_flow_action_rss *rss;
#ifdef HAVE_IBV_FLOW_DEVX_COUNTERS
		const struct rte_flow_action_count *count;
#endif
		const struct rte_flow_action *action = actions;
		const uint8_t *rss_key;

		switch (actions->type) {
		case RTE_FLOW_ACTION_TYPE_VOID:
			break;
		case RTE_FLOW_ACTION_TYPE_FLAG:
			dev_flow->dv.actions[actions_n].type =
				MLX5DV_FLOW_ACTION_TAG;
			dev_flow->dv.actions[actions_n].tag_value =
				mlx5_flow_mark_set(MLX5_FLOW_MARK_DEFAULT);
			actions_n++;
			action_flags |= MLX5_FLOW_ACTION_FLAG;
			break;
		case RTE_FLOW_ACTION_TYPE_MARK:
			dev_flow->dv.actions[actions_n].type =
				MLX5DV_FLOW_ACTION_TAG;
			dev_flow->dv.actions[actions_n].tag_value =
				mlx5_flow_mark_set
				(((const struct rte_flow_action_mark *)
				  (actions->conf))->id);
			actions_n++;
			action_flags |= MLX5_FLOW_ACTION_MARK;
			break;
		case RTE_FLOW_ACTION_TYPE_DROP:
			dev_flow->dv.actions[actions_n].type =
				MLX5DV_FLOW_ACTION_DROP;
			action_flags |= MLX5_FLOW_ACTION_DROP;
			break;
		case RTE_FLOW_ACTION_TYPE_QUEUE:
			queue = actions->conf;
			flow->rss.queue_num = 1;
			(*flow->queue)[0] = queue->index;
			action_flags |= MLX5_FLOW_ACTION_QUEUE;
			break;
		case RTE_FLOW_ACTION_TYPE_RSS:
			rss = actions->conf;
			if (flow->queue)
				memcpy((*flow->queue), rss->queue,
				       rss->num * sizeof(uint16_t));
			flow->rss.queue_num = rss->num;
			/* NULL RSS key indicates default RSS key. */
			rss_key = !rss->rss_conf->rss_key ?
				rss_hash_default_key :
				rss->rss_conf->rss_key;
			memcpy(flow->key, rss_key, MLX5_RSS_HASH_KEY_LEN);
			/* RSS type 0 indicates default RSS type ETH_RSS_IP. */
			flow->rss.types = !rss->rss_conf->rss_hf ?
				ETH_RSS_IP : rss->rss_conf->rss_hf;
			flow->rss.level =
				rss->rss_conf->rss_level;
			action_flags |= MLX5_FLOW_ACTION_RSS;
			break;
		case RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP:
		case RTE_FLOW_ACTION_TYPE_NVGRE_ENCAP:
			if (flow_dv_create_action_l2_encap(dev, actions,
						       dev_flow, false, error))
				return -rte_errno;
			dev_flow->dv.actions[actions_n].type =
				MLX5DV_FLOW_ACTION_IBV_FLOW_ACTION;
			dev_flow->dv.actions[actions_n].action =
				dev_flow->dv.encap_decap->verbs_action;
			actions_n++;
			action_flags |= actions->type ==
					RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP ?
					MLX5_FLOW_ACTION_VXLAN_ENCAP :
					MLX5_FLOW_ACTION_NVGRE_ENCAP;
			break;
		case RTE_FLOW_ACTION_TYPE_VXLAN_DECAP:
		case RTE_FLOW_ACTION_TYPE_NVGRE_DECAP:
			if (flow_dv_create_action_l2_decap(dev, dev_flow,
							   false, error))
				return -rte_errno;
			dev_flow->dv.actions[actions_n].type =
				MLX5DV_FLOW_ACTION_IBV_FLOW_ACTION;
			dev_flow->dv.actions[actions_n].action =
				dev_flow->dv.encap_decap->verbs_action;
			actions_n++;
			action_flags |= actions->type ==
					RTE_FLOW_ACTION_TYPE_VXLAN_DECAP ?
					MLX5_FLOW_ACTION_VXLAN_DECAP :
					MLX5_FLOW_ACTION_NVGRE_DECAP;
			break;
		case RTE_FLOW_ACTION_TYPE_RAW_ENCAP:
			/* Handle encap with preceding decap. */
			if (action_flags & MLX5_FLOW_ACTION_RAW_DECAP) {
				if (flow_dv_create_action_raw_encap
						(dev, actions, dev_flow,
						 false, attr, error))
					return -rte_errno;
				dev_flow->dv.actions[actions_n].type =
					MLX5DV_FLOW_ACTION_IBV_FLOW_ACTION;
				dev_flow->dv.actions[actions_n].action =
					dev_flow->dv.encap_decap->verbs_action;
			} else {
				/* Handle encap without preceding decap. */
				if (flow_dv_create_action_l2_encap
						     (dev, actions,
						      dev_flow, false, error))
					return -rte_errno;
				dev_flow->dv.actions[actions_n].type =
					MLX5DV_FLOW_ACTION_IBV_FLOW_ACTION;
				dev_flow->dv.actions[actions_n].action =
					dev_flow->dv.encap_decap->verbs_action;
			}
			actions_n++;
			action_flags |= MLX5_FLOW_ACTION_RAW_ENCAP;
			break;
		case RTE_FLOW_ACTION_TYPE_RAW_DECAP:
			/* Check if this decap is followed by encap. */
			for (; action->type != RTE_FLOW_ACTION_TYPE_END &&
			       action->type != RTE_FLOW_ACTION_TYPE_RAW_ENCAP;
			       action++) {
			}
			/* Handle decap only if it isn't followed by encap. */
			if (action->type != RTE_FLOW_ACTION_TYPE_RAW_ENCAP) {
				if (flow_dv_create_action_l2_decap
								(dev, dev_flow,
								 false, error))
					return -rte_errno;
				dev_flow->dv.actions[actions_n].type =
					MLX5DV_FLOW_ACTION_IBV_FLOW_ACTION;
				dev_flow->dv.actions[actions_n].action =
					dev_flow->dv.encap_decap->verbs_action;
				actions_n++;
			}
			/* If decap is followed by encap, handle it at encap. */
			action_flags |= MLX5_FLOW_ACTION_RAW_DECAP;
			break;
#ifdef HAVE_IBV_FLOW_DEVX_COUNTERS
		case RTE_FLOW_ACTION_TYPE_COUNT:
			count = action->conf;
			flow->handle->counter = flow_dv_counter_new
				(dev, count->shared, count->id, count->obj);
			if (!flow->handle->counter)
				return rte_flow_error_set
						(error, rte_errno,
						 RTE_FLOW_ERROR_TYPE_ACTION,
						 action,
						 "cannot create counter"
						 " object.");
			dev_flow->dv.actions[actions_n].type =
					MLX5DV_FLOW_ACTION_COUNTER_DEVX;
			dev_flow->dv.actions[actions_n].obj =
						flow->handle->counter->dcs->obj;
			flow->actions |= MLX5_FLOW_ACTION_COUNT;
			actions_n++;
			break;
#endif
		default:
			break;
		}
	}
	dev_flow->dv.actions_n = actions_n;
	flow->actions = action_flags;
	for (; items->type != RTE_FLOW_ITEM_TYPE_END; items++) {
		int tunnel = !!(item_flags & MLX5_FLOW_LAYER_TUNNEL);
		void *match_mask = matcher.mask.buf;
		void *match_value = dev_flow->dv.value.buf;

		switch (items->type) {
		case RTE_FLOW_ITEM_TYPE_ETH:
			flow_dv_translate_item_eth(match_mask, match_value,
						   items, tunnel);
			matcher.priority = MLX5_PRIORITY_MAP_L2;
			item_flags |= tunnel ? MLX5_FLOW_LAYER_INNER_L2 :
					       MLX5_FLOW_LAYER_OUTER_L2;
			break;
		case RTE_FLOW_ITEM_TYPE_VLAN:
			flow_dv_translate_item_vlan(match_mask, match_value,
						    items, tunnel);
			matcher.priority = MLX5_PRIORITY_MAP_L2;
			item_flags |= tunnel ? (MLX5_FLOW_LAYER_INNER_L2 |
						MLX5_FLOW_LAYER_INNER_VLAN) :
					       (MLX5_FLOW_LAYER_OUTER_L2 |
						MLX5_FLOW_LAYER_OUTER_VLAN);
			break;
		case RTE_FLOW_ITEM_TYPE_IPV4:
			flow_dv_translate_item_ipv4
						(match_mask, match_value,
						 items, tunnel, attr->group);
			matcher.priority = MLX5_PRIORITY_MAP_L3;
			dev_flow->dv.hash_fields |=
				mlx5_flow_hashfields_adjust
					(dev_flow, tunnel,
					 MLX5_IPV4_LAYER_TYPES,
					 MLX5_IPV4_IBV_RX_HASH);
			item_flags |= tunnel ? MLX5_FLOW_LAYER_INNER_L3_IPV4 :
					       MLX5_FLOW_LAYER_OUTER_L3_IPV4;
			break;
		case RTE_FLOW_ITEM_TYPE_IPV6:
			flow_dv_translate_item_ipv6
						(match_mask, match_value,
						 items, tunnel, attr->group);
			matcher.priority = MLX5_PRIORITY_MAP_L3;
			dev_flow->dv.hash_fields |=
				mlx5_flow_hashfields_adjust
					(dev_flow, tunnel,
					 MLX5_IPV6_LAYER_TYPES,
					 MLX5_IPV6_IBV_RX_HASH);
			item_flags |= tunnel ? MLX5_FLOW_LAYER_INNER_L3_IPV6 :
					       MLX5_FLOW_LAYER_OUTER_L3_IPV6;
			break;
		case RTE_FLOW_ITEM_TYPE_TCP:
			flow_dv_translate_item_tcp(match_mask, match_value,
						   items, tunnel);
			matcher.priority = MLX5_PRIORITY_MAP_L4;
			dev_flow->dv.hash_fields |=
				mlx5_flow_hashfields_adjust
					(dev_flow, tunnel, ETH_RSS_TCP,
					 IBV_RX_HASH_SRC_PORT_TCP |
					 IBV_RX_HASH_DST_PORT_TCP);
			item_flags |= tunnel ? MLX5_FLOW_LAYER_INNER_L4_TCP :
					       MLX5_FLOW_LAYER_OUTER_L4_TCP;
			break;
		case RTE_FLOW_ITEM_TYPE_UDP:
			flow_dv_translate_item_udp(match_mask, match_value,
						   items, tunnel);
			matcher.priority = MLX5_PRIORITY_MAP_L4;
			dev_flow->dv.hash_fields |=
				mlx5_flow_hashfields_adjust
					(dev_flow, tunnel, ETH_RSS_UDP,
					 IBV_RX_HASH_SRC_PORT_UDP |
					 IBV_RX_HASH_DST_PORT_UDP);
			item_flags |= tunnel ? MLX5_FLOW_LAYER_INNER_L4_UDP :
					       MLX5_FLOW_LAYER_OUTER_L4_UDP;
			break;
		case RTE_FLOW_ITEM_TYPE_GRE:
			flow_dv_translate_item_gre(match_mask, match_value,
						   items, tunnel);
			item_flags |= MLX5_FLOW_LAYER_GRE;
			break;
		case RTE_FLOW_ITEM_TYPE_GRE_OPT_KEY:
			flow_dv_translate_item_gre_opt_key(match_mask,
							   match_value, items);
			item_flags |= MLX5_FLOW_LAYER_GRE_OPT_KEY;
			break;
		case RTE_FLOW_ITEM_TYPE_NVGRE:
			flow_dv_translate_item_nvgre(match_mask, match_value,
						     items, tunnel);
			item_flags |= MLX5_FLOW_LAYER_GRE;
			break;
		case RTE_FLOW_ITEM_TYPE_VXLAN:
			flow_dv_translate_item_vxlan(match_mask, match_value,
						     items, tunnel);
			item_flags |= MLX5_FLOW_LAYER_VXLAN;
			break;
		case RTE_FLOW_ITEM_TYPE_VXLAN_GPE:
			flow_dv_translate_item_vxlan(match_mask, match_value,
						     items, tunnel);
			item_flags |= MLX5_FLOW_LAYER_VXLAN_GPE;
			break;
		case RTE_FLOW_ITEM_TYPE_META:
			flow_dv_translate_item_meta(match_mask, match_value,
						    items);
			item_floags |= MLX5_FLOW_ITEM_METADATA(0);
			break;
		case RTE_FLOW_ITEM_TYPE_META_EXT:
			flow_dv_translate_item_meta_ext(match_mask, match_value,
							items);
			item_flags |= MLX5_FLOW_ITEM_METADATA
			(((const struct rte_flow_item_meta_ext *)
			  (items->spec))->id);
			break;
		default:
			break;
		}
	}
	assert(!flow_dv_check_valid_spec(matcher.mask.buf,
					 dev_flow->dv.value.buf));
	dev_flow->layers = item_flags;
	/* Register matcher. */
	matcher.crc = rte_raw_cksum((const void *)matcher.mask.buf,
				    matcher.mask.size);
	matcher.priority = mlx5_flow_adjust_priority(dev, priority,
						     matcher.priority);
	matcher.group = attr->group;
	matcher.egress = attr->egress;
	if (flow_dv_matcher_register(dev, &matcher, dev_flow, error))
		return -rte_errno;
	return 0;
}

/**
 * Apply the flow to the NIC.
 *
 * @param[in] dev
 *   Pointer to the Ethernet device structure.
 * @param[in, out] flow
 *   Pointer to flow structure.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
flow_dv_apply(struct rte_eth_dev *dev, struct rte_flow *flow,
	      struct rte_flow_error *error)
{
	struct mlx5_flow_dv *dv;
	struct mlx5_flow *dev_flow;
	int n;
	int err;

	LIST_FOREACH(dev_flow, &flow->dev_flows, next) {
		dv = &dev_flow->dv;
		n = dv->actions_n;
		if (flow->actions & MLX5_FLOW_ACTION_DROP) {
			dv->handle->hrxq = mlx5_hrxq_drop_new(dev);
			if (!dv->hrxq) {
				rte_flow_error_set
					(error, errno,
					 RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
					 "cannot get drop hash queue");
				goto error;
			}
			dv->actions[n].type = MLX5DV_FLOW_ACTION_DEST_IBV_QP;
			dv->actions[n].qp = dv->hrxq->qp;
			n++;
		} else if (flow->actions &
			   (MLX5_FLOW_ACTION_QUEUE | MLX5_FLOW_ACTION_RSS)) {
			struct mlx5_hrxq *hrxq;

			hrxq = mlx5_hrxq_get(dev, flow->key,
					     MLX5_RSS_HASH_KEY_LEN,
					     dv->hash_fields,
					     (*flow->queue),
					     flow->rss.queue_num,
					     !!(dev_flow->layers &
					        MLX5_FLOW_LAYER_TUNNEL));
			if (!hrxq)
				hrxq = mlx5_hrxq_new
					(dev, flow->key, MLX5_RSS_HASH_KEY_LEN,
					 dv->hash_fields, (*flow->queue),
					 flow->rss.queue_num,
					 !!(dev_flow->layers &
					    MLX5_FLOW_LAYER_TUNNEL));
			if (!hrxq) {
				rte_flow_error_set
					(error, rte_errno,
					 RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
					 "cannot get hash queue");
				goto error;
			}
			dv->handle->hrxq = hrxq;
			dv->actions[n].type = MLX5DV_FLOW_ACTION_DEST_IBV_QP;
			dv->actions[n].qp = hrxq->qp;
			n++;
		}
		dv->flow =
			mlx5_glue->dv_create_flow(dv->matcher->matcher_object,
						  (void *)&dv->value, n,
						  dv->actions);
		if (!dv->flow) {
			rte_flow_error_set(error, errno,
					   RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
					   NULL,
					   "hardware refuses to create flow");
			goto error;
		}
	}
	return 0;
error:
	err = rte_errno; /* Save rte_errno before cleanup. */
	LIST_FOREACH(dev_flow, &flow->dev_flows, next) {
		struct mlx5_flow_dv *dv = &dev_flow->dv;
		if (dv->hrxq) {
			mlx5_release_hrxq_dv(dev, dv->hrxq,
				flow->actions & MLX5_FLOW_ACTION_DROP);
			dv->handle->hrxq = NULL;
			dv->hrxq = NULL;
		}
	}
	rte_errno = err; /* Restore rte_errno. */
	return -rte_errno;
}

#endif 

/**
 * Release the tag.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param flow
 *   Pointer to mlx5_flow.
 *
 * @return
 *   1 while a reference on it exists, 0 when freed.
 */
static int
flow_dv_tag_release(struct rte_eth_dev *dev,
		    struct mlx5_flow_dv_tag_resource *tag)
{
	struct priv *priv = dev->data->dev_private;
	struct mlx5_ibv_shared *sh = priv->sh;

	assert(tag);
	DRV_LOG(DEBUG, "port %u tag %p: refcnt %d--",
		dev->data->port_id, (void *)tag,
		rte_atomic32_read(&tag->refcnt));
	if (rte_atomic32_dec_and_test(&tag->refcnt)) {
#ifdef HAVE_MLX5DV_DR
		claim_zero(mlx5dv_dr_action_destroy
			   (tag->action));
#endif
		/* tag will be freed inside the hlist del */
		(void)rte_hlist_del_key(sh->tag_table, &tag->tag);
		DRV_LOG(DEBUG, "port %u tag %p: removed",
			dev->data->port_id, (void *)tag);

		return 0;
	}
	return 1;
}

/**
 * Release the modify.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param flow
 *   Pointer to mlx5_flow.
 *
 * @return
 *   1 while a reference on it exists, 0 when freed.
 */
static int
flow_dv_modify_release(struct rte_eth_dev *dev,
		    struct mlx5_flow_dv_modify_resource *modify)
{
	assert(modify);
	DRV_LOG(DEBUG, "port %u modify %p: refcnt %d--",
		dev->data->port_id, (void *)modify,
		rte_atomic32_read(&modify->refcnt));
	if (rte_atomic32_dec_and_test(&modify->refcnt)) {
#ifdef HAVE_MLX5DV_DR
		claim_zero(mlx5dv_dr_action_destroy
			   (modify->action));
#endif
		LIST_REMOVE(modify, next);
		DRV_LOG(DEBUG, "port %u modify %p: removed",
			dev->data->port_id, (void *)modify);
		rte_free(modify);
		return 0;
	}
	return 1;
}
/**
 * Release the flow matcher.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param flow
 *   Pointer to mlx5_flow.
 *
 * @return
 *   1 while a reference on it exists, 0 when freed.
 */
static int
flow_dv_matcher_release(struct rte_eth_dev *dev,
			struct mlx5_flow_dv_matcher *matcher)
{
	assert(matcher->matcher_object);
	DRV_LOG(DEBUG, "port %u matcher %p: refcnt %d--",
		dev->data->port_id, (void *)matcher,
		rte_atomic32_read(&matcher->refcnt));
	if (rte_atomic32_dec_and_test(&matcher->refcnt)) {
#ifdef __DR__
		claim_zero(mlx5dv_dr_matcher_destroy
			   (matcher->matcher_object));
#else
		claim_zero(mlx5_glue->dv_destroy_flow_matcher
			   (matcher->matcher_object));
#endif
		LIST_REMOVE(matcher, next);
		rte_free(matcher);
		DRV_LOG(DEBUG, "port %u matcher %p: removed",
			dev->data->port_id, (void *)matcher);
		return 0;
	}
	return 1;
}

/**
 * Release an encap/decap resource.
 *
 * @param flow
 *   Pointer to mlx5_flow.
 *
 * @return
 *   1 while a reference on it exists, 0 when freed.
 */
static int
flow_dv_encap_decap_resource_release
	(struct mlx5_flow_dv_encap_decap_resource *cache_resource)
{
	assert(cache_resource->verbs_action);
	DRV_LOG(DEBUG, "encap/decap resource %p: refcnt %d--",
		(void *)cache_resource,
		rte_atomic32_read(&cache_resource->refcnt));
	if (rte_atomic32_dec_and_test(&cache_resource->refcnt)) {
#ifdef HAVE_MLX5DV_DR
		claim_zero(mlx5dv_dr_action_destroy
				(cache_resource->verbs_action));
#endif
		LIST_REMOVE(cache_resource, next);
		rte_free(cache_resource);
		DRV_LOG(DEBUG, "encap/decap resource %p: removed",
			(void *)cache_resource);
		return 0;
	}
	return 1;
}

/**
 * Remove the flow from the NIC but keeps it in memory.
 *
 * @param[in] dev
 *   Pointer to Ethernet device.
 * @param[in, out] flow
 *   Pointer to flow structure.
 */
static void
flow_dv_remove(struct rte_eth_dev *dev __rte_unused,
	       struct rte_flow *flow __rte_unused)
{
#ifdef RTE_LIBRTE_MLX5_FLOW_CACHE
	struct mlx5_flow_dv *dv;
	struct mlx5_flow *dev_flow;
#ifdef __DR__
	struct priv *priv = dev->data->dev_private;
#endif

	if (!flow)
		return;
	LIST_FOREACH(dev_flow, &flow->dev_flows, next) {
		dv = &dev_flow->dv;
		if (dv->handle->flow) {
#ifdef __DR__
			claim_zero(mlx5dv_dr_rule_destroy(dv->handle->flow));
#else
			claim_zero(mlx5_glue->destroy_flow(dv->handle->flow));
#endif
			dv->handle->flow = NULL;
		}
#ifdef __DR__
		if (dv->handle->flow_id != 0) {
			mlx5_flow_id_release(priv->sh->flow_stack,
					     dv->handle->flow_id);
			dv->handle->flow_id = 0;
		}
		if (dv->handle->sfxt_flow) {
			claim_zero(mlx5dv_dr_rule_destroy
						(dv->handle->sfxt_flow));
			dv->handle->sfxt_flow = NULL;
		}
#endif
		if (dv->handle->hrxq) {
			mlx5_release_hrxq_dv(dev, dv->handle->hrxq,
				flow->actions & MLX5_FLOW_ACTION_DROP);
			dv->handle->hrxq = NULL;
		}
	}
#endif
}

#ifdef RTE_LIBRTE_MLX5_FLOW_CACHE
/**
 * Remove the flow from the NIC and the memory.
 *
 * @param[in] dev
 *   Pointer to the Ethernet device structure.
 * @param[in, out] flow
 *   Pointer to flow structure.
 */
static void
flow_dv_destroy(struct rte_eth_dev *dev, struct rte_flow *flow)
{
	struct mlx5_flow *dev_flow;

	if (!flow)
		return;
	flow_dv_remove(dev, flow);
	if (flow->handle->counter) {
		flow_dv_counter_release(dev, flow->handle->counter);
		flow->handle->counter = NULL;
	}
	if (flow->handle->meter) {
		mlx5_flow_meter_detach(flow->handle->meter);
		flow->handle->meter = NULL;
	}
#ifdef HAVE_MLX5DV_DR
	if (flow->handle->meta_reg_action) {
		claim_zero(mlx5dv_dr_action_destroy
			   (flow->handle->meta_reg_action));
		flow->handle->meta_reg_action = NULL;
	}
#endif
	while (!LIST_EMPTY(&flow->dev_flows)) {
		dev_flow = LIST_FIRST(&flow->dev_flows);
		LIST_REMOVE(dev_flow, next);
		if (dev_flow->dv.handle->matcher)
			flow_dv_matcher_release(dev,
						dev_flow->dv.handle->matcher);
		if (dev_flow->dv.handle->sfxt_matcher)
			flow_dv_matcher_release(dev,
						dev_flow->dv.handle->sfxt_matcher);
		if (dev_flow->dv.handle->tag)
			flow_dv_tag_release(dev, dev_flow->dv.handle->tag);
		if (dev_flow->dv.handle->encap_decap)
			flow_dv_encap_decap_resource_release
				(dev_flow->dv.handle->encap_decap);
		if (dev_flow->dv.handle->modify)
			flow_dv_modify_release(dev, dev_flow->dv.handle->modify);
#ifdef HAVE_MLX5DV_DR
		if (dev_flow->dv.handle->port_id_action) {
			claim_zero(mlx5dv_dr_action_destroy
					(dev_flow->dv.handle->port_id_action));
			dev_flow->dv.handle->port_id_action = NULL;
		}
#endif
		if (dev_flow->dv.handle)
			rte_free(dev_flow->dv.handle);
		rte_free(dev_flow);
	}
}

static void
flow_d_destroy(struct rte_eth_dev *dev, struct rte_flow *flow)
{
	flow_d_shared_lock(dev);
	flow_dv_destroy(dev, flow);
	flow_d_shared_unlock(dev);
}
#else
/**
 * Remove the flow from the NIC and the memory.
 *
 * @param[in] dev
 *   Pointer to the Ethernet device structure.
 * @param[in, out] handle
 *   Pointer to flow structure.
 */
static void
flow_dv_destroy_handle(struct rte_eth_dev *dev, struct rte_flow *flow)
{
	struct rte_flow_handle *handle = (struct rte_flow_handle *)flow;
	struct mlx5_flow_handle *dev_handle;
	struct priv *priv = dev->data->dev_private;

	if (!handle)
		return;
	if (handle->counter) {
		flow_dv_counter_release(dev, handle->counter);
		handle->counter = NULL;
	}
	if (handle->meter) {
		mlx5_flow_meter_detach(handle->meter);
		if (!handle->meter->use_c) {
			const struct rte_flow_attr attr = {
				.egress = 1,
				.ingress = 1,
			};
			flow_d_destroy_policer_rules(dev, handle->meter, &attr);
		}
		handle->meter = NULL;
	}
	while (handle->dev_handles) {
		dev_handle = handle->dev_handles;
		handle->dev_handles = dev_handle->next;
		if (dev_handle->flow)
			claim_zero(mlx5dv_dr_rule_destroy(dev_handle->flow));
		dev_handle->flow = NULL;
		if (dev_handle->sfxt_flow) {
			claim_zero(mlx5dv_dr_rule_destroy
				   (dev_handle->sfxt_flow));
			dev_handle->sfxt_flow = NULL;
		}
		if (dev_handle->matcher)
			flow_dv_matcher_release(dev, dev_handle->matcher);
		if (dev_handle->sfxt_matcher)
			flow_dv_matcher_release(dev,
						dev_handle->sfxt_matcher);
		if (dev_handle->tag)
			flow_dv_tag_release(dev, dev_handle->tag);
		if (dev_handle->encap_decap)
			flow_dv_encap_decap_resource_release
				(dev_handle->encap_decap);
		if (dev_handle->modify)
			flow_dv_modify_release(dev, dev_handle->modify);
		if (dev_handle->flow_id != 0) 
			mlx5_flow_id_release(priv->sh->flow_stack,
					     dev_handle->flow_id);
		if (dev_handle->hrxq) {
			mlx5_release_hrxq_dv(dev, dev_handle->hrxq,
				dev_handle->actions & MLX5_FLOW_ACTION_DROP);
			dev_handle->hrxq = NULL;
		}
#ifdef HAVE_MLX5DV_DR
		if (dev_handle->port_id_action) {
			claim_zero(mlx5dv_dr_action_destroy
						(dev_handle->port_id_action));
			dev_handle->port_id_action = NULL;
		}
#endif
		rte_free(dev_handle);
	}
}

static void
flow_d_destroy_handle(struct rte_eth_dev *dev, struct rte_flow *flow)
{
	flow_d_shared_lock(dev);
	flow_dv_destroy_handle(dev, flow);
	flow_d_shared_unlock(dev);
}
#endif

/**
 * Query a dv flow  rule for its statistics via devx.
 *
 * @param[in] dev
 *   Pointer to Ethernet device.
 * @param[in] flow
 *   Pointer to the sub flow.
 * @param[out] qc
 *   Pointer to counter query request.
 * @param[out] error
 *   Perform verbose error reporting if not NULL.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
flow_dv_query_count(struct rte_eth_dev *dev __rte_unused,
		    struct rte_flow *flow,
		    struct rte_flow_query_count *qc,
		    struct rte_flow_error *error)
{
	struct priv *priv = dev->data->dev_private;
	struct rte_flow_handle *handle = NULL;
	uint64_t pkts = 0;
	uint64_t bytes = 0;
	int err;

#ifdef RTE_LIBRTE_MLX5_FLOW_CACHE
	handle = flow->handle;
#else
	handle = (struct rte_flow_handle *)flow;
#endif

	if (!handle->counter)
		return rte_flow_error_set(error, ENOENT,
				  RTE_FLOW_ERROR_TYPE_ACTION, NULL,
				  "counter not defined in the rule");
	struct mlx5_devx_counter_set *dcs = handle->counter->dcs;
	if (!qc)
		return rte_flow_error_set(error, ENOENT,
				  RTE_FLOW_ERROR_TYPE_ACTION, NULL,
				  "data not defined in the rule query");
	if (dcs->type == MLX5_COUNTER_TYPE_SINGLE)	
		err = mlx5_devx_cmd_fc_query(dcs, qc->reset,
					     &pkts, &bytes, 0,
					     0, NULL, NULL,
					     priv->sh->devx_comp);
	else {
		struct mlx5_devx_counter_set temp_dcs;
		//TODO  add support for reading with offset.
		temp_dcs.id = dcs->id;
		temp_dcs.obj = ((struct mlx5_flow_bulk_counters *)dcs->obj)->obj;
		err = mlx5_devx_cmd_fc_query(&temp_dcs, qc->reset,
					     &pkts, &bytes,
					     0, 0, NULL, NULL,
					     priv->sh->devx_comp);
	}
	if (err)
		return rte_flow_error_set(error, err,
				RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
				"cannot read counter");
	qc->hits_set = 1;
	qc->bytes_set = 1;
	qc->hits = pkts - handle->counter->hits;
	qc->bytes = bytes - handle->counter->bytes;
	if (qc->reset) {
		handle->counter->hits = pkts;
		handle->counter->bytes = bytes;
	}
	return 0;
}

/**
 * Query a flow.
 *
 * @see rte_flow_query()
 * @see rte_flow_ops
 */
static int
flow_dv_query(struct rte_eth_dev *dev,
	      struct rte_flow *flow,
	      const struct rte_flow_action *actions,
	      void *data,
	      struct rte_flow_error *error)
{
	int ret = -EINVAL;

	for (; actions->type != RTE_FLOW_ACTION_TYPE_END; actions++) {
		switch (actions->type) {
		case RTE_FLOW_ACTION_TYPE_VOID:
			break;
		case RTE_FLOW_ACTION_TYPE_COUNT:
			ret = flow_dv_query_count(dev, flow, data, error);
			break;
		default:
			return rte_flow_error_set(error, ENOTSUP,
						  RTE_FLOW_ERROR_TYPE_ACTION,
						  actions,
						  "action not supported");
		}
	}
	return ret;
}

static int
flow_d_translate(struct rte_eth_dev *dev,
		 struct mlx5_flow *dev_flow,
		 const struct rte_flow_attr *attr,
		 const struct rte_flow_item items[],
		 const struct rte_flow_action actions[],
		 struct rte_flow_error *error)
{
	int ret;

	flow_d_shared_lock(dev);
#ifdef __DR__
	ret = flow_dr_translate(dev, dev_flow, attr, items, actions, error);
#else
	ret = flow_dv_translate(dev, dev_flow, attr, items, actions, error);
#endif
	flow_d_shared_unlock(dev);
	return ret;
}

static int
flow_d_apply(struct rte_eth_dev *dev, struct rte_flow *flow,
	      struct rte_flow_error *error)
{
	int ret;

	flow_d_shared_lock(dev);
#ifdef __DR__
	ret = flow_dr_apply(dev, flow, error);
#else
	ret = flow_dv_apply(dev, flow, error);
#endif
	flow_d_shared_unlock(dev);
	return ret;
}

static void
flow_d_remove(struct rte_eth_dev *dev, struct rte_flow *flow)
{
	flow_d_shared_lock(dev);
	flow_dv_remove(dev, flow);
	flow_d_shared_unlock(dev);
}

static int
flow_dr_destroy_mtr_tbl(struct rte_eth_dev *dev,
			struct mlx5_meter_tbls_dv *tbl)
{
#if defined(HAVE_MLX5DV_DR) && defined(__DR__)
	struct priv *priv = dev->data->dev_private;
	struct mlx5_meter_tbls_dv *mtd = (struct mlx5_meter_tbls_dv *)tbl;
	const struct mlx5_flow_meter *fm;
	int i;

	if (!mtd || !priv->config.dv_flow_en)
		return 0;
	fm = mtd->fm;
	for (i = 0; i <= RTE_MTR_DROPPED; i++)
		if (mtd->count_actns[i])
			mlx5dv_dr_action_destroy(mtd->count_actns[i]);
	if (mtd->drop_actn)
		mlx5dv_dr_action_destroy(mtd->drop_actn);
	if (mtd->egress.color_matcher)
		mlx5dv_dr_matcher_destroy(mtd->egress.color_matcher);
	if (mtd->egress.any_matcher)
		mlx5dv_dr_matcher_destroy(mtd->egress.any_matcher);
	if (mtd->egress.tbl)
		mlx5dv_dr_table_destroy(mtd->egress.tbl);
	if (mtd->ingress.color_matcher)
		mlx5dv_dr_matcher_destroy(mtd->ingress.color_matcher);
	if (mtd->ingress.any_matcher)
		mlx5dv_dr_matcher_destroy(mtd->ingress.any_matcher);
	if (mtd->ingress.tbl)
		mlx5dv_dr_table_destroy(mtd->ingress.tbl);
	if (mtd->transfer.color_matcher)
		mlx5dv_dr_matcher_destroy(mtd->transfer.color_matcher);
	if (mtd->transfer.any_matcher)
		mlx5dv_dr_matcher_destroy(mtd->transfer.any_matcher);
	if (mtd->transfer.tbl)
		mlx5dv_dr_table_destroy(mtd->transfer.tbl);
	memset(mtd, 0, sizeof(*mtd));
	mtd->fm = fm;
	return 0;
#else
	(void)dev;
	(void)tbl;
	return -ENOTSUP;
#endif
}

static struct mlx5_meter_tbls_dv *
flow_dr_create_mtr_tbl(struct rte_eth_dev *dev,
		       const struct mlx5_flow_meter *fm)
{
#if defined(HAVE_MLX5DV_DR) && defined(__DR__)
	struct priv *priv = dev->data->dev_private;
	struct mlx5_flow_dv_match_params mask = {
		.size = sizeof(mask.buf),
	};
	struct mlx5_flow_dv_match_params value = {
		.size = sizeof(value.buf),
	};
	struct mlx5dv_dr_action *actions[2] __rte_unused;
	struct mlx5_meter_tbls_dv *mtb;
	int i;

	if (!priv->config.dv_flow_en) {
		rte_errno = ENOTSUP;
		return NULL;
	}
	/*
	 * Common
	 */
	mtb = rte_calloc(__func__, 1, sizeof(*mtb), 0);
	if (!mtb) {
		DRV_LOG(ERR, "Failed to allocate memory");
		return NULL;
	}
	/* Create meter count actions */
	for (i = 0; i <= RTE_MTR_DROPPED; i++) {
		if (!fm->policer_stats.dcs[i].obj)
			continue;
		mtb->count_actns[i] =
			mlx5dv_dr_action_create_flow_counter
			(fm->policer_stats.dcs[i].obj, 0);
		if (!mtb->count_actns[i]) {
			rte_errno = errno;
			DRV_LOG(ERR, "Failed to create count action");
			goto error_exit;
		}
	}
	/* Create drop action */
	mtb->drop_actn = mlx5dv_dr_action_create_drop();
	if (!mtb->drop_actn) {
		rte_errno = errno;
		DRV_LOG(ERR, "Failed to create drop action");
		goto error_exit;
	}
	/*
	 * Egress
	 */
	/* If the suffix table in missing, create it. */
	if (!priv->sh->tx_meter_suffix_table) {
		priv->sh->tx_meter_suffix_table =
			    mlx5dv_dr_table_create(priv->sh->tx_domain,
						MLX5_FLOW_TABLE_LEVEL_SUFFIX);
		if (!priv->sh->tx_meter_suffix_table)
			goto error_exit;
	}
	/* Create the meter table with METER level */
	mtb->egress.tbl = mlx5dv_dr_table_create(priv->sh->tx_domain,
					      MLX5_FLOW_TABLE_LEVEL_METER);
	if (!mtb->egress.tbl) {
		rte_errno = errno;
		DRV_LOG(ERR, "Failed to create egress policer table");
		goto error_exit;
	}
	/* Create matchers, Any and Color */
	mtb->egress.any_matcher =
		mlx5dv_dr_matcher_create
				(mtb->egress.tbl, 3, 0,
				 (struct mlx5dv_flow_match_parameters *)&mask);
	if (!mtb->egress.any_matcher) {
		rte_errno = errno;
		DRV_LOG(ERR, "Failed to create egress policer default matcher");
		goto error_exit;
	}
	flow_dv_translate_item_meta_c(mask.buf, value.buf,
				      fm->metadata_reg_c_idx, 0xff,
				      rte_col_2_mlx5_col(RTE_MTR_COLORS));
	mtb->egress.color_matcher =
		mlx5dv_dr_matcher_create
				(mtb->egress.tbl, 0,
				 1 << MLX5_MATCH_CRITERIA_ENABLE_MISC2_BIT,
				 (struct mlx5dv_flow_match_parameters *)&mask);
	if (!mtb->egress.color_matcher) {
		rte_errno = errno;
		DRV_LOG(ERR, "Failed to create egress policer color matcher");
		goto error_exit;
	}
	i = 0;
	if (mtb->count_actns[RTE_MTR_DROPPED])
		actions[i++] = mtb->count_actns[RTE_MTR_DROPPED];
	actions[i++] = mtb->drop_actn;
	/* Default rule: lowest priority, match any, actions: count drop */
	mtb->egress.policer_rules[RTE_MTR_DROPPED] =
			mlx5dv_dr_rule_create(mtb->egress.any_matcher,
					      (void *)&value, i, actions);
	if (!mtb->egress.policer_rules[RTE_MTR_DROPPED]) {
		rte_errno = errno;
		DRV_LOG(ERR, "Failed to create egress policer drop rule");
		goto error_exit;
	}
	/*
	 * Ingress
	 */
	/* Clear prev work */
	memset(mask.buf, 0, sizeof(mask.buf));
	memset(value.buf, 0, sizeof(value.buf));
	/* If the suffix table in missing, create it. */
	if (!priv->sh->rx_meter_suffix_table) {
		priv->sh->rx_meter_suffix_table =
			    mlx5dv_dr_table_create(priv->sh->rx_domain,
						MLX5_FLOW_TABLE_LEVEL_SUFFIX);
		if (!priv->sh->rx_meter_suffix_table)
			goto error_exit;
	}
	/* Create the meter table with METER leve */
	mtb->ingress.tbl = mlx5dv_dr_table_create(priv->sh->rx_domain,
					       MLX5_FLOW_TABLE_LEVEL_METER);
	if (!mtb->ingress.tbl) {
		rte_errno = errno;
		DRV_LOG(ERR, "Failed to create ingress policer table");
		goto error_exit;
	}
	/* Create matchers, Any and Color */
	mtb->ingress.any_matcher =
		mlx5dv_dr_matcher_create
				(mtb->ingress.tbl, 3, 0,
				 (struct mlx5dv_flow_match_parameters *)&mask);
	if (!mtb->ingress.any_matcher) {
		rte_errno = errno;
		DRV_LOG(ERR, "Failed to create policer default matcher");
		goto error_exit;
	}
	flow_dv_translate_item_meta_c(mask.buf, value.buf,
				      fm->metadata_reg_c_idx, 0xff,
				      rte_col_2_mlx5_col(RTE_MTR_COLORS));
	mtb->ingress.color_matcher =
		mlx5dv_dr_matcher_create
				(mtb->ingress.tbl, 0,
				 1 << MLX5_MATCH_CRITERIA_ENABLE_MISC2_BIT,
				 (struct mlx5dv_flow_match_parameters *)&mask);
	if (!mtb->ingress.color_matcher) {
		rte_errno = errno;
		DRV_LOG(ERR, "Failed to create ingress policer color matcher");
		goto error_exit;
	}
	i = 0;
	if (mtb->count_actns[RTE_MTR_DROPPED])
		actions[i++] = mtb->count_actns[RTE_MTR_DROPPED];
	actions[i++] = mtb->drop_actn;
	/* Default rule: lowest priority, match any, actions: count drop */
	mtb->ingress.policer_rules[RTE_MTR_DROPPED] =
			mlx5dv_dr_rule_create(mtb->ingress.any_matcher,
					      (void *)&value, i, actions);
	if (!mtb->ingress.policer_rules[RTE_MTR_DROPPED]) {
		rte_errno = errno;
		DRV_LOG(ERR, "Failed to create ingress policer drop rule");
		goto error_exit;
	}
	/*
	 * Transfer
	 */
	if (priv->config.dv_eswitch_en) {
		/* Clear prev work */
		memset(mask.buf, 0, sizeof(mask.buf));
		memset(value.buf, 0, sizeof(value.buf));
		/* If the suffix table in missing, create it. */
		if (!priv->sh->fdb_meter_suffix_table) {
			priv->sh->fdb_meter_suffix_table =
				mlx5dv_dr_table_create
					       (priv->sh->fdb_domain,
						MLX5_FLOW_TABLE_LEVEL_SUFFIX);
			if (!priv->sh->fdb_meter_suffix_table)
				goto error_exit;
		}
		/* Create the meter table with METER level */
		mtb->transfer.tbl = mlx5dv_dr_table_create
						(priv->sh->fdb_domain,
						 MLX5_FLOW_TABLE_LEVEL_METER);
		if (!mtb->transfer.tbl) {
			rte_errno = errno;
			DRV_LOG(ERR, "Failed to create transfer policer table");
			goto error_exit;
		}
		/* Create matchers, Any and Color */
		mtb->transfer.any_matcher =
			mlx5dv_dr_matcher_create
				(mtb->transfer.tbl, 3, 0,
				(struct mlx5dv_flow_match_parameters *)&mask);
		if (!mtb->transfer.any_matcher) {
			rte_errno = errno;
			DRV_LOG(ERR,
				"Failed to create policer default matcher");
			goto error_exit;
		}
		flow_dv_translate_item_meta_c
					(mask.buf, value.buf,
					 fm->metadata_reg_c_idx, 0xff,
					 rte_col_2_mlx5_col(RTE_MTR_COLORS));
		mtb->transfer.color_matcher =
			mlx5dv_dr_matcher_create
				(mtb->transfer.tbl, 0,
				 1 << MLX5_MATCH_CRITERIA_ENABLE_MISC2_BIT,
				 (struct mlx5dv_flow_match_parameters *)&mask);
		if (!mtb->transfer.color_matcher) {
			rte_errno = errno;
			DRV_LOG
			     (ERR,
			      "Failed to create transfer policer color matcher");
			goto error_exit;
		}
		i = 0;
		if (mtb->count_actns[RTE_MTR_DROPPED])
			actions[i++] = mtb->count_actns[RTE_MTR_DROPPED];
		actions[i++] = mtb->drop_actn;
		/*
		 * Default rule:
		 *   lowest priority, match any, actions: count drop
		 */
		mtb->transfer.policer_rules[RTE_MTR_DROPPED] =
				mlx5dv_dr_rule_create(mtb->transfer.any_matcher,
						      (void *)&value,
						      i, actions);
		if (!mtb->transfer.policer_rules[RTE_MTR_DROPPED]) {
			rte_errno = errno;
			DRV_LOG(ERR, "Failed to create transfer policer drop rule");
			goto error_exit;
		}
	}
	/* TODO: Add all the drop rules here ? */

	return mtb;
error_exit:
	flow_dr_destroy_mtr_tbl(dev, mtb);
	return NULL;
#else
	(void)dev;
	(void)fm;
	rte_errno = ENOTSUP;
	return NULL;
#endif
}

#ifdef __DR__
static int
flow_dr_destroy_policer_rules(const struct mlx5_flow_meter *fm,
			      const struct rte_flow_attr *attr)
{
	struct mlx5_meter_tbls_dv *mtb = fm ? fm->mfts : NULL;
	int i;

	if (!mtb)
		return 0;
	if (attr->egress) {
		for (i = 0; i <= RTE_MTR_DROPPED; i++) {
			if (mtb->egress.policer_rules[i])
				mlx5dv_dr_rule_destroy
					(mtb->egress.policer_rules[i]);
			mtb->egress.policer_rules[i] = NULL;
		}
		if (mtb->egress.jump_actn)
			mlx5dv_dr_action_destroy(mtb->egress.jump_actn);
		mtb->egress.jump_actn = NULL;
	}
	if (attr->ingress) {
		for (i = 0; i <= RTE_MTR_DROPPED; i++) {
			if (mtb->ingress.policer_rules[i])
				mlx5dv_dr_rule_destroy
					(mtb->ingress.policer_rules[i]);
			mtb->ingress.policer_rules[i] = NULL;
		}
		if (mtb->ingress.jump_actn)
			mlx5dv_dr_action_destroy(mtb->ingress.jump_actn);
		mtb->ingress.jump_actn = NULL;
	}
	if (attr->transfer) {
		for (i = 0; i <= RTE_MTR_DROPPED; i++) {
			if (mtb->transfer.policer_rules[i])
				mlx5dv_dr_rule_destroy
					(mtb->transfer.policer_rules[i]);
			mtb->transfer.policer_rules[i] = NULL;
		}
		if (mtb->transfer.jump_actn)
			mlx5dv_dr_action_destroy(mtb->transfer.jump_actn);
		mtb->transfer.jump_actn = NULL;
	}
	return 0;
}

static int
flow_dr_create_policer_rules(struct rte_eth_dev *dev,
			     struct mlx5_flow_meter *fm,
			     const struct rte_flow_attr *attr)
{
	struct priv *priv = dev->data->dev_private;
	struct mlx5_flow_dv_match_params matcher = {
		.size = sizeof(matcher.buf),
	};
	struct mlx5_flow_dv_match_params value = {
		.size = sizeof(value.buf),
	};
	struct mlx5_meter_tbls_dv *mtb = fm->mfts;
	void *sfx_tble;
	struct mlx5dv_dr_action *actions[2];
	int i;

	if (attr->egress) {
		/* Create jump action */
		sfx_tble = priv->sh->tx_meter_suffix_table;
		if (!sfx_tble)
			goto error;
		mtb->egress.jump_actn =
			mlx5dv_dr_action_create_dest_table(sfx_tble);
		if (!mtb->egress.jump_actn) {
			DRV_LOG(ERR, "Failed to create policer jump action");
			goto error;
		}
		for (i = 0; i < RTE_MTR_DROPPED; i++) {
			int j = 0;

			flow_dv_translate_item_meta_c(matcher.buf, value.buf,
						      fm->metadata_reg_c_idx,
						      0xff,
						      rte_col_2_mlx5_col(i));
			if (mtb->count_actns[i])
				actions[j++] = mtb->count_actns[i];
			if (fm->params.action[i] == MTR_POLICER_ACTION_DROP)
				actions[j++] = mtb->drop_actn;
			else
				actions[j++] = mtb->egress.jump_actn;
			mtb->egress.policer_rules[i] =
				mlx5dv_dr_rule_create
				       (mtb->egress.color_matcher,
					(struct mlx5dv_flow_match_parameters *)
					&value, j, actions);
			if (!mtb->egress.policer_rules[i]) {
				DRV_LOG(ERR, "Failed to create policer rule");
				goto error;
			}
		}
	}
	if (attr->ingress) {
		sfx_tble = priv->sh->rx_meter_suffix_table;
		if (!sfx_tble)
			goto error;
		mtb->ingress.jump_actn =
			mlx5dv_dr_action_create_dest_table(sfx_tble);
		if (!mtb->ingress.jump_actn) {
			DRV_LOG(ERR, "Failed to create policer jump action");
			goto error;
		}
		for (i = 0; i < RTE_MTR_DROPPED; i++) {
			int j = 0;

			flow_dv_translate_item_meta_c(matcher.buf, value.buf,
						      fm->metadata_reg_c_idx,
						      0xff,
						      rte_col_2_mlx5_col(i));
			if (mtb->count_actns[i])
				actions[j++] = mtb->count_actns[i];
			if (fm->params.action[i] == MTR_POLICER_ACTION_DROP)
				actions[j++] = mtb->drop_actn;
			else
				actions[j++] = mtb->ingress.jump_actn;
			mtb->ingress.policer_rules[i] =
				mlx5dv_dr_rule_create
				       (mtb->ingress.color_matcher,
					(struct mlx5dv_flow_match_parameters *)
					&value,	j, actions);
			if (!mtb->ingress.policer_rules[i]) {
				DRV_LOG(ERR, "Failed to create policer rule");
				goto error;
			}
		}
	}
	if (attr->transfer) {
		sfx_tble = priv->sh->fdb_meter_suffix_table;
		if (!sfx_tble)
			goto error;
		mtb->transfer.jump_actn =
			mlx5dv_dr_action_create_dest_table(sfx_tble);
		if (!mtb->transfer.jump_actn) {
			DRV_LOG(ERR, "Failed to create policer jump action");
			goto error;
		}
		for (i = 0; i < RTE_MTR_DROPPED; i++) {
			int j = 0;

			flow_dv_translate_item_meta_c(matcher.buf, value.buf,
						      fm->metadata_reg_c_idx,
						      0xff,
						      rte_col_2_mlx5_col(i));
			if (mtb->count_actns[i])
				actions[j++] = mtb->count_actns[i];
			if (fm->params.action[i] == MTR_POLICER_ACTION_DROP)
				actions[j++] = mtb->drop_actn;
			else
				actions[j++] = mtb->transfer.jump_actn;
			mtb->transfer.policer_rules[i] =
				mlx5dv_dr_rule_create
				       (mtb->transfer.color_matcher,
					(struct mlx5dv_flow_match_parameters *)
					&value,	j, actions);
			if (!mtb->transfer.policer_rules[i]) {
				DRV_LOG(ERR, "Failed to create policer rule");
				goto error;
			}
		}
	}
	return 0;
error:
	flow_dr_destroy_policer_rules(fm, attr);
	return -EINVAL;
}

#endif /* #ifdef __DR__ */

static struct mlx5_meter_tbls_dv *
flow_d_create_mtr_tbl(struct rte_eth_dev *dev,
		      const struct mlx5_flow_meter *fm)
{
#ifdef __DR__
	struct mlx5_meter_tbls_dv *tbl;

	flow_d_shared_lock(dev);
	tbl = flow_dr_create_mtr_tbl(dev, fm);
	flow_d_shared_unlock(dev);
	return tbl;
#else
	(void)dev;
	(void)fm;
	rte_errno = ENOTSUP;
	return NULL;
#endif
}

static int
flow_d_destroy_mtr_tbl(struct rte_eth_dev *dev,
		       struct mlx5_meter_tbls_dv *tbl)
{
#ifdef __DR__
	int ret;

	flow_d_shared_lock(dev);
	ret = flow_dr_destroy_mtr_tbl(dev, tbl);
	flow_d_shared_unlock(dev);
	return ret;
#else
	return -ENOTSUP;
#endif
}

static int
flow_d_create_policer_rules(struct rte_eth_dev *dev,
			    struct mlx5_flow_meter *fm,
			    const struct rte_flow_attr *attr)
{
#ifdef __DR__
	int ret;

	flow_d_shared_lock(dev);
	ret = flow_dr_create_policer_rules(dev, fm, attr);
	flow_d_shared_unlock(dev);
	return ret;
#else
	(void)dev;
	(void)fm;
	(void)attr;
	rte_errno = ENOTSUP;
	return NULL;
#endif
}

static int
flow_d_destroy_policer_rules(struct rte_eth_dev *dev,
			     struct mlx5_flow_meter *fm,
			     const struct rte_flow_attr *attr)
{
#ifdef __DR__
	int ret;

	flow_d_shared_lock(dev);
	ret = flow_dr_destroy_policer_rules(fm, attr);
	flow_d_shared_unlock(dev);
	return ret;
#else
	(void)dev;
	(void)fm;
	(void)attr;
	return -ENOTSUP;
#endif
}

const struct mlx5_flow_driver_ops mlx5_flow_dv_drv_ops = {
	.validate = flow_dv_validate,
	.prepare = flow_dv_prepare,
	.translate = flow_d_translate,
	.apply = flow_d_apply,
	.remove = flow_d_remove,
#ifdef RTE_LIBRTE_MLX5_FLOW_CACHE
	.destroy = flow_d_destroy,
#else
	.destroy = flow_d_destroy_handle,
#endif
	.query = flow_dv_query,
	.counter_alloc = flow_dv_bulk_counters_alloc,
	.counter_free = flow_dv_bulk_counter_free,
	.counter_query = flow_dv_counter_query,
	.sync = flow_dv_sync,
	.create_mtr_tbls = flow_d_create_mtr_tbl,
	.destroy_mtr_tbls = flow_d_destroy_mtr_tbl,
	.create_policer_rules = flow_d_create_policer_rules,
	.destroy_policer_rules = flow_d_destroy_policer_rules,
};

#endif /* HAVE_IBV_FLOW_DV_SUPPORT */
