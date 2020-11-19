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
#include <stdbool.h>
#include <pthread.h>

#include <rte_malloc.h>
#include <rte_debug.h>

#include <rte_cycles.h>
#include <rte_alarm.h>
#include <rte_debug.h>
#include <unistd.h>
#include <assert.h>
#include "rte_vswitch.h"

#include "rte_vswitch_private.h"

#define _VSWITCH_MAX_GROUPS 1024
#define _VSWITCH_EXC_GROUP_ID 1023
#define _RTE_VSWITCH_MAX_RSS_QUEUES 512
#define _VSWITCH_FABRIC_VXLAN_UDP_PORT 250
#define _VSWITCH_LB_VXLAN_UDP_PORT 4789
#define _GET_VPORT_METADATA(v) ((((v)->vport_id) << 16) + ((v)->egroup->group_id << 1) + 1)
#define _GET_SRIOV_METADATA(sv,dv) ((((sv)->vport_id) << 21) + (((dv)->vport_id) << 10) + ((sv)->egroup->group_id << 5) + (dv)->egroup->group_id)

#define _VSWITCH_RET_ON_ERR(_v, _l, _s, ...) \
	do { \
		if (_v) { \
			RTE_LOG(ERR, VSWITCH, _s, ##__VA_ARGS__); \
			goto _l; \
		} \
	} while(0)

/* <timeout of restart procedure. Worse case is 4M flows in cache mode */
#define _VSWITCH_RESTART_TIMEOUT (16*1000*1000)

/* <which pf port request restart */
static rte_atomic16_t restart_req[RTE_MAX_ETHPORTS];

union urss {
	struct rte_flow_action_rss rss_action;
	uint8_t bytes[sizeof(struct rte_flow_action_rss) +
		       _RTE_VSWITCH_MAX_RSS_QUEUES * sizeof(uint16_t)];
};

/* default encapsulation data used to configure the management flows. */
struct rte_vswitch_flow_action_vxlan_encap lb_encap = {
		.ether = {
			.ether_type = RTE_BE16(ETHER_TYPE_IPv4),
		},
		.ipv4 = {
			.version_ihl = (uint8_t)0x45,
			.type_of_service = 0,
			.total_length = 0,
			.packet_id = 0,
			.fragment_offset = 0,
			.time_to_live = 64,
			.next_proto_id = IPPROTO_UDP,
			.hdr_checksum = 0,
			.src_addr = 0x01010101,
			.dst_addr = 0x02020202,
		},
		.udp = {
			.src_port = 0x0101,
			.dst_port = RTE_BE16(_VSWITCH_LB_VXLAN_UDP_PORT),
		},
};

struct rte_mtr_meter_profile default_profile = {
	.alg = RTE_MTR_SRTCM_RFC2697,
	.srtcm_rfc2697 = {
			.cir = 0,
			.cbs = 0,
			.ebs = 0,
		},
};

struct rte_mtr_params default_meter_params = {
		.use_prev_mtr_color = 0,
		.dscp_table = NULL,
		.meter_enable = 1,
		.action = {MTR_POLICER_ACTION_COLOR_GREEN,
				   MTR_POLICER_ACTION_COLOR_YELLOW,
				   MTR_POLICER_ACTION_DROP},
		.stats_mask = UINT64_MAX,
};

static int port_lock_init(struct rte_eth_dev *dev);
static int _vswitch_prepare_context(struct rte_vswitch_ctx *ctx);
static int _vswitch_flush_meter(struct rte_vswitch_ctx *ctx);

/**
 * re-create all meters after fwreset
 *
 * @param ctx
 *   pointer to rte_vswitch_ctx
 *
 * @return
 *   0 - success, all meters are re-created
 *   otherwise fail, all meters are destroyed
 */
static int
_vswitch_recreate_meters(struct rte_vswitch_ctx *ctx)
{
	int i = 0;
	int ret = 0;
	struct rte_vswitch_meter_profile profile = {0};
	struct rte_vswitch_meter *mtr = NULL;

	for (i = 0; i < RTE_VSWITCH_MAX_METER_NUM; i++) {
		mtr = &ctx->vmeters[i];
		if (mtr->valid) {
			mtr->valid = 0;
			profile.bps = mtr->bps;
			ret = rte_vswitch_create_meter(ctx, mtr->meter_id, &profile);
			_VSWITCH_RET_ON_ERR(ret, recreate_meters_teardown,
					    "re-create meter[%d] failed "
					    "ret[%d]\n", i, ret);
		}
	}
	return ret;
recreate_meters_teardown:
	/*< keep valid flag in order to re-try again lately */
	mtr->valid = 1;
	/*< destroy already re-created meters */
	for (--i; i >= 0; i--) {
		mtr = &ctx->vmeters[i];
		if (mtr->valid) {
			if (rte_vswitch_destroy_meter(ctx, mtr->meter_id)) {
				RTE_LOG(ERR, VSWITCH,
						"%s teardown destroy meter[%d] "
						"failed\n", __func__, i);
			}
			/*< keep valid flag in order to re-try again lately */
			mtr->valid = 1;
		}
	}
	return ret;
}

/**
 * handler of hotplug restart timeout
 *
 * @param args
 *   Pointer to the args
 *
 * @return
 *   None
 */
static void
_vswitch_restart_timeout_alarm(void *args)
{
	rte_atomic16_t *timeout_flag = (rte_atomic16_t *)args;
	rte_atomic16_test_and_set(timeout_flag);
}

/**
 * Handler routine of PF event
 * only RTE_ETH_EVENT_INTR_RMV event
 * at this moment for rte_vswitch_hotplug_restart()
 */
static int
_vswitch_event_handler(uint16_t pf_port_id, enum rte_eth_event_type event,
		       void *args, void *ret_param)
{
	RTE_SET_USED(args);
	RTE_SET_USED(ret_param);
	if (event == RTE_ETH_EVENT_INTR_RMV) {
		rte_atomic16_test_and_set(&restart_req[pf_port_id]);
	}
	return 0;
}

/* Initiate the group pools lists with the vswitch context memory. */
static void
_vswitch_init_group_pools(struct rte_vswitch_ctx *ctx)
{
	uint32_t i;
	struct vswitch_group *gr = (struct vswitch_group *)
			(ctx->vports + ctx->max_vport_id + 1);

	TAILQ_INIT(&ctx->ipool.groups);
	TAILQ_INIT(&ctx->epool.groups);
	TAILQ_INIT(&ctx->invalid_groups);
	for (i = 0; i < _VSWITCH_MAX_GROUPS; ++i) {
		gr->group_id = i;
		gr->pool = &ctx->ipool;
		if (i)
			TAILQ_INSERT_TAIL(&ctx->ipool.groups, gr, next);
		gr += 1;
	}
	for (i = 0; i < _VSWITCH_MAX_GROUPS; ++i) {
		gr->group_id = i;
		gr->pool = &ctx->epool;
		/* No need to clear to 0 because of the rte_zmalloc* */
		gr->firsts = (struct vswitch_dispatch_flow_data_head *)(gr + 1);
		if (i && gr->group_id != _VSWITCH_EXC_GROUP_ID)
			TAILQ_INSERT_TAIL(&ctx->epool.groups, gr, next);
		gr = (struct vswitch_group *)
				(gr->firsts + ctx->max_vport_id + 1);
	}
}

static struct vswitch_group *
_vswitch_get_group_by_id(struct rte_vswitch_ctx *ctx, uint16_t group_id, uint8_t ingress)
{
	struct vswitch_group *gr = (struct vswitch_group *)
				(ctx->vports + ctx->max_vport_id + 1);
	if (ingress)
		gr += group_id;
	else
		gr = (struct vswitch_group *)
			((uint8_t *)(gr + _VSWITCH_MAX_GROUPS + group_id) +
			(sizeof(gr->firsts[0]) * (ctx->max_vport_id + 1)) *
			group_id);
	return gr;
}

#define VSWITCH_GROUP_LIST_INIT_NUM		64
#define VSWITCH_GROUP_LIST_ENTRY_PER_LIST	4

static struct rte_hlist_table *_vswitch_group_hlist_create(
	uint16_t pid, uint16_t gid, uint32_t dir)
{
	char list_name[RTE_HLIST_NAMESIZE - 8];

	struct rte_hlist_params hp = {
		.name = NULL,
		.entries = VSWITCH_GROUP_LIST_INIT_NUM,
		.entries_per_bucket = VSWITCH_GROUP_LIST_ENTRY_PER_LIST,
		.key_len = sizeof(struct vswitch_dispatch_flow_key),
		.hash_func = rte_hash_crc,
		.free_func = NULL,
		.init_val = 0,
	};
	hp.socket_id = rte_socket_id();
	snprintf(list_name, sizeof(list_name), "vs_%cgr_list_%hu_%hu",
		dir?'e':'i', pid, gid);
	hp.name = list_name;
	return rte_hlist_create(&hp);
}

static void _vswitch_group_hlist_free(struct rte_hlist_table *h)
{
	(void)rte_hlist_free(h);
}

static void _vswitch_group_hlist_data_release(void *data)
{
	struct rte_flow_error err_info;
	struct vswitch_dispatch_flow_data *dflow;

	dflow = (struct vswitch_dispatch_flow_data *)data;
	_rte_flow_destroy(dflow->port_id, dflow->dflow, &err_info);
	LIST_REMOVE(dflow, plink);
	rte_free(dflow);
}

/**
  * Supply a free group to be used.
  *
  * @param pool
  *   Pointer to the group pool.
  *
  * @return
  *   A group on success, NULL otherwise.
  */
static struct vswitch_group *
_vswitch_group_pop(struct vswitch_group_pool *pool) {
	struct vswitch_group *gr;

	if (!TAILQ_EMPTY(&pool->groups)) {
		gr = TAILQ_FIRST(&pool->groups);
		TAILQ_REMOVE(&pool->groups, gr, next);
		gr->valid = 1;
		gr->reseted = 0;
		gr->mcounter = 0;
		return gr;
	}
	RTE_LOG(ERR, VSWITCH, "No more groups\n");
	return NULL;
}

/**
 * Push a group to the group pool.
 *
 * @param gr
 *   Pointer to the group.
 */
static void
_vswitch_group_push(struct vswitch_group *gr) {
	RTE_LOG(DEBUG, VSWITCH, "push group %u\n", gr->group_id);
	if (gr->hl != NULL)
		_vswitch_group_hlist_free(gr->hl);
	TAILQ_INSERT_TAIL(&gr->pool->groups, gr, next);
}

static uint16_t
_oflow_port(struct rte_vswitch_ctx *ctx, struct vswitch_group *gr,
	    struct rte_vswitch_offload_flow *oflow)
{

	if (oflow->type == VSWITCH_OFFLOAD_FLOW_TYPE_PF_TO_VIRTIO ||
	    oflow->type == VSWITCH_OFFLOAD_FLOW_TYPE_PF_TO_VF)
		return ctx->pf->data->port_id;
	if (!gr)
		gr = _vswitch_get_group_by_id(ctx, oflow->mgr_id,
					      oflow->gr_ingress);
	assert(gr);
	return gr->ethdev_port_id;
}

/* This flow is created to catch any unmatched fabric traffic. */
static int
_rte_vswitch_create_pf_fabric_exception_flow(struct rte_vswitch_ctx *ctx,
		 	 	 	     struct vswitch_vport *vport)
{
	static struct rte_flow_attr attr = {
		.ingress = 1,
		.priority = 2,
	};
	static struct rte_flow_item_eth eth_spec = {
		.type = RTE_BE16(ETHER_TYPE_IPv4),
	};
	static struct rte_flow_item_eth eth_mask = {
	    .type = -1,
	};
	static struct rte_flow_item_ipv4 ipv4_spec = {
		.hdr = {
			.next_proto_id = IPPROTO_UDP,
		},
	};
	static struct rte_flow_item_ipv4 ipv4_mask = {
		.hdr = {
			.next_proto_id = -1,
		},
	};
	static struct rte_flow_item_udp udp_spec = {
		.hdr = {
			.dst_port = RTE_BE16(_VSWITCH_FABRIC_VXLAN_UDP_PORT),
		},
	};
	static struct rte_flow_item_udp udp_mask = {
		.hdr = {
			.dst_port = -1,
		},
	};
	enum {ETH, IPV4, UDP, VXLAN, END};
	static struct rte_flow_item pattern[] = {
		[ETH] = {
			.type = RTE_FLOW_ITEM_TYPE_ETH,
			.spec = &eth_spec,
			.mask = &eth_mask,
			.last = NULL,
		},
		[IPV4] = {
			.type = RTE_FLOW_ITEM_TYPE_IPV4,
			.spec = &ipv4_spec,
			.mask = &ipv4_mask,
			.last = NULL,
		},
		[UDP] = {
			.type = RTE_FLOW_ITEM_TYPE_UDP,
			.spec = &udp_spec,
			.mask = &udp_mask,
			.last = NULL,
		},
		[VXLAN] = {
			.type = RTE_FLOW_ITEM_TYPE_VXLAN,
			.spec = NULL,
			.mask = NULL,
			.last = NULL,
		},
		[END] = {
			.type = RTE_FLOW_ITEM_TYPE_END,
			.spec = NULL,
			.mask = NULL,
			.last = NULL,
		},
	};
	static struct rte_eth_rss_conf rss_conf = {
		.rss_key = NULL,
		.rss_key_len = 0,
		.rss_hf = ETH_RSS_IP | ETH_RSS_TCP | ETH_RSS_UDP,
		.rss_level = 1, /* Inner RSS. */
	};
	static union urss rss ={
		.rss_action = {
			.rss_conf = &rss_conf,
			.num = 0,
		},
	};
	static struct rte_flow_action_mark mark;
	enum {RSS, MARK, AEND};
	static struct rte_flow_action actions[] = {
		[RSS] = {
			.type = RTE_FLOW_ACTION_TYPE_RSS,
			.conf = &rss.rss_action,
		},
		[MARK] = {
			.type = RTE_FLOW_ACTION_TYPE_MARK,
			.conf = &mark,
		},
		[AEND] = {
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};
	struct rte_flow_error err;
	unsigned int i;

	if (ctx->type == RTE_VSWITCH_TYPE_SRIOV) {
		/* Eswitch mode PF can't support tunnel offloading. */
		pattern[VXLAN].type = RTE_FLOW_ITEM_TYPE_VOID;
		rss_conf.rss_level = 0;
	} else {
		pattern[VXLAN].type = RTE_FLOW_ITEM_TYPE_VXLAN;
		rss_conf.rss_level = 1;
	}
	mark.id = RTE_VSWITCH_MARK_TYPE_UNKNOWN_VPORT_FLOW | (vport->vport_id << 8);
	rss.rss_action.num = ctx->pf->data->nb_rx_queues;
	for (i = 0; i < rss.rss_action.num; ++i)
		rss.rss_action.queue[i] = i;
	if (!vport->eflowi) {
		vport->eflowi = _rte_flow_create(ctx->pf->data->port_id, &attr,
						 pattern, actions, &err);
		if (!vport->eflowi) {
			RTE_LOG(ERR, VSWITCH,
				"vport: %hu, Failed to create the fabric"
				" exception flow - %s\n", vport->vport_id,
				err.message ? err.message :
					      "(no stated reason)");
			return -1;
		}
	}
	return 0;
}

static int
_vswitch_create_sriov_port_id_flows(struct vswitch_vport *vport)
{
	static struct rte_flow_attr attr = {
		.ingress = 1,
		.transfer = 1,
		.priority = 2,
	};
	static struct rte_flow_item_port_id port_id;
	static struct rte_flow_item pattern[] = {
		[0] = {
			.type = RTE_FLOW_ITEM_TYPE_PORT_ID,
			.spec = &port_id,
			.mask = NULL,
			.last = NULL,
		},
		[1] = {
			.type = RTE_FLOW_ITEM_TYPE_END,
			.spec = NULL,
			.mask = NULL,
			.last = NULL,
		},
	};
	static struct rte_flow_action_jump jump = {
			.group = 1,
	};
	enum {JUMP, PF, END};
	static struct rte_flow_action actions[] = {
		[JUMP] = {
			.type = RTE_FLOW_ACTION_TYPE_JUMP,
			.conf = &jump,
		},
		[PF] = {
			.type = RTE_FLOW_ACTION_TYPE_PF,
			.conf = NULL,
		},
		[END] = {
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};
	struct rte_flow_error err;

	port_id.id = vport->vport_dev->data->port_id;
	actions[JUMP].type = RTE_FLOW_ACTION_TYPE_JUMP;
	actions[PF].type = RTE_FLOW_ACTION_TYPE_VOID;
	attr.group = 0;
	vport->eflowe = _rte_flow_create(port_id.id, &attr, pattern, actions,
					 &err);
	if (!vport->eflowe)
		return -1;
	actions[JUMP].type = RTE_FLOW_ACTION_TYPE_VOID;
	actions[PF].type = RTE_FLOW_ACTION_TYPE_PF;
	attr.group = 1;
	vport->eflowg1 = _rte_flow_create(port_id.id, &attr, pattern, actions,
					  &err);
	if (!vport->eflowg1) {
		_rte_flow_destroy(port_id.id, vport->eflowe, &err);
		vport->eflowe = NULL;
		return -1;
	}
	attr.group = 2;
	vport->eflowg2 = _rte_flow_create(port_id.id, &attr, pattern, actions,
					  &err);
	if (!vport->eflowg2) {
		_rte_flow_destroy(port_id.id, vport->eflowe, &err);
		_rte_flow_destroy(port_id.id, vport->eflowg1, &err);
		vport->eflowe = NULL;
		vport->eflowg1 = NULL;
		return -1;
	}
	return 0;
}

/**
 * Create an ingress exception flow.
 * This flow used to catch unknown policy traffic comes to the vport from
 * the fabric on specific destination group table.
 *
 * @param pf
 *   Pointer to the PF ethernet device.
 * @param vport_id
 *   The vport ID.
 * @param group_id
 *   The group ID.
 *
 * @return
 *   Flow pointer in case of success, NULL otherwise.
 */
static struct rte_flow *
_vswitch_create_group_exception_flow_ingress(struct rte_vswitch_ctx *ctx,
					     struct rte_eth_dev *pf,
					     uint16_t vport_id,
					     uint16_t group_id) {
	static struct rte_flow_attr attr = {
		.priority = 2,
		.ingress = 1,
	};
	static struct rte_flow_item_udp udp_spec = {
		.hdr = {
			.dst_port = RTE_BE16(_VSWITCH_FABRIC_VXLAN_UDP_PORT),
		},
	};
	static struct rte_flow_item_udp udp_mask = {
		.hdr = {
			.dst_port = -1,
		},
	};
	enum {ETH, IP, UDP, VXLAN, END};
	static struct rte_flow_item pattern[] = {
		[ETH] = {
			.type = RTE_FLOW_ITEM_TYPE_ETH,
			.spec = NULL,
			.mask = NULL,
			.last = NULL,
		},
		[IP] = {
			.type = RTE_FLOW_ITEM_TYPE_IPV4,
			.spec = NULL,
			.mask = NULL,
			.last = NULL,
		},
		[UDP] = {
			.type = RTE_FLOW_ITEM_TYPE_UDP,
			.spec = &udp_spec,
			.mask = &udp_mask,
			.last = NULL,
		},
		[VXLAN] = {
			.type = RTE_FLOW_ITEM_TYPE_VXLAN,
			.spec = NULL,
			.mask = NULL,
			.last = NULL,
		},
		[END] = {
			.type = RTE_FLOW_ITEM_TYPE_END,
			.spec = NULL,
			.mask = NULL,
			.last = NULL,
		},
	};
	static struct rte_eth_rss_conf rss_conf = {
		.rss_key = NULL,
		.rss_key_len = 0,
		.rss_hf = ETH_RSS_IP | ETH_RSS_UDP | ETH_RSS_TCP,
		.rss_level = 1,
	};
	static union urss rss ={
		.rss_action = {
			.rss_conf = &rss_conf,
			.num = 0,
		},
	};
	static struct rte_flow_action_mark mark;
	enum {RSS, MARK, AEND};
	static struct rte_flow_action actions[] = {
		[RSS] = {
			.type = RTE_FLOW_ACTION_TYPE_RSS,
			.conf = &rss.rss_action,
		},
		[MARK] = {
			.type = RTE_FLOW_ACTION_TYPE_MARK,
			.conf = &mark,
		},
		[AEND] = {
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};
	struct rte_flow *flow;
	struct rte_flow_error err;
	unsigned int i;

	if (ctx->type == RTE_VSWITCH_TYPE_VIRTIO) {
		pattern[IP].type = RTE_FLOW_ITEM_TYPE_IPV4;
		pattern[UDP].type = RTE_FLOW_ITEM_TYPE_UDP;
		pattern[VXLAN].type = RTE_FLOW_ITEM_TYPE_VXLAN;
		rss_conf.rss_level = 1;
	} else {
		pattern[IP].type = RTE_FLOW_ITEM_TYPE_VOID;
		pattern[UDP].type = RTE_FLOW_ITEM_TYPE_VOID;
		pattern[VXLAN].type = RTE_FLOW_ITEM_TYPE_VOID;
		rss_conf.rss_level = 0;
	}
	attr.group = group_id;
	mark.id = RTE_VSWITCH_MARK_TYPE_UNKNOWN_VPORT_FLOW |
			(vport_id << 8);
	rss.rss_action.num = pf->data->nb_rx_queues;
	for (i = 0; i < rss.rss_action.num; ++i)
		rss.rss_action.queue[i] = i;
	flow = _rte_flow_create(pf->data->port_id, &attr, pattern, actions,
				&err);
	if (!flow)
		RTE_LOG(ERR, VSWITCH, "Failed to create an ingress"
			" PF exception flow in group %u - %s\n", group_id,
			err.message ? err.message : "(no stated reason)");
	else
		RTE_LOG(DEBUG, VSWITCH, "An ingress PF exception flow was "
			"created in group %u\n", group_id);
	return flow;
}

/**
 * Create a vport egress group exception flows on egress group.
 * This flow used to catch unknown policy traffic comes from the vport.
 *
 * @param pf
 *   Pointer to the PF ethernet device.
 * @param vport_id
 *   The vport ID.
 * @param group_id
 *   The flow group ID.
 * @param prio
 *   The flow priority.
 *
 * @return
 *    Flow pointer in case of success, NULL otherwise.
 */
static struct rte_flow *
_vswitch_create_group_exception_flow_egress(struct rte_eth_dev *pf,
					     uint16_t vport_id,
					     uint16_t group_id,
					     uint32_t metadata,
					     uint8_t prio) {
	static struct rte_flow_attr attr = {
		.egress = 1,
	};
	enum {META, END};
	static struct rte_flow_item_meta_ext meta = {
		.id = 0,
	};
	static struct rte_flow_item_meta_ext meta_mask = {
		.id = UINT64_MAX,
		.data = RTE_BE32(0xFFFF0000),
	};
	static struct rte_flow_item pattern[] = {
		[META] = {
			.type = RTE_FLOW_ITEM_TYPE_META_EXT,
			.spec = &meta,
			.mask = &meta_mask,
			.last = NULL,
		},
		[END] = {
			.type = RTE_FLOW_ITEM_TYPE_END,
			.spec = NULL,
			.mask = NULL,
			.last = NULL,
		},
	};
	static struct rte_flow_action_raw_encap encap = {
		.data = (uint8_t *)&lb_encap,
		.size = sizeof(lb_encap),
	};
	enum {ENCAP, AEND};
	static struct rte_flow_action actions[] = {
		[ENCAP] = {
			.type = RTE_FLOW_ACTION_TYPE_RAW_ENCAP,
			.conf = &encap,
		},
		[AEND] = {
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};
	struct rte_flow *flow;
	struct rte_flow_error err;

	meta.data = rte_cpu_to_be_32(metadata);
	attr.group = group_id;
	attr.priority = prio;
	lb_encap.vxlan_flags = 0x08,
	lb_encap.vxlan_vni = RTE_VSWITCH_MARK_TYPE_UNKNOWN_VPORT_FLOW |
			(vport_id << 8);
	memcpy(&lb_encap.ether.d_addr, pf->data->mac_addrs,
	       sizeof(lb_encap.ether.d_addr));
	memcpy(&lb_encap.ether.s_addr, pf->data->mac_addrs,
	       sizeof(lb_encap.ether.d_addr));
	flow = _rte_flow_create(pf->data->port_id, &attr, pattern, actions,
				&err);
	if (!flow)
		RTE_LOG(ERR, VSWITCH, "Failed to create an egress exception "
			"flow on group %u, metadata %u of vport %hu - %s\n",
			group_id, metadata, vport_id,
			err.message ? err.message : "(no stated reason)");
	else
		RTE_LOG(DEBUG, VSWITCH, "An egress exception flow on group %u,"
			" metadata %u of vport %hu was created\n", group_id,
			metadata, vport_id);
	return flow;
}

/**
 * Create the management flows of a vport:
 *  - a flow used to catch known policy traffic comes to the vport.
 *  - flows used to catch unknown policy traffic comes from the vport.
 *
 * @param pf
 *   Pointer to the PF ethernet device.
 * @param vport
 *   Pointer to the vport.
 *
 * @return
 *   0 in case of success, a negative errno otherwise.
 */
static int
_vswitch_vport_prepare_lb_management_flows(struct rte_vswitch_ctx *ctx,
				       struct vswitch_vport *vport)
{
	struct rte_eth_dev *pf = ctx->pf;
	static struct rte_flow_attr attr = {
		.ingress = 1,
		.priority = 1,
	};
	static struct rte_flow_item_eth eth_spec = {
		.type = RTE_BE16(ETHER_TYPE_IPv4),
	};
	static struct rte_flow_item_eth eth_mask = {
	    .type = -1,
	};
	static struct rte_flow_item_ipv4 ipv4_spec = {
		.hdr = {
			.next_proto_id = IPPROTO_UDP,
		},
	};
	static struct rte_flow_item_ipv4 ipv4_mask = {
		.hdr = {
			.next_proto_id = -1,
		},
	};
	static struct rte_flow_item_udp udp_spec = {
		.hdr = {
			.dst_port = RTE_BE16(_VSWITCH_LB_VXLAN_UDP_PORT),
		},
	};
	static struct rte_flow_item_udp udp_mask = {
		.hdr = {
			.dst_port = -1,
		},
	};
	static struct rte_flow_item_vxlan vxlan_spec;
	static struct rte_flow_item_vxlan vxlan_mask = {
		.vni = "\xff\xff\xff",
	};
	enum {ETH, IPV4, UDP, VXLAN, END};
	static struct rte_flow_item pattern[] = {
		[ETH] = {
			.type = RTE_FLOW_ITEM_TYPE_ETH,
			.spec = &eth_spec,
			.mask = &eth_mask,
			.last = NULL,
		},
		[IPV4] = {
			.type = RTE_FLOW_ITEM_TYPE_IPV4,
			.spec = &ipv4_spec,
			.mask = &ipv4_mask,
			.last = NULL,
		},
		[UDP] = {
			.type = RTE_FLOW_ITEM_TYPE_UDP,
			.spec = &udp_spec,
			.mask = &udp_mask,
			.last = NULL,
		},
		[VXLAN] = {
			.type = RTE_FLOW_ITEM_TYPE_VXLAN,
			.spec = &vxlan_spec,
			.mask = &vxlan_mask,
			.last = NULL,
		},
		[END] = {
			.type = RTE_FLOW_ITEM_TYPE_END,
			.spec = NULL,
			.mask = NULL,
			.last = NULL,
		},
	};
	static struct rte_eth_rss_conf rss_conf = {
		.rss_key = NULL,
		.rss_key_len = 0,
		.rss_hf = ETH_RSS_IP | ETH_RSS_UDP | ETH_RSS_TCP,
		.rss_level = 0,
	};
	static union urss rss ={
		.rss_action = {
			.rss_conf = &rss_conf,
			.num = 0,
		},
	};
	static struct rte_flow_action_mark mark;
	enum {DECAP, RSS, MARK, AEND};
	static struct rte_flow_action actions[] = {
		[DECAP] = {
			.type = RTE_FLOW_ACTION_TYPE_RAW_DECAP,
			.conf = NULL,
		},
		[RSS] = {
			.type = RTE_FLOW_ACTION_TYPE_RSS,
			.conf = &rss.rss_action,
		},
		[MARK] = {
			.type = RTE_FLOW_ACTION_TYPE_MARK,
			.conf = &mark,
		},
		[AEND] = {
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};
	struct rte_flow_error err;
	unsigned int i;

	mark.id = RTE_VSWITCH_MARK_TYPE_VPORT_FLOW | (vport->vport_id << 8);
	vxlan_spec.vni[0] = mark.id & 0xFF;
	vxlan_spec.vni[1] = (mark.id >> 8) & 0xFF;
	vxlan_spec.vni[2] = (mark.id >> 16) & 0xFF;
	rss.rss_action.num = pf->data->nb_rx_queues;
	for (i = 0; i < rss.rss_action.num; ++i)
		rss.rss_action.queue[i] = i;
	if (!ctx->restarting && !vport->lb_flow ){
		vport->lb_flow = _rte_flow_create(pf->data->port_id, &attr,
						  pattern, actions, &err);
		if (!vport->lb_flow) {
			RTE_LOG(ERR, VSWITCH,
				"vport: %hu, Failed to create the vport"
				"  LB flow - %s\n", vport->vport_id,
				err.message ? err.message :
					      "(no stated reason)");
			return -1;
		}
	}
	mark.id = RTE_VSWITCH_MARK_TYPE_UNKNOWN_VPORT_FLOW | (vport->vport_id << 8);
	vxlan_spec.vni[0] = RTE_VSWITCH_MARK_TYPE_UNKNOWN_VPORT_FLOW;
	if (!vport->eflowi) {
		vport->eflowi = _rte_flow_create(pf->data->port_id, &attr,
						 pattern, actions, &err);
		if (!vport->eflowi) {
			RTE_LOG(ERR, VSWITCH,
				"vport: %hu, Failed to create the vport"
				" LB exception flow - %s\n", vport->vport_id,
				err.message ? err.message :
					      "(no stated reason)");
			return -1;
		}
	}
	return 0;
}

/**
 * Destroy vport flows.
 *
 * @param ctx
 *   Pointer to the lib context.
 * @param vport
 *   Pointer to the vport.
 * @param exception
 *   whether to destroy the exception flow of the vport group.
 * @param dispatch
 *   whether to destroy the dispatch flow of the vport.
 * @param manage
 *   whether to destroy the management flows of the vport.
 */
static void
_rte_vswitch_destroy_vport_flows(struct rte_vswitch_ctx *ctx,
				 struct vswitch_vport *vport,
				 bool exception, bool dispatch,
				 bool manage) {
	struct rte_flow_error err;
	uint32_t v;

	if (exception) {
		if (vport->igroup && vport->igroup->eflow) {
			_rte_flow_destroy(ctx->pf->data->port_id,
					  vport->igroup->eflow, &err);
			vport->igroup->eflow = NULL;
		}
		if (vport->egroup && vport->egroup->eflow) {
			_rte_flow_destroy(ctx->pf->data->port_id,
					  vport->egroup->eflow, &err);
			vport->egroup->eflow = NULL;
		}
		if (vport->vport_id == ctx->pf_vport_id) {
			for (v = 0; v <= ctx->max_vport_id; ++v) {
				if (ctx->vports[v].valid &&
				    ctx->vports[v].igroup &&
				    ctx->vports[v].igroup->eflow) {
					_rte_flow_destroy(ctx->pf->data->port_id,
							  ctx->vports[v].igroup->eflow,
							  &err);
					ctx->vports[v].igroup->eflow = NULL;
				}
			}
		}
	}
	if (dispatch) {
		struct vswitch_dispatch_flow_data *dflow, *dflow_next, *dflow_tmp;
		struct rte_hlist_data_element *p_de;

		if (vport->igroup) {
			/* Ingress group: PF will be released at first */
			rte_hlist_clear_all_entries_with_cb(
					vport->igroup->hl,
					_vswitch_group_hlist_data_release);
		}
		if (vport->vport_id == ctx->pf_vport_id) {
			for (v = 0; v <= ctx->max_vport_id; ++v) {
				if (ctx->vports[v].valid && ctx->vports[v].igroup) {
					LIST_FOREACH_SAFE(dflow, &vport->egroup->firsts[v], plink, dflow_next) {
						p_de = dflow->p_de;
						rte_hlist_del_entry_fast_return_data(
							ctx->vports[v].igroup->hl,
							p_de, (void **)&dflow_tmp);
						RTE_ASSERT(dflow == dflow_tmp);
						_rte_flow_destroy(dflow->port_id,
							dflow->dflow, &err);
						LIST_REMOVE(dflow, plink);
						rte_free(dflow);
					}
				}
			}
			if (vport->pf_disp_flow) {
				_rte_flow_destroy(ctx->pf->data->port_id,
						  vport->pf_disp_flow, &err);
				vport->pf_disp_flow = NULL;
			}
		}
		if (vport->egroup) {
			/* vport as the destination of a dispatch flow */
			rte_hlist_clear_all_entries_with_cb(
					vport->egroup->hl,
					_vswitch_group_hlist_data_release);
			for (v=0; v<=ctx->max_vport_id; v++) {
				if (!ctx->vports[v].valid)
					continue;
				/* vport as source of a dispatch flow */
				LIST_FOREACH_SAFE(dflow, &vport->egroup->firsts[v], plink, dflow_next) {
					p_de = dflow->p_de;
					rte_hlist_del_entry_fast_return_data(
						ctx->vports[v].egroup->hl,
						p_de, (void **)&dflow_tmp);
					RTE_ASSERT(dflow == dflow_tmp);
					_rte_flow_destroy(dflow->port_id, dflow->dflow, &err);
					LIST_REMOVE(dflow, plink);
					rte_free(dflow);
				}
			}
		}
	}
	if (manage) {
		uint16_t port_id = ctx->type ==  RTE_VSWITCH_TYPE_VIRTIO ?
			ctx->pf->data->port_id :
			vport->vport_dev->data->port_id;

		if (vport->eflowe) {
			_rte_flow_destroy(port_id, vport->eflowe, &err);
			vport->eflowe = NULL;
		}
		if (vport->eflowi) {
			_rte_flow_destroy(port_id, vport->eflowi, &err);
			vport->eflowi = NULL;
		}
		if (vport->lb_flow) {
			_rte_flow_destroy(port_id, vport->lb_flow, &err);
			vport->lb_flow = NULL;
		}
		if (vport->eflowg1) {
			_rte_flow_destroy(port_id, vport->eflowg1, &err);
			vport->eflowg1 = NULL;
		}
		if (vport->eflowg2) {
			_rte_flow_destroy(port_id, vport->eflowg2, &err);
			vport->eflowg2 = NULL;
		}
	}
}

/**
 *  Create the egress exception flow to jump to group.
 *
 * @param pf
 *   Pointer to the PF ethernet device.
 * @param vport_id
 *   The vport ID..
 * @param group_id
 *   The egress group ID.
 * @param next_group_id
 *   The group ID to jump.
 *
 * @return
 *   Dispatch flow pointer in case of success, NULL otherwise.
 */
static struct rte_flow *
_vswitch_create_jump_exception_flow_egress(struct rte_eth_dev *pf,
					 uint32_t next_group_id,
					 uint32_t group_id,
					 uint32_t metadata,
					 uint8_t prio) {
	static struct rte_flow_attr attr = {
		.egress = 1,
	};
	static struct rte_flow_item_meta_ext meta = {
		.id = 0,
	};
	static struct rte_flow_item_meta_ext meta_mask = {
		.id = UINT64_MAX,
		.data = RTE_BE32(0xFFFF0000),
	};
	enum {META, ETH, END};
	static struct rte_flow_item pattern[] = {
		[META] = {
			.type = RTE_FLOW_ITEM_TYPE_META_EXT,
			.spec = &meta,
			.mask = &meta_mask,
			.last = NULL,
		},
		[ETH] = {
			.type = RTE_FLOW_ITEM_TYPE_ETH,
			.spec = NULL,
			.mask = NULL,
			.last = NULL,
		},
		[END] = {
			.type = RTE_FLOW_ITEM_TYPE_END,
			.spec = NULL,
			.mask = NULL,
			.last = NULL,
		},
	};
	static struct rte_flow_action_jump jump;
	static struct rte_flow_action actions[] = {
		[0] = {
			.type = RTE_FLOW_ACTION_TYPE_JUMP,
			.conf = &jump,
		},
		[1] = {
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};
	struct rte_flow_error err;
	struct rte_flow *flow;

	if (metadata == 1) {
		meta.data = rte_cpu_to_be_32(metadata);
		pattern[META].type = RTE_FLOW_ITEM_TYPE_META_EXT;
		meta_mask.data = RTE_BE32(0x1);
	} else if (metadata) {
		meta.data = rte_cpu_to_be_32(metadata);
		pattern[META].type = RTE_FLOW_ITEM_TYPE_META_EXT;
		meta_mask.data = RTE_BE32(0xFFFF0000);
	} else
		pattern[META].type = RTE_FLOW_ITEM_TYPE_VOID;
	jump.group = next_group_id;
	attr.group = group_id;
	attr.priority = prio;
	flow = _rte_flow_create(pf->data->port_id, &attr, pattern,
				actions, &err);
	if (!flow)
		RTE_LOG(ERR, VSWITCH, "Failed to create jump exception flow"
			" metadata %u jump to group %u on group %u- %s\n",
			metadata, next_group_id, group_id,
			err.message ? err.message : "(no stated reason)");
	else
		RTE_LOG(DEBUG, VSWITCH, "Jump exception flow on group 0 was "
			"created: metadata %u jump to group %u on group %u\n",
			metadata, next_group_id, group_id);
	return flow;
}

static void
_vswitch_invalidate_vport_group(struct rte_vswitch_ctx *ctx,
				struct vswitch_group **gr)
{
	if (gr && *gr) {
		(*gr)->valid = 0;
		if (LIST_EMPTY(&(*gr)->oflows) &&
		    (*gr)->mcounter == 0)
			_vswitch_group_push(*gr);
		else
			TAILQ_INSERT_TAIL(&ctx->invalid_groups, *gr,
					  next);
		*gr = NULL;
	}
}

/**
 * stop one vport
 * all oflows' handlers are kept for user lazy deletion
 * all rte_flow should be cleaned up during eth_dev_stop
 *
 * @param ctx
 *   pointer to rte_vswitch_context
 *
 */
static void
_vswitch_vport_stop(struct rte_vswitch_ctx *ctx, struct vswitch_vport * vport,
		    uint8_t reset)
{
	_rte_vswitch_destroy_vport_flows(ctx, vport, 1, 1, 1);
	if (vport->igroup) {
		vport->igroup->reseted = reset;
		_vswitch_invalidate_vport_group(ctx, &vport->igroup);
	}
	if (vport->egroup) {
		vport->egroup->reseted = reset;
		_vswitch_invalidate_vport_group(ctx, &vport->egroup);
	}
}

/**
 * stop all vports
 * all oflows' handlers are kept
 * all rte_flow should be cleaned up during eth_dev_stop
 *
 * @param ctx
 *   Pointer to the rte_vswitch_ctx
 */
static void
_vswitch_stop(struct rte_vswitch_ctx *ctx)
{
	uint32_t v;

	for (v = 0; v <= ctx->max_vport_id; v++)
		if (ctx->vports[v].valid)
			_vswitch_vport_stop(ctx, &ctx->vports[v], 1);
}

/**
 *  Unregister a vport. Release all the management resources associated to the
 *  vport. Note: the offload flows must be destroyed by the application.
 *
 * @param ctx
 *   Pointer to the lib context.
 * @param vport_id
 *   The vport ID.
 */
static void
_rte_vswitch_unregister_vport(struct rte_vswitch_ctx *ctx, uint16_t vport_id) {
	struct vswitch_vport *vport = &ctx->vports[vport_id];

	_vswitch_vport_stop(ctx, vport, 0);
	memset(vport, 0, sizeof(*vport));
	RTE_LOG(DEBUG, VSWITCH, "vport %hu was destroyed.\n", vport_id);
}

/* Destroy the vport groups. */
static void
_rte_vswitch_destroy_vport_groups(struct rte_vswitch_ctx *ctx,
				  struct vswitch_group **igr,
				  struct vswitch_group **egr) {

	struct rte_flow_error err;

	if (igr && *igr) {
		if ((*igr)->eflow) {
			_rte_flow_destroy(ctx->pf->data->port_id,
					  (*igr)->eflow, &err);
			(*igr)->eflow = NULL;
		}
		_vswitch_group_push(*igr);
		*igr = NULL;
	}
	if (egr && *egr) {
		if ((*egr)->eflow) {
			_rte_flow_destroy(ctx->pf->data->port_id,
					  (*egr)->eflow, &err);
			(*egr)->eflow = NULL;
		}
		_vswitch_group_push(*egr);
		*egr = NULL;
	}
}

/* Create the vport groups. */
static int
_rte_vswitch_create_vport_groups(struct rte_vswitch_ctx *ctx,
				 uint16_t vport_id,
				 struct vswitch_group **igr,
				 struct vswitch_group **egr) {
	struct vswitch_group *gr;

	if (igr) {
		gr = _vswitch_group_pop(&ctx->ipool);
		if (!gr) {
			RTE_LOG(ERR, VSWITCH, "vport %hu, Failed to create a"
				" vport ingress group\n", vport_id);
			return -ENOMEM;
		}
		if (ctx->type == RTE_VSWITCH_TYPE_VIRTIO) {
			gr->eflow =
				_vswitch_create_group_exception_flow_ingress
					(ctx, ctx->pf, ctx->pf_vport_id,
					 gr->group_id);
			if (!gr->eflow) {
				RTE_LOG(ERR, VSWITCH, "vport %hu, Failed to "
					"create a vport ingress group "
					"exception flow\n", vport_id);
				goto error;
			}
		}
		gr->ethdev_port_id = ctx->vports[vport_id].vport_dev ?
			ctx->vports[vport_id].vport_dev->data->port_id :
			ctx->pf->data->port_id;
		gr->hl = _vswitch_group_hlist_create(gr->ethdev_port_id,
							gr->group_id, 0);
		if (gr->hl == NULL) {
			RTE_LOG(ERR, VSWITCH,
				"Failed to create hlist for igroup %u %u\n",
				gr->ethdev_port_id, gr->group_id);
			goto error;
		}
		*igr = gr;
	}
	if (egr) {
		gr = _vswitch_group_pop(&ctx->epool);
		if (!gr) {
			RTE_LOG(ERR, VSWITCH, "vport %hu, Failed to create a"
				" vport egress group\n", vport_id);
			goto error;
		}
		if (ctx->type == RTE_VSWITCH_TYPE_VIRTIO) {
			gr->eflow = _vswitch_create_jump_exception_flow_egress
				(ctx->pf, _VSWITCH_EXC_GROUP_ID, gr->group_id,
				 1, 1);
			if (!gr->eflow) {
				RTE_LOG(ERR, VSWITCH, "vport %hu, Failed to "
					"create a vport egress group exception"
					" flow\n", vport_id);
				goto error;
			}
		}
		gr->ethdev_port_id = ctx->vports[vport_id].vport_dev ?
			ctx->vports[vport_id].vport_dev->data->port_id :
			ctx->pf->data->port_id;
		gr->hl = _vswitch_group_hlist_create(gr->ethdev_port_id,
							gr->group_id, 1);
		if (gr->hl == NULL) {
			RTE_LOG(ERR, VSWITCH,
				"Failed to create hlist for egroup %u %u\n",
				gr->ethdev_port_id, gr->group_id);
			goto error;
		}
		*egr = gr;
	}
	return 0;
error:
	_rte_vswitch_destroy_vport_groups(ctx, igr, egr);
	return -1;
}

/**
 *  Register a vport.
 *
 * @param ctx
 *   Pointer to the lib context.
 * @param vport_id
 *   The vport ID.
 * @param vport_dev
 *   Pointer to the vport ethernet device.
 *
 * @return
 *   0 in case of success, a negative value otherwise.
 */
static int
_rte_vswitch_register_vport(struct rte_vswitch_ctx *ctx, uint16_t vport_id,
			    struct rte_eth_dev *vport_dev) {
	struct vswitch_vport *vport = &ctx->vports[vport_id];
	struct rte_flow *temp_eflowe = NULL;

	vport->vport_id = vport_id;
	vport->vport_dev = vport_dev;
	if (vport_dev && port_lock_init(vport_dev))
		return -1;
	if (_rte_vswitch_create_vport_groups(ctx, vport_id,
					     !vport_dev ? &vport->igroup : NULL,
					     &vport->egroup))
		return -ENOMEM;
	if (ctx->type == RTE_VSWITCH_TYPE_VIRTIO) {
		if (!vport_dev) {
			if (_vswitch_vport_prepare_lb_management_flows
				(ctx, vport))
				goto error;
			/* we could have temp eflowe which is in root table */
			temp_eflowe = vport->eflowe;
			vport->eflowe =
				_vswitch_create_group_exception_flow_egress
				(ctx->pf, vport->vport_id,
				 _VSWITCH_EXC_GROUP_ID,
				 _GET_VPORT_METADATA(vport), 0);
			/* release temp eflow which is in root table */
			if (temp_eflowe)
				_rte_flow_destroy
				(ctx->pf->data->port_id, temp_eflowe, NULL);
			if (!vport->eflowe) {
				RTE_LOG(ERR, VSWITCH,
					"vport: %hu, Failed to create the vport"
					" LB egress exception flow\n",
					vport->vport_id);
				goto error;
			}
		} else {
			if(_rte_vswitch_create_pf_fabric_exception_flow(ctx, vport))
				goto error;
			vport->eflowe = _vswitch_create_jump_exception_flow_egress
					(ctx->pf, _VSWITCH_EXC_GROUP_ID, 0, 1, 3);
			if (!vport->eflowe)
				goto error;
			vport->pf_disp_flow =
				_vswitch_create_jump_exception_flow_egress
					(ctx->pf, vport->egroup->group_id, 0, 1, 1);
			if (!vport->pf_disp_flow)
				goto error;
		}
	} else {
		if (vport_id == ctx->pf_vport_id) {
			if(_rte_vswitch_create_pf_fabric_exception_flow(ctx, vport))
				goto error;
		} else {
			vport->eflowi =
				_vswitch_create_group_exception_flow_ingress
					(ctx, vport_dev, vport_id, 0);
			if (!vport->eflowi)
				goto error;
		}
		if (_vswitch_create_sriov_port_id_flows(vport))
			goto error;
	}
	vport->valid = 1;
	if (vport_dev)
		aging_register_port(vport_id, vport_dev->data->port_id, ctx);
	RTE_LOG(DEBUG, VSWITCH, "vport %hu was created.\n", vport_id);
	return 0;
error:
	_rte_vswitch_destroy_vport_flows(ctx, vport, 1, 1, 1);
	_rte_vswitch_destroy_vport_groups(ctx,
					  !vport_dev ? &vport->igroup : NULL,
					  &vport->egroup);
	vport->vport_dev = NULL;
	return -1;
}

int
rte_vswitch_register_vport(struct rte_vswitch_ctx *ctx, uint16_t vport_id,
			   struct rte_eth_dev *vport_rep) {
	if (!ctx) {
		RTE_LOG(ERR, VSWITCH, "Failed to create vport %hu - invalid"
			" context\n", vport_id);
		return -EINVAL;
	}
	if (vport_id > ctx->max_vport_id) {
		RTE_LOG(ERR, VSWITCH, "Failed to create vport - invalid"
			" vport ID(%hu > %hu)\n", vport_id, ctx->max_vport_id);
		return -E2BIG;
	}
	if (ctx->vports[vport_id].valid) {
		RTE_LOG(ERR, VSWITCH, "Failed to register vport %hu - already"
			" registered\n", vport_id);
		return -EEXIST;
	}
	if (ctx->type == RTE_VSWITCH_TYPE_VIRTIO && vport_rep) {
		RTE_LOG(ERR, VSWITCH, "Failed to create vport %hu -  ethdev"
			" should not be valid in VIRTIO vswitch\n", vport_id);
		return -EINVAL;
	} else if (ctx->type == RTE_VSWITCH_TYPE_SRIOV && !vport_rep) {
		RTE_LOG(ERR, VSWITCH, "Failed to create vport %hu - ethdev"
			" should be valid for SRIOV vswitch\n", vport_id);
	}
	if (_vswitch_prepare_context(ctx))
		return -EINVAL;
	return _rte_vswitch_register_vport(ctx, vport_id, vport_rep);
}

int
rte_vswitch_unregister_vport(struct rte_vswitch_ctx *ctx, uint16_t vport_id) {
	if (!ctx) {
		RTE_LOG(ERR, VSWITCH, "Failed to unregister vport %hu -"
			" invalid context\n", vport_id);
		return -EINVAL;
	}
	if (vport_id > ctx->max_vport_id) {
		RTE_LOG(ERR, VSWITCH, "Failed to unregister vport - invalid"
			" vport ID(%hu > %hu)\n", vport_id, ctx->max_vport_id);
		return -E2BIG;
	}
	if (!ctx->vports[vport_id].valid) {
		RTE_LOG(WARNING, VSWITCH, "vport %hu - already unregistered\n",
			vport_id);
		return 0;
	}
	if (_vswitch_prepare_context(ctx))
		return -EINVAL;
	_rte_vswitch_unregister_vport(ctx, vport_id);
	return 0;
}

struct rte_vswitch_ctx *
rte_vswitch_open(struct rte_eth_dev *pf, uint16_t pf_vport_id,
		 uint16_t max_vport_id, enum rte_vswitch_type type) {
	struct rte_vswitch_ctx *vswitch_ctx;
	unsigned int alloc_size;

	if (!pf) {
		RTE_LOG(ERR, VSWITCH, "Failed to create vswitch - invalid"
			" PF ethernet device\n");
		return NULL;
	}
	if (max_vport_id == 0)
		RTE_LOG(WARNING, VSWITCH, "Creating vswitch without vport enabled\n");
	if (pf_vport_id > max_vport_id) {
		RTE_LOG(ERR, VSWITCH, "Failed to create vswitch - pf_vport_id"
			" cannot be bigger than max_vport_id\n");
		return NULL;
	}
	if (pf->data->dev_started == 0) {
		RTE_LOG(ERR, VSWITCH, "Device %u is not started\n", pf_vport_id);
		return NULL;
	}
	if (type != RTE_VSWITCH_TYPE_VIRTIO &&
	    type != RTE_VSWITCH_TYPE_SRIOV) {
		RTE_LOG(ERR, VSWITCH, "Failed to create vswitch - unknown"
			" vswitch type\n");
		return NULL;
	}
	alloc_size = sizeof(struct rte_vswitch_ctx) + (max_vport_id + 1) *
			sizeof(struct vswitch_vport);
	alloc_size += sizeof(struct vswitch_group) * _VSWITCH_MAX_GROUPS;
	alloc_size += (sizeof(struct vswitch_group) +
			sizeof(struct vswitch_dispatch_flow *) *
			(max_vport_id + 1)) * _VSWITCH_MAX_GROUPS;
	vswitch_ctx = rte_zmalloc_socket(__func__, alloc_size,
					 RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (!vswitch_ctx) {
		RTE_LOG(ERR, VSWITCH, "Cannot allocate memory for vswitch"
			" context\n");
		return NULL;
	}
	vswitch_ctx->max_vport_id = max_vport_id;
	vswitch_ctx->pf = pf;
	vswitch_ctx->pf_vport_id = pf_vport_id;
	vswitch_ctx->type = type;
	_vswitch_init_group_pools(vswitch_ctx);
	aging_init();
	/* group 0 will be used for vswitch management purposes */
	if (_rte_vswitch_register_vport(vswitch_ctx, pf_vport_id, pf))
		goto error;
	if (rte_eth_dev_callback_register(pf_vport_id,
					  RTE_ETH_EVENT_INTR_RMV,
					  _vswitch_event_handler,
					  NULL)) {
		_rte_vswitch_unregister_vport(vswitch_ctx, pf_vport_id);
		goto error;
	}
	return vswitch_ctx;
error:
	rte_free(vswitch_ctx);
	return NULL;
}

int
rte_vswitch_close(struct rte_vswitch_ctx *ctx) {
	struct vswitch_group *gr;
	struct rte_vswitch_offload_flow *oflow;
	struct rte_flow_error err;
	uint32_t v;

	if (!ctx) {
		RTE_LOG(ERR, VSWITCH, "Failed to close vswitch - invalid"
			" context\n");
		return -EINVAL;
	}
	aging_close();
	for (v = 0; v <= ctx->max_vport_id; ++v)
		if (ctx->vports[v].valid)
			_rte_vswitch_unregister_vport(ctx, v);
	TAILQ_FOREACH(gr, &ctx->invalid_groups, next) {
		while (!LIST_EMPTY(&gr->oflows)) {
			oflow = LIST_FIRST(&gr->oflows);
			if (!gr->reseted && oflow->flow)
				_rte_flow_destroy(_oflow_port(ctx, NULL, oflow),
						  oflow->flow, &err);
			LIST_REMOVE(oflow, next);
			rte_free(oflow);
		}
	}
	_vswitch_flush_meter(ctx);
	if (rte_eth_dev_callback_unregister(ctx->pf->data->port_id,
					    RTE_ETH_EVENT_INTR_RMV,
					    _vswitch_event_handler, NULL))
		RTE_LOG(WARNING, VSWITCH,
			"Cannot unregister _vswitch_event_handler");
	rte_free(ctx);
	return 0;
}

/* Create an egress dispatch flow if not exist. */
static int
_vswitch_prepare_egress_dispatch_flow(struct rte_vswitch_ctx *ctx,
				      struct vswitch_vport *dst_vport,
				      struct vswitch_vport *src_vport,
				      struct rte_vswitch_flow_keys_base *key)
{
	static struct rte_flow_item_port_id port_id;
	static struct rte_flow_attr attr;
	static struct rte_flow_item_meta_ext meta = {
		.id = 0,
	};
	static struct rte_flow_item_meta_ext meta_mask = {
		.id = UINT64_MAX,
		.data = RTE_BE32(0xFFFFFFFF),
	};
	static struct rte_flow_item_ipv4 ipv4_spec;
	static struct rte_flow_item_ipv4 ipv4_mask = {
		.hdr = {
			.dst_addr = RTE_BE32(0xffffffff),
		},
	};
	static struct rte_flow_item_ipv6 ipv6_spec;
	static struct rte_flow_item_ipv6 ipv6_mask = {
		.hdr = {
			.dst_addr =
				"\xff\xff\xff\xff\xff\xff\xff\xff"
				"\xff\xff\xff\xff\xff\xff\xff\xff",
		},
	};
	enum {PORT_ID, META, ETH, IPV4, IPV6, END};
	static struct rte_flow_item pattern[] = {
		[PORT_ID] = {
			.type = RTE_FLOW_ITEM_TYPE_PORT_ID,
			.spec = &port_id,
			.mask = NULL,
			.last = NULL,
		},
		[META] = {
			.type = RTE_FLOW_ITEM_TYPE_META_EXT,
			.spec = &meta,
			.mask = &meta_mask,
			.last = NULL,
		},
		[ETH] = {
			.type = RTE_FLOW_ITEM_TYPE_ETH,
			.spec = NULL,
			.mask = NULL,
			.last = NULL,
		},
		[IPV4] = {
			.type = RTE_FLOW_ITEM_TYPE_IPV4,
			.spec = &ipv4_spec,
			.mask = &ipv4_mask,
			.last = NULL,
		},
		[IPV6] = {
			.type = RTE_FLOW_ITEM_TYPE_IPV6,
			.spec = &ipv6_spec,
			.mask = &ipv6_mask,
			.last = NULL,
		},
		[END] = {
			.type = RTE_FLOW_ITEM_TYPE_END,
			.spec = NULL,
			.mask = NULL,
			.last = NULL,
		},
	};
	static struct rte_flow_action_set_meta set_meta = {
		.id = 1,
	};
	static struct rte_flow_action_jump jump;
	enum {SET_META, JUMP, AEND};
	static struct rte_flow_action actions[] = {
		[SET_META] = {
			.type = RTE_FLOW_ACTION_TYPE_SET_META,
			.conf = &set_meta,
		},
		[JUMP] = {
			.type = RTE_FLOW_ACTION_TYPE_JUMP,
			.conf = &jump,
		},
		[AEND] = {
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};
	struct rte_flow_error err;
	struct vswitch_group *gr = dst_vport->egroup;
	struct vswitch_dispatch_flow_key df_key;
	struct vswitch_dispatch_flow_data *dflow;
	struct vswitch_dispatch_flow_data *r_dflow;
	struct rte_hlist_data_element *de;
	int ret;

	if (!key->dst_addr_valid) {
		RTE_LOG(ERR, VSWITCH, "Failed to create an egress dispatch "
			"flow from vport %hu to vport %hu - invalid dst L3 "
			"address\n", src_vport->vport_id, dst_vport->vport_id);
		return -EINVAL;
	}
	df_key.ipv = key->ip_type;
	df_key.vni = 0;
	df_key.vxlan_type = 0;
	df_key.pad = 0;
	if (df_key.ipv == 0) {
		df_key.ipv4_addr = key->dst_addr;
		memset(&df_key.ipv6_addr[4], 0, 12);
	} else {
		rte_memcpy(df_key.ipv6_addr, key->dst_addr6, 16);
	}
	de = rte_hlist_add_key(gr->hl, &df_key);
	if (!rte_hlist_entry_is_new(de))
		return 0;

	dflow = rte_zmalloc_socket(__func__, sizeof(struct vswitch_dispatch_flow_data),
				   RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (!dflow) {
		RTE_LOG(ERR, VSWITCH, "Failed to create an egress dispatch "
			"flow from vport %hu to vport %hu - no memory \n",
			src_vport->vport_id, dst_vport->vport_id);
		rte_hlist_del_entry_fast_return_data(gr->hl, de, (void **)&r_dflow);
		return -ENOMEM;
	}
	if ((ret = rte_hlist_entry_append_custom_data(gr->hl, de, dflow)) != 0) {
		RTE_LOG(ERR, VSWITCH, "Failed to append customer data "
			"flow from vport %hu to vport %hu - %d\n",
			src_vport->vport_id, dst_vport->vport_id, ret);
		rte_hlist_del_entry_fast_return_data(gr->hl, de, (void **)&r_dflow);
		return ret;
	}
	dflow->p_de = de;

	if (!key->ip_type) {
		pattern[IPV4].type = RTE_FLOW_ITEM_TYPE_IPV4;
		pattern[IPV6].type = RTE_FLOW_ITEM_TYPE_VOID;
		ipv4_spec.hdr.dst_addr = key->dst_addr;
	} else {
		pattern[IPV4].type = RTE_FLOW_ITEM_TYPE_VOID;
		pattern[IPV6].type = RTE_FLOW_ITEM_TYPE_IPV6;
		memcpy(ipv6_spec.hdr.dst_addr, key->dst_addr6, 16);
	}
	if (ctx->type == RTE_VSWITCH_TYPE_VIRTIO) {
		attr.group = 0;
		attr.egress = 1;
		attr.ingress = 0;
		attr.transfer = 0;
		pattern[PORT_ID].type = RTE_FLOW_ITEM_TYPE_VOID;
		pattern[META].type = RTE_FLOW_ITEM_TYPE_META_EXT;
		actions[SET_META].type = RTE_FLOW_ACTION_TYPE_VOID;
		jump.group = dst_vport->egroup->group_id;
		meta.data = rte_cpu_to_be_32(_GET_VPORT_METADATA(src_vport));
		dflow->port_id = port_id.id = ctx->pf->data->port_id;
	} else {
		attr.group = 1;
		attr.egress = 0;
		attr.ingress = 1;
		attr.transfer = 1;
		pattern[PORT_ID].type = RTE_FLOW_ITEM_TYPE_PORT_ID;
		pattern[META].type = RTE_FLOW_ITEM_TYPE_VOID;
		actions[SET_META].type = RTE_FLOW_ACTION_TYPE_SET_META;
		dflow->port_id = port_id.id = src_vport->vport_dev->data->port_id;
		jump.group = 2;
		set_meta.data = rte_cpu_to_be_32
				(_GET_SRIOV_METADATA(src_vport, dst_vport));
	}
	dflow->dflow = _rte_flow_create(port_id.id, &attr, pattern, actions, &err);
	if (!dflow->dflow) {
		rte_hlist_del_entry_fast_return_data(gr->hl, de, (void **)&r_dflow);
		RTE_ASSERT(r_dflow == dflow);
		rte_free(dflow);
		RTE_LOG(ERR, VSWITCH, "Failed to create an egress dispatch "
			"flow from vport %hu to vport %hu - %s\n",
			src_vport->vport_id, dst_vport->vport_id,
			err.message ? err.message : "(no stated reason)");
		return -1;
	}
	RTE_LOG(DEBUG, VSWITCH, "Dispatch flow egress was created from vport %hu"
		" to vport %hu\n", src_vport->vport_id, dst_vport->vport_id);
	LIST_INSERT_HEAD(&src_vport->egroup->firsts[dst_vport->vport_id],
			dflow, plink);
	return 0;
}

/**
 *  Create a non-tunnel offload flow.
 *
 * @param ctx
 *   Pointer to the vswitch context.
 * @param oflow
 *   Pointer to new offload flow.
 * @param keys
 *   The flow keys pointer.
 * @param oactions
 *   The vswitch offload flow actions pointer.
 * @param dst_vport
 *   The destination vport pointer.
 * @param src_vport
 *   The source vport pointer.
 *
 * @return
 *   0 in case of success, a negative value otherwise.
 */
static int
_vswitch_create_non_tunnel_offload_flow(struct rte_vswitch_ctx *ctx,
					struct rte_vswitch_offload_flow *oflow,
					struct rte_vswitch_flow_keys *keys,
					struct rte_vswitch_flow_actions *oactions,
					struct vswitch_vport *dst_vport,
					struct vswitch_vport *src_vport) {
	static struct rte_flow_attr attr;
	static struct rte_flow_item_port_id port_id;
	static struct rte_flow_item_meta_ext meta;
	static struct rte_flow_item_meta_ext meta_mask = {
		.id = UINT64_MAX,
		.data = RTE_BE32(0xFFFFFFFF),
	};
	static struct rte_flow_item_eth eth_spec;
	static struct rte_flow_item_eth eth_mask;
	static struct rte_flow_item_ipv4 ipv4_spec;
	static struct rte_flow_item_ipv4 ipv4_mask;
	static struct rte_flow_item_ipv6 ipv6_spec;
	static struct rte_flow_item_ipv6 ipv6_mask;
	static struct rte_flow_item_icmp icmp_spec;
	static struct rte_flow_item_icmp icmp_mask = {
		.hdr = { .icmp_type = 0xff, },
	};
	static struct rte_flow_item_icmpv6 icmpv6_spec;
	static struct rte_flow_item_icmpv6 icmpv6_mask = {
		.hdr = { .icmp_type = 0xff, },
	};
	static struct rte_flow_item_tcp tcp_spec;
	static struct rte_flow_item_tcp tcp_mask;
	static struct rte_flow_item_udp udp_spec;
	static struct rte_flow_item_udp udp_mask;
	enum {PORT_ID, META, ETH, IPV4, IPV6, ICMP, ICMPV6, TCP, UDP, END};
	static struct rte_flow_item pattern[] = {
		[PORT_ID] = {
			.type = RTE_FLOW_ITEM_TYPE_PORT_ID,
			.spec = &port_id,
			.mask = NULL,
			.last = NULL,
		},
		[META] = {
			.type = RTE_FLOW_ITEM_TYPE_META_EXT,
			.spec = &meta,
			.mask = &meta_mask,
			.last = NULL,
		},
		[ETH] = {
			.type = RTE_FLOW_ITEM_TYPE_ETH,
			.spec = &eth_spec,
			.mask = &eth_mask,
			.last = NULL,
		},
		[IPV4] = {
			.type = RTE_FLOW_ITEM_TYPE_IPV4,
			.spec = &ipv4_spec,
			.mask = &ipv4_mask,
			.last = NULL,
		},
		[IPV6] = {
			.type = RTE_FLOW_ITEM_TYPE_IPV6,
			.spec = &ipv6_spec,
			.mask = &ipv6_mask,
			.last = NULL,
		},
		[ICMP] = {
			.type = RTE_FLOW_ITEM_TYPE_ICMP,
			.spec = &icmp_spec,
			.mask = &icmp_mask,
			.last = NULL,
		},
		[ICMPV6] = {
			.type = RTE_FLOW_ITEM_TYPE_ICMPV6,
			.spec = &icmpv6_spec,
			.mask = &icmpv6_mask,
			.last = NULL,
		},
		[TCP] = {
			.type = RTE_FLOW_ITEM_TYPE_TCP,
			.spec = &tcp_spec,
			.mask = &tcp_mask,
			.last = NULL,
		},
		[UDP] = {
			.type = RTE_FLOW_ITEM_TYPE_UDP,
			.spec = &udp_spec,
			.mask = &udp_mask,
			.last = NULL,
		},
		[END] = {
			.type = RTE_FLOW_ITEM_TYPE_END,
			.spec = NULL,
			.mask = NULL,
			.last = NULL,
		},
	};
	static struct rte_flow_action_port_id act_port_id;
	static struct rte_flow_action_raw_decap decap;
	static struct rte_flow_action_raw_encap encap;
	static struct rte_flow_action_set_mac set_mac_src;
	static struct rte_flow_action_set_mac set_mac_dst;
	static struct rte_flow_action_set_ipv4 set_ipv4_src;
	static struct rte_flow_action_set_ipv4 set_ipv4_dst;
	static struct rte_flow_action_set_ipv6 set_ipv6_src;
	static struct rte_flow_action_set_ipv6 set_ipv6_dst;
	static struct rte_flow_action_set_tp set_tp_src;
	static struct rte_flow_action_set_tp set_tp_dst;
	static struct rte_flow_action_set_ttl set_ttl;
	static struct rte_flow_action_modify_tcp_seq dec_tcp_seq;
	static struct rte_flow_action_modify_tcp_seq inc_tcp_seq;
	static struct rte_flow_action_modify_tcp_ack dec_tcp_ack;
	static struct rte_flow_action_modify_tcp_ack inc_tcp_ack;
	static struct rte_flow_action_count count;
	static struct rte_flow_action_meter meter;
	enum {ACT_PORT_ID, SET_IPV4_SRC, SET_IPV4_DST, SET_IPV6_SRC,
	      SET_IPV6_DST, SET_MAC_SRC, SET_MAC_DST, SET_TP_SRC, SET_TP_DST,
	      SET_TTL, DEC_TTL, DEC_TCP_SEQ, INC_TCP_SEQ, DEC_TCP_ACK,
	      INC_TCP_ACK, DECAP, ENCAP, COUNT, METER,AEND};
	static struct rte_flow_action actions[] = {
		[ACT_PORT_ID] = {
			.type = RTE_FLOW_ACTION_TYPE_PORT_ID,
			.conf = &act_port_id,
		},
		[SET_IPV4_SRC] = {
			.type = RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC,
			.conf = &set_ipv4_src,
		},
		[SET_IPV4_DST] = {
			.type = RTE_FLOW_ACTION_TYPE_SET_IPV4_DST,
			.conf = &set_ipv4_dst,
		},
		[SET_IPV6_SRC] = {
			.type = RTE_FLOW_ACTION_TYPE_SET_IPV6_SRC,
			.conf = &set_ipv6_src,
		},
		[SET_IPV6_DST] = {
			.type = RTE_FLOW_ACTION_TYPE_SET_IPV6_DST,
			.conf = &set_ipv6_dst,
		},
		[SET_MAC_SRC] = {
			.type = RTE_FLOW_ACTION_TYPE_SET_MAC_SRC,
			.conf = &set_mac_src,
		},
		[SET_MAC_DST] = {
			.type = RTE_FLOW_ACTION_TYPE_SET_MAC_DST,
			.conf = &set_mac_dst,
		},
		[SET_TP_SRC] = {
			.type = RTE_FLOW_ACTION_TYPE_SET_TP_SRC,
			.conf = &set_tp_src,
		},
		[SET_TP_DST] = {
			.type = RTE_FLOW_ACTION_TYPE_SET_TP_DST,
			.conf = &set_tp_dst,
		},
		[SET_TTL] = {
			.type = RTE_FLOW_ACTION_TYPE_SET_TTL,
			.conf = &set_ttl,
		},
		[DEC_TTL] = {
			.type = RTE_FLOW_ACTION_TYPE_DEC_TTL,
			.conf = NULL,
		},
		[DEC_TCP_SEQ] = {
			.type = RTE_FLOW_ACTION_TYPE_DEC_TCP_SEQ,
			.conf = &dec_tcp_seq,
		},
		[INC_TCP_SEQ] = {
			.type = RTE_FLOW_ACTION_TYPE_INC_TCP_SEQ,
			.conf = &inc_tcp_seq,
		},
		[DEC_TCP_ACK] = {
			.type = RTE_FLOW_ACTION_TYPE_DEC_TCP_ACK,
			.conf = &dec_tcp_ack,
		},
		[INC_TCP_ACK] = {
			.type = RTE_FLOW_ACTION_TYPE_INC_TCP_ACK,
			.conf = &inc_tcp_ack,
		},
		[DECAP] = {
			.type = RTE_FLOW_ACTION_TYPE_RAW_DECAP,
			.conf = &decap,
		},
		[ENCAP] = {
			.type = RTE_FLOW_ACTION_TYPE_RAW_ENCAP,
			.conf = &encap,
		},
		[COUNT] = {
			.type = RTE_FLOW_ACTION_TYPE_COUNT,
			.conf = &count,
		},
		[METER] = {
			.type = RTE_FLOW_ACTION_TYPE_METER,
			.conf = &meter,
		},
		[AEND] = {
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};
	struct vswitch_group *gr = NULL;
	struct rte_flow_error err;
	int ret = 0;

	if ((oflow->type == VSWITCH_OFFLOAD_FLOW_TYPE_VIRTIO_TO_VIRTIO ||
	     oflow->type == VSWITCH_OFFLOAD_FLOW_TYPE_VF_TO_VF) &&
	    (oactions->encap || oactions->decap || oactions->remove_ethernet ||
	     oactions->add_ethernet)) {
		RTE_LOG(ERR, VSWITCH, "vport %hu, Failed to create a"
			" non-tunnel offload flow - encap/decap actions are"
			" not expected in VM->VM flow\n",
			dst_vport->vport_id);
		return -EINVAL;
	}
	if (keys->outer.ip_type == 0) { //IPV4
		pattern[IPV6].type = RTE_FLOW_ITEM_TYPE_VOID;
		pattern[IPV4].type = RTE_FLOW_ITEM_TYPE_IPV4;
		if (keys->outer.src_addr_valid) {
			ipv4_spec.hdr.src_addr = keys->outer.src_addr;
			ipv4_mask.hdr.src_addr = -1;
		} else
			ipv4_mask.hdr.src_addr = 0;
		if (keys->outer.dst_addr_valid) {
			ipv4_spec.hdr.dst_addr = keys->outer.dst_addr;
			ipv4_mask.hdr.dst_addr = -1;
		} else
			ipv4_mask.hdr.dst_addr = 0;
		if (keys->outer.proto_valid) {
			ipv4_spec.hdr.next_proto_id = keys->outer.proto;
			ipv4_mask.hdr.next_proto_id = -1;
		} else
			ipv4_mask.hdr.next_proto_id = 0;
	} else { //IPV6
		pattern[IPV6].type = RTE_FLOW_ITEM_TYPE_IPV6;
		pattern[IPV4].type = RTE_FLOW_ITEM_TYPE_VOID;
		if (keys->outer.src_addr_valid) {
			memcpy(ipv6_spec.hdr.src_addr,
			       keys->outer.src_addr6, 16);
			memset(ipv6_mask.hdr.src_addr, 0xff, 16);
		} else
			memset(ipv6_mask.hdr.src_addr, 0, 16);
		if (keys->outer.dst_addr_valid) {
			memcpy(ipv6_spec.hdr.dst_addr,
			       keys->outer.dst_addr6, 16);
			memset(ipv6_mask.hdr.dst_addr, 0xff, 16);
		} else
			memset(ipv6_mask.hdr.dst_addr, 0, 16);
		if (keys->outer.proto_valid) {
			ipv6_spec.hdr.proto = keys->outer.proto;
			ipv6_mask.hdr.proto = -1;
		} else
			ipv6_mask.hdr.proto = 0;
	}
	if (keys->outer.src_port_valid || keys->outer.dst_port_valid) {
		if (!keys->outer.proto_valid)
			return -EINVAL;
		if (keys->outer.proto == IPPROTO_UDP) {
			pattern[TCP].type = RTE_FLOW_ITEM_TYPE_VOID;
			pattern[UDP].type = RTE_FLOW_ITEM_TYPE_UDP;
			if (keys->outer.src_port_valid) {
				udp_spec.hdr.src_port = keys->outer.src_port;
				udp_mask.hdr.src_port = -1;
			} else
				udp_mask.hdr.src_port = 0;
			if (keys->outer.dst_port_valid) {
				udp_spec.hdr.dst_port = keys->outer.dst_port;
				udp_mask.hdr.dst_port = -1;
			} else
				udp_mask.hdr.dst_port = 0;
		} else if (keys->outer.proto == IPPROTO_TCP) {
			pattern[TCP].type = RTE_FLOW_ITEM_TYPE_TCP;
			pattern[UDP].type = RTE_FLOW_ITEM_TYPE_VOID;
			if (keys->outer.src_port_valid) {
				tcp_spec.hdr.src_port = keys->outer.src_port;
				tcp_mask.hdr.src_port = -1;
			} else
				tcp_mask.hdr.src_port = 0;
			if (keys->outer.dst_port_valid) {
				tcp_spec.hdr.dst_port = keys->outer.dst_port;
				tcp_mask.hdr.dst_port = -1;
			} else
				tcp_mask.hdr.dst_port = 0;
			if (keys->outer.tcp_flags_valid.flags) {
				tcp_spec.hdr.tcp_flags =
						keys->outer.tcp_flags.flags;
				tcp_mask.hdr.tcp_flags =
						keys->outer.tcp_flags_valid.flags;
			} else
				tcp_mask.hdr.tcp_flags = 0;
		} else {
			RTE_LOG(ERR, VSWITCH, "Unsupported L4 type %u\n",
				keys->outer.proto);
			return -EINVAL;
		}
	} else {
		pattern[TCP].type = RTE_FLOW_ITEM_TYPE_VOID;
		pattern[UDP].type = RTE_FLOW_ITEM_TYPE_VOID;
	}
	if (keys->outer.proto == IPPROTO_ICMPV6) {
		if (!keys->outer.ip_type) {
			RTE_LOG(ERR, VSWITCH, "ICMPv6 must follow IPv6\n");
			return -EINVAL;
		}
		pattern[ICMPV6].type = RTE_FLOW_ITEM_TYPE_ICMPV6;
		pattern[ICMP].type = RTE_FLOW_ITEM_TYPE_VOID;
		icmpv6_spec.hdr.icmp_type = keys->outer.icmp_type;
	} else if (keys->outer.proto == IPPROTO_ICMP) { /* IPv4. */
		if (keys->outer.ip_type) {
			RTE_LOG(ERR, VSWITCH, "ICMPv4 must follow IPv4\n");
			return -EINVAL;
		}
		pattern[ICMPV6].type = RTE_FLOW_ITEM_TYPE_VOID;
		pattern[ICMP].type = RTE_FLOW_ITEM_TYPE_ICMP;
		icmp_spec.hdr.icmp_type = keys->outer.icmp_type;
	} else {
		pattern[ICMPV6].type = RTE_FLOW_ITEM_TYPE_VOID;
		pattern[ICMP].type = RTE_FLOW_ITEM_TYPE_VOID;
	}
	if (oactions->modify) {
		if (oactions->modify->set_dst_mac) {
			actions[SET_MAC_DST].type =
					RTE_FLOW_ACTION_TYPE_SET_MAC_DST;
			memcpy(&set_mac_dst, &oactions->modify->dst_mac,
			       ETHER_ADDR_LEN);
		} else
			actions[SET_MAC_DST].type = RTE_FLOW_ACTION_TYPE_VOID;
		if (oactions->modify->set_src_mac) {
			actions[SET_MAC_SRC].type =
					RTE_FLOW_ACTION_TYPE_SET_MAC_SRC;
			memcpy(&set_mac_src, &oactions->modify->src_mac,
			       ETHER_ADDR_LEN);
		} else
			actions[SET_MAC_SRC].type = RTE_FLOW_ACTION_TYPE_VOID;

		if (oactions->modify->set_src_ip4) {
			if (oactions->modify->set_src_ip6 ||
			    oactions->modify->set_dst_ip6)
				return -EINVAL;
			actions[SET_IPV4_SRC].type =
					RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC;
			set_ipv4_src.ipv4_addr = oactions->modify->src_ip4;
		} else
			actions[SET_IPV4_SRC].type = RTE_FLOW_ACTION_TYPE_VOID;
		if (oactions->modify->set_dst_ip4) {
			if (oactions->modify->set_src_ip6 ||
			    oactions->modify->set_dst_ip6)
				return -EINVAL;
			actions[SET_IPV4_DST].type =
					RTE_FLOW_ACTION_TYPE_SET_IPV4_DST;
			set_ipv4_dst.ipv4_addr = oactions->modify->dst_ip4;
		} else
			actions[SET_IPV4_DST].type = RTE_FLOW_ACTION_TYPE_VOID;

		if (oactions->modify->set_src_ip6) {
			actions[SET_IPV6_SRC].type =
					RTE_FLOW_ACTION_TYPE_SET_IPV6_SRC;
			memcpy(set_ipv6_src.ipv6_addr, oactions->modify->src_ip6, 16);
		} else
			actions[SET_IPV6_SRC].type = RTE_FLOW_ACTION_TYPE_VOID;
		if (oactions->modify->set_dst_ip6) {
			actions[SET_IPV6_DST].type =
					RTE_FLOW_ACTION_TYPE_SET_IPV6_DST;
			memcpy(set_ipv6_dst.ipv6_addr,
			       oactions->modify->dst_ip6, 16);
		} else
			actions[SET_IPV6_DST].type = RTE_FLOW_ACTION_TYPE_VOID;

		if (oactions->modify->set_src_port) {
			actions[SET_TP_SRC].type =
					RTE_FLOW_ACTION_TYPE_SET_TP_SRC;
			set_tp_src.port = oactions->modify->src_port;
		} else
			actions[SET_TP_SRC].type = RTE_FLOW_ACTION_TYPE_VOID;
		if (oactions->modify->set_dst_port) {
			actions[SET_TP_DST].type =
					RTE_FLOW_ACTION_TYPE_SET_TP_DST;
			set_tp_dst.port = oactions->modify->dst_port;
		} else
			actions[SET_TP_DST].type = RTE_FLOW_ACTION_TYPE_VOID;
		if ((oflow->type == VSWITCH_OFFLOAD_FLOW_TYPE_VIRTIO_TO_PF ||
		     oflow->type == VSWITCH_OFFLOAD_FLOW_TYPE_VF_TO_PF) &&
		    (oactions->modify->set_ttl || oactions->modify->dec_ttl)) {
			RTE_LOG(ERR, VSWITCH, "TTL modify actions are not "
				"supported in VM to PF flows\n");
			return -EINVAL;
		}
		if (oactions->modify->set_ttl) {
			if (oactions->modify->dec_ttl)
				return -EINVAL;
			actions[SET_TTL].type = RTE_FLOW_ACTION_TYPE_SET_TTL;
			set_ttl.ttl_value = oactions->modify->ttl;
		} else
			actions[SET_TTL].type = RTE_FLOW_ACTION_TYPE_VOID;
		if (oactions->modify->dec_ttl)
			actions[DEC_TTL].type = RTE_FLOW_ACTION_TYPE_DEC_TTL;
		else
			actions[DEC_TTL].type = RTE_FLOW_ACTION_TYPE_VOID;
		if (oactions->modify->dec_tcp_seq) {
			if (oactions->modify->inc_tcp_seq)
				return -EINVAL;
			actions[DEC_TCP_SEQ].type =
				RTE_FLOW_ACTION_TYPE_DEC_TCP_SEQ;
			dec_tcp_seq.value = oactions->modify->tcp_seq;
		} else
			actions[DEC_TCP_SEQ].type = RTE_FLOW_ACTION_TYPE_VOID;
		if (oactions->modify->inc_tcp_seq) {
			actions[INC_TCP_SEQ].type =
				RTE_FLOW_ACTION_TYPE_INC_TCP_SEQ;
			inc_tcp_seq.value = oactions->modify->tcp_seq;
		} else
			actions[INC_TCP_SEQ].type = RTE_FLOW_ACTION_TYPE_VOID;
		if (oactions->modify->dec_tcp_ack) {
			if (oactions->modify->inc_tcp_ack)
				return -EINVAL;
			actions[DEC_TCP_ACK].type =
				RTE_FLOW_ACTION_TYPE_DEC_TCP_ACK;
			dec_tcp_ack.value = oactions->modify->tcp_ack;
		} else
			actions[DEC_TCP_ACK].type = RTE_FLOW_ACTION_TYPE_VOID;
		if (oactions->modify->inc_tcp_ack) {
			actions[INC_TCP_ACK].type =
				RTE_FLOW_ACTION_TYPE_INC_TCP_ACK;
			inc_tcp_ack.value = oactions->modify->tcp_ack;
		} else
			actions[INC_TCP_ACK].type = RTE_FLOW_ACTION_TYPE_VOID;
	} else {
		actions[SET_MAC_SRC].type = RTE_FLOW_ACTION_TYPE_VOID;
		actions[SET_MAC_DST].type = RTE_FLOW_ACTION_TYPE_VOID;
		actions[SET_IPV4_SRC].type = RTE_FLOW_ACTION_TYPE_VOID;
		actions[SET_IPV4_DST].type = RTE_FLOW_ACTION_TYPE_VOID;
		actions[SET_IPV6_SRC].type = RTE_FLOW_ACTION_TYPE_VOID;
		actions[SET_IPV6_DST].type = RTE_FLOW_ACTION_TYPE_VOID;
		actions[SET_TP_SRC].type = RTE_FLOW_ACTION_TYPE_VOID;
		actions[SET_TP_DST].type = RTE_FLOW_ACTION_TYPE_VOID;
		actions[SET_TTL].type = RTE_FLOW_ACTION_TYPE_VOID;
		actions[DEC_TTL].type = RTE_FLOW_ACTION_TYPE_VOID;
		actions[DEC_TCP_SEQ].type = RTE_FLOW_ACTION_TYPE_VOID;
		actions[INC_TCP_SEQ].type = RTE_FLOW_ACTION_TYPE_VOID;
		actions[DEC_TCP_ACK].type = RTE_FLOW_ACTION_TYPE_VOID;
		actions[INC_TCP_ACK].type = RTE_FLOW_ACTION_TYPE_VOID;
	}
	if (oactions->encap) {
		if (oactions->decap || !oactions->remove_ethernet ||
		    oactions->add_ethernet)
			return -EINVAL;
		actions[DECAP].type = RTE_FLOW_ACTION_TYPE_RAW_DECAP;
		actions[ENCAP].type = RTE_FLOW_ACTION_TYPE_RAW_ENCAP;
		encap.data = (uint8_t *)oactions->encap;
		encap.size = sizeof(*oactions->encap);
	} else if (oflow->type == VSWITCH_OFFLOAD_FLOW_TYPE_VIRTIO_TO_VIRTIO) {
		actions[DECAP].type = RTE_FLOW_ACTION_TYPE_VOID;
		actions[ENCAP].type = RTE_FLOW_ACTION_TYPE_RAW_ENCAP;
		lb_encap.vxlan_flags = 0x08,
		lb_encap.vxlan_vni = RTE_VSWITCH_MARK_TYPE_VPORT_FLOW |
					(dst_vport->vport_id << 8);
		memcpy(&lb_encap.ether.d_addr, ctx->pf->data->mac_addrs,
		       sizeof(lb_encap.ether.d_addr));
		memcpy(&lb_encap.ether.s_addr, ctx->pf->data->mac_addrs,
		       sizeof(lb_encap.ether.d_addr));
		encap.data = (uint8_t *)&lb_encap;
		encap.size = sizeof(lb_encap);
	}  else {
		actions[DECAP].type = RTE_FLOW_ACTION_TYPE_VOID;
		actions[ENCAP].type = RTE_FLOW_ACTION_TYPE_VOID;
	}
	if (oactions->meter) {
		if (oactions->meter_id >= RTE_VSWITCH_MAX_METER_NUM) {
			RTE_LOG(ERR, VSWITCH, "Invalid meter id %u must be smaller than %u\n",
					oactions->meter_id, RTE_VSWITCH_MAX_METER_NUM);
			ret = -EINVAL;
			goto error;
		}
		if (!ctx->vmeters[oactions->meter_id].valid) {
			RTE_LOG(ERR, VSWITCH, "Invalid meter id %u\n",
				oactions->meter_id);
			ret = -EINVAL;
			goto error;
		}
		meter.mtr_id = oactions->meter_id;
		actions[METER].type = RTE_FLOW_ACTION_TYPE_METER;
	} else
		actions[METER].type = RTE_FLOW_ACTION_TYPE_VOID;
	if (ctx->type == RTE_VSWITCH_TYPE_VIRTIO) {
		pattern[PORT_ID].type = RTE_FLOW_ITEM_TYPE_VOID;
		actions[ACT_PORT_ID].type = RTE_FLOW_ACTION_TYPE_VOID;
		attr.egress = 1;
		attr.ingress = 0;
		attr.transfer = 0;
		attr.group = dst_vport->egroup->group_id;
		meta.id = 0;
		meta.data = rte_cpu_to_be_32(_GET_VPORT_METADATA(src_vport));
		port_id.id = ctx->pf->data->port_id;
	} else {
		pattern[PORT_ID].type = RTE_FLOW_ITEM_TYPE_PORT_ID;
		port_id.id = src_vport->vport_dev->data->port_id;
		actions[ACT_PORT_ID].type = RTE_FLOW_ACTION_TYPE_PORT_ID;
		attr.egress = 0;
		attr.ingress = 1;
		attr.transfer = 1;
		attr.group = 2;
		act_port_id.id = dst_vport->vport_dev->data->port_id;
		meta.id = 1;
		meta.data = rte_cpu_to_be_32
				(_GET_SRIOV_METADATA(src_vport, dst_vport));
	}
	if (oactions->count || oactions->timeout) {
		actions[COUNT].type = RTE_FLOW_ACTION_TYPE_COUNT;
		count.handle = aging_counter_alloc(port_id.id,
						   &count.id, &count.bias);
		if (!count.handle)
			return -ENOTSUP;
		oflow->counter_id = count.id;
	} else
		actions[COUNT].type = RTE_FLOW_ACTION_TYPE_VOID;
	gr = dst_vport->egroup;
	oflow->gr_id = gr->group_id;
	oflow->gr_ingress = 0;
	oflow->flow = _rte_flow_create(port_id.id, &attr, pattern,
				       actions, &err);
	if (!oflow->flow) {
		RTE_LOG(ERR, VSWITCH, "vport: %hu, Failed to create a"
			" non-tunnel offload flow - %s\n",
			dst_vport->vport_id,
			err.message ? err.message : "(no stated reason)");
		ret = -1;
		goto error;
	}
	if (oflow->type == VSWITCH_OFFLOAD_FLOW_TYPE_VIRTIO_TO_VIRTIO ||
	    ctx->type == RTE_VSWITCH_TYPE_SRIOV){
		if(_vswitch_prepare_egress_dispatch_flow(ctx, dst_vport,
							 src_vport,
							 &keys->outer)) {
			_rte_flow_destroy(port_id.id, oflow->flow,
					  &err);
			ret = -1;
			goto error;
		}
	}
	oflow->mgr_id = src_vport->egroup->group_id;
	src_vport->egroup->mcounter++;
	LIST_INSERT_HEAD(&gr->oflows, oflow, next);
	return 0;
error:
	if (count.handle)
		aging_counter_free(port_id.id, count.id);
	return ret;
}

/* Create an ingress dispatch flow if not exist. */
static int
_vswitch_prepare_ingress_dispatch_flow(struct rte_vswitch_ctx *ctx,
				       struct vswitch_vport *dst_vport,
				       struct rte_vswitch_flow_keys *keys)
{
	static struct rte_flow_item_port_id port_id;
	static struct rte_flow_attr attr = {
		.ingress = 1,
	};
	static struct rte_flow_item_udp udp_spec = {
		.hdr = {
			.dst_port = RTE_BE16(_VSWITCH_FABRIC_VXLAN_UDP_PORT),
		},
	};
	static struct rte_flow_item_udp udp_mask = {
		.hdr = {
			.dst_port = -1,
		},
	};
	static struct rte_flow_item_vxlan vxlan_spec;
	static struct rte_flow_item_vxlan vxlan_mask = {
		.vni = "\xff\xff\xff",
	};
	static struct rte_flow_item_vxlan_gpe vxlan_gpe_spec;
	static struct rte_flow_item_vxlan_gpe vxlan_gpe_mask = {
		.vni = "\xff\xff\xff",
	};
	static struct rte_flow_item_ipv4 iipv4_spec;
	static struct rte_flow_item_ipv4 iipv4_mask = {
		.hdr = {
			.dst_addr = RTE_BE32(0xffffffff),
		},
	};
	static struct rte_flow_item_ipv6 iipv6_spec;
	static struct rte_flow_item_ipv6 iipv6_mask = {
		.hdr = {
			.dst_addr =
				"\xff\xff\xff\xff\xff\xff\xff\xff"
				"\xff\xff\xff\xff\xff\xff\xff\xff",
		},
	};
	enum {PORT_ID, ETH, IPV4, UDP, VXLAN, VXLAN_GPE, IIPV4, IIPV6, IEND};
	static struct rte_flow_item pattern[] = {
		[PORT_ID] = {
			.type = RTE_FLOW_ITEM_TYPE_PORT_ID,
			.spec = &port_id,
			.mask = NULL,
			.last = NULL,
		},
		[ETH] = {
			.type = RTE_FLOW_ITEM_TYPE_ETH,
			.spec = NULL,
			.mask = NULL,
			.last = NULL,
		},
		[IPV4] = {
			.type = RTE_FLOW_ITEM_TYPE_IPV4,
			.spec = NULL,
			.mask = NULL,
			.last = NULL,
		},
		[UDP] = {
			.type = RTE_FLOW_ITEM_TYPE_UDP,
			.spec = &udp_spec,
			.mask = &udp_mask,
			.last = NULL,
		},
		[VXLAN] = {
			.type = RTE_FLOW_ITEM_TYPE_VXLAN,
			.spec = &vxlan_spec,
			.mask = &vxlan_mask,
			.last = NULL,
		},
		[VXLAN_GPE] = {
			.type = RTE_FLOW_ITEM_TYPE_VXLAN_GPE,
			.spec = &vxlan_gpe_spec,
			.mask = &vxlan_gpe_mask,
			.last = NULL,
		},
		[IIPV4] = {
			.type = RTE_FLOW_ITEM_TYPE_IPV4,
			.spec = &iipv4_spec,
			.mask = &iipv4_mask,
			.last = NULL,
		},
		[IIPV6] = {
			.type = RTE_FLOW_ITEM_TYPE_IPV6,
			.spec = &iipv6_spec,
			.mask = &iipv6_mask,
			.last = NULL,
		},
		[IEND] = {
			.type = RTE_FLOW_ITEM_TYPE_END,
			.spec = NULL,
			.mask = NULL,
			.last = NULL,
		},

	};
	enum {SET_META, MARK, JUMP, END};
	static struct rte_flow_action_set_meta set_meta= {
		.id = 1,
	};
	static struct rte_flow_action_mark mark;
	static struct rte_flow_action_jump jump;
	static struct rte_flow_action actions[] = {
		[SET_META] = {
			.type = RTE_FLOW_ACTION_TYPE_SET_META,
			.conf = &set_meta,
		},
		[MARK] = {
			.type = RTE_FLOW_ACTION_TYPE_MARK,
			.conf = &mark,
		},
		[JUMP] = {
			.type = RTE_FLOW_ACTION_TYPE_JUMP,
			.conf = &jump,
		},
		[END] = {
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};
	struct rte_flow_error err;
	struct vswitch_dispatch_flow_key df_key;
	struct vswitch_dispatch_flow_data *dflow;
	struct vswitch_dispatch_flow_data *r_dflow;
	struct rte_hlist_data_element *de;
	int ret;
	struct vswitch_vport *src_vport = &ctx->vports[ctx->pf_vport_id];
	struct vswitch_group *gr = (ctx->type == RTE_VSWITCH_TYPE_VIRTIO) ?
			dst_vport->igroup : dst_vport->egroup;

	if (!keys->inner.dst_addr_valid) {
		RTE_LOG(ERR, VSWITCH, "Failed to create an ingress dispatch "
			"flow to vport %hu - invalid dst L3 address\n",
			dst_vport->vport_id);
		return -EINVAL;
	}

	df_key.vni = keys->vni;
	df_key.ipv = keys->inner.ip_type;
	df_key.vxlan_type = keys->tunnel_type;
	df_key.pad = 0;
	if (df_key.ipv == 0) {
		df_key.ipv4_addr = keys->inner.dst_addr;
		memset(&df_key.ipv6_addr[4], 0, 12);
	} else {
		rte_memcpy(df_key.ipv6_addr, keys->inner.dst_addr6, 16);
	}
	de = rte_hlist_add_key(gr->hl, &df_key);
	if (!rte_hlist_entry_is_new(de))
		return 0;

	dflow = rte_zmalloc_socket(__func__, sizeof(struct vswitch_dispatch_flow_data),
				   RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (!dflow) {
		RTE_LOG(ERR, VSWITCH, "Failed to create an ingress dispatch "
			"flow to vport %hu - no mem\n", dst_vport->vport_id);
		rte_hlist_del_entry_fast_return_data(gr->hl, de, (void **)&r_dflow);
		return -ENOMEM;
	}
	if ((ret = rte_hlist_entry_append_custom_data(gr->hl, de, dflow)) != 0) {
		RTE_LOG(ERR, VSWITCH, "Failed to append customer data "
			"flow to vport %hu - %d\n", dst_vport->vport_id, ret);
		rte_hlist_del_entry_fast_return_data(gr->hl, de, (void **)&r_dflow);
		return ret;
	}
	dflow->p_de = de;

	if (keys->tunnel_type == RTE_VSWITCH_TUNNEL_TYPE_VXLAN) {
		pattern[VXLAN].type = RTE_FLOW_ITEM_TYPE_VXLAN;
		pattern[VXLAN_GPE].type = RTE_FLOW_ITEM_TYPE_VOID;
		vxlan_spec.vni[0] = keys->vni & 0xff;
		vxlan_spec.vni[1] = (keys->vni >> 8) & 0xff;
		vxlan_spec.vni[2] = (keys->vni >> 16) & 0xff;
	} else {
		pattern[VXLAN_GPE].type = RTE_FLOW_ITEM_TYPE_VXLAN_GPE;
		pattern[VXLAN].type = RTE_FLOW_ITEM_TYPE_VOID;
		vxlan_gpe_spec.vni[0] = keys->vni & 0xff;
		vxlan_gpe_spec.vni[1] = (keys->vni >> 8) & 0xff;
		vxlan_gpe_spec.vni[2] = (keys->vni >> 16) & 0xff;
	}
	if (keys->inner.ip_type == 0) { //IPV4
		pattern[IIPV6].type = RTE_FLOW_ITEM_TYPE_VOID;
		pattern[IIPV4].type = RTE_FLOW_ITEM_TYPE_IPV4;
		iipv4_spec.hdr.dst_addr = keys->inner.dst_addr;
	} else { //IPV6
		pattern[IIPV6].type = RTE_FLOW_ITEM_TYPE_IPV6;
		pattern[IIPV4].type = RTE_FLOW_ITEM_TYPE_VOID;
		memcpy(iipv6_spec.hdr.dst_addr, keys->inner.dst_addr6,
		       16);

	}
	dflow->port_id = port_id.id = ctx->pf->data->port_id;
	if (ctx->type == RTE_VSWITCH_TYPE_VIRTIO) {
		attr.group = 0;
		attr.transfer = 0;
		pattern[PORT_ID].type = RTE_FLOW_ITEM_TYPE_VOID;
		actions[MARK].type = RTE_FLOW_ACTION_TYPE_MARK;
		actions[SET_META].type = RTE_FLOW_ACTION_TYPE_VOID;
		mark.id = RTE_VSWITCH_MARK_TYPE_VPORT_FLOW |
				(dst_vport->vport_id << 8);
		jump.group = gr->group_id;
	} else {
		attr.group = 1;
		attr.transfer = 1;
		pattern[PORT_ID].type = RTE_FLOW_ITEM_TYPE_PORT_ID;
		actions[MARK].type = RTE_FLOW_ACTION_TYPE_VOID;
		actions[SET_META].type = RTE_FLOW_ACTION_TYPE_SET_META;
		jump.group = 2;
		set_meta.data = rte_cpu_to_be_32
			(_GET_SRIOV_METADATA(src_vport, dst_vport));
	}
	dflow->dflow = _rte_flow_create(port_id.id,
					&attr, pattern, actions,
					&err);
	if (!dflow->dflow) {
		RTE_LOG(ERR, VSWITCH, "Failed to create an ingress dispatch "
			"flow to vport %hu - %s\n", dst_vport->vport_id,
			err.message ? err.message : "(no stated reason)");
		rte_hlist_del_entry_fast_return_data(gr->hl, de, (void **)&r_dflow);
		RTE_ASSERT(r_dflow == dflow);
		rte_free(dflow);
		return -1;
	}
	LIST_INSERT_HEAD(&src_vport->egroup->firsts[dst_vport->vport_id],
			dflow, plink);
	RTE_LOG(DEBUG, VSWITCH, "Dispatch flow ingress was created to vport %hu\n",
		dst_vport->vport_id);
	return 0;
}

/**
 *  Create a tunnel offload flow.
 *
 * @param pf
 *   Pointer to the PF ethernet device.
 * @param oflow
 *   Pointer to new offload flow.
 * @param keys
 *   The flow keys pointer.
 * @param oactions
 *   The vswitch offload flow actions pointer.
 * @param dst_vport
 *   The destination vport pointer.
 *
 * @return
 *   0 in case of success, a negative value otherwise.
 */
static int
_vswitch_create_tunnel_offload_flow(struct rte_vswitch_ctx *ctx,
				    struct rte_vswitch_offload_flow *oflow,
				    struct rte_vswitch_flow_keys *keys,
				    struct rte_vswitch_flow_actions *oactions,
				    struct vswitch_vport *dst_vport) {
	static struct rte_flow_attr attr = {
		.ingress = 1,
	};
	static struct rte_flow_item_port_id port_id;
	static struct rte_flow_item_meta_ext meta = {
		.id = 1,
	};
	static struct rte_flow_item_meta_ext meta_mask = {
		.id = UINT64_MAX,
		.data = RTE_BE32(0xFFFFFFFF),
	};
	static struct rte_flow_item_ipv4 ipv4_spec;
	static struct rte_flow_item_ipv4 ipv4_mask;
	static struct rte_flow_item_udp udp_spec = {
		.hdr = {
			.dst_port = RTE_BE16(_VSWITCH_FABRIC_VXLAN_UDP_PORT),
		},
	};
	static struct rte_flow_item_udp udp_mask = {
		.hdr = {
			.dst_port = -1,
		},
	};
	static struct rte_flow_item_vxlan vxlan_spec;
	static struct rte_flow_item_vxlan vxlan_mask = {
		.vni = "\xff\xff\xff",
	};
	static struct rte_flow_item_vxlan_gpe vxlan_gpe_spec;
	static struct rte_flow_item_vxlan_gpe vxlan_gpe_mask = {
		.vni = "\xff\xff\xff",
	};
	static struct rte_flow_item_ipv4 iipv4_spec;
	static struct rte_flow_item_ipv4 iipv4_mask;
	static struct rte_flow_item_ipv6 iipv6_spec;
	static struct rte_flow_item_ipv6 iipv6_mask;
	static struct rte_flow_item_icmp iicmp_spec;
	static struct rte_flow_item_icmp iicmp_mask = {
		.hdr = { .icmp_type = 0xff, },
	};
	static struct rte_flow_item_icmpv6 iicmpv6_spec;
	static struct rte_flow_item_icmpv6 iicmpv6_mask = {
		.hdr = { .icmp_type = 0xff, },
	};
	static struct rte_flow_item_tcp itcp_spec;
	static struct rte_flow_item_tcp itcp_mask;
	static struct rte_flow_item_udp iudp_spec;
	static struct rte_flow_item_udp iudp_mask;

	enum {PORT_ID, META, ETH, IPV4, UDP, VXLAN, VXLAN_GPE, IIPV4, IIPV6,
	      IICMP, IICMPV6, ITCP, IUDP, IEND};
	static struct rte_flow_item pattern[] = {
		[PORT_ID] = {
			.type = RTE_FLOW_ITEM_TYPE_PORT_ID,
			.spec = &port_id,
			.mask = NULL,
			.last = NULL,
		},
		[META] = {
			.type = RTE_FLOW_ITEM_TYPE_META_EXT,
			.spec = &meta,
			.mask = &meta_mask,
			.last = NULL,
		},
		[ETH] = {
			.type = RTE_FLOW_ITEM_TYPE_ETH,
			.spec = NULL,
			.mask = NULL,
			.last = NULL,
		},
		[IPV4] = {
			.type = RTE_FLOW_ITEM_TYPE_IPV4,
			.spec = &ipv4_spec,
			.mask = &ipv4_mask,
			.last = NULL,
		},
		[UDP] = {
			.type = RTE_FLOW_ITEM_TYPE_UDP,
			.spec = &udp_spec,
			.mask = &udp_mask,
			.last = NULL,
		},
		[VXLAN] = {
			.type = RTE_FLOW_ITEM_TYPE_VXLAN,
			.spec = &vxlan_spec,
			.mask = &vxlan_mask,
			.last = NULL,
		},
		[VXLAN_GPE] = {
			.type = RTE_FLOW_ITEM_TYPE_VXLAN_GPE,
			.spec = &vxlan_gpe_spec,
			.mask = &vxlan_gpe_mask,
			.last = NULL,
		},
		[IIPV4] = {
			.type = RTE_FLOW_ITEM_TYPE_IPV4,
			.spec = &iipv4_spec,
			.mask = &iipv4_mask,
			.last = NULL,
		},
		[IIPV6] = {
			.type = RTE_FLOW_ITEM_TYPE_IPV6,
			.spec = &iipv6_spec,
			.mask = &iipv6_mask,
			.last = NULL,
		},
		[IICMP] = {
			.type = RTE_FLOW_ITEM_TYPE_ICMP,
			.spec = &iicmp_spec,
			.mask = &iicmp_mask,
			.last = NULL,
		},
		[IICMPV6] = {
			.type = RTE_FLOW_ITEM_TYPE_ICMPV6,
			.spec = &iicmpv6_spec,
			.mask = &iicmpv6_mask,
			.last = NULL,
		},
		[ITCP] = {
			.type = RTE_FLOW_ITEM_TYPE_TCP,
			.spec = &itcp_spec,
			.mask = &itcp_mask,
			.last = NULL,
		},
		[IUDP] = {
			.type = RTE_FLOW_ITEM_TYPE_UDP,
			.spec = &iudp_spec,
			.mask = &iudp_mask,
			.last = NULL,
		},
		[IEND] = {
			.type = RTE_FLOW_ITEM_TYPE_END,
			.spec = NULL,
			.mask = NULL,
			.last = NULL,
		},
	};
	static struct rte_flow_action_port_id act_port_id;
	static struct rte_flow_action_raw_decap decap;
	static struct rte_flow_action_raw_encap encap = {
		.size = sizeof(struct ether_hdr),
	};
	static struct rte_flow_action_set_ipv4 set_ipv4_src;
	static struct rte_flow_action_set_ipv4 set_ipv4_dst;
	static struct rte_flow_action_set_ipv6 set_ipv6_src;
	static struct rte_flow_action_set_ipv6 set_ipv6_dst;
	static struct rte_flow_action_set_tp set_tp_src;
	static struct rte_flow_action_set_tp set_tp_dst;
	static struct rte_flow_action_modify_tcp_seq dec_tcp_seq;
	static struct rte_flow_action_modify_tcp_seq inc_tcp_seq;
	static struct rte_flow_action_modify_tcp_ack dec_tcp_ack;
	static struct rte_flow_action_modify_tcp_ack inc_tcp_ack;
	static struct rte_eth_rss_conf rss_conf = {
		.rss_key = NULL,
		.rss_key_len = 0,
		/* Default to all fields, PMD will adapt from pattern. */
		.rss_hf = ETH_RSS_IP | ETH_RSS_UDP | ETH_RSS_TCP,
		.rss_level = 0,
	};
	static union urss rss = {
		.rss_action = {
			.rss_conf = &rss_conf,
			.num = 0,
		},
	};
	static struct rte_flow_action_mark mark;
	static struct rte_flow_action_count count;
	static struct rte_flow_action_meter meter;
	enum {DECAP, ENCAP, SET_IPV4_SRC, SET_IPV4_DST, SET_IPV6_SRC,
	      SET_IPV6_DST, SET_TP_SRC, SET_TP_DST, DEC_TCP_SEQ, INC_TCP_SEQ,
	      DEC_TCP_ACK, INC_TCP_ACK, RSS, MARK, COUNT, METER, ACT_PORT_ID,
	      AEND};
	static struct rte_flow_action actions[] = {
		[DECAP] = {
			.type = RTE_FLOW_ACTION_TYPE_RAW_DECAP,
			.conf = &decap,
		},
		[ENCAP] = {
			.type = RTE_FLOW_ACTION_TYPE_RAW_ENCAP,
			.conf = &encap,
		},
		[SET_IPV4_SRC] = {
			.type = RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC,
			.conf = &set_ipv4_src,
		},
		[SET_IPV4_DST] = {
			.type = RTE_FLOW_ACTION_TYPE_SET_IPV4_DST,
			.conf = &set_ipv4_dst,
		},
		[SET_IPV6_SRC] = {
			.type = RTE_FLOW_ACTION_TYPE_SET_IPV6_SRC,
			.conf = &set_ipv6_src,
		},
		[SET_IPV6_DST] = {
			.type = RTE_FLOW_ACTION_TYPE_SET_IPV6_DST,
			.conf = &set_ipv6_dst,
		},
		[SET_TP_SRC] = {
			.type = RTE_FLOW_ACTION_TYPE_SET_TP_SRC,
			.conf = &set_tp_src,
		},
		[SET_TP_DST] = {
			.type = RTE_FLOW_ACTION_TYPE_SET_TP_DST,
			.conf = &set_tp_dst,
		},
		[DEC_TCP_SEQ] = {
			.type = RTE_FLOW_ACTION_TYPE_DEC_TCP_SEQ,
			.conf = &dec_tcp_seq,
		},
		[INC_TCP_SEQ] = {
			.type = RTE_FLOW_ACTION_TYPE_INC_TCP_SEQ,
			.conf = &inc_tcp_seq,
		},
		[DEC_TCP_ACK] = {
			.type = RTE_FLOW_ACTION_TYPE_DEC_TCP_ACK,
			.conf = &dec_tcp_ack,
		},
		[INC_TCP_ACK] = {
			.type = RTE_FLOW_ACTION_TYPE_INC_TCP_ACK,
			.conf = &inc_tcp_ack,
		},
		[RSS] = {
			.type = RTE_FLOW_ACTION_TYPE_RSS,
			.conf = &rss.rss_action,
		},
		[MARK] = {
			.type = RTE_FLOW_ACTION_TYPE_MARK,
			.conf = &mark,
		},
		[COUNT] = {
			.type = RTE_FLOW_ACTION_TYPE_COUNT,
			.conf = &count,
		},
		[METER] = {
			.type = RTE_FLOW_ACTION_TYPE_METER,
			.conf = &meter,
		},
		[ACT_PORT_ID] = {
			.type = RTE_FLOW_ACTION_TYPE_PORT_ID,
			.conf = &act_port_id,
		},
		[AEND] = {
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};
	struct rte_flow_error err;
	unsigned int i;
	struct vswitch_group *gr = NULL;
	struct vswitch_vport *src_vport = &ctx->vports[ctx->pf_vport_id];
	struct rte_eth_dev *pf = ctx->vports[ctx->pf_vport_id].vport_dev;
	int ret;

	if ((keys->tunnel_type != RTE_VSWITCH_TUNNEL_TYPE_VXLAN) &&
	    (keys->tunnel_type != RTE_VSWITCH_TUNNEL_TYPE_VXLAN_GPE)) {
		RTE_LOG(ERR, VSWITCH, "vport %hu, Failed to create a tunnel"
			" offload flow - tunnel type %d is not supported\n",
			dst_vport->vport_id, keys->tunnel_type);
		return -EINVAL;
	}
	if (!keys->outer.dst_port_valid ||
	    keys->outer.dst_port != RTE_BE16(_VSWITCH_FABRIC_VXLAN_UDP_PORT)) {
		RTE_LOG(ERR, VSWITCH, "vport %hu, Failed to create an ingress "
			"offload flow - invalid outer UDP dest port(%hu!=%hu)"
			"\n", dst_vport->vport_id,
			keys->outer.src_port,
			(uint16_t)_VSWITCH_FABRIC_VXLAN_UDP_PORT);
		return -EINVAL;
	}
	if (keys->outer.ip_type != 0) {
		RTE_LOG(ERR, VSWITCH, "vport %hu, Failed to create an ingress"
			" offload flow - outer header is not IPV4\n",
			dst_vport->vport_id);
		return -EINVAL;
	}
	attr.priority = 1;
	if (keys->outer.src_addr_valid) {
		ipv4_spec.hdr.src_addr = keys->outer.src_addr;
		ipv4_mask.hdr.src_addr = -1;
		attr.priority = 0;
	} else
		ipv4_mask.hdr.src_addr = 0;
	if (keys->outer.dst_addr_valid) {
		ipv4_spec.hdr.dst_addr = keys->outer.dst_addr;
		ipv4_mask.hdr.dst_addr = -1;
		attr.priority = 0;
	} else
		ipv4_mask.hdr.dst_addr = 0;
	if (keys->outer.src_port_valid) {
		udp_spec.hdr.src_port = keys->outer.src_port;
		udp_mask.hdr.src_port = -1;
		attr.priority = 0;
	} else
		udp_mask.hdr.src_port = 0;
	if (keys->tunnel_type == RTE_VSWITCH_TUNNEL_TYPE_VXLAN) {
		vxlan_spec.vni[0] = keys->vni & 0xff;
		vxlan_spec.vni[1] = (keys->vni >> 8) & 0xff;
		vxlan_spec.vni[2] = (keys->vni >> 16) & 0xff;
		pattern[VXLAN].type = RTE_FLOW_ITEM_TYPE_VXLAN;
		pattern[VXLAN_GPE].type = RTE_FLOW_ITEM_TYPE_VOID;
	} else {
		vxlan_gpe_spec.vni[0] = keys->vni & 0xff;
		vxlan_gpe_spec.vni[1] = (keys->vni >> 8) & 0xff;
		vxlan_gpe_spec.vni[2] = (keys->vni >> 16) & 0xff;
		if (keys->flags_valid) {
			vxlan_gpe_spec.flags = keys->flags;
			vxlan_gpe_mask.flags = 0xff;
		} else
			vxlan_gpe_mask.flags = 0;
		if (keys->protocol_valid) {
			vxlan_gpe_spec.protocol = keys->protocol;
			vxlan_gpe_mask.protocol = 0xff;
		} else
			vxlan_gpe_mask.protocol = 0;
		pattern[VXLAN_GPE].type = RTE_FLOW_ITEM_TYPE_VXLAN_GPE;
		pattern[VXLAN].type = RTE_FLOW_ITEM_TYPE_VOID;
	}
	if (keys->inner.ip_type == 0) { //IPV4
		pattern[IIPV6].type = RTE_FLOW_ITEM_TYPE_VOID;
		pattern[IIPV4].type = RTE_FLOW_ITEM_TYPE_IPV4;
		if (keys->inner.src_addr_valid) {
			iipv4_spec.hdr.src_addr = keys->inner.src_addr;
			iipv4_mask.hdr.src_addr = -1;
		} else
			iipv4_mask.hdr.src_addr = 0;
		if (keys->inner.dst_addr_valid) {
			iipv4_spec.hdr.dst_addr = keys->inner.dst_addr;
			iipv4_mask.hdr.dst_addr = -1;
		} else
			iipv4_mask.hdr.dst_addr = 0;
		if (keys->inner.proto_valid) {
			iipv4_spec.hdr.next_proto_id = keys->inner.proto;
			iipv4_mask.hdr.next_proto_id = -1;
		} else
			iipv4_mask.hdr.next_proto_id = 0;
	} else { //IPV6
		if (keys->tunnel_type != RTE_VSWITCH_TUNNEL_TYPE_VXLAN_GPE) {
			RTE_LOG(ERR, VSWITCH, "vport %hu, Failed to create an "
				"ingress offload flow - IPv6 is not supported "
				"for non VXLAN-GPE tunnel\n",
				dst_vport->vport_id);
			return -EINVAL;
		}
		pattern[IIPV6].type = RTE_FLOW_ITEM_TYPE_IPV6;
		pattern[IIPV4].type = RTE_FLOW_ITEM_TYPE_VOID;
		if (keys->inner.src_addr_valid) {
			memcpy(iipv6_spec.hdr.src_addr, keys->inner.src_addr6,
			       16);
			memset(iipv6_mask.hdr.src_addr, 0xff, 16);
		} else
			memset(iipv6_mask.hdr.src_addr, 0, 16);
		if (keys->inner.dst_addr_valid) {
			memcpy(iipv6_spec.hdr.dst_addr, keys->inner.dst_addr6,
			       16);
			memset(iipv6_mask.hdr.dst_addr, 0xff, 16);
		} else
			memset(iipv6_mask.hdr.dst_addr, 0, 16);
		if (keys->inner.proto_valid) {
			iipv6_spec.hdr.proto = keys->inner.proto;
			iipv6_mask.hdr.proto = -1;
		} else
			iipv6_mask.hdr.proto = 0;
	}
	if (keys->inner.proto_valid) {
		if (keys->inner.proto == IPPROTO_UDP) {
			pattern[ITCP].type = RTE_FLOW_ITEM_TYPE_VOID;
			pattern[IUDP].type = RTE_FLOW_ITEM_TYPE_UDP;
			if (keys->inner.src_port_valid) {
				iudp_spec.hdr.src_port = keys->inner.src_port;
				iudp_mask.hdr.src_port = -1;
			} else
				iudp_mask.hdr.src_port = 0;
			if (keys->inner.dst_port_valid) {
				iudp_spec.hdr.dst_port = keys->inner.dst_port;
				iudp_mask.hdr.dst_port = -1;
			} else
				iudp_mask.hdr.dst_port = 0;
		} else if (keys->inner.proto == IPPROTO_TCP) {
			pattern[ITCP].type = RTE_FLOW_ITEM_TYPE_TCP;
			pattern[IUDP].type = RTE_FLOW_ITEM_TYPE_VOID;
			if (keys->inner.src_port_valid) {
				itcp_spec.hdr.src_port = keys->inner.src_port;
				itcp_mask.hdr.src_port = -1;
			} else
				itcp_mask.hdr.src_port = 0;
			if (keys->inner.dst_port_valid) {
				itcp_spec.hdr.dst_port = keys->inner.dst_port;
				itcp_mask.hdr.dst_port = -1;
			} else
				itcp_mask.hdr.dst_port = 0;
			if (keys->inner.tcp_flags_valid.flags) {
				itcp_spec.hdr.tcp_flags =
						keys->inner.tcp_flags.flags;
				itcp_mask.hdr.tcp_flags =
						keys->inner.tcp_flags_valid.flags;
			} else
				itcp_mask.hdr.tcp_flags = 0;
		} else {
			pattern[IUDP].type = RTE_FLOW_ITEM_TYPE_VOID;
			pattern[ITCP].type = RTE_FLOW_ITEM_TYPE_VOID;
			if (keys->inner.proto != IPPROTO_ICMP &&
			    keys->inner.proto != IPPROTO_ICMPV6) {
				RTE_LOG(ERR, VSWITCH, "Unsupported L4 type %u\n",
					keys->inner.proto);
				return -EINVAL;
			}
		}
	} else {
		pattern[IUDP].type = RTE_FLOW_ITEM_TYPE_VOID;
		pattern[ITCP].type = RTE_FLOW_ITEM_TYPE_VOID;
		if (keys->inner.src_port_valid || keys->inner.dst_port_valid)
			return -EINVAL;
	}
	if (keys->inner.proto == IPPROTO_ICMPV6) { /* IPv6. */
		if (!keys->inner.ip_type) {
			RTE_LOG(ERR, VSWITCH, "ICMPv6 must follow IPv6\n");
			return -EINVAL;
		}
		pattern[IICMPV6].type = RTE_FLOW_ITEM_TYPE_ICMPV6;
		pattern[IICMP].type = RTE_FLOW_ITEM_TYPE_VOID;
		iicmpv6_spec.hdr.icmp_type = keys->inner.icmp_type;
	} else if (keys->inner.proto == IPPROTO_ICMP) { /* IPv4. */
		if (keys->inner.ip_type) {
			RTE_LOG(ERR, VSWITCH, "ICMPv4 must follow IPv4\n");
			return -EINVAL;
		}
		pattern[IICMPV6].type = RTE_FLOW_ITEM_TYPE_VOID;
		pattern[IICMP].type = RTE_FLOW_ITEM_TYPE_ICMP;
		iicmp_spec.hdr.icmp_type = keys->inner.icmp_type;
	} else {
		pattern[IICMPV6].type = RTE_FLOW_ITEM_TYPE_VOID;
		pattern[IICMP].type = RTE_FLOW_ITEM_TYPE_VOID;
	}
	if (oactions->decap) {
		if (oactions->encap || oactions->remove_ethernet ||
		    !oactions->add_ethernet)
			return -EINVAL;
		actions[DECAP].type = RTE_FLOW_ACTION_TYPE_RAW_DECAP;
		actions[ENCAP].type = RTE_FLOW_ACTION_TYPE_RAW_ENCAP;
		encap.data = (uint8_t *)oactions->add_ethernet;
	} else if (oactions->remove_ethernet || oactions->add_ethernet ||
		   oactions->encap)
		return -EINVAL;
	else {
		actions[DECAP].type = RTE_FLOW_ACTION_TYPE_VOID;
		actions[ENCAP].type = RTE_FLOW_ACTION_TYPE_VOID;
	}
	if (oactions->modify) {
		if (oactions->modify->set_src_mac ||
		    oactions->modify->set_dst_mac)
			return -EINVAL;
		if (oactions->modify->set_src_ip4) {
			if (oactions->modify->set_src_ip6 ||
			    oactions->modify->set_dst_ip6)
				return -EINVAL;
			actions[SET_IPV4_SRC].type =
					RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC;
			set_ipv4_src.ipv4_addr = oactions->modify->src_ip4;
		} else
			actions[SET_IPV4_SRC].type = RTE_FLOW_ACTION_TYPE_VOID;
		if (oactions->modify->set_dst_ip4) {
			if (oactions->modify->set_src_ip6 ||
			    oactions->modify->set_dst_ip6)
				return -EINVAL;
			actions[SET_IPV4_DST].type =
					RTE_FLOW_ACTION_TYPE_SET_IPV4_DST;
			set_ipv4_dst.ipv4_addr = oactions->modify->dst_ip4;
		} else
			actions[SET_IPV4_DST].type = RTE_FLOW_ACTION_TYPE_VOID;

		if (oactions->modify->set_src_ip6) {
			actions[SET_IPV6_SRC].type =
					RTE_FLOW_ACTION_TYPE_SET_IPV6_SRC;
			memcpy(set_ipv6_src.ipv6_addr, oactions->modify->src_ip6, 16);
		} else
			actions[SET_IPV6_SRC].type = RTE_FLOW_ACTION_TYPE_VOID;
		if (oactions->modify->set_dst_ip6) {
			actions[SET_IPV6_DST].type =
					RTE_FLOW_ACTION_TYPE_SET_IPV6_DST;
			memcpy(set_ipv6_dst.ipv6_addr, oactions->modify->dst_ip6, 16);
		} else
			actions[SET_IPV6_DST].type = RTE_FLOW_ACTION_TYPE_VOID;

		if (oactions->modify->set_src_port) {
			actions[SET_TP_SRC].type =
					RTE_FLOW_ACTION_TYPE_SET_TP_SRC;
			set_tp_src.port = oactions->modify->src_port;
		} else
			actions[SET_TP_SRC].type = RTE_FLOW_ACTION_TYPE_VOID;
		if (oactions->modify->set_dst_port) {
			actions[SET_TP_DST].type =
					RTE_FLOW_ACTION_TYPE_SET_TP_DST;
			set_tp_dst.port = oactions->modify->dst_port;

		} else
			actions[SET_TP_DST].type = RTE_FLOW_ACTION_TYPE_VOID;
		if (oactions->modify->set_ttl || oactions->modify->dec_ttl) {
			RTE_LOG(ERR, VSWITCH, "TTL modify actions are not "
				"supported in PF to VM flows\n");
			return -EINVAL;
		}
		if (oactions->modify->dec_tcp_seq) {
			if (oactions->modify->inc_tcp_seq)
				return -EINVAL;
			actions[DEC_TCP_SEQ].type =
				RTE_FLOW_ACTION_TYPE_DEC_TCP_SEQ;
			dec_tcp_seq.value = oactions->modify->tcp_seq;
		} else
			actions[DEC_TCP_SEQ].type = RTE_FLOW_ACTION_TYPE_VOID;
		if (oactions->modify->inc_tcp_seq) {
			actions[INC_TCP_SEQ].type =
				RTE_FLOW_ACTION_TYPE_INC_TCP_SEQ;
			inc_tcp_seq.value = oactions->modify->tcp_seq;
		} else
			actions[INC_TCP_SEQ].type = RTE_FLOW_ACTION_TYPE_VOID;
		if (oactions->modify->dec_tcp_ack) {
			if (oactions->modify->inc_tcp_ack)
				return -EINVAL;
			actions[DEC_TCP_ACK].type =
				RTE_FLOW_ACTION_TYPE_DEC_TCP_ACK;
			dec_tcp_ack.value = oactions->modify->tcp_ack;
		} else
			actions[DEC_TCP_ACK].type = RTE_FLOW_ACTION_TYPE_VOID;
		if (oactions->modify->inc_tcp_ack) {
			actions[INC_TCP_ACK].type =
				RTE_FLOW_ACTION_TYPE_INC_TCP_ACK;
			inc_tcp_ack.value = oactions->modify->tcp_ack;
		} else
			actions[INC_TCP_ACK].type = RTE_FLOW_ACTION_TYPE_VOID;
	} else {
		actions[SET_IPV4_SRC].type = RTE_FLOW_ACTION_TYPE_VOID;
		actions[SET_IPV4_DST].type = RTE_FLOW_ACTION_TYPE_VOID;
		actions[SET_IPV6_SRC].type = RTE_FLOW_ACTION_TYPE_VOID;
		actions[SET_IPV6_DST].type = RTE_FLOW_ACTION_TYPE_VOID;
		actions[SET_TP_SRC].type = RTE_FLOW_ACTION_TYPE_VOID;
		actions[SET_TP_DST].type = RTE_FLOW_ACTION_TYPE_VOID;
		actions[DEC_TCP_SEQ].type = RTE_FLOW_ACTION_TYPE_VOID;
		actions[INC_TCP_SEQ].type = RTE_FLOW_ACTION_TYPE_VOID;
		actions[DEC_TCP_ACK].type = RTE_FLOW_ACTION_TYPE_VOID;
		actions[INC_TCP_ACK].type = RTE_FLOW_ACTION_TYPE_VOID;

	}
	if (oactions->count || oactions->timeout) {
		actions[COUNT].type = RTE_FLOW_ACTION_TYPE_COUNT;
		count.handle = aging_counter_alloc(pf->data->port_id,
						   &count.id, &count.bias);
		if (!count.handle)
			return -ENOTSUP;
		oflow->counter_id = count.id;
	} else
		actions[COUNT].type = RTE_FLOW_ACTION_TYPE_VOID;
	if (oactions->meter) {
		if (oactions->meter_id >= RTE_VSWITCH_MAX_METER_NUM) {
			RTE_LOG(ERR, VSWITCH, "Invalid meter id %u must be "
				"smaller than %u\n", oactions->meter_id,
				RTE_VSWITCH_MAX_METER_NUM);
			ret = -EINVAL;
			goto error;
		}
		if (!ctx->vmeters[oactions->meter_id].valid) {
			RTE_LOG(ERR, VSWITCH, "Invalid meter id %u\n",
				oactions->meter_id);
			ret = -EINVAL;
			goto error;
		}
		meter.mtr_id = oactions->meter_id;
		actions[METER].type = RTE_FLOW_ACTION_TYPE_METER;
	} else
		actions[METER].type = RTE_FLOW_ACTION_TYPE_VOID;
	port_id.id = ctx->pf->data->port_id;
	if (oflow->type == VSWITCH_OFFLOAD_FLOW_TYPE_PF_TO_VIRTIO) {
		pattern[PORT_ID].type = RTE_FLOW_ITEM_TYPE_VOID;
		pattern[META].type = RTE_FLOW_ITEM_TYPE_VOID;
		actions[ACT_PORT_ID].type = RTE_FLOW_ACTION_TYPE_VOID;
		actions[MARK].type = RTE_FLOW_ACTION_TYPE_VOID;
		actions[RSS].type = RTE_FLOW_ACTION_TYPE_RSS;
		//mark.id = RTE_VSWITCH_MARK_TYPE_VPORT_FLOW |
		//		(dst_vport->vport_id << 8);
		attr.transfer = 0;
		attr.group = dst_vport->igroup->group_id;
		rss.rss_action.num = pf->data->nb_rx_queues;
		for (i = 0; i < rss.rss_action.num; ++i)
			rss.rss_action.queue[i] = i;
		gr = dst_vport->igroup;
		oflow->gr_id = gr->group_id;
		oflow->gr_ingress = 1;
	} else { // VSWITCH_OFFLOAD_FLOW_TYPE_PF_TO_VF
		pattern[PORT_ID].type = RTE_FLOW_ITEM_TYPE_PORT_ID;
		pattern[META].type = RTE_FLOW_ITEM_TYPE_META_EXT;
		actions[ACT_PORT_ID].type = RTE_FLOW_ACTION_TYPE_PORT_ID;
		actions[MARK].type = RTE_FLOW_ACTION_TYPE_VOID;
		actions[RSS].type = RTE_FLOW_ACTION_TYPE_VOID;
		attr.group = 2;
		attr.transfer = 1;
		meta.data = rte_cpu_to_be_32
				(_GET_SRIOV_METADATA(src_vport, dst_vport));
		act_port_id.id = dst_vport->vport_dev->data->port_id;
		gr = dst_vport->egroup;
		oflow->gr_id = gr->group_id;
		oflow->gr_ingress = 0;
	}
	oflow->flow = _rte_flow_create(port_id.id, &attr, pattern,
				       actions, &err);
	if (!oflow->flow) {
		RTE_LOG(ERR, VSWITCH, "vport %hu, Failed to create a tunnel"
			" offload flow - %s\n", dst_vport->vport_id,
			err.message ? err.message : "(no stated reason)");
		ret = -rte_errno;
		goto error;
	}
	if (_vswitch_prepare_ingress_dispatch_flow(ctx, dst_vport, keys)) {
		_rte_flow_destroy(port_id.id, oflow->flow, &err);
		ret = -1;
		goto error;
	}
	if (ctx->type == RTE_VSWITCH_TYPE_SRIOV) {
		oflow->mgr_id = src_vport->egroup->group_id;
		src_vport->egroup->mcounter++;
	}
	LIST_INSERT_HEAD(&gr->oflows, oflow, next);
	return 0;
error:
	if (count.handle)
		aging_counter_free(pf->data->port_id, count.id);
	return ret;
}

/**
 * The function follow the following heuristics to decide on the
 * type of flows to create.
 * if in_port has ethdev and out_port don't -> ingress rule (wire to VM)
 * if in_port doesn't have ethdev and out_port has -> egress rule (VM to wire)
 * if both in_port and out_port doesn't have ethdev -> ingress and egress rule
 * (VM to VM)
 * if both in_port and out_port has ethdev -> eswitch rule
 * (we are in switchdev mode)
 *
 * The library will maintain a 2 dedicated rte_flow groups per vport. group 0 will
 * act as a dispatcher to the different groups.
 * This is a design choise in order to flush all the vport rule on a simple and
 * fast way(only in virtio case).
 * The function will split the flow rule on the input parameters into multiple
 * rte_flow rules on multiple groups. The split of a rule into the
 * different flow groups will be done using the following scheme:
 *
 * Tunnel rules:
 * - match on fabric vxlan + vni + inner dst L3 address on group 0.
 * - all the other headers fields match w/ decup the rest of actions on the
 *   destination vport dedicated group.
 *
 * Non-tunnel rules:
 * - match on metadata + dst L3 address on group 0. (only for virtio case)
 * - match on headers, w/ rest of actions on the destination vport dedicated
 *   group.
 */
struct rte_vswitch_offload_flow *
rte_vswitch_create_offload_flow(struct rte_vswitch_ctx *ctx,
				uint16_t vport_id,
				struct rte_vswitch_flow_keys *keys,
				struct rte_vswitch_flow_actions *actions)
{
	struct rte_vswitch_offload_flow *oflow;
	struct vswitch_vport *vport_src, *vport_dst, *vport_pf;

	if (!keys || !actions || !ctx || !ctx->vports[vport_id].valid ||
	    !ctx->vports[actions->vport_id].valid)
		return NULL;
	if (vport_id == ctx->pf_vport_id &&
	    actions->vport_id == ctx->pf_vport_id) {
		RTE_LOG(ERR, VSWITCH, "Do not support PF to PF flows\n");
		return NULL;
	}
	if (_vswitch_prepare_context(ctx))
		return NULL;
	oflow = rte_zmalloc_socket(__func__, sizeof(*oflow),
				   RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (!oflow) {
		RTE_LOG(ERR, VSWITCH, "Not enough memory for offload flow\n");
		return NULL;
	}
	vport_src = &ctx->vports[vport_id];
	vport_dst = &ctx->vports[actions->vport_id];
	vport_pf = &ctx->vports[ctx->pf_vport_id];
	if (vport_src->vport_dev == vport_pf->vport_dev) {
		oflow->type = !vport_dst->vport_dev ?
				VSWITCH_OFFLOAD_FLOW_TYPE_PF_TO_VIRTIO:
				VSWITCH_OFFLOAD_FLOW_TYPE_PF_TO_VF;
		if (_vswitch_create_tunnel_offload_flow(ctx, oflow, keys,
							actions, vport_dst))
			goto error;
	} else {
		if (vport_dst->vport_dev != vport_pf->vport_dev) {
			oflow->type = !vport_src->vport_dev ?
				VSWITCH_OFFLOAD_FLOW_TYPE_VIRTIO_TO_VIRTIO:
				VSWITCH_OFFLOAD_FLOW_TYPE_VF_TO_VF;
		} else {
			oflow->type = !vport_src->vport_dev ?
					VSWITCH_OFFLOAD_FLOW_TYPE_VIRTIO_TO_PF:
					VSWITCH_OFFLOAD_FLOW_TYPE_VF_TO_PF;
		}
		if (keys->tunnel_type != RTE_VSWITCH_TUNNEL_TYPE_NONE)
			goto error;
		if (_vswitch_create_non_tunnel_offload_flow
			(ctx, oflow, keys, actions, vport_dst, vport_src))
			goto error;
	}
	if (actions->timeout || actions->count)
		aging_on_flow_create(_oflow_port(ctx, NULL, oflow), oflow,
				     actions->timeout, oflow->counter_id);
	_rte_offload_flow_stats_inc(ctx, oflow->type);
	return oflow;
error:
	rte_free(oflow);
	return NULL;
}

int
rte_vswitch_destroy_offload_flow(struct rte_vswitch_ctx *ctx,
				 struct rte_vswitch_offload_flow *oflow) {
	struct vswitch_group *gr, *mgr;
	struct rte_flow_error err;
	uint16_t port_id;

	if (!ctx || !oflow) {
		RTE_LOG(ERR, VSWITCH, "Invalid arguments\n");
		return -EINVAL;
	}
	if (_vswitch_prepare_context(ctx))
		return -EINVAL;
	gr = _vswitch_get_group_by_id(ctx, oflow->gr_id, oflow->gr_ingress);
	mgr = oflow->mgr_id == 0 ? NULL :
			_vswitch_get_group_by_id(ctx, oflow->mgr_id, 0);
	port_id = _oflow_port(ctx, mgr, oflow);
	if (oflow->flow && !gr->reseted)
		aging_on_flow_destroy(port_id, oflow, oflow->counter_id);
	if (!gr->reseted && oflow->flow) {
		_rte_flow_destroy(port_id, oflow->flow, &err);
		_rte_offload_flow_stats_dec(ctx, oflow->type);
	}
	LIST_REMOVE(oflow, next);
	if (!gr->valid && LIST_EMPTY(&gr->oflows) &&
	    gr->mcounter == 0) {
		/* remove group from invalid list. */
		TAILQ_REMOVE(&ctx->invalid_groups, gr, next);
		_vswitch_group_push(gr);
	}
	if (mgr && mgr != gr) {
		mgr->mcounter--;
		if (mgr->mcounter == 0 && !mgr->valid &&
		   LIST_EMPTY(&mgr->oflows)) {
			/* remove group from invalid list. */
			TAILQ_REMOVE(&ctx->invalid_groups, mgr, next);
			_vswitch_group_push(mgr);
		}
	}
	rte_free(oflow);
	return 0;
}

int
rte_vswitch_modify_offload_flow(struct rte_vswitch_ctx *ctx,
				struct rte_vswitch_offload_flow *oflow,
				uint16_t timeout)
{
	struct vswitch_group *gr;

	if (_vswitch_prepare_context(ctx))
		return -EINVAL;
	gr = _vswitch_get_group_by_id(ctx, oflow->gr_id, oflow->gr_ingress);
	if (oflow->flow && gr && !gr->reseted)
		return aging_flow_modify(_oflow_port(ctx, NULL, oflow),
					 oflow, timeout);
	return -EINVAL;
}

/**
 * The function invalidates all the flows comes from a vport quickly,
 * The application should destroy thus flows on its preferred time.
 */
static int
_vswitch_flush_vport_offload_flows(struct rte_vswitch_ctx *ctx,
				   struct vswitch_vport *vport,
				   uint32_t *metadata) {
	struct vswitch_group *grs[ctx->max_vport_id + 1];
	struct rte_flow *pf_disp_flow;
	uint8_t sriov = ctx->type == RTE_VSWITCH_TYPE_SRIOV;

	if (sriov || vport->vport_id != ctx->pf_vport_id) {
		grs[0] = NULL;
		grs[1] = NULL;
		if (_rte_vswitch_create_vport_groups(ctx,
						     vport->vport_id,
						     sriov ? NULL : &grs[0],
						     &grs[1])) {
			RTE_LOG(ERR, VSWITCH, "vport %hu, Failed to"
				" flush - probably a temporary resource"
				" lack - try again\n", vport->vport_id);
			return -EAGAIN;
		}
		_rte_vswitch_destroy_vport_flows(ctx, vport, 1, 1, 0);
		_vswitch_invalidate_vport_group(ctx, &vport->egroup);
		vport->egroup = grs[1];
		if (sriov)
			return 0;
		_vswitch_invalidate_vport_group(ctx, &vport->igroup);
		vport->igroup = grs[0];
	} else {
		int32_t v;
		uint8_t prio;

		for (v = 0; v <= ctx->max_vport_id; ++v) {
			grs[v] = NULL;
			if (!ctx->vports[v].valid)
				continue;
			if (v == ctx->pf_vport_id) {
				if (_rte_vswitch_create_vport_groups
					(ctx, v, NULL, &grs[v]))
					goto error;
			} else {
				if (_rte_vswitch_create_vport_groups
					(ctx, v, &grs[v], NULL))
					goto error;
			}
		}
		prio = (vport->flush_bit ? 1 : 2);
		pf_disp_flow =
			_vswitch_create_jump_exception_flow_egress
				(ctx->pf,
				 grs[ctx->pf_vport_id]->group_id, 0, 1,
				 prio);
		if (!pf_disp_flow)
			goto error;
		vport->flush_bit = vport->flush_bit ? 0 : 1;
		_rte_vswitch_destroy_vport_flows(ctx, vport, 1, 1, 0);
		for (v = 0; v <= ctx->max_vport_id; ++v) {
			if (grs[v]) {
				if (v == ctx->pf_vport_id) {
					_vswitch_invalidate_vport_group
						(ctx, &vport->egroup);
					ctx->vports[v].egroup = grs[v];
				} else {
					_vswitch_invalidate_vport_group
						(ctx, &vport->igroup);
					ctx->vports[v].igroup = grs[v];
				}
			}
		}
		vport->pf_disp_flow = pf_disp_flow;
		return 0;
error:
		for (v--; v >= 0; v--) {
			if (!grs[v])
				continue;
			if (v == ctx->pf_vport_id)
				_rte_vswitch_destroy_vport_groups
					(ctx, NULL, &grs[v]);
			else
				_rte_vswitch_destroy_vport_groups
					(ctx, &grs[v], NULL);
		}
		RTE_LOG(ERR, VSWITCH, "vport %hu, Failed to"
			" flush - probably a temporary resource"
			" lack - try again\n", vport->vport_id);
		return -EAGAIN;
	}
	*metadata = rte_vswitch_get_vport_metadata(ctx, vport->vport_id);
	return 0;
}

int
rte_vswitch_flush_vport_offload_flows(struct rte_vswitch_ctx *ctx,
				      uint16_t vport_id, uint32_t *metadata) {

	if (!ctx) {
		RTE_LOG(ERR, VSWITCH, "Failed to flush vport %hu - invalid"
			" context\n", vport_id);
		return -EINVAL;
	}
	if (vport_id > ctx->max_vport_id || !ctx->vports[vport_id].valid) {
		RTE_LOG(ERR, VSWITCH, "Invalid vport %hu\n", vport_id);
		return -EINVAL;
	}
	if (_vswitch_prepare_context(ctx))
		return -EINVAL;
	return _vswitch_flush_vport_offload_flows(ctx, &ctx->vports[vport_id], metadata);
}

int
rte_vswitch_flush_all(struct rte_vswitch_ctx *ctx)
{
	uint32_t v;
	int ret;
	uint32_t metadata;
	uint64_t perf_start;
	int n = 0;

	if (!ctx) {
		RTE_LOG(ERR, VSWITCH, "Failed to flush all vports - invalid"
			" context\n");
		return -EINVAL;
	}
	if (_vswitch_prepare_context(ctx))
		return -EINVAL;
	perf_start = rte_rdtsc();
	for (v = 0; v <= ctx->max_vport_id; ++v) {
		if (ctx->vports[v].valid) {
			ret = _vswitch_flush_vport_offload_flows(ctx,
							&ctx->vports[v],
							&metadata);
			if (ret)
				return ret;
			n++;
		}
	}
	RTE_LOG(INFO, VSWITCH, "Flushed %d vport flows in %"PRIu64"ms\n", n,
		((rte_rdtsc() - perf_start) * 1000 / rte_get_tsc_hz()));
	ret = _vswitch_flush_meter(ctx);
	return ret;
}

int
rte_vswitch_create_meter(struct rte_vswitch_ctx *ctx, uint32_t meter_id,
						 struct rte_vswitch_meter_profile *profile)
{
	struct rte_mtr_error error;
	struct rte_vswitch_meter *mtr;

	if (!ctx || !profile) {
		RTE_LOG(ERR, VSWITCH, "Failed to create a meter - invalid"
			" context/profile\n");
		return -EINVAL;
	}
	if (ctx->type != RTE_VSWITCH_TYPE_VIRTIO) {
		RTE_LOG(ERR, VSWITCH, "Unsupported Vswitch type. %d",
				ctx->type);
		return -EINVAL;
	}
	if (meter_id >= RTE_VSWITCH_MAX_METER_NUM) {
		RTE_LOG(ERR, VSWITCH, "Invalid meter id %u must be smaller than %u\n",
				meter_id, RTE_VSWITCH_MAX_METER_NUM);
		return -EINVAL;
	}
	if (_vswitch_prepare_context(ctx))
		return -EINVAL;
	mtr = &ctx->vmeters[meter_id];
	if (mtr->valid) {
		RTE_LOG(ERR, VSWITCH, "Invalid meter id %u already exists\n",
				meter_id);
		return -EEXIST;
	}
	default_profile.srtcm_rfc2697.cir = profile->bps;
	default_profile.srtcm_rfc2697.cbs = profile->bps >> 1;
	default_profile.srtcm_rfc2697.ebs = 0;
	if (_rte_mtr_meter_profile_add(ctx->pf->data->port_id, meter_id,
				       &default_profile, &error)) {
		RTE_LOG(ERR, VSWITCH, "Failed to create meter profile %u - %s\n",
				meter_id, error.message ? error.message : "no cause");
		return -1;
	}
	default_meter_params.meter_profile_id = meter_id;
	if (_rte_mtr_create(ctx->pf->data->port_id, meter_id,
					   &default_meter_params, 1, &error)) {
		RTE_LOG(ERR, VSWITCH, "Failed to create meter %u - %s\n",
				meter_id, error.message ? error.message : "no cause");
		_rte_mtr_meter_profile_delete(ctx->pf->data->port_id, meter_id,
					      &error);
		return -1;
	}
	mtr->valid = 1;
	mtr->meter_id = meter_id;
	mtr->profile_id = meter_id;
	mtr->bps =  profile->bps;
	return 0;
}

int
rte_vswitch_generate_meter(struct rte_vswitch_ctx *ctx, uint32_t *meter_id,
			   struct rte_vswitch_meter_profile *profile)
{
	int i;
	struct rte_vswitch_meter *mtr;

	if (_vswitch_prepare_context(ctx))
		return -EINVAL;
	for (i = 0; i < RTE_VSWITCH_MAX_METER_NUM; i++) {
		mtr = &ctx->vmeters[i];
		if (!mtr->valid) {
			*meter_id = i;
        		return rte_vswitch_create_meter(ctx, i, profile);
		}
	}
	RTE_LOG(ERR, VSWITCH, "No more free meter IDs\n");
	return -ELOOP;
}

int
rte_vswitch_update_meter(struct rte_vswitch_ctx *ctx, uint32_t meter_id,
						 struct rte_vswitch_meter_profile *new_profile) {
	struct rte_mtr_error error;
	struct rte_vswitch_meter *mtr;
	uint32_t new_profile_id;

	if (!ctx || !new_profile) {
		RTE_LOG(ERR, VSWITCH, "Failed to create a meter - invalid"
			" context/profile\n");
		return -EINVAL;
	}
	if (ctx->type != RTE_VSWITCH_TYPE_VIRTIO) {
		RTE_LOG(ERR, VSWITCH, "Unsupported Vswitch type. %d",
				ctx->type);
		return -EINVAL;
	}
	if (meter_id >= RTE_VSWITCH_MAX_METER_NUM) {
		RTE_LOG(ERR, VSWITCH, "Invalid meter id %u must be smaller than %u\n",
				meter_id, RTE_VSWITCH_MAX_METER_NUM);
		return -EINVAL;
	}
	if (_vswitch_prepare_context(ctx))
		return -EINVAL;
	mtr = &ctx->vmeters[meter_id];
	if (!mtr->valid) {
		RTE_LOG(ERR, VSWITCH, "Invalid meter id %u\n", meter_id);
		return -EEXIST;
	}
	if (mtr->bps == new_profile->bps)
		return 0;
	new_profile_id = mtr->profile_id == meter_id ? meter_id +
						RTE_VSWITCH_MAX_METER_NUM : meter_id;
	default_profile.srtcm_rfc2697.cir = new_profile->bps;
	default_profile.srtcm_rfc2697.cbs = new_profile->bps >> 1;
	default_profile.srtcm_rfc2697.ebs = 0;
	if (_rte_mtr_meter_profile_add(ctx->pf->data->port_id, new_profile_id,
				       &default_profile, &error)) {
		RTE_LOG(ERR, VSWITCH, "Failed to create meter profile %u - %s\n",
				meter_id, error.message ? error.message : "no cause");
		return -1;
	}
	if (_rte_mtr_meter_profile_update(ctx->pf->data->port_id, meter_id,
					  new_profile_id, &error)) {
		RTE_LOG(ERR, VSWITCH, "Failed to update meter %u - %s\n",
				meter_id, error.message ? error.message : "no cause");
		_rte_mtr_meter_profile_delete(ctx->pf->data->port_id,
					      new_profile_id, &error);
		return -1;
	}
	_rte_mtr_meter_profile_delete(ctx->pf->data->port_id, mtr->profile_id,
								 &error);
	mtr->profile_id = new_profile_id;
	mtr->bps = new_profile->bps;
	return 0;
}

int
rte_vswitch_query_meter(struct rte_vswitch_ctx *ctx, uint32_t meter_id,
						struct rte_vswitch_meter_stats* stats) {
	struct rte_mtr_error error;
	struct rte_vswitch_meter *mtr;
	struct rte_mtr_stats mtr_stats;
	uint64_t stat_mask;

	if (!ctx || !stats) {
		RTE_LOG(ERR, VSWITCH, "Failed to create a meter - invalid"
				" context/stats\n");
		return -EINVAL;
	}
	if (ctx->type != RTE_VSWITCH_TYPE_VIRTIO) {
		RTE_LOG(ERR, VSWITCH, "Unsupported Vswitch type. %d",
				ctx->type);
		return -EINVAL;
	}
	if (meter_id >= RTE_VSWITCH_MAX_METER_NUM) {
		RTE_LOG(ERR, VSWITCH, "Invalid meter id %u must be smaller than %u\n",
				meter_id, RTE_VSWITCH_MAX_METER_NUM);
		return -EINVAL;
	}
	if (_vswitch_prepare_context(ctx))
		return -EINVAL;
	mtr = &ctx->vmeters[meter_id];
	if (!mtr->valid) {
		RTE_LOG(ERR, VSWITCH, "Invalid meter id %u\n", meter_id);
		return -EEXIST;
	}
	memset(&mtr_stats, 0, sizeof(mtr_stats));
	if (_rte_mtr_stats_read(ctx->pf->data->port_id, meter_id, &mtr_stats,
						   &stat_mask, 0, &error)) {
		RTE_LOG(ERR, VSWITCH, "Failed to read meter %u stats - %s\n",
				meter_id, error.message ? error.message : "no cause");
		return -1;
	}
	stats->n_pkts = mtr_stats.n_pkts[RTE_MTR_GREEN] +
						mtr_stats.n_pkts[RTE_MTR_YELLOW];
	stats->n_bytes = mtr_stats.n_bytes[RTE_MTR_GREEN] +
						mtr_stats.n_bytes[RTE_MTR_YELLOW];
	stats->n_pkts_dropped = mtr_stats.n_pkts[RTE_MTR_RED];
	stats->n_bytes_dropped = mtr_stats.n_bytes[RTE_MTR_RED];
	return 0;
}
int
rte_vswitch_enable_meter(struct rte_vswitch_ctx *ctx, uint32_t meter_id)
{
	struct rte_mtr_error error;
	struct rte_vswitch_meter *mtr;

	if (!ctx) {
		RTE_LOG(ERR, VSWITCH, "Failed to enable a meter - invalid"
			" context/profile\n");
		return -EINVAL;
	}
	if (ctx->type != RTE_VSWITCH_TYPE_VIRTIO) {
		RTE_LOG(ERR, VSWITCH, "Unsupported Vswitch type. %d",
				ctx->type);
		return -EINVAL;
	}
	if (meter_id >= RTE_VSWITCH_MAX_METER_NUM) {
		RTE_LOG(ERR, VSWITCH, "Invalid meter id %u must be smaller than %u\n",
				meter_id, RTE_VSWITCH_MAX_METER_NUM);
		return -EINVAL;
	}
	if (_vswitch_prepare_context(ctx))
		return -EINVAL;
	mtr = &ctx->vmeters[meter_id];
	if (!mtr->valid) {
		RTE_LOG(ERR, VSWITCH, "Invalid meter id %u\n", meter_id);
		return -EEXIST;
	}
	return _rte_mtr_enable(ctx->pf->data->port_id, meter_id, &error);
}

int
rte_vswitch_disable_meter(struct rte_vswitch_ctx *ctx, uint32_t meter_id)
{
	struct rte_mtr_error error;
	struct rte_vswitch_meter *mtr;

	if (!ctx) {
		RTE_LOG(ERR, VSWITCH, "Failed to disable a meter - invalid"
			" context/profile\n");
		return -EINVAL;
	}
	if (ctx->type != RTE_VSWITCH_TYPE_VIRTIO) {
		RTE_LOG(ERR, VSWITCH, "Unsupported Vswitch type. %d",
				ctx->type);
		return -EINVAL;
	}
	if (meter_id >= RTE_VSWITCH_MAX_METER_NUM) {
		RTE_LOG(ERR, VSWITCH, "Invalid meter id %u must be smaller than %u\n",
				meter_id, RTE_VSWITCH_MAX_METER_NUM);
		return -EINVAL;
	}
	if (_vswitch_prepare_context(ctx))
		return -EINVAL;
	mtr = &ctx->vmeters[meter_id];
	if (!mtr->valid) {
		RTE_LOG(ERR, VSWITCH, "Invalid meter id %u\n", meter_id);
		return -EEXIST;
	}
	return _rte_mtr_disable(ctx->pf->data->port_id, meter_id, &error);
}

int
rte_vswitch_destroy_meter(struct rte_vswitch_ctx *ctx, uint32_t meter_id)
{
	struct rte_mtr_error error;
	struct rte_vswitch_meter *mtr;

	if (!ctx) {
		RTE_LOG(ERR, VSWITCH, "Failed to create a meter - invalid"
				" context\n");
		return -EINVAL;
	}
	if (ctx->type != RTE_VSWITCH_TYPE_VIRTIO) {
		RTE_LOG(ERR, VSWITCH, "Unsupported Vswitch type. %d",
				ctx->type);
		return -EINVAL;
	}
	if (meter_id >= RTE_VSWITCH_MAX_METER_NUM) {
		RTE_LOG(ERR, VSWITCH, "Invalid meter id %u must be smaller than %u\n",
				meter_id, RTE_VSWITCH_MAX_METER_NUM);
		return -EINVAL;
	}
	if (_vswitch_prepare_context(ctx))
		return -EINVAL;
	mtr = &ctx->vmeters[meter_id];
	if (!mtr->valid) {
		RTE_LOG(ERR, VSWITCH, "Invalid meter id %u\n", meter_id);
		return -EEXIST;
	}
	_rte_mtr_destroy(ctx->pf->data->port_id, meter_id, &error);
	_rte_mtr_meter_profile_delete(ctx->pf->data->port_id, mtr->profile_id,
								 &error);
	return 0;
}

static int
_vswitch_flush_meter(struct rte_vswitch_ctx *ctx)
{
	uint32_t meter_id;
	int err, ret = 0;
	int n = 0;
	uint64_t perf_start = rte_rdtsc();

	for (meter_id = 0; meter_id < RTE_DIM(ctx->vmeters); meter_id++) {
		if (!ctx->vmeters[meter_id].valid)
			continue;
		err = rte_vswitch_destroy_meter(ctx, meter_id);
		if (!err)
			n++;
		if (err && !ret)
			ret = err;
	}
	RTE_LOG(INFO, VSWITCH, "Flushed %d meters in %"PRIu64"ms\n",
		n, ((rte_rdtsc() - perf_start) * 1000 / rte_get_tsc_hz()));
	return ret;
}

struct rte_vswitch_mark_id
rte_vswitch_translate_mark_id(struct rte_vswitch_ctx* ctx __rte_unused,
			      uint32_t mark_id) {
	return (struct rte_vswitch_mark_id) {
						.type = mark_id & 0xf,
						.vport_id = (mark_id >> 8) & 0xffff,
					};
}

uint32_t
rte_vswitch_get_vport_metadata(struct rte_vswitch_ctx* ctx,
			       uint16_t vport_id) {
	if (unlikely(ctx->restarting))
		return rte_cpu_to_be_32
			((vport_id << 16) + 1);
	if (likely(ctx && vport_id <= ctx->max_vport_id &&
	    ctx->vports[vport_id].valid))
		return rte_cpu_to_be_32
			(_GET_VPORT_METADATA(&ctx->vports[vport_id]));
	return 0;
}

/**
 * The data struct contains numa infomation of each rx/tx queue
 * Used during vport restart
 */
struct rte_rxq_txq_info {
	uint8_t rxq_numa : 4,
		txq_numa : 4;
	struct rte_mempool *rx_mp;
};

/**
 * The data structure associated with each port.
 * Which contains mandantory information for port restarting.
 */
struct rte_port_info {
	struct rte_eth_dev_info dev_info;   /**< PCI info + driver name */
	struct rte_eth_conf dev_conf;   /**< Port configuration. */
	struct ether_addr eth_addr;   /**< Port ethernet address */
	unsigned int socket_id;  /**< For NUMA support */
	uint16_t tso_segsz;  /**< Segmentation offload MSS for non-tunneled packets. */
	uint16_t tunnel_tso_segsz; /**< Segmentation offload MSS for tunneled pkts. */
	uint16_t tx_vlan_id;/**< The tag ID */
	uint16_t tx_vlan_id_outer;/**< The outer tag ID */
	uint8_t tx_queue_stats_mapping_enabled;
	uint8_t rx_queue_stats_mapping_enabled;
	uint8_t rss_flag;   /**< enable rss or not */
	uint8_t dcb_flag;   /**< enable dcb */
	struct rte_eth_rxconf rx_conf;    /**< rx configuration */
	struct rte_eth_txconf tx_conf;    /**< tx configuration */
	uint16_t nb_rxq;     /**< configed number of rx queue */
	uint16_t nb_txq;     /**< configed number of tx queue */
	uint16_t nb_rxqd; /**< number of rxq descriptor */
	uint16_t nb_txqd; /**< number of txq descriptor */
	uint8_t	isolated;   /** isolated mode or not */
	struct rte_rxq_txq_info rxq_txq_info[RTE_MAX_QUEUES_PER_PORT];
	/*
	 * Per device lock, to protect PMD from multiple thread access.
	 * Known threads:
	 *	Control path thread perform:
	 *		flow create/query/destroy
	 *		meter operations
	 *	Aging thread that perform:
	 *		flow destroy
	 *		counter allocation/query/destroy
	 * During port reset, aging stopped and no lock.
	 */
	pthread_mutex_t lock;
};

struct rte_port_info ports_info[RTE_MAX_ETHPORTS];

static int
port_lock_init(struct rte_eth_dev *dev)
{
	pthread_mutexattr_t attr;

	if (pthread_mutexattr_init(&attr) ||
	    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) ||
	    pthread_mutex_init(&ports_info[dev->data->port_id].lock, &attr)) {
		RTE_LOG(ERR, VSWITCH, "port %hu failed to init mutex.\n",
			dev->data->port_id);
		return -1;
	}
	return 0;
}

inline void
port_lock(uint16_t port)
{
	pthread_mutex_lock(&ports_info[port].lock);
}

inline void
port_unlock(uint16_t port)
{
	pthread_mutex_unlock(&ports_info[port].lock);
}

static int
_vswitch_create_temp_flows(struct rte_vswitch_ctx *ctx)
{
	int i;
	struct vswitch_vport *vport = NULL;

	if (ctx->type != RTE_VSWITCH_TYPE_VIRTIO)
		return -EPERM;
	ctx->restarting = 1;
	for (i = 0; i <= ctx->max_vport_id; i++) {
		vport = &ctx->vports[i];
		if (!vport->valid)
			continue;
		if (!vport->vport_dev) {
			if (_vswitch_vport_prepare_lb_management_flows
				(ctx, vport))
				goto error;
			vport->eflowe =
				_vswitch_create_group_exception_flow_egress
				(ctx->pf, vport->vport_id, 0,
				 (vport->vport_id << 16) + 1, 0);
			if (!vport->eflowe) {
				RTE_LOG(ERR, VSWITCH,
					"vport: %hu, Failed to create the vport"
					" temporary egress exception flow\n",
					vport->vport_id);
				goto error;
			}
		} else {
			if (_rte_vswitch_create_pf_fabric_exception_flow
				(ctx, vport))
				goto error;
		}
	}
	return 0;
error:
	for (; i >= 0; i--) {
		vport = &ctx->vports[i];
		if (vport->valid)
			_rte_vswitch_destroy_vport_flows(ctx, vport, 0, 0, 1);
	}
	ctx->restarting = 0;
	return -1;
}

static int
_vswitch_hotplug_add(const char *busname, const char *devname,
		     const char *devargs, const char *devdataname)
{
	int ret;
	uint16_t port_id = UINT16_MAX;

	ret = rte_eal_hotplug_add(busname, devname, devargs);
	if (!ret) {
		/*< check device data name.*/
		if (!rte_eth_dev_get_port_by_name(devdataname, &port_id))
			return 0;
		/*< the device is not the one waiting for, release.*/
		if (!rte_eth_dev_get_port_by_name(devname, &port_id)) {
			rte_eth_dev_release_port(&rte_eth_devices[port_id]);
			rte_eal_hotplug_remove(busname, devname);
			ret = -1;
		}
	}
	return ret;
}

int
rte_vswitch_hotplug_restart(struct rte_vswitch_ctx *ctx)
{
	int ret = 0;
	uint16_t pf_port_id = ctx->pf->data->port_id;
	uint16_t new_pf_port_id = 0xFFFF;
	struct rte_flow_error error;
	struct rte_eth_dev *dev;
	struct rte_eth_link link;
	struct rte_intr_conf tmp_intr_conf;
	struct rte_devargs *devargs;
	char devargs_name[RTE_DEV_NAME_MAX_LEN];
	char dev_data_name[RTE_ETH_NAME_MAX_LEN];
	char *devargs_args = NULL;
	rte_atomic16_t timeout_flag;
	uint8_t promiscuous = 0;
	uint64_t start_cycles = 0;

	if (ctx->type == RTE_VSWITCH_TYPE_SRIOV) {
		ret = -EPERM;
		_VSWITCH_RET_ON_ERR(ret, hotplug_restart_exit,
				    "%s doesn't support SRIOV mode\n",
				    __func__);
	}
	if (!rte_eth_dev_is_valid_port(pf_port_id)) {
		_VSWITCH_RET_ON_ERR(-ENODEV, hotplug_restart_exit,
				    "%s invalid pf port[%u]\n",
				    __func__, pf_port_id);
	}
	dev = &rte_eth_devices[pf_port_id];
	devargs = dev->device->devargs;
	strncpy(devargs_name, devargs->name, RTE_DEV_NAME_MAX_LEN);
	strncpy(dev_data_name, dev->data->name, RTE_ETH_NAME_MAX_LEN);
	devargs_args = strdup(devargs->args);
	assert(devargs_args);
	ports_info[pf_port_id].dev_conf = dev->data->dev_conf;
	promiscuous = dev->data->promiscuous;
	/* setup timeout alarm */
	rte_atomic16_init(&timeout_flag);
	rte_eal_alarm_set(_VSWITCH_RESTART_TIMEOUT,
			  _vswitch_restart_timeout_alarm,
			  (void*)(&timeout_flag));
	for (;;) {
		if (rte_atomic16_read(&restart_req[pf_port_id]))
			break;
		if (rte_atomic16_read(&timeout_flag)) {
			ret = -ETIME;
			_VSWITCH_RET_ON_ERR(ret, hotplug_restart_exit,
					    "%s timeout at wait restart flag\n",
					    __func__);
		}
	}
	if (rte_log_get_level(RTE_LOGTYPE_VSWITCH) >= (int)RTE_LOG_INFO) {
		start_cycles = rte_rdtsc();
	}
	aging_reset(pf_port_id);
	_vswitch_stop(ctx);
	rte_eth_dev_stop(pf_port_id);
	rte_eth_dev_close(pf_port_id);
	rte_eth_dev_release_port(dev);
	ret = rte_eal_hotplug_remove("pci", devargs_name);
	_VSWITCH_RET_ON_ERR(ret, hotplug_restart_exit,
			    "failed to hotplug_remove device %s", devargs_name);
	rte_atomic16_set(&restart_req[pf_port_id], 0);
	for(;;) {
		ret = _vswitch_hotplug_add("pci",
					   devargs_name, devargs_args,
					   dev_data_name);
		if (!ret)
			break;
		rte_delay_ms(1);
		if (rte_atomic16_read(&timeout_flag)) {
			ret = -ETIME;
			_VSWITCH_RET_ON_ERR(ret, hotplug_restart_exit,
					    "%s timeout at hotplug_add\n",
					    __func__);
		}
	}
	/* let's have a sanity check if pf port id is still the same one */
	ret = rte_eth_dev_get_port_by_name(dev_data_name,
					   &new_pf_port_id);
	_VSWITCH_RET_ON_ERR(ret, hotplug_restart_exit,
			    "Cannot find port by name[%s] ret[%d]\n",
			    dev_data_name, ret);
	assert(new_pf_port_id == pf_port_id);
	/* update pf pointer, just make sure */
	dev = &rte_eth_devices[pf_port_id];
	ctx->pf = dev;
	if (ports_info[pf_port_id].isolated) {
		ret = rte_flow_isolate(pf_port_id, 1, &error);
		_VSWITCH_RET_ON_ERR(ret, hotplug_restart_teardown,
				    "isolate pf port[%u] failed ret[%d]\n",
				    pf_port_id, ret);
	}
	if (promiscuous)
		rte_eth_promiscuous_enable(pf_port_id);
	ret = rte_eth_dev_configure(pf_port_id,
				    ports_info[pf_port_id].nb_rxq,
				    ports_info[pf_port_id].nb_txq,
				    &ports_info[pf_port_id].dev_conf);
	_VSWITCH_RET_ON_ERR(ret, hotplug_restart_teardown,
			    "re-configure device (pf port [%u]) failed ret[%d]",
			    pf_port_id, ret);
	int qi = 0;
	struct rte_rxq_txq_info rxq_txq;
	for (qi = 0; qi < ports_info[pf_port_id].nb_txq; qi++) {
		rxq_txq = ports_info[pf_port_id].rxq_txq_info[qi];
		ret = rte_eth_tx_queue_setup(pf_port_id,
					     qi,
					     ports_info[pf_port_id].nb_txqd,
					     rxq_txq.txq_numa,
					     &ports_info[pf_port_id].tx_conf);
		_VSWITCH_RET_ON_ERR(ret, hotplug_restart_teardown,
				    "re-setup tx queue[%d] (pf port [%u]) "
				    "failed ret[%d]", qi, pf_port_id, ret);
	}
	for (qi = 0; qi < ports_info[pf_port_id].nb_rxq; qi++) {
		rxq_txq = ports_info[pf_port_id].rxq_txq_info[qi];
		ret = rte_eth_rx_queue_setup(pf_port_id, qi,
					     ports_info[pf_port_id].nb_rxqd,
					     rxq_txq.rxq_numa,
					     &ports_info[pf_port_id].rx_conf,
					     rxq_txq.rx_mp);
		_VSWITCH_RET_ON_ERR(ret, hotplug_restart_teardown,
				    "re-setup rx queue[%d] (pf port[%u]) "
				    "failed ret[%d]\n", qi, pf_port_id, ret);
	}
	ret = rte_eth_dev_start(pf_port_id);
	_VSWITCH_RET_ON_ERR(ret, hotplug_restart_teardown,
			    "re-start dev (pf port[%u]) failed ret[%d]",
			    pf_port_id, ret);
	/* re-create meters */
	ret = _vswitch_recreate_meters(ctx);
	_VSWITCH_RET_ON_ERR(ret, hotplug_restart_teardown,
			    "re-create meters (pf port[%u]) failed ret[%d]\n",
			    pf_port_id, ret);
	/* wait till link up */
	memset(&link, 0, sizeof(link));
	tmp_intr_conf.lsc = dev->data->dev_conf.intr_conf.lsc;
	/*
	 * clear interrupt set of lsc to force call device's link_update()
	 * directly because we could be in interrupt thread right now
	 */
	dev->data->dev_conf.intr_conf.lsc = 0;
	for (;;) {
		rte_eth_link_get_nowait(pf_port_id, &link);
		if (link.link_status == ETH_LINK_UP)
			break;
		rte_delay_ms(100);
		if (rte_atomic16_read(&timeout_flag)) {
			dev->data->dev_conf.intr_conf.lsc = tmp_intr_conf.lsc;
			ret = -ETIME;
			_VSWITCH_RET_ON_ERR(ret , hotplug_restart_teardown,
					    "%s timeout at wait link up\n",
					    __func__);
		}
	}
	dev->data->dev_conf.intr_conf.lsc = tmp_intr_conf.lsc;
	ret = rte_eth_dev_callback_register(ctx->pf->data->port_id,
					    RTE_ETH_EVENT_INTR_RMV,
					    _vswitch_event_handler,
					    NULL);
	_VSWITCH_RET_ON_ERR(ret, hotplug_restart_teardown,
			    "re-register RTE_ETH_EVENT_INTR_RMV event's "
			    "callback function failed ret[%d]", ret);
	_vswitch_create_temp_flows(ctx);
	RTE_LOG(INFO, VSWITCH, "%s: %"PRIu64" ms\n", __func__,
		PERF_DIFF_MS(start_cycles));
	goto hotplug_restart_exit;
hotplug_restart_teardown:
	rte_eth_dev_stop(pf_port_id);
	rte_eth_dev_close(pf_port_id);
	rte_eth_dev_release_port(dev);
	rte_eal_hotplug_remove("pci", devargs_name);
hotplug_restart_exit:
	if (devargs_args)
		free(devargs_args);
	rte_eal_alarm_cancel(_vswitch_restart_timeout_alarm, (void *)-1);
	return ret;
}

int
rte_vswitch_vport_configure(uint16_t port_id, uint16_t nb_rx_q,
			    uint16_t nb_tx_q,
			    const struct rte_eth_conf *dev_conf)
{
	int ret = 0;

	ret = rte_eth_dev_configure(port_id, nb_rx_q, nb_tx_q, dev_conf);
	if (!ret) {
		ports_info[port_id].nb_rxq = nb_rx_q;
		ports_info[port_id].nb_txq = nb_tx_q;
		ports_info[port_id].dev_conf = (*dev_conf);
	}
	return ret;
}

int
rte_vswitch_vport_rx_queue_setup(uint16_t port_id, uint16_t rx_queue_id,
				 uint16_t nb_rx_desc, unsigned int socket_id,
				 const struct rte_eth_rxconf *rx_conf,
				 struct rte_mempool *mp)
{
	int ret = 0;

	ret = rte_eth_rx_queue_setup(port_id, rx_queue_id, nb_rx_desc,
				     socket_id, rx_conf, mp);
	if (!ret) {
		ports_info[port_id].rxq_txq_info[rx_queue_id].rxq_numa =
			socket_id;
		ports_info[port_id].rxq_txq_info[rx_queue_id].rx_mp = mp;
		ports_info[port_id].nb_rxqd = nb_rx_desc;
		if (rx_conf)
			ports_info[port_id].rx_conf = (*rx_conf);
		else
			memset(&ports_info[port_id].rx_conf, 0, sizeof(struct rte_eth_rxconf));
	}
	return ret;
}

int
rte_vswitch_vport_tx_queue_setup(uint16_t port_id, uint16_t tx_queue_id,
		       		 uint16_t nb_tx_desc, unsigned int socket_id,
		       		 const struct rte_eth_txconf *tx_conf)
{
	int ret = 0;

	ret = rte_eth_tx_queue_setup(port_id, tx_queue_id, nb_tx_desc,
				     socket_id, tx_conf);
	if (!ret) {
		ports_info[port_id].rxq_txq_info[tx_queue_id].txq_numa =
			socket_id;
		if (tx_conf)
			ports_info[port_id].tx_conf = (*tx_conf);
		else
			memset(&ports_info[port_id].tx_conf, 0,
			       sizeof(struct rte_eth_txconf));
		ports_info[port_id].nb_txqd = nb_tx_desc;
	}
	return ret;
}

int
rte_vswitch_vport_isolate(uint16_t port_id,
			  int set,
			  struct rte_flow_error *error)
{
	int ret = 0;

	ret = rte_flow_isolate(port_id, set, error);
	if (!ret)
		ports_info[port_id].isolated = set ? 1 : 0;
	return ret;
}

int
rte_vswitch_offload_flow_query(struct rte_vswitch_ctx *ctx,
			       uint16_t vport_id __rte_unused,
			       struct rte_vswitch_offload_flow *flow,
			       uint32_t flags,
			       struct rte_vswitch_flow_status *status)
{
	struct vswitch_group *gr, *mgr;
	int rc = 0;

	if (!ctx || !flow || !status)
		return -EINVAL;
	if (_vswitch_prepare_context(ctx))
		return -EINVAL;
	gr = _vswitch_get_group_by_id(ctx, flow->gr_id, flow->gr_ingress);
	mgr = flow->mgr_id == 0 ? NULL :
			_vswitch_get_group_by_id(ctx, flow->mgr_id, 0);
	if (flags & RTE_VSWITCH_QUERY_STATUS) {
		status->hw_valid = !!flow->flow && !gr->reseted;
		status->valid = status->hw_valid && gr->valid &&
				(!mgr || mgr->valid);
	}
	if (!status->hw_valid || (flags & ~RTE_VSWITCH_QUERY_STATUS) == 0)
		return 0;
	if (flags & (RTE_VSWITCH_QUERY_COUNTER_CACHE |
			     RTE_VSWITCH_QUERY_COUNTER)) {
		rc = aging_flow_query(_oflow_port(ctx, mgr, flow),
				      flow, &status->stats);
		if (rc == -EEXIST) {
			/* Flow aged out in aging thread. */
			status->valid = 0;
			status->hw_valid = !!flow->flow && !gr->reseted;
			return 0;
		}
	}
	if (!rc) {
		/*
		 * The requeierment is to count only the inner packet bytes
		 * without the ethernet header - adjust the HW counting.
		 */
		if (flow->type == VSWITCH_OFFLOAD_FLOW_TYPE_VF_TO_PF ||
		    flow->type == VSWITCH_OFFLOAD_FLOW_TYPE_VIRTIO_TO_PF)
			/*
			 * VM to PF: the bytes statistic includes the L3 encap
			 *  data - need to reduce it.
			 */
			status->stats.bytes -=
			   sizeof(struct rte_vswitch_flow_action_vxlan_encap) *
					status->stats.hits;
		else if (flow->type ==
			 VSWITCH_OFFLOAD_FLOW_TYPE_VIRTIO_TO_VIRTIO)
			/*
			 * VIRTIO to VIRTIO: the bytes statistic includes the
			 * L2 encap data - need to reduce encap data size +
			 * ethernet header size.
			 */
			status->stats.bytes -=
			  (sizeof(struct rte_vswitch_flow_action_vxlan_encap) +
			   sizeof(struct ether_hdr)) * status->stats.hits;
		else
			/*
			 * else: the bytes statistic includes the ethernet
			 * header data - need to reduce ethernet header size.
			 */
			status->stats.bytes -= sizeof(struct ether_hdr) *
							status->stats.hits;
	}
	return rc;
}

/**
 * prepare the vswitch's context.
 *
 * @param ctx
 *   Pointer to the rte_vswitch_ctx
 *
 * @return
 *   0 - success
 *   1 - fail
 */

static int
_vswitch_prepare_context(struct rte_vswitch_ctx *ctx)
{
	int i;
	struct vswitch_vport *vport = NULL;

	if (likely(!ctx->restarting))
		return 0;
	ctx->restarting = 0;
	for (i = 0; i <= ctx->max_vport_id; i++) {
		vport = &ctx->vports[i];
		if (!vport->valid)
			continue;
		if (_rte_vswitch_register_vport(ctx, vport->vport_id,
						vport->vport_dev)) {
			for (--i; i >= 0; i--) {
				_rte_vswitch_unregister_vport
					(ctx, ctx->vports[i].vport_id);
			}
			ctx->restarting = 1;
			RTE_LOG(ERR, VSWITCH,
				"Failed to prepare vswitch context\n");
			return -1;
		}
	}
	return 0;
}

static int
vswitch_on_flow_aged(struct rte_vswitch_ctx *ctx,
		     struct rte_vswitch_offload_flow *flow)
{
	struct rte_flow_error error = { .type = 0 };
	int ret;
	struct rte_flow *rte_flow = flow->flow;
	uint16_t port = _oflow_port(ctx, NULL, flow);

	if (!flow->flow)
		return 0;
	flow->flow = NULL;
	flow->counter_id = 0;
	ret = _rte_flow_destroy(port, rte_flow, &error);
	if (ret) {
		RTE_LOG(ERR, VSWITCH,
			"port: %hu failed to destroy aged flow %p counter id %d: %s\n",
			port, flow, flow->counter_id, error.message);
		return ret;
	}
	/* type of the flow is still valid */
	_rte_offload_flow_stats_age(ctx, flow->type);
	return 0;
}

int
vswitch_on_flows_aged(struct rte_vswitch_ctx *ctx,
		     struct rte_vswitch_offload_flow *flows[], int n)
{
	int i;

	if (!n)
		return 0;
	for (i = 0; i < n; ++i)
		vswitch_on_flow_aged(ctx, flows[i]);
	return 0;
}

void
rte_vswitch_dump(int clear)
{
	aging_dump(clear);
}

int
rte_vswitch_offload_flow_stats_query(struct rte_vswitch_ctx *ctx,
			struct rte_vswitch_offload_flow_stats *stats)
{
	if ((NULL == ctx) || (NULL == stats) ||
		(ctx->type >= RTE_VSWITCH_TYPE_UNKNOWN))
		return -EINVAL;

	/*
	 * The condition that number of destroyed flows larger than number of
	 * created flows will rarely happen, unsigned integer will take care of
	 * this. Numbers in the context can be used for debugging if needed.
	 */
	if (ctx->type == RTE_VSWITCH_TYPE_VIRTIO) {
		stats->n_rx_flows =
			ctx->ofstats.c_cnt[VSWITCH_OFFLOAD_FLOW_TYPE_PF_TO_VIRTIO] -
			ctx->ofstats.d_cnt[VSWITCH_OFFLOAD_FLOW_TYPE_PF_TO_VIRTIO] -
			ctx->ofstats.a_cnt[VSWITCH_OFFLOAD_FLOW_TYPE_PF_TO_VIRTIO];
		stats->n_tx_flows =
			ctx->ofstats.c_cnt[VSWITCH_OFFLOAD_FLOW_TYPE_VIRTIO_TO_PF] -
			ctx->ofstats.d_cnt[VSWITCH_OFFLOAD_FLOW_TYPE_VIRTIO_TO_PF] -
			ctx->ofstats.a_cnt[VSWITCH_OFFLOAD_FLOW_TYPE_VIRTIO_TO_PF];
		stats->n_nc_flows =
			ctx->ofstats.c_cnt[VSWITCH_OFFLOAD_FLOW_TYPE_VIRTIO_TO_VIRTIO] -
			ctx->ofstats.d_cnt[VSWITCH_OFFLOAD_FLOW_TYPE_VIRTIO_TO_VIRTIO] -
			ctx->ofstats.a_cnt[VSWITCH_OFFLOAD_FLOW_TYPE_VIRTIO_TO_VIRTIO];
	} else if (ctx->type == RTE_VSWITCH_TYPE_SRIOV) {
		stats->n_rx_flows =
			ctx->ofstats.c_cnt[VSWITCH_OFFLOAD_FLOW_TYPE_PF_TO_VF] -
			ctx->ofstats.d_cnt[VSWITCH_OFFLOAD_FLOW_TYPE_PF_TO_VF] -
			ctx->ofstats.a_cnt[VSWITCH_OFFLOAD_FLOW_TYPE_PF_TO_VF];
		stats->n_tx_flows =
			ctx->ofstats.c_cnt[VSWITCH_OFFLOAD_FLOW_TYPE_VF_TO_PF] -
			ctx->ofstats.d_cnt[VSWITCH_OFFLOAD_FLOW_TYPE_VF_TO_PF] -
			ctx->ofstats.a_cnt[VSWITCH_OFFLOAD_FLOW_TYPE_VF_TO_PF];
		stats->n_nc_flows =
			ctx->ofstats.c_cnt[VSWITCH_OFFLOAD_FLOW_TYPE_VF_TO_PF] -
			ctx->ofstats.d_cnt[VSWITCH_OFFLOAD_FLOW_TYPE_VF_TO_PF] -
			ctx->ofstats.a_cnt[VSWITCH_OFFLOAD_FLOW_TYPE_VF_TO_PF];
	}
	stats->n_flows = stats->n_rx_flows + stats->n_tx_flows + stats->n_nc_flows;

	return 0;
}

void
rte_vswitch_print_offload_flow_params(struct rte_vswitch_ctx *ctx,
			       uint16_t vport_id,
			       struct rte_vswitch_flow_keys *keys,
			       struct rte_vswitch_flow_actions *actions) {
	if (!ctx || !keys || !actions) {
		RTE_LOG(ERR, VSWITCH, "Invalid arguments\n");
		return;
	}
	if (_vswitch_prepare_context(ctx))
		return;
	printf("\nvswitch: vport ID %hu(%s) offload flow parameters:\n",
	       vport_id, ctx->pf_vport_id == vport_id ? "PF" : "VM");
	if (actions->encap) {
		uint32_t i;

		printf("\nuint8_t encap_data[] = {\n");
		for (i = 0; i < sizeof(*actions->encap); i++) {
			if ((i & 0xF) == 0) {
				printf("\n\t%02X", ((uint8_t *)(actions->encap))[i]);
			} else
				printf(",%02X", ((uint8_t *)(actions->encap))[i]);
		}
		printf("\n};\n");
	}
	if (actions->add_ethernet) {
		uint32_t i;

		printf("\nuint8_t eth_data[] = {");
		for (i = 0; i < sizeof(*actions->add_ethernet); i++) {
			if ((i & 0xF) == 0) {
				printf("\n\t%02X", ((uint8_t *)(actions->add_ethernet))[i]);
			} else
				printf(",%02X", ((uint8_t *)(actions->add_ethernet))[i]);
		}
		printf("\n};\n");
	}
	if (actions->modify) {
		printf("struct rte_vswitch_action_modify_packet modi = {\n"
		       "\t.set_src_mac = %u,\n"
		       "\t.set_dst_mac = %u,\n"
		       "\t.set_dst_ip4 = %u,\n"
		       "\t.set_src_ip4 = %u,\n"
		       "\t.set_dst_ip6 = %u,\n"
		       "\t.set_src_ip6 = %u,\n"
		       "\t.set_dst_port = %u,\n"
		       "\t.set_src_port = %u,\n"
		       "\t.set_ttl = %u,\n"
		       "\t.dec_ttl = %u,\n"
		       "\t.dec_tcp_seq = %u,\n"
		       "\t.dec_tcp_ack = %u,\n"
		       "\t.inc_tcp_seq = %u,\n"
		       "\t.inc_tcp_ack = %u,\n"
		       "\t.dst_mac = {.addr_bytes = {0x%02X, 0x%02X, 0x%02X,"
		       " 0x%02X, 0x%02X, 0x%02X},},\n"
		       "\t.src_mac = {.addr_bytes = {0x%02X, 0x%02X, 0x%02X,"
		       " 0x%02X, 0x%02X, 0x%02X},},\n"
		       "\t.dst_ip4 = 0x%08X,\n"
		       "\t.src_ip4 = 0x%08X,\n"
		       "\t.src_ip6 = {0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X,"
		       " 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X,"
		       " 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X},\n"
		       "\t.dst_ip6 = {0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X,"
		       " 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X,"
		       " 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X},\n"
		       "\t.src_port = %hu,\n"
		       "\t.dst_port = %hu,\n"
		       "\t.ttl = %u,\n"
		       "\t.tcp_seq = %08X,\n"
		       "\t.tcp_ack = %08X,\n};\n",
		       actions->modify->set_src_mac, actions->modify->set_dst_mac,
		       actions->modify->set_dst_ip4, actions->modify->set_src_ip4,
		       actions->modify->set_dst_ip6, actions->modify->set_src_ip6,
		       actions->modify->set_dst_port, actions->modify->set_src_port,
		       actions->modify->set_ttl, actions->modify->dec_ttl,
		       actions->modify->dec_tcp_seq, actions->modify->dec_tcp_ack,
		       actions->modify->inc_tcp_seq, actions->modify->inc_tcp_ack,
		       actions->modify->dst_mac.addr_bytes[0],
		       actions->modify->dst_mac.addr_bytes[1],
		       actions->modify->dst_mac.addr_bytes[2],
		       actions->modify->dst_mac.addr_bytes[3],
		       actions->modify->dst_mac.addr_bytes[4],
		       actions->modify->dst_mac.addr_bytes[5],
		       actions->modify->src_mac.addr_bytes[0],
		       actions->modify->src_mac.addr_bytes[1],
		       actions->modify->src_mac.addr_bytes[2],
		       actions->modify->src_mac.addr_bytes[3],
		       actions->modify->src_mac.addr_bytes[4],
		       actions->modify->src_mac.addr_bytes[5],
		       actions->modify->dst_ip4, actions->modify->src_ip4,
		       actions->modify->src_ip6[0],
		       actions->modify->src_ip6[1],
		       actions->modify->src_ip6[2],
		       actions->modify->src_ip6[3],
		       actions->modify->src_ip6[4],
		       actions->modify->src_ip6[5],
		       actions->modify->src_ip6[6],
		       actions->modify->src_ip6[7],
		       actions->modify->src_ip6[8],
		       actions->modify->src_ip6[9],
		       actions->modify->src_ip6[10],
		       actions->modify->src_ip6[11],
		       actions->modify->src_ip6[12],
		       actions->modify->src_ip6[13],
		       actions->modify->src_ip6[14],
		       actions->modify->src_ip6[15],
		       actions->modify->dst_ip6[0],
		       actions->modify->dst_ip6[1],
		       actions->modify->dst_ip6[2],
		       actions->modify->dst_ip6[3],
		       actions->modify->dst_ip6[4],
		       actions->modify->dst_ip6[5],
		       actions->modify->dst_ip6[6],
		       actions->modify->dst_ip6[7],
		       actions->modify->dst_ip6[8],
		       actions->modify->dst_ip6[9],
		       actions->modify->dst_ip6[10],
		       actions->modify->dst_ip6[11],
		       actions->modify->dst_ip6[12],
		       actions->modify->dst_ip6[13],
		       actions->modify->dst_ip6[14],
		       actions->modify->dst_ip6[15],
		       actions->modify->src_port, actions->modify->dst_port,
		       actions->modify->ttl, actions->modify->tcp_seq,
		       actions->modify->tcp_ack);
	}
	printf("struct rte_vswitch_flow_keys keys = {\n"
		"\t.outer = {\n"
		"\t\t.ip_type = %u,\n"
		"\t\t.src_addr_valid = %u,\n"
		"\t\t.dst_addr_valid = %u,\n"
		"\t\t.proto_valid = %u,\n"
		"\t\t.src_port_valid = %u,\n"
		"\t\t.dst_port_valid = %u,\n"
		"\t\t.tcp_flags_valid = {reserved=%u,urg=%u,ack=%u,psh=%u,"
		"rst=%u,syn=%u,fin=%u},\n"
		"\t\t.src_addr6 = {0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,"
		"0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,"
		"0x%02x,0x%02x},\n"
		"\t\t.dst_addr6 = {0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,"
		"0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,"
		"0x%02x,0x%02x},\n"
		"\t\t.proto = 0x%02X,\n"
		"\t\t.src_port = 0x%04X,\n"
		"\t\t.dst_port = 0x%04X,\n"
		"\t\t.tcp_flags = {reserved=%u,urg=%u,ack=%u,psh=%u,"
		"rst=%u,syn=%u,fin=%u},\n"
		"\t\t.icmp_type = %u,\n\t},\n"
		"\t.tunnel_type = %u,\n"
		"\t.flags_valid = %u,\n"
		"\t.protocol_valid = %u,\n"
		"\t.vni = 0x%06X,\n"
		"\t.flags = %u,\n"
		"\t.protocol = %u,\n"
		"\t.inner = {\n"
		"\t\t.ip_type = %u,\n"
		"\t\t.src_addr_valid = %u,\n"
		"\t\t.dst_addr_valid = %u,\n"
		"\t\t.proto_valid = %u,\n"
		"\t\t.src_port_valid = %u,\n"
		"\t\t.dst_port_valid = %u,\n"
		"\t\t.tcp_flags_valid = {reserved=%u,urg=%u,ack=%u,psh=%u,"
		"rst=%u,syn=%u,fin=%u},\n"
		"\t\t.src_addr6 = {0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,"
		"0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,"
		"0x%02x,0x%02x},\n"
		"\t\t.dst_addr6 = {0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,"
		"0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,"
		"0x%02x,0x%02x},\n"
		"\t\t.proto = 0x%02X,\n"
		"\t\t.src_port = 0x%04X,\n"
		"\t\t.dst_port = 0x%04X,\n"
		"\t\t.tcp_flags = {reserved=%u,urg=%u,ack=%u,psh=%u,"
		"rst=%u,syn=%u,fin=%u},\n"
		"\t\t.icmp_type = %u,\n\t},\n};\n"
		"struct rte_vswitch_flow_actions actions = {\n"
		"\t.vport_id = %hu,\n"
		"\t.count = %u,\n"
		"\t.meter = %u,\n"
		"\t.decap = %u,\n"
		"\t.remove_ethernet = %u,\n"
		"\t.timeout = %hu,\n"
		"\t.encap = %s,\n"
		"\t.add_ethernet = %s,\n"
		"\t.modify = %s,\n"
		"\t.meter_id = %u,\n};\n",
		keys->outer.ip_type, keys->outer.src_addr_valid,
		keys->outer.dst_addr_valid,
		keys->outer.proto_valid, keys->outer.src_port_valid,
		keys->outer.dst_port_valid,
		keys->outer.tcp_flags_valid.reserved,
		keys->outer.tcp_flags_valid.urg,
		keys->outer.tcp_flags_valid.ack,
		keys->outer.tcp_flags_valid.psh,
		keys->outer.tcp_flags_valid.rst,
		keys->outer.tcp_flags_valid.syn,
		keys->outer.tcp_flags_valid.fin,
		keys->outer.src_addr6[0],keys->outer.src_addr6[1],
		keys->outer.src_addr6[2],keys->outer.src_addr6[3],
		keys->outer.src_addr6[4],keys->outer.src_addr6[5],
		keys->outer.src_addr6[6],keys->outer.src_addr6[7],
		keys->outer.src_addr6[8],keys->outer.src_addr6[9],
		keys->outer.src_addr6[10],keys->outer.src_addr6[11],
		keys->outer.src_addr6[12],keys->outer.src_addr6[13],
		keys->outer.src_addr6[14],keys->outer.src_addr6[15],
		keys->outer.dst_addr6[0],keys->outer.dst_addr6[1],
		keys->outer.dst_addr6[2],keys->outer.dst_addr6[3],
		keys->outer.dst_addr6[4],keys->outer.dst_addr6[5],
		keys->outer.dst_addr6[6],keys->outer.dst_addr6[7],
		keys->outer.dst_addr6[8],keys->outer.dst_addr6[9],
		keys->outer.dst_addr6[10],keys->outer.dst_addr6[11],
		keys->outer.dst_addr6[12],keys->outer.dst_addr6[13],
		keys->outer.dst_addr6[14],keys->outer.dst_addr6[15],
		keys->outer.proto, keys->outer.src_port, keys->outer.dst_port,
		keys->outer.tcp_flags.reserved, keys->outer.tcp_flags.urg,
		keys->outer.tcp_flags.ack, keys->outer.tcp_flags.psh,
		keys->outer.tcp_flags.rst, keys->outer.tcp_flags.syn,
		keys->outer.tcp_flags.fin, keys->outer.icmp_type,
		keys->tunnel_type, keys->flags_valid, keys->protocol_valid,
		keys->vni, keys->flags, keys->protocol, keys->inner.ip_type,
		keys->inner.src_addr_valid, keys->inner.dst_addr_valid,
		keys->inner.proto_valid, keys->inner.src_port_valid,
		keys->inner.dst_port_valid,
		keys->inner.tcp_flags_valid.reserved,
		keys->inner.tcp_flags_valid.urg,
		keys->inner.tcp_flags_valid.ack,
		keys->inner.tcp_flags_valid.psh,
		keys->inner.tcp_flags_valid.rst,
		keys->inner.tcp_flags_valid.syn,
		keys->inner.tcp_flags_valid.fin,
		keys->inner.src_addr6[0],keys->inner.src_addr6[1],
		keys->inner.src_addr6[2],keys->inner.src_addr6[3],
		keys->inner.src_addr6[4],keys->inner.src_addr6[5],
		keys->inner.src_addr6[6],keys->inner.src_addr6[7],
		keys->inner.src_addr6[8],keys->inner.src_addr6[9],
		keys->inner.src_addr6[10],keys->inner.src_addr6[11],
		keys->inner.src_addr6[12],keys->inner.src_addr6[13],
		keys->inner.src_addr6[14],keys->inner.src_addr6[15],
		keys->inner.dst_addr6[0],keys->inner.dst_addr6[1],
		keys->inner.dst_addr6[2],keys->inner.dst_addr6[3],
		keys->inner.dst_addr6[4],keys->inner.dst_addr6[5],
		keys->inner.dst_addr6[6],keys->inner.dst_addr6[7],
		keys->inner.dst_addr6[8],keys->inner.dst_addr6[9],
		keys->inner.dst_addr6[10],keys->inner.dst_addr6[11],
		keys->inner.dst_addr6[12],keys->inner.dst_addr6[13],
		keys->inner.dst_addr6[14],keys->inner.dst_addr6[15],
		keys->inner.proto, keys->inner.src_port, keys->inner.dst_port,
		keys->inner.tcp_flags.reserved, keys->inner.tcp_flags.urg,
		keys->inner.tcp_flags.ack, keys->inner.tcp_flags.psh,
		keys->inner.tcp_flags.rst, keys->inner.tcp_flags.syn,
		keys->inner.tcp_flags.fin, keys->inner.icmp_type,
		actions->vport_id, actions->count, actions->meter,
		actions->decap, actions->remove_ethernet, actions->timeout,
		actions->encap ? "encap_data" : "NULL" ,
		actions->add_ethernet ? "eth_data" : "NULL",
		actions->modify ? "&modi" : "NULL", actions->meter_id
	);
}
