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

#ifndef RTE_VSWITCH_SDK_H_
#define RTE_VSWITCH_SDK_H_

#include <pthread.h>

#include <rte_spinlock.h>
#include <rte_mtr.h>
#include <rte_hlist.h>
#include "rte_qpool.h"

#define RTE_VSWITCH_MAX_METER_NUM 4096

#define PERF_START() \
	uint64_t perf_end, perf_start = rte_rdtsc()

#define PERF_ADD(sum) \
	do {							\
		perf_end = rte_rdtsc();				\
		sum += (perf_end - perf_start);			\
		perf_start = perf_end;				\
	} while (0)

#define PERF_DIFF_MS(perf_start) \
	((rte_rdtsc() - perf_start) * 1000 / rte_get_tsc_hz())

enum vswitch_offload_flow_type {
	VSWITCH_OFFLOAD_FLOW_TYPE_PF_TO_VIRTIO,
	VSWITCH_OFFLOAD_FLOW_TYPE_VIRTIO_TO_PF,
	VSWITCH_OFFLOAD_FLOW_TYPE_VIRTIO_TO_VIRTIO,
	VSWITCH_OFFLOAD_FLOW_TYPE_PF_TO_VF,
	VSWITCH_OFFLOAD_FLOW_TYPE_VF_TO_PF,
	VSWITCH_OFFLOAD_FLOW_TYPE_VF_TO_VF,
	VSWITCH_OFFLOAD_FLOW_TYPE_MAX,
};

extern pthread_mutex_t *vswitch_lock;

struct vswitch_dispatch_flow_key {
	uint32_t vni : 24;
	uint32_t ipv : 1;
	uint32_t vxlan_type : 4;
	uint32_t pad: 3;
	union {
		uint32_t ipv4_addr;
		uint8_t ipv6_addr[16];
	};
};

struct vswitch_dispatch_flow_data {
	struct rte_flow *dflow;
	uint16_t port_id;
	LIST_ENTRY(vswitch_dispatch_flow_data) plink;
	struct rte_hlist_data_element *p_de;
};

struct vswitch_group_pool {
	TAILQ_HEAD(free_group, vswitch_group) groups;
};

LIST_HEAD(vswitch_dispatch_flow_data_head, vswitch_dispatch_flow_data);

struct vswitch_group {
	TAILQ_ENTRY(vswitch_group) next;
	uint8_t valid : 1;
	uint8_t reseted : 1;
	uint16_t group_id;
	uint16_t ethdev_port_id;
	uint32_t mcounter; /* metadata counter */
	struct vswitch_group_pool *pool;
	struct rte_hlist_table *hl;
	LIST_HEAD(flow, rte_vswitch_offload_flow) oflows;
	struct rte_flow *eflow;
	struct vswitch_dispatch_flow_data_head *firsts;
};

struct vswitch_vport {
	uint8_t valid : 1;
	uint8_t flush_bit : 1;
	uint16_t vport_id;
	struct rte_eth_dev *vport_dev;
	struct vswitch_group *igroup;
	struct vswitch_group *egroup;
	union {
		struct rte_flow *lb_flow;
		struct rte_flow *pf_disp_flow;
	};
	struct rte_flow *eflowi;
	struct rte_flow *eflowe;
	struct rte_flow *eflowg1;
	struct rte_flow *eflowg2;
};

struct rte_vswitch_meter {
	uint8_t valid;
	uint32_t meter_id;
	uint32_t profile_id;
	uint64_t bps;
};

/* No atomic operation is needed, each thread will change different members */
struct rte_vswitch_offload_flow_counts {
	uint64_t c_cnt[VSWITCH_OFFLOAD_FLOW_TYPE_MAX];	/* created flows number */
	uint64_t d_cnt[VSWITCH_OFFLOAD_FLOW_TYPE_MAX];	/* destroyed flows number */
	uint64_t a_cnt[VSWITCH_OFFLOAD_FLOW_TYPE_MAX];	/* aged flows number */
};

struct rte_vswitch_ctx {
	enum rte_vswitch_type type;
	uint16_t max_vport_id;
	uint16_t pf_vport_id;
	uint8_t restarting : 1;
	struct rte_eth_dev *pf;
	struct vswitch_group_pool ipool;
	struct vswitch_group_pool epool;
	TAILQ_HEAD(invalid_group, vswitch_group) invalid_groups;
	struct rte_vswitch_meter vmeters[RTE_VSWITCH_MAX_METER_NUM];
	struct rte_vswitch_offload_flow_counts ofstats;
	struct vswitch_vport vports[];
};

struct rte_vswitch_offload_flow {
	LIST_ENTRY(rte_vswitch_offload_flow) next;
	uint32_t type : 3;
	uint32_t gr_ingress:1;
	uint32_t gr_id : 11;
	uint32_t mgr_id : 11;
	int counter_id;
	struct rte_flow *flow;
};

void port_lock(uint16_t port);
void port_unlock(uint16_t port);

/************* Aging **************/

int aging_init(void);
void aging_close(void);
void aging_reset(int port);
int aging_register_port(uint32_t index, uint16_t dev_id,
			struct rte_vswitch_ctx *dev);
int aging_on_flow_create(uint16_t port_id,
			 struct rte_vswitch_offload_flow *flow,
			 uint16_t ttl, int counter_id);
int aging_on_flow_destroy(uint16_t port_id,
			  struct rte_vswitch_offload_flow *flow,
			  int counter_id);
void *aging_counter_alloc(uint16_t port_id, uint32_t *counter_id,
			  struct rte_flow_count_value *bias);
int aging_counter_free(uint16_t port_id, int counter_id);

void aging_dump(int clear);
int aging_flow_query(uint16_t port_id, struct rte_vswitch_offload_flow *flow,
		     struct rte_flow_count_value *status);
int vswitch_on_flows_aged(struct rte_vswitch_ctx *ctx,
			  struct rte_vswitch_offload_flow *flows[], int n);
int aging_flow_modify(uint16_t port_id, struct rte_vswitch_offload_flow *flow,
		      uint16_t timeout);

/*
 * Simulate new flows for pressure test.
 */
void rte_vswitch_aging_pressure(struct rte_vswitch_ctx *ctx, uint16_t vport,
				int mode, int count, uint16_t timeout);

/*
 * Dump and clear vswitch statistics.
 *
 * @param clear
 *   Clear statistics if non-zero.
 */
void
rte_vswitch_dump(int clear);

/* RTE api wrappers with lock protection. */

static inline struct rte_flow *
_rte_flow_create(uint16_t port_id,
		 const struct rte_flow_attr *attr,
		 const struct rte_flow_item pattern[],
		 const struct rte_flow_action actions[],
		 struct rte_flow_error *error)
{
	struct rte_flow *flow;

	port_lock(port_id);
	flow = rte_flow_create(port_id, attr, pattern, actions, error);
	port_unlock(port_id);
	return flow;
}

static inline int
_rte_flow_destroy(uint16_t port_id,
		  struct rte_flow *flow,
		  struct rte_flow_error *error)
{
	int ret;

	port_lock(port_id);
	ret = rte_flow_destroy(port_id, flow, error);
	port_unlock(port_id);
	return ret;
}

static inline int
_rte_flow_sync(uint16_t port_id,
	       struct rte_flow_error *error)
{
	int ret;

	port_lock(port_id);
	ret = rte_flow_sync(port_id, error);
	port_unlock(port_id);
	return ret;
}

static inline int
_rte_flow_query(uint16_t port_id,
		struct rte_flow *flow,
		enum rte_flow_action_type action,
		void *data,
		struct rte_flow_error *error)
{
	int ret;

	port_lock(port_id);
	ret = rte_flow_query(port_id, flow, action, data, error);
	port_unlock(port_id);
	return ret;
}

static inline void *
_rte_flow_counter_alloc(uint16_t port_id, uint32_t *start_index,
			uint32_t *blk_sz, struct rte_flow_error *error)
{
	void *handle;

	port_lock(port_id);
	handle = rte_flow_counter_alloc(port_id, start_index, blk_sz, error);
	port_unlock(port_id);
	return handle;
}

static inline int
_rte_flow_counter_free(uint16_t port_id,
		       void *handle,
		       struct rte_flow_error *error)
{
	int ret;

	port_lock(port_id);
	ret = rte_flow_counter_free(port_id, handle, error);
	port_unlock(port_id);
	return ret;
}

static inline int
_rte_flow_counter_query(uint16_t port_id,
		       int counter_id,
		       void *counter_handle,
		       int count,
		       struct rte_flow_count_value *buf,
		       int buf_count,
		       rte_flow_cb_fn cb,
		       void *cb_arg,
		       struct rte_flow_error *error)
{
	int ret;

	port_lock(port_id);
	ret = rte_flow_counter_query(port_id, counter_id, counter_handle, count,
				     buf, buf_count, cb, cb_arg, error);
	port_unlock(port_id);
	return ret;
}

static inline int
_rte_mtr_meter_profile_add(uint16_t port_id,
			   uint32_t meter_profile_id,
			   struct rte_mtr_meter_profile *profile,
			   struct rte_mtr_error *error)
{
	int ret;

	port_lock(port_id);
	ret = rte_mtr_meter_profile_add(port_id, meter_profile_id, profile,
					error);
	port_unlock(port_id);
	return ret;
}

int
rte_mtr_meter_profile_update(uint16_t port_id,
	uint32_t mtr_id,
	uint32_t meter_profile_id,
	struct rte_mtr_error *error);

static inline int
_rte_mtr_meter_profile_update(uint16_t port_id,
			      uint32_t mtr_id,
			      uint32_t meter_profile_id,
			      struct rte_mtr_error *error)
{
	int ret;

	port_lock(port_id);
	ret = rte_mtr_meter_profile_update(port_id, mtr_id, meter_profile_id,
					   error);
	port_unlock(port_id);
	return ret;
}

static inline int
_rte_mtr_meter_profile_delete(uint16_t port_id,
			      uint32_t meter_profile_id,
			      struct rte_mtr_error *error)
{
	int ret;

	port_lock(port_id);
	ret = rte_mtr_meter_profile_delete(port_id, meter_profile_id, error);
	port_unlock(port_id);
	return ret;
}

static inline int
_rte_mtr_create(uint16_t port_id,
		uint32_t mtr_id,
		struct rte_mtr_params *params,
		int shared,
		struct rte_mtr_error *error)
{
	int ret;

	port_lock(port_id);
	ret = rte_mtr_create(port_id, mtr_id, params, shared, error);
	port_unlock(port_id);
	return ret;
}

static inline int
_rte_mtr_destroy(uint16_t port_id,
		 uint32_t mtr_id,
		 struct rte_mtr_error *error)
{
	int ret;

	port_lock(port_id);
	ret = rte_mtr_destroy(port_id, mtr_id, error);
	port_unlock(port_id);
	return ret;
}

static inline int
_rte_mtr_stats_read(uint16_t port_id,
		    uint32_t mtr_id,
		    struct rte_mtr_stats *stats,
		    uint64_t *stats_mask,
		    int clear,
		    struct rte_mtr_error *error)
{
	int ret;

	port_lock(port_id);
	ret = rte_mtr_stats_read(port_id, mtr_id, stats, stats_mask, clear,
				 error);
	port_unlock(port_id);
	return ret;
}

static inline int
_rte_mtr_enable(uint16_t port_id,
		 uint32_t mtr_id,
		 struct rte_mtr_error *error)
{
	int ret;

	port_lock(port_id);
	ret = rte_mtr_meter_enable(port_id, mtr_id, error);
	port_unlock(port_id);
	return ret;
}

static inline int
_rte_mtr_disable(uint16_t port_id,
		 uint32_t mtr_id,
		 struct rte_mtr_error *error)
{
	int ret;

	port_lock(port_id);
	ret = rte_mtr_meter_disable(port_id, mtr_id, error);
	port_unlock(port_id);
	return ret;
}

static inline void
_rte_offload_flow_stats_inc(struct rte_vswitch_ctx *ctx,
		enum vswitch_offload_flow_type type)
{
	RTE_ASSERT(ctx != NULL);
	RTE_ASSERT(type < VSWITCH_OFFLOAD_FLOW_TYPE_MAX);
	ctx->ofstats.c_cnt[type]++;
}

static inline void
_rte_offload_flow_stats_dec(struct rte_vswitch_ctx *ctx,
		enum vswitch_offload_flow_type type)
{
	RTE_ASSERT(ctx != NULL);
	RTE_ASSERT(type < VSWITCH_OFFLOAD_FLOW_TYPE_MAX);
	ctx->ofstats.d_cnt[type]++;
}

static inline void
_rte_offload_flow_stats_age(struct rte_vswitch_ctx *ctx,
		enum vswitch_offload_flow_type type)
{
	RTE_ASSERT(ctx != NULL);
	RTE_ASSERT(type < VSWITCH_OFFLOAD_FLOW_TYPE_MAX);
	ctx->ofstats.a_cnt[type]++;
}

#endif /* RTE_VSWITCH_SDK_H_ */
