// SPDX-License-Identifier: BSD-3-Clause
/* Copyright 2018 Mellanox Technologies, Ltd */

#include <rte_flow_driver.h>
#include <rte_malloc.h>

#include "mlx5.h"
#include "mlx5_prm.h"
#include "mlx5_flow.h"
#include "mlx5_devx_cmds.h"
#include "mlx5_flow.h"
#include "mlx5_glue.h"

/*
 * Dummy struct to prevent compilation errors when
 * mlx5dv_devx_obj is not defined in mlx5dv.h
 */
//#ifndef HAVE_IBV_DEVX_OBJ
struct mlx5dv_devx_obj {
	struct ibv_context *context;
	uint32_t handle;
	uint32_t tbl_id;
	uint32_t ctr_id;
};
//#endif /* HAVE_IBV_DEVX_OBJ */

int mlx5_devx_cmd_fc_alloc(struct ibv_context *ctx,
			   struct mlx5_devx_counter_set *dcs,
			   uint8_t bulk_sz)
{
#if defined(HAVE_IBV_FLOW_DEVX_COUNTERS) && defined(HAVE_IBV_DEVX_OBJ)
	uint32_t in[MLX5_ST_SZ_DW(alloc_flow_counter_in)]   = {0};
	uint32_t out[MLX5_ST_SZ_DW(alloc_flow_counter_out)] = {0};
	int status, syndrome;

	MLX5_SET(alloc_flow_counter_in, in, opcode,
		 MLX5_CMD_OP_ALLOC_FLOW_COUNTER);
	MLX5_SET(alloc_flow_counter_in, in, flow_counter_bulk, bulk_sz);
	dcs->obj = mlx5dv_devx_obj_create(ctx,
					  in, sizeof(in), out, sizeof(out));
	if (!dcs->obj)
		return -errno;
	status = MLX5_GET(query_flow_counter_out, out, status);
	syndrome = MLX5_GET(query_flow_counter_out, out, syndrome);
	if (status) {
		DRV_LOG(DEBUG, "Failed to create devx counters, "
			"status %x, syndrome %x", status, syndrome);
		return -1;
	}
	dcs->id = MLX5_GET(alloc_flow_counter_out,
			   out, flow_counter_id);
	//dcs->obj->ctr_id = dcs->id;
	//ooOri this struct is defined above should be defined in mlx5dv
	return 0;
#else
	(void)ctx;
	(void)dcs;
	return -ENOTSUP;
#endif /* HAVE_IBV_FLOW_DEVX_COUNTERS && HAVE_IBV_DEVX_OBJ */
}

int mlx5_devx_cmd_fc_free(struct mlx5dv_devx_obj *obj)
{
#if defined(HAVE_IBV_FLOW_DEVX_COUNTERS) && defined(HAVE_IBV_DEVX_OBJ)
	return mlx5dv_devx_obj_destroy(obj);
#else
	(void)obj;
	return -ENOTSUP;
#endif /* HAVE_IBV_FLOW_DEVX_COUNTERS && HAVE_IBV_DEVX_OBJ */
}

struct mlx5_devx_cmd_fc_query_cb_arg {
	int counter_id;
	uint32_t *out;
	uint32_t batch;
	struct rte_flow_count_value *addr;
	void *ext_arg;
};

static int
mlx5_devx_cmd_fc_query_resolve(int counter_id __rte_unused,
			       uint32_t *out __rte_unused,
			       uint64_t *pkts __rte_unused,
			       uint64_t *bytes __rte_unused,
			       uint32_t batch __rte_unused,
			       struct rte_flow_count_value *addr __rte_unused)
{
#if defined(HAVE_IBV_FLOW_DEVX_COUNTERS) && defined(HAVE_IBV_DEVX_OBJ)
	void *stats;
	int status, syndrome;
	int rc = 0;

	status = MLX5_GET(query_flow_counter_out, out, status);
	syndrome = MLX5_GET(query_flow_counter_out, out, syndrome);
	if (status) {
		DRV_LOG(ERR, "Failed to query devx counters, "
			"id %d, status %x, syndrome = %x",
			counter_id, status, syndrome);
		rc = -1;
	} else if (!batch) {
		stats = MLX5_ADDR_OF(query_flow_counter_out,
				     out, flow_statistics);
		*pkts = MLX5_GET64(traffic_counter, stats, packets);
		*bytes = MLX5_GET64(traffic_counter, stats, octets);
	}
	return rc;
#else
	return -ENOTSUP;
#endif /* HAVE_IBV_FLOW_DEVX_COUNTERS && HAVE_IBV_DEVX_OBJ */
}

void
mlx5_devx_cmd_fc_query_callback(int ret, int syndrome, void *cb_arg)
{
	struct mlx5_devx_cmd_fc_query_cb_arg *arg = cb_arg;
	void *ext_arg = arg->ext_arg;

	RTE_ASSERT(arg);
	if (ret)
		DRV_LOG(ERR, "Failed to query devx counters, "
			"id %d, count %u, addr: %p, status: %d, syndrome: %d",
			arg->counter_id, arg->batch, (void *)arg->addr,
			ret, syndrome);
	free(arg);
	mlx5_flow_batch_async_callback(ret, ext_arg);
}

int
mlx5_devx_cmd_fc_query(struct mlx5_devx_counter_set *dcs __rte_unused,
		       int clear,
		       uint64_t *pkts __rte_unused,
		       uint64_t *bytes __rte_unused,
		       uint32_t batch __rte_unused,
		       uint32_t mkey __rte_unused,
		       struct rte_flow_count_value *addr __rte_unused,
		       void *ext_arg __rte_unused,
		       void *cmd_comp __rte_unused)
{
#if defined(HAVE_IBV_FLOW_DEVX_COUNTERS) && defined(HAVE_IBV_DEVX_OBJ)
	uint32_t in[MLX5_ST_SZ_DW(query_flow_counter_in)] = {0};
	int rc;
	int out_len = MLX5_ST_SZ_BYTES(query_flow_counter_out) +
		      MLX5_ST_SZ_BYTES(traffic_counter);
	uint32_t out[out_len];
	struct mlx5_devx_cmd_fc_query_cb_arg *arg = NULL;

	memset(out, 0, sizeof(out));
	MLX5_SET(query_flow_counter_in, in, opcode,
		 MLX5_CMD_OP_QUERY_FLOW_COUNTER);
	MLX5_SET(query_flow_counter_in, in, op_mod, 0);
	MLX5_SET(query_flow_counter_in, in, flow_counter_id, dcs->id);
	MLX5_SET(query_flow_counter_in, in, clear, !!clear);
	if (batch) {
		assert((batch % 4) == 0);
		assert((dcs->id % 4) == 0);
		assert(addr);
		MLX5_SET(query_flow_counter_in, in, flow_counter_id, dcs->id);
		MLX5_SET(query_flow_counter_in, in, num_of_counters, batch);
		MLX5_SET(query_flow_counter_in, in, dump_to_memory, 1);
		MLX5_SET(query_flow_counter_in, in, mkey, mkey);
		MLX5_SET64(query_flow_counter_in, in, address,
			   (uint64_t)(void *)addr);
	}
	if (ext_arg) {
		/* Supposed to be released in interrupt thread,
		 * can't use rte_malloc as it uses spin lock.
		 */
		arg = calloc(1, sizeof(*arg));
		if (!arg)
			return -ENOMEM;
		arg->addr = addr;
		arg->batch = batch;
		arg->counter_id = dcs->id;
		arg->ext_arg = ext_arg;
		arg->out = out;
#ifndef MLX5_NO_ASYNC
#ifdef HAVE_MLX5_DEVX_ASYNC_SUPPORT
		rc = mlx5dv_devx_obj_query_async(dcs->obj, in, sizeof(in),
						 out_len, (uint64_t)arg,
						 cmd_comp); 
#else
		rc = mlx5dv_devx_obj_query_async(dcs->obj, in, sizeof(in),
						 out, out_len, (uint64_t)arg);
#endif
		if (rc)
			free(arg);
		return rc;
#else
		rc = mlx5dv_devx_obj_query(dcs->obj, in, sizeof(in), out,
					   out_len);
		mlx5_devx_cmd_fc_query_callback(rc, arg);
		return 0;
#endif
	} else {
		rc = mlx5dv_devx_obj_query(dcs->obj, in, sizeof(in), out,
					   out_len);
		if (rc)
			return rc;
		return mlx5_devx_cmd_fc_query_resolve(dcs->id, out, pkts,
						      bytes, batch, addr);
	}
#else
	return -ENOTSUP;
#endif /* HAVE_IBV_FLOW_DEVX_COUNTERS && HAVE_IBV_DEVX_OBJ */
}

struct mlx5_devx_mkey *mlx5_create_mkey(struct ibv_context *ctx,
					struct mlx5_devx_mkey_attr *mkey_attr)
{
	uint32_t in[MLX5_ST_SZ_DW(create_mkey_in)] = {0};
	uint32_t out[MLX5_ST_SZ_DW(create_mkey_out)] = {0};
	uint32_t status;
	void * mkc;
	struct mlx5_devx_mkey *mkey = NULL;

	mkey = rte_zmalloc("mkey", sizeof(*mkey), 64);

	MLX5_SET(create_mkey_in, in, opcode, MLX5_CMD_OP_CREATE_MKEY);

	mkc = MLX5_ADDR_OF(create_mkey_in, in, memory_key_mkey_entry);
	MLX5_SET(mkc, mkc, lw, 0x1);
	MLX5_SET(mkc, mkc, lr, 0x1);
	MLX5_SET(mkc, mkc, rw, 0x1);
	MLX5_SET(mkc, mkc, rr, 0x1);
	MLX5_SET(mkc, mkc, access_mode_1_0, MLX5_MKC_ACCESS_MODE_MTT);
	MLX5_SET(mkc, mkc, qpn, 0xffffff);
	MLX5_SET(mkc, mkc, length64, 0x0);
	MLX5_SET(mkc, mkc, pd, mkey_attr->pd);
	MLX5_SET(mkc, mkc, mkey_7_0, 0x50);//FIXME: should be dynamic
	MLX5_SET(mkc, mkc, translations_octword_size, (((mkey_attr->size + 4095) / 4096)+1)/2);
	MLX5_SET(create_mkey_in, in, translations_octword_actual_size, (((mkey_attr->size + 4095) / 4096)+1)/2);
	MLX5_SET(create_mkey_in, in, pg_access, 1);

#if 1
	//MLX5_SET(mkc, mkc, pas_umem_id, mkey_attr->pas_id);
	MLX5_SET64(mkc, mkc, start_addr,mkey_attr->addr);
	MLX5_SET64(mkc, mkc, len, mkey_attr->size);
	MLX5_SET(mkc, mkc, log_page_size, 12);

	MLX5_SET(create_mkey_in, in, mkey_umem_id, mkey_attr->pas_id);
#else
	struct devx_obj_handle *mem;
	uint32_t mem_id;
	void *buff;
	buff = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
	mem = devx_umem_reg(priv->ctx, buff, 0x1000, 7, &mem_id);
	printf("%s:%d %p %d %d\n", __func__, __LINE__, mem, errno, mem_id);
	MLX5_SET64(mkc, mkc, start_addr,(intptr_t) buff);
	MLX5_SET64(mkc, mkc, len, 0x1000);
	MLX5_SET(mkc, mkc, log_page_size, log2(0x1000));
	MLX5_SET(mkc, mkc, pas_umem_id, mem_id);
#endif

	mkey->obj = mlx5dv_devx_obj_create(ctx, in, sizeof(in), out,
					   sizeof(out));

	if(!mkey->obj) {
		printf("Can't create mkey error %d\n", errno);
		return NULL;
	}
	status = MLX5_GET(create_mkey_out, out, status);
	mkey->key = MLX5_GET(create_mkey_out, out, mkey_index);
	mkey->key = (mkey->key<<8) | 0x50;
	//printf("create mkey status %d mkey value %d\n",status, (mkey->key << 8) | 0x50 );
	if(status)
		return NULL;



	return mkey;
}

int
mlx5_devx_cmd_query_hca_attr(struct ibv_context *ctx,
			     struct mlx5_hca_attr *attr)
{
	uint32_t in[MLX5_ST_SZ_DW(query_hca_cap_in)] = {0};
	uint32_t out[MLX5_ST_SZ_DW(query_hca_cap_out)] = {0};
	void *hcattr;
	int status, syndrome, rc;

	MLX5_SET(query_hca_cap_in, in, opcode, MLX5_CMD_OP_QUERY_HCA_CAP);
	MLX5_SET(query_hca_cap_in, in, op_mod,
		 MLX5_GET_HCA_CAP_OP_MOD_GENERAL_DEVICE |
		 MLX5_HCA_CAP_OPMOD_GET_CUR);

	rc = mlx5_glue->devx_general_cmd(ctx,
					 in, sizeof(in), out, sizeof(out));
	if (rc)
		return rc;
	status = MLX5_GET(query_hca_cap_out, out, status);
	syndrome = MLX5_GET(query_hca_cap_out, out, syndrome);
	if (status) {
		DRV_LOG(DEBUG, "Failed to query devx HCA capabilities, "
			"status %x, syndrome = %x",
			status, syndrome);
		return -1;
	}
	hcattr = MLX5_ADDR_OF(query_hca_cap_out, out, capability);
	attr->flow_counter_bulk_alloc_bitmap =
			MLX5_GET(cmd_hca_cap, hcattr, flow_counter_bulk_alloc);
	attr->eswitch_manager = MLX5_GET(cmd_hca_cap, hcattr, eswitch_manager);
	attr->qos.sup = MLX5_GET(cmd_hca_cap, hcattr, qos);
	if (attr->qos.sup) {
		MLX5_SET(query_hca_cap_in, in, op_mod,
			 MLX5_GET_HCA_CAP_OP_MOD_QOS_CAP |
			 MLX5_HCA_CAP_OPMOD_GET_CUR);
		rc = mlx5_glue->devx_general_cmd
					(ctx,
					 in, sizeof(in), out, sizeof(out));
		if (rc)
			return rc;
		if (status) {
			DRV_LOG(DEBUG, "Failed to query devx QOS capabilities,"
				" status %x, syndrome = %x",
				status, syndrome);
			return -1;
		}
		hcattr = MLX5_ADDR_OF(query_hca_cap_out, out, capability);
		attr->qos.srtcm_sup =
				MLX5_GET(qos_cap, hcattr, flow_meter_srtcm);
		attr->qos.log_max_flow_meter =
				MLX5_GET(qos_cap, hcattr, log_max_flow_meter);
		attr->qos.flow_meter_reg_c_ids =
			MLX5_GET(qos_cap, hcattr, flow_meter_reg_id);
	}
	return 0;
}

void
mlx5_devx_cmd_flow_meter_fill_params(struct ibv_context *ctx __rte_unused,
				     struct mlx5_flow_meter *fm)
{
	void *attr = fm->mfts->fmp;
	struct mlx5_flow_meter_srtcm_rfc2697_prm *srtcm =
						     &fm->profile->srtcm_prm;

	fm->mfts->fmp_size = MLX5_ST_SZ_DB(flow_meter_parameters);
	memset(attr, 0, fm->mfts->fmp_size);
	MLX5_SET(flow_meter_parameters, attr, valid, 1);
	MLX5_SET(flow_meter_parameters, attr, bucket_overflow, 1);
	MLX5_SET(flow_meter_parameters, attr,
		 start_color, MLX5_FLOW_COLOR_GREEN);
	MLX5_SET(flow_meter_parameters, attr, both_buckets_on_green, 0);
	MLX5_SET(flow_meter_parameters,
		 attr, cbs_exponent, srtcm->cbs_exponent);
	MLX5_SET(flow_meter_parameters,
		 attr, cbs_mantissa, srtcm->cbs_mantissa);
	MLX5_SET(flow_meter_parameters,
		 attr, cir_exponent, srtcm->cir_exponent);
	MLX5_SET(flow_meter_parameters,
		 attr, cir_mantissa, srtcm->cir_mantissa);
	MLX5_SET(flow_meter_parameters,
		 attr, ebs_exponent, srtcm->ebs_exponent);
	MLX5_SET(flow_meter_parameters,
		 attr, ebs_mantissa, srtcm->ebs_mantissa);
}

int
mlx5_devx_cmd_flow_meter_modify(struct mlx5_flow_meter *fm,
		struct mlx5_flow_meter_srtcm_rfc2697_prm *srtcm, /* New value */
		uint64_t modify_bits, uint32_t active_state)
{
#ifdef HAVE_MLX5_DR_CREATE_ACTION_FLOW_METER
	uint32_t in[MLX5_ST_SZ_DW(flow_meter_parameters)] = { 0 };
	uint32_t *attr;
	struct mlx5dv_dr_flow_meter_attr mod_attr = { 0 };
	int ret;

	/* Fill command parameters */
	mod_attr.reg_c_index = fm->metadata_reg_c_idx;
	mod_attr.flow_meter_parameter = in;
	mod_attr.flow_meter_parameter_sz = fm->mfts->fmp_size;
	if (modify_bits & MLX5_FLOW_METER_OBJ_MODIFY_FIELD_ACTIVE)
		mod_attr.active = !!active_state;
	else
		mod_attr.active = 0;
	attr = in;
	if (modify_bits & MLX5_FLOW_METER_OBJ_MODIFY_FIELD_CBS) {
		MLX5_SET(flow_meter_parameters,
			 attr, cbs_exponent, srtcm->cbs_exponent);
		MLX5_SET(flow_meter_parameters,
			 attr, cbs_mantissa, srtcm->cbs_mantissa);
	}
	if (modify_bits & MLX5_FLOW_METER_OBJ_MODIFY_FIELD_CIR) {
		MLX5_SET(flow_meter_parameters,
			 attr, cir_exponent, srtcm->cir_exponent);
		MLX5_SET(flow_meter_parameters,
			 attr, cir_mantissa, srtcm->cir_mantissa);
	}
	if (modify_bits & MLX5_FLOW_METER_OBJ_MODIFY_FIELD_EBS) {
		MLX5_SET(flow_meter_parameters,
			 attr, ebs_exponent, srtcm->ebs_exponent);
		MLX5_SET(flow_meter_parameters,
			 attr, ebs_mantissa, srtcm->ebs_mantissa);
	}
	/* Apply modifications to meter only if it was created */
	if (fm->mfts->meter_action) {
		ret = mlx5dv_dr_action_modify_flow_meter
						(fm->mfts->meter_action,
						 &mod_attr, modify_bits);
		if (ret)
			return ret;
	}
	/* Update succeedded modify meter  parameters */
	if (modify_bits & MLX5_FLOW_METER_OBJ_MODIFY_FIELD_ACTIVE)
		fm->active_state = !!active_state;
	attr = fm->mfts->fmp;
	if (modify_bits & MLX5_FLOW_METER_OBJ_MODIFY_FIELD_CBS) {
		MLX5_SET(flow_meter_parameters,
			 attr, cbs_exponent, srtcm->cbs_exponent);
		MLX5_SET(flow_meter_parameters,
			 attr, cbs_mantissa, srtcm->cbs_mantissa);
	}
	if (modify_bits & MLX5_FLOW_METER_OBJ_MODIFY_FIELD_CIR) {
		MLX5_SET(flow_meter_parameters,
			 attr, cir_exponent, srtcm->cir_exponent);
		MLX5_SET(flow_meter_parameters,
			 attr, cir_mantissa, srtcm->cir_mantissa);
	}
	if (modify_bits & MLX5_FLOW_METER_OBJ_MODIFY_FIELD_EBS) {
		MLX5_SET(flow_meter_parameters,
			 attr, ebs_exponent, srtcm->ebs_exponent);
		MLX5_SET(flow_meter_parameters,
			 attr, ebs_mantissa, srtcm->ebs_mantissa);
	}

	return 0;
#else
	(void)fm;
	(void)modify_bits;
	(void)active_state;
	return -ENOTSUP;
#endif /* HAVE_IBV_DEVX_OBJ */
}

