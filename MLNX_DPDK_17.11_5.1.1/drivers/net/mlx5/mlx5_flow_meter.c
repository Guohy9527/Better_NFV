// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2018 Mellanox Technologies, Ltd
 */
#include <math.h>

#include <rte_malloc.h>
#include <rte_mtr.h>
#include <rte_mtr_driver.h>

#include "mlx5.h"
#include "mlx5_flow.h"

static int
my_ceil(float num)
{
	int a = num;

	if ((float)a != num)
		return num + 1;
	return num;
}

static int
flow_meter_profile_check(struct rte_eth_dev *dev,
			 uint32_t meter_profile_id,
			 struct rte_mtr_meter_profile *profile,
			 struct rte_mtr_error *error)
{
	struct priv *priv = dev->data->dev_private;
	struct mlx5_flow_meter_profile *fmp;

	/* Meter profile ID must be valid. */
	if (meter_profile_id == UINT32_MAX)
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_METER_PROFILE_ID,
					  NULL, "Meter profile id not valid");
	/* Meter profile must not exist. */
	fmp = mlx5_flow_meter_profile_find(priv, meter_profile_id);
	if (fmp)
		return -rte_mtr_error_set(error, EEXIST,
					  RTE_MTR_ERROR_TYPE_METER_PROFILE_ID,
					  NULL,
					  "Meter profile already exists");
	/* Profile must not be NULL. */
	if (profile == NULL)
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_METER_PROFILE,
					  NULL, "profile is null");

	if (profile->alg == RTE_MTR_SRTCM_RFC2697) {
		if (priv->config.hca_attr.qos.srtcm_sup) {
			/* Verify support for flow meter parameters */
			if (profile->srtcm_rfc2697.cir > 0 &&
			    profile->srtcm_rfc2697.cir <= MLX5_SRTCM_CIR_MAX &&
			    profile->srtcm_rfc2697.cbs > 0 &&
			    profile->srtcm_rfc2697.cbs <= MLX5_SRTCM_CBS_MAX &&
			    profile->srtcm_rfc2697.ebs <= MLX5_SRTCM_EBS_MAX)
				return 0;
			else
				return -rte_mtr_error_set
					     (error, EINVAL,
					      RTE_MTR_ERROR_TYPE_MTR_PARAMS,
					      NULL,
					      profile->srtcm_rfc2697.ebs ?
					      "Metering value ebs must be 0" :
					      "Invalid metering parameters");
		}
	}
	return -rte_mtr_error_set(error, ENOTSUP,
				  RTE_MTR_ERROR_TYPE_METER_PROFILE,
				  NULL, "Metering algorithm not supported");
}

static void
flow_meter_calc_cir_man_exp(uint64_t cir, uint8_t *man, uint8_t *exp)
{
	uint64_t _cir;
	int64_t delta = INT64_MAX;
	uint8_t _man = 0;
	uint8_t _exp = 0;
	uint64_t m, e;

	for (m = 0; m <= 0xFF; m++) { /* man width 8 bit */
		for (e = 0; e <= 0x1F; e++) { /* exp width 5bit */
			_cir = (1000000000ULL * m) >> e;
			if (llabs(cir - _cir) <= delta) {
				delta = llabs(cir - _cir);
				_man = m;
				_exp = e;
			}
		}
	}
	*man = _man;
	*exp = _exp;
}

static void
flow_meter_calc_xbs_man_exp(uint64_t xbs, uint8_t *man, uint8_t *exp)
{
	int _exp;
	double _man;

	/*  special case xbs == 0 ? both exp and matissa are 0. */
	if (xbs == 0) {
		*man = 0;
		*exp = 0;
		return;
	}
	/*
	 * xbs = xbs_mantissa * 2^xbs_exponent
	 */
	_man = frexp(xbs, &_exp);
	_man = _man * pow(2, MLX5_MAN_WIDTH);
	_exp = _exp - MLX5_MAN_WIDTH;
	*man = my_ceil(_man);
	*exp = _exp;
}

static int
flow_meter_prm_param_fill(struct mlx5_flow_meter_profile *fmp,
			  struct rte_mtr_error *error)
{
	struct mlx5_flow_meter_srtcm_rfc2697_prm *srtcm = &fmp->srtcm_prm;
	uint8_t man, exp;

	if (fmp->profile.alg != RTE_MTR_SRTCM_RFC2697)
		return -rte_mtr_error_set(error, ENOTSUP,
				RTE_MTR_ERROR_TYPE_METER_PROFILE,
				NULL, "Metering algorithm not supported");
	/*
	 * RTE_MTR_SRTCM_RFC2697
	 */
	 /* cbs = cbs_mantissa * 2^cbs_exponent */
	flow_meter_calc_xbs_man_exp(fmp->profile.srtcm_rfc2697.cbs,
				    &man, &exp);
	srtcm->cbs_mantissa = man;
	srtcm->cbs_exponent = exp;
	/* Check if mantissa is too large */
	if (srtcm->cbs_exponent != exp)
		goto error;
	/* ebs = ebs_mantissa * 2^ebs_exponent */
	flow_meter_calc_xbs_man_exp(fmp->profile.srtcm_rfc2697.ebs,
				    &man, &exp);
	srtcm->ebs_mantissa = man;
	srtcm->ebs_exponent = exp;
	/* Check if mantissa is too large */
	if (srtcm->ebs_exponent != exp)
		goto error;
	/* cir = 8G * cir_mantissa * 1/(2^cir_exponent)) Bytes/Sec */
	flow_meter_calc_cir_man_exp(fmp->profile.srtcm_rfc2697.cir,
				    &man, &exp);
	srtcm->cir_mantissa = man;
	srtcm->cir_exponent = exp;
	/* Check if mantissa is too large */
	if (srtcm->cir_exponent != exp)
		goto error;
	return 0;
error:
	return -rte_mtr_error_set(error, EINVAL,
				  RTE_MTR_ERROR_TYPE_MTR_PARAMS,
				  NULL, "Meter profile parameters are invalid");
}

static int
flow_mtr_cap_get(struct rte_eth_dev *dev,
		 struct rte_mtr_capabilities *cap,
		 struct rte_mtr_error *error __rte_unused)
{
	struct priv *priv = dev->data->dev_private;
	struct mlx5_hca_qos_attr *qattr = &priv->config.hca_attr.qos;

	memset(cap, 0, sizeof(*cap));
	if (!qattr->sup || !qattr->srtcm_sup)
		return 0;

	cap->n_max = 1 << qattr->log_max_flow_meter;
	cap->n_shared_max = cap->n_max;
	cap->identical = 1;
	cap->shared_identical = 1;
	cap->shared_n_flows_per_mtr_max = 4 << 20;
	/* 2M flows can share the same meter. */
	cap->chaining_n_mtrs_per_flow_max = 1; /* Chaining is not supported. */
	cap->meter_srtcm_rfc2697_n_max = qattr->srtcm_sup ? cap->n_max : 0;
	cap->meter_rate_max = 1ULL << 40; /* 1 Tera tokens per sec */
	cap->policer_action_drop_supported = 1;
	cap->stats_mask = RTE_MTR_STATS_N_BYTES_DROPPED |
			  RTE_MTR_STATS_N_PKTS_DROPPED;
	return 0;
}

static int
flow_meter_profile_add(struct rte_eth_dev *dev,
		       uint32_t meter_profile_id,
		       struct rte_mtr_meter_profile *profile,
		       struct rte_mtr_error *error)
{
	struct priv *priv = dev->data->dev_private;
	struct mlx5_flow_meter_profiles *fmps = &priv->flow_meter_profiles;
	struct mlx5_flow_meter_profile *fmp;
	int stat;

	/* Check input params */
	stat = flow_meter_profile_check(dev, meter_profile_id, profile, error);
	if (stat)
		return stat;

	/* Memory allocation */
	fmp = rte_calloc(__func__,
			 1,
			 sizeof(struct mlx5_flow_meter_profile),
			 RTE_CACHE_LINE_SIZE);
	if (fmp == NULL)
		return -rte_mtr_error_set(error, ENOMEM,
					  RTE_MTR_ERROR_TYPE_UNSPECIFIED,
					  NULL, "Memory alloc failed");
	/* Fill profile info */
	fmp->meter_profile_id = meter_profile_id;
	memcpy(&fmp->profile, profile, sizeof(fmp->profile));
	/* Fill the flow meter parameters for the PRM */
	stat = flow_meter_prm_param_fill(fmp, error);
	if (stat)
		goto error;
	/* Add to list */
	TAILQ_INSERT_TAIL(fmps, fmp, next);
	return 0;
error:
	rte_free(fmp);
	return stat;
}

static int
flow_meter_profile_delete(struct rte_eth_dev *dev,
			  uint32_t meter_profile_id,
			  struct rte_mtr_error *error)
{
	struct priv *priv = dev->data->dev_private;
	struct mlx5_flow_meter_profile *fmp;

	/* Meter profile must exist */
	fmp = mlx5_flow_meter_profile_find(priv, meter_profile_id);
	if (fmp == NULL)
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_METER_PROFILE_ID,
					  NULL, "Meter profile id invalid");
	/* Check unused */
	if (fmp->use_c)
		return -rte_mtr_error_set(error, EBUSY,
					  RTE_MTR_ERROR_TYPE_METER_PROFILE_ID,
					  NULL, "Meter profile in use");
	/* Remove from list */
	TAILQ_REMOVE(&priv->flow_meter_profiles, fmp, next);
	rte_free(fmp);
	return 0;
}

static enum rte_mtr_error_type
action2error(enum rte_mtr_policer_action action)
{
	switch (action) {
	case MTR_POLICER_ACTION_COLOR_GREEN:
		return RTE_MTR_ERROR_TYPE_POLICER_ACTION_GREEN;
	case MTR_POLICER_ACTION_COLOR_YELLOW:
		return RTE_MTR_ERROR_TYPE_POLICER_ACTION_YELLOW;
	case MTR_POLICER_ACTION_COLOR_RED:
		return RTE_MTR_ERROR_TYPE_POLICER_ACTION_RED;
	default:
		break;
	}
	return RTE_MTR_ERROR_TYPE_UNSPECIFIED;
}

static int
flow_meter_check(struct priv *priv, uint32_t meter_id,
		 struct rte_mtr_params *params, int shared __rte_unused,
		 struct rte_mtr_error *error)
{
	static enum rte_mtr_policer_action
				valid_recol_action[RTE_MTR_COLORS] = {
					       MTR_POLICER_ACTION_COLOR_GREEN,
					       MTR_POLICER_ACTION_COLOR_YELLOW,
					       MTR_POLICER_ACTION_COLOR_RED };
	int i;

	/* Meter id valid  */
	if (mlx5_flow_meter_find(priv, meter_id))
		return -rte_mtr_error_set(error, EEXIST,
					  RTE_MTR_ERROR_TYPE_MTR_ID, NULL,
					  "Meter object already exists");
	/* Meter params must not be NULL */
	if (params == NULL)
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_MTR_PARAMS,
					  NULL, "Meter object params null");
	/* Previous meter color not supported */
	if (params->use_prev_mtr_color)
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_MTR_PARAMS,
					  NULL,
					  "Previous meter color "
					  "not supported");
	/* Check policer settings */
	for (i = 0; i < RTE_MTR_COLORS; i++)
		if (params->action[i] != valid_recol_action[i] &&
		    params->action[i] != MTR_POLICER_ACTION_DROP)
			return -rte_mtr_error_set
					(error, EINVAL,
					 action2error(params->action[i]),
					 NULL, "Recolor action not supported");
	return 0;
}

static int
flow_meter_create(struct rte_eth_dev *dev, uint32_t meter_id,
		       struct rte_mtr_params *params, int shared,
		       struct rte_mtr_error *error)
{
	struct priv *priv = dev->data->dev_private;
	struct mlx5_flow_meters *fms = &priv->flow_meters;
	struct mlx5_flow_meter_profile *fmp;
	struct mlx5_flow_meter *fm;
	const struct rte_flow_attr attr = {
				.ingress = 1,
				.egress = 1,
				.transfer = priv->config.dv_eswitch_en ? 1 : 0,
			};
	int stat;
	unsigned int i;

	if (priv->vf)
		return -rte_mtr_error_set(error, ENOMEM,
					  RTE_MTR_ERROR_TYPE_UNSPECIFIED,
					  NULL,
					  "Meter is not supported in VFs");
	/* Check parameters */
	stat = flow_meter_check(priv, meter_id, params, shared, error);
	if (stat)
		return stat;
	/* Meter profile must exist */
	fmp = mlx5_flow_meter_profile_find(priv, params->meter_profile_id);
	if (fmp == NULL)
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_METER_PROFILE_ID,
					  NULL, "Meter profile id not valid");
	/* Memory allocation */
	fm = rte_calloc(__func__, 1,
			sizeof(struct mlx5_flow_meter), RTE_CACHE_LINE_SIZE);
	if (fm == NULL)
		return -rte_mtr_error_set(error, ENOMEM,
					  RTE_MTR_ERROR_TYPE_UNSPECIFIED,
					  NULL, "Memory alloc failed");
	/* Fill in */
	fm->meter_id = meter_id;
	fm->profile = fmp;
	memcpy(&fm->params, params, sizeof(fm->params));
	/* assign rec_c to the meter */
	fm->metadata_reg_c_idx =
		ffs(priv->config.hca_attr.qos.flow_meter_reg_c_ids);
	if (fm->metadata_reg_c_idx == 0 || fm->metadata_reg_c_idx > 8) {
		DRV_LOG(ERR, "Invalid reg_c bitmap 0x%x",
			priv->config.hca_attr.qos.flow_meter_reg_c_ids);
		stat = -EINVAL;
		goto error;
	}
	fm->metadata_reg_c_idx -= 1; /* Convert bit location to index */
	/* Alloc policer counters */
	for (i = 0; i < RTE_DIM(fm->policer_stats.dcs); i++) {
		stat = mlx5_devx_cmd_fc_alloc(priv->sh->ctx,
					      &fm->policer_stats.dcs[i],
					      0);
		fm->policer_stats.dcs[i].type = MLX5_COUNTER_TYPE_SINGLE;
		if (stat)
			goto error;
	}
	fm->mfts = mlx5_flow_create_mtr_tbls(dev, fm);
	if (!fm->mfts)
		goto error;
	stat = mlx5_flow_create_policer_rules(dev, fm, &attr);
	if (stat)
		goto error;
	/* Add to list */
	TAILQ_INSERT_TAIL(fms, fm, next);
	fm->active_state = 1; /* Meter starts as active */
	fm->shared = !!shared;
	fm->policer_stats.stats_mask = params->stats_mask;
	fm->profile->use_c++;
	return 0;
error:
	mlx5_flow_destroy_policer_rules(dev, fm, &attr);
	mlx5_flow_destroy_mtr_tbls(dev, fm->mfts);
	/* Free policer counters */
	for (i = 0; i < RTE_DIM(fm->policer_stats.dcs); i++)
		if (fm->policer_stats.dcs[i].obj)
			mlx5_devx_cmd_fc_free(fm->policer_stats.dcs[i].obj);
	rte_free(fm);
	return -rte_mtr_error_set(error, -stat,
				  RTE_MTR_ERROR_TYPE_UNSPECIFIED,
				  NULL, "failed to create devx meter");
}

static int
flow_meter_destroy(struct rte_eth_dev *dev, uint32_t meter_id,
		   struct rte_mtr_error *error)
{
	struct priv *priv = dev->data->dev_private;
	struct mlx5_flow_meters *fms = &priv->flow_meters;
	struct mlx5_flow_meter_profile *fmp;
	struct mlx5_flow_meter *fm;
	const struct rte_flow_attr attr = {
				.ingress = 1,
				.egress = 1,
				.transfer = priv->config.dv_eswitch_en ? 1 : 0,
			};
	unsigned int i;

	/* Meter object must exist */
	fm = mlx5_flow_meter_find(priv, meter_id);
	if (fm == NULL)
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_MTR_ID,
					  NULL, "Meter object id not valid");
	/* Meter object must not have any owner */
	if (fm->use_c > 0)
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_UNSPECIFIED,
					  NULL, "Meter object is being used");
	/* Get meter profile */
	fmp = fm->profile;
	if (fmp == NULL)
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_METER_PROFILE_ID,
					  NULL,
					  "MTR object meter profile invalid");
	/* Update dependencies */
	fmp->use_c--;
	/* Remove from list */
	TAILQ_REMOVE(fms, fm, next);
	/* Free policer counters */
	for (i = 0; i < RTE_DIM(fm->policer_stats.dcs); i++)
		if (fm->policer_stats.dcs[i].obj)
			mlx5_devx_cmd_fc_free(fm->policer_stats.dcs[i].obj);
	/* Free meter flow table */
	mlx5_flow_destroy_policer_rules(dev, fm, &attr);
	mlx5_flow_destroy_mtr_tbls(dev, fm->mfts);
	rte_free(fm);
	return 0;
}

static int
flow_meter_stats_update(struct rte_eth_dev *dev,
			uint32_t meter_id,
			uint64_t stats_mask,
			struct rte_mtr_error *error)
{
	struct priv *priv = dev->data->dev_private;
	struct mlx5_flow_meter *fm;

	/* Meter object must exist */
	fm = mlx5_flow_meter_find(priv, meter_id);
	if (fm == NULL)
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_MTR_ID,
					  NULL, "Meter object id not valid");
	fm->policer_stats.stats_mask = stats_mask;
	return 0;
}

static int
flow_meter_stats_read(struct rte_eth_dev *dev,
		      uint32_t meter_id,
		      struct rte_mtr_stats *stats,
		      uint64_t *stats_mask,
		      int clear,
		      struct rte_mtr_error *error)
{
	static uint64_t meter2mask[RTE_MTR_DROPPED + 1] = {
		RTE_MTR_STATS_N_PKTS_GREEN | RTE_MTR_STATS_N_BYTES_GREEN,
		RTE_MTR_STATS_N_PKTS_YELLOW | RTE_MTR_STATS_N_BYTES_YELLOW,
		RTE_MTR_STATS_N_PKTS_RED | RTE_MTR_STATS_N_BYTES_RED,
		RTE_MTR_STATS_N_PKTS_DROPPED | RTE_MTR_STATS_N_BYTES_DROPPED
	};
	struct priv *priv = dev->data->dev_private;
	struct mlx5_flow_meter *fm;
	struct mlx5_flow_policer_stats *ps;
	uint64_t pkts_dropped = 0;
	uint64_t bytes_dropped = 0;
	int i;
	int stat = 0;

	/* Meter object must exist */
	fm = mlx5_flow_meter_find(priv, meter_id);
	if (fm == NULL)
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_MTR_ID,
					  NULL, "Meter object id not valid");
	ps = &fm->policer_stats;
	*stats_mask = ps->stats_mask;
	for (i = 0; i < RTE_MTR_DROPPED; i++) {
		if (*stats_mask & meter2mask[i]) {
			stat = mlx5_devx_cmd_fc_query(&ps->dcs[i], clear,
						      &stats->n_pkts[i],
						      &stats->n_bytes[i],
						      0, 0, NULL, NULL,
						      priv->sh->devx_comp);
			if (stat)
				goto error;
			stats->n_bytes[i] -= sizeof(struct ether_hdr) *
						stats->n_pkts[i];
			if (fm->params.action[i] == MTR_POLICER_ACTION_DROP) {
				pkts_dropped += stats->n_pkts[i];
				bytes_dropped += stats->n_bytes[i];
			}
		}
	}
	/* Dropped packets/bytes are treated differently. */
	if (*stats_mask & meter2mask[i]) {
		stat = mlx5_devx_cmd_fc_query(&ps->dcs[i], clear,
					      &stats->n_pkts_dropped,
					      &stats->n_bytes_dropped,
					      0, 0, NULL, NULL,
					      priv->sh->devx_comp);
		if (stat)
			goto error;
		stats->n_bytes_dropped -= sizeof(struct ether_hdr) *
						stats->n_pkts_dropped;
		stats->n_pkts_dropped += pkts_dropped;
		stats->n_bytes_dropped += bytes_dropped;
	}
	return 0;
error:
	return -rte_mtr_error_set(error, stat,
			  RTE_MTR_ERROR_TYPE_STATS,
			  NULL,
			  "Failed to read policer counters");
}

static int
flow_meter_modify_state(struct mlx5_flow_meter *fm,
			uint32_t new_state,
			struct rte_mtr_error *error)
{
	struct mlx5_flow_meter_srtcm_rfc2697_prm srtcm = {
		.cbs_exponent = 20,
		.cbs_mantissa = 191,
		.cir_exponent = 0,
		.cir_mantissa = 200,
		.ebs_exponent = 0,
		.ebs_mantissa = 0,

	};
	uint64_t modify_bits = MLX5_FLOW_METER_OBJ_MODIFY_FIELD_CBS |
			       MLX5_FLOW_METER_OBJ_MODIFY_FIELD_CIR;
	int stat;

	if (new_state == MLX5_FLOW_METER_DISABLE)
		stat =  mlx5_devx_cmd_flow_meter_modify(fm, &srtcm,
							modify_bits, 0);
	else
		stat =  mlx5_devx_cmd_flow_meter_modify(fm,
							&fm->profile->srtcm_prm,
							modify_bits, 0);
	if (stat)
		return -rte_mtr_error_set(error, -stat,
					  RTE_MTR_ERROR_TYPE_MTR_PARAMS,
					  NULL,
					  new_state ?
					  "Failed to enable meter" :
					  "Failed to disable meter");
	return 0;
}

static int
flow_meter_enable(struct rte_eth_dev *dev,
		  uint32_t meter_id,
		  struct rte_mtr_error *error)
{
	struct priv *priv = dev->data->dev_private;
	struct mlx5_flow_meter *fm;
	int stat;

	/* Meter object must exist */
	fm = mlx5_flow_meter_find(priv, meter_id);
	if (fm == NULL)
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_MTR_ID,
					  NULL, "Meter not found");
	if (fm->active_state == MLX5_FLOW_METER_ENABLE)
		return 0;
	stat = flow_meter_modify_state(fm, MLX5_FLOW_METER_ENABLE, error);
	if (!stat)
		fm->active_state = MLX5_FLOW_METER_ENABLE;
	return stat;
}

static int
flow_meter_disable(struct rte_eth_dev *dev,
		  uint32_t meter_id,
		  struct rte_mtr_error *error)
{
	struct priv *priv = dev->data->dev_private;
	struct mlx5_flow_meter *fm;
	int stat;

	/* Meter object must exist */
	fm = mlx5_flow_meter_find(priv, meter_id);
	if (fm == NULL)
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_MTR_ID,
					  NULL, "Meter not found");
	if (fm->active_state == MLX5_FLOW_METER_DISABLE)
		return 0;
	stat = flow_meter_modify_state(fm, MLX5_FLOW_METER_DISABLE, error);
	if (!stat)
		fm->active_state = MLX5_FLOW_METER_DISABLE;
	return stat;
}

static int
flow_meter_profile_update(struct rte_eth_dev *dev,
			  uint32_t meter_id,
			  uint32_t meter_profile_id,
			  struct rte_mtr_error *error)
{
	struct priv *priv = dev->data->dev_private;
	struct mlx5_flow_meter_profile *fmp;
	struct mlx5_flow_meter *fm;
	uint64_t modify_bits = MLX5_FLOW_METER_OBJ_MODIFY_FIELD_CBS |
			       MLX5_FLOW_METER_OBJ_MODIFY_FIELD_CIR;
	int stat;

	/* Meter profile must exist */
	fmp = mlx5_flow_meter_profile_find(priv, meter_profile_id);
	if (fmp == NULL)
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_METER_PROFILE_ID,
					  NULL, "Meter profile not found");
	/* Meter object must exist */
	fm = mlx5_flow_meter_find(priv, meter_id);
	if (fm == NULL)
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_MTR_ID,
					  NULL, "Meter not found");
	/* MTR object already set to meter profile id */
	if (fmp == fm->profile)
		return 0;
	/* Replace the profile */
	fm->profile->use_c--;
	fm->profile = fmp;
	fm->profile->use_c++;
	/* Update meter params in HW (if not disabled) */
	if (fm->active_state == MLX5_FLOW_METER_DISABLE)
		return 0;
	stat = mlx5_devx_cmd_flow_meter_modify(fm, &fm->profile->srtcm_prm,
					       modify_bits, fm->active_state);
	if (stat)
		return -rte_mtr_error_set(error, -stat,
					  RTE_MTR_ERROR_TYPE_MTR_PARAMS,
					  NULL, "Failed to update meter"
					  " parmeters in hardware");
	return 0;
}

static const struct rte_mtr_ops mlx5_flow_mtr_ops = {
	.capabilities_get = flow_mtr_cap_get,
	.meter_profile_add = flow_meter_profile_add,
	.meter_profile_delete = flow_meter_profile_delete,
	.create = flow_meter_create,
	.destroy = flow_meter_destroy,
	.meter_enable = flow_meter_enable,
	.meter_disable = flow_meter_disable,
	.meter_profile_update = flow_meter_profile_update,
	.meter_dscp_table_update = NULL,
	.policer_actions_update = NULL,
	.stats_update = flow_meter_stats_update,
	.stats_read = flow_meter_stats_read,
};

int
mlx5_flow_meter_ops_get(struct rte_eth_dev *dev __rte_unused, void *arg)
{
	*(const struct rte_mtr_ops **)arg = &mlx5_flow_mtr_ops;
	return 0;
}

struct mlx5_flow_meter_profile *
mlx5_flow_meter_profile_find(struct priv *priv, uint32_t meter_profile_id)
{
	struct mlx5_flow_meter_profiles *fmps = &priv->flow_meter_profiles;
	struct mlx5_flow_meter_profile *fmp;

	TAILQ_FOREACH(fmp, fmps, next)
		if (meter_profile_id == fmp->meter_profile_id)
			return fmp;
	return NULL;
}

/**
 * Verify the flow meter profile list is empty
 *
 * @param dev
 *  Pointer to Ethernet device.
 *
 * @return the number of flows meter profiles not released.
 */
int
mlx5_flow_meter_profile_verify(struct rte_eth_dev *dev)
{
	struct priv *priv = dev->data->dev_private;
	struct mlx5_flow_meter_profile *fmp;
	int ret = 0;

	TAILQ_FOREACH(fmp, &priv->flow_meter_profiles, next) {
		DRV_LOG(DEBUG, "port %u flow meter profile %p still referenced",
			dev->data->port_id, (void *)fmp);
		++ret;
	}
	return ret;
}

struct mlx5_flow_meter *
mlx5_flow_meter_find(struct priv *priv, uint32_t meter_id)
{
	struct mlx5_flow_meters *fms = &priv->flow_meters;
	struct mlx5_flow_meter *fm;

	TAILQ_FOREACH(fm, fms, next)
		if (meter_id == fm->meter_id)
			return fm;
	return NULL;
}

/**
 * Verify the flow meter list is empty
 *
 * @param dev
 *  Pointer to Ethernet device.
 *
 * @return the number of flows meters not released.
 */
int
mlx5_flow_meter_verify(struct rte_eth_dev *dev)
{
	struct priv *priv = dev->data->dev_private;
	struct mlx5_flow_meter *fm;
	int ret = 0;

	TAILQ_FOREACH(fm, &priv->flow_meters, next) {
		DRV_LOG(DEBUG, "port %u flow meter %p still referenced",
			dev->data->port_id, (void *)fm);
		++ret;
	}
	return ret;
}

/**
 * attach to a flow meter
 * Unidirectional Meter creation can be done only be done
 * when flow direction is known, i.e. when calling meter_attach
 *
 * @param dev
 *  Pointer to Ethernet device.
 *
 * @return the number of flows meters not released.
 */
struct mlx5_flow_meter *
mlx5_flow_meter_attach(struct priv *priv, uint32_t meter_id,
		       const struct rte_flow_attr *attr)
{
	struct mlx5_flow_meter *fm;
	struct mlx5dv_dr_flow_meter_attr mtr_init;

	fm = mlx5_flow_meter_find(priv, meter_id);
	if (fm == NULL)
		goto error;
	if(!fm->shared && fm->use_c) {
		DRV_LOG(ERR, "Cannot share a non-shared meter");
		goto error;
	}
	if (!fm->use_c++) {
		fm->attr = *attr;
		mlx5_devx_cmd_flow_meter_fill_params(priv->sh->ctx, fm);
		mtr_init.next_table =
			attr->transfer ? fm->mfts->transfer.tbl :
					  attr->egress ? fm->mfts->egress.tbl :
							 fm->mfts->ingress.tbl;
		mtr_init.reg_c_index = fm->metadata_reg_c_idx;
		mtr_init.flow_meter_parameter = fm->mfts->fmp;
		mtr_init.flow_meter_parameter_sz = fm->mfts->fmp_size;
		mtr_init.active = fm->active_state;
		/* This also creates the meter object */
		fm->mfts->meter_action =
			mlx5dv_dr_action_create_flow_meter(&mtr_init);
		if (!fm->mfts->meter_action)
			goto error_detach;
	} else {
		if (attr->transfer != fm->attr.transfer ||
		    attr->ingress != fm->attr.ingress ||
		    attr->egress != fm->attr.egress ||
		    attr->egress == attr->ingress) {
			DRV_LOG(ERR, "meter I/O attributes do not "
				"match flow I/O attributes");
			goto error_detach;
		}
	}
	return fm;
error_detach:
	mlx5_flow_meter_detach(fm);
error:
	rte_errno = EINVAL;
	return NULL;
}

/**
 * detach from a flow meter
 *
 * @param dev
 *  Pointer to Ethernet device.
 *
 * @return the number of flows meters not released.
 */
void
mlx5_flow_meter_detach(struct mlx5_flow_meter *fm)
{
	const struct rte_flow_attr attr = { 0 };

	RTE_ASSERT(fm->use_c);
	if (--fm->use_c)
		return;
	if (fm->mfts->meter_action)
		mlx5dv_dr_action_destroy(fm->mfts->meter_action);
	fm->mfts->meter_action = NULL;
	fm->attr = attr;
}
