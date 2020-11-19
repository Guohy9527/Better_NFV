/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018 Mellanox Technologies, Ltd
 */

#ifndef RTE_PMD_MLX5_DEVX_CMDS_H_
#define RTE_PMD_MLX5_DEVX_CMDS_H_

#include <rte_common.h>

/* Verbs header. */
/* ISO C doesn't support unnamed structs/unions, disabling -pedantic. */
#ifdef PEDANTIC
#pragma GCC diagnostic ignored "-Wpedantic"
#endif
#include <infiniband/mlx5dv.h>
#ifdef PEDANTIC
#pragma GCC diagnostic error "-Wpedantic"
#endif

#include "mlx5_autoconf.h"
#include "mlx5.h"

#ifndef HAVE_IBV_DEVX_OBJ
struct mlx5dv_devx_obj;
#endif

enum {
	MLX5_CMD_OP_QUERY_HCA_CAP		= 0x100,
	MLX5_CMD_OP_CREATE_MKEY			= 0x200, 
	MLX5_CMD_OP_ALLOC_FLOW_COUNTER		= 0x939,
	MLX5_CMD_OP_DEALLOC_FLOW_COUNTER	= 0x93a,
	MLX5_CMD_OP_QUERY_FLOW_COUNTER		= 0x93b,
	MLX5_CMD_OP_CREATE_GENERAL_OBJECT	= 0xa00,
	MLX5_CMD_OP_MODIFY_GENERAL_OBJECT	= 0xa01,
	MLX5_CMD_OP_QUERY_GENERAL_OBJECT	= 0xa02,
	MLX5_CMD_OP_DESTROY_GENERAL_OBJECT	= 0xa03,
};

enum {
	MLX5_MKC_ACCESS_MODE_PA    = 0x0,
	MLX5_MKC_ACCESS_MODE_MTT   = 0x1,
	MLX5_MKC_ACCESS_MODE_KLMS  = 0x2,
	MLX5_MKC_ACCESS_MODE_KSM   = 0x3,
	MLX5_MKC_ACCESS_MODE_MEMIC = 0x5,
};

enum {
	MLX5_GENERAL_OBJ_TYPES_CAP_UCTX = (1ULL << 4),
	MLX5_GENERAL_OBJ_TYPES_CAP_UMEM = (1ULL << 5),
	MLX5_GENERAL_OBJ_TYPES_CAP_FLOW_METER = (1ULL << 10),
};

enum {
	MLX5_OBJ_TYPE_UCTX = 0x0004,
	MLX5_OBJ_TYPE_UMEM = 0x0005,
	MLX5_OBJ_TYPE_FLOW_METER = 0x000a,
};

/* Flow counters. */
struct mlx5_ifc_alloc_flow_counter_out_bits {
	u8         status[0x8];
	u8         reserved_at_8[0x18];
	u8         syndrome[0x20];
	u8         flow_counter_id[0x20];
	u8         reserved_at_60[0x20];
};

struct mlx5_ifc_alloc_flow_counter_in_bits {
	u8         opcode[0x10];
	u8         reserved_at_10[0x10];
	u8         reserved_at_20[0x10];
	u8         op_mod[0x10];
	u8         flow_counter_id[0x20];
	u8         reserved_at_40[0x18];
	u8         flow_counter_bulk[0x8];
};

struct mlx5_ifc_dealloc_flow_counter_out_bits {
	u8         status[0x8];
	u8         reserved_at_8[0x18];
	u8         syndrome[0x20];
	u8         reserved_at_40[0x40];
};

struct mlx5_ifc_dealloc_flow_counter_in_bits {
	u8         opcode[0x10];
	u8         reserved_at_10[0x10];
	u8         reserved_at_20[0x10];
	u8         op_mod[0x10];
	u8         flow_counter_id[0x20];
	u8         reserved_at_60[0x20];
};

struct mlx5_ifc_traffic_counter_bits {
	u8         packets[0x40];
	u8         octets[0x40];
};

struct mlx5_ifc_query_flow_counter_out_bits {
	u8         status[0x8];
	u8         reserved_at_8[0x18];
	u8         syndrome[0x20];
	u8         reserved_at_40[0x40];
	struct mlx5_ifc_traffic_counter_bits flow_statistics[];
};

struct mlx5_ifc_query_flow_counter_in_bits {
	u8         opcode[0x10];
	u8         reserved_at_10[0x10];
	u8         reserved_at_20[0x10];
	u8         op_mod[0x10];
	u8         reserved_at_40[0x20];
	u8         mkey[0x20];
	u8         address[0x40];
	u8         clear[0x1];
	u8         dump_to_memory[0x1];
	u8         num_of_counters[0x1e];
	u8         flow_counter_id[0x20];
};

struct mlx5_ifc_mkc_bits {
	u8         reserved_at_0[0x1];
	u8         free[0x1];
	u8         reserved_at_2[0x1];
	u8         access_mode_4_2[0x3];
	u8         reserved_at_6[0x7];
	u8         relaxed_ordering_write[0x1];
	u8         reserved_at_e[0x1];
	u8         small_fence_on_rdma_read_response[0x1];
	u8         umr_en[0x1];
	u8         a[0x1];
	u8         rw[0x1];
	u8         rr[0x1];
	u8         lw[0x1];
	u8         lr[0x1];
	u8         access_mode_1_0[0x2];
	u8         reserved_at_18[0x8];

	u8         qpn[0x18];
	u8         mkey_7_0[0x8];

	u8         reserved_at_40[0x20];

	u8         length64[0x1];
	u8         bsf_en[0x1];
	u8         sync_umr[0x1];
	u8         reserved_at_63[0x2];
	u8         expected_sigerr_count[0x1];
	u8         reserved_at_66[0x1];
	u8         en_rinval[0x1];
	u8         pd[0x18];

	u8         start_addr[0x40];

	u8         len[0x40];

	u8         bsf_octword_size[0x20];

	u8         reserved_at_120[0x80];

	u8         translations_octword_size[0x20];

	u8         reserved_at_1c0[0x1b];
	u8         log_page_size[0x5];

	u8         reserved_at_1e0[0x20];
};

struct mlx5_ifc_create_mkey_out_bits {
	u8         status[0x8];
	u8         reserved_at_8[0x18];

	u8         syndrome[0x20];

	u8         reserved_at_40[0x8];
	u8         mkey_index[0x18];

	u8         reserved_at_60[0x20];
};

struct mlx5_ifc_create_mkey_in_bits {
	u8         opcode[0x10];
	u8         reserved_at_10[0x10];

	u8         reserved_at_20[0x10];
	u8         op_mod[0x10];

	u8         reserved_at_40[0x20];

	u8         pg_access[0x1];
	u8         reserved_at_61[0x1f];

	struct mlx5_ifc_mkc_bits memory_key_mkey_entry;

	u8         reserved_at_280[0x80];

	u8         translations_octword_actual_size[0x20];

	u8         mkey_umem_id[0x20];

	u8         mkey_umem_offset[0x40];

	u8         reserved_at_380[0x500];

	u8         klm_pas_mtt[][0x20];
};

/*
 * Query HCA capabilities
 */

enum {
	MLX5_GET_HCA_CAP_OP_MOD_GENERAL_DEVICE = 0x0 << 1,
	MLX5_GET_HCA_CAP_OP_MOD_QOS_CAP        = 0xc << 1,
};

enum {
	MLX5_HCA_CAP_OPMOD_GET_MAX   = 0,
	MLX5_HCA_CAP_OPMOD_GET_CUR   = 1,
};

enum {
	MLX5_HCA_CAP_ALLOC_BULK_128_COUNTERS = (1 << 0),
	MLX5_HCA_CAP_ALLOC_BULK_256_COUNTERS = (1 << 1),
	MLX5_HCA_CAP_ALLOC_BULK_512_COUNTERS = (1 << 2),
	MLX5_HCA_CAP_ALLOC_BULK_1024_COUNTERS = (1 << 3),
	MLX5_HCA_CAP_ALLOC_BULK_2048_COUNTERS = (1 << 4),
	MLX5_HCA_CAP_ALLOC_BULK_4096_COUNTERS = (1 << 5),
	MLX5_HCA_CAP_ALLOC_BULK_8192_COUNTERS = (1 << 6),
	MLX5_HCA_CAP_ALLOC_BULK_16384_COUNTERS = (1 << 7),
};
/* Convert enum MLX5_HCA_CAP_ALLOC_BULK_*_COUNTERS to number of counters */
#define BULK_TO_NUM_COUNTERS(bc) (128 * bc)


struct mlx5_ifc_cmd_hca_cap_bits {
	u8         reserved_at_0[0x30];
	u8         vhca_id[0x10];

	u8         reserved_at_40[0x40];

	u8         log_max_srq_sz[0x8];
	u8         log_max_qp_sz[0x8];
	u8         reserved_at_90[0xb];
	u8         log_max_qp[0x5];

	u8         reserved_at_a0[0xb];
	u8         log_max_srq[0x5];
	u8         reserved_at_b0[0x10];

	u8         reserved_at_c0[0x8];
	u8         log_max_cq_sz[0x8];
	u8         reserved_at_d0[0xb];
	u8         log_max_cq[0x5];

	u8         log_max_eq_sz[0x8];
	u8         reserved_at_e8[0x2];
	u8         log_max_mkey[0x6];
	u8         reserved_at_f0[0x8];
	u8         dump_fill_mkey[0x1];
	u8         reserved_at_f9[0x3];
	u8         log_max_eq[0x4];

	u8         max_indirection[0x8];
	u8         fixed_buffer_size[0x1];
	u8         log_max_mrw_sz[0x7];
	u8         force_teardown[0x1];
	u8         reserved_at_111[0x1];
	u8         log_max_bsf_list_size[0x6];
	u8         umr_extended_translation_offset[0x1];
	u8         null_mkey[0x1];
	u8         log_max_klm_list_size[0x6];

	u8         reserved_at_120[0xa];
	u8         log_max_ra_req_dc[0x6];
	u8         reserved_at_130[0xa];
	u8         log_max_ra_res_dc[0x6];

	u8         reserved_at_140[0xa];
	u8         log_max_ra_req_qp[0x6];
	u8         reserved_at_150[0xa];
	u8         log_max_ra_res_qp[0x6];

	u8         end_pad[0x1];
	u8         cc_query_allowed[0x1];
	u8         cc_modify_allowed[0x1];
	u8         start_pad[0x1];
	u8         cache_line_128byte[0x1];
	u8         reserved_at_165[0xa];
	u8         qcam_reg[0x1];
	u8         gid_table_size[0x10];

	u8         out_of_seq_cnt[0x1];
	u8         vport_counters[0x1];
	u8         retransmission_q_counters[0x1];
	u8         debug[0x1];
	u8         modify_rq_counter_set_id[0x1];
	u8         rq_delay_drop[0x1];
	u8         max_qp_cnt[0xa];
	u8         pkey_table_size[0x10];

	u8         vport_group_manager[0x1];
	u8         vhca_group_manager[0x1];
	u8         ib_virt[0x1];
	u8         eth_virt[0x1];
	u8         vnic_env_queue_counters[0x1];
	u8         ets[0x1];
	u8         nic_flow_table[0x1];
	u8         eswitch_manager[0x1];
	u8         device_memory[0x1];
	u8         mcam_reg[0x1];
	u8         pcam_reg[0x1];
	u8         local_ca_ack_delay[0x5];
	u8         port_module_event[0x1];
	u8         enhanced_error_q_counters[0x1];
	u8         ports_check[0x1];
	u8         reserved_at_1b3[0x1];
	u8         disable_link_up[0x1];
	u8         beacon_led[0x1];
	u8         port_type[0x2];
	u8         num_ports[0x8];

	u8         reserved_at_1c0[0x1];
	u8         pps[0x1];
	u8         pps_modify[0x1];
	u8         log_max_msg[0x5];
	u8         reserved_at_1c8[0x4];
	u8         max_tc[0x4];
	u8         temp_warn_event[0x1];
	u8         dcbx[0x1];
	u8         general_notification_event[0x1];
	u8         reserved_at_1d3[0x2];
	u8         fpga[0x1];
	u8         rol_s[0x1];
	u8         rol_g[0x1];
	u8         reserved_at_1d8[0x1];
	u8         wol_s[0x1];
	u8         wol_g[0x1];
	u8         wol_a[0x1];
	u8         wol_b[0x1];
	u8         wol_m[0x1];
	u8         wol_u[0x1];
	u8         wol_p[0x1];

	u8         stat_rate_support[0x10];
	u8         reserved_at_1f0[0xc];
	u8         cqe_version[0x4];

	u8         compact_address_vector[0x1];
	u8         striding_rq[0x1];
	u8         reserved_at_202[0x1];
	u8         ipoib_enhanced_offloads[0x1];
	u8         ipoib_basic_offloads[0x1];
	u8         reserved_at_205[0x1];
	u8         repeated_block_disabled[0x1];
	u8         umr_modify_entity_size_disabled[0x1];
	u8         umr_modify_atomic_disabled[0x1];
	u8         umr_indirect_mkey_disabled[0x1];
	u8         umr_fence[0x2];
	u8         reserved_at_20c[0x3];
	u8         drain_sigerr[0x1];
	u8         cmdif_checksum[0x2];
	u8         sigerr_cqe[0x1];
	u8         reserved_at_213[0x1];
	u8         wq_signature[0x1];
	u8         sctr_data_cqe[0x1];
	u8         reserved_at_216[0x1];
	u8         sho[0x1];
	u8         tph[0x1];
	u8         rf[0x1];
	u8         dct[0x1];
	u8         qos[0x1];
	u8         eth_net_offloads[0x1];
	u8         roce[0x1];
	u8         atomic[0x1];
	u8         reserved_at_21f[0x1];

	u8         cq_oi[0x1];
	u8         cq_resize[0x1];
	u8         cq_moderation[0x1];
	u8         reserved_at_223[0x3];
	u8         cq_eq_remap[0x1];
	u8         pg[0x1];
	u8         block_lb_mc[0x1];
	u8         reserved_at_229[0x1];
	u8         scqe_break_moderation[0x1];
	u8         cq_period_start_from_cqe[0x1];
	u8         cd[0x1];
	u8         reserved_at_22d[0x1];
	u8         apm[0x1];
	u8         vector_calc[0x1];
	u8         umr_ptr_rlky[0x1];
	u8	   imaicl[0x1];
	u8         reserved_at_232[0x4];
	u8         qkv[0x1];
	u8         pkv[0x1];
	u8         set_deth_sqpn[0x1];
	u8         reserved_at_239[0x3];
	u8         xrc[0x1];
	u8         ud[0x1];
	u8         uc[0x1];
	u8         rc[0x1];

	u8         uar_4k[0x1];
	u8         reserved_at_241[0x9];
	u8         uar_sz[0x6];
	u8         reserved_at_250[0x8];
	u8         log_pg_sz[0x8];

	u8         bf[0x1];
	u8         driver_version[0x1];
	u8         pad_tx_eth_packet[0x1];
	u8         reserved_at_263[0x8];
	u8         log_bf_reg_size[0x5];

	u8         reserved_at_270[0xb];
	u8         lag_master[0x1];
	u8         num_lag_ports[0x4];

	u8         reserved_at_280[0x10];
	u8         max_wqe_sz_sq[0x10];

	u8         reserved_at_2a0[0x10];
	u8         max_wqe_sz_rq[0x10];

	u8         max_flow_counter_31_16[0x10];
	u8         max_wqe_sz_sq_dc[0x10];

	u8         reserved_at_2e0[0x7];
	u8         max_qp_mcg[0x19];

	u8         reserved_at_300[0x10];
	u8         flow_counter_bulk_alloc[0x08];
	u8         log_max_mcg[0x8];

	u8         reserved_at_320[0x3];
	u8         log_max_transport_domain[0x5];
	u8         reserved_at_328[0x3];
	u8         log_max_pd[0x5];
	u8         reserved_at_330[0xb];
	u8         log_max_xrcd[0x5];

	u8         nic_receive_steering_discard[0x1];
	u8         receive_discard_vport_down[0x1];
	u8         transmit_discard_vport_down[0x1];
	u8         reserved_at_343[0x5];
	u8         log_max_flow_counter_bulk[0x8];
	u8         max_flow_counter_15_0[0x10];


	u8         reserved_at_360[0x3];
	u8         log_max_rq[0x5];
	u8         reserved_at_368[0x3];
	u8         log_max_sq[0x5];
	u8         reserved_at_370[0x3];
	u8         log_max_tir[0x5];
	u8         reserved_at_378[0x3];
	u8         log_max_tis[0x5];

	u8         basic_cyclic_rcv_wqe[0x1];
	u8         reserved_at_381[0x2];
	u8         log_max_rmp[0x5];
	u8         reserved_at_388[0x3];
	u8         log_max_rqt[0x5];
	u8         reserved_at_390[0x3];
	u8         log_max_rqt_size[0x5];
	u8         reserved_at_398[0x3];
	u8         log_max_tis_per_sq[0x5];

	u8         ext_stride_num_range[0x1];
	u8         reserved_at_3a1[0x2];
	u8         log_max_stride_sz_rq[0x5];
	u8         reserved_at_3a8[0x3];
	u8         log_min_stride_sz_rq[0x5];
	u8         reserved_at_3b0[0x3];
	u8         log_max_stride_sz_sq[0x5];
	u8         reserved_at_3b8[0x3];
	u8         log_min_stride_sz_sq[0x5];

	u8         hairpin[0x1];
	u8         reserved_at_3c1[0x2];
	u8         log_max_hairpin_queues[0x5];
	u8         reserved_at_3c8[0x3];
	u8         log_max_hairpin_wq_data_sz[0x5];
	u8         reserved_at_3d0[0x3];
	u8         log_max_hairpin_num_packets[0x5];
	u8         reserved_at_3d8[0x3];
	u8         log_max_wq_sz[0x5];

	u8         nic_vport_change_event[0x1];
	u8         disable_local_lb_uc[0x1];
	u8         disable_local_lb_mc[0x1];
	u8         log_min_hairpin_wq_data_sz[0x5];
	u8         reserved_at_3e8[0x3];
	u8         log_max_vlan_list[0x5];
	u8         reserved_at_3f0[0x3];
	u8         log_max_current_mc_list[0x5];
	u8         reserved_at_3f8[0x3];
	u8         log_max_current_uc_list[0x5];

	u8         general_obj_types[0x40];

	u8         reserved_at_440[0x20];

	u8         reserved_at_460[0x10];
	u8         max_num_eqs[0x10];

	u8         reserved_at_480[0x3];
	u8         log_max_l2_table[0x5];
	u8         reserved_at_488[0x8];
	u8         log_uar_page_sz[0x10];

	u8         reserved_at_4a0[0x20];
	u8         device_frequency_mhz[0x20];
	u8         device_frequency_khz[0x20];

	u8         reserved_at_500[0x20];
	u8	   num_of_uars_per_page[0x20];

	u8         flex_parser_protocols[0x20];
	u8         reserved_at_560[0x20];

	u8         reserved_at_580[0x3c];
	u8         mini_cqe_resp_stride_index[0x1];
	u8         cqe_128_always[0x1];
	u8         cqe_compression_128[0x1];
	u8         cqe_compression[0x1];

	u8         cqe_compression_timeout[0x10];
	u8         cqe_compression_max_num[0x10];

	u8         reserved_at_5e0[0x10];
	u8         tag_matching[0x1];
	u8         rndv_offload_rc[0x1];
	u8         rndv_offload_dc[0x1];
	u8         log_tag_matching_list_sz[0x5];
	u8         reserved_at_5f8[0x3];
	u8         log_max_xrq[0x5];

	u8	   affiliate_nic_vport_criteria[0x8];
	u8	   native_port_num[0x8];
	u8	   num_vhca_ports[0x8];
	u8	   reserved_at_618[0x6];
	u8	   sw_owner_id[0x1];
	u8	   reserved_at_61f[0x1e1];
};

struct mlx5_ifc_qos_cap_bits {
	u8         packet_pacing[0x1];
	u8         esw_scheduling[0x1];
	u8         esw_bw_share[0x1];
	u8         esw_rate_limit[0x1];

	u8         reserved_at_4[0x1];

	u8         packet_pacing_burst_bound[0x1];
	u8         packet_pacing_typical_size[0x1];
	u8         flow_meter_srtcm[0x1];

	u8         reserved_at_8[0x8];

	u8         log_max_flow_meter[0x8];

	u8         flow_meter_reg_id[0x8];
	u8         reserved_at_25[0x20];

	u8         packet_pacing_max_rate[0x20];

	u8         packet_pacing_min_rate[0x20];

	u8         reserved_at_80[0x10];
	u8         packet_pacing_rate_table_size[0x10];

	u8         esw_element_type[0x10];
	u8         esw_tsar_type[0x10];

	u8         reserved_at_c0[0x10];
	u8         max_qos_para_vport[0x10];

	u8         max_tsar_bw_share[0x20];

	u8         reserved_at_100[0x6e8];
};

union mlx5_ifc_hca_cap_union_bits {
	struct mlx5_ifc_cmd_hca_cap_bits cmd_hca_cap;
	struct mlx5_ifc_qos_cap_bits qos_cap;
	u8         reserved_at_0[0x8000];
};

struct mlx5_ifc_query_hca_cap_out_bits {
	u8         status[0x8];
	u8         reserved_at_8[0x18];

	u8         syndrome[0x20];

	u8         reserved_at_40[0x40];

	union mlx5_ifc_hca_cap_union_bits capability;
};

struct mlx5_ifc_query_hca_cap_in_bits {
	u8         opcode[0x10];
	u8         reserved_at_10[0x10];

	u8         reserved_at_20[0x10];
	u8         op_mod[0x10];

	u8         reserved_at_40[0x40];
};

/* General objects */

struct mlx5_ifc_general_obj_in_cmd_hdr_bits {
	u8         opcode[0x10];
	u8         uid[0x10];

	u8         reserved_at_20[0x10];
	u8         obj_type[0x10];

	u8         obj_id[0x20];

	u8         reserved_at_60[0x20];
};

struct mlx5_ifc_general_obj_out_cmd_hdr_bits {
	u8         status[0x8];
	u8         reserved_at_8[0x18];

	u8         syndrome[0x20];

	u8         obj_id[0x20];

	u8         reserved_at_60[0x20];
};

struct mlx5_ifc_flow_meter_parameters_bits {
	u8         valid[0x1];			// 00h
	u8         bucket_overflow[0x1];
	u8         start_color[0x2];
	u8         both_buckets_on_green[0x1];
	u8         meter_mode[0x2];
	u8         reserved_at_1[0x19];

	u8         reserved_at_2[0x20]; //04h

	u8         reserved_at_3[0x3];
	u8         cbs_exponent[0x5];		// 08h
	u8         cbs_mantissa[0x8];
	u8         reserved_at_4[0x3];
	u8         cir_exponent[0x5];
	u8         cir_mantissa[0x8];

	u8         reserved_at_5[0x20];		// 0Ch

	u8         reserved_at_6[0x3];
	u8         ebs_exponent[0x5];		// 10h
	u8         ebs_mantissa[0x8];
	u8         reserved_at_7[0x3];
	u8         eir_exponent[0x5];
	u8         eir_mantissa[0x8];

	u8         reserved_at_8[0x60];		// 14h-1Ch
};

enum {
	MLX5_FLOW_METER_OBJ_MODIFY_FIELD_ACTIVE = (1ULL << 0),
	MLX5_FLOW_METER_OBJ_MODIFY_FIELD_CBS = (1ULL << 1),
	MLX5_FLOW_METER_OBJ_MODIFY_FIELD_CIR = (1ULL << 2),
	MLX5_FLOW_METER_OBJ_MODIFY_FIELD_EBS = (1ULL << 3),
	MLX5_FLOW_METER_OBJ_MODIFY_FIELD_EIR = (1ULL << 4),
};

struct mlx5_ifc_flow_meter_obj_bits {
	u8         modify_field_select[0x40];	// 0h-07h
	u8         active[0x1];			// 08h
	u8         reserved_at_1[0x3];
	u8         return_reg_id[0x4];
	u8         table_type[0x8];
	u8         reserved_at_50[0x10];
	u8         reserved_at_60[0x8];		//10h
	u8         destination_table_id[0x18];
	u8         reserved_at_80[0x80];		// 14h-1Fh
	struct mlx5_ifc_flow_meter_parameters_bits flow_meter_params; // 20h-3Ch
	u8         reserved_at_180[0x180];
	u8         sw_steering_icm_address_rx[0x40];
	u8         sw_steering_icm_address_tx[0x40];
};

struct mlx5_ifc_create_flow_meter_in_bits {
	struct mlx5_ifc_general_obj_in_cmd_hdr_bits   hdr;
	struct mlx5_ifc_flow_meter_obj_bits           obj;
};

struct mlx5_ifc_query_flow_meter_out_bits {
	struct mlx5_ifc_general_obj_out_cmd_hdr_bits  hdr;
	struct mlx5_ifc_flow_meter_obj_bits           obj;
};

/* mlx5_devx_cmds.c */
struct mlx5_flow_meter_srtcm_rfc2697_prm;

int mlx5_devx_cmd_fc_alloc(struct ibv_context *ctx,
			   struct mlx5_devx_counter_set *dcs,
			   uint8_t bulk_sz);
int mlx5_devx_cmd_fc_free(struct mlx5dv_devx_obj *obj);
int mlx5_devx_cmd_fc_query(struct mlx5_devx_counter_set *dcs,
			   int clear, uint64_t *pkts, uint64_t *bytes,
		       	   uint32_t batch, uint32_t mkey __rte_unused,
			   struct rte_flow_count_value *addr,
			   void *cb_arg, void *cmd_comp);
void mlx5_devx_cmd_fc_query_callback(int ret, int syndrome, void *arg);
struct mlx5_devx_mkey *mlx5_create_mkey(struct ibv_context *ctx,
					struct mlx5_devx_mkey_attr *mkey_attr);
int mlx5_devx_cmd_query_hca_attr(struct ibv_context *ctx,
				 struct mlx5_hca_attr *attr);
int mlx5_devx_cmd_flow_meter_modify
			(struct mlx5_flow_meter *fm,
			 struct mlx5_flow_meter_srtcm_rfc2697_prm *srtcm,
			 uint64_t modify_bits, uint32_t active_state);
#ifdef HAVE_MLX5_DR_CREATE_ACTION_FLOW_METER
void mlx5_devx_cmd_flow_meter_fill_params(struct ibv_context *ctx,
					  struct mlx5_flow_meter *fm);
#endif

#endif /* RTE_PMD_MLX5_DEVX_CMDS_H_ */
