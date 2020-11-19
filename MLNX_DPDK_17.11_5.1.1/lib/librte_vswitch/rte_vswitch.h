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
#ifndef _RTE_VSWITCH_H_
#define _RTE_VSWITCH_H_

#include <rte_ethdev.h>
#include <rte_flow.h>

#define RTE_VSWITCH_QUERY_STATUS (1u << 0)
#define RTE_VSWITCH_QUERY_COUNTER (1u << 1)
#define RTE_VSWITCH_QUERY_COUNTER_CACHE (1u << 2)

/**
 * Opaque type returned after successfully creating an offloaded flow.
 *
 */
struct rte_vswitch_offload_flow;

/**
 * Library Context returned after library init and being used as an input for
 * every library call.
 */
struct rte_vswitch_ctx;

struct rte_vswitch_flow_status {
	uint8_t valid:1; /* 0 if the flow was flushed or aged */
	uint8_t hw_valid:1; /* 0 if the flow was aged. */
	struct rte_flow_count_value stats;
};

struct rte_vswitch_meter_stats {
	uint64_t n_pkts;
	uint64_t n_bytes;
	uint64_t n_pkts_dropped;
	uint64_t n_bytes_dropped;
};

struct rte_vswitch_flow_action_vxlan_encap {
	struct ether_hdr ether;
	struct ipv4_hdr ipv4;
	struct udp_hdr udp;
	/**< destination udp port for vxlan encapsulation. */
	union {
		struct vxlan_hdr vxlan;
		struct {
			uint32_t vxlan_flags:8;
			uint32_t vxlan_rsvd0:16;
			uint32_t vxlan_protocol:8;
			/**< Used in case of VXLAN-GPE otherwise reserved. */
			uint32_t vxlan_vni:24; /**< VXLAN identifier */
			uint32_t vxlan_rsvd1:8; /**< Reserved, always 0x00 */
		};
	};
} __attribute__((__packed__));

struct rte_vswitch_action_modify_packet {
	uint16_t set_src_mac:1;
	uint16_t set_dst_mac:1;
	uint16_t set_dst_ip4:1;
	uint16_t set_src_ip4:1;
	uint16_t set_dst_ip6:1;
	uint16_t set_src_ip6:1;
	uint16_t set_dst_port:1;
	uint16_t set_src_port:1;
	uint16_t set_ttl:1;
	uint16_t dec_ttl:1;
	uint16_t dec_tcp_seq:1;
	uint16_t dec_tcp_ack:1;
	uint16_t inc_tcp_seq:1;
	uint16_t inc_tcp_ack:1;
	struct ether_addr dst_mac;
	struct ether_addr src_mac;
	uint32_t dst_ip4;
	uint32_t src_ip4;
	uint8_t src_ip6[16];
	uint8_t dst_ip6[16];
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t ttl;
	uint32_t tcp_seq;
	uint32_t tcp_ack;
};

struct rte_vswitch_meter_profile {
	uint64_t bps;
};

struct rte_vswitch_flow_actions {
	uint8_t count:1;
	uint8_t meter:1;
	/**< enable counter when set to 1, ignored otherwise */
	uint8_t decap:1;
	/**< decap outer headers when set to 1, ignored otherwise. */
	uint8_t remove_ethernet:1;
	/**< remove ethernet headers when set to 1, ignored otherwise. */
	uint16_t vport_id; /**< destination output vport */
	uint16_t timeout;
	/**< idle timeout in seconds granularity, ignored when set to 0 */
	struct rte_vswitch_flow_action_vxlan_encap *encap;
	/**< ignored when set to NULL */
	struct ether_hdr *add_ethernet;
	/**< ignored when set to NULL */
	struct rte_vswitch_action_modify_packet *modify;
	/**< ignored when set to NULL */
	uint32_t meter_id;
};

struct rte_vswitch_tcp_flags {
	union {
		struct {
			uint8_t fin:1;
			uint8_t syn:1;
			uint8_t rst:1;
			uint8_t psh:1;
			uint8_t ack:1;
			uint8_t urg:1;
			uint8_t reserved:2;
		};
		uint8_t flags;
	};
};

struct rte_vswitch_flow_keys_base {
	uint16_t ip_type:1; /**< 0 ipv4, 1 ipv6 */
	uint16_t src_addr_valid:1;
	uint16_t dst_addr_valid:1;
	uint16_t proto_valid:1;
	uint16_t src_port_valid:1;
	uint16_t dst_port_valid:1;
	struct rte_vswitch_tcp_flags tcp_flags_valid;
	union {
		uint32_t src_addr; /**< source ipv4 address. */
		uint8_t  src_addr6[16]; /**< source ipv6 address. */
	};
	union {
		uint32_t dst_addr; /**< destination ipv4 address. */
		uint8_t  dst_addr6[16]; /**< destination ipv6 address. */
	};
	uint8_t  proto; /**< protocol ID. must be set to match L4 ports.*/
	uint16_t src_port; /**< L4 source port, ignored when set to 0 */
	uint16_t dst_port; /**< L4 destination port, ignored when set to 0 */
	struct rte_vswitch_tcp_flags tcp_flags; /**< TCP flags */
	uint8_t icmp_type; /**< ICMP type. */
};

enum rte_vswitch_tunnel_type {
	RTE_VSWITCH_TUNNEL_TYPE_NONE,
	RTE_VSWITCH_TUNNEL_TYPE_VXLAN,
	RTE_VSWITCH_TUNNEL_TYPE_VXLAN_GPE,
};

struct rte_vswitch_flow_keys {
	struct rte_vswitch_flow_keys_base outer;
	enum rte_vswitch_tunnel_type tunnel_type;
	uint32_t flags_valid:1;
	/**< marks if the flags field is valid. only valid in vxlan-gpe. */
	uint32_t protocol_valid:1;
	/**< marks if the protocol field is valid. only valid in vxlan-gpe. */
	union {
		struct vxlan_hdr vxlan;
		struct {
			uint32_t flags:8; /**< vxlan flags. */
			uint32_t rsvd0:16; /**< Reserved, normally 0x0000. */
			uint32_t protocol:8; /**< vxlan protocol. */
			uint32_t vni:24; /**< vxlan vni */
			uint32_t rsvd1:8; /**< Reserved, normally 0x00. */
		};
	};
	struct rte_vswitch_flow_keys_base inner;
	/**< inner packet ignored when tunnel_type is none. */
};

enum rte_vswitch_mark_type {
	RTE_VSWITCH_MARK_TYPE_UNKNOWN,
	/**< unknown mark type. */
	RTE_VSWITCH_MARK_TYPE_VPORT_FLOW,
	/**< the packet should be forwarded to the vport. */
	RTE_VSWITCH_MARK_TYPE_UNKNOWN_VPORT_FLOW,
	/**< no policy to the packet comes from the vport. */
};

/*
 * lib will set mark id according to below convention.
 */
struct rte_vswitch_mark_id {
	enum rte_vswitch_mark_type type;
	uint16_t vport_id;
};

struct rte_vswitch_offload_flow_stats {
	uint64_t n_flows;		/**< number of total flows */
	uint64_t n_tx_flows;		/**< number of flows from VM to PF */
	uint64_t n_rx_flows;		/**< number of flows from PF to VM */
	uint64_t n_nc_flows;		/**< number of flows from VM to VM */
};

/**
 * Helper function to translate mbufs mark id to application
 * inputs.
 *
 * @param ctx
 *   Pointer to the lib context.
 * @param mark_id
 *   Mbuf's mark id.
 *
 * @return
 *   Translation of mark id into application parameters.
 */
struct rte_vswitch_mark_id
rte_vswitch_translate_mark_id(struct rte_vswitch_ctx* ctx,
			      uint32_t mark_id);
/**
 * Helper function to get the metadata for packet sent from
 * a vport.
 *
 * @param ctx
 *   Pointer to the lib context.
 * @param vport_id
 *   The vport to register.
 *
 * @return
 *   The metadata value to set in the mbuf.
 */
uint32_t
rte_vswitch_get_vport_metadata(struct rte_vswitch_ctx* ctx,
			       uint16_t vport_id);
enum rte_vswitch_type {
	RTE_VSWITCH_TYPE_VIRTIO,
	RTE_VSWITCH_TYPE_SRIOV,
	RTE_VSWITCH_TYPE_UNKNOWN,
};

/**
 * Initialize library contexts.
 * The libary should init for each PF on the host. The vports namespace is
 * per PF (meaning they can be numerated independently).
 * That means each PF has its own vswitch, and packet cannot be forwarded
 * using this libary between the different vswitches.
 * Following a successful libary init, the exception path for the PF will
 * be created.
 *
 * @param pf
 *   Pointer to the PF ethernet device.
 * @param pf_vport_id
 *   The PF assigned vport id.
 * @param max_vport_id
 *   The maximum vport id exists on the PF vswitch.
 * @param
 *   The maximum vport id exists on the PF vswitch.
 *
 * @return
 *   A valid handle in case of success, NULL otherwise.
 */
struct rte_vswitch_ctx *
rte_vswitch_open(struct rte_eth_dev *pf, uint16_t pf_vport_id,
		 uint16_t max_vport_id, enum rte_vswitch_type type);

/**
 * Close library contexts.
 *
 * @param ctx
 *   Pointer to the lib context.
 *
 * @return
 *   0 in case of success, a negative errno otherwise.
 */
int
rte_vswitch_close(struct rte_vswitch_ctx *ctx);

/**
 * Register a virtual port to the library.
 * In case the vport is backed-up with an ethdev, user should provide it.
 * After a successful registration the exception path for the vport will
 * be created.
 *
 * @param ctx
 *   Pointer to the lib context.
 * @param vport_id
 *   The vport to register.
 * @param vport_rep
 *   Pointer to the vport ethernet device if exists, null otherwise.
 *
 * @return
 *   0 in case of success, a negative errno otherwise.
 */
int
rte_vswitch_register_vport(struct rte_vswitch_ctx *ctx, uint16_t vport_id,
			   struct rte_eth_dev *vport_rep);

/**
 * Un-register a virtual port to the library.
 * After a successful un-registration the exception path for the vport will
 * be removed.
 *
 * @param ctx
 *   Pointer to the lib context.
 * @param vport_id
 *   The vport to register.
 *
 * @return
 *   0 in case of success, a negative errno otherwise.
 */
int
rte_vswitch_unregister_vport(struct rte_vswitch_ctx *ctx, uint16_t vport_id);

/**
 * Create an offload flow rule.
 *
 * Using offload flow rule traffic can be redirected between two vports, while
 * the packet is being modified on the flight.
 *
 * Counter can be associated with a flow for monitoring purposes.
 *
 * Offload flow can be subject to aging, and will be removed by the lib
 * when its timeout expires.
 *
 * @param ctx
 *   Pointer to the lib context.
 * @param vport_id
 *   The vport to register.
 * @param[in] keys
 *   Flow rule match fields.
 * @param[in] actions
 *   Associated actions.
 *
 * @return
 *   A valid flow handle in case of success, NULL otherwise.
 */
struct rte_vswitch_offload_flow *
rte_vswitch_create_offload_flow(struct rte_vswitch_ctx *ctx,
				uint16_t vport_id,
				struct rte_vswitch_flow_keys *keys,
				struct rte_vswitch_flow_actions *actions);
/**
 * Print an offload flow parameters.
 *
 * @param ctx
 *   Pointer to the lib context.
 * @param vport_id
 *   The vport to register.
 * @param[in] keys
 *   Flow rule match fields.
 * @param[in] actions
 *   Associated actions.
 */
void
rte_vswitch_print_offload_flow_params(struct rte_vswitch_ctx *ctx,
			       uint16_t vport_id,
			       struct rte_vswitch_flow_keys *keys,
			       struct rte_vswitch_flow_actions *actions);

/**
 * Destroys and offload flow rule.
 *
 * @param ctx
 *   Pointer to the lib context.
 * @param flow
 *   Pointer to the flow to delete.
 *
 * @return
 *   0 in case of success, a negative errno otherwise.
 */

int
rte_vswitch_destroy_offload_flow(struct rte_vswitch_ctx *ctx,
				 struct rte_vswitch_offload_flow *flow);

/**
 * Create meter and attached it to vport.
 * Each vport can have multiple meters, but a meter can't be
 * shared between two vports.
 *
 * @param ctx
 *   Pointer to the lib context.
 * @param meter_id
 *   Meter ID to be used.
 * @param profile
 *   Profile to be used.
 *
 * @return
 *   0 in case of success, a negative errno otherwise.
 */
int
rte_vswitch_create_meter(struct rte_vswitch_ctx *ctx,
			 uint32_t meter_id,
			 struct rte_vswitch_meter_profile *profile);

/* Create a meter and generate a unique ID for it */
int
rte_vswitch_generate_meter(struct rte_vswitch_ctx *ctx,
			   uint32_t *meter_id,
			   struct rte_vswitch_meter_profile *profile);

/**
 * Update meter with a new profile.
 *
 * @param ctx
 *   Pointer to the lib context.
 * @param meter_id
 *   Meter ID to be used.
 * @param profile
 *   Profile to be used.
 *
 * @return
 *   0 in case of success, a negative errno otherwise.
 */
int
rte_vswitch_update_meter(struct rte_vswitch_ctx *ctx, uint32_t meter_id,
			 struct rte_vswitch_meter_profile *new_profile);

/**
 * Query the meter stats.
 *
 * @param ctx
 *   Pointer to the lib context.
 * @param meter_id
 *   Meter ID to be used.
 * @param stats
 *   The measured statistics.
 *
 * @return
 *   0 in case of success, a negative errno otherwise.
 */
int
rte_vswitch_query_meter(struct rte_vswitch_ctx *ctx, uint32_t meter_id,
						struct rte_vswitch_meter_stats* stats);


/**
 * Enable the meter.
 *
 * @param ctx
 *   Pointer to the lib context.
 * @param meter_id
 *   Meter ID to be used.
 *
 * @return
 *   0 in case of success, a negative errno otherwise.
 */
int
rte_vswitch_enable_meter(struct rte_vswitch_ctx *ctx, uint32_t meter_id);

/**
 * Disable the meter by putting it in pass-through mode.
 * @param ctx
 *   Pointer to the lib context.
 * @param meter_id
 *   Meter ID to be used.
 *
 * @return
 *   0 in case of success, a negative errno otherwise.
 */
int
rte_vswitch_disable_meter(struct rte_vswitch_ctx *ctx, uint32_t meter_id);

/**
 * Destroy the meter.
 *
 * @param ctx
 *   Pointer to the lib context.
 * @param meter_id
 *   Meter ID to be used.
 *
 * @return
 *   0 in case of success, a negative errno otherwise.
 */
int
rte_vswitch_destroy_meter(struct rte_vswitch_ctx *ctx, uint32_t meter_id);

/**
 * Modify flow timeout.
 *
 * @param ctx
 *   Pointer to the lib context.
 * @param flow
 *   Pointer to the flow to modify.
 * @param timeout
 *   Flow expire time in second.
 *
 * @return
 *   0 in case of success, a negative errno otherwise.
 */
int
rte_vswitch_modify_offload_flow(struct rte_vswitch_ctx *ctx,
				struct rte_vswitch_offload_flow *oflow,
				uint16_t timeout);

/**
 * Detach the vport offloaded flows.
 *
 * Following a successful call packet will no longer be able to match
 * any of the vport offload rules.
 * All the vport rules will be marked as invalid. User should cleanup those
 * stall handles by explicit call to rte_vswitch_destroy_offload_flow.
 *
 * @param ctx
 *   Pointer to the lib context.
 * @param vport_id
 *   The vport to register.
 * @param metadata
 *   The pointer to the vport metadata.
 *
 * @return
 *   0 and updated metadata in case of success, a negative errno otherwise.
 */
int
rte_vswitch_flush_vport_offload_flows(struct rte_vswitch_ctx *ctx,
				      uint16_t vport_id, uint32_t *metadata);

/**
 * Detach all vports offloaded flows and flush all meters.
 *
 * Following a successful call packet will no longer be able to match
 * any of the vport offload rules.
 * All the vport rules will be marked as invalid. User should cleanup those
 * stall handles by explicit call to rte_vswitch_destroy_flow.
 * All meters will be destroyed and resource released from hardware.
 *
 * @param ctx
 *   Pointer to the lib context.
 *
 * @return
 *    0 in case of success, a negative errno otherwise.
 *    In case of success all the vports metadata was updated - use
 *    rte_vswitch_get_vport_metadata API to get them.
 */
int
rte_vswitch_flush_all(struct rte_vswitch_ctx *ctx);

/**
 * Returns flow information based on flags.
 *
 * flows that cannot match packet anymore (e.g. aged flows or flows of
 * some vport following rte_vswitch_flush_vport_offload_flows) are counted
 * as invalid.
 *
 * @param ctx
 *   Pointer to the lib context.
 * @param vport_id
 *   The vport to register.
 * @param flow
 *   Pointer to the flow to query.
 * @param flags
 *   Flags for the query. see RTE_VSWITCH_QUERY_*.
 * @param[out] status
 *   Pointer to the output query structure.
 *
 *
 * @return
 *   0 in case of success, a negative errno otherwise.
 */
int
rte_vswitch_offload_flow_query(struct rte_vswitch_ctx *ctx,
			       uint16_t vport_id,
			       struct rte_vswitch_offload_flow *flow,
			       uint32_t flags,
			       struct rte_vswitch_flow_status *status);

/**
 * Wrapper of rte_eth_dev_configure in order to save settings
 * needed during restart
 */
int
rte_vswitch_vport_configure(uint16_t port_id, uint16_t nb_rx_q,
			    uint16_t nb_tx_q,
			    const struct rte_eth_conf *dev_conf);
/**
 * Wrapper of rte_eth_rx_queue_setup in order to save settings
 * needed during restart
 */
int
rte_vswitch_vport_rx_queue_setup(uint16_t port_id, uint16_t rx_queue_id,
				 uint16_t nb_rx_desc, unsigned int socket_id,
				 const struct rte_eth_rxconf *rx_conf,
				 struct rte_mempool *mp);
/**
 * Wrapper of rte_eth_tx_queue_setup in order to save settings
 * needed during restart
 */
int
rte_vswitch_vport_tx_queue_setup(uint16_t port_id, uint16_t tx_queue_id,
				 uint16_t nb_tx_desc, unsigned int socket_id,
				 const struct rte_eth_txconf *tx_conf);
/**
 * Wrapper of rte_flow_isolate in order to save settings
 * needed during restart
 */
int
rte_vswitch_vport_isolate(uint16_t port_id, int set,
			  struct rte_flow_error *error);

/**
 * initiate vswitch restart after firmware reset triggered.
 *
 * This function will wait for the RTE_ETH_EVENT_INTR_RMV
 * When the RTE_ETH_EVENT_INTR_RMV event is detected,
 * it will restart the vswitch.
 *
 * @note
 *   The vport's metadata will be updated in the first flow creation
 *   after this vswitch restart
 *
 * @param ctx
 *   Pointer to the lib context.
 * @param vport_id
 *   The vport to register.
 *
 * @return
 *   0 in case of success, a negative errno otherwise.
 */
int
rte_vswitch_hotplug_restart(struct rte_vswitch_ctx *ctx);

/**
 * Query the number of offload flows that remaining in the system with
 * different types.
 *
 * @param ctx
 *   Pointer to the lib context.
 * @param[out] stats
 *   Pointer to the output statistics structure.
 *
 * @return
 *   0 in case of success, a negative errno otherwise.
 */
int
rte_vswitch_offload_flow_stats_query(struct rte_vswitch_ctx *ctx,
			struct rte_vswitch_offload_flow_stats *stats);


#endif /* _RTE_VSWITCH_H_ */
