/*-
 *   BSD LICENSE
 *
 *   Copyright 2019 Mellanox.
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
 *     * Neither the name of Mellanox. nor the names of its
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

#include <stdio.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_net.h>
#include <rte_vswitch.h>

#define MAX_VPORT_INDEX 7
#define PF_VPORT_ID 0
#define VSWITCH_TIMEOUT 44
#define VSWITCH_METER_EN 1
#define DEBUG 0
#define VSWITCH_PRINT(...) if (DEBUG) printf(__VA_ARGS__)

/*
 * This application shows vswitch API usage in VIRTIO mode.
 * The application works with all the EAL cores while each core is dedicated
 * for different RX queue.
 * The application works only with one physical port and without any vhost
 * devices, due that, the VM vports traffic comes from the wire as the real
 * fabric traffic, So, when a packet is not marked as a vswitch packet this
 * example considers it as a VM traffic. which VM? the VM vport ID as in the
 * source IPv4 address.(assuming only IPv4 packets). because of that, the
 * example doesn't configure isolated mode .
 * The IPv4 address of each vport (including the PF) is the vport ID.
 * The example configures vswitch offload flows from all the vports to all the
 * vports and shows statistics for each flow.
 * Find more details\comments in the relevant code section below.
 */

volatile bool force_quit;

uint8_t port_id;
uint16_t nr_queues;
struct rte_mempool *mbuf_pool;
struct rte_vswitch_ctx *vctx;
struct rte_vswitch_offload_flow *pf_oflows[MAX_VPORT_INDEX + 1];
struct rte_vswitch_offload_flow *vm_oflows_to_pf[MAX_VPORT_INDEX + 1];
struct rte_vswitch_offload_flow *
	vm_oflows_to_vm[MAX_VPORT_INDEX + 1][MAX_VPORT_INDEX + 1];

static void
vswitch_print_stats(void)
{
	struct rte_vswitch_flow_status status;
	uint32_t vportid, vport_dst;

	printf("Statistics:\n");
	for (vportid = 1; vportid <= MAX_VPORT_INDEX; ++vportid) {
		printf("vport %hu(PF) to vport %hu(VM):",
		       PF_VPORT_ID, vportid);
		memset(&status, 0, sizeof(status));
		if (rte_vswitch_offload_flow_query(vctx, PF_VPORT_ID,
						   pf_oflows[vportid],
						   RTE_VSWITCH_QUERY_STATUS |
						   RTE_VSWITCH_QUERY_COUNTER,
						   &status) == 0) {
			if (status.valid)
				printf("\tPackets: %lu\tBytes: %lu\n",
				       status.stats.hits, status.stats.bytes);
			else if (status.hw_valid)
				printf("\tFlow is invalid - was flushed\n");
			else
				printf("\tFlow is invalid - was aged\n");
		} else {
			printf("\tQuery failed\n");
		}
	}
	for (vportid = 1; vportid <= MAX_VPORT_INDEX; ++vportid) {
		printf("vport %hu(VM) to vport %hu(PF):",
		       vportid, PF_VPORT_ID);
		memset(&status, 0, sizeof(status));
		if (rte_vswitch_offload_flow_query(vctx, vportid,
						   vm_oflows_to_pf[vportid],
						   RTE_VSWITCH_QUERY_STATUS |
						   RTE_VSWITCH_QUERY_COUNTER,
						   &status) == 0) {
			if (status.valid)
				printf("\tPackets: %lu\tBytes: %lu\n",
				       status.stats.hits, status.stats.bytes);
			else if (status.hw_valid)
				printf("\tFlow is invalid - was flushed\n");
			else
				printf("\tFlow is invalid - was aged\n");
		} else {
			printf("\tQuery failed\n");
		}
	}
	for (vportid = 1; vportid <= MAX_VPORT_INDEX; ++vportid) {
		for (vport_dst = 1; vport_dst <= MAX_VPORT_INDEX; ++vport_dst) {
			if (vportid == vport_dst)
				continue;
			printf("vport %hu(VM) to vport %hu(VM):", vportid,
			       vport_dst);
			memset(&status, 0, sizeof(status));
			if (rte_vswitch_offload_flow_query(vctx, vportid,
					vm_oflows_to_vm[vportid][vport_dst],
					RTE_VSWITCH_QUERY_STATUS |
					RTE_VSWITCH_QUERY_COUNTER,
					&status) == 0) {
				if (status.valid)
					printf("\tPackets: %lu\tBytes: %lu\n",
					       status.stats.hits, status.stats.bytes);
				else if (status.hw_valid)
					printf("\tFlow is invalid - was flushed\n");
				else
					printf("\tFlow is invalid - was aged\n");
			} else {
				printf("\tQuery failed\n");
			}
		}
	}
	printf("Statistics for all meters:\n");
	for (vportid = 0; vportid <= MAX_VPORT_INDEX; ++vportid) {
		struct rte_vswitch_meter_stats mtr_stats;

		memset(&mtr_stats, 0, sizeof(mtr_stats));
		if(!rte_vswitch_query_meter(vctx, vportid, &mtr_stats))
			printf("\tmeter id %u:\n"
			       "\t\tdropped: pkts: %lu, bytes:"
			       " %lu\n"
			       "\t\tpassed: pkts: %lu, bytes:"
			       " %lu\n",
			       vportid, mtr_stats.n_pkts_dropped,
			       mtr_stats.n_bytes_dropped,
			       mtr_stats.n_pkts,
			       mtr_stats.n_bytes
			);
		else
			printf("\tERROR: cannot query meter %u\n", vportid);
	}
}

static int
vswitch_create_tunnel_offload_flows(void)
{
	static struct rte_vswitch_flow_keys keys =
		{
			.outer = {
				.ip_type = 0, /* 0 for IPv4 */
				.src_addr_valid = 0,
				.dst_addr_valid = 0,
				.proto_valid = 1,
				.src_port_valid = 0,
				.dst_port_valid = 1,
				.tcp_flags_valid = {
					.flags = 0,
				},
				.src_addr = 0,
				.dst_addr = 0,
				.proto = IPPROTO_UDP,
				.src_port = 0,
				.dst_port = RTE_BE16(250),
				.tcp_flags = {
					.flags = 0,
				},
			},
			.tunnel_type = RTE_VSWITCH_TUNNEL_TYPE_VXLAN,
			.vni = RTE_BE32(0x20) >> 8,
			.inner = {
				.ip_type = 0,
				.src_addr_valid = 1,
				.dst_addr_valid = 1,
				.proto_valid = 1,
				.src_port_valid = 1,
				.dst_port_valid = 1,
				.tcp_flags_valid = {
					.flags = 0,
				},
				.src_addr = RTE_BE32(PF_VPORT_ID),
				.dst_addr = RTE_BE32(0x00000001),
				.proto = IPPROTO_UDP,
				.src_port = RTE_BE16(0),
				.dst_port = RTE_BE16(0),
				.tcp_flags = {
					.flags = 0,
				},
			},
		};
	static struct ether_hdr eth = {
		.d_addr = {
			.addr_bytes = {0x00, 0x37, 0x44, 0x9A, 0x0D, 0xFF},
			},
		.s_addr = {
			.addr_bytes = {0x00, 0x38, 0x44, 0x9A, 0x0D, 0xFF},
			},
		.ether_type = RTE_BE16(ETHER_TYPE_IPv4),
	};
	static struct rte_vswitch_flow_actions actions = {
		.vport_id = 1, /* The destination vport ID */
		.count = 1, /* Count the flow matched packets */
		.decap = 1, /* Decapsulate the VXLAN outer packet */
		.meter = 0, /* Limit the traffic rate of this flow */
		.remove_ethernet = 0,
		.timeout = VSWITCH_TIMEOUT, /* Aging timeout */
		.encap = NULL,
		.add_ethernet = &eth,
		/* Add an Ethernet header after the decapsulation */
		.modify = NULL,
		.meter_id = 0,
	};
	uint32_t dst_vport;

	/*
	 * The next packet pattern will be matched by the next flow:
	 * Ether()/IP()/UDP(dport=250)/VXLAN(vni=0x20)/
	 * IP(src=PF_VPORT_ID,dst=dst VM vport id)/UDP(dport=0,sport=0)
	 * The action will be to decapsulate the tunnel header and to add an
	 * ethernet header: dst 00:37:44:9A:0D:0xFF src 00:38:44:9A:0D:0xFF
	 * type 0x800
	 * then, to get the packet via RSS queue with MARK related to the
	 * destination vport.
	 */
	for (dst_vport = 1; dst_vport <= MAX_VPORT_INDEX; ++dst_vport) {
		keys.inner.dst_addr = rte_cpu_to_be_32(dst_vport);
		actions.vport_id = dst_vport;
		pf_oflows[dst_vport] = rte_vswitch_create_offload_flow
				(vctx, PF_VPORT_ID, &keys, &actions);
		if (!pf_oflows[dst_vport]) {
			printf("cannot create an offload flow from vport %hu to"
			       " vport %hu\n", PF_VPORT_ID, dst_vport);
			return -1;
		}
	}
	return 0;
}

static int
vswitch_create_non_tunnel_offload_flows(void)
{
	static struct rte_vswitch_flow_keys keys =
		{
			.outer = {
				.ip_type = 0,
				.src_addr_valid = 1,
				.dst_addr_valid = 1,
				.proto_valid = 1,
				.src_port_valid = 1,
				.dst_port_valid = 1,
				.tcp_flags_valid = {
					.flags = 0,
				},
				.src_addr = RTE_BE32(0x00000001),
				.dst_addr = RTE_BE32(0x00000000),
				.proto = IPPROTO_UDP,
				.src_port = RTE_BE16(0),
				.dst_port = RTE_BE16(0),
				.tcp_flags = {
					.flags = 0,
				},
			},
			.tunnel_type = RTE_VSWITCH_TUNNEL_TYPE_NONE,
		};
	static struct rte_vswitch_flow_action_vxlan_encap encap = {
		.ether = {
			.d_addr = {
				.addr_bytes = {0x00, 0x37, 0x44, 0x9A, 0x0D, 0xFF},
				},
			.s_addr = {
				.addr_bytes = {0x00, 0x38, 0x44, 0x9A, 0x0D, 0xFF},
				},
			.ether_type = RTE_BE16(ETHER_TYPE_IPv4),
		},
		.ipv4 = {
			.version_ihl = (uint8_t)(0x45),
			.type_of_service = 0,
			.total_length = 0,
			.packet_id = 0,
			.fragment_offset = 0,
			.time_to_live = 64,
			.next_proto_id = IPPROTO_UDP,
			.hdr_checksum = 0,
			.src_addr = 0x03030303,
			.dst_addr = 0x04040404,
		},
		.udp = {
			.src_port = RTE_BE16(0xBBBB),
			.dst_port = RTE_BE16(250),
			.dgram_len = 0,
			.dgram_cksum = 0,
		},
		.vxlan_flags = 0x08,
		.vxlan_rsvd0 = 0,
		.vxlan_protocol = 0,
		.vxlan_vni = 0x50,
		.vxlan_rsvd1 = 0,
	};

	static struct rte_vswitch_flow_actions actions = {
		.vport_id = 0,
		.count = 1,
		.meter = VSWITCH_METER_EN,
		.decap = 0,
		.remove_ethernet = 1,
		.timeout = VSWITCH_TIMEOUT,
		.encap = &encap,
		.add_ethernet = NULL,
		.modify = NULL,
	};
	uint32_t dst_vport, src_vport;

	/*
	 * The next packet pattern will be matched by the next flow:
	 * Ether()/IP(src=src VM vport id,dst=PF_VPORT_ID)/UDP(dport=0,sport=0)
	 * The action will be to remove the ethernet header and to encapsulate
	 * the above tunnel header and to send it to the wire.
	 * This flow packet should come from a VM, so the datapath must set the
	 * vport meta-data in the mbuf.
	 */
	actions.vport_id = PF_VPORT_ID;
	actions.remove_ethernet = 1;
	actions.encap = &encap;
	keys.outer.dst_addr = RTE_BE32(PF_VPORT_ID);
	for (src_vport = 1; src_vport <= MAX_VPORT_INDEX; ++src_vport) {
		keys.outer.src_addr = rte_cpu_to_be_32(src_vport);
		actions.meter_id = PF_VPORT_ID;
		vm_oflows_to_pf[src_vport] = rte_vswitch_create_offload_flow
				(vctx, src_vport, &keys, &actions);
		if (!vm_oflows_to_pf[src_vport]) {
			printf("cannot create an offload flow from vport %hu to"
			       " vport %hu\n", src_vport, PF_VPORT_ID);
			return -1;
		}
	}

	/*
	 * The next packet pattern will be matched by the next flow:
	 * Ether()/IP(src=src VM vport id,dst=dst VM vport id)/
	 * UDP(dport=0,sport=0)
	 * The action will be to do loop-back in the HW and to get the packet
	 * via RSS queue with MARK related to the destination vport.
	 * This flow packet should come from a VM, so the datapath must set the
	 * vport meta-data in the mbuf.
	 */
	actions.remove_ethernet = 0;
	actions.encap = NULL;
	for (src_vport = 1; src_vport <= MAX_VPORT_INDEX; ++src_vport) {
		for (dst_vport = 1; dst_vport <= MAX_VPORT_INDEX; ++dst_vport) {
			if (src_vport == dst_vport)
				continue;
			keys.outer.src_addr = rte_cpu_to_be_32(src_vport);
			keys.outer.dst_addr = rte_cpu_to_be_32(dst_vport);
			actions.vport_id = dst_vport;
			actions.meter_id = dst_vport;
			vm_oflows_to_vm[src_vport][dst_vport] =
				rte_vswitch_create_offload_flow (vctx,
								 src_vport,
								 &keys,
								 &actions);
			if (!vm_oflows_to_vm[src_vport][dst_vport]) {
				printf("cannot create an offload flow from"
				       " vport %hu to vport %hu\n",
				       src_vport, dst_vport);
				return -1;
			}
		}
	}
	return 0;
}

static inline void
vswitch_forward(uint16_t q) {
	struct rte_mbuf *mbufs[32];
	struct rte_vswitch_mark_id mark;
	uint16_t nb_pkts, nb_tx;
	uint16_t p;

	nb_pkts = rte_eth_rx_burst(port_id, q, mbufs, 32);
	for (p = 0; p < nb_pkts; p++) {
		struct rte_mbuf *m = mbufs[p];

		if (m->ol_flags & PKT_RX_FDIR_ID) {
			/* Translate the packet mark by the vswitch API. */
			mark = rte_vswitch_translate_mark_id(vctx,
							     m->hash.fdir.hi);
			switch (mark.type) {
			case RTE_VSWITCH_MARK_TYPE_VPORT_FLOW:
				VSWITCH_PRINT("Queue %hu: MATCHED packet for "
					      "vport %hu\n", q, mark.vport_id);
				break;
			case RTE_VSWITCH_MARK_TYPE_UNKNOWN_VPORT_FLOW:
				VSWITCH_PRINT("Queue %hu: UNKNOWN packet comes"
					      " from vport %hu\n", q,
					      mark.vport_id);
				break;
			default:
				VSWITCH_PRINT("Queue %hu: UNKNOWN packet comes"
					      " from vport %hu - this packet"
					      " probably was matched by"
					      " non-vswitch flow\n", q,
					      PF_VPORT_ID);
				break;
			}
			m->ol_flags &= ~PKT_TX_METADATA;
		} else {
			/*
			 * Unknown packet comes from the PF - this packet is
			 * probably not a VXLAN packet. For the example: This
			 * packet simulates a VM vport packet.
			 * Set the meta-data as the src IPv4 address - assuming
			 * all the traffic is IPv4.
			 */
			struct ipv4_hdr* ip_hdr =
				(struct ipv4_hdr*)(rte_pktmbuf_mtod
						  (m, struct ether_hdr *) + 1);
			/*
			 * Get the correct vport meta-data using the vswitch API.
			 * Can be calculated one time after the vport registration.
			 */
			m->udata32 = rte_vswitch_get_vport_metadata(vctx,
					   rte_be_to_cpu_32(ip_hdr->src_addr));
			m->ol_flags |= PKT_TX_METADATA;
		}
	}
	nb_tx = 0;
	while (nb_tx < nb_pkts)
		nb_tx += rte_eth_tx_burst(port_id, q,
					  &mbufs[nb_tx],
					  nb_pkts - nb_tx);

}

static int
vswitch_loop(void *args __rte_unused)
{
	unsigned lcore_id = rte_lcore_id();
	uint16_t q = rte_lcore_index(lcore_id);

	if (q > nr_queues - 1) {
		printf("lcore %u has nothing to do...\n", lcore_id);
		return 0;
	} else
		printf("lcore %u works on queue %hu...\n", lcore_id, q);

	while (!force_quit)
		vswitch_forward(q);

	return 0;
}

static void
assert_link_status(void)
{
	struct rte_eth_link link;

	memset(&link, 0, sizeof(link));
	rte_eth_link_get(port_id, &link);
	if (link.link_status == ETH_LINK_DOWN)
		rte_exit(EXIT_FAILURE, ":: error: link is still down\n");
}

static int
vswitch_event_callback(uint16_t pid, enum rte_eth_event_type type,
		       void *param __rte_unused, void *ret_param __rte_unused)
{
	struct rte_eth_link link;

	if (pid == port_id && type == RTE_ETH_EVENT_INTR_LSC) {
		printf("Link interrupt\n");
		memset(&link, 0, sizeof(link));
		rte_eth_link_get(port_id, &link);
		if (link.link_status == ETH_LINK_DOWN) {
			printf("Link interrupt - link is down\n");
		} else {
			printf("Link interrupt - link is up\n");
		}
	} else
		printf("Unexpected port %hu interrupt %d\n", pid, type);

	return 0;
}

static void
vswitch_init_port(void)
{
	int ret;
	uint16_t i;
	struct rte_eth_conf port_conf = {
		.rxmode = {
			/**< CRC stripped by hardware */
			.hw_strip_crc   = 1,
		},
		.txmode = {
			/**< Enable matching on Tx meta-data */
			.offloads = DEV_TX_OFFLOAD_MATCH_METADATA,
		},
		/**< Enable HW loop-back from TX to RX */
		.lpbk_mode = 1,
		.intr_conf = {
			.lsc = 1,
		},
	};

	printf(":: initializing port: %d\n", port_id);
	/*
	 * Use vswitch API for configuration to be able to reconfigure by
	 * vswitch after FW reset event.
	 */
	ret = rte_vswitch_vport_configure(port_id,
				nr_queues, nr_queues, &port_conf);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
			":: cannot configure device: err=%d, port=%u\n",
			ret, port_id);
	}

	/* only set Rx queues: something we care only so far */
	for (i = 0; i < nr_queues; i++) {
		/*
		 * Use vswitch API for configuration to be able to re-setup by
		 * vswitch after FW reset event.
		 */
		ret = rte_vswitch_vport_rx_queue_setup(port_id, i, 512,
						rte_eth_dev_socket_id(port_id),
						NULL, mbuf_pool);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				":: Rx queue setup failed: err=%d, port=%u\n",
				ret, port_id);
		}
		/*
		 * Use vswitch API for configuration to be able to re-setup by
		 * vswitch after FW reset event.
		 */
		ret = rte_vswitch_vport_tx_queue_setup(port_id, i, 512,
						rte_eth_dev_socket_id(port_id),
						NULL);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				":: Tx queue setup failed: err=%d, port=%u\n",
				ret, port_id);
		}
	}

	rte_eth_promiscuous_enable(port_id);
	rte_eth_dev_callback_register(port_id, RTE_ETH_EVENT_INTR_LSC,
				      vswitch_event_callback, NULL);
	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
			"rte_eth_dev_start:err=%d, port=%u\n",
			ret, port_id);
	}

	assert_link_status();

	printf(":: initializing port: %d done\n", port_id);
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
		       signum);
		force_quit = true;
	}
}

int
main(int argc, char **argv)
{
	int ret;
	unsigned lcore_id;
	uint32_t dst_vport, src_vport;
	uint16_t v = 1;
	uint8_t nr_ports;
	uint32_t metadata;
	struct rte_vswitch_meter_profile mprof = {
		.bps = 20 * 1000000, // 20M Bytes
	};

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, ":: invalid EAL arguments\n");

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	nr_ports = rte_eth_dev_count();
	if (nr_ports == 0)
		rte_exit(EXIT_FAILURE, ":: no Ethernet ports found\n");
	port_id = 0;
	if (nr_ports != 1) {
		printf(":: warn: %d ports detected, but we use only one port"
		       " %u\n", nr_ports, port_id);
	}
	mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", 4096, 128, 0,
					    RTE_MBUF_DEFAULT_BUF_SIZE,
					    rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	nr_queues = rte_lcore_count();

	vswitch_init_port();

	/*
	 * Open a vswitch context:
	 * The vswitch PF represented by an ethdev device of 'port_id'.
	 * The PF is one of the vports - PF_VPORT_ID!
	 * The PF vport must be registered for all the vswitch life time,
	 * so it is registered by the open command and unregistered by the
	 * close command.
	 * The VMs number is 1 (same as max vports index).
	 * The vswitch type is VIRTIO - all the VMs are connected by VIRTIO.
	 */
	vctx = rte_vswitch_open(&rte_eth_devices[port_id], PF_VPORT_ID,
				MAX_VPORT_INDEX, RTE_VSWITCH_TYPE_VIRTIO);
	if (!vctx) {
		printf(":: Failed to open vswitch context\n");
		goto error;
	}

	/*
	 * Create a meter with 4M bytes limitation for the PF vport.
	 * We can configure more than 1 meter per vport.
	 * For the example the meter ID is like the vport ID.
	 */
	if (rte_vswitch_create_meter(vctx, PF_VPORT_ID, &mprof)) {
		printf("Failed to create meter for vport %d\n", PF_VPORT_ID);
		goto error;
	}

	for (v = 1; v <= MAX_VPORT_INDEX; ++v) {
		/*
		 * Register a VM vport with ID v.
		 * Here the VMs are simulated as VIRTIO connected VMs, in this
		 * case, the third parameter should be NULL.
		 * Starting from the registration point, the vport is managed
		 * by the vswitch to match offload flows \ exception flows.
		 */
		if (rte_vswitch_register_vport(vctx, v, NULL)) {
			printf(":: Failed to register vport %hu\n", v);
			goto error;
		}
		/* Create a meter with 4M bytes limitation for the vport v. */
		if (rte_vswitch_create_meter(vctx, v, &mprof)) {
			printf("Failed to create meter for vport %d\n", v);
			rte_vswitch_unregister_vport(vctx, v);
			goto error;
		}
	}

	/* Create a tunnel offload flows - from the PF to each VM */
	if (vswitch_create_tunnel_offload_flows() != 0)
		goto error;

	/* Create non-tunnel offload flows - from each VM to each VM\PF. */
	if (vswitch_create_non_tunnel_offload_flows() != 0)
		goto error;

	printf("\nSIGNUM/SIGTERM will cause flush to the VM vport 1 and will"
	       " change the meters rate of vport 0 to 2MBps\n");
	/* Start forwarding for all the lcores. */
	rte_eal_mp_remote_launch(vswitch_loop, NULL, CALL_MASTER);
	RTE_LCORE_FOREACH_SLAVE(lcore_id)
		rte_eal_wait_lcore(lcore_id);

	printf("\nSIGNUM/SIGTERM detected\nStatistics before vport 1 flush:\n");
	vswitch_print_stats();
	/*
	 * For the example:
	 * the first quit cause a flush operation of the first VM vport offload
	 * flows using the vswitch flush API.
	 * All the first vport  offload flows will be invalidated fastly.
	 * If it is a VM, like here, the metadata of the VM will be changed.
	 */
	force_quit = false;
	rte_vswitch_flush_vport_offload_flows(vctx, 1, &metadata);

	/* Update vport 0 meter rate. */
	mprof.bps = 2 * 1000000;
	if (rte_vswitch_update_meter(vctx, PF_VPORT_ID, &mprof)) {
		printf("Failed to update meter for vport %d\n", PF_VPORT_ID);
		goto error;
	}

	printf("\nAll vport 1 flows was flushed fast - "
	       "these flows packets should be unmatched now...\n"
	       "Vport 0 meter rate was update to 2MBps\n"
	       "Statistics after flush:\n");

	vswitch_print_stats();

	printf("\nSIGNUM/SIGTERM will close the program\n");

	rte_eal_mp_remote_launch(vswitch_loop, NULL, CALL_MASTER);
	RTE_LCORE_FOREACH_SLAVE(lcore_id)
		rte_eal_wait_lcore(lcore_id);

	vswitch_print_stats();

error:
	if (vctx) {
		printf("\nDestroy all the vswitch resources...\n");
		/* Destroy all the configured offload flows. */
		for (src_vport = 1; src_vport <= MAX_VPORT_INDEX;
		     ++src_vport) {
			if (pf_oflows[src_vport])
				rte_vswitch_destroy_offload_flow
					(vctx, pf_oflows[src_vport]);
			if (vm_oflows_to_pf[src_vport])
				rte_vswitch_destroy_offload_flow
					(vctx, vm_oflows_to_pf[src_vport]);
			for (dst_vport = 1; dst_vport <= MAX_VPORT_INDEX;
			     ++dst_vport) {
				if (vm_oflows_to_vm[src_vport][dst_vport])
					rte_vswitch_destroy_offload_flow (vctx,
					vm_oflows_to_vm[src_vport][dst_vport]);
			}
		}

		for (v--; v >= 1; v--) {
			/*
			 * Destroy the meter of the vport v.
			 * Not - the user must destroy all the meter flows before.
			 */
			rte_vswitch_destroy_meter(vctx, v);
			/*
			 * Unregister a VM vport with ID v.
			 * Release all the vport resources and invalidate it.
			 * Note: This vport offload flows resources must be
			 * released by the user.
			 */
			rte_vswitch_unregister_vport(vctx, v);
		}

		/*
		 * Release all the current vswitch resources.
		 * This API unregister all the vports and destroy all the
		 * offload flows if exists.
		 */
		rte_vswitch_close(vctx);
	}
	printf("\nClose ethdev port...\nBye..\n");
	/* closing and releasing ethdev port resources */
	rte_eth_dev_stop(port_id);
	rte_eth_dev_close(port_id);

	return 0;
}
