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

#include "testpmd.h"
#include <rte_vswitch.h>

#define VSWITCH_PRINT(...) if (verbose_level & 0x1) printf(__VA_ARGS__)

inline uint32_t
vswitch_get_metadata(struct rte_mbuf *pkt) {
	struct ether_hdr *pkt_eth = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	uint8_t last_byte = pkt_eth->d_addr.addr_bytes[5];

	if (last_byte == 0xFF) {
		if (pkt->ol_flags & PKT_RX_FDIR_ID) {
			pkt_eth->d_addr.addr_bytes[1] = pkt->hash.fdir.hi &
								0xFF;
			pkt_eth->d_addr.addr_bytes[2] =
					(pkt->hash.fdir.hi >> 8) & 0xFF;
		} else {
			pkt_eth->d_addr.addr_bytes[1] = 0;
			pkt_eth->d_addr.addr_bytes[2] =	0;
		}
		pkt->ol_flags &= ~PKT_TX_METADATA;
		return 0;
	} else if (last_byte != 0) {
		pkt_eth->d_addr.addr_bytes[5] = 0xFF;
		pkt->ol_flags |= PKT_TX_METADATA;
		return rte_vswitch_get_vport_metadata(get_vswitch_ctx(), last_byte - 1);
	}
	return 0;
}

inline int
vswitch_prepare_direction_mode_flow(uint32_t dmode, uint16_t *in_vport_p,
				    uint16_t *out_vport_p, uint16_t pf_vport,
				    uint32_t i, uint32_t vms_max_index) {
	static uint16_t out_vport;
	static uint16_t in_vport;

	switch (dmode) {
	case 0: //PF to VMs
		if (i == 0)
			out_vport = 0;
		*in_vport_p = pf_vport;
		if (out_vport > vms_max_index) {
			out_vport = 0;
		}
		if (out_vport == pf_vport) {
			out_vport++;
			if (out_vport > vms_max_index) {
				out_vport = 0;
			}
		}
		*out_vport_p = out_vport;
		out_vport++;
		break;
	case 1: // VMs to pf
		if (i == 0)
			in_vport = 0;
		*out_vport_p = pf_vport;
		if (in_vport > vms_max_index) {
			in_vport = 0;
		}
		if (in_vport == pf_vport) {
			in_vport++;
			if (in_vport > vms_max_index) {
				in_vport = 0;
			}
		}
		*in_vport_p = in_vport;
		in_vport++;
		break;
	case 2: // VMs to VMs
		if (i == 0) {
			if (vms_max_index < 2) {
				printf("vswitch: for direction mode %u you must"
				       " to configure at least 3 vports -> PF +"
				       " 2 VMs\n",
				       dmode);
				return -ENOTSUP;
			}
			out_vport = 0;
			in_vport = 1;
		}
		if (in_vport == pf_vport)
			in_vport = (in_vport + 1) % (vms_max_index + 1);
		if (out_vport == pf_vport)
			out_vport = (out_vport + 1) % (vms_max_index + 1);
		if (in_vport == out_vport) {
			out_vport = (out_vport + 1) % (vms_max_index + 1);
			in_vport = (out_vport + 1) % (vms_max_index + 1);
			if (in_vport == pf_vport)
				in_vport = (in_vport + 1) %
						(vms_max_index + 1);
			if (out_vport == pf_vport) {
				out_vport = (out_vport + 1) % (vms_max_index + 1);
				in_vport = (out_vport + 1) % (vms_max_index + 1);
			}
		}
		*in_vport_p = in_vport;
		*out_vport_p = out_vport;
		in_vport = (in_vport + 1) % (vms_max_index + 1);

		break;
	case 3: // ALL to ALL
		if (i == 0) {
			out_vport = 0;
			in_vport = 1;
		}
		if (in_vport == out_vport) {
			out_vport = (out_vport + 1) % (vms_max_index + 1);
			in_vport = (out_vport + 1) % (vms_max_index + 1);
		}
		*in_vport_p = in_vport;
		*out_vport_p = out_vport;
		in_vport = (in_vport + 1) % (vms_max_index + 1);
	default:
		printf("vswitch: unknown direction mode %u\n", dmode);
		return -ENOTSUP;
	}
	return 0;
}

struct vswitch_flow_structures vfs_default_a = {
	.keys = {
		.outer = {
			.ip_type = 0,
			.src_addr_valid = 0,
			.dst_addr_valid = 0,
			.proto_valid = 1,
			.src_port_valid = 0,
			.dst_port_valid = 1,
			.tcp_flags_valid = {
				.flags = 0,
			},
			.src_addr = 0,
			.dst_addr = RTE_BE32(0xFEDCBA98),
			.proto = IPPROTO_UDP,
			.src_port = 0,
			.dst_port = RTE_BE16(250),
			.tcp_flags = {
				.flags = 0,
			},
		},
		.tunnel_type = RTE_VSWITCH_TUNNEL_TYPE_VXLAN,
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
			.src_addr = 0x0264A8C0,
			.dst_addr = 0x0264A8C1,
			.proto = IPPROTO_UDP,
			.src_port = 1,
			.dst_port = 1,
			.tcp_flags = {
				.flags = 0,
			},
		},
	},
	.eth = {
		.d_addr = {
			.addr_bytes = {0x00, 0x37, 0x44, 0x9A, 0x0D, 0xFF},
		},
		.s_addr = {
			.addr_bytes = {0x00, 0x38, 0x44, 0x9A, 0x0D, 0xFF},
		},
		.ether_type = RTE_BE16(ETHER_TYPE_IPv4),
	},
	.encap = {
		.ipv4 = {
			.version_ihl = 0,
			.type_of_service = 0,
			.total_length = 0,
			.packet_id = 0,
			.fragment_offset = 0,
			.time_to_live = 0,
			.next_proto_id = 0,
			.hdr_checksum = 0,
			.src_addr = 0,
			.dst_addr = 0,
			},
		.udp = {
			.src_port = 0,
			.dst_port = 0,
			.dgram_len = 0,
			.dgram_cksum = 0,
			},
	},
	.modify = {
		.set_src_mac = 0,
		.set_dst_mac = 0,
		.set_dst_ip4 = 0,
		.set_src_ip4 = 0,
		.set_dst_ip6 = 0,
		.set_src_ip6 = 0,
		.set_dst_port = 0,
		.set_src_port = 0,
		.set_ttl = 0,
		.dec_ttl = 0,
		.dec_tcp_seq = 0,
		.dec_tcp_ack = 0,
		.inc_tcp_seq = 0,
		.inc_tcp_ack = 0,
		.dst_ip4 = 0,
		.src_ip4 = 0,
		.src_port = 0,
		.dst_port = 0,
		.ttl = 0,
		.tcp_seq = 0,
		.tcp_ack = 0,
	},
	.actions = {
		.vport_id = 0,
		.count = 0,
		.decap = 0,
		.remove_ethernet = 0,
		.timeout = 0,
		.encap = NULL,
		.add_ethernet = NULL,
		.modify = NULL,
	},
};

static int
vswitch_prepare_mode_a_flow(uint32_t flows_mode, uint16_t in_vport,
			    uint16_t out_vport,
			    struct vswitch_flow_structures **vfs_pp_ret,
			    uint32_t i) {
	static struct vswitch_flow_structures vfs;

	if (i == 0) {
		vfs_default_a.keys.vni = RTE_BE32(0x20) >> 8,
		vfs = vfs_default_a;
		VSWITCH_PRINT("flows packet pattern:\n");
		if (flows_mode < 50) {
			if (flows_mode != 4) {
				VSWITCH_PRINT("\tEther(type=0x800)/IP/UDP"
					      "(dport=250)/VXLAN(vni=0x20,"
					      "flags=0x%X)/IP(src="
					      "\"0.0.%u.%u\",dst="
					      "\"0.0.%u.%u\")/UDP(dport=X,"
					      "sport=Y)\n", flows_mode < 25 ?
					      0x8 : 0xC, (in_vport >> 8) &
					      0xFF, in_vport & 0xFF,
					      (out_vport >> 8) & 0xFF,
					      out_vport & 0xFF);
			} else {
				VSWITCH_PRINT("\tEther(type=0x800)/IP(dst="
					      "254.220.186.152)/UDP(dport=250)"
					      "/VXLAN(vni=0x20,flags=0x%X)/IP"
					      "(src=\"0.0.%u.%u\",dst="
					      "\"0.0.%u.%u\")/UDP(dport=X,"
					      "sport=Y)\n", flows_mode < 25 ?
					      0x8 : 0xC, (in_vport >> 8) &
					      0xFF, in_vport & 0xFF,
					      (out_vport >> 8) & 0xFF,
					      out_vport & 0xFF);
			}
		} else {
			VSWITCH_PRINT("\tEther(type=0x800)/IP/UDP(dport=250)/"
				      "VXLAN(vni=0x20)/IP(src=\"0.0.%u.%u\","
				      "dst=\"0.0.%u.%u\")/TCP(flags=0,dport=X,"
				      "sport=Y)\n", (in_vport >> 8) & 0xFF,
				      in_vport & 0xFF, (out_vport >> 8) & 0xFF,
				      out_vport & 0xFF);
		}
		VSWITCH_PRINT("\tY = flow_index & 0xFFFF\n");
		VSWITCH_PRINT("\tX = (flow_index >> 16) & 0xFFFF\n");
		VSWITCH_PRINT("\tsrc vport is %u\n\tdst vport is %u\n",
			      in_vport, out_vport);
		VSWITCH_PRINT("flows packet actions:\n\tdefault MARK and"
			      " RSS\n");
		switch(flows_mode) {
		case 0:
			break;
		case 1:
			vfs.actions.decap = 1;
			vfs.actions.add_ethernet = &vfs.eth;
			VSWITCH_PRINT(", DECUP + add ethernet dst"
			       " 00:37:44:9A:0D:FF src"
			       " 00:38:44;9A:0D:FF type 0x800\n");
			break;
		case 2:
			vfs.actions.modify = &vfs.modify;
			vfs.modify.set_dst_ip4 = 1;
			vfs.modify.set_dst_port = 1;
			vfs.actions.decap = 1;
			vfs.actions.add_ethernet = &vfs.eth;
			VSWITCH_PRINT(", DNAT + DECUP + add ethernet dst"
			       " 00:37:44:9A:0D:FF src"
			       " 00:38:44;9A:0D:FF type 0x800\n");
			break;
		case 4:
			vfs.actions.modify = &vfs.modify;
			vfs.modify.set_dst_ip4 = 1;
			vfs.modify.set_dst_port = 1;
			vfs.actions.decap = 1;
			vfs.actions.add_ethernet = &vfs.eth;
			vfs.keys.outer.dst_addr_valid = 1;
			VSWITCH_PRINT(", DNAT + DECUP + add ethernet dst"
			       " 00:37:44:9A:0D:FF src"
			       " 00:38:44;9A:0D:FF type 0x800\n");
			break;
		case 25:
			vfs.keys.tunnel_type = RTE_VSWITCH_TUNNEL_TYPE_VXLAN_GPE;
			//vfs.keys.protocol_valid = 1;
			//vfs.keys.protocol = 0x1 ; //1 - IPv4,  2 - IPv6, 3 - ETH
			vfs.actions.decap = 1;
			vfs.actions.add_ethernet = &vfs.eth;
			VSWITCH_PRINT(", DECUP + add ethernet dst"
			       " 00:37:44:9A:0D:FF src"
			       " 00:38:44;9A:0D:FF type 0x800\n");
			break;
		case 50:
			vfs.keys.inner.proto = IPPROTO_TCP;
			vfs.keys.inner.tcp_flags_valid.syn = 1;
			vfs.keys.inner.tcp_flags_valid.rst = 1;
			vfs.keys.inner.tcp_flags_valid.fin = 1;
			vfs.actions.modify = &vfs.modify;
			vfs.modify.set_dst_ip4 = 1;
			vfs.modify.set_dst_port = 1;
			vfs.actions.decap = 1;
			vfs.actions.add_ethernet = &vfs.eth;
			VSWITCH_PRINT(", DNAT + DECUP + add ethernet dst"
			       " 00:37:44:9A:0D:FF src"
			       " 00:38:44;9A:0D:FF type 0x800\n");
			break;
		case 52:
			vfs.keys.inner.proto = IPPROTO_TCP;
			vfs.actions.modify = &vfs.modify;
			vfs.modify.inc_tcp_ack = 1;
			vfs.modify.inc_tcp_seq = 1;
			vfs.actions.decap = 1;
			vfs.actions.add_ethernet = &vfs.eth;
			VSWITCH_PRINT(", tcp seq\ack inc + DECUP + add"
				      " ethernet dst 00:37:44:9A:0D:FF src"
				      " 00:38:44;9A:0D:FF type 0x800\n");
			break;
		default:
			printf("vswitch: unknown mode_a flows %u\n",
			       flows_mode);
			return -ENOTSUP;
		}
	}
	*vfs_pp_ret = &vfs;
	switch(flows_mode) {
	case 0:
		break;
	case 1:
		break;
	case 2:
		vfs.modify.dst_ip4 = rte_cpu_to_be_32(0xFF + i);
		vfs.modify.dst_port = rte_cpu_to_be_16(0xFF + i);
		break;
	case 4:
		vfs.modify.dst_ip4 = rte_cpu_to_be_32(0xFF + i);
		vfs.modify.dst_port = rte_cpu_to_be_16(0xFF + i);
		break;
	case 25:
		break;
	case 50:
		vfs.modify.dst_ip4 = rte_cpu_to_be_32(0xFF + i);
		vfs.modify.dst_port = rte_cpu_to_be_16(0xFF + i);
		break;
	case 52:
		vfs.modify.tcp_ack = rte_cpu_to_be_32(0xFF + i);
		vfs.modify.tcp_seq = rte_cpu_to_be_32(0xFF + i);
		break;
	default:
		printf("vswitch: unknown mode_a flows %u\n", flows_mode);
		return -ENOTSUP;
	}
	vfs.keys.inner.src_port = rte_cpu_to_be_16(i & 0xFFFF);
	vfs.keys.inner.dst_port = rte_cpu_to_be_16((i >> 16) & 0xFFFF);
	vfs.keys.inner.src_addr = rte_cpu_to_be_32(in_vport);
	vfs.keys.inner.dst_addr = rte_cpu_to_be_32(out_vport);
	return 0;
}

struct vswitch_flow_structures vfs_default_b = {
	.keys = {
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
			.src_addr = 0x12345678,
			.dst_addr = 0x12345679,
			.proto = IPPROTO_UDP,
			.src_port = 0x1235,
			.dst_port = 0x1234,
			.tcp_flags = {
				.flags = 0,
			},
		},
		.tunnel_type = RTE_VSWITCH_TUNNEL_TYPE_NONE,
	},
	.eth = {
		.d_addr = {
			.addr_bytes = {0x00, 0x37, 0x44, 0x9A, 0x0D, 0xEC},
		},
		.s_addr = {
			.addr_bytes = {0x00, 0x37, 0x44, 0x9A, 0x0D, 0xED},
		},
		.ether_type = RTE_BE16(ETHER_TYPE_IPv4),
	},
	.encap = {
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
	},
	.modify = {
		.set_src_mac = 0,
		.set_dst_mac = 0,
		.set_dst_ip4 = 0,
		.set_src_ip4 = 0,
		.set_dst_ip6 = 0,
		.set_src_ip6 = 0,
		.set_dst_port = 0,
		.set_src_port = 0,
		.set_ttl = 0,
		.dec_ttl = 0,
		.dec_tcp_seq = 0,
		.dec_tcp_ack = 0,
		.inc_tcp_seq = 0,
		.inc_tcp_ack = 0,
		.dst_ip4 = 0,
		.src_ip4 = 0,
		.src_port = 0,
		.dst_port = 0,
		.ttl = 0,
		.tcp_seq = 0,
		.tcp_ack = 0,
	},
	.actions = {
		.vport_id = 0,
		.count = 0,
		.decap = 0,
		.remove_ethernet = 0,
		.timeout = 0,
		.encap = NULL,
		.add_ethernet = NULL,
		.modify = NULL,
	},
};
static int
vswitch_prepare_mode_b_flow(uint32_t flows_mode, uint16_t in_vport,
			    uint16_t out_vport,
			    struct vswitch_flow_structures **vfs_pp_ret,
			    uint32_t i) {
	static struct vswitch_flow_structures vfs;

	if (i == 0) {
		vfs_default_b.encap.vxlan_flags = 0x08;
		vfs_default_b.encap.vxlan_vni = 0x50;
		vfs = vfs_default_b;
		VSWITCH_PRINT("flows packet pattern:\n");
		if ((flows_mode < 200 && flows_mode >= 150) ||
		    flows_mode >= 250) {
			VSWITCH_PRINT("\t METADATA + Ether(type=0x800)/IP(src="
				      "\"0.0.%u.%u\",dst=\"0.0.%u.%u\")/TCP("
				      "flags=0, dport=X,sport=Y)\n",
				      (in_vport >> 8) & 0xFF, in_vport & 0xFF,
				      (out_vport >> 8) & 0xFF, out_vport &
				      0xFF);
		} else {
			VSWITCH_PRINT("\t METADATA + Ether(type=0x800)/IP(src="
				      "\"0.0.%u.%u\",dst=\"0.0.%u.%u\")/UDP("
				      "dport=X,sport=Y)\n", (in_vport >> 8) &
				      0xFF, in_vport & 0xFF, (out_vport >> 8) &
				      0xFF, out_vport & 0xFF);
		}
		VSWITCH_PRINT("\tY = flow_index & 0xFFFF\n");
		VSWITCH_PRINT("\tX = (flows_index >> 16) & 0xFFFF\n");
		VSWITCH_PRINT("\tsrc vport is %u\n\tdst vport is %u\n",
			      in_vport, out_vport);
		switch (flows_mode) {
		case 101:
			VSWITCH_PRINT("flows packet actions:\nthe vswitch should"
				" encapsulate STD vxlan in egress, send to"
				" LB and decap the STD vxlan in ingress\n");
			break;
		case 102:
			vfs.actions.modify = &vfs.modify;
			vfs.modify.set_dst_ip4 = 1;
			VSWITCH_PRINT("flows packet actions:\nthe vswitch"
				      " should change the dst ipv4 addr to"
				      " 0xFF+flow index, to encapsulate STD"
				      " vxlan in egress, send to LB and decap"
				      " the STD vxlan in ingress\n");
			break;
		case 103:
			vfs.actions.modify = &vfs.modify;
			vfs.modify.set_src_ip4 = 1;
			VSWITCH_PRINT("flows packet actions:\nthe vswitch"
				      " should change the src ipv4 addr to"
				      " 0xFF+flow index, to encapsulate STD"
				      " vxlan in egress, send to LB and decap"
				      " the STD vxlan in ingress\n");
			break;
		case 104:
			vfs.actions.modify = &vfs.modify;
			vfs.modify.set_dst_port = 1;
			VSWITCH_PRINT("flows packet actions:\nthe vswitch"
				      " should change the dst l4 port to flow"
				      " index + 0xFF, to encapsulate STD vxlan"
				      " in egress, send to LB and decap the"
				      " STD vxlan in ingress\n");
			break;
		case 105:
			vfs.actions.modify = &vfs.modify;
			vfs.modify.set_src_port = 1;
			VSWITCH_PRINT("flows packet actions:\nthe vswitch"
				      " should change the src l4 port to flow"
				      " index + 0xFF, to encapsulate STD vxlan"
				      " in egress, send to LB and decap the"
				      " STD vxlan in ingress\n");
			break;
		case 106:
			vfs.actions.modify = &vfs.modify;
			vfs.modify.set_ttl = 1;
			VSWITCH_PRINT("flows packet actions:\nthe vswitch"
				      " should change the ttl to flow index"
				      " & 0xFF, to encapsulate STD vxlan in"
				      " egress, send to LB and decap the STD"
				      " vxlan in ingress\n");
			break;
		case 107:
			vfs.actions.modify = &vfs.modify;
			vfs.modify.dec_ttl = 1;
			VSWITCH_PRINT("flows packet actions:\nthe vswitch"
				      " should change the ttl to ttl - 1,"
				      " to encapsulate STD vxlan in egress,"
				      " send to LB and decap the STD vxlan in"
				      " ingress\n");
			break;
		case 108:
			vfs.actions.modify = &vfs.modify;
			vfs.modify.set_dst_ip4 = 1;
			vfs.modify.set_src_ip4 = 1;
			vfs.modify.set_dst_port = 1;
			vfs.modify.set_src_port = 1;
			VSWITCH_PRINT("flows packet actions:\nthe vswitch"
				      " should change the dst ipv4 addr to"
				      " 0xFF+flow index, change the src ipv4"
				      " addr to 0xFF+flow index, change the dst"
				      " port to flow index + 0xFF, change the"
				      " src port to flow index + 0xFF, to"
				      " encapsulate STD vxlan in egress, send"
				      " to LB and decap the STD vxlan in"
				      " ingress\n");
			break;
		case 109:
			vfs.actions.modify = &vfs.modify;
			vfs.modify.set_dst_ip4 = 1;
			vfs.modify.set_src_ip4 = 1;
			vfs.modify.set_dst_port = 1;
			vfs.modify.set_src_port = 1;
			vfs.modify.dec_ttl = 1;
			VSWITCH_PRINT("flows packet actions:\nthe vswitch"
				      " should change the dst ipv4 addr to"
				      " 0xFF+flow index, change the src ipv4"
				      " addr to 0xFF+flow index, change the"
				      " dst port to flow index+0xFF, change the"
				      " src port to flow index+0xFF, change the"
				      " ttl to ttl - 1, to encapsulate STD"
				      " vxlan in egress, send to LB and decap"
				      " the STD vxlan in ingress\n");
			break;
		case 110:
			vfs.actions.modify = &vfs.modify;
			vfs.modify.set_dst_ip4 = 1;
			vfs.modify.set_src_ip4 = 1;
			vfs.modify.set_dst_port = 1;
			vfs.modify.set_src_port = 1;
			vfs.modify.set_ttl = 1;
			VSWITCH_PRINT("flows packet actions:\nthe vswitch"
				      " should change the dst ipv4 addr to"
				      " 0xFF+flow index, change the src ipv4"
				      " addr to 0xFF+flow index, change the dst"
				      " port to flow index+0xFF, change the src"
				      " port to flow index + 0xFF, change the"
				      " ttl to flow index & 0xFF, to"
				      " encapsulate STD vxlan in egress, send"
				      " to LB and decap the STD vxlan in"
				      " ingress\n");
			break;
		case 111:
			vfs.actions.modify = &vfs.modify;
			vfs.modify.dec_ttl = 1;
			vfs.modify.set_dst_mac = 1;
			memcpy(vfs.modify.dst_mac.addr_bytes,
			       (uint8_t [6]){0x0,0x11,0x22,0x33,0x44,0xFF}, 6);
			vfs.modify.set_src_mac = 1;
			memcpy(vfs.modify.src_mac.addr_bytes,
			       (uint8_t [6]){0x0,0x66,0x77,0x88,0x99,0xFF}, 6);
			VSWITCH_PRINT("flows packet actions:\nthe vswitch"
				      " should dec the ttl, set dst mac"
				      " 00:11:22:X:44:55, set src mac"
				      " 00:66:77:X:99:AA, to encapsulate STD"
				      " vxlan in egress, send to LB and decap"
				      " the STD vxlan in ingress\n");
			break;
		case 150:
			vfs.keys.outer.proto = IPPROTO_TCP;
			vfs.keys.outer.tcp_flags_valid.syn = 1;
			vfs.keys.outer.tcp_flags_valid.rst = 1;
			vfs.keys.outer.tcp_flags_valid.fin = 1;
			vfs.actions.modify = &vfs.modify;
			vfs.modify.set_dst_ip4 = 1;
			vfs.modify.set_src_ip4 = 1;
			vfs.modify.set_dst_port = 1;
			vfs.modify.set_src_port = 1;
			vfs.modify.dec_ttl = 1;
			vfs.modify.inc_tcp_seq = 1;
			VSWITCH_PRINT("flows packet actions:\nthe vswitch"
				      " should change the dst ipv4 addr to"
				      " 0xFF+flow index, change the src ipv4"
				      " addr to 0xFF+flow index, change the dst"
				      " port to flow index+0xFF, change the src"
				      " port to flow index + 0xFF, change the"
				      " ttl to ttl -1, inc tcp seq by 0xFF +"
				      " flow index,to encapsulate STD vxlan in"
				      " egress, send to LB and decap the STD"
				      " vxlan in ingress\n");
			break;
		case 151:
			vfs.keys.outer.proto = IPPROTO_TCP;
			vfs.keys.outer.tcp_flags_valid.syn = 1;
			vfs.keys.outer.tcp_flags_valid.rst = 1;
			vfs.keys.outer.tcp_flags_valid.fin = 1;
			vfs.actions.modify = &vfs.modify;
			vfs.modify.set_dst_ip4 = 1;
			vfs.modify.set_src_ip4 = 1;
			vfs.modify.set_dst_port = 1;
			vfs.modify.set_src_port = 1;
			vfs.modify.dec_ttl = 1;
			vfs.modify.inc_tcp_ack = 1;
			VSWITCH_PRINT("flows packet actions:\nthe vswitch"
				      " should change the dst ipv4 addr to"
				      " 0xFF+flow index, change the src ipv4"
				      " addr to 0xFF+flow index, change the dst"
				      " port to flow index+0xFF, change the src"
				      " port to flow index + 0xFF, change the"
				      " ttl to ttl -1, inc tcp ack by 0xFF +"
				      " flow index,to encapsulate STD vxlan in"
				      " egress, send to LB and decap the STD"
				      " vxlan in ingress\n");
			break;
		case 152:
			vfs.keys.outer.proto = IPPROTO_TCP;
			vfs.actions.modify = &vfs.modify;
			vfs.modify.inc_tcp_ack = 1;
			VSWITCH_PRINT("flows packet actions:\nthe vswitch"
				      " should inc tcp ack by 0xFF +"
				      " flow index,to encapsulate STD vxlan in"
				      " egress, send to LB and decap the STD"
				      " vxlan in ingress\n");
			break;
		case 153:
			vfs.keys.outer.proto = IPPROTO_TCP;
			vfs.actions.modify = &vfs.modify;
			vfs.modify.dec_tcp_ack = 1;
			VSWITCH_PRINT("flows packet actions:\nthe vswitch"
				      " should dec tcp ack by flow index,to"
				      " encapsulate STD vxlan in egress, send"
				      " to LB and decap the STD vxlan in"
				      " ingress\n");
			break;
		case 154:
			vfs.keys.outer.proto = IPPROTO_TCP;
			vfs.actions.modify = &vfs.modify;
			vfs.modify.inc_tcp_seq = 1;
			VSWITCH_PRINT("flows packet actions:\nthe vswitch"
				      " should inc tcp seq by 0xFF +"
				      " flow index,to encapsulate STD vxlan in"
				      " egress, send to LB and decap the STD"
				      " vxlan in ingress\n");
			break;
		case 155:
			vfs.keys.outer.proto = IPPROTO_TCP;
			vfs.actions.modify = &vfs.modify;
			vfs.modify.dec_tcp_seq = 1;
			VSWITCH_PRINT("flows packet actions:\nthe vswitch"
				      " should dec tcp seq by flow index,to"
				      " encapsulate STD vxlan in egress, send"
				      " to LB and decap the STD vxlan in"
				      " ingress\n");
			break;
		case 200:
			vfs.actions.encap = &vfs.encap;
			vfs.actions.remove_ethernet = 1;
			vfs.encap.ether = vfs.eth;
			VSWITCH_PRINT("flows packet actions:\n\tENCAP +"
				      " remove ethernet\n");
			break;
		case 201:
			vfs.actions.encap = &vfs.encap;
			vfs.actions.remove_ethernet = 1;
			vfs.encap.ether = vfs.eth;
			VSWITCH_PRINT("flows packet actions:\n\tENCAP +"
				      " remove ethernet\n");
			vfs.actions.modify = &vfs.modify;
			vfs.modify.set_src_ip4 = 1;
			vfs.modify.set_src_port = 1;
			VSWITCH_PRINT(" + SNAT\n");
			break;
		case 225:
			vfs.actions.encap = &vfs.encap;
			vfs.encap.vxlan_flags = 0x0C;
			vfs.encap.vxlan_protocol = 0x1;
			vfs.actions.remove_ethernet = 1;
			vfs.encap.ether = vfs.eth;
			VSWITCH_PRINT("flows packet actions:\n\tENCAP vxlan"
				      " gpe + remove ethernet\n");
			break;
		case 250:
			vfs.keys.outer.proto = IPPROTO_TCP;
			vfs.keys.outer.tcp_flags_valid.syn = 1;
			vfs.keys.outer.tcp_flags_valid.rst = 1;
			vfs.keys.outer.tcp_flags_valid.fin = 1;
			vfs.actions.encap = &vfs.encap;
			vfs.actions.remove_ethernet = 1;
			vfs.encap.ether = vfs.eth;
			VSWITCH_PRINT("flows packet actions:\n\tENCAP +"
				      " remove ethernet\n");
			vfs.actions.modify = &vfs.modify;
			vfs.modify.dec_ttl = 1;
			vfs.modify.set_src_ip4 = 1;
			vfs.modify.set_src_port = 1;
			vfs.modify.inc_tcp_seq = 1;
			vfs.modify.inc_tcp_ack = 1;
			VSWITCH_PRINT(" + SNAT + dec ttl + inc tcp seq\ack by"
				      " 0xFF + flow index\n");
			break;
		case 252:
			vfs.keys.outer.proto = IPPROTO_TCP;
			vfs.actions.encap = &vfs.encap;
			vfs.actions.remove_ethernet = 1;
			vfs.encap.ether = vfs.eth;
			VSWITCH_PRINT("flows packet actions:\n\tENCAP +"
				      " remove ethernet\n");
			vfs.actions.modify = &vfs.modify;
			vfs.modify.inc_tcp_seq = 1;
			vfs.modify.inc_tcp_ack = 1;
			VSWITCH_PRINT(" inc tcp seq\ack by"
				      " 0xFF + flow index\n");
			break;
		default:
			printf("vswitch: unknown mode_b flows %u\n",
			       flows_mode);
			return -ENOTSUP;
		}

	}
	*vfs_pp_ret = &vfs;
	switch (flows_mode) {
	case 102:
		vfs.modify.dst_ip4 = rte_cpu_to_be_32(0xFF + i);
		break;
	case 103:
		vfs.modify.src_ip4 = rte_cpu_to_be_32(0xFF + i);
		break;
	case 104:
		vfs.modify.dst_port = rte_cpu_to_be_16(0xFF + i);
		break;
	case 105:
		vfs.modify.src_port = rte_cpu_to_be_16(0xFF + i);
		break;
	case 106:
		vfs.modify.ttl = i;
		break;
	case 107:
		break;
	case 110:
		vfs.modify.ttl = i;
		/* fallthrouh */
	case 108:
	case 109:
		vfs.modify.dst_ip4 = rte_cpu_to_be_32(0xFF + i);
		vfs.modify.src_ip4 = rte_cpu_to_be_32(0xFF + i);
		vfs.modify.dst_port = rte_cpu_to_be_16(0xFF + i);
		vfs.modify.src_port = rte_cpu_to_be_16(0xFF + i);
		break;
	case 111:
		vfs.modify.dst_mac.addr_bytes[3] = i;
		vfs.modify.src_mac.addr_bytes[3] = i;
		break;
	case 150:
		vfs.modify.dst_ip4 = rte_cpu_to_be_32(0xFF + i);
		vfs.modify.src_ip4 = rte_cpu_to_be_32(0xFF + i);
		vfs.modify.dst_port = rte_cpu_to_be_16(0xFF + i);
		vfs.modify.src_port = rte_cpu_to_be_16(0xFF + i);
		vfs.modify.tcp_seq = rte_cpu_to_be_32(0xFF + i);
		break;
	case 151:
		vfs.modify.dst_ip4 = rte_cpu_to_be_32(0xFF + i);
		vfs.modify.src_ip4 = rte_cpu_to_be_32(0xFF + i);
		vfs.modify.dst_port = rte_cpu_to_be_16(0xFF + i);
		vfs.modify.src_port = rte_cpu_to_be_16(0xFF + i);
		vfs.modify.tcp_ack = rte_cpu_to_be_32(0xFF + i);
		break;
	case 152:
		vfs.modify.tcp_ack = rte_cpu_to_be_32(0xFF + i);
		break;
	case 153:
		vfs.modify.tcp_ack = rte_cpu_to_be_32(i);
		break;
	case 154:
		vfs.modify.tcp_seq = rte_cpu_to_be_32(0xFF + i);
		break;
	case 155:
		vfs.modify.tcp_seq = rte_cpu_to_be_32(i);
		break;
	case 200:
		break;
	case 201:
		vfs.modify.src_ip4 = rte_cpu_to_be_32(0xFF + i);
		vfs.modify.src_port = rte_cpu_to_be_16(0xFF + i);
		break;
	case 225:
		break;
	case 250:
		vfs.modify.src_ip4 = rte_cpu_to_be_32(0xFF + i);
		vfs.modify.src_port = rte_cpu_to_be_16(0xFF + i);
		vfs.modify.tcp_ack = rte_cpu_to_be_32(0xFF + i);
		vfs.modify.tcp_seq = rte_cpu_to_be_32(0xFF + i);
		break;
	case 252:
		vfs.modify.tcp_ack = rte_cpu_to_be_32(0xFF + i);
		vfs.modify.tcp_seq = rte_cpu_to_be_32(0xFF + i);
		break;
	default:
		break;
	}
	vfs.keys.outer.src_port = rte_cpu_to_be_16(i & 0xFFFF);
	vfs.keys.outer.dst_port = rte_cpu_to_be_16((i >> 16) & 0xFFFF);
	vfs.keys.outer.src_addr = rte_cpu_to_be_32(in_vport);
	vfs.keys.outer.dst_addr = rte_cpu_to_be_32(out_vport);
	return 0;
}

struct vswitch_flow_structures vfs_default_c = {
	.keys = {
		.outer = {
			.ip_type = 0,
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
		.tunnel_type = RTE_VSWITCH_TUNNEL_TYPE_VXLAN_GPE,
		.inner = {
			.ip_type = 1,
			.src_addr_valid = 1,
			.dst_addr_valid = 1,
			.proto_valid = 1,
			.src_port_valid = 1,
			.dst_port_valid = 1,
			.tcp_flags_valid = {
				.flags = 0,
			},
			.src_addr6 = "\x00\x00\x00\x00\x00\x00\x00\x00",
			.dst_addr6 = "\x00\x00\x00\x00\x00\x00\x00\x00",
			.proto = IPPROTO_UDP,
			.src_port = 1,
			.dst_port = 1,
			.tcp_flags = {
				.flags = 0,
			},
		},
	},
	.eth = {
		.d_addr = {
			.addr_bytes = {0x00, 0x37, 0x44, 0x9A, 0x0D, 0xFF},
		},
		.s_addr = {
			.addr_bytes = {0x00, 0x38, 0x44, 0x9A, 0x0D, 0xFF},
		},
		.ether_type = RTE_BE16(ETHER_TYPE_IPv6),
	},
	.encap = {
		.ipv4 = {
			.version_ihl = 0,
			.type_of_service = 0,
			.total_length = 0,
			.packet_id = 0,
			.fragment_offset = 0,
			.time_to_live = 0,
			.next_proto_id = 0,
			.hdr_checksum = 0,
			.src_addr = 0,
			.dst_addr = 0,
		},
		.udp = {
			.src_port = 0,
			.dst_port = 0,
			.dgram_len = 0,
			.dgram_cksum = 0,
		},
	},
	.modify = {
		.set_src_mac = 0,
		.set_dst_mac = 0,
		.set_dst_ip4 = 0,
		.set_src_ip4 = 0,
		.set_dst_ip6 = 0,
		.set_src_ip6 = 0,
		.set_dst_port = 0,
		.set_src_port = 0,
		.set_ttl = 0,
		.dec_ttl = 0,
		.dec_tcp_seq = 0,
		.dec_tcp_ack = 0,
		.inc_tcp_seq = 0,
		.inc_tcp_ack = 0,
		.dst_ip4 = 0,
		.src_ip4 = 0,
		.src_port = 0,
		.dst_port = 0,
		.ttl = 0,
		.tcp_seq = 0,
		.tcp_ack = 0,
	},
	.actions = {
		.vport_id = 0,
		.count = 0,
		.decap = 0,
		.remove_ethernet = 0,
		.timeout = 0,
		.encap = NULL,
		.add_ethernet = NULL,
		.modify = NULL,
	},
};
static int
vswitch_prepare_mode_c_flow(uint32_t flows_mode, uint16_t in_vport,
			    uint16_t out_vport,
			    struct vswitch_flow_structures **vfs_pp_ret,
			    uint32_t i) {
	static struct vswitch_flow_structures vfs;

	if (i == 0) {
		vfs_default_c.keys.vni = RTE_BE32(0x20) >> 8,
		vfs = vfs_default_c;
		VSWITCH_PRINT("flows packet pattern:\n");
		if (flows_mode < 50) {
			VSWITCH_PRINT("\tEther(type=0x86dd)/IP()/UDP(dport=250)/"
				      "VXLAN(vni=0x20,flags=0x%X, NextProtocol=2"
				      ")/IPv6(src="
				      "\"::0.0.%u.%u\",dst=\"::0.0.%u.%u\")/UDP"
				      "(dport=X,sport=Y)\n", 0x4, (in_vport >> 8) & 0xFF,
				      in_vport & 0xFF, (out_vport >> 8) & 0xFF,
				      out_vport & 0xFF);
		} else {
			VSWITCH_PRINT("\tEther(type=0x86dd)/IP()/UDP(dport=250)/"
				      "VXLAN(vni=0x20,flags=0x%X, NextProtocol=2"
				      ")/IPv6(src="
				      "\"::0.0.%u.%u\",dst=\"::0.0.%u.%u\")/TCP"
				      "(dport=X,sport=Y)\n", 0x4, (in_vport >> 8) & 0xFF,
				      in_vport & 0xFF, (out_vport >> 8) & 0xFF,
				      out_vport & 0xFF);
		}
		VSWITCH_PRINT("\tY = flow_index & 0xFFFF\n");
		VSWITCH_PRINT("\tX = (flow_index >> 16) & 0xFFFF\n");
		VSWITCH_PRINT("\tsrc vport is %u\n\tdst vport is %u\n",
			      in_vport, out_vport);
		VSWITCH_PRINT("flows packet actions:\n\tdefault MARK and"
			      " RSS\n");
		switch(flows_mode) {
			case 3:
				vfs.actions.decap = 1;
				vfs.actions.add_ethernet = &vfs.eth;
				VSWITCH_PRINT(", DECUP + add ethernet "
		                              "dst 00:37:44:9A:0D:FF src"
					      " 00:38:44;9A:0D:FF type "
	                                      "0x86dd\n");
				break;
			case 26:
				vfs.actions.modify = &vfs.modify;
				vfs.modify.set_dst_ip6 = 1;
				vfs.modify.set_dst_port = 1;
				vfs.actions.decap = 1;
				vfs.actions.add_ethernet = &vfs.eth;
				VSWITCH_PRINT(", DNAT + DECUP + add ethernet dst"
					      " 00:37:44:9A:0D:FF src"
					      " 00:38:44;9A:0D:FF type 0x86dd\n");
				break;
			case 51:
				vfs.keys.inner.proto = IPPROTO_TCP;
				vfs.keys.inner.tcp_flags_valid.syn = 1;
				vfs.keys.inner.tcp_flags_valid.rst = 1;
				vfs.keys.inner.tcp_flags_valid.fin = 1;
				vfs.actions.modify = &vfs.modify;
				vfs.modify.set_dst_ip6 = 1;
				vfs.modify.set_dst_port = 1;
				vfs.actions.decap = 1;
				vfs.actions.add_ethernet = &vfs.eth;
				VSWITCH_PRINT(", DNAT + DECUP + add ethernet dst"
					      " 00:37:44:9A:0D:FF src"
					      " 00:38:44;9A:0D:FF type 0x800\n");
				break;
			default:
				printf("vswitch: unknown mode_c flows %u\n",
				       flows_mode);
				return -ENOTSUP;
		}
	}
	*vfs_pp_ret = &vfs;
	switch(flows_mode) {
		case 3:
			break;
		case 26:
			vfs.modify.dst_ip6[15] = (uint8_t)(0xFF + i);
			vfs.modify.dst_ip6[14] = (uint8_t)((0xFF + i) >> 8);
			vfs.modify.dst_port = rte_cpu_to_be_16(0xFF + i);
			break;
		case 51:
			vfs.modify.dst_ip6[15] = (uint8_t)(0xFF + i);
			vfs.modify.dst_ip6[14] = (uint8_t)((0xFF + i) >> 8);
			vfs.modify.dst_port = rte_cpu_to_be_16(0xFF + i);
			break;
		default:
			printf("vswitch: unknown mode_c flows %u\n", flows_mode);
			return -ENOTSUP;
	}
	vfs.keys.inner.src_port = rte_cpu_to_be_16(i & 0xFFFF);
	vfs.keys.inner.dst_port = rte_cpu_to_be_16((i >> 16) & 0xFFFF);
	vfs.keys.inner.src_addr6[15] = in_vport & 0xff;
	vfs.keys.inner.src_addr6[14] = (in_vport & 0xff00) >> 8;
	vfs.keys.inner.dst_addr6[15] = out_vport & 0xff;
	vfs.keys.inner.dst_addr6[14] = (out_vport & 0xff00) >> 8;
	return 0;
}
struct vswitch_flow_structures vfs_default_d = {
	.keys = {
		.outer = {
			.ip_type = 1,
			.src_addr_valid = 1,
			.dst_addr_valid = 1,
			.proto_valid = 1,
			.src_port_valid = 1,
			.dst_port_valid = 1,
			.tcp_flags_valid = {
				.flags = 0,
			},
			.src_addr6 = "\x00\x00\x00\x00\x00\x00\x00\x00",
			.dst_addr6 = "\x00\x00\x00\x00\x00\x00\x00\x00",
			.proto = IPPROTO_UDP,
			.src_port = 0x1235,
			.dst_port = 0x1234,
			.tcp_flags = {
				.flags = 0,
			},
		},
		.tunnel_type = RTE_VSWITCH_TUNNEL_TYPE_NONE,
	},
	.eth = {
		.d_addr = {
			.addr_bytes = {0x00, 0x37, 0x44, 0x9A, 0x0D, 0xEC},
		},
		.s_addr = {
			.addr_bytes = {0x00, 0x37, 0x44, 0x9A, 0x0D, 0xED},
		},
		.ether_type = RTE_BE16(ETHER_TYPE_IPv4),
	},
	.encap = {
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
	},
	.modify = {
		.set_src_mac = 0,
		.set_dst_mac = 0,
		.set_dst_ip4 = 0,
		.set_src_ip4 = 0,
		.set_dst_ip6 = 0,
		.set_src_ip6 = 0,
		.set_dst_port = 0,
		.set_src_port = 0,
		.set_ttl = 0,
		.dec_ttl = 0,
		.dec_tcp_seq = 0,
		.dec_tcp_ack = 0,
		.inc_tcp_seq = 0,
		.inc_tcp_ack = 0,
		.dst_ip4 = 0,
		.src_ip4 = 0,
		.src_port = 0,
		.dst_port = 0,
		.ttl = 0,
		.tcp_seq = 0,
		.tcp_ack = 0,
	},
	.actions = {
		.vport_id = 0,
		.count = 0,
		.decap = 0,
		.remove_ethernet = 0,
		.timeout = 0,
		.encap = NULL,
		.add_ethernet = NULL,
		.modify = NULL,
	},
};
static int
vswitch_prepare_mode_d_flow(uint32_t flows_mode, uint16_t in_vport,
			    uint16_t out_vport,
			    struct vswitch_flow_structures **vfs_pp_ret,
			    uint32_t i) {
	static struct vswitch_flow_structures vfs;

	if (i == 0) {
		vfs_default_d.encap.vxlan_flags = 0x0c;
		vfs_default_d.encap.vxlan_protocol = 2;
		vfs_default_d.encap.vxlan_vni = 0x50;
		vfs = vfs_default_d;
		VSWITCH_PRINT("flows packet pattern:\n");
		if ((flows_mode < 200 && flows_mode >= 150) ||
		    flows_mode >= 251) {
			VSWITCH_PRINT("\t METADATA + Ether(type=0x800)/IPv6(src"
		                      "=\"::0.0.%u.%u\",dst=\"::0.0.%u.%u\")/"
			              "TCP(flags=0, dport=X,sport=Y)\n",
				      (in_vport >> 8) & 0xFF, in_vport & 0xFF,
				      (out_vport >> 8) & 0xFF, out_vport &
					      0xFF);
		} else {
			VSWITCH_PRINT("\t METADATA + Ether(type=0x800)/IPv6(src"
		                      "=\"::0.0.%u.%u\",dst=\"::0.0.%u.%u\")/"
			              "UDP(dport=X,sport=Y)\n",
			              (in_vport >> 8) & 0xFF, in_vport & 0xFF,
			              (out_vport >> 8) & 0xFF, out_vport & 0xFF);
		}
		VSWITCH_PRINT("\tY = flow_index & 0xFFFF\n");
		VSWITCH_PRINT("\tX = (flows_index >> 16) & 0xFFFF\n");
		VSWITCH_PRINT("\tsrc vport is %u\n\tdst vport is %u\n",
			      in_vport, out_vport);
		switch (flows_mode) {
			case 112:
				vfs.actions.modify = &vfs.modify;
				vfs.modify.set_dst_ip6 = 1;
				VSWITCH_PRINT("flows packet actions:\nthe vswitch"
					      " should change the dst ipv6 addr to"
					      " 0xFF+flow index, to encapsulate STD"
					      " vxlan in egress, send to LB and decap"
					      " the STD vxlan in ingress\n");
				break;
			case 113:
				vfs.actions.modify = &vfs.modify;
				vfs.modify.set_src_ip6 = 1;
				VSWITCH_PRINT("flows packet actions:\nthe vswitch"
					      " should change the src ipv6 addr to"
					      " 0xFF+flow index, to encapsulate STD"
					      " vxlan in egress, send to LB and decap"
					      " the STD vxlan in ingress\n");
				break;
			case 114:
				vfs.actions.modify = &vfs.modify;
				vfs.modify.dec_ttl = 1;
				vfs.modify.set_dst_mac = 1;
				memcpy(vfs.modify.dst_mac.addr_bytes,
				       (uint8_t [6]){0x0,0x11,0x22,0x33,0x44,0xFF}, 6);
				vfs.modify.set_src_mac = 1;
				memcpy(vfs.modify.src_mac.addr_bytes,
				       (uint8_t [6]){0x0,0x66,0x77,0x88,0x99,0xFF}, 6);
				VSWITCH_PRINT("flows packet actions:\nthe vswitch"
					      " should dec the ttl, set dst mac"
					      " 00:11:22:X:44:55, set src mac"
					      " 00:66:77:X:99:AA, to encapsulate STD"
					      " vxlan in egress, send to LB and decap"
					      " the STD vxlan in ingress\n");
				break;

			case 211:
				vfs.actions.encap = &vfs.encap;
				vfs.actions.remove_ethernet = 1;
				vfs.encap.ether = vfs.eth;
				VSWITCH_PRINT("flows packet actions:\n\tvxlan gpe"
					      " ENCAP + remove ethernet\n");
				vfs.actions.modify = &vfs.modify;
				vfs.modify.set_src_ip6 = 1;
				vfs.modify.set_src_port = 1;
				VSWITCH_PRINT(" + SNAT\n");
				break;
			case 226:
				vfs.actions.encap = &vfs.encap;
				vfs.encap.vxlan_flags = 0x0C;
				vfs.encap.vxlan_protocol = 0x2;
				vfs.actions.remove_ethernet = 1;
				vfs.encap.ether = vfs.eth;
				VSWITCH_PRINT("flows packet actions:\n\tENCAP vxlan"
					      " gpe + remove ethernet\n");
				break;
			case 251:
				vfs.keys.outer.proto = IPPROTO_TCP;
				vfs.keys.outer.tcp_flags_valid.syn = 1;
				vfs.keys.outer.tcp_flags_valid.rst = 1;
				vfs.keys.outer.tcp_flags_valid.fin = 1;
				vfs.actions.encap = &vfs.encap;
				vfs.actions.remove_ethernet = 1;
				vfs.encap.ether = vfs.eth;
				VSWITCH_PRINT("flows packet actions:\n\tENCAP +"
					      " remove ethernet\n");
				vfs.actions.modify = &vfs.modify;
				vfs.modify.set_src_ip6 = 1;
				vfs.modify.inc_tcp_seq = 1;
				vfs.modify.inc_tcp_ack = 1;
				VSWITCH_PRINT(" + SNAT + dec ttl + inc tcp seq\ack by"
					      " 0xFF + flow index\n");
				break;
			default:
				printf("vswitch: unknown mode_d flows %u\n",
				       flows_mode);
				return -ENOTSUP;
		}
	}
	*vfs_pp_ret = &vfs;
	switch (flows_mode) {
		case 112:
			vfs.modify.dst_ip6[15] = (0xFF + i) & 0xff;
			vfs.modify.dst_ip6[14] = ((0xFF + i) >> 8) & 0xff;
			break;
		case 113:
			vfs.modify.src_ip6[15] = (0xFF + i) & 0xff;
			vfs.modify.src_ip6[14] = ((0xFF + i) >> 8) & 0xff;
			break;
		case 114:
			vfs.modify.dst_mac.addr_bytes[3] = i;
			vfs.modify.src_mac.addr_bytes[3] = i;
			break;
		case 211:
			vfs.modify.src_ip6[15] = (0xFF + i) & 0xff;
			vfs.modify.src_ip6[14] = ((0xFF + i) >> 8) & 0xff;
			vfs.modify.src_port = rte_cpu_to_be_16(0xFF + i);
			break;
		case 226:
			break;
		case 251:
			vfs.modify.src_ip6[15] = (0xFF + i) & 0xff;
			vfs.modify.src_ip6[14] = ((0xFF + i) >> 8) & 0xff;
			vfs.modify.src_port = rte_cpu_to_be_16(0xFF + i);
			vfs.modify.tcp_ack = rte_cpu_to_be_32(0xFF + i);
			vfs.modify.tcp_seq = rte_cpu_to_be_32(0xFF + i);
			break;
		default:
			break;
	}
	vfs.keys.outer.src_port = rte_cpu_to_be_16(i & 0xFFFF);
	vfs.keys.outer.dst_port = rte_cpu_to_be_16((i >> 16) & 0xFFFF);
	vfs.keys.outer.src_addr6[15] = in_vport & 0xff;
	vfs.keys.outer.src_addr6[14] = (in_vport & 0xff00) >> 8;
	vfs.keys.outer.dst_addr6[15] = out_vport & 0xff;
	vfs.keys.outer.dst_addr6[14] = (out_vport & 0xff00) >> 8;
	return 0;
}
int
vswitch_prepare_flow(uint32_t flows_mode, uint16_t in_vport,
		     uint16_t out_vport,
		     struct vswitch_flow_structures **vfs_pp_ret,
		     uint32_t i) {

	switch (flows_mode) {
	/* tunnel flows without any modifications */
	case 0:
	/* tunnel flows with decap + add ethernet */
	case 1:
	/* tunnel flows with dst ip\port modify decap + add ethernet */
	case 2:
	/*
	 * tunnel flows with outer dst IP match, dst ip\port modify decap +
	 * add ethernet
	 */
	case 4:
	/* VXLAN-GPE tunnel flows with decap + add ethernet */
	case 25:
	/*
	 * tunnel flows(inner tcp) with dst ip\port modify decap +
	 * add ethernet
	 */
	case 50:
	/* tunnel flows(inner tcp), tcp seq\ack modify, decap + add ethernet */
	case 52:
		if (vswitch_prepare_mode_a_flow(flows_mode,
						in_vport,
						out_vport,
						vfs_pp_ret, i))
			return -1;
		break;
	/* ipv6 VXLAN-GPE tunnel flows with decap + add ethernet */
	case 3:
	/*
	 * ipv6 VXLAN-GPE tunnel flows with dst ip/port modify decap +
	 * add ethernet
	 * */
	case 26:
	/*
	 * vxlan gpe tunnel flows - inner ipv6 TCP(syn=rst=fin=0)
	 * with dst ip/port modify decap +add ethernet
	 * */
	case 51:
		if (vswitch_prepare_mode_c_flow(flows_mode,
						in_vport,
						out_vport,
						vfs_pp_ret, i))
			return -1;
		break;
	/* regular packet flow without and modification */
	case 101:
	/* regular packet flow with dst ipv4 modify */
	case 102:
	/* regular packet flow with src ipv4 modify */
	case 103:
	/* regular packet flow with dst port modify */
	case 104:
	/* regular packet flow with src port modify */
	case 105:
	/* regular packet flow with set ttl modify */
	case 106:
	/* regular packet flow with dec ttl modify */
	case 107:
	/* regular packet flow dst/src ipv4/port modify */
	case 108:
	/* regular packet flow dst/src ipv4/port, dec ttl modify */
	case 109:
	/* regular packet flow dst/src ipv4/port, set ttl modify */
	case 110:
	/* regular packet flow dst/src mac, dec ttl modify */
	case 111:
	/*
	 * regular TCP packet flow dst/src ipv4/port, dec ttl and inc tcp seq
	 * modify
	 */
	case 150:
	/*
	 * regular TCP packet flow dst/src ipv4/port, dec ttl and inc tcp ack
	 * modify
	 */
	case 151:
	/* regular TCP packet flow inc tcp ack modify */
	case 152:
	/* regular TCP packet flow dec tcp ack modify */
	case 153:
	/* regular TCP packet flow inc tcp seq modify */
	case 154:
	/* regular TCP packet flow dec tcp seq modify */
	case 155:
	/* regular packet flow with encap + remove eth */
	case 200:
	/* regular packet flow with encap + remove eth + src ip\port modify */
	case 201:
	/* regular packet flow with encap vxlan gpe + remove eth */
	case 225:
	/*
	 * regular TCP packet flow with encap + remove eth + src ip\port dec
	 * ttl and inc tcp seq\ack modify
	 */
	case 250:
	/* regular TCP packet flow with encap+remove eth, inc seq\ack modify */
	case 252:
		if (vswitch_prepare_mode_b_flow(flows_mode,
						in_vport,
						out_vport,
						vfs_pp_ret, i))
			return -1;
		break;
	/* regular packet flow with dst ipv6 modify */
	case 112:
	/* regular packet flow with src ipv6 modify */
	case 113:
	/* V->V: regular ipv6 packet flow dst/src mac dec ttl modify */
	case 114:
	/* flows ipv6 packet actions: encap + remove ethernet + SNAT */
	case 211:
	/*
	 * regular ipv6 packet flows with encap vxlan gpe +
	 * remove ethernet.
	 * */
	case 226:
	/*
	 * regular ipv6 TCP packet flow with encap remove eth + src ip
	 * and inc tcp modify.
	 */
	case 251:
		if (vswitch_prepare_mode_d_flow(flows_mode,
						in_vport,
						out_vport,
						vfs_pp_ret, i))
			return -1;
			break;
	default:
		printf("vswitch: mode %u is not supported\n",
		      flows_mode);
		return -ENOTSUP;
	}
	return 0;
}
