#   BSD LICENSE
#
#   Copyright 2015 6WIND S.A.
#   Copyright 2015 Mellanox.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions
#   are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#     * Neither the name of 6WIND S.A. nor the names of its
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

include $(RTE_SDK)/mk/rte.vars.mk

# Library name.
LIB = librte_pmd_mlx5.a
LIB_GLUE = $(LIB_GLUE_BASE).$(LIB_GLUE_VERSION)
LIB_GLUE_BASE = librte_pmd_mlx5_glue.so
LIB_GLUE_VERSION = 18.11.0

# Library name.
LIB = librte_pmd_mlx5.a

# Sources.
SRCS-$(CONFIG_RTE_LIBRTE_MLX5_PMD) += mlx5.c
ifneq ($(CONFIG_RTE_LIBRTE_MLX5_DLOPEN_DEPS),y)
SRCS-$(CONFIG_RTE_LIBRTE_MLX5_PMD) += mlx5_glue.c
endif
SRCS-$(CONFIG_RTE_LIBRTE_MLX5_PMD) += mlx5_rxq.c
SRCS-$(CONFIG_RTE_LIBRTE_MLX5_PMD) += mlx5_txq.c
SRCS-$(CONFIG_RTE_LIBRTE_MLX5_PMD) += mlx5_rxtx.c
ifneq ($(filter y,$(CONFIG_RTE_ARCH_X86_64) \
		  $(CONFIG_RTE_ARCH_ARM64)),)
SRCS-$(CONFIG_RTE_LIBRTE_MLX5_PMD) += mlx5_rxtx_vec.c
endif
SRCS-$(CONFIG_RTE_LIBRTE_MLX5_PMD) += mlx5_trigger.c
SRCS-$(CONFIG_RTE_LIBRTE_MLX5_PMD) += mlx5_ethdev.c
SRCS-$(CONFIG_RTE_LIBRTE_MLX5_PMD) += mlx5_nl.c
SRCS-$(CONFIG_RTE_LIBRTE_MLX5_PMD) += mlx5_mac.c
SRCS-$(CONFIG_RTE_LIBRTE_MLX5_PMD) += mlx5_rxmode.c
SRCS-$(CONFIG_RTE_LIBRTE_MLX5_PMD) += mlx5_vlan.c
SRCS-$(CONFIG_RTE_LIBRTE_MLX5_PMD) += mlx5_stats.c
SRCS-$(CONFIG_RTE_LIBRTE_MLX5_PMD) += mlx5_rss.c
SRCS-$(CONFIG_RTE_LIBRTE_MLX5_PMD) += mlx5_mr.c
SRCS-$(CONFIG_RTE_LIBRTE_MLX5_PMD) += mlx5_flow.c
SRCS-$(CONFIG_RTE_LIBRTE_MLX5_PMD) += mlx5_flow_dv.c
SRCS-$(CONFIG_RTE_LIBRTE_MLX5_PMD) += mlx5_flow_verbs.c
SRCS-$(CONFIG_RTE_LIBRTE_MLX5_PMD) += mlx5_socket.c
SRCS-$(CONFIG_RTE_LIBRTE_MLX5_PMD) += mlx5_devx_cmds.c
SRCS-$(CONFIG_RTE_LIBRTE_MLX5_PMD) += mlx5_flow_meter.c

# Basic CFLAGS.
CFLAGS += -O3
CFLAGS += -std=c11 -Wall -Wextra
CFLAGS += -g
CFLAGS += -I.
CFLAGS += -D_BSD_SOURCE
CFLAGS += -D_DEFAULT_SOURCE
CFLAGS += -D_XOPEN_SOURCE=600
CFLAGS += $(WERROR_FLAGS)
CFLAGS += -Wno-strict-prototypes
ifeq ($(CONFIG_RTE_LIBRTE_MLX5_DLOPEN_DEPS),y)
CFLAGS += -DMLX5_GLUE='"$(LIB_GLUE)"'
CFLAGS += -DMLX5_GLUE_VERSION='"$(LIB_GLUE_VERSION)"'
CFLAGS_mlx5_glue.o += -fPIC
LDLIBS += -ldl
else
LDLIBS += -libverbs -lmlx5
endif
LDLIBS += -lrte_eal -lrte_mbuf -lrte_mempool -lrte_ring -lrte_hash
LDLIBS += -lrte_ethdev -lrte_net -lrte_kvargs
LDLIBS += -lrte_bus_pci
LDLIBS += -lpthread

# A few warnings cannot be avoided in external headers.
CFLAGS += -Wno-error=cast-qual

EXPORT_MAP := rte_pmd_mlx5_version.map
LIBABIVER := 1

# DEBUG which is usually provided on the command-line may enable
# CONFIG_RTE_LIBRTE_MLX5_DEBUG.
ifeq ($(DEBUG),1)
CONFIG_RTE_LIBRTE_MLX5_DEBUG := y
endif

# User-defined CFLAGS.
ifeq ($(CONFIG_RTE_LIBRTE_MLX5_DEBUG),y)
CFLAGS += -pedantic -UNDEBUG -DPEDANTIC
else
CFLAGS += -DNDEBUG -UPEDANTIC
endif

ifdef CONFIG_RTE_LIBRTE_MLX5_MR_CACHE_N
CFLAGS += -DMLX5_MR_CACHE_N=$(CONFIG_RTE_LIBRTE_MLX5_MR_CACHE_N)
endif

ifeq ($(CONFIG_RTE_LIBRTE_MLX5_FLOW_CACHE),y)
CFLAGS += -DRTE_LIBRTE_MLX5_FLOW_CACHE
else
endif

include $(RTE_SDK)/mk/rte.lib.mk

# Generate and clean-up mlx5_autoconf.h.

export CC CFLAGS CPPFLAGS EXTRA_CFLAGS EXTRA_CPPFLAGS
export AUTO_CONFIG_CFLAGS = -Wno-error

ifndef V
AUTOCONF_OUTPUT := >/dev/null
endif

mlx5_autoconf.h.new: FORCE

mlx5_autoconf.h.new: $(RTE_SDK)/buildtools/auto-config-h.sh
	$Q $(RM) -f -- '$@'
	$Q sh -- '$<' '$@' \
		HAVE_IBV_FLOW_DV_SUPPORT \
		infiniband/mlx5dv.h \
		enum MLX5DV_FLOW_ACTION_TAG \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_IBV_FLOW_TABLE_SUPPORT \
		infiniband/mlx5dv.h \
		enum MLX5_IB_UAPI_FLOW_TABLE_TYPE_NIC_RX \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_IBV_FLOW_ACT_PKT_REFRMT_SUPPORT \
		infiniband/mlx5dv.h \
		enum MLX5_IB_UAPI_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TUNNEL_TO_L2 \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_IBV_QP_CREATE_TIR_ALLOW_SELF_LPBK_UC_SUPPORT \
		infiniband/mlx5dv.h \
		enum MLX5DV_QP_CREATE_TIR_ALLOW_SELF_LOOPBACK_UC \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_IBV_DEVICE_STRIDING_RQ_SUPPORT \
		infiniband/mlx5dv.h \
		enum MLX5DV_CQE_RES_FORMAT_CSUM_STRIDX \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_IBV_DEVICE_TUNNEL_SUPPORT \
		infiniband/mlx5dv.h \
		enum MLX5DV_CONTEXT_MASK_TUNNEL_OFFLOADS \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_IBV_MLX5_MOD_SWP \
		infiniband/mlx5dv.h \
		type 'struct mlx5dv_sw_parsing_caps' \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_IBV_MLX5_MOD_MPW \
		infiniband/mlx5dv.h \
		enum MLX5DV_CONTEXT_FLAGS_MPW_ALLOWED \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_IBV_MLX5_MOD_CQE_128B_COMP \
		infiniband/mlx5dv.h \
		enum MLX5DV_CONTEXT_FLAGS_CQE_128B_COMP \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_IBV_FLOW_DEVX_COUNTERS \
		infiniband/mlx5dv.h \
		enum MLX5DV_FLOW_ACTION_COUNTERS_DEVX \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_IBV_DEVX_CONTEXT \
		infiniband/mlx5dv.h \
		enum MLX5DV_CONTEXT_FLAGS_DEVX \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_IBV_DEVX_OBJ \
		infiniband/mlx5dv.h \
		func mlx5dv_devx_obj_create \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_MLX5DV_DR \
		infiniband/mlx5dv.h \
		enum MLX5DV_DR_DOMAIN_TYPE_NIC_RX \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_MLX5DV_DR_METER \
		infiniband/mlx5dv.h \
		func mlx5dv_dr_create_action_devx_meter \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_MLX5DV_DR_FT \
		infiniband/mlx5dv.h \
		func mlx5dv_dr_create_ft \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_MLX5_DR_CREATE_ACTION_FLOW_METER \
		infiniband/mlx5dv.h \
		func mlx5dv_dr_action_create_flow_meter \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_MLX5_DEVX_ASYNC_SUPPORT \
		infiniband/mlx5dv.h \
		type 'struct mlx5dv_devx_cmd_comp' \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_MLX5DV_DR_ESWITCH \
		infiniband/mlx5dv.h \
		enum MLX5DV_DR_DOMAIN_TYPE_FDB \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_IBV_WQ_FLAG_RX_END_PADDING \
		infiniband/verbs.h \
		enum IBV_WQ_FLAG_RX_END_PADDING \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_IBV_DEVICE_COUNTERS_SET_V42 \
		infiniband/verbs.h \
		type 'struct ibv_counter_set_init_attr' \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_IBV_DEVICE_COUNTERS_SET_V45 \
		infiniband/verbs.h \
		type 'struct ibv_counters_init_attr' \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_ETHTOOL_LINK_MODE_25G \
		/usr/include/linux/ethtool.h \
		enum ETHTOOL_LINK_MODE_25000baseCR_Full_BIT \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_RDMA_NL_NLDEV \
		rdma/rdma_netlink.h \
		enum RDMA_NL_NLDEV \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_RDMA_NLDEV_CMD_GET \
		rdma/rdma_netlink.h \
		enum RDMA_NLDEV_CMD_GET \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_RDMA_NLDEV_CMD_PORT_GET \
		rdma/rdma_netlink.h \
		enum RDMA_NLDEV_CMD_PORT_GET \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_RDMA_NLDEV_ATTR_DEV_INDEX \
		rdma/rdma_netlink.h \
		enum RDMA_NLDEV_ATTR_DEV_INDEX \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_RDMA_NLDEV_ATTR_DEV_NAME \
		rdma/rdma_netlink.h \
		enum RDMA_NLDEV_ATTR_DEV_NAME \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_RDMA_NLDEV_ATTR_PORT_INDEX \
		rdma/rdma_netlink.h \
		enum RDMA_NLDEV_ATTR_PORT_INDEX \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_RDMA_NLDEV_ATTR_NDEV_INDEX \
		rdma/rdma_netlink.h \
		enum RDMA_NLDEV_ATTR_NDEV_INDEX \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_IFLA_NUM_VF \
		linux/if_link.h \
		enum IFLA_NUM_VF \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_IFLA_EXT_MASK \
		linux/if_link.h \
		enum IFLA_EXT_MASK \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_IFLA_PHYS_SWITCH_ID \
		linux/if_link.h \
		enum IFLA_PHYS_SWITCH_ID \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_ETHTOOL_LINK_MODE_50G \
		/usr/include/linux/ethtool.h \
		enum ETHTOOL_LINK_MODE_50000baseCR2_Full_BIT \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_ETHTOOL_LINK_MODE_100G \
		/usr/include/linux/ethtool.h \
		enum ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_CHAIN \
		linux/rtnetlink.h \
		enum TCA_CHAIN \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_ACT \
		linux/pkt_cls.h \
		enum TCA_FLOWER_ACT \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_FLAGS \
		linux/pkt_cls.h \
		enum TCA_FLOWER_FLAGS \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_ETH_TYPE \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_ETH_TYPE \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_ETH_DST \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_ETH_DST \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_ETH_DST_MASK \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_ETH_DST_MASK \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_ETH_SRC \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_ETH_SRC \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_ETH_SRC_MASK \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_ETH_SRC_MASK \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_IP_PROTO \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_IP_PROTO \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_IPV4_SRC \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_IPV4_SRC \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_IPV4_SRC_MASK \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_IPV4_SRC_MASK \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_IPV4_DST \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_IPV4_DST \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_IPV4_DST_MASK \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_IPV4_DST_MASK \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_IPV6_SRC \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_IPV6_SRC \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_IPV6_SRC_MASK \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_IPV6_SRC_MASK \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_IPV6_DST \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_IPV6_DST \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_IPV6_DST_MASK \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_IPV6_DST_MASK \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_TCP_SRC \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_TCP_SRC \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_TCP_SRC_MASK \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_TCP_SRC_MASK \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_TCP_DST \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_TCP_DST \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_TCP_DST_MASK \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_TCP_DST_MASK \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_UDP_SRC \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_UDP_SRC \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_UDP_SRC_MASK \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_UDP_SRC_MASK \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_UDP_DST \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_UDP_DST \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_UDP_DST_MASK \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_UDP_DST_MASK \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_VLAN_ID \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_VLAN_ID \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_VLAN_PRIO \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_VLAN_PRIO \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_VLAN_ETH_TYPE \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_VLAN_ETH_TYPE \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_TCP_FLAGS \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_TCP_FLAGS \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_TCP_FLAGS_MASK \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_TCP_FLAGS_MASK \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_IP_TOS \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_IP_TOS \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_IP_TOS_MASK \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_IP_TOS_MASK \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_IP_TTL \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_IP_TTL \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_IP_TTL_MASK \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_IP_TTL_MASK \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TC_ACT_GOTO_CHAIN \
		linux/pkt_cls.h \
		define TC_ACT_GOTO_CHAIN \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TC_ACT_VLAN \
		linux/tc_act/tc_vlan.h \
		enum TCA_VLAN_PUSH_VLAN_PRIORITY \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_ENC_KEY_ID \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_ENC_KEY_ID \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_ENC_IPV4_SRC \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_ENC_IPV4_SRC \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_ENC_IPV4_SRC_MASK \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_ENC_IPV4_SRC_MASK \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_ENC_IPV4_DST \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_ENC_IPV4_DST \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_ENC_IPV4_DST_MASK \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_ENC_IPV4_DST_MASK \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_ENC_IPV6_SRC \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_ENC_IPV6_SRC \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_ENC_IPV6_SRC_MASK \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_ENC_IPV6_SRC_MASK \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_ENC_IPV6_DST \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_ENC_IPV6_DST \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_ENC_IPV6_DST_MASK \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_ENC_IPV6_DST_MASK \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_ENC_UDP_SRC_PORT \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_ENC_UDP_SRC_PORT \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_ENC_UDP_SRC_PORT_MASK \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_ENC_UDP_SRC_PORT_MASK \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_ENC_UDP_DST_PORT \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_ENC_UDP_DST_PORT \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_ENC_UDP_DST_PORT_MASK \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_ENC_UDP_DST_PORT_MASK \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_ENC_IP_TOS \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_ENC_IP_TOS \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_ENC_IP_TOS_MASK \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_ENC_IP_TOS_MASK \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_ENC_IP_TTL \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_ENC_IP_TTL \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_FLOWER_KEY_ENC_IP_TTL_MASK \
		linux/pkt_cls.h \
		enum TCA_FLOWER_KEY_ENC_IP_TTL_MASK \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TC_ACT_TUNNEL_KEY \
		linux/tc_act/tc_tunnel_key.h \
		define TCA_ACT_TUNNEL_KEY \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_TUNNEL_KEY_ENC_DST_PORT \
		linux/tc_act/tc_tunnel_key.h \
		enum TCA_TUNNEL_KEY_ENC_DST_PORT \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_TUNNEL_KEY_ENC_TOS \
		linux/tc_act/tc_tunnel_key.h \
		enum TCA_TUNNEL_KEY_ENC_TOS \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_TUNNEL_KEY_ENC_TTL \
		linux/tc_act/tc_tunnel_key.h \
		enum TCA_TUNNEL_KEY_ENC_TTL \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TCA_TUNNEL_KEY_NO_CSUM \
		linux/tc_act/tc_tunnel_key.h \
		enum TCA_TUNNEL_KEY_NO_CSUM \
		$(AUTOCONF_OUTPUT)
	$Q sh -- '$<' '$@' \
		HAVE_TC_ACT_PEDIT \
		linux/tc_act/tc_pedit.h \
		enum TCA_PEDIT_KEY_EX_HDR_TYPE_UDP \
		$(AUTOCONF_OUTPUT)

# Create mlx5_autoconf.h or update it in case it differs from the new one.

mlx5_autoconf.h: mlx5_autoconf.h.new
	$Q [ -f '$@' ] && \
		cmp '$<' '$@' $(AUTOCONF_OUTPUT) || \
		mv '$<' '$@'

$(SRCS-$(CONFIG_RTE_LIBRTE_MLX5_PMD):.c=.o): mlx5_autoconf.h

clean_mlx5: FORCE
	$Q rm -f -- mlx5_autoconf.h mlx5_autoconf.h.new

clean: clean_mlx5
