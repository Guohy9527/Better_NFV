/*-
 *   BSD LICENSE
 *
 *   Copyright 2015 6WIND S.A.
 *   Copyright 2015 Mellanox.
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

#ifndef RTE_PMD_MLX5_H_
#define RTE_PMD_MLX5_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/queue.h>

/* Verbs header. */
/* ISO C doesn't support unnamed structs/unions, disabling -pedantic. */
#ifdef PEDANTIC
#pragma GCC diagnostic ignored "-Wpedantic"
#endif
#include <infiniband/verbs.h>
#ifdef PEDANTIC
#pragma GCC diagnostic error "-Wpedantic"
#endif

#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_spinlock.h>
#include <rte_interrupts.h>
#include <rte_errno.h>
#include <rte_flow.h>
#include <rte_hlist.h>

#include "mlx5_utils.h"
#include "mlx5_rxtx.h"
#include "mlx5_autoconf.h"
#include "mlx5_defs.h"

enum {
	PCI_VENDOR_ID_MELLANOX = 0x15b3,
};

enum {
	PCI_DEVICE_ID_MELLANOX_CONNECTX4 = 0x1013,
	PCI_DEVICE_ID_MELLANOX_CONNECTX4VF = 0x1014,
	PCI_DEVICE_ID_MELLANOX_CONNECTX4LX = 0x1015,
	PCI_DEVICE_ID_MELLANOX_CONNECTX4LXVF = 0x1016,
	PCI_DEVICE_ID_MELLANOX_CONNECTX5 = 0x1017,
	PCI_DEVICE_ID_MELLANOX_CONNECTX5VF = 0x1018,
	PCI_DEVICE_ID_MELLANOX_CONNECTX5EX = 0x1019,
	PCI_DEVICE_ID_MELLANOX_CONNECTX5EXVF = 0x101a,
	PCI_DEVICE_ID_MELLANOX_CONNECTX5BF = 0xa2d2,
};

struct mlx5_devx_mkey {
	void *		obj;
	uint32_t	key;
};

struct mlx5_devx_mkey_attr {
	uint64_t	addr;
	uint64_t	size;
	uint32_t	pas_id;
	uint32_t	pd;
};

/* Recognized Infiniband device physical port name types. */
enum mlx5_phys_port_name_type {
	MLX5_PHYS_PORT_NAME_TYPE_NOTSET = 0, /* Not set. */
	MLX5_PHYS_PORT_NAME_TYPE_LEGACY, /* before kernel ver < 5.0 */
	MLX5_PHYS_PORT_NAME_TYPE_UPLINK, /* p0, kernel ver >= 5.0 */
	MLX5_PHYS_PORT_NAME_TYPE_PFVF, /* pf0vf0, kernel ver >= 5.0 */
	MLX5_PHYS_PORT_NAME_TYPE_UNKNOWN, /* Unrecognized. */
};

/** Switch information returned by mlx5_nl_switch_info(). */
struct mlx5_switch_info {
	uint32_t master:1; /**< Master device. */
	uint32_t representor:1; /**< Representor device. */
	enum mlx5_phys_port_name_type name_type; /** < Port name type. */
	int32_t pf_num; /**< PF number (valid for pfxvfx format only). */
	int32_t port_name; /**< Representor port name. */
	uint64_t switch_id; /**< Switch identifier. */
};

LIST_HEAD(mlx5_dev_list, priv);

struct mlx5_counter_ctrl {
	/* Name of the counter. */
	char dpdk_name[RTE_ETH_XSTATS_NAME_SIZE];
	/* Name of the counter on the device table. */
	char ctr_name[RTE_ETH_XSTATS_NAME_SIZE];
	uint32_t ib:1; /**< Nonzero for IB counters. */
};

struct mlx5_xstats_ctrl {
	/* Number of device stats. */
	uint16_t stats_n;
	/* Number of device stats identified by PMD. */
	uint16_t  mlx5_stats_n;
	/* Index in the device counters table. */
	uint16_t dev_table_idx[MLX5_MAX_XSTATS];
	uint64_t base[MLX5_MAX_XSTATS];
	struct mlx5_counter_ctrl info[MLX5_MAX_XSTATS];
};

/* Flow list . */
#ifdef RTE_LIBRTE_MLX5_FLOW_CACHE
TAILQ_HEAD(mlx5_flows, rte_flow);
#else
TAILQ_HEAD(mlx5_flows, rte_flow_handle);
#endif

/* Flow meter profile list. */
TAILQ_HEAD(mlx5_flow_meter_profiles, mlx5_flow_meter_profile);

TAILQ_HEAD(mlx5_flow_meters, mlx5_flow_meter);

#ifndef HAVE_MLX5_DEVX_ASYNC_SUPPORT
struct mlx5dv_devx_cmd_comp;
#endif

/* counters struct */
enum mlx5_counter_type {
	MLX5_COUNTER_TYPE_SINGLE,
	MLX5_COUNTER_TYPE_BULK,
	MLX5_COUNTER_TYPE_EXTERNAL,
};

struct mlx5_devx_counter_set {
	TAILQ_ENTRY(mlx5_devx_counter_set) next;
	/**< Pointer to the next counter. */
	enum mlx5_counter_type type; /**< The counter type. */
	union {
		void *obj; /* Struct mlx5dv_devx_obj *obj; */
		struct mlx5_flow_bulk_counters *bulk;
		/**< Pointer to the bulk. */ 
	};
	uint32_t id; /* Flow counter ID */
};

TAILQ_HEAD(mlx5_dcs, mlx5_devx_counter_set);

/* Default PMD specific parameter value. */
#define MLX5_ARG_UNSET (-1)

/* Structure for Drop queue. */
struct mlx5_hrxq_drop {
	struct ibv_rwq_ind_table *ind_table; /**< Indirection table. */
	struct ibv_qp *qp; /**< Verbs queue pair. */
	struct ibv_wq *wq; /**< Verbs work queue. */
	struct ibv_cq *cq; /**< Verbs completion queue. */
};

struct mlx5_hca_qos_attr {
	uint32_t sup:1;	/* QOS is supported */
	uint32_t srtcm_sup:1; /* "single rate 3 color mode" support */
	uint8_t log_max_flow_meter;
	uint8_t flow_meter_reg_c_ids;
	/* Bitmap of the reg_Cs available for flow meter use */

};

struct mlx5_hca_attr {
	struct mlx5_hca_qos_attr qos;
	uint32_t eswitch_manager:1;
	uint8_t flow_counter_bulk_alloc_bitmap;
};

/*
 * Device configuration structure.
 *
 * Merged configuration from:
 *
 *  - Device capabilities,
 *  - User device parameters disabled features.
 */
struct mlx5_dev_config {
	unsigned int hw_csum:1; /* Checksum offload is supported. */
	unsigned int hw_vlan_strip:1; /* VLAN stripping is supported. */
	unsigned int hw_fcs_strip:1; /* FCS stripping is supported. */
	unsigned int hw_padding:1; /* End alignment padding is supported. */
	unsigned int hw_vxlan_rx:1; /* VXLAN RX offload is supported. */
	unsigned int hw_gre_rx:1; /* GRE RX offload is supported. */
	unsigned int mps:2; /* Multi-packet send supported mode. */
	unsigned int tunnel_en:1;
	/* Whether tunnel stateless offloads are supported. */
	unsigned int flow_counter_en:1; /* Whether flow counter is supported. */
	unsigned int cqe_comp:1; /* CQE compression is enabled. */
	unsigned int tso:1; /* Whether TSO is supported. */
	unsigned int tx_vec_en:1; /* Tx vector is enabled. */
	unsigned int rx_vec_en:1; /* Rx vector is enabled. */
	unsigned int mpw_hdr_dseg:1; /* Enable DSEGs in the title WQEBB. */
	unsigned int l3_vxlan_en:1; /* Enable L3 VXLAN flow creation. */
	unsigned int vf_nl_en:1; /* Enable Netlink requests in VF mode. */
	unsigned int dv_flow_en:1; /* Enable DV flow. */
	unsigned int dv_eswitch_en:1; /* Enable eswitch flow config via DV. */
	unsigned int flow_metering:1; /* Whether flow metering is supported. */
	unsigned int swp:1; /* Whether software parser is supported. */
	unsigned int swp_force:1; /* Whether software parser is forced. */
	unsigned int devx:1; /* Whether devx interface is available or not. */
	struct {
		unsigned int enabled:1; /* Whether MPRQ is enabled. */
		unsigned int stride_num_n; /* Number of strides. */
		unsigned int min_stride_size_n; /* Min size of a stride. */
		unsigned int max_stride_size_n; /* Max size of a stride. */
		unsigned int max_memcpy_len;
		/* Maximum packet size to memcpy Rx packets. */
		unsigned int min_rxqs_num;
		/* Rx queue count threshold to enable MPRQ. */
	} mprq; /* Configurations for Multi-Packet RQ. */
	/* Total number of flow priorities available */
	unsigned int flow_prio;
	unsigned int tso_max_payload_sz; /* Maximum TCP payload for TSO. */
	unsigned int ind_table_max_size; /* Maximum indirection table size. */
	int txq_inline; /* Maximum packet size for inlining. */
	int txqs_inline; /* Queue number threshold for inlining. */
	int inline_max_packet_sz; /* Max packet size for inlining. */
	uint64_t rss_fields_mask; /* Mask for disabling/enabling RSS fields. */
	struct mlx5_hca_attr hca_attr; /* HCA attributes. */
};

/* 8 Verbs priorities. */
#define MLX5_VERBS_FLOW_PRIO_8 8
/* Verbs priorities per flow priority. */
#define MLX5_FLOW_VERBS_SPAN 3
/* Minimal user flow priorities. */
#define MLX5_USER_FLOWS_MIN 2

/**
 * Type of objet being allocated.
 */
enum mlx5_verbs_alloc_type {
	MLX5_VERBS_ALLOC_TYPE_NONE,
	MLX5_VERBS_ALLOC_TYPE_TX_QUEUE,
	MLX5_VERBS_ALLOC_TYPE_RX_QUEUE,
};


/**
 * Verbs allocator needs a context to know in the callback which kind of
 * resources it is allocating.
 */
struct mlx5_verbs_alloc_ctx {
	enum mlx5_verbs_alloc_type type; /* Kind of object being allocated. */
	const void *obj; /* Pointer to the DPDK object. */
};

/* Flow drop context necessary due to Verbs API. */
struct mlx5_drop {
	struct mlx5_hrxq *hrxq; /* Hash Rx queue queue. */
	struct mlx5_rxq_ibv *rxq; /* Verbs Rx queue. */
};

struct mlx5_flow_tcf_context;

/* Direct Rules max tables. */
#define MLX5_MAX_TABLES 1024
#define MLX5_MAX_FDB_TABLES 32
/* Max number of prioritys for DR table */
#define MLX5_MAX_NUMBER_OF_PRIORITYS 16
#define MLX5_FLOW_TABLE_FACTOR 1

/* Per port data of shared IB device. */
struct mlx5_ibv_shared_port {
	uint32_t ih_port_id;
	/*
	 * Interrupt handler port_id. Used by shared interrupt
	 * handler to find the corresponding rte_eth device
	 * by IB port index. If value is equal or greater
	 * RTE_MAX_ETHPORTS it means there is no subhandler
	 * installed for specified IB port index.
	 */
};

/*
 * Shared Infiniband device context for Master/Representors
 * which belong to same IB device with multiple IB ports.
 **/
struct mlx5_ibv_shared {
	LIST_ENTRY(mlx5_ibv_shared) next;
	uint32_t refcnt;
	uint32_t devx:1; /* Opened with DV. */
	uint32_t max_port; /* Maximal IB device port index. */
	struct ibv_context *ctx; /* Verbs/DV context. */
	struct ibv_pd *pd; /* Protection Domain. */
	char ibdev_name[IBV_SYSFS_NAME_MAX]; /* IB device name. */
	char ibdev_path[IBV_SYSFS_PATH_MAX]; /* IB device path for secondary */
	struct ibv_device_attr_ex device_attr; /* Device properties. */
	struct mlx5_mr (*mr)[]; /* Static MR table. */
	struct mlx5_mr_cache (*mr_cache)[]; /* Global MR cache table. */
	uint32_t mr_n; /* Size of static MR table. */
	uint32_t mr_refcnt; /* MR table reference counter. */
	/* Shared DV/DR flow data section. */
	pthread_mutex_t dv_mutex; /* DV context mutex. */
	uint32_t dv_refcnt; /* DV/DR data reference counter. */
	void *rx_domain; /* RX Direct Rules name space handle. */
	void *rx_tables[MLX5_MAX_TABLES]; /* RX Direct Rules tables/ */
	void *rx_meter_suffix_table;
	/* RX suffix table for handling flows with meters */
	void *tx_domain; /* TX Direct Rules name space handle. */
	void *tx_tables[MLX5_MAX_TABLES]; /* TX Direct Rules tables. */
	/* Shared DV/DR objects. */
	LIST_HEAD(matchers, mlx5_flow_dv_matcher) matchers; /* Flow matchers. */
	LIST_HEAD(encap_decap, mlx5_flow_dv_encap_decap_resource) encaps_decaps;
	struct rte_hlist_table *tag_table;
	LIST_HEAD(modify, mlx5_flow_dv_modify_resource) modifys;
	/* Also referred as Tx meter prefix tables */
	void *tx_meter_suffix_table;
	/* TX suffix  table for handling flows with meters */
	struct mlx5_flow_stack *flow_stack; /* Pointer to flow id stack. */
	/* Shared interrupt handler section. */
	void *fdb_domain; /* Eswitch FDB direct Rules name space handle. */
	void *fdb_tables[MLX5_MAX_FDB_TABLES];
	void *fdb_meter_suffix_table;
	/* Eswitch fdb Direct Rules tables */
	pthread_mutex_t intr_mutex; /* Interrupt config mutex. */
	uint32_t intr_cnt; /* Interrupt handler reference counter. */
#ifdef HAVE_MLX5_DEVX_ASYNC_SUPPORT
	struct rte_intr_handle intr_handle_devx; /* DEVX interrupt handler. */
#endif
	void *drop_action; /* Pointer to drop action. */
	struct mlx5dv_devx_cmd_comp *devx_comp; /* DEVX async comp obj. */
	struct rte_intr_handle intr_handle; /* Interrupt handler for device. */
	struct mlx5_ibv_shared_port port[]; /* per device port data array. */
};

struct priv {
	struct rte_eth_dev_data *dev_data;  /* Pointer to device data. */
	struct mlx5_ibv_shared *sh; /* Shared IB device context. */
	uint32_t ibv_port; /* IB device port number. */
	struct ether_addr mac[MLX5_MAX_MAC_ADDRESSES]; /* MAC addresses. */
	BITFIELD_DECLARE(mac_own, uint64_t, MLX5_MAX_MAC_ADDRESSES);
	/* Bit-field of MAC addresses owned by the PMD. */
	uint16_t vlan_filter[MLX5_MAX_VLAN_IDS]; /* VLAN filters table. */
	unsigned int vlan_filter_n; /* Number of configured VLAN filters. */
	/* Device properties. */
	uint16_t mtu; /* Configured MTU. */
	unsigned int isolated:1; /* Whether isolated mode is enabled. */
	unsigned int representor:1; /* Device is a port representor. */
	unsigned int master:1; /* Device is a E-Switch master. */
	unsigned int dv_shared:1; /* DV/DR data is shared. */
	unsigned int mr_shared:1; /* MR table is shared. */
	unsigned int vf:1; /* Device is a virtual function device. */
	uint16_t domain_id; /* Switch domain identifier. */
	uint16_t vport_id; /* Associated VF vport index (if any). */
	int32_t representor_id; /* Port representor identifier. */
	/* RX/TX queues. */
	unsigned int rxqs_n; /* RX queues array size. */
	unsigned int txqs_n; /* TX queues array size. */
	struct mlx5_rxq_data *(*rxqs)[]; /* RX queues. */
	struct mlx5_txq_data *(*txqs)[]; /* TX queues. */
	struct rte_mempool *mprq_mp; /* Mempool for Multi-Packet RQ. */
	struct rte_eth_rss_conf rss_conf; /* RSS configuration. */
	struct rte_intr_handle intr_handle; /* Interrupt handler. */
	unsigned int (*reta_idx)[]; /* RETA index table. */
	unsigned int reta_idx_n; /* RETA index size. */
	struct mlx5_drop drop_queue; /* Flow drop queues. */
	struct mlx5_flows flows; /* RTE Flow rules. */
	struct mlx5_flows ctrl_flows; /* Control flow rules. */
#if defined(HAVE_IBV_DEVICE_COUNTERS_SET_V42) || \
	defined(HAVE_IBV_DEVICE_COUNTERS_SET_V45) || \
	defined(HAVE_IBV_FLOW_DEVX_COUNTERS) || \
	defined(HAVE_IBV_FLOW_DV_SUPPORT)
	LIST_HEAD(counters, mlx5_flow_counter) flow_counters;
	/* Flow counters. */
#endif
	struct mlx5_flow_meter_profiles flow_meter_profiles;
	struct mlx5_flow_meters flow_meters;
	/* Flow meters and profiles, see rte_mtr_driver.h. */
	LIST_HEAD(rxq, mlx5_rxq_ctrl) rxqsctrl; /* DPDK Rx queues. */
	LIST_HEAD(rxqibv, mlx5_rxq_ibv) rxqsibv; /* Verbs Rx queues. */
	LIST_HEAD(hrxq, mlx5_hrxq) hrxqs; /* Verbs Hash Rx queues. */
	LIST_HEAD(txq, mlx5_txq_ctrl) txqsctrl; /* DPDK Tx queues. */
	LIST_HEAD(txqibv, mlx5_txq_ibv) txqsibv; /* Verbs Tx queues. */
	/* Verbs Indirection tables. */
	LIST_HEAD(ind_tables, mlx5_ind_table_ibv) ind_tbls;
	SLIST_HEAD(counter_mr, mlx5_flow_counter_query_mr) counter_mr;
	SLIST_HEAD(bulk_counters, mlx5_flow_bulk_counters) bulk_dcs;
	struct mlx5_dcs dcs; /* list of dcs objects. */
	uint32_t link_speed_capa; /* Link speed capabilities. */
	struct mlx5_xstats_ctrl xstats_ctrl; /* Extended stats control. */
	int primary_socket; /* Unix socket for primary process. */
	void *uar_base; /* Reserved address space for UAR mapping */
	struct rte_intr_handle intr_handle_socket; /* Interrupt handler. */
	struct mlx5_dev_config config; /* Device configuration. */
	struct rte_intr_handle intr_handle_dev; /* Rx Interrupt handler. */
	struct mlx5_verbs_alloc_ctx verbs_alloc_ctx;
	/* Context for Verbs allocator. */
	int nl_socket_rdma; /* Netlink socket (NETLINK_RDMA). */
	int nl_socket_route; /* Netlink socket (NETLINK_ROUTE). */
	uint32_t nl_sn; /* Netlink message sequence number. */
	struct mlx5_devx_mkey mkey;
};

#define PORT_ID(priv) ((priv)->dev_data->port_id)
#define ETH_DEV(priv) (&rte_eth_devices[PORT_ID(priv)])

/* mlx5.c */

int mlx5_getenv_int(const char *);

/* mlx5_ethdev.c */

int mlx5_get_ifname(const struct rte_eth_dev *dev, char (*ifname)[IF_NAMESIZE]);
int mlx5_get_ifname_base(const struct rte_eth_dev *base,
			 const struct rte_eth_dev *dev,
			 char (*ifname)[IF_NAMESIZE]);
int mlx5_get_master_ifname(const char *ibdev_path, char (*ifname)[IF_NAMESIZE]);
unsigned int mlx5_ifindex(const struct rte_eth_dev *dev);
int mlx5_ifreq(const struct rte_eth_dev *dev, int req, struct ifreq *ifr);
int mlx5_ifreq_base(const struct rte_eth_dev *base,
		    const struct rte_eth_dev *dev,
		    int req, struct ifreq *ifr);
int mlx5_get_mtu(struct rte_eth_dev *dev, uint16_t *mtu);
int mlx5_set_flags(struct rte_eth_dev *dev, unsigned int keep,
		   unsigned int flags);
int mlx5_dev_configure(struct rte_eth_dev *dev);
void mlx5_dev_infos_get(struct rte_eth_dev *dev, struct rte_eth_dev_info *info);
const uint32_t *mlx5_dev_supported_ptypes_get(struct rte_eth_dev *dev);
int mlx5_link_update(struct rte_eth_dev *dev, int wait_to_complete);
int mlx5_force_link_status_change(struct rte_eth_dev *dev, int status);
int mlx5_dev_set_mtu(struct rte_eth_dev *dev, uint16_t mtu);
int mlx5_dev_get_flow_ctrl(struct rte_eth_dev *dev,
			   struct rte_eth_fc_conf *fc_conf);
int mlx5_dev_set_flow_ctrl(struct rte_eth_dev *dev,
			   struct rte_eth_fc_conf *fc_conf);
int mlx5_ibv_device_to_pci_addr(const struct ibv_device *device,
				struct rte_pci_addr *pci_addr);
void mlx5_dev_link_status_handler(void *arg);
void mlx5_dev_interrupt_handler(void *arg);
#ifdef HAVE_MLX5_DEVX_ASYNC_SUPPORT
void mlx5_dev_interrupt_handler_devx(void *arg);
#endif
void mlx5_dev_interrupt_handler_uninstall(struct rte_eth_dev *dev);
void mlx5_dev_interrupt_handler_install(struct rte_eth_dev *dev);
int mlx5_set_link_down(struct rte_eth_dev *dev);
int mlx5_set_link_up(struct rte_eth_dev *dev);
int mlx5_is_removed(struct rte_eth_dev *dev);
eth_tx_burst_t mlx5_select_tx_function(struct rte_eth_dev *dev);
eth_rx_burst_t mlx5_select_rx_function(struct rte_eth_dev *dev);
unsigned int mlx5_dev_to_port_id(const struct rte_device *dev,
				 uint16_t *port_list,
				 unsigned int port_list_n);
unsigned int mlx5_port_to_ifindex(uint16_t port);
int mlx5_port_to_eswitch_info(uint16_t port,
			      uint16_t *es_domain_id, uint16_t *es_port_id);
int mlx5_sysfs_switch_info(unsigned int ifindex,
			   struct mlx5_switch_info *info);
void mlx5_sysfs_check_switch_info(bool device_dir,
				  struct mlx5_switch_info *switch_info);
void mlx5_nl_check_switch_info(bool nun_vf_set,
			       struct mlx5_switch_info *switch_info);
void mlx5_translate_port_name(const char *port_name_in,
			      struct mlx5_switch_info *port_info_out);

/* mlx5_mac.c */

int mlx5_get_mac(struct rte_eth_dev *dev, uint8_t (*mac)[ETHER_ADDR_LEN]);
void mlx5_mac_addr_remove(struct rte_eth_dev *dev, uint32_t index);
int mlx5_mac_addr_add(struct rte_eth_dev *dev, struct ether_addr *mac,
		      uint32_t index, uint32_t vmdq);
void mlx5_mac_addr_set(struct rte_eth_dev *dev, struct ether_addr *mac_addr);

/* mlx5_rss.c */

int mlx5_rss_hash_update(struct rte_eth_dev *dev,
			 struct rte_eth_rss_conf *rss_conf);
int mlx5_rss_hash_conf_get(struct rte_eth_dev *dev,
			   struct rte_eth_rss_conf *rss_conf);
int mlx5_rss_reta_index_resize(struct rte_eth_dev *dev, unsigned int reta_size);
int mlx5_dev_rss_reta_query(struct rte_eth_dev *dev,
			    struct rte_eth_rss_reta_entry64 *reta_conf,
			    uint16_t reta_size);
int mlx5_dev_rss_reta_update(struct rte_eth_dev *dev,
			     struct rte_eth_rss_reta_entry64 *reta_conf,
			     uint16_t reta_size);

/* mlx5_rxmode.c */

void mlx5_promiscuous_enable(struct rte_eth_dev *dev);
void mlx5_promiscuous_disable(struct rte_eth_dev *dev);
void mlx5_allmulticast_enable(struct rte_eth_dev *dev);
void mlx5_allmulticast_disable(struct rte_eth_dev *dev);

/* mlx5_stats.c */

void mlx5_xstats_init(struct rte_eth_dev *dev);
int mlx5_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats);
void mlx5_stats_reset(struct rte_eth_dev *dev);
int mlx5_xstats_get(struct rte_eth_dev *dev, struct rte_eth_xstat *stats,
		    unsigned int n);
void mlx5_xstats_reset(struct rte_eth_dev *dev);
int mlx5_xstats_get_names(struct rte_eth_dev *dev __rte_unused,
			  struct rte_eth_xstat_name *xstats_names,
			  unsigned int n);

/* mlx5_vlan.c */

int mlx5_vlan_filter_set(struct rte_eth_dev *dev, uint16_t vlan_id, int on);
void mlx5_vlan_strip_queue_set(struct rte_eth_dev *dev, uint16_t queue, int on);
int mlx5_vlan_offload_set(struct rte_eth_dev *dev, int mask);

/* mlx5_trigger.c */

int mlx5_dev_start(struct rte_eth_dev *dev);
void mlx5_dev_stop(struct rte_eth_dev *dev);
int mlx5_traffic_enable(struct rte_eth_dev *dev);
void mlx5_traffic_disable(struct rte_eth_dev *dev);
int mlx5_traffic_restart(struct rte_eth_dev *dev);

/* mlx5_flow.c */
int mlx5_flow_discover_priorities(struct rte_eth_dev *dev);
void mlx5_flow_print(struct rte_flow *flow);
int mlx5_flow_validate(struct rte_eth_dev *dev,
		       const struct rte_flow_attr *attr,
		       const struct rte_flow_item items[],
		       const struct rte_flow_action actions[],
		       struct rte_flow_error *error);
struct rte_flow *mlx5_flow_create(struct rte_eth_dev *dev,
				  const struct rte_flow_attr *attr,
				  const struct rte_flow_item items[],
				  const struct rte_flow_action actions[],
				  struct rte_flow_error *error);
int mlx5_flow_destroy(struct rte_eth_dev *dev, struct rte_flow *flow,
		      struct rte_flow_error *error);
void mlx5_flow_list_flush(struct rte_eth_dev *dev, struct mlx5_flows *list);
int mlx5_flow_flush(struct rte_eth_dev *dev, struct rte_flow_error *error);
int mlx5_flow_query(struct rte_eth_dev *dev, struct rte_flow *flow,
		    const struct rte_flow_action *action, void *data,
		    struct rte_flow_error *error);
int mlx5_flow_query_legacy(struct rte_eth_dev *dev, struct rte_flow *flow,
			   enum rte_flow_action_type type, void *data,
			   struct rte_flow_error *error);
int mlx5_flow_isolate(struct rte_eth_dev *dev, int enable,
		      struct rte_flow_error *error);
int mlx5_dev_filter_ctrl(struct rte_eth_dev *dev,
			 enum rte_filter_type filter_type,
			 enum rte_filter_op filter_op,
			 void *arg);
int mlx5_flow_start(struct rte_eth_dev *dev, struct mlx5_flows *list);
void mlx5_flow_stop(struct rte_eth_dev *dev, struct mlx5_flows *list);
int mlx5_flow_verify(struct rte_eth_dev *dev);
int mlx5_ctrl_flow_vlan(struct rte_eth_dev *dev,
			struct rte_flow_item_eth *eth_spec,
			struct rte_flow_item_eth *eth_mask,
			struct rte_flow_item_vlan *vlan_spec,
			struct rte_flow_item_vlan *vlan_mask);
int mlx5_ctrl_flow(struct rte_eth_dev *dev,
		   struct rte_flow_item_eth *eth_spec,
		   struct rte_flow_item_eth *eth_mask);
struct mlx5_meter_tbls_dv *mlx5_flow_create_mtr_tbls
					(struct rte_eth_dev *dev,
					 const struct mlx5_flow_meter *fm);
int mlx5_flow_destroy_mtr_tbls(struct rte_eth_dev *dev,
			      struct mlx5_meter_tbls_dv *tbl);
int mlx5_flow_create_policer_rules(struct rte_eth_dev *dev,
				   struct mlx5_flow_meter *fm,
				   const struct rte_flow_attr *attr);
int mlx5_flow_destroy_policer_rules(struct rte_eth_dev *dev,
				    struct mlx5_flow_meter *fm,
				    const struct rte_flow_attr *attr);

/* Common functions. */
int mlx5_flow_isolate(struct rte_eth_dev *dev, int enable,
		      struct rte_flow_error *error);
int mlx5_dev_filter_ctrl(struct rte_eth_dev *dev,
			 enum rte_filter_type filter_type,
			 enum rte_filter_op filter_op,
			 void *arg);
int mlx5_ctrl_flow(struct rte_eth_dev *dev,
		   struct rte_flow_item_eth *eth_spec,
		   struct rte_flow_item_eth *eth_mask);

/* mlx5_flow_dv.c */
#ifdef HAVE_IBV_FLOW_DV_SUPPORT
int mlx5_dv_flow_validate(struct rte_eth_dev *dev,
			  const struct rte_flow_attr *attr,
			  const struct rte_flow_item items[],
			  const struct rte_flow_action actions[],
			  struct rte_flow_error *error);
struct rte_flow *mlx5_dv_flow_create(struct rte_eth_dev *dev,
				     const struct rte_flow_attr *attr,
				     const struct rte_flow_item items[],
				     const struct rte_flow_action actions[],
				     struct rte_flow_error *error);
int mlx5_dv_flow_destroy(struct rte_eth_dev *dev, struct rte_flow *flow,
			 struct rte_flow_error *error);
void mlx5_dv_flow_list_flush(struct rte_eth_dev *dev, struct mlx5_flows *list);
int mlx5_dv_flow_flush(struct rte_eth_dev *dev, struct rte_flow_error *error);
int mlx5_dv_flow_query(struct rte_eth_dev *dev, struct rte_flow *flow,
		       enum rte_flow_action_type action, void *data,
		       struct rte_flow_error *error);
int mlx5_dv_flow_start(struct rte_eth_dev *dev, struct mlx5_flows *list);
void mlx5_dv_flow_stop(struct rte_eth_dev *dev, struct mlx5_flows *list);
int mlx5_dv_flow_verify(struct rte_eth_dev *dev);
int mlx5_dv_ctrl_flow_vlan(struct rte_eth_dev *dev,
			struct rte_flow_item_eth *eth_spec,
			struct rte_flow_item_eth *eth_mask,
			struct rte_flow_item_vlan *vlan_spec,
			struct rte_flow_item_vlan *vlan_mask);
int mlx5_dv_fdir_ctrl_func(struct rte_eth_dev *dev,
			   enum rte_filter_op filter_op,
			   void *arg);
#endif

/* mlx5_socket.c */

int mlx5_socket_init(struct rte_eth_dev *dev);
void mlx5_socket_uninit(struct rte_eth_dev *dev);
void mlx5_socket_handle(struct rte_eth_dev *dev);
int mlx5_socket_connect(struct rte_eth_dev *dev);

/* mlx5_nl.c */

int mlx5_nl_init(int protocol);
unsigned int mlx5_nl_portnum(int nl, const char *name);
unsigned int mlx5_nl_ifindex(int nl, const char *name, uint32_t pindex);
int mlx5_nl_switch_info(int nl, unsigned int ifindex,
			struct mlx5_switch_info *info);
int mlx5_nl_mac_addr_add(struct rte_eth_dev *dev, struct ether_addr *mac,
			 uint32_t index);
int mlx5_nl_mac_addr_remove(struct rte_eth_dev *dev, struct ether_addr *mac,
			    uint32_t index);
void mlx5_nl_mac_addr_sync(struct rte_eth_dev *dev);
void mlx5_nl_mac_addr_flush(struct rte_eth_dev *dev);
int mlx5_nl_promisc(struct rte_eth_dev *dev, int enable);
int mlx5_nl_allmulti(struct rte_eth_dev *dev, int enable);

/* mlx5_mr.c */

int mlx5_mr_register_memseg(struct rte_eth_dev *dev);
void mlx5_mr_deregister_memseg(struct rte_eth_dev *dev);

#endif /* RTE_PMD_MLX5_H_ */
