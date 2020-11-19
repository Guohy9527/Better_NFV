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

#define _GNU_SOURCE

#include <stddef.h>
#include <assert.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <dirent.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <fcntl.h>
#include <stdalign.h>
#include <sys/un.h>
#include <time.h>

#include <rte_atomic.h>
#include <rte_ethdev.h>
#include <rte_bus_pci.h>
#include <rte_mbuf.h>
#include <rte_common.h>
#include <rte_interrupts.h>
#include <rte_malloc.h>
#include <rte_string_fns.h>
#include <rte_rwlock.h>

#include "mlx5.h"
#include "mlx5_rxtx.h"
#include "mlx5_utils.h"
#include "mlx5_flow.h"
#include "mlx5_glue.h"

/* Add defines in case the running kernel is not the same as user headers. */
#ifndef ETHTOOL_GLINKSETTINGS
struct ethtool_link_settings {
	uint32_t cmd;
	uint32_t speed;
	uint8_t duplex;
	uint8_t port;
	uint8_t phy_address;
	uint8_t autoneg;
	uint8_t mdio_support;
	uint8_t eth_to_mdix;
	uint8_t eth_tp_mdix_ctrl;
	int8_t link_mode_masks_nwords;
	uint32_t reserved[8];
	uint32_t link_mode_masks[];
};

#define ETHTOOL_GLINKSETTINGS 0x0000004c
#define ETHTOOL_LINK_MODE_1000baseT_Full_BIT 5
#define ETHTOOL_LINK_MODE_Autoneg_BIT 6
#define ETHTOOL_LINK_MODE_1000baseKX_Full_BIT 17
#define ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT 18
#define ETHTOOL_LINK_MODE_10000baseKR_Full_BIT 19
#define ETHTOOL_LINK_MODE_10000baseR_FEC_BIT 20
#define ETHTOOL_LINK_MODE_20000baseMLD2_Full_BIT 21
#define ETHTOOL_LINK_MODE_20000baseKR2_Full_BIT 22
#define ETHTOOL_LINK_MODE_40000baseKR4_Full_BIT 23
#define ETHTOOL_LINK_MODE_40000baseCR4_Full_BIT 24
#define ETHTOOL_LINK_MODE_40000baseSR4_Full_BIT 25
#define ETHTOOL_LINK_MODE_40000baseLR4_Full_BIT 26
#define ETHTOOL_LINK_MODE_56000baseKR4_Full_BIT 27
#define ETHTOOL_LINK_MODE_56000baseCR4_Full_BIT 28
#define ETHTOOL_LINK_MODE_56000baseSR4_Full_BIT 29
#define ETHTOOL_LINK_MODE_56000baseLR4_Full_BIT 30
#endif
#ifndef HAVE_ETHTOOL_LINK_MODE_25G
#define ETHTOOL_LINK_MODE_25000baseCR_Full_BIT 31
#define ETHTOOL_LINK_MODE_25000baseKR_Full_BIT 32
#define ETHTOOL_LINK_MODE_25000baseSR_Full_BIT 33
#endif
#ifndef HAVE_ETHTOOL_LINK_MODE_50G
#define ETHTOOL_LINK_MODE_50000baseCR2_Full_BIT 34
#define ETHTOOL_LINK_MODE_50000baseKR2_Full_BIT 35
#endif
#ifndef HAVE_ETHTOOL_LINK_MODE_100G
#define ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT 36
#define ETHTOOL_LINK_MODE_100000baseSR4_Full_BIT 37
#define ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT 38
#define ETHTOOL_LINK_MODE_100000baseLR4_ER4_Full_BIT 39
#endif

/**
 * Get master interface name from private structure.
 *
 * @param[in] dev
 *   Pointer to Ethernet device.
 * @param[out] ifname
 *   Interface name output buffer.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_get_master_ifname(const char *ibdev_path, char (*ifname)[IF_NAMESIZE])
{
	DIR *dir;
	struct dirent *dent;
	unsigned int dev_type = 0;
	unsigned int dev_port_prev = ~0u;
	char match[IF_NAMESIZE] = "";

	assert(ibdev_path);
	{
		MKSTR(path, "%s/device/net", ibdev_path);

		dir = opendir(path);
		if (dir == NULL) {
			rte_errno = errno;
			return -rte_errno;
		}
	}
	while ((dent = readdir(dir)) != NULL) {
		char *name = dent->d_name;
		FILE *file;
		unsigned int dev_port;
		int r;

		if ((name[0] == '.') &&
		    ((name[1] == '\0') ||
		     ((name[1] == '.') && (name[2] == '\0'))))
			continue;

		MKSTR(path, "%s/device/net/%s/%s",
		      ibdev_path, name,
		      (dev_type ? "dev_id" : "dev_port"));

		file = fopen(path, "rb");
		if (file == NULL) {
			if (errno != ENOENT)
				continue;
			/*
			 * Switch to dev_id when dev_port does not exist as
			 * is the case with Linux kernel versions < 3.15.
			 */
try_dev_id:
			match[0] = '\0';
			if (dev_type)
				break;
			dev_type = 1;
			dev_port_prev = ~0u;
			rewinddir(dir);
			continue;
		}
		r = fscanf(file, (dev_type ? "%x" : "%u"), &dev_port);
		fclose(file);
		if (r != 1)
			continue;
		/*
		 * Switch to dev_id when dev_port returns the same value for
		 * all ports. May happen when using a MOFED release older than
		 * 3.0 with a Linux kernel >= 3.15.
		 */
		if (dev_port == dev_port_prev)
			goto try_dev_id;
		dev_port_prev = dev_port;
		if (dev_port == 0)
			strlcpy(match, name, sizeof(match));
	}
	closedir(dir);
	if (match[0] == '\0') {
		rte_errno = ENOENT;
		return -rte_errno;
	}
	strncpy(*ifname, match, sizeof(*ifname));
	return 0;
}

/**
 * Get interface name from private structure.
 *
 * This is a port representor-aware version of mlx5_get_master_ifname().
 *
 * @param[in] dev
 *   Pointer to Ethernet device.
 * @param[out] ifname
 *   Interface name output buffer.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_get_ifname(const struct rte_eth_dev *dev, char (*ifname)[IF_NAMESIZE])
{
	struct priv *priv = dev->data->dev_private;
	unsigned int ifindex;

	assert(priv);
	assert(priv->sh);
	ifindex = priv->nl_socket_rdma >= 0 ?
		mlx5_nl_ifindex(priv->nl_socket_rdma,
				priv->sh->ibdev_name,
				priv->ibv_port) : 0;
	if (!ifindex) {
		if (!priv->representor)
			return mlx5_get_master_ifname(priv->sh->ibdev_path,
						      ifname);
		rte_errno = ENXIO;
		return -rte_errno;
	}
	if (if_indextoname(ifindex, &(*ifname)[0]))
		return 0;
	rte_errno = errno;
	return -rte_errno;
}

/**
 * Get interface name for the specified device, uses the extra base
 * device resources to perform Netlink requests.
 *
 * This is a port representor-aware version of mlx5_get_master_ifname().
 *
 * @param[in] dev
 *   Pointer to Ethernet device.
 * @param[out] ifname
 *   Interface name output buffer.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_get_ifname_base(const struct rte_eth_dev *base,
		     const struct rte_eth_dev *dev,
		     char (*ifname)[IF_NAMESIZE])
{
	struct priv *priv = dev->data->dev_private;
	struct priv *priv_base = base->data->dev_private;
	unsigned int ifindex;

	assert(priv);
	assert(priv->sh);
	assert(priv_base);
	ifindex = priv_base->nl_socket_rdma >= 0 ?
		  mlx5_nl_ifindex(priv_base->nl_socket_rdma,
				  priv->sh->ibdev_name,
				  priv->ibv_port) : 0;
	if (!ifindex) {
		if (!priv->representor)
			return mlx5_get_master_ifname(priv->sh->ibdev_path,
						      ifname);
		rte_errno = ENXIO;
		return -rte_errno;
	}
	if (if_indextoname(ifindex, &(*ifname)[0]))
		return 0;
	rte_errno = errno;
	return -rte_errno;
}
/**
 * Get the interface index from device name.
 *
 * @param[in] dev
 *   Pointer to Ethernet device.
 *
 * @return
 *   Nonzero interface index on success, zero otherwise and rte_errno is set.
 */
unsigned int
mlx5_ifindex(const struct rte_eth_dev *dev)
{
	char ifname[IF_NAMESIZE];
	unsigned int ifindex;

	if (mlx5_get_ifname(dev, &ifname))
		return 0;
	ifindex = if_nametoindex(ifname);
	if (!ifindex)
		rte_errno = errno;
	return ifindex;
}

/**
 * Perform ifreq ioctl() on associated Ethernet device.
 *
 * @param[in] dev
 *   Pointer to Ethernet device.
 * @param req
 *   Request number to pass to ioctl().
 * @param[out] ifr
 *   Interface request structure output buffer.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_ifreq(const struct rte_eth_dev *dev, int req, struct ifreq *ifr)
{
	int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	int ret = 0;

	if (sock == -1) {
		rte_errno = errno;
		return -rte_errno;
	}
	ret = mlx5_get_ifname(dev, &ifr->ifr_name);
	if (ret)
		goto error;
	ret = ioctl(sock, req, ifr);
	if (ret == -1) {
		rte_errno = errno;
		goto error;
	}
	close(sock);
	return 0;
error:
	close(sock);
	return -rte_errno;
}

/**
 * Perform ifreq ioctl() on specified Ethernet device,
 * ifindex, name and other attributes are requested
 * on the base device to avoid specified device Netlink
 * socket sharing (this is not thread-safe).
 *
 * @param[in] base
 *   Pointer to Ethernet device to get dev attributes.
 * @param[in] dev
 *   Pointer to Ethernet device to perform ioctl.
 * @param req
 *   Request number to pass to ioctl().
 * @param[out] ifr
 *   Interface request structure output buffer.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_ifreq_base(const struct rte_eth_dev *base,
		const struct rte_eth_dev *dev,
		int req, struct ifreq *ifr)
{
	int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	int ret = 0;

	if (sock == -1) {
		rte_errno = errno;
		return -rte_errno;
	}
	ret = mlx5_get_ifname_base(base, dev, &ifr->ifr_name);
	if (ret)
		goto error;
	ret = ioctl(sock, req, ifr);
	if (ret == -1) {
		rte_errno = errno;
		goto error;
	}
	close(sock);
	return 0;
error:
	close(sock);
	return -rte_errno;
}

/**
 * Get device MTU.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param[out] mtu
 *   MTU value output buffer.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_get_mtu(struct rte_eth_dev *dev, uint16_t *mtu)
{
	struct ifreq request;
	int ret = mlx5_ifreq(dev, SIOCGIFMTU, &request);

	if (ret)
		return ret;
	*mtu = request.ifr_mtu;
	return 0;
}

/**
 * Set device MTU.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param mtu
 *   MTU value to set.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
mlx5_set_mtu(struct rte_eth_dev *dev, uint16_t mtu)
{
	struct ifreq request = { .ifr_mtu = mtu, };

	return mlx5_ifreq(dev, SIOCSIFMTU, &request);
}

/**
 * Set device flags.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param keep
 *   Bitmask for flags that must remain untouched.
 * @param flags
 *   Bitmask for flags to modify.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_set_flags(struct rte_eth_dev *dev, unsigned int keep, unsigned int flags)
{
	struct ifreq request;
	int ret = mlx5_ifreq(dev, SIOCGIFFLAGS, &request);

	if (ret)
		return ret;
	request.ifr_flags &= keep;
	request.ifr_flags |= flags & ~keep;
	return mlx5_ifreq(dev, SIOCSIFFLAGS, &request);
}

/**
 * DPDK callback for Ethernet device configuration.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_dev_configure(struct rte_eth_dev *dev)
{
	struct priv *priv = dev->data->dev_private;
	unsigned int rxqs_n = dev->data->nb_rx_queues;
	unsigned int txqs_n = dev->data->nb_tx_queues;
	unsigned int i;
	unsigned int j;
	unsigned int reta_idx_n;
	const uint8_t use_app_rss_key =
		!!dev->data->dev_conf.rx_adv_conf.rss_conf.rss_key;
	int ret = 0;

	if (dev->data->dev_conf.rx_adv_conf.rss_conf.rss_hf &
	    MLX5_RSS_HF_MASK) {
		DRV_LOG(ERR,
			"Some RSS hash function not supported requested"
			" 0x%" PRIx64 " supported 0x%" PRIx64,
			dev->data->dev_conf.rx_adv_conf.rss_conf.rss_hf,
			(uint64_t)(~MLX5_RSS_HF_MASK));
		return ENOTSUP;
	}
	if (use_app_rss_key &&
	    (dev->data->dev_conf.rx_adv_conf.rss_conf.rss_key_len !=
	     rss_hash_default_key_len)) {
		DRV_LOG(ERR, "port %u RSS key len must be %zu Bytes long",
			dev->data->port_id, rss_hash_default_key_len);
		rte_errno = EINVAL;
		return -rte_errno;
	}
	priv->rss_conf.rss_key =
		rte_realloc(priv->rss_conf.rss_key,
			    rss_hash_default_key_len, 0);
	if (!priv->rss_conf.rss_key) {
		DRV_LOG(ERR, "port %u cannot allocate RSS hash key memory (%u)",
			dev->data->port_id, rxqs_n);
		rte_errno = ENOMEM;
		return -rte_errno;
	}
	memcpy(priv->rss_conf.rss_key,
	       use_app_rss_key ?
	       dev->data->dev_conf.rx_adv_conf.rss_conf.rss_key :
	       rss_hash_default_key,
	       rss_hash_default_key_len);
	priv->rss_conf.rss_key_len = rss_hash_default_key_len;
	priv->rss_conf.rss_hf = dev->data->dev_conf.rx_adv_conf.rss_conf.rss_hf;
	priv->rxqs = (void *)dev->data->rx_queues;
	priv->txqs = (void *)dev->data->tx_queues;
	if (txqs_n != priv->txqs_n) {
		DRV_LOG(INFO, "port %u Tx queues number update: %u -> %u",
			dev->data->port_id, priv->txqs_n, txqs_n);
		priv->txqs_n = txqs_n;
	}
	if (rxqs_n > priv->config.ind_table_max_size) {
		DRV_LOG(ERR, "port %u cannot handle this many Rx queues (%u)",
			dev->data->port_id, rxqs_n);
		rte_errno = EINVAL;
		return -rte_errno;
	}
	if (rxqs_n == priv->rxqs_n)
		return 0;
	DRV_LOG(INFO, "port %u Rx queues number update: %u -> %u",
		dev->data->port_id, priv->rxqs_n, rxqs_n);
	priv->rxqs_n = rxqs_n;
	/* If the requested number of RX queues is not a power of two, use the
	 * maximum indirection table size for better balancing.
	 * The result is always rounded to the next power of two. */
	reta_idx_n = (1 << log2above((rxqs_n & (rxqs_n - 1)) ?
				     priv->config.ind_table_max_size :
				     rxqs_n));
	ret = mlx5_rss_reta_index_resize(dev, reta_idx_n);
	if (ret)
		return ret;
	ret = mlx5_mr_register_memseg(dev);
	if (ret)
		return ret;
	/* When the number of RX queues is not a power of two, the remaining
	 * table entries are padded with reused WQs and hashes are not spread
	 * uniformly. */
	for (i = 0, j = 0; (i != reta_idx_n); ++i) {
		(*priv->reta_idx)[i] = j;
		if (++j == rxqs_n)
			j = 0;
	}
	return 0;
}

/**
 * DPDK callback to get information about the device.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param[out] info
 *   Info structure output buffer.
 */
void
mlx5_dev_infos_get(struct rte_eth_dev *dev, struct rte_eth_dev_info *info)
{
	struct priv *priv = dev->data->dev_private;
	struct mlx5_dev_config *config = &priv->config;
	unsigned int max;
	char ifname[IF_NAMESIZE];

	info->pci_dev = RTE_ETH_DEV_TO_PCI(dev);
	/* FIXME: we should ask the device for these values. */
	info->min_rx_bufsize = 32;
	info->max_rx_pktlen = 65536;
	/*
	 * Since we need one CQ per QP, the limit is the minimum number
	 * between the two values.
	 */
	max = RTE_MIN(priv->sh->device_attr.orig_attr.max_cq,
		      priv->sh->device_attr.orig_attr.max_qp);
	/* If max >= 65535 then max = 0, max_rx_queues is uint16_t. */
	if (max >= 65535)
		max = 65535;
	info->max_rx_queues = max;
	info->max_tx_queues = max;
	info->max_mac_addrs = RTE_DIM(priv->mac);
	info->rx_queue_offload_capa = mlx5_get_rx_queue_offloads(dev);
	info->rx_offload_capa = (mlx5_get_rx_port_offloads() |
				 info->rx_queue_offload_capa);
	info->tx_offload_capa = mlx5_get_tx_port_offloads(dev);
	if (mlx5_get_ifname(dev, &ifname) == 0)
		info->if_index = if_nametoindex(ifname);
	info->reta_size = priv->reta_idx_n ?
		priv->reta_idx_n : config->ind_table_max_size;
	info->hash_key_size = rss_hash_default_key_len;
	info->speed_capa = priv->link_speed_capa;
	info->flow_type_rss_offloads = ~MLX5_RSS_HF_MASK;
	info->switch_info.name = dev->data->name;
	info->switch_info.domain_id = priv->domain_id;
	info->switch_info.port_id = priv->representor_id;
	if (priv->representor) {
		unsigned int i = mlx5_dev_to_port_id(dev->device, NULL, 0);
		uint16_t port_id[i];

		i = RTE_MIN(mlx5_dev_to_port_id(dev->device, port_id, i), i);
		while (i--) {
			struct priv *opriv =
				rte_eth_devices[port_id[i]].data->dev_private;

			if (!opriv ||
			    opriv->representor ||
			    opriv->domain_id != priv->domain_id)
				continue;
			/*
			 * Override switch name with that of the master
			 * device.
			 */
			info->switch_info.name = opriv->dev_data->name;
			break;
		}
	}
}

/**
 * Get supported packet types.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 *
 * @return
 *   A pointer to the supported Packet types array.
 */
const uint32_t *
mlx5_dev_supported_ptypes_get(struct rte_eth_dev *dev)
{
	static const uint32_t ptypes[] = {
		/* refers to rxq_cq_to_pkt_type() */
		RTE_PTYPE_L2_ETHER,
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN,
		RTE_PTYPE_L3_IPV6_EXT_UNKNOWN,
		RTE_PTYPE_L4_NONFRAG,
		RTE_PTYPE_L4_FRAG,
		RTE_PTYPE_L4_TCP,
		RTE_PTYPE_L4_UDP,
		RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN,
		RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN,
		RTE_PTYPE_INNER_L4_NONFRAG,
		RTE_PTYPE_INNER_L4_FRAG,
		RTE_PTYPE_INNER_L4_TCP,
		RTE_PTYPE_INNER_L4_UDP,
		RTE_PTYPE_UNKNOWN
	};

	if (dev->rx_pkt_burst == mlx5_rx_burst ||
	    dev->rx_pkt_burst == mlx5_rx_burst_mprq ||
	    dev->rx_pkt_burst == mlx5_rx_burst_vec)
		return ptypes;
	return NULL;
}

/**
 * Retrieve the master device for representor in the same switch domain.
 *
 * @param dev
 *   Pointer to representor Ethernet device structure.
 *
 * @return
 *   Master device structure  on success, NULL otherwise.
 */

static struct rte_eth_dev *
mlx5_find_master_dev(struct rte_eth_dev *dev)
{
	struct priv *priv;
	uint16_t port_id;
	uint16_t domain_id;

	priv = dev->data->dev_private;
	domain_id = priv->domain_id;
	assert(priv->representor);
	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
		if (rte_eth_devices[port_id].device != dev->device)
			continue;
		priv = rte_eth_devices[port_id].data->dev_private;
		if (priv &&
		    priv->master &&
		    priv->domain_id == domain_id)
			return &rte_eth_devices[port_id];
	}
	return NULL;
}

/**
 * DPDK callback to retrieve physical link information.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param[out] link
 *   Storage for current link status.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
mlx5_link_update_unlocked_gset(struct rte_eth_dev *dev,
			       struct rte_eth_link *link)
{
	struct priv *priv = dev->data->dev_private;
	struct ethtool_cmd edata = {
		.cmd = ETHTOOL_GSET /* Deprecated since Linux v4.5. */
	};
	struct ifreq ifr;
	struct rte_eth_link dev_link;
	int link_speed = 0;
	int ret;

	ret = mlx5_ifreq(dev, SIOCGIFFLAGS, &ifr);
	if (ret) {
		DRV_LOG(WARNING, "port %u ioctl(SIOCGIFFLAGS) failed: %s",
			dev->data->port_id, strerror(rte_errno));
		return ret;
	}
	memset(&dev_link, 0, sizeof(dev_link));
	dev_link.link_status = ((ifr.ifr_flags & IFF_UP) &&
				(ifr.ifr_flags & IFF_RUNNING));
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_data = (void *)&edata;
	ret = mlx5_ifreq(dev, SIOCETHTOOL, &ifr);
	if (ret) {
		if (ret == -ENOTSUP && priv->representor) {
			struct rte_eth_dev *master;
		
			/*
			 * For representors we can try to inherit link
			 * settings from the master device. Actually
			 * link settings do not make a lot of sense
			 * for representors due to missing physical
			 * link. The old kernel drivers supported
			 * emulated settings query for representors,
			 * the new ones do not, so we have to add
			 * this code for compatibility issues.
			 */
			master = mlx5_find_master_dev(dev);
			if (master) {
				ifr = (struct ifreq) {
					.ifr_data = (void *)&edata,
				};
				/*
				 * Use special version of mlx5_ifreq()
				 * to get master device name with local
				 * device Netlink socket. Using master
				 * device Netlink socket is not thread
				 * safe.
				 */
				ret = mlx5_ifreq_base(dev, master,
						      SIOCETHTOOL, &ifr);
			}
		}
		if (ret) {		
			DRV_LOG(WARNING,
				"port %u ioctl(SIOCETHTOOL,"
				" ETHTOOL_GSET) failed: %s",
				dev->data->port_id, strerror(rte_errno));
			return ret;
		}
	}
	link_speed = ethtool_cmd_speed(&edata);
	if (link_speed == -1)
		dev_link.link_speed = 0;
	else
		dev_link.link_speed = link_speed;
	priv->link_speed_capa = 0;
	if (edata.supported & SUPPORTED_Autoneg)
		priv->link_speed_capa |= ETH_LINK_SPEED_AUTONEG;
	if (edata.supported & (SUPPORTED_1000baseT_Full |
			       SUPPORTED_1000baseKX_Full))
		priv->link_speed_capa |= ETH_LINK_SPEED_1G;
	if (edata.supported & SUPPORTED_10000baseKR_Full)
		priv->link_speed_capa |= ETH_LINK_SPEED_10G;
	if (edata.supported & (SUPPORTED_40000baseKR4_Full |
			       SUPPORTED_40000baseCR4_Full |
			       SUPPORTED_40000baseSR4_Full |
			       SUPPORTED_40000baseLR4_Full))
		priv->link_speed_capa |= ETH_LINK_SPEED_40G;
	dev_link.link_duplex = ((edata.duplex == DUPLEX_HALF) ?
				ETH_LINK_HALF_DUPLEX : ETH_LINK_FULL_DUPLEX);
	dev_link.link_autoneg = !(dev->data->dev_conf.link_speeds &
			ETH_LINK_SPEED_FIXED);
	if (((dev_link.link_speed && !dev_link.link_status) ||
	     (!dev_link.link_speed && dev_link.link_status))) {
		rte_errno = EAGAIN;
		return -rte_errno;
	}
	*link = dev_link;
	return 0;
}

/**
 * Retrieve physical link information (unlocked version using new ioctl).
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param[out] link
 *   Storage for current link status.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
mlx5_link_update_unlocked_gs(struct rte_eth_dev *dev,
			     struct rte_eth_link *link)

{
	struct priv *priv = dev->data->dev_private;
	struct ethtool_link_settings gcmd = { .cmd = ETHTOOL_GLINKSETTINGS };
	struct ifreq ifr;
	struct rte_eth_link dev_link;
	struct rte_eth_dev *master = NULL;
	uint64_t sc;
	int ret;

	ret = mlx5_ifreq(dev, SIOCGIFFLAGS, &ifr);
	if (ret) {
		DRV_LOG(WARNING, "port %u ioctl(SIOCGIFFLAGS) failed: %s",
			dev->data->port_id, strerror(rte_errno));
		return ret;
	}
	memset(&dev_link, 0, sizeof(dev_link));
	dev_link.link_status = ((ifr.ifr_flags & IFF_UP) &&
				(ifr.ifr_flags & IFF_RUNNING));
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_data = (void *)&gcmd;
	ret = mlx5_ifreq(dev, SIOCETHTOOL, &ifr);
	if (ret) {
		if (ret == -ENOTSUP && priv->representor) {
			/*
			 * For representors we can try to inherit link
			 * settings from the master device. Actually
			 * link settings do not make a lot of sense
			 * for representors due to missing physical
			 * link. The old kernel drivers supported
			 * emulated settings query for representors,
			 * the new ones do not, so we have to add
			 * this code for compatibility issues.
			 */
			master = mlx5_find_master_dev(dev);
			if (master) {
				ifr = (struct ifreq) {
					.ifr_data = (void *)&gcmd,
				};
				/*
				 * Avoid using master Netlink socket.
				 * This is not thread-safe.
				 */
				ret = mlx5_ifreq_base(dev, master,
						      SIOCETHTOOL, &ifr);
			}
		}
		if (ret) {
			DRV_LOG(DEBUG,
				"port %u ioctl(SIOCETHTOOL,"
				" ETHTOOL_GLINKSETTINGS) failed: %s",
				dev->data->port_id, strerror(rte_errno));
			return ret;
		}

	}
	gcmd.link_mode_masks_nwords = -gcmd.link_mode_masks_nwords;

	alignas(struct ethtool_link_settings)
	uint8_t data[offsetof(struct ethtool_link_settings, link_mode_masks) +
		     sizeof(uint32_t) * gcmd.link_mode_masks_nwords * 3];
	struct ethtool_link_settings *ecmd = (void *)data;

	*ecmd = gcmd;
	ifr.ifr_data = (void *)ecmd;
	ret = mlx5_ifreq_base(dev, master ? master : dev, SIOCETHTOOL, &ifr);
	if (ret) {
		DRV_LOG(DEBUG,
			"port %u ioctl(SIOCETHTOOL,"
			"ETHTOOL_GLINKSETTINGS) failed: %s",
			dev->data->port_id, strerror(rte_errno));
		return ret;
	}
	dev_link.link_speed = ecmd->speed;
	sc = ecmd->link_mode_masks[0] |
		((uint64_t)ecmd->link_mode_masks[1] << 32);
	priv->link_speed_capa = 0;
	if (sc & MLX5_BITSHIFT(ETHTOOL_LINK_MODE_Autoneg_BIT))
		priv->link_speed_capa |= ETH_LINK_SPEED_AUTONEG;
	if (sc & (MLX5_BITSHIFT(ETHTOOL_LINK_MODE_1000baseT_Full_BIT) |
		  MLX5_BITSHIFT(ETHTOOL_LINK_MODE_1000baseKX_Full_BIT)))
		priv->link_speed_capa |= ETH_LINK_SPEED_1G;
	if (sc & (MLX5_BITSHIFT(ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT) |
		  MLX5_BITSHIFT(ETHTOOL_LINK_MODE_10000baseKR_Full_BIT) |
		  MLX5_BITSHIFT(ETHTOOL_LINK_MODE_10000baseR_FEC_BIT)))
		priv->link_speed_capa |= ETH_LINK_SPEED_10G;
	if (sc & (MLX5_BITSHIFT(ETHTOOL_LINK_MODE_20000baseMLD2_Full_BIT) |
		  MLX5_BITSHIFT(ETHTOOL_LINK_MODE_20000baseKR2_Full_BIT)))
		priv->link_speed_capa |= ETH_LINK_SPEED_20G;
	if (sc & (MLX5_BITSHIFT(ETHTOOL_LINK_MODE_40000baseKR4_Full_BIT) |
		  MLX5_BITSHIFT(ETHTOOL_LINK_MODE_40000baseCR4_Full_BIT) |
		  MLX5_BITSHIFT(ETHTOOL_LINK_MODE_40000baseSR4_Full_BIT) |
		  MLX5_BITSHIFT(ETHTOOL_LINK_MODE_40000baseLR4_Full_BIT)))
		priv->link_speed_capa |= ETH_LINK_SPEED_40G;
	if (sc & (MLX5_BITSHIFT(ETHTOOL_LINK_MODE_56000baseKR4_Full_BIT) |
		  MLX5_BITSHIFT(ETHTOOL_LINK_MODE_56000baseCR4_Full_BIT) |
		  MLX5_BITSHIFT(ETHTOOL_LINK_MODE_56000baseSR4_Full_BIT) |
		  MLX5_BITSHIFT(ETHTOOL_LINK_MODE_56000baseLR4_Full_BIT)))
		priv->link_speed_capa |= ETH_LINK_SPEED_56G;
	if (sc & (MLX5_BITSHIFT(ETHTOOL_LINK_MODE_25000baseCR_Full_BIT) |
		  MLX5_BITSHIFT(ETHTOOL_LINK_MODE_25000baseKR_Full_BIT) |
		  MLX5_BITSHIFT(ETHTOOL_LINK_MODE_25000baseSR_Full_BIT)))
		priv->link_speed_capa |= ETH_LINK_SPEED_25G;
	if (sc & (MLX5_BITSHIFT(ETHTOOL_LINK_MODE_50000baseCR2_Full_BIT) |
		  MLX5_BITSHIFT(ETHTOOL_LINK_MODE_50000baseKR2_Full_BIT)))
		priv->link_speed_capa |= ETH_LINK_SPEED_50G;
	if (sc & (MLX5_BITSHIFT(ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT) |
		  MLX5_BITSHIFT(ETHTOOL_LINK_MODE_100000baseSR4_Full_BIT) |
		  MLX5_BITSHIFT(ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT) |
		  MLX5_BITSHIFT(ETHTOOL_LINK_MODE_100000baseLR4_ER4_Full_BIT)))
		priv->link_speed_capa |= ETH_LINK_SPEED_100G;
	dev_link.link_duplex = ((ecmd->duplex == DUPLEX_HALF) ?
				ETH_LINK_HALF_DUPLEX : ETH_LINK_FULL_DUPLEX);
	dev_link.link_autoneg = !(dev->data->dev_conf.link_speeds &
				  ETH_LINK_SPEED_FIXED);
	if (((dev_link.link_speed && !dev_link.link_status) ||
	     (!dev_link.link_speed && dev_link.link_status))) {
		rte_errno = EAGAIN;
		return -rte_errno;
	}
	*link = dev_link;
	return 0;
}

/**
 * DPDK callback to retrieve physical link information.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param wait_to_complete
 *   Wait for request completion.
 *
 * @return
 *   0 if link status was not updated, positive if it was, a negative errno
 *   value otherwise and rte_errno is set.
 */
int
mlx5_link_update(struct rte_eth_dev *dev, int wait_to_complete)
{
	int ret;
	struct rte_eth_link dev_link;
	time_t start_time = time(NULL);

	do {
		ret = mlx5_link_update_unlocked_gs(dev, &dev_link);
		if (ret)
			ret = mlx5_link_update_unlocked_gset(dev, &dev_link);
		if (ret == 0)
			break;
		/* Handle wait to complete situation. */
		if (wait_to_complete && ret == -EAGAIN) {
			if (abs((int)difftime(time(NULL), start_time)) <
			    MLX5_LINK_STATUS_TIMEOUT) {
				usleep(0);
				continue;
			} else {
				rte_errno = EBUSY;
				return -rte_errno;
			}
		} else if (ret < 0) {
			return ret;
		}
	} while (wait_to_complete);
	ret = !!memcmp(&dev->data->dev_link, &dev_link,
		       sizeof(struct rte_eth_link));
	dev->data->dev_link = dev_link;
	return ret;
}

/**
 * DPDK callback to change the MTU.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param in_mtu
 *   New MTU.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_dev_set_mtu(struct rte_eth_dev *dev, uint16_t mtu)
{
	struct priv *priv = dev->data->dev_private;
	uint16_t kern_mtu = 0;
	int ret;

	ret = mlx5_get_mtu(dev, &kern_mtu);
	if (ret)
		return ret;
	/* Set kernel interface MTU first. */
	ret = mlx5_set_mtu(dev, mtu);
	if (ret)
		return ret;
	ret = mlx5_get_mtu(dev, &kern_mtu);
	if (ret)
		return ret;
	if (kern_mtu == mtu) {
		priv->mtu = mtu;
		DRV_LOG(DEBUG, "port %u adapter MTU set to %u",
			dev->data->port_id, mtu);
		return 0;
	}
	rte_errno = EAGAIN;
	return -rte_errno;
}

/**
 * DPDK callback to get flow control status.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param[out] fc_conf
 *   Flow control output buffer.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_dev_get_flow_ctrl(struct rte_eth_dev *dev, struct rte_eth_fc_conf *fc_conf)
{
	struct ifreq ifr;
	struct ethtool_pauseparam ethpause = {
		.cmd = ETHTOOL_GPAUSEPARAM
	};
	int ret;

	ifr.ifr_data = (void *)&ethpause;
	ret = mlx5_ifreq(dev, SIOCETHTOOL, &ifr);
	if (ret) {
		DRV_LOG(WARNING,
			"port %u ioctl(SIOCETHTOOL, ETHTOOL_GPAUSEPARAM) failed:"
			" %s",
			dev->data->port_id, strerror(rte_errno));
		return ret;
	}
	fc_conf->autoneg = ethpause.autoneg;
	if (ethpause.rx_pause && ethpause.tx_pause)
		fc_conf->mode = RTE_FC_FULL;
	else if (ethpause.rx_pause)
		fc_conf->mode = RTE_FC_RX_PAUSE;
	else if (ethpause.tx_pause)
		fc_conf->mode = RTE_FC_TX_PAUSE;
	else
		fc_conf->mode = RTE_FC_NONE;
	return 0;
}

/**
 * DPDK callback to modify flow control parameters.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param[in] fc_conf
 *   Flow control parameters.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_dev_set_flow_ctrl(struct rte_eth_dev *dev, struct rte_eth_fc_conf *fc_conf)
{
	struct ifreq ifr;
	struct ethtool_pauseparam ethpause = {
		.cmd = ETHTOOL_SPAUSEPARAM
	};
	int ret;

	ifr.ifr_data = (void *)&ethpause;
	ethpause.autoneg = fc_conf->autoneg;
	if (((fc_conf->mode & RTE_FC_FULL) == RTE_FC_FULL) ||
	    (fc_conf->mode & RTE_FC_RX_PAUSE))
		ethpause.rx_pause = 1;
	else
		ethpause.rx_pause = 0;

	if (((fc_conf->mode & RTE_FC_FULL) == RTE_FC_FULL) ||
	    (fc_conf->mode & RTE_FC_TX_PAUSE))
		ethpause.tx_pause = 1;
	else
		ethpause.tx_pause = 0;
	ret = mlx5_ifreq(dev, SIOCETHTOOL, &ifr);
	if (ret) {
		DRV_LOG(WARNING,
			"port %u ioctl(SIOCETHTOOL, ETHTOOL_SPAUSEPARAM)"
			" failed: %s",
			dev->data->port_id, strerror(rte_errno));
		return ret;
	}
	return 0;
}

/**
 * Get PCI information from struct ibv_device.
 *
 * @param device
 *   Pointer to Ethernet device structure.
 * @param[out] pci_addr
 *   PCI bus address output buffer.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_ibv_device_to_pci_addr(const struct ibv_device *device,
			    struct rte_pci_addr *pci_addr)
{
	FILE *file;
	char line[32];
	MKSTR(path, "%s/device/uevent", device->ibdev_path);

	file = fopen(path, "rb");
	if (file == NULL) {
		rte_errno = errno;
		return -rte_errno;
	}
	while (fgets(line, sizeof(line), file) == line) {
		size_t len = strlen(line);
		int ret;

		/* Truncate long lines. */
		if (len == (sizeof(line) - 1))
			while (line[(len - 1)] != '\n') {
				ret = fgetc(file);
				if (ret == EOF)
					break;
				line[(len - 1)] = ret;
			}
		/* Extract information. */
		if (sscanf(line,
			   "PCI_SLOT_NAME="
			   "%" SCNx32 ":%" SCNx8 ":%" SCNx8 ".%" SCNx8 "\n",
			   &pci_addr->domain,
			   &pci_addr->bus,
			   &pci_addr->devid,
			   &pci_addr->function) == 4) {
			ret = 0;
			break;
		}
	}
	fclose(file);
	return 0;
}

/**
 * Handle shared asynchronous events the NIC (removal event
 * and link status change). Supports multiport IB device.
 *
 * @param cb_arg
 *   Callback argument.
 */
void
mlx5_dev_interrupt_handler(void *cb_arg)
{
	struct mlx5_ibv_shared *sh = cb_arg;
	struct ibv_async_event event;

	/* Read all message from the IB device and acknowledge them. */
	for (;;) {
		struct rte_eth_dev *dev = NULL;
		uint32_t ib_port_num = 0;
		uint32_t ih_port_id;
		uint32_t i;
		uint8_t is_port_event = 0;
		uint32_t is_ca_event = 0;

		if (mlx5_glue->get_async_event(sh->ctx, &event))
			break;
		switch (event.event_type) {
		case IBV_EVENT_DEVICE_FATAL:
			/* CA event */
			is_ca_event = 1;
			break;
		case IBV_EVENT_PORT_ERR:
		case IBV_EVENT_PORT_ACTIVE:
		case IBV_EVENT_LID_CHANGE:
		case IBV_EVENT_PKEY_CHANGE:
		case IBV_EVENT_SM_CHANGE:
		case IBV_EVENT_CLIENT_REREGISTER:
		case IBV_EVENT_GID_CHANGE:
			/*
			 * Port Events
			 * Retrieve and check IB port index.
			 */
			ib_port_num = (uint32_t)event.element.port_num;
			assert(ib_port_num && (ib_port_num <= sh->max_port));
			is_port_event = 1;
			break;
		default:
			/* we don't handle QP and CP events */
			ib_port_num = 0;
			break;
		}
		if ((!ib_port_num && !is_ca_event) ||
		    (is_port_event && (ib_port_num > sh->max_port ||
			sh->port[ib_port_num - 1].ih_port_id >=
			RTE_MAX_ETHPORTS))) {
			/*
			 * Invalid IB port index or no handler
			 * installed for this port.
			 */
			mlx5_glue->ack_async_event(&event);
			continue;
		}
		/* Retrieve ethernet device descriptor. */
		if (is_port_event) {
			dev =
			&rte_eth_devices[sh->port[ib_port_num - 1].ih_port_id];
			assert(dev);
		}
		ib_port_num = 0;
		if ((event.event_type == IBV_EVENT_PORT_ACTIVE ||
		     event.event_type == IBV_EVENT_PORT_ERR) &&
			dev->data->dev_conf.intr_conf.lsc) {
			mlx5_glue->ack_async_event(&event);
			if (mlx5_link_update(dev, 0) == -EAGAIN) {
				usleep(0);
				continue;
			}
			_rte_eth_dev_callback_process
				(dev, RTE_ETH_EVENT_INTR_LSC, NULL, NULL);
			continue;
		}
		if (event.event_type == IBV_EVENT_DEVICE_FATAL) {
			mlx5_glue->ack_async_event(&event);
			for (i = 0; i < sh->max_port; ++i) {
				ih_port_id = sh->port[i].ih_port_id;
				if (ih_port_id < RTE_MAX_ETHPORTS) {
					dev = &rte_eth_devices[ih_port_id];
					if (dev->data->dev_conf.intr_conf.rmv) {
						_rte_eth_dev_callback_process
						(dev, RTE_ETH_EVENT_INTR_RMV,
						 NULL, NULL);
					}
				}
			}
			continue;
		}
#ifndef HAVE_MLX5_DEVX_ASYNC_SUPPORT
		if ((event.event_type == IB_EVENT_DRIVER_RAW ||
		     event.event_type == IB_EVENT_DRIVER_RAW_ERROR)) {
			int ret = event.event_type != IB_EVENT_DRIVER_RAW;

			mlx5_glue->ack_async_event(&event);
			mlx5_devx_cmd_fc_query_callback(ret, 0,
					(void *)event.element.raw_driver);
			continue;
		}
#endif
		DRV_LOG(DEBUG,
			"port %u event type %d on not handled",
			dev->data->port_id, event.event_type);
		mlx5_glue->ack_async_event(&event);
	}
}

#ifdef HAVE_MLX5_DEVX_ASYNC_SUPPORT
/**
 * Handle DEVX interrupts from the NIC.
 *
 * @param[in] intr_handle
 *   Interrupt handler.
 * @param cb_arg
 *   Callback argument.
 */
void
mlx5_dev_interrupt_handler_devx(void *cb_arg)
{
	struct mlx5_ibv_shared *sh = cb_arg;
	union {
		struct mlx5dv_devx_async_cmd_hdr cmd_resp;
		uint8_t buf[64];
	} out;
	uint8_t *buf = out.buf + sizeof(out.cmd_resp);
	int status, syndrome;

	if (mlx5dv_devx_get_async_cmd_comp(sh->devx_comp, &out.cmd_resp,
					   sizeof(out.buf)))
		return;
	status = MLX5_GET(query_flow_counter_out, buf, status);
	syndrome = MLX5_GET(query_flow_counter_out, buf, syndrome);
	mlx5_devx_cmd_fc_query_callback(status, syndrome,
					(void *)out.cmd_resp.wr_id);
}
#endif

/**
 * Handle interrupts from the socket.
 *
 * @param cb_arg
 *   Callback argument.
 */
static void
mlx5_dev_handler_socket(void *cb_arg)
{
	struct rte_eth_dev *dev = cb_arg;

	mlx5_socket_handle(dev);
}

/**
 * Unregister callback handler safely and definitely.
 * If the callback is still active, we try again until
 * it is succesfully unregisterd or other errors.
 *
 * @param handle
 *   interrupt handle
 * @param cb_fn
 *   pointer to callback routine
 * @cb_arg
 *   opaque callback parameter
 */
static void
mlx5_intr_callback_unregister(const struct rte_intr_handle *handle,
			      rte_intr_callback_fn cb_fn, void *cb_arg)
{
	int ret =0;
	int tries = 0;
	struct timespec sleeptime = {.tv_sec = 0, .tv_nsec = 0};

	for(;;) {
		ret = rte_intr_callback_unregister(handle, cb_fn, cb_arg);
		if (likely(ret != -EAGAIN))
			break;
		if (unlikely(++tries % 100 == 0))
			DRV_LOG(ERR, "Tried %d times, handler is still in use!",
				tries);
		nanosleep(&sleeptime, NULL);
	}
}

/**
 * Uninstall shared asynchronous device events handler.
 * This function is implemeted to support event sharing
 * between multiple ports of single IB device.
 *
 * @param dev
 *   Pointer to Ethernet device.
 */
static void
mlx5_dev_shared_handler_uninstall(struct rte_eth_dev *dev)
{
	struct priv *priv = dev->data->dev_private;
	struct mlx5_ibv_shared *sh = priv->sh;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return;
	pthread_mutex_lock(&sh->intr_mutex);
	assert(priv->ibv_port);
	assert(priv->ibv_port <= sh->max_port);
	assert(dev->data->port_id < RTE_MAX_ETHPORTS);
	if (sh->port[priv->ibv_port - 1].ih_port_id >= RTE_MAX_ETHPORTS)
		goto exit;
	assert(sh->port[priv->ibv_port - 1].ih_port_id ==
					(uint32_t)dev->data->port_id);
	assert(sh->intr_cnt);
	sh->port[priv->ibv_port - 1].ih_port_id = RTE_MAX_ETHPORTS;
	if (!sh->intr_cnt || --sh->intr_cnt)
		goto exit;
	mlx5_intr_callback_unregister(&sh->intr_handle,
				      mlx5_dev_interrupt_handler, sh);
	sh->intr_handle.fd = 0;
	sh->intr_handle.type = RTE_INTR_HANDLE_UNKNOWN;
#ifdef HAVE_MLX5_DEVX_ASYNC_SUPPORT
	if (sh->intr_handle_devx.fd) {
		mlx5_intr_callback_unregister(&sh->intr_handle_devx,
					      mlx5_dev_interrupt_handler_devx,
					      sh);
		sh->intr_handle_devx.fd = 0;
		sh->intr_handle_devx.type = RTE_INTR_HANDLE_UNKNOWN;
	}
	if (sh->devx_comp) {
		mlx5dv_devx_destroy_cmd_comp(sh->devx_comp);
		sh->devx_comp = NULL;
	}
#endif
exit:
	pthread_mutex_unlock(&sh->intr_mutex);
}

/**
 * Install shared asyncronous device events handler.
 * This function is implemeted to support event sharing
 * between multiple ports of single IB device.
 *
 * @param dev
 *   Pointer to Ethernet device.
 */
static void
mlx5_dev_shared_handler_install(struct rte_eth_dev *dev)
{
	struct priv *priv = dev->data->dev_private;
	struct mlx5_ibv_shared *sh = priv->sh;
	int ret;
	int flags;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return;
	pthread_mutex_lock(&sh->intr_mutex);
	assert(priv->ibv_port);
	assert(priv->ibv_port <= sh->max_port);
	assert(dev->data->port_id < RTE_MAX_ETHPORTS);
	if (sh->port[priv->ibv_port - 1].ih_port_id < RTE_MAX_ETHPORTS) {
		/* The handler is already installed for this port. */
		assert(sh->intr_cnt);
		goto exit;
	}
	sh->port[priv->ibv_port - 1].ih_port_id = (uint32_t)dev->data->port_id;
	if (sh->intr_cnt) {
		sh->intr_cnt++;
		goto exit;
	}
	/* No shared handler installed. */
	assert(sh->ctx->async_fd > 0);
	flags = fcntl(sh->ctx->async_fd, F_GETFL);
	ret = fcntl(sh->ctx->async_fd, F_SETFL, flags | O_NONBLOCK);
	if (ret) {
		DRV_LOG(INFO, "failed to change file descriptor"
			      " async event queue");
		/* Indicate there will be no interrupts. */
		dev->data->dev_conf.intr_conf.lsc = 0;
		dev->data->dev_conf.intr_conf.rmv = 0;
		sh->port[priv->ibv_port - 1].ih_port_id = RTE_MAX_ETHPORTS;
		goto exit;
	}
	sh->intr_handle.fd = sh->ctx->async_fd;
	sh->intr_handle.type = RTE_INTR_HANDLE_EXT;
	rte_intr_callback_register(&sh->intr_handle,
				   mlx5_dev_interrupt_handler, sh);
#ifdef HAVE_MLX5_DEVX_ASYNC_SUPPORT
	if (priv->config.devx) {
		sh->devx_comp = mlx5dv_devx_create_cmd_comp(sh->ctx);
		if (sh->devx_comp) {
			flags = fcntl(sh->devx_comp->fd, F_GETFL);
			ret = fcntl(sh->devx_comp->fd, F_SETFL,
				    flags | O_NONBLOCK);
			if (ret) {
				DRV_LOG(INFO,
					"port %u failed to change file"
					" descriptor async event queue",
					dev->data->port_id);
			}
			sh->intr_handle_devx.fd = sh->devx_comp->fd;
			sh->intr_handle_devx.type = RTE_INTR_HANDLE_EXT;
			rte_intr_callback_register
				(&sh->intr_handle_devx,
				 mlx5_dev_interrupt_handler_devx, sh);
		} else {
			DRV_LOG(INFO,
				"port %u failed to create"
				" DEVX async command completion",
				dev->data->port_id);
		}
	}
#endif
	sh->intr_cnt++;
exit:
	pthread_mutex_unlock(&sh->intr_mutex);
}

/**
 * Uninstall interrupt handler.
 *
 * @param dev
 *   Pointer to Ethernet device.
 */
void
mlx5_dev_interrupt_handler_uninstall(struct rte_eth_dev *dev)
{
	struct priv *priv = dev->data->dev_private;

	mlx5_dev_shared_handler_uninstall(dev);
	if (priv->primary_socket) {
		mlx5_intr_callback_unregister(&priv->intr_handle_socket,
					      mlx5_dev_handler_socket,
					      dev);
	}
	priv->intr_handle_socket.fd = 0;
	priv->intr_handle_socket.type = RTE_INTR_HANDLE_UNKNOWN;
}

/**
 * Install interrupt handler.
 *
 * @param dev
 *   Pointer to Ethernet device.
 */
void
mlx5_dev_interrupt_handler_install(struct rte_eth_dev *dev)
{
	struct priv *priv = dev->data->dev_private;
	int ret;

	mlx5_dev_shared_handler_install(dev);
	ret = mlx5_socket_init(dev);
	if (ret)
		DRV_LOG(ERR, "port %u cannot initialise socket: %s",
			dev->data->port_id, strerror(rte_errno));
	else if (priv->primary_socket) {
		priv->intr_handle_socket.fd = priv->primary_socket;
		priv->intr_handle_socket.type = RTE_INTR_HANDLE_EXT;
		rte_intr_callback_register(&priv->intr_handle_socket,
					   mlx5_dev_handler_socket, dev);
	}
}

/**
 * DPDK callback to bring the link DOWN.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_set_link_down(struct rte_eth_dev *dev)
{
	return mlx5_set_flags(dev, ~IFF_UP, ~IFF_UP);
}

/**
 * DPDK callback to bring the link UP.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_set_link_up(struct rte_eth_dev *dev)
{
	return mlx5_set_flags(dev, ~IFF_UP, IFF_UP);
}

/**
 * Configure the TX function to use.
 *
 * @param dev
 *   Pointer to private data structure.
 *
 * @return
 *   Pointer to selected Tx burst function.
 */
eth_tx_burst_t
mlx5_select_tx_function(struct rte_eth_dev *dev)
{
	struct priv *priv = dev->data->dev_private;
	eth_tx_burst_t tx_pkt_burst = mlx5_tx_burst;
	struct mlx5_dev_config *config = &priv->config;
	uint64_t tx_offloads = dev->data->dev_conf.txmode.offloads;
	int tso = !!(tx_offloads & (DEV_TX_OFFLOAD_TCP_TSO |
				    DEV_TX_OFFLOAD_VXLAN_TNL_TSO |
				    DEV_TX_OFFLOAD_GRE_TNL_TSO |
				    DEV_TX_OFFLOAD_GENERIC_TNL_CKSUM_TSO));
	int vlan_insert = !!(tx_offloads & DEV_TX_OFFLOAD_VLAN_INSERT);

	assert(priv != NULL);
	/* Select appropriate TX function. */
	if (vlan_insert || tso)
		return tx_pkt_burst;
	if (config->mps == MLX5_MPW_ENHANCED) {
		if (mlx5_check_vec_tx_support(dev) > 0) {
			if (mlx5_check_raw_vec_tx_support(dev) > 0)
				tx_pkt_burst = mlx5_tx_burst_raw_vec;
			else
				tx_pkt_burst = mlx5_tx_burst_vec;
			DRV_LOG(DEBUG,
				"port %u selected enhanced MPW Tx vectorized"
				" function",
				dev->data->port_id);
		} else {
			tx_pkt_burst = mlx5_tx_burst_empw;
			DRV_LOG(DEBUG,
				"port %u selected enhanced MPW Tx function",
				dev->data->port_id);
		}
	} else if (config->mps && (config->txq_inline > 0)) {
		tx_pkt_burst = mlx5_tx_burst_mpw_inline;
		DRV_LOG(DEBUG, "port %u selected MPW inline Tx function",
			dev->data->port_id);
	} else if (config->mps) {
		tx_pkt_burst = mlx5_tx_burst_mpw;
		DRV_LOG(DEBUG, "port %u selected MPW Tx function",
			dev->data->port_id);
	}
	return tx_pkt_burst;
}

/**
 * Configure the RX function to use.
 *
 * @param dev
 *   Pointer to private data structure.
 *
 * @return
 *   Pointer to selected Rx burst function.
 */
eth_rx_burst_t
mlx5_select_rx_function(struct rte_eth_dev *dev)
{
	eth_rx_burst_t rx_pkt_burst = mlx5_rx_burst;

	assert(dev != NULL);
	if (mlx5_check_vec_rx_support(dev) > 0) {
		rx_pkt_burst = mlx5_rx_burst_vec;
		DRV_LOG(DEBUG, "port %u selected Rx vectorized function",
			dev->data->port_id);
	} else if (mlx5_mprq_enabled(dev)) {
		rx_pkt_burst = mlx5_rx_burst_mprq;
	}
	return rx_pkt_burst;
}

/**
 * Check if mlx5 device was removed.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 *
 * @return
 *   1 when device is removed, otherwise 0.
 */
int
mlx5_is_removed(struct rte_eth_dev *dev)
{
	struct ibv_device_attr device_attr;
	struct priv *priv = dev->data->dev_private;

	if (ibv_query_device(priv->sh->ctx, &device_attr) == EIO)
		return 1;
	return 0;
}

/**
 * Get port ID list of mlx5 instances sharing a common device.
 *
 * @param[in] dev
 *   Device to look for.
 * @param[out] port_list
 *   Result buffer for collected port IDs.
 * @param port_list_n
 *   Maximum number of entries in result buffer. If 0, @p port_list can be
 *   NULL.
 *
 * @return
 *   Number of matching instances regardless of the @p port_list_n
 *   parameter, 0 if none were found.
 */
unsigned int
mlx5_dev_to_port_id(const struct rte_device *dev, uint16_t *port_list,
		    unsigned int port_list_n)
{
	uint16_t id;
	unsigned int n = 0;

	RTE_ETH_FOREACH_DEV(id) {
		struct rte_eth_dev *ldev = &rte_eth_devices[id];

		if (!ldev->device ||
		    !ldev->device->driver ||
		    strcmp(ldev->device->driver->name, MLX5_DRIVER_NAME) ||
		    ldev->device != dev)
			continue;
		if (n < port_list_n)
			port_list[n] = id;
		n++;
	}
	return n;
}

/**
 * Get port ifindex.
 *
 * @param[in] port
 *   Device port id.
 *
 * @return
 *   Port ifindex.
 */
unsigned int
mlx5_port_to_ifindex(uint16_t port)
{
	static unsigned int ifindexes[RTE_MAX_ETHPORTS];
	struct rte_eth_dev_info dev_info;
	struct rte_eth_dev *dev = &rte_eth_devices[port];

	assert(port < RTE_MAX_ETHPORTS);

	if (ifindexes[port])
		return ifindexes[port];
	if (!dev->device || !dev->data)
		return 0;
	rte_eth_dev_info_get(port, &dev_info);
	ifindexes[port] = dev_info.if_index;
	return dev_info.if_index;
}

/**
 * Get the e-switch domain id this port belongs to.
 *
 * @param[in] port
 *   Device port id.
 * @param[out] es_domain_id
 *   e-switch domain id.
 * @param[out] es_port_id
 *   The port id of the port in the switch.
 *
 * @return
 *   0 on success, Negative error otherwise.
 */
int
mlx5_port_to_eswitch_info(uint16_t port,
			  uint16_t *es_domain_id, uint16_t *es_port_id)
{
	struct rte_eth_dev *dev;
	struct priv *priv;

	if (port >= RTE_MAX_ETHPORTS)
		return -EINVAL;
	dev = &rte_eth_devices[port];
	if (dev == NULL)
		return -ENODEV;
	if (!dev->device ||
	    !dev->device->driver ||
	    strcmp(dev->device->driver->name, MLX5_DRIVER_NAME))
		return -EINVAL;
	priv = dev->data->dev_private;
	if (!(priv->representor || priv->master))
		return -EINVAL;
	if (es_domain_id)
		*es_domain_id = priv->domain_id;
	if (es_port_id)
		*es_port_id = priv->vport_id;
	return 0;
}

/**
 * Get switch information associated with network interface.
 *
 * @param ifindex
 *   Network interface index.
 * @param[out] info
 *   Switch information object, populated in case of success.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_sysfs_switch_info(unsigned int ifindex, struct mlx5_switch_info *info)
{
	char ifname[IF_NAMESIZE];
	char port_name[IF_NAMESIZE];
	FILE *file;
	DIR *dir;
	struct mlx5_switch_info data = {
		.master = 0,
		.representor = 0,
		.name_type = MLX5_PHYS_PORT_NAME_TYPE_NOTSET,
		.port_name = 0,
		.switch_id = 0,
	};
	bool port_switch_id_set = false;
	bool device_dir = false;
	char c;
	int ret;

	if (!if_indextoname(ifindex, ifname)) {
		rte_errno = errno;
		return -rte_errno;
	}

	MKSTR(phys_port_name, "/sys/class/net/%s/phys_port_name",
	      ifname);
	MKSTR(phys_switch_id, "/sys/class/net/%s/phys_switch_id",
	      ifname);
	MKSTR(pci_device, "/sys/class/net/%s/device",
	      ifname);

	file = fopen(phys_port_name, "rb");
	if (file != NULL) {
		ret = fscanf(file, "%s", port_name);
		fclose(file);
		if (ret == 1)
			mlx5_translate_port_name(port_name, &data);
	}
	file = fopen(phys_switch_id, "rb");
	if (file == NULL) {
		rte_errno = errno;
		return -rte_errno;
	}
	port_switch_id_set =
		fscanf(file, "%" SCNx64 "%c", &data.switch_id, &c) == 2 &&
		c == '\n';
	fclose(file);
	dir = opendir(pci_device);
	if (dir != NULL) {
		closedir(dir);
		device_dir = true;
	}
	if (port_switch_id_set) {
		/* We have some E-Switch configuration. */
		mlx5_sysfs_check_switch_info(device_dir, &data);
	}
	*info = data;
	assert(!(data.master && data.representor));
	if (data.master && data.representor) {
		DRV_LOG(ERR, "ifindex %u device is recognized as master"
			     " and as representor", ifindex);
		rte_errno = ENODEV;
		return -rte_errno;
	}
	return 0;
}

/**
 * Analyze gathered port parameters via Netlink to recognize master
 * and representor devices for E-Switch configuration.
 *
 * @param[in] num_vf_set
 *   flag of presence of number of VFs port attribute.
 * @param[inout] switch_info
 *   Port information, including port name as a number and port name
 *   type if recognized
 *
 * @return
 *   master and representor flags are set in switch_info according to
 *   recognized parameters (if any).
 */
void
mlx5_nl_check_switch_info(bool num_vf_set,
			  struct mlx5_switch_info *switch_info)
{
	switch (switch_info->name_type) {
	case MLX5_PHYS_PORT_NAME_TYPE_UNKNOWN:
		/*
		 * Name is not recognized, assume the master,
		 * check the number of VFs key presence.
		 */
		switch_info->master = num_vf_set;
		break;
	case MLX5_PHYS_PORT_NAME_TYPE_NOTSET:
		/*
		 * Name is not set, this assumes the legacy naming
		 * schema for master, just check if there is a
		 * number of VFs key.
		 */
		switch_info->master = num_vf_set;
		break;
	case MLX5_PHYS_PORT_NAME_TYPE_UPLINK:
		/* New uplink naming schema recognized. */
		switch_info->master = 1;
		break;
	case MLX5_PHYS_PORT_NAME_TYPE_LEGACY:
		/* Legacy representors naming schema. */
		switch_info->representor = !num_vf_set;
		break;
	case MLX5_PHYS_PORT_NAME_TYPE_PFVF:
		/* New representors naming schema. */
		switch_info->representor = 1;
		break;
	}
}

/**
 * Analyze gathered port parameters via sysfs to recognize master
 * and representor devices for E-Switch configuration.
 *
 * @param[in] device_dir
 *   flag of presence of "device" directory under port device key.
 * @param[inout] switch_info
 *   Port information, including port name as a number and port name
 *   type if recognized
 *
 * @return
 *   master and representor flags are set in switch_info according to
 *   recognized parameters (if any).
 */
void
mlx5_sysfs_check_switch_info(bool device_dir,
			     struct mlx5_switch_info *switch_info)
{
	switch (switch_info->name_type) {
	case MLX5_PHYS_PORT_NAME_TYPE_UNKNOWN:
		/*
		 * Name is not recognized, assume the master,
		 * check the device directory presence.
		 */
		switch_info->master = device_dir;
		break;
	case MLX5_PHYS_PORT_NAME_TYPE_NOTSET:
		/*
		 * Name is not set, this assumes the legacy naming
		 * schema for master, just check if there is
		 * a device directory.
		 */
		switch_info->master = device_dir;
		break;
	case MLX5_PHYS_PORT_NAME_TYPE_UPLINK:
		/* New uplink naming schema recognized. */
		switch_info->master = 1;
		break;
	case MLX5_PHYS_PORT_NAME_TYPE_LEGACY:
		/* Legacy representors naming schema. */
		switch_info->representor = !device_dir;
		break;
	case MLX5_PHYS_PORT_NAME_TYPE_PFVF:
		/* New representors naming schema. */
		switch_info->representor = 1;
		break;
	}
}

/**
 * Extract port name, as a number, from sysfs or netlink information.
 *
 * @param[in] port_name_in
 *   String representing the port name.
 * @param[out] port_info_out
 *   Port information, including port name as a number and port name
 *   type if recognized
 *
 * @return
 *   port_name field set according to recognized name format.
 */
void
mlx5_translate_port_name(const char *port_name_in,
			 struct mlx5_switch_info *port_info_out)
{
	char pf_c1, pf_c2, vf_c1, vf_c2;
	char *end;
	int sc_items;

	/*
	 * Check for port-name as a string of the form pf0vf0
	 * (support kernel ver >= 5.0 or OFED ver >= 4.6).
	 */
	sc_items = sscanf(port_name_in, "%c%c%d%c%c%d",
			  &pf_c1, &pf_c2, &port_info_out->pf_num,
			  &vf_c1, &vf_c2, &port_info_out->port_name);
	if (sc_items == 6 &&
	    pf_c1 == 'p' && pf_c2 == 'f' &&
	    vf_c1 == 'v' && vf_c2 == 'f') {
		port_info_out->name_type = MLX5_PHYS_PORT_NAME_TYPE_PFVF;
		return;
	}
	/*
	 * Check for port-name as a string of the form p0
	 * (support kernel ver >= 5.0, or OFED ver >= 4.6).
	 */
	sc_items = sscanf(port_name_in, "%c%d",
			  &pf_c1, &port_info_out->port_name);
	if (sc_items == 2 && pf_c1 == 'p') {
		port_info_out->name_type = MLX5_PHYS_PORT_NAME_TYPE_UPLINK;
		return;
	}
	/* Check for port-name as a number (support kernel ver < 5.0 */
	errno = 0;
	port_info_out->port_name = strtol(port_name_in, &end, 0);
	if (!errno &&
	    (size_t)(end - port_name_in) == strlen(port_name_in)) {
		port_info_out->name_type = MLX5_PHYS_PORT_NAME_TYPE_LEGACY;
		return;
	}
	port_info_out->name_type = MLX5_PHYS_PORT_NAME_TYPE_UNKNOWN;
	return;
}