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

#include <ctype.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <net/if.h>
#include <sys/mman.h>
#include <linux/rtnetlink.h>

/* Verbs header. */
/* ISO C doesn't support unnamed structs/unions, disabling -pedantic. */
#ifdef PEDANTIC
#pragma GCC diagnostic ignored "-Wpedantic"
#endif
#include <infiniband/verbs.h>
#ifdef PEDANTIC
#pragma GCC diagnostic error "-Wpedantic"
#endif

#include <rte_malloc.h>
#include <rte_ethdev_driver.h>
#include <rte_ethdev_pci.h>
#include <rte_pci.h>
#include <rte_bus_pci.h>
#include <rte_common.h>
#include <rte_config.h>
#include <rte_eal_memconfig.h>
#include <rte_kvargs.h>
#include <rte_rwlock.h>
#include <rte_spinlock.h>
#include <rte_string_fns.h>

#include "mlx5.h"
#include "mlx5_utils.h"
#include "mlx5_rxtx.h"
#include "mlx5_autoconf.h"
#include "mlx5_defs.h"
#include "mlx5_devx_cmds.h"
#include "mlx5_flow.h"
#include "mlx5_glue.h"

/* Device parameter to enable RX completion queue compression. */
#define MLX5_RXQ_CQE_COMP_EN "rxq_cqe_comp_en"

/* Device parameter to enable Multi-Packet Rx queue. */
#define MLX5_RX_MPRQ_EN "mprq_en"

/* Device parameter to configure log 2 of the number of strides for MPRQ. */
#define MLX5_RX_MPRQ_LOG_STRIDE_NUM "mprq_log_stride_num"

/* Device parameter to limit the size of memcpy'd packet for MPRQ. */
#define MLX5_RX_MPRQ_MAX_MEMCPY_LEN "mprq_max_memcpy_len"

/* Device parameter to set the minimum number of Rx queues to enable MPRQ. */
#define MLX5_RXQS_MIN_MPRQ "rxqs_min_mprq"

/* Device parameter to configure inline send. */
#define MLX5_TXQ_INLINE "txq_inline"

/*
 * Device parameter to configure the number of TX queues threshold for
 * enabling inline send.
 */
#define MLX5_TXQS_MIN_INLINE "txqs_min_inline"

/* Device parameter to enable multi-packet send WQEs. */
#define MLX5_TXQ_MPW_EN "txq_mpw_en"

/* Device parameter to include 2 dsegs in the title WQEBB. */
#define MLX5_TXQ_MPW_HDR_DSEG_EN "txq_mpw_hdr_dseg_en"

/* Device parameter to limit the size of inlining packet. */
#define MLX5_TXQ_MAX_INLINE_LEN "txq_max_inline_len"

/* Device parameter to enable hardware Tx vector. */
#define MLX5_TX_VEC_EN "tx_vec_en"

/* Device parameter to enable hardware Rx vector. */
#define MLX5_RX_VEC_EN "rx_vec_en"

/* Activate DV flow steering. */
#define MLX5_DV_FLOW_EN "dv_flow_en"

/* Activate eswitch flow configuration via. */
#define MLX5_DV_ESWITCH_EN "dv_esw_en"

/* Select port representors to instantiate. */
#define MLX5_REPRESENTOR "representor"

/* Force Software Parser enablement/disablement. */
#define MLX5_FORCE_SWP "force_swp"

/* Device parameter to configure on which field to RSS. */
#define MLX5_HF_WHITE_LIST "hf_white_list"

/* Device parameter to configure on which field not to RSS. */
#define MLX5_HF_BLACK_LIST "hf_black_list"

#ifndef HAVE_IBV_MLX5_MOD_MPW
#define MLX5DV_CONTEXT_FLAGS_MPW_ALLOWED (1 << 2)
#define MLX5DV_CONTEXT_FLAGS_ENHANCED_MPW (1 << 3)
#endif

#ifndef HAVE_IBV_MLX5_MOD_CQE_128B_COMP
#define MLX5DV_CONTEXT_FLAGS_CQE_128B_COMP (1 << 4)
#endif

#define MLX5_RSS_IP_SRC (1 << 0)
#define MLX5_RSS_IP_DST (1 << 1)
#define MLX5_RSS_TCP_SRC_PORT (1 << 2)
#define MLX5_RSS_TCP_DST_PORT (1 << 3)
#define MLX5_RSS_UDP_SRC_PORT (1 << 4)
#define MLX5_RSS_UDP_DST_PORT (1 << 5)

/** Data associated with devices to spawn. */
struct mlx5_dev_spawn_data {
	uint32_t ifindex; /**< Network interface index. */
	uint32_t max_port; /**< IB device maximal port index. */
	uint32_t ibv_port; /**< IB device physical port index. */
	struct mlx5_switch_info info; /**< Switch information. */
	struct ibv_device *ibv_dev; /**< Associated IB device. */
	struct rte_eth_dev *eth_dev; /**< Associated Ethernet device. */
	struct rte_pci_device *pci_dev; /**< Associated PCI device */
};

static LIST_HEAD(, mlx5_ibv_shared) mlx5_ibv_list = LIST_HEAD_INITIALIZER();
static pthread_mutex_t mlx5_ibv_list_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * Allocate shared IB device context. If there is multiport device the
 * master and representors will share this context, if there is single
 * port dedicated IB device, the context will be used by only given
 * port due to unification.
 *
 * Routine first searches the context for the specified IB device name,
 * if found the shared context assumed and reference counter is incremented.
 * If no context found the new one is created and initialized with specified
 * IB device context and parameters.
 *
 * @param[in] spawn
 *   Pointer to the IB device attributes (name, port, etc).
 *
 * @return
 *   Pointer to mlx5_ibv_shared object on success,
 *   otherwise NULL and rte_errno is set.
 */
static struct mlx5_ibv_shared *
mlx5_alloc_shared_ibctx(const struct mlx5_dev_spawn_data *spawn)
{
	struct mlx5_ibv_shared *sh;
	int err = 0;
	uint32_t i;

	assert(spawn);
	/* Secondary process should not create the shared context. */
	assert(rte_eal_process_type() == RTE_PROC_PRIMARY);
	pthread_mutex_lock(&mlx5_ibv_list_mutex);
	/* Search for IB context by device name. */
	LIST_FOREACH(sh, &mlx5_ibv_list, next) {
		if (!strcmp(sh->ibdev_name, spawn->ibv_dev->name)) {
			sh->refcnt++;
			goto exit;
		}
	}
	/* No device found, we have to create new sharted context. */
	assert(spawn->max_port);
	sh = rte_zmalloc("ethdev shared ib context",
			 sizeof(struct mlx5_ibv_shared) +
			 spawn->max_port *
			 sizeof(struct mlx5_ibv_shared_port),
			 RTE_CACHE_LINE_SIZE);
	if (!sh) {
		DRV_LOG(ERR, "shared context allocation failure");
		rte_errno  = ENOMEM;
		goto exit;
	}
	/* Try to open IB device with DV first, then usual Verbs. */
	errno = 0;
#ifdef HAVE_IBV_DEVX_CONTEXT
	sh->ctx = mlx5_glue->dv_open_device(spawn->ibv_dev);
#endif
	if (sh->ctx) {
		sh->devx = 1;
		DRV_LOG(DEBUG, "DevX is supported");
	} else {
		sh->ctx = mlx5_glue->open_device(spawn->ibv_dev);
		if (!sh->ctx) {
			err = errno ? errno : ENODEV;
			goto error;
		}
		DRV_LOG(DEBUG, "DevX is NOT supported");
	}
	err = mlx5_glue->query_device_ex(sh->ctx, NULL, &sh->device_attr);
	if (err) {
		DRV_LOG(DEBUG, "ibv_query_device_ex() failed");
		goto error;
	}
	sh->refcnt = 1;
	sh->max_port = spawn->max_port;
	strncpy(sh->ibdev_name, sh->ctx->device->name,
		sizeof(sh->ibdev_name));
	strncpy(sh->ibdev_path, sh->ctx->device->ibdev_path,
		sizeof(sh->ibdev_path));
	pthread_mutex_init(&sh->intr_mutex, NULL);
	for (i = 0; i < sh->max_port; i++)
		sh->port[i].ih_port_id = RTE_MAX_ETHPORTS;
	sh->pd = mlx5_glue->alloc_pd(sh->ctx);
	if (sh->pd == NULL) {
		DRV_LOG(ERR, "PD allocation failure");
		err = ENOMEM;
		goto error;
	}
	LIST_INSERT_HEAD(&mlx5_ibv_list, sh, next);
exit:
	pthread_mutex_unlock(&mlx5_ibv_list_mutex);
	return sh;
error:
	pthread_mutex_unlock(&mlx5_ibv_list_mutex);
	assert(sh);
	if (sh->pd)
		claim_zero(mlx5_glue->dealloc_pd(sh->pd));
	if (sh->ctx)
		claim_zero(mlx5_glue->close_device(sh->ctx));
	rte_free(sh);
	assert(err > 0);
	rte_errno = err;
	return NULL;
}

/**
 * Free shared IB device context. Decrement counter and if zero free
 * all allocated resources and close handles.
 *
 * @param[in] sh
 *   Pointer to mlx5_ibv_shared object to free
 */
static void
mlx5_free_shared_ibctx(struct mlx5_ibv_shared *sh)
{
	pthread_mutex_lock(&mlx5_ibv_list_mutex);
#ifndef NDEBUG
	/* Check the object presence in the list. */
	struct mlx5_ibv_shared *lctx;

	LIST_FOREACH(lctx, &mlx5_ibv_list, next)
		if (lctx == sh)
			break;
	assert(lctx);
	if (lctx != sh) {
		DRV_LOG(ERR, "Freeing non-existing shared IB context");
		goto exit;
	}
#endif
	assert(sh);
	assert(sh->refcnt);
	/* Secondary process should not free the shared context. */
	assert(rte_eal_process_type() == RTE_PROC_PRIMARY);
	if (--sh->refcnt)
		goto exit;
	LIST_REMOVE(sh, next);
	/*
	 *  Ensure there is no async event handler installed.
	 *  Only primary process handles async device events.
	 **/
	assert(!sh->intr_cnt);
	if (sh->intr_cnt) {
		if (sh->intr_handle.fd)
			rte_intr_callback_unregister
				(&sh->intr_handle,
				 mlx5_dev_interrupt_handler, sh);
#ifdef HAVE_MLX5_DEVX_ASYNC_SUPPORT
		if (sh->intr_handle_devx.fd)
			rte_intr_callback_unregister
				(&sh->intr_handle_devx,
				 mlx5_dev_interrupt_handler_devx, sh);
		if (sh->devx_comp)
			mlx5dv_devx_destroy_cmd_comp(sh->devx_comp);
#endif
	}
	pthread_mutex_destroy(&sh->intr_mutex);
	if (sh->pd)
		claim_zero(mlx5_glue->dealloc_pd(sh->pd));
	if (sh->ctx)
		claim_zero(mlx5_glue->close_device(sh->ctx));
	rte_free(sh);
exit:
	pthread_mutex_unlock(&mlx5_ibv_list_mutex);
}

#ifdef HAVE_MLX5DV_DR
/**
 * Initialize DV/DR related data within private structure.
 * Routine checks the reference counter and does actual
 * resources creation/iniialization only if counter is zero.
 *
 * @param[in] priv
 *   Pointer to the private device data structure.
 *
 * @return
 *   Zero on success, positive error code otherwise.
 */
static int
mlx5_alloc_shared_dv(struct priv *priv, const struct mlx5_dev_config *config)
{
	struct mlx5_ibv_shared *sh = priv->sh;
	pthread_mutexattr_t mattr;
	unsigned int i;
	int err = 0;
	void *domain;

	assert(sh);
	if (sh->dv_refcnt) {
		/* Shared DV/DR structures is already initialized. */
		sh->dv_refcnt++;
		priv->dv_shared = 1;
		return 0;
	}
	/* Reference counter is zero, we should initialize structures. */
	sh->flow_stack = mlx5_flow_stack_alloc();
	if (!sh->flow_stack) {
		err = ENOMEM;
		goto error;
	}
	sh->tag_table = mlx5_flow_tags_hlist_create(priv->sh->ibdev_name);
	if (!sh->tag_table) {
		err = ENOMEM;
		goto error;
	}
	domain = mlx5dv_dr_domain_create(sh->ctx, MLX5DV_DR_DOMAIN_TYPE_NIC_RX);
	if (domain == NULL) {
		DRV_LOG(ERR, "ingress mlx5dv_dr_domain_create failed");
		err = errno;
		goto error;
	}
	sh->rx_domain = domain;
	domain = mlx5dv_dr_domain_create(sh->ctx, MLX5DV_DR_DOMAIN_TYPE_NIC_TX);
	if (domain == NULL) {
		DRV_LOG(ERR, "egress mlx5dv_dr_domain_create failed");
		err = errno;
		goto error;
	}
	sh->tx_domain = domain;
#ifdef HAVE_MLX5DV_DR_ESWITCH
	if (config->dv_eswitch_en) {
		domain = mlx5dv_dr_domain_create
			(sh->ctx, MLX5DV_DR_DOMAIN_TYPE_FDB);
		if (domain == NULL) {
			DRV_LOG(ERR, "mlx5dv_dr_domain_create failed");
			err = errno;
			goto error;
		}
		sh->fdb_domain = domain;
		sh->drop_action = mlx5dv_dr_action_create_drop();
		if (!sh->drop_action) {
			DRV_LOG(ERR, "create drop action failed");
			goto error;
		}
	}
#endif /* HAVE_MLX5DV_DR_ESWITCH */
	pthread_mutexattr_init(&mattr);
	pthread_mutexattr_settype(&mattr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&sh->dv_mutex, &mattr);
	pthread_mutexattr_destroy(&mattr);
	assert(!sh->dv_refcnt);
	sh->dv_refcnt++;
	priv->dv_shared = 1;
	return 0;
error:
	/* Rollback the created objects. */
	for (i = 0; i < MLX5_MAX_TABLES; ++i)
		if (sh->rx_tables[i])
			mlx5dv_dr_table_destroy(sh->rx_tables[i]);
	if (sh->rx_meter_suffix_table)
		mlx5dv_dr_table_destroy(sh->rx_meter_suffix_table);
	if (sh->rx_domain)
		mlx5dv_dr_domain_destroy(sh->rx_domain);
	for (i = 0; i < MLX5_MAX_TABLES; ++i)
		if (sh->tx_tables[i])
			mlx5dv_dr_table_destroy(sh->tx_tables[i]);
	if (sh->tx_meter_suffix_table)
		mlx5dv_dr_table_destroy(sh->tx_meter_suffix_table);
	if (sh->tx_domain)
		mlx5dv_dr_domain_destroy(sh->tx_domain);
	if (sh->tag_table)
		mlx5_flow_tags_hlist_free(sh->tag_table);
	if (sh->flow_stack)
		mlx5_flow_stack_release(sh->flow_stack);
	for (i = 0; i < MLX5_MAX_FDB_TABLES; ++i)
		if (sh->fdb_tables[i])
			mlx5dv_dr_table_destroy(sh->fdb_tables[i]);
	if (sh->fdb_meter_suffix_table)
		mlx5dv_dr_table_destroy(sh->fdb_meter_suffix_table);
	if (sh->drop_action)
		mlx5dv_dr_action_destroy(sh->drop_action);
	if (sh->fdb_domain)
		mlx5dv_dr_domain_destroy(sh->fdb_domain);
	rte_errno = err;
	return -err;
}
/**
 * Destroy DV/DR related structures within private structure.
 *
 * @param[in] priv
 *   Pointer to the private device data structure.
 */
static void
mlx5_free_shared_dv(struct priv *priv)
{
	struct mlx5_ibv_shared *sh;
	unsigned int i;

	if (!priv->dv_shared)
		return;
	priv->dv_shared = 0;
	sh = priv->sh;
	assert(sh);
	assert(sh->dv_refcnt);
	if (sh->dv_refcnt && --sh->dv_refcnt)
		return;
	for (i = 0; i < MLX5_MAX_TABLES; ++i)
		if (sh->rx_tables[i])
			mlx5dv_dr_table_destroy(sh->rx_tables[i]);
	if (sh->rx_meter_suffix_table)
		mlx5dv_dr_table_destroy(sh->rx_meter_suffix_table);
	if (sh->rx_domain)
		mlx5dv_dr_domain_destroy(sh->rx_domain);
	for (i = 0; i < MLX5_MAX_TABLES; ++i)
		if (sh->tx_tables[i])
			mlx5dv_dr_table_destroy(sh->tx_tables[i]);
	if (sh->tx_meter_suffix_table)
		mlx5dv_dr_table_destroy(sh->tx_meter_suffix_table);
	if (sh->tx_domain)
		mlx5dv_dr_domain_destroy(sh->tx_domain);
	if (sh->tag_table)
		mlx5_flow_tags_hlist_free(sh->tag_table);
	if (sh->flow_stack)
		mlx5_flow_stack_release(sh->flow_stack);
	for (i = 0; i < MLX5_MAX_FDB_TABLES; ++i)
		if (sh->fdb_tables[i])
			mlx5dv_dr_table_destroy(sh->fdb_tables[i]);
	if (sh->fdb_meter_suffix_table)
		mlx5dv_dr_table_destroy(sh->fdb_meter_suffix_table);
	if (sh->drop_action)
		mlx5dv_dr_action_destroy(sh->drop_action);
	if (sh->fdb_domain)
		mlx5dv_dr_domain_destroy(sh->fdb_domain);
	pthread_mutex_destroy(&sh->dv_mutex);
}
#endif /* HAVE_MLX5DV_DR */

/**
 * Retrieve integer value from environment variable.
 *
 * @param[in] name
 *   Environment variable name.
 *
 * @return
 *   Integer value, 0 if the variable is not set.
 */
int
mlx5_getenv_int(const char *name)
{
	const char *val = getenv(name);

	if (val == NULL)
		return 0;
	return atoi(val);
}

/**
 * Verbs callback to allocate a memory. This function should allocate the space
 * according to the size provided residing inside a huge page.
 * Please note that all allocation must respect the alignment from libmlx5
 * (i.e. currently sysconf(_SC_PAGESIZE)).
 *
 * @param[in] size
 *   The size in bytes of the memory to allocate.
 * @param[in] data
 *   A pointer to the callback data.
 *
 * @return
 *   Allocated buffer, NULL otherwise and rte_errno is set.
 */
static void *
mlx5_alloc_verbs_buf(size_t size, void *data)
{
	struct priv *priv = data;
	void *ret;
	size_t alignment = sysconf(_SC_PAGESIZE);
	unsigned int socket = SOCKET_ID_ANY;

	if (priv->verbs_alloc_ctx.type == MLX5_VERBS_ALLOC_TYPE_TX_QUEUE) {
		const struct mlx5_txq_ctrl *ctrl = priv->verbs_alloc_ctx.obj;

		socket = ctrl->socket;
	} else if (priv->verbs_alloc_ctx.type ==
		   MLX5_VERBS_ALLOC_TYPE_RX_QUEUE) {
		const struct mlx5_rxq_ctrl *ctrl = priv->verbs_alloc_ctx.obj;

		socket = ctrl->socket;
	}
	assert(data != NULL);
	ret = rte_zmalloc_socket(__func__, size, alignment, socket);
	if (!ret && size)
		rte_errno = ENOMEM;
	return ret;
}

/**
 * Verbs callback to free a memory.
 *
 * @param[in] ptr
 *   A pointer to the memory to free.
 * @param[in] data
 *   A pointer to the callback data.
 */
static void
mlx5_free_verbs_buf(void *ptr, void *data __rte_unused)
{
	assert(data != NULL);
	rte_free(ptr);
}

/**
 * DPDK callback to close the device.
 *
 * Destroy all queues and objects, free memory.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 */
static void
mlx5_dev_close(struct rte_eth_dev *dev)
{
	struct priv *priv = dev->data->dev_private;
	unsigned int i;
	int ret;

	DRV_LOG(DEBUG, "port %u closing device \"%s\"",
		dev->data->port_id,
		((priv->sh->ctx != NULL) ? priv->sh->ctx->device->name : ""));
	/* In case mlx5_dev_stop() has not been called. */
	mlx5_dev_interrupt_handler_uninstall(dev);
	mlx5_traffic_disable(dev);
	/* Prevent crashes when queues are still in use. */
	dev->rx_pkt_burst = removed_rx_burst;
	dev->tx_pkt_burst = removed_tx_burst;
	if (priv->rxqs != NULL) {
		/* XXX race condition if mlx5_rx_burst() is still running. */
		usleep(1000);
		for (i = 0; (i != priv->rxqs_n); ++i)
			mlx5_rxq_release(dev, i);
		priv->rxqs_n = 0;
		priv->rxqs = NULL;
	}
	if (priv->txqs != NULL) {
		/* XXX race condition if mlx5_tx_burst() is still running. */
		usleep(1000);
		for (i = 0; (i != priv->txqs_n); ++i)
			mlx5_txq_release(dev, i);
		priv->txqs_n = 0;
		priv->txqs = NULL;
	}
	mlx5_mprq_free_mp(dev);
	mlx5_mr_deregister_memseg(dev);
#ifdef HAVE_MLX5DV_DR
	if (priv->config.dv_flow_en) {
		mlx5_free_shared_dv(priv);
	}
#endif /* HAVE_MLX5DV_DR */
	flow_counter_mr_empty(dev);
	assert(priv->sh);
	if (priv->rss_conf.rss_key != NULL)
		rte_free(priv->rss_conf.rss_key);
	if (priv->reta_idx != NULL)
		rte_free(priv->reta_idx);
	if (priv->primary_socket)
		mlx5_socket_uninit(dev);
	if (priv->sh) {
		/*
		 * Free the shared context in last turn, because the cleanup
		 * routines above may use some shared fields, like
		 * mlx5_nl_mac_addr_flush() uses ibdev_path for retrieveing
		 * ifindex if Netlink fails.
		 */
		mlx5_free_shared_ibctx(priv->sh);
		priv->sh = NULL;
	}
	ret = mlx5_hrxq_ibv_verify(dev);
	if (ret)
		DRV_LOG(WARNING, "port %u some hash Rx queue still remain",
			dev->data->port_id);
	ret = mlx5_ind_table_ibv_verify(dev);
	if (ret)
		DRV_LOG(WARNING, "port %u some indirection table still remain",
			dev->data->port_id);
	ret = mlx5_rxq_ibv_verify(dev);
	if (ret)
		DRV_LOG(WARNING, "port %u some Verbs Rx queue still remain",
			dev->data->port_id);
	ret = mlx5_rxq_verify(dev);
	if (ret)
		DRV_LOG(WARNING, "port %u some Rx queues still remain",
			dev->data->port_id);
	ret = mlx5_txq_ibv_verify(dev);
	if (ret)
		DRV_LOG(WARNING, "port %u some Verbs Tx queue still remain",
			dev->data->port_id);
	ret = mlx5_txq_verify(dev);
	if (ret)
		DRV_LOG(WARNING, "port %u some Tx queues still remain",
			dev->data->port_id);
	ret = mlx5_flow_verify(dev);
	if (ret)
		DRV_LOG(WARNING, "port %u some flows still remain",
			dev->data->port_id);
	ret = mlx5_flow_meter_profile_verify(dev);
	if (ret)
		DRV_LOG(WARNING, "port %u some flow meter profiles "
			"still remain",	dev->data->port_id);
	ret = mlx5_flow_meter_verify(dev);
	if (ret)
		DRV_LOG(WARNING, "port %u some flow meters still remain",
			dev->data->port_id);
	if (priv->domain_id != RTE_ETH_DEV_SWITCH_DOMAIN_ID_INVALID) {
		unsigned int c = 0;
		unsigned int i = mlx5_dev_to_port_id(dev->device, NULL, 0);
		uint16_t port_id[i];

		i = RTE_MIN(mlx5_dev_to_port_id(dev->device, port_id, i), i);
		while (i--) {
			struct priv *opriv =
				rte_eth_devices[port_id[i]].data->dev_private;

			if (!opriv ||
			    opriv->domain_id != priv->domain_id ||
			    &rte_eth_devices[port_id[i]] == dev)
				continue;
			++c;
		}
		if (!c)
			claim_zero(rte_eth_switch_domain_free(priv->domain_id));
	}
	memset(priv, 0, sizeof(*priv));
	priv->domain_id = RTE_ETH_DEV_SWITCH_DOMAIN_ID_INVALID;
}

const struct eth_dev_ops mlx5_dev_ops = {
	.dev_configure = mlx5_dev_configure,
	.dev_start = mlx5_dev_start,
	.dev_stop = mlx5_dev_stop,
	.dev_set_link_down = mlx5_set_link_down,
	.dev_set_link_up = mlx5_set_link_up,
	.dev_close = mlx5_dev_close,
	.promiscuous_enable = mlx5_promiscuous_enable,
	.promiscuous_disable = mlx5_promiscuous_disable,
	.allmulticast_enable = mlx5_allmulticast_enable,
	.allmulticast_disable = mlx5_allmulticast_disable,
	.link_update = mlx5_link_update,
	.stats_get = mlx5_stats_get,
	.stats_reset = mlx5_stats_reset,
	.xstats_get = mlx5_xstats_get,
	.xstats_reset = mlx5_xstats_reset,
	.xstats_get_names = mlx5_xstats_get_names,
	.dev_infos_get = mlx5_dev_infos_get,
	.dev_supported_ptypes_get = mlx5_dev_supported_ptypes_get,
	.vlan_filter_set = mlx5_vlan_filter_set,
	.rx_queue_setup = mlx5_rx_queue_setup,
	.tx_queue_setup = mlx5_tx_queue_setup,
	.rx_queue_release = mlx5_rx_queue_release,
	.tx_queue_release = mlx5_tx_queue_release,
	.flow_ctrl_get = mlx5_dev_get_flow_ctrl,
	.flow_ctrl_set = mlx5_dev_set_flow_ctrl,
	.mac_addr_remove = mlx5_mac_addr_remove,
	.mac_addr_add = mlx5_mac_addr_add,
	.mac_addr_set = mlx5_mac_addr_set,
	.mtu_set = mlx5_dev_set_mtu,
	.vlan_strip_queue_set = mlx5_vlan_strip_queue_set,
	.vlan_offload_set = mlx5_vlan_offload_set,
	.reta_update = mlx5_dev_rss_reta_update,
	.reta_query = mlx5_dev_rss_reta_query,
	.rss_hash_update = mlx5_rss_hash_update,
	.rss_hash_conf_get = mlx5_rss_hash_conf_get,
	.filter_ctrl = mlx5_dev_filter_ctrl,
	.rx_descriptor_status = mlx5_rx_descriptor_status,
	.tx_descriptor_status = mlx5_tx_descriptor_status,
	.rx_queue_intr_enable = mlx5_rx_intr_enable,
	.rx_queue_intr_disable = mlx5_rx_intr_disable,
	.mtr_ops_get = mlx5_flow_meter_ops_get,
};

static const struct eth_dev_ops mlx5_dev_sec_ops = {
	.stats_get = mlx5_stats_get,
	.stats_reset = mlx5_stats_reset,
	.xstats_get = mlx5_xstats_get,
	.xstats_reset = mlx5_xstats_reset,
	.xstats_get_names = mlx5_xstats_get_names,
	.dev_infos_get = mlx5_dev_infos_get,
	.rx_descriptor_status = mlx5_rx_descriptor_status,
	.tx_descriptor_status = mlx5_tx_descriptor_status,
};

/* Available operators in flow isolated mode. */
const struct eth_dev_ops mlx5_dev_ops_isolate = {
	.dev_configure = mlx5_dev_configure,
	.dev_start = mlx5_dev_start,
	.dev_stop = mlx5_dev_stop,
	.dev_set_link_down = mlx5_set_link_down,
	.dev_set_link_up = mlx5_set_link_up,
	.dev_close = mlx5_dev_close,
	.link_update = mlx5_link_update,
	.stats_get = mlx5_stats_get,
	.stats_reset = mlx5_stats_reset,
	.xstats_get = mlx5_xstats_get,
	.xstats_reset = mlx5_xstats_reset,
	.xstats_get_names = mlx5_xstats_get_names,
	.dev_infos_get = mlx5_dev_infos_get,
	.dev_supported_ptypes_get = mlx5_dev_supported_ptypes_get,
	.vlan_filter_set = mlx5_vlan_filter_set,
	.rx_queue_setup = mlx5_rx_queue_setup,
	.tx_queue_setup = mlx5_tx_queue_setup,
	.rx_queue_release = mlx5_rx_queue_release,
	.tx_queue_release = mlx5_tx_queue_release,
	.flow_ctrl_get = mlx5_dev_get_flow_ctrl,
	.flow_ctrl_set = mlx5_dev_set_flow_ctrl,
	.mac_addr_remove = mlx5_mac_addr_remove,
	.mac_addr_add = mlx5_mac_addr_add,
	.mac_addr_set = mlx5_mac_addr_set,
	.mtu_set = mlx5_dev_set_mtu,
	.vlan_strip_queue_set = mlx5_vlan_strip_queue_set,
	.vlan_offload_set = mlx5_vlan_offload_set,
	.filter_ctrl = mlx5_dev_filter_ctrl,
	.rx_descriptor_status = mlx5_rx_descriptor_status,
	.tx_descriptor_status = mlx5_tx_descriptor_status,
	.rx_queue_intr_enable = mlx5_rx_intr_enable,
	.rx_queue_intr_disable = mlx5_rx_intr_disable,
	.mtr_ops_get = mlx5_flow_meter_ops_get,
};

/**
 * Convert the rss bits to ibv_rss_bits.
 *
 * @param[in] value
 *   The RSS fields.
 *
 * @return
 *   The RSS as IBV defines.
 */
static unsigned long 
mlx5_convert_rss_bits(unsigned long value)
{
	unsigned long res = 0;

	if (value & MLX5_RSS_IP_SRC)
		res |= IBV_RX_HASH_SRC_IPV4 | IBV_RX_HASH_SRC_IPV6;
	if (value & MLX5_RSS_IP_DST)
		res |= IBV_RX_HASH_DST_IPV4 | IBV_RX_HASH_DST_IPV6;
	if (value & MLX5_RSS_TCP_SRC_PORT)
		res |= IBV_RX_HASH_SRC_PORT_TCP;
	if (value & MLX5_RSS_TCP_DST_PORT)
		res |= IBV_RX_HASH_DST_PORT_TCP;
	if (value & MLX5_RSS_UDP_SRC_PORT)
		res |= IBV_RX_HASH_SRC_PORT_UDP;
	if (value & MLX5_RSS_UDP_DST_PORT)
		res |= IBV_RX_HASH_DST_PORT_UDP;
	return res;
}

/**
 * Verify and store value for device argument.
 *
 * @param[in] key
 *   Key argument to verify.
 * @param[in] val
 *   Value associated with key.
 * @param opaque
 *   User data.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
mlx5_args_check(const char *key, const char *val, void *opaque)
{
	struct mlx5_dev_config *config = opaque;
	unsigned long tmp;

	/* No-op, port representors are processed in mlx5_dev_spawn(). */
	if (!strcmp(MLX5_REPRESENTOR, key))
		return 0;
	errno = 0;
	tmp = strtoul(val, NULL, 0);
	if (errno) {
		rte_errno = errno;
		DRV_LOG(WARNING, "%s: \"%s\" is not a valid integer", key, val);
		return -rte_errno;
	}
	if (strcmp(MLX5_RXQ_CQE_COMP_EN, key) == 0) {
		config->cqe_comp = !!tmp;
	} else if (strcmp(MLX5_RX_MPRQ_EN, key) == 0) {
		config->mprq.enabled = !!tmp;
	} else if (strcmp(MLX5_RX_MPRQ_LOG_STRIDE_NUM, key) == 0) {
		config->mprq.stride_num_n = tmp;
	} else if (strcmp(MLX5_RX_MPRQ_MAX_MEMCPY_LEN, key) == 0) {
		config->mprq.max_memcpy_len = tmp;
	} else if (strcmp(MLX5_RXQS_MIN_MPRQ, key) == 0) {
		config->mprq.min_rxqs_num = tmp;
	} else if (strcmp(MLX5_TXQ_INLINE, key) == 0) {
		config->txq_inline = tmp;
	} else if (strcmp(MLX5_TXQS_MIN_INLINE, key) == 0) {
		config->txqs_inline = tmp;
	} else if (strcmp(MLX5_TXQ_MPW_EN, key) == 0) {
		config->mps = !!tmp ? config->mps : 0;
	} else if (strcmp(MLX5_TXQ_MPW_HDR_DSEG_EN, key) == 0) {
		config->mpw_hdr_dseg = !!tmp;
	} else if (strcmp(MLX5_TXQ_MAX_INLINE_LEN, key) == 0) {
		config->inline_max_packet_sz = tmp;
	} else if (strcmp(MLX5_TX_VEC_EN, key) == 0) {
		config->tx_vec_en = !!tmp;
	} else if (strcmp(MLX5_RX_VEC_EN, key) == 0) {
		config->rx_vec_en = !!tmp;
	} else if (strcmp(MLX5_FORCE_SWP, key) == 0) {
		config->swp = !!tmp;
		config->swp_force = 1;
	} else if (strcmp(MLX5_HF_WHITE_LIST, key) == 0) {
		config->rss_fields_mask = mlx5_convert_rss_bits(tmp);
	} else if (strcmp(MLX5_HF_BLACK_LIST, key) == 0) {
		config->rss_fields_mask = ~mlx5_convert_rss_bits(tmp);
	} else if (strcmp(MLX5_DV_FLOW_EN, key) == 0) {
		config->dv_flow_en = !!tmp;
	} else if (strcmp(MLX5_DV_ESWITCH_EN, key) == 0) {
		config->dv_eswitch_en = !!tmp;
	} else {
		DRV_LOG(WARNING, "%s: unknown parameter", key);
		rte_errno = EINVAL;
		return -rte_errno;
	}
	return 0;
}

/**
 * Parse device parameters.
 *
 * @param config
 *   Pointer to device configuration structure.
 * @param devargs
 *   Device arguments structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
mlx5_args(struct mlx5_dev_config *config, struct rte_devargs *devargs)
{
	const char **params = (const char *[]){
		MLX5_RXQ_CQE_COMP_EN,
		MLX5_RX_MPRQ_EN,
		MLX5_RX_MPRQ_LOG_STRIDE_NUM,
		MLX5_RX_MPRQ_MAX_MEMCPY_LEN,
		MLX5_RXQS_MIN_MPRQ,
		MLX5_TXQ_INLINE,
		MLX5_TXQS_MIN_INLINE,
		MLX5_TXQ_MPW_EN,
		MLX5_TXQ_MPW_HDR_DSEG_EN,
		MLX5_TXQ_MAX_INLINE_LEN,
		MLX5_TX_VEC_EN,
		MLX5_RX_VEC_EN,
		MLX5_REPRESENTOR,
		MLX5_FORCE_SWP,
		MLX5_HF_WHITE_LIST,
		MLX5_HF_BLACK_LIST,
		MLX5_DV_FLOW_EN,
		MLX5_DV_ESWITCH_EN,
		NULL,
	};
	struct rte_kvargs *kvlist;
	int ret = 0;
	int i;

	if (devargs == NULL)
		return 0;
	/* Following UGLY cast is done to pass checkpatch. */
	kvlist = rte_kvargs_parse(devargs->args, params);
	if (kvlist == NULL)
		return 0;
	/* Process parameters. */
	for (i = 0; (params[i] != NULL); ++i) {
		if (rte_kvargs_count(kvlist, params[i])) {
			ret = rte_kvargs_process(kvlist, params[i],
						 mlx5_args_check, config);
			if (ret) {
				rte_errno = EINVAL;
				rte_kvargs_free(kvlist);
				return -rte_errno;
			}
		}
	}
	rte_kvargs_free(kvlist);
	return 0;
}

static struct rte_pci_driver mlx5_driver;

/*
 * Reserved UAR address space for TXQ UAR(hw doorbell) mapping, process
 * local resource used by both primary and secondary to avoid duplicate
 * reservation.
 * The space has to be available on both primary and secondary process,
 * TXQ UAR maps to this area using fixed mmap w/o double check.
 */
static void *uar_base;

/**
 * Reserve UAR address space for primary process.
 *
 * @param[in] dev
 *   Pointer to Ethernet device.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
mlx5_uar_init_primary(struct rte_eth_dev *dev)
{
	struct priv *priv = dev->data->dev_private;
	void *addr = (void *)0;
	int i;
	const struct rte_mem_config *mcfg;

	if (uar_base) { /* UAR address space mapped. */
		priv->uar_base = uar_base;
		return 0;
	}
	/* find out lower bound of hugepage segments */
	mcfg = rte_eal_get_configuration()->mem_config;
	for (i = 0; i < RTE_MAX_MEMSEG && mcfg->memseg[i].addr; i++) {
		if (addr)
			addr = RTE_MIN(addr, mcfg->memseg[i].addr);
		else
			addr = mcfg->memseg[i].addr;
	}
	/* keep distance to hugepages to minimize potential conflicts. */
	addr = RTE_PTR_SUB(addr, MLX5_UAR_OFFSET + MLX5_UAR_SIZE);
	/* anonymous mmap, no real memory consumption. */
	addr = mmap(addr, MLX5_UAR_SIZE,
		    PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED) {
		DRV_LOG(ERR,
			"port %u failed to reserve UAR address space, please"
			" adjust MLX5_UAR_SIZE or try --base-virtaddr",
			dev->data->port_id);
		rte_errno = ENOMEM;
		return -rte_errno;
	}
	/* Accept either same addr or a new addr returned from mmap if target
	 * range occupied.
	 */
	DRV_LOG(INFO, "port %u reserved UAR address space: %p",
		dev->data->port_id, addr);
	priv->uar_base = addr; /* for primary and secondary UAR re-mmap. */
	uar_base = addr; /* process local, don't reserve again. */
	return 0;
}

/**
 * Reserve UAR address space for secondary process, align with
 * primary process.
 *
 * @param[in] dev
 *   Pointer to Ethernet device.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
mlx5_uar_init_secondary(struct rte_eth_dev *dev)
{
	struct priv *priv = dev->data->dev_private;
	void *addr;

	assert(priv->uar_base);
	if (uar_base) { /* already reserved. */
		assert(uar_base == priv->uar_base);
		return 0;
	}
	/* anonymous mmap, no real memory consumption. */
	addr = mmap(priv->uar_base, MLX5_UAR_SIZE,
		    PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED) {
		DRV_LOG(ERR, "port %u UAR mmap failed: %p size: %llu",
			dev->data->port_id, priv->uar_base, MLX5_UAR_SIZE);
		rte_errno = ENXIO;
		return -rte_errno;
	}
	if (priv->uar_base != addr) {
		DRV_LOG(ERR,
			"port %u UAR address %p size %llu occupied, please"
			" adjust MLX5_UAR_OFFSET or try EAL parameter"
			" --base-virtaddr",
			dev->data->port_id, priv->uar_base, MLX5_UAR_SIZE);
		rte_errno = ENXIO;
		return -rte_errno;
	}
	uar_base = addr; /* process local, don't reserve again */
	DRV_LOG(INFO, "port %u reserved UAR address space: %p",
		dev->data->port_id, addr);
	return 0;
}

/**
 * Spawn an Ethernet device from Verbs information.
 *
 * @param dpdk_dev
 *   Backing DPDK device.
 * @param spawn
 *   Verbs device parameters (name, port, switch_info) to spawn.
 *
 * @return
 *   A valid Ethernet device object on success, NULL otherwise and rte_errno
 *   is set.
 */
static struct rte_eth_dev *
mlx5_dev_spawn(struct rte_device *dpdk_dev,
	       struct mlx5_dev_spawn_data *spawn)
{
	const struct mlx5_switch_info *switch_info = &spawn->info;
	struct mlx5_ibv_shared *sh;
	struct ibv_port_attr port_attr;
	struct mlx5dv_context dv_attr = { .comp_mask = 0 };
	struct mlx5_dev_config config = {
		.cqe_comp = 1,
		.tx_vec_en = 1,
		.rx_vec_en = 1,
		.mpw_hdr_dseg = 0,
		.txq_inline = MLX5_ARG_UNSET,
		.txqs_inline = MLX5_ARG_UNSET,
		.inline_max_packet_sz = MLX5_ARG_UNSET,
		.mprq = {
			.enabled = 0,
			.stride_num_n = MLX5_MPRQ_STRIDE_NUM_N,
			.max_memcpy_len = MLX5_MPRQ_MEMCPY_DEFAULT_LEN,
			.min_rxqs_num = MLX5_MPRQ_MIN_RXQS,
		},
		.rss_fields_mask = -1,
		.mps = 1,
		.swp = 1,
		.hca_attr = {
			.qos = { 0 },
			.eswitch_manager = 0,
			.flow_counter_bulk_alloc_bitmap = 0,
		},
		.dv_flow_en = 1,
#ifdef HAVE_MLX5DV_DR_ESWITCH
		.dv_eswitch_en = 1,
#endif
	};
	struct rte_eth_dev *eth_dev = NULL;
	struct priv *priv = NULL;
	int err = 0;
	unsigned int mps;
	unsigned int cqe_comp;
	unsigned int swp = 0;
	unsigned int mprq = 0;
	unsigned int mprq_min_stride_size_n = 0;
	unsigned int mprq_max_stride_size_n = 0;
	unsigned int mprq_min_stride_num_n = 0;
	unsigned int mprq_max_stride_num_n = 0;
#ifdef HAVE_IBV_DEVICE_COUNTERS_SET_V42
	struct ibv_counter_set_description cs_desc = { .counter_type = 0 };
#endif
	struct ether_addr mac;
	char name[RTE_ETH_NAME_MAX_LEN];
	int own_domain_id = 0;
	uint16_t port_id;
	unsigned int i;
	uint8_t bond_device = 0;

	/* Determine if this port representor is supposed to be spawned. */
	if (switch_info->representor && dpdk_dev->devargs) {
		struct rte_eth_devargs eth_da;

		err = rte_eth_devargs_parse(dpdk_dev->devargs->args, &eth_da);
		if (err) {
			rte_errno = -err;
			DRV_LOG(ERR, "failed to process device arguments: %s",
				strerror(rte_errno));
			return NULL;
		}
		for (i = 0; i < eth_da.nb_representor_ports; ++i)
			if (eth_da.representor_ports[i] ==
			    (uint16_t)switch_info->port_name)
				break;
		if (i == eth_da.nb_representor_ports) {
			rte_errno = EBUSY;
			return NULL;
		}
	}
	err = mlx5_args(&config, dpdk_dev->devargs);
	/* Build device name. */
	if (strstr(spawn->ibv_dev->name, "mlx5_bond"))
		bond_device = 1;
	if (!switch_info->representor) {
		if (bond_device)
			snprintf(name, sizeof(name), "%s_%s",
				 dpdk_dev->name, spawn->ibv_dev->name);
		else
			snprintf(name, sizeof(name), "%s", dpdk_dev->name);
	} else {
		if (bond_device)
			snprintf(name, sizeof(name), "%s_%s_representor_%u",
				 dpdk_dev->name, spawn->ibv_dev->name,
				 switch_info->port_name);
		else
			snprintf(name, sizeof(name), "%s_representor_%u",
				 dpdk_dev->name, switch_info->port_name);
	}
	/* check if the device is already spawned */
	if (rte_eth_dev_get_port_by_name(name, &port_id) == 0) {
		rte_errno = EEXIST;
		return NULL;
	}
	if (rte_eal_process_type() == RTE_PROC_SECONDARY) {
		eth_dev = rte_eth_dev_attach_secondary(name);
		if (eth_dev == NULL) {
			DRV_LOG(ERR, "can not attach rte ethdev");
			rte_errno = ENOMEM;
			return NULL;
		}
		eth_dev->device = dpdk_dev;
		eth_dev->dev_ops = &mlx5_dev_sec_ops;
		err = mlx5_uar_init_secondary(eth_dev);
		if (err)
			return NULL;
		/* Receive command fd from primary process */
		err = mlx5_socket_connect(eth_dev);
		if (err < 0)
			return NULL;
		/* Remap UAR for Tx queues. */
		err = mlx5_tx_uar_remap(eth_dev, err);
		if (err)
			return NULL;
		/*
		 * Ethdev pointer is still required as input since
		 * the primary device is not accessible from the
		 * secondary process.
		 */
		eth_dev->rx_pkt_burst = mlx5_select_rx_function(eth_dev);
		eth_dev->tx_pkt_burst = mlx5_select_tx_function(eth_dev);
		return eth_dev;
	}
	sh = mlx5_alloc_shared_ibctx(spawn);
	if (!sh)
		return NULL;
	config.devx = sh->devx;
	config.dv_flow_en = sh->devx;
	DRV_LOG(INFO, "DEVX is %ssupported", config.devx ? "" : "not ");
#ifdef HAVE_IBV_MLX5_MOD_SWP
	dv_attr.comp_mask |= MLX5DV_CONTEXT_MASK_SWP;
#endif
#ifdef HAVE_IBV_DEVICE_TUNNEL_SUPPORT
	dv_attr.comp_mask |= MLX5DV_CONTEXT_MASK_TUNNEL_OFFLOADS;
#endif
#ifdef HAVE_IBV_DEVICE_STRIDING_RQ_SUPPORT
	dv_attr.comp_mask |= MLX5DV_CONTEXT_MASK_STRIDING_RQ;
#endif
	mlx5_glue->dv_query_device(sh->ctx, &dv_attr);
	if (dv_attr.flags & MLX5DV_CONTEXT_FLAGS_MPW_ALLOWED) {
		if (dv_attr.flags & MLX5DV_CONTEXT_FLAGS_ENHANCED_MPW) {
			DRV_LOG(DEBUG, "enhanced MPW is supported");
			mps = MLX5_MPW_ENHANCED;
		} else {
			DRV_LOG(DEBUG, "MPW is supported");
			mps = MLX5_MPW;
		}
	} else {
		DRV_LOG(DEBUG, "MPW isn't supported");
		mps = MLX5_MPW_DISABLED;
	}
	if (config.mps)
		config.mps = mps;
#ifdef HAVE_IBV_MLX5_MOD_SWP
	if (dv_attr.comp_mask & MLX5DV_CONTEXT_MASK_SWP)
		swp = dv_attr.sw_parsing_caps.sw_parsing_offloads;
	DRV_LOG(DEBUG, "Software parser is %ssupported", swp ? "" : "not ");
#endif
#ifdef HAVE_IBV_DEVICE_TUNNEL_SUPPORT
	if (dv_attr.comp_mask & MLX5DV_CONTEXT_MASK_TUNNEL_OFFLOADS)
		DRV_LOG(DEBUG, "Tunnel RX offloading supports VXLAN:%s GRE:%s",
			dv_attr.tunnel_offloads_caps &
			MLX5DV_RAW_PACKET_CAP_TUNNELED_OFFLOAD_VXLAN ?
			"yes" : "no",
			dv_attr.tunnel_offloads_caps &
			MLX5DV_RAW_PACKET_CAP_TUNNELED_OFFLOAD_GRE ?
			"yes" : "no");
	else
		DRV_LOG(DEBUG, "Tunnel RX offloading supports VXLAN:no GRE:no");
#else
	DRV_LOG(WARNING,
		"Tunnel RX offloading disabled"
		" due to OFED version lower than 4.3");
#endif
	if (!config.swp_force)
		config.swp = !!swp;
#ifdef HAVE_IBV_DEVICE_STRIDING_RQ_SUPPORT
	if (dv_attr.comp_mask & MLX5DV_CONTEXT_MASK_STRIDING_RQ) {
		struct mlx5dv_striding_rq_caps mprq_caps =
			dv_attr.striding_rq_caps;

		DRV_LOG(DEBUG, "\tmin_single_stride_log_num_of_bytes: %d",
			mprq_caps.min_single_stride_log_num_of_bytes);
		DRV_LOG(DEBUG, "\tmax_single_stride_log_num_of_bytes: %d",
			mprq_caps.max_single_stride_log_num_of_bytes);
		DRV_LOG(DEBUG, "\tmin_single_wqe_log_num_of_strides: %d",
			mprq_caps.min_single_wqe_log_num_of_strides);
		DRV_LOG(DEBUG, "\tmax_single_wqe_log_num_of_strides: %d",
			mprq_caps.max_single_wqe_log_num_of_strides);
		DRV_LOG(DEBUG, "\tsupported_qpts: %d",
			mprq_caps.supported_qpts);
		DRV_LOG(DEBUG, "device supports Multi-Packet RQ");
		mprq = 1;
		mprq_min_stride_size_n =
			mprq_caps.min_single_stride_log_num_of_bytes;
		mprq_max_stride_size_n =
			mprq_caps.max_single_stride_log_num_of_bytes;
		mprq_min_stride_num_n =
			mprq_caps.min_single_wqe_log_num_of_strides;
		mprq_max_stride_num_n =
			mprq_caps.max_single_wqe_log_num_of_strides;
		if (!config.mprq.stride_num_n)
			config.mprq.stride_num_n =
				RTE_MAX(MLX5_MPRQ_STRIDE_NUM_N,
					mprq_min_stride_num_n);
	}
#endif
	if (RTE_CACHE_LINE_SIZE == 128 &&
	    !(dv_attr.flags & MLX5DV_CONTEXT_FLAGS_CQE_128B_COMP))
		cqe_comp = 0;
	else
		cqe_comp = 1;
	if (config.cqe_comp)
		config.cqe_comp = cqe_comp;
	err = mlx5_devx_cmd_query_hca_attr(sh->ctx, &config.hca_attr);
	if (err) {
		DRV_LOG(ERR, "Could not retrieve raw HCA attributes");
		goto error;
	}
	DRV_LOG(DEBUG, "naming Ethernet device \"%s\"", name);
	if (rte_eth_dev_allocated(name)) {
		DRV_LOG(WARNING, "Skip registered device: %s", name);
		err = EBUSY;
		goto error;
	}
	/* Check port status. */
	err = mlx5_glue->query_port(sh->ctx, spawn->ibv_port, &port_attr);
	if (err) {
		DRV_LOG(ERR, "port query failed: %s", strerror(err));
		goto error;
	}
	if (port_attr.link_layer != IBV_LINK_LAYER_ETHERNET) {
		DRV_LOG(ERR, "port is not configured in Ethernet mode");
		err = EINVAL;
		goto error;
	}
	if (port_attr.state != IBV_PORT_ACTIVE)
		DRV_LOG(DEBUG, "port is not active: \"%s\" (%d)",
			mlx5_glue->port_state_str(port_attr.state),
			port_attr.state);
	/* Allocate private eth device data. */
	priv = rte_zmalloc("ethdev private structure",
			   sizeof(*priv),
			   RTE_CACHE_LINE_SIZE);
	if (priv == NULL) {
		DRV_LOG(ERR, "priv allocation failure");
		err = ENOMEM;
		goto error;
	}
	priv->sh = sh;
	priv->ibv_port = spawn->ibv_port;
	priv->mtu = ETHER_MTU;
#if defined HAVE_MLX5DV_DR_ESWITCH && defined HAVE_MLX5DV_DR
	if (!(config.dv_flow_en && config.hca_attr.eswitch_manager &&
	    (switch_info->representor || switch_info->master)))
		config.dv_eswitch_en = 0;
#else
	config.dv_eswitch_en = 0;
#endif
	DRV_LOG(INFO, "eswitch dr configuration is%ssupported",
		config.dv_eswitch_en ? " " : " not ");

	switch (spawn->pci_dev->id.device_id) {
	case PCI_DEVICE_ID_MELLANOX_CONNECTX4VF:
	case PCI_DEVICE_ID_MELLANOX_CONNECTX4LXVF:
	case PCI_DEVICE_ID_MELLANOX_CONNECTX5VF:
	case PCI_DEVICE_ID_MELLANOX_CONNECTX5EXVF:
		priv->vf = 1;
		break;
	default:
		priv->vf = 0;
		break;
	}
	DRV_LOG(INFO, "device is a %s", priv->vf ? "VF" : "PF");
#ifdef HAVE_MLX5DV_DR
	if (config.dv_flow_en) {
		err = mlx5_alloc_shared_dv(priv, &config);
		if (err)
			goto error;
		config.flow_metering = 1;
	}
#endif /* HAVE_MLX5DV_DR */
#ifndef RTE_ARCH_64
	/* Initialize UAR access locks for 32bit implementations. */
	rte_spinlock_init(&priv->uar_lock_cq);
	for (i = 0; i < MLX5_UAR_PAGE_NUM_MAX; i++)
		rte_spinlock_init(&priv->uar_lock[i]);
#endif
	/* Some internal functions rely on Netlink sockets, open them now. */
	priv->nl_socket_rdma = mlx5_nl_init(NETLINK_RDMA);
	priv->nl_socket_route =	mlx5_nl_init(NETLINK_ROUTE);
	priv->representor = !!switch_info->representor;
	priv->master = !!switch_info->master;
	priv->domain_id = RTE_ETH_DEV_SWITCH_DOMAIN_ID_INVALID;
	priv->representor_id =
		switch_info->representor ? switch_info->port_name : -1;
	/*
	 * Currently we support single E-Switch per PF configurations
	 * only and vport_id field contains the vport index for
	 * associated VF, which is deduced from representor port name.
	 * For exapmple, let's have the IB device port 10, it has
	 * attached network device eth0, which has port name attribute
	 * pf0vf2, we can deduce the VF number as 2, and set vport index
	 * as 3 (2+1). This assigning schema should be changed if the
	 * multiple E-Switch instances per PF configurations or/and PCI
	 * subfunctions are added.
	 */
	priv->vport_id = switch_info->representor ?
			 switch_info->port_name + 1 : -1;
	/*
	 * Look for sibling devices in order to reuse their switch domain
	 * if any, otherwise allocate one.
	 */
	i = mlx5_dev_to_port_id(dpdk_dev, NULL, 0);
	if (i > 0) {
		uint16_t port_id[i];

		i = RTE_MIN(mlx5_dev_to_port_id(dpdk_dev, port_id, i), i);
		while (i--) {
			const struct priv *opriv =
				rte_eth_devices[port_id[i]].data->dev_private;

			if (!opriv ||
			    opriv->domain_id ==
			    RTE_ETH_DEV_SWITCH_DOMAIN_ID_INVALID)
				continue;
			priv->domain_id = opriv->domain_id;
			break;
		}
	}
	if (priv->domain_id == RTE_ETH_DEV_SWITCH_DOMAIN_ID_INVALID) {
		err = rte_eth_switch_domain_alloc(&priv->domain_id);
		if (err) {
			err = rte_errno;
			DRV_LOG(ERR, "unable to allocate switch domain: %s",
				strerror(rte_errno));
			goto error;
		}
		own_domain_id = 1;
	}
#ifdef HAVE_IBV_DEVICE_TUNNEL_SUPPORT
	if (dv_attr.comp_mask & MLX5DV_CONTEXT_MASK_TUNNEL_OFFLOADS) {
		config.hw_vxlan_rx = !!(dv_attr.tunnel_offloads_caps &
			MLX5DV_RAW_PACKET_CAP_TUNNELED_OFFLOAD_VXLAN);
		config.hw_gre_rx = !!(dv_attr.tunnel_offloads_caps &
			MLX5DV_RAW_PACKET_CAP_TUNNELED_OFFLOAD_GRE);
		config.tunnel_en = (config.hw_gre_rx &&
				    config.hw_vxlan_rx);
	}
#endif
	if (err) {
		err = rte_errno;
		DRV_LOG(ERR, "failed to process device arguments: %s",
			strerror(rte_errno));
		goto error;
	}
	config.hw_csum = !!(sh->device_attr.device_cap_flags_ex &
			    IBV_DEVICE_RAW_IP_CSUM);
	DRV_LOG(DEBUG, "checksum offloading is %ssupported",
		(config.hw_csum ? "" : "not "));
#if defined(HAVE_IBV_DEVICE_COUNTERS_SET_V42)
	config.flow_counter_en = !!attr.max_counter_sets;
	ibv_describe_counter_set(ctx, 0, &cs_desc);
	DRV_LOG(DEBUG, "counter type = %d, num of cs = %ld, attributes = %d",
		cs_desc.counter_type, cs_desc.num_of_cs,
		cs_desc.attributes);
#elif defined(HAVE_IBV_DEVICE_COUNTERS_SET_V45)
	DRV_LOG(DEBUG, "MLNX_OFED 4.5+ flow counters support is assumed");
	config.flow_counter_en = 1;
#else
	DRV_LOG(DEBUG, "No flow counters support is compiled, "
			"MLNX_OFED 4.2 or higher is required");
#endif
#ifndef HAVE_IBV_FLOW_DV_SUPPORT
	if (config.dv_flow_en) {
		DRV_LOG(WARNING, "DV flow is not supported");
		config.dv_flow_en = 0;
	}
#endif
	config.ind_table_max_size =
		sh->device_attr.rss_caps.max_rwq_indirection_table_size;
	/*
	 * Remove this check once DPDK supports larger/variable
	 * indirection tables.
	 */
	if (config.ind_table_max_size > (unsigned int)ETH_RSS_RETA_SIZE_512)
		config.ind_table_max_size = ETH_RSS_RETA_SIZE_512;
	DRV_LOG(DEBUG, "maximum Rx indirection table size is %u",
		config.ind_table_max_size);
	config.hw_vlan_strip = !!(sh->device_attr.raw_packet_caps &
				  IBV_RAW_PACKET_CAP_CVLAN_STRIPPING);
	DRV_LOG(DEBUG, "VLAN stripping is %ssupported",
		(config.hw_vlan_strip ? "" : "not "));
	config.hw_fcs_strip = !!(sh->device_attr.raw_packet_caps &
				IBV_RAW_PACKET_CAP_SCATTER_FCS);
	DRV_LOG(DEBUG, "FCS stripping configuration is %ssupported",
		(config.hw_fcs_strip ? "" : "not "));
#ifdef HAVE_IBV_WQ_FLAG_RX_END_PADDING
	config.hw_padding = !!attr.rx_pad_end_addr_align;
#endif
	DRV_LOG(DEBUG, "hardware Rx end alignment padding is %ssupported",
		(config.hw_padding ? "" : "not "));
	config.tso = (sh->device_attr.tso_caps.max_tso > 0 &&
		      (sh->device_attr.tso_caps.supported_qpts &
		       (1 << IBV_QPT_RAW_PACKET)));
	if (config.tso)
		config.tso_max_payload_sz = sh->device_attr.tso_caps.max_tso;
	if (config.mps && !mps) {
		DRV_LOG(ERR,
			"multi-packet send not supported on this device"
			" (" MLX5_TXQ_MPW_EN ")");
		err = ENOTSUP;
		goto error;
	}
	DRV_LOG(INFO, "%sMPS is %s",
		config.mps == MLX5_MPW_ENHANCED ? "enhanced " : "",
		config.mps != MLX5_MPW_DISABLED ? "enabled" : "disabled");
	if (!config.cqe_comp)
		DRV_LOG(WARNING, "Rx CQE compression isn't supported");
	if (config.mprq.enabled && mprq) {
		if (config.mprq.stride_num_n > mprq_max_stride_num_n ||
		    config.mprq.stride_num_n < mprq_min_stride_num_n) {
			config.mprq.stride_num_n =
				RTE_MAX(MLX5_MPRQ_STRIDE_NUM_N,
					mprq_min_stride_num_n);
			DRV_LOG(WARNING,
				"the number of strides"
				" for Multi-Packet RQ is out of range,"
				" setting default value (%u)",
				1 << config.mprq.stride_num_n);
		}
		config.mprq.min_stride_size_n = mprq_min_stride_size_n;
		config.mprq.max_stride_size_n = mprq_max_stride_size_n;
	} else if (config.mprq.enabled && !mprq) {
		DRV_LOG(WARNING, "Multi-Packet RQ isn't supported");
		config.mprq.enabled = 0;
	}
	eth_dev = rte_eth_dev_allocate(name);
	if (eth_dev == NULL) {
		DRV_LOG(ERR, "can not allocate rte ethdev");
		err = ENOMEM;
		goto error;
	}
	if (priv->representor)
		eth_dev->data->dev_flags |= RTE_ETH_DEV_REPRESENTOR;
	eth_dev->data->dev_private = priv;
	priv->dev_data = eth_dev->data;
	eth_dev->data->mac_addrs = priv->mac;
	eth_dev->device = dpdk_dev;
	eth_dev->device->driver = &mlx5_driver.driver;
	err = mlx5_uar_init_primary(eth_dev);
	if (err) {
		err = rte_errno;
		goto error;
	}
	/* Configure the first MAC address by default. */
	if (mlx5_get_mac(eth_dev, &mac.addr_bytes)) {
		DRV_LOG(ERR,
			"port %u cannot get MAC address, is mlx5_en"
			" loaded? (errno: %s)",
			eth_dev->data->port_id, strerror(rte_errno));
		err = ENODEV;
		goto error;
	}
	DRV_LOG(INFO,
		"port %u MAC address is %02x:%02x:%02x:%02x:%02x:%02x",
		eth_dev->data->port_id,
		mac.addr_bytes[0], mac.addr_bytes[1],
		mac.addr_bytes[2], mac.addr_bytes[3],
		mac.addr_bytes[4], mac.addr_bytes[5]);
#ifndef NDEBUG
	{
		char ifname[IF_NAMESIZE];

		if (mlx5_get_ifname(eth_dev, &ifname) == 0)
			DRV_LOG(DEBUG, "port %u ifname is \"%s\"",
				eth_dev->data->port_id, ifname);
		else
			DRV_LOG(DEBUG, "port %u ifname is unknown",
				eth_dev->data->port_id);
	}
#endif
	/* Get actual MTU if possible. */
	err = mlx5_get_mtu(eth_dev, &priv->mtu);
	if (err) {
		err = rte_errno;
		goto error;
	}
	DRV_LOG(DEBUG, "port %u MTU is %u", eth_dev->data->port_id,
		priv->mtu);
	/* Initialize burst functions to prevent crashes before link-up. */
	eth_dev->rx_pkt_burst = removed_rx_burst;
	eth_dev->tx_pkt_burst = removed_tx_burst;
	eth_dev->dev_ops = &mlx5_dev_ops;
	/* Register MAC address. */
	claim_zero(mlx5_mac_addr_add(eth_dev, &mac, 0, 0));
	TAILQ_INIT(&priv->flows);
	TAILQ_INIT(&priv->ctrl_flows);
	TAILQ_INIT(&priv->flow_meter_profiles);
	TAILQ_INIT(&priv->flow_meters);
	/* Hint libmlx5 to use PMD allocator for data plane resources */
	struct mlx5dv_ctx_allocators alctr = {
		.alloc = &mlx5_alloc_verbs_buf,
		.free = &mlx5_free_verbs_buf,
		.data = priv,
	};
	mlx5_glue->dv_set_context_attr(sh->ctx,
				       MLX5DV_CTX_ATTR_BUF_ALLOCATORS,
				       (void *)((uintptr_t)&alctr));
	/* Bring Ethernet device up. */
	DRV_LOG(DEBUG, "port %u forcing Ethernet interface up",
		eth_dev->data->port_id);
	mlx5_set_link_up(eth_dev);
	/*
	 * Even though the interrupt handler is not installed yet,
	 * interrupts will still trigger on the asyn_fd from
	 * Verbs context returned by ibv_open_device().
	 */
	mlx5_link_update(eth_dev, 0);
	/* Store device configuration on private structure. */
	priv->config = config;
	/* Supported Verbs flow priority number detection. */
	err = mlx5_flow_discover_priorities(eth_dev);
	if (err < 0) {
		err = -err;
		goto error;
	}
	priv->config.flow_prio = err;
	return eth_dev;
error:
	if (priv) {
		if (priv->nl_socket_route >= 0)
			close(priv->nl_socket_route);
		if (priv->nl_socket_rdma >= 0)
			close(priv->nl_socket_rdma);
		if (own_domain_id)
			claim_zero(rte_eth_switch_domain_free(priv->domain_id));
		rte_free(priv);
		if (eth_dev != NULL)
			eth_dev->data->dev_private = NULL;
	}
	if (eth_dev != NULL) {
		/*
		 * mac_addrs must not be freed alone because
		 * part of dev_private.
		 */
		eth_dev->data->mac_addrs = NULL;
		rte_eth_dev_release_port(eth_dev);
	}
	if (sh)
		mlx5_free_shared_ibctx(sh);
	assert(err > 0);
	rte_errno = err;
	return NULL;
}

/**
 * Comparison callback to sort device data.
 *
 * This is meant to be used with qsort().
 *
 * @param a[in]
 *   Pointer to pointer to first data object.
 * @param b[in]
 *   Pointer to pointer to second data object.
 *
 * @return
 *   0 if both objects are equal, less than 0 if the first argument is less
 *   than the second, greater than 0 otherwise.
 */
static int
mlx5_dev_spawn_data_cmp(const void *a, const void *b)
{
	const struct mlx5_dev_spawn_data *si_a =
			(const struct mlx5_dev_spawn_data *)a;
	const struct mlx5_dev_spawn_data *si_b =
			(const struct mlx5_dev_spawn_data *)b;
	int ret;

	/* Master device first. */
	ret = si_b->info.master - si_a->info.master;
	if (ret)
		return ret;
	/* Then representor devices. */
	ret = si_b->info.representor - si_a->info.representor;
	if (ret)
		return ret;
	/* Unidentified devices come last in no specific order. */
	if (!si_a->info.representor)
		return 0;
	/* Order representors by name. */
	return si_a->info.port_name - si_b->info.port_name;
}

/**
 * DPDK callback to register a PCI device.
 *
 * This function spawns Ethernet devices out of a given PCI device.
 *
 * @param[in] pci_drv
 *   PCI driver structure (mlx5_driver).
 * @param[in] pci_dev
 *   PCI device information.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
mlx5_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
	       struct rte_pci_device *pci_dev)
{
	struct ibv_device **ibv_list;
	/*
	 * Number of found IB Devices matching with requested PCI BDF.
	 * nd != 1 means there are multiple IB devices over the same
	 * PCI device and we have representors and master.
	 */
	unsigned int nd = 0;
	/*
	 * Number of found IB device Ports. nd = 1 and np = 1..n means
	 * we have the single multiport IB device, and there may be
	 * representors attached to some of found ports.
	 */
	unsigned int np = 0;
	/*
	 * Number of DPDK ethernet devices to Spawn - either over
	 * multiple IB devices or multiple ports of single IB device.
	 * Actually this is the number of iterations to spawn.
	 */
	unsigned int ns = 0;
	int ret;

	assert(pci_drv == &mlx5_driver);
	errno = 0;
	ibv_list = mlx5_glue->get_device_list(&ret);
	if (!ibv_list) {
		rte_errno = errno ? errno : ENOSYS;
		DRV_LOG(ERR, "cannot list devices, is ib_uverbs loaded?");
		return -rte_errno;
	}
	/*
	 * First scan the list of all Infiniband devices to find
	 * matching ones, gathering into the list.
	 */
	struct ibv_device *ibv_match[ret + 1];
	int nl_route = -1;
	int nl_rdma = -1;
	unsigned int i;

	while (ret-- > 0) {
		struct rte_pci_addr pci_addr;

		DRV_LOG(DEBUG, "checking device \"%s\"", ibv_list[ret]->name);
		if (mlx5_ibv_device_to_pci_addr(ibv_list[ret], &pci_addr))
			continue;
		if (pci_dev->addr.domain != pci_addr.domain ||
		    pci_dev->addr.bus != pci_addr.bus ||
		    pci_dev->addr.devid != pci_addr.devid ||
		    pci_dev->addr.function != pci_addr.function)
			continue;
		DRV_LOG(INFO, "PCI information matches for device \"%s\"",
			ibv_list[ret]->name);
		ibv_match[nd++] = ibv_list[ret];
	}
	ibv_match[nd] = NULL;
	if (!nd) {
		/* No device macthes, just complain and bail out. */
		mlx5_glue->free_device_list(ibv_list);
		DRV_LOG(WARNING,
			"no Verbs device matches PCI device " PCI_PRI_FMT ","
			" are kernel drivers loaded?",
			pci_dev->addr.domain, pci_dev->addr.bus,
			pci_dev->addr.devid, pci_dev->addr.function);
		rte_errno = ENOENT;
		ret = -rte_errno;
		return ret;
	}
	nl_route = mlx5_nl_init(NETLINK_ROUTE);
	nl_rdma = mlx5_nl_init(NETLINK_RDMA);
	if (nd == 1) {
		/*
		 * Found single matching device may have multiple ports.
		 * Each port may be representor, we have to check the port
		 * number and check the representors existence.
		 */
		if (nl_rdma >= 0)
			np = mlx5_nl_portnum(nl_rdma, ibv_match[0]->name);
		if (!np)
			DRV_LOG(WARNING, "can not get IB device \"%s\""
					 " ports number", ibv_match[0]->name);
	}
	/*
	 * Now we can determine the maximal
	 * amount of devices to be spawned.
	 */
	struct mlx5_dev_spawn_data list[np ? np : nd];

	if (np > 1) {
		/*
		 * Signle IB device with multiple ports found,
		 * it may be E-Switch master device and representors.
		 * We have to perform identification trough the ports.
		 */
		assert(nl_rdma >= 0);
		assert(ns == 0);
		assert(nd == 1);
		for (i = 1; i <= np; ++i) {
			list[ns].max_port = np;
			list[ns].ibv_port = i;
			list[ns].ibv_dev = ibv_match[0];
			list[ns].eth_dev = NULL;
			list[ns].ifindex = mlx5_nl_ifindex
					(nl_rdma, list[ns].ibv_dev->name, i);
			if (!list[ns].ifindex) {
				/*
				 * No network interface index found for the
				 * specified port, it means there is no
				 * representor on this port. It's OK,
				 * there can be disabled ports, for example
				 * if sriov_numvfs < sriov_totalvfs.
				 */
				continue;
			}
			ret = -1;
			if (nl_route >= 0)
				ret = mlx5_nl_switch_info
					       (nl_route,
						list[ns].ifindex,
						&list[ns].info);
			if (ret || (!list[ns].info.representor &&
				    !list[ns].info.master)) {
				/*
				 * We failed to recognize representors with
				 * Netlink, let's try to perform the task
				 * with sysfs.
				 */
				ret =  mlx5_sysfs_switch_info
						(list[ns].ifindex,
						 &list[ns].info);
			}
			if (!ret && (list[ns].info.representor ^
				     list[ns].info.master))
				ns++;
		}
		if (!ns) {
			DRV_LOG(ERR,
				"unable to recognize master/representors"
				" on the IB device with multiple ports");
			rte_errno = ENOENT;
			ret = -rte_errno;
			goto exit;
		}
	} else {
		/*
		 * The existence of several matching entries (nd > 1) means
		 * port representors have been instantiated. No existing Verbs
		 * call nor sysfs entries can tell them apart, this can only
		 * be done through Netlink calls assuming kernel drivers are
		 * recent enough to support them.
		 *
		 * In the event of identification failure through Netlink,
		 * try again through sysfs, then:
		 *
		 * 1. A single IB device matches (nd == 1) with single
		 *    port (np=0/1) and is not a representor, assume
		 *    no switch support.
		 *
		 * 2. Otherwise no safe assumptions can be made;
		 *    complain louder and bail out.
		 */
		np = 1;
		for (i = 0; i != nd; ++i) {
			memset(&list[ns].info, 0, sizeof(list[ns].info));
			list[ns].max_port = 1;
			list[ns].ibv_port = 1;
			list[ns].ibv_dev = ibv_match[i];
			list[ns].eth_dev = NULL;
			list[ns].ifindex = 0;
			if (nl_rdma >= 0)
				list[ns].ifindex = mlx5_nl_ifindex
					(nl_rdma, list[ns].ibv_dev->name, 1);
			if (!list[ns].ifindex) {
				char ifname[IF_NAMESIZE];

				/*
				 * Netlink failed, it may happen with old
				 * ib_core kernel driver (before 4.16).
				 * We can assume there is old driver because
				 * here we are processing single ports IB
				 * devices. Let's try sysfs to retrieve
				 * the ifindex. The method works for
				 * master device only.
				 */
				if (nd > 1) {
					/*
					 * Multiple devices found, assume
					 * representors, can not distinguish
					 * master/representor and retrieve
					 * ifindex via sysfs.
					 */
					continue;
				}
				ret = mlx5_get_master_ifname
					(ibv_match[i]->ibdev_path, &ifname);
				if (!ret)
					list[ns].ifindex =
						if_nametoindex(ifname);
				if (!list[ns].ifindex) {
					/*
					 * No network interface index found
					 * for the specified device, it means
					 * there it is neither representor
					 * nor master.
					 */
					continue;
				}
			}
			ret = -1;
			if (nl_route >= 0)
				ret = mlx5_nl_switch_info
					       (nl_route,
						list[ns].ifindex,
						&list[ns].info);
			if (ret || (!list[ns].info.representor &&
				    !list[ns].info.master)) {
				/*
				 * We failed to recognize representors with
				 * Netlink, let's try to perform the task
				 * with sysfs.
				 */
				ret =  mlx5_sysfs_switch_info
						(list[ns].ifindex,
						 &list[ns].info);
			}
			if (!ret && (list[ns].info.representor ^
				     list[ns].info.master)) {
				ns++;
			} else if ((nd == 1) &&
				   !list[ns].info.representor &&
				   !list[ns].info.master) {
				/*
				 * Single IB device with
				 * one physical port and
				 * attached network device.
				 * May be SRIOV is not enabled
				 * or there is no representors.
				 */
				DRV_LOG(INFO, "no E-Switch support detected");
				ns++;
				break;
			}
		}
		if (!ns) {
			DRV_LOG(ERR,
				"unable to recognize master/representors"
				" on the multiple IB devices");
			rte_errno = ENOENT;
			ret = -rte_errno;
			goto exit;
		}
	}
	assert(ns);
	/*
	 * Sort list to probe devices in natural order for users convenience
	 * (i.e. master first, then representors from lowest to highest ID).
	 */
	qsort(list, ns, sizeof(*list), mlx5_dev_spawn_data_cmp);
	for (i = 0; i != ns; ++i) {
		uint32_t restore;

		list[i].pci_dev = pci_dev;
		list[i].eth_dev = mlx5_dev_spawn(&pci_dev->device, &list[i]);
		if (!list[i].eth_dev) {
			if (rte_errno != EBUSY && rte_errno != EEXIST)
				break;
			/* Device is disabled, ignore it. */
			continue;
		}
		restore = list[i].eth_dev->data->dev_flags;
		rte_eth_copy_pci_info(list[i].eth_dev, pci_dev);
		/* Restore non-PCI flags cleared by the above call. */
		list[i].eth_dev->data->dev_flags |= restore;
	}
	if (i != ns) {
		DRV_LOG(ERR,
			"probe of PCI device " PCI_PRI_FMT " aborted after"
			" encountering an error: %s",
			pci_dev->addr.domain, pci_dev->addr.bus,
			pci_dev->addr.devid, pci_dev->addr.function,
			strerror(rte_errno));
		ret = -rte_errno;
		/* Roll back. */
		while (i--) {
			if (!list[i].eth_dev)
				continue;
			mlx5_dev_close(list[i].eth_dev);
			if (rte_eal_process_type() == RTE_PROC_PRIMARY)
				rte_free(list[i].eth_dev->data->dev_private);
			claim_zero(rte_eth_dev_release_port(list[i].eth_dev));
		}
		/* Restore original error. */
		rte_errno = -ret;
	} else {
		ret = 0;
	}
exit:
	/*
	 * Do the routine cleanup:
	 * - close opened Netlink sockets
	 * - free the Infiniband device list
	 */
	if (nl_rdma >= 0)
		close(nl_rdma);
	if (nl_route >= 0)
		close(nl_route);
	assert(ibv_list);
	mlx5_glue->free_device_list(ibv_list);
	return ret;
}

static const struct rte_pci_id mlx5_pci_id_map[] = {
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX4)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX4VF)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX4LX)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX4LXVF)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX5)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX5VF)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX5EX)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX5EXVF)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX5BF)
	},
	{
		.vendor_id = 0
	}
};

static struct rte_pci_driver mlx5_driver = {
	.driver = {
		.name = MLX5_DRIVER_NAME
	},
	.id_table = mlx5_pci_id_map,
	.probe = mlx5_pci_probe,
	.drv_flags = RTE_PCI_DRV_INTR_LSC | RTE_PCI_DRV_INTR_RMV,
};

#ifdef RTE_LIBRTE_MLX5_DLOPEN_DEPS

/**
 * Suffix RTE_EAL_PMD_PATH with "-glue".
 *
 * This function performs a sanity check on RTE_EAL_PMD_PATH before
 * suffixing its last component.
 *
 * @param buf[out]
 *   Output buffer, should be large enough otherwise NULL is returned.
 * @param size
 *   Size of @p out.
 *
 * @return
 *   Pointer to @p buf or @p NULL in case suffix cannot be appended.
 */
static char *
mlx5_glue_path(char *buf, size_t size)
{
	static const char *const bad[] = { "/", ".", "..", NULL };
	const char *path = RTE_EAL_PMD_PATH;
	size_t len = strlen(path);
	size_t off;
	int i;

	while (len && path[len - 1] == '/')
		--len;
	for (off = len; off && path[off - 1] != '/'; --off)
		;
	for (i = 0; bad[i]; ++i)
		if (!strncmp(path + off, bad[i], (int)(len - off)))
			goto error;
	i = snprintf(buf, size, "%.*s-glue", (int)len, path);
	if (i == -1 || (size_t)i >= size)
		goto error;
	return buf;
error:
	DRV_LOG(ERR,
		"unable to append \"-glue\" to last component of"
		" RTE_EAL_PMD_PATH (\"" RTE_EAL_PMD_PATH "\"),"
		" please re-configure DPDK");
	return NULL;
}

/**
 * Initialization routine for run-time dependency on rdma-core.
 */
static int
mlx5_glue_init(void)
{
	char glue_path[sizeof(RTE_EAL_PMD_PATH) - 1 + sizeof("-glue")];
	const char *path[] = {
		/*
		 * A basic security check is necessary before trusting
		 * MLX5_GLUE_PATH, which may override RTE_EAL_PMD_PATH.
		 */
		(geteuid() == getuid() && getegid() == getgid() ?
		 getenv("MLX5_GLUE_PATH") : NULL),
		/*
		 * When RTE_EAL_PMD_PATH is set, use its glue-suffixed
		 * variant, otherwise let dlopen() look up libraries on its
		 * own.
		 */
		(*RTE_EAL_PMD_PATH ?
		 mlx5_glue_path(glue_path, sizeof(glue_path)) : ""),
	};
	unsigned int i = 0;
	void *handle = NULL;
	void **sym;
	const char *dlmsg;

	while (!handle && i != RTE_DIM(path)) {
		const char *end;
		size_t len;
		int ret;

		if (!path[i]) {
			++i;
			continue;
		}
		end = strpbrk(path[i], ":;");
		if (!end)
			end = path[i] + strlen(path[i]);
		len = end - path[i];
		ret = 0;
		do {
			char name[ret + 1];

			ret = snprintf(name, sizeof(name), "%.*s%s" MLX5_GLUE,
				       (int)len, path[i],
				       (!len || *(end - 1) == '/') ? "" : "/");
			if (ret == -1)
				break;
			if (sizeof(name) != (size_t)ret + 1)
				continue;
			DRV_LOG(DEBUG, "looking for rdma-core glue as \"%s\"",
				name);
			handle = dlopen(name, RTLD_LAZY);
			break;
		} while (1);
		path[i] = end + 1;
		if (!*end)
			++i;
	}
	if (!handle) {
		rte_errno = EINVAL;
		dlmsg = dlerror();
		if (dlmsg)
			DRV_LOG(WARNING, "cannot load glue library: %s", dlmsg);
		goto glue_error;
	}
	sym = dlsym(handle, "mlx5_glue");
	if (!sym || !*sym) {
		rte_errno = EINVAL;
		dlmsg = dlerror();
		if (dlmsg)
			DRV_LOG(ERR, "cannot resolve glue symbol: %s", dlmsg);
		goto glue_error;
	}
	mlx5_glue = *sym;
	return 0;
glue_error:
	if (handle)
		dlclose(handle);
	DRV_LOG(WARNING,
		"cannot initialize PMD due to missing run-time dependency on"
		" rdma-core libraries (libibverbs, libmlx5)");
	return -rte_errno;
}

#endif

/**
 * Driver initialization routine.
 */
RTE_INIT(rte_mlx5_pmd_init);
static void
rte_mlx5_pmd_init(void)
{
	/* Build the static tables for verbs conversion. */
	mlx5_set_ptype_table();
	mlx5_set_cksum_table();
	mlx5_set_swp_types_table();
	/*
	 * RDMAV_HUGEPAGES_SAFE tells ibv_fork_init() we intend to use
	 * huge pages. Calling ibv_fork_init() during init allows
	 * applications to use fork() safely for purposes other than
	 * using this PMD, which is not supported in forked processes.
	 */
	setenv("RDMAV_HUGEPAGES_SAFE", "1", 1);
	/* Match the size of Rx completion entry to the size of a cacheline. */
	if (RTE_CACHE_LINE_SIZE == 128)
		setenv("MLX5_CQE_SIZE", "128", 0);
	/*
	 * MLX5_DEVICE_FATAL_CLEANUP tells ibv_destroy functions to
	 * cleanup all the Verbs resources even when the device was removed.
	 */
	setenv("MLX5_DEVICE_FATAL_CLEANUP", "1", 1);
#ifdef RTE_LIBRTE_MLX5_DLOPEN_DEPS
	if (mlx5_glue_init())
		return;
	assert(mlx5_glue);
#endif
#ifndef NDEBUG
	/* Glue structure must not contain any NULL pointers. */
	{
		unsigned int i;

		for (i = 0; i != sizeof(*mlx5_glue) / sizeof(void *); ++i)
			assert(((const void *const *)mlx5_glue)[i]);
	}
#endif
	if (strcmp(mlx5_glue->version, MLX5_GLUE_VERSION)) {
		DRV_LOG(ERR,
			"rdma-core glue \"%s\" mismatch: \"%s\" is required",
			mlx5_glue->version, MLX5_GLUE_VERSION);
		return;
	}
	mlx5_glue->fork_init();
	rte_pci_register(&mlx5_driver);
}

RTE_PMD_EXPORT_NAME(net_mlx5, __COUNTER__);
RTE_PMD_REGISTER_PCI_TABLE(net_mlx5, mlx5_pci_id_map);
RTE_PMD_REGISTER_KMOD_DEP(net_mlx5, "* ib_uverbs & mlx5_core & mlx5_ib");
