/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Intel Corporation
 */

#ifndef _RTE_ETHDEV_DRIVER_H_
#define _RTE_ETHDEV_DRIVER_H_

/**
 * @file
 *
 * RTE Ethernet Device PMD API
 *
 * These APIs for the use from Ethernet drivers, user applications shouldn't
 * use them.
 *
 */

#include <rte_ethdev.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Allocate an unique switch domain identifier.
 *
 * A pool of switch domain identifiers which can be allocated on request. This
 * will enabled devices which support the concept of switch domains to request
 * a switch domain id which is guaranteed to be unique from other devices
 * running in the same process.
 *
 * @param domain_id
 *  switch domain identifier parameter to pass back to application
 *
 * @return
 *   Negative errno value on error, 0 on success.
 */
int rte_eth_switch_domain_alloc(uint16_t *domain_id);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Free switch domain.
 *
 * Return a switch domain identifier to the pool of free identifiers after it is
 * no longer in use by device.
 *
 * @param domain_id
 *  switch domain identifier to free
 *
 * @return
 *   Negative errno value on error, 0 on success.
 */
int rte_eth_switch_domain_free(uint16_t domain_id);

#endif /* _RTE_ETHDEV_DRIVER_H_ */
