#   BSD LICENSE
#
#   Copyright(c) 2010-2017 Intel Corporation. All rights reserved.
#   All rights reserved.
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
#     * Neither the name of Intel Corporation nor the names of its
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

#
# library name
#
LIB = librte_ethdev.a

CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS)
LDLIBS += -lrte_net -lrte_eal -lrte_mempool -lrte_ring
LDLIBS += -lrte_mbuf

EXPORT_MAP := rte_ethdev_version.map

LIBABIVER := 8

SRCS-y += rte_ethdev.c
SRCS-y += rte_flow.c
SRCS-y += rte_tm.c
SRCS-y += rte_mtr.c
SRCS-y += ethdev_profile.c

#
# Export include files
#
SYMLINK-y-include += rte_ethdev.h
SYMLINK-y-include += rte_ethdev_driver.h
SYMLINK-y-include += rte_ethdev_pci.h
SYMLINK-y-include += rte_ethdev_vdev.h
SYMLINK-y-include += rte_eth_ctrl.h
SYMLINK-y-include += rte_dev_info.h
SYMLINK-y-include += rte_flow.h
SYMLINK-y-include += rte_flow_driver.h
SYMLINK-y-include += rte_tm.h
SYMLINK-y-include += rte_tm_driver.h
SYMLINK-y-include += rte_mtr.h
SYMLINK-y-include += rte_mtr_driver.h

include $(RTE_SDK)/mk/rte.lib.mk
