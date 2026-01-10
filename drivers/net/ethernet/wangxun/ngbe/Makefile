################################################################################
#
# WangXun GbE PCI Express Linux Network Driver
# Copyright(c) 2015 - 2017 Beijing WangXun Technology Co., Ltd.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU General Public License,
# version 2, as published by the Free Software Foundation.
#
# This program is distributed in the hope it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# The full GNU General Public License is included in this distribution in
# the file called "COPYING".
#
################################################################################
#
# Makefile for the WangXun(R) GbE PCI Express ethernet driver
#
CONFIG_NGBE=m
obj-$(CONFIG_NGBE) += ngbe.o

define ngbe-y
	ngbe_main.o
	ngbe_ethtool.o
	ngbe_lib.o
	ngbe_mbx.o
	ngbe_sriov.o
	ngbe_param.o
	ngbe_phy.o
	ngbe_procfs.o
	ngbe_hw.o
	ngbe_pcierr.o
	ngbe_xsk.o
endef
ngbe-y := $(strip ${ngbe-y})

ngbe-${CONFIG_DEBUG_FS} += ngbe_debugfs.o

ngbe-$(CONFIG_PTP_1588_CLOCK:m=y) += ngbe_ptp.o

ngbe-${CONFIG_SYSFS} += ngbe_sysfs.o

ngbe-y += kcompat.o
