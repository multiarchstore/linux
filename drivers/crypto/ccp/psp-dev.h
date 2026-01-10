/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * AMD Platform Security Processor (PSP) interface driver
 *
 * Copyright (C) 2017-2019 Advanced Micro Devices, Inc.
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 */

#ifndef __PSP_DEV_H__
#define __PSP_DEV_H__

#include <linux/device.h>
#include <linux/list.h>
#include <linux/bits.h>
#include <linux/interrupt.h>
#include <linux/miscdevice.h>

#include "sp-dev.h"

#define PSP_RBCTL_X86_WRITES		BIT(31)
#define PSP_RBCTL_RBMODE_ACT		BIT(30)
#define PSP_RBCTL_CLR_INTSTAT		BIT(29)
#define PSP_RBTAIL_QHI_TAIL_SHIFT	16
#define PSP_RBTAIL_QHI_TAIL_MASK	0x7FF0000
#define PSP_RBTAIL_QLO_TAIL_MASK	0x7FF

#define PSP_RBHEAD_QHI_HEAD_SHIFT	16
#define PSP_RBHEAD_QHI_HEAD_MASK	0x7FF0000
#define PSP_RBHEAD_QLO_HEAD_MASK	0x7FF

#define PSP_RBHEAD_QPAUSE_INT_STAT	BIT(30)

#define MAX_PSP_NAME_LEN		16

#ifdef CONFIG_HYGON_PSP2CPU_CMD
#define PSP_X86_CMD			BIT(2)
#define P2C_NOTIFIERS_MAX		16
#endif

extern struct psp_device *psp_master;

typedef void (*psp_irq_handler_t)(int, void *, unsigned int);

struct psp_device {
	struct list_head entry;

	struct psp_vdata *vdata;
	char name[MAX_PSP_NAME_LEN];

	struct device *dev;
	struct sp_device *sp;

	void __iomem *io_regs;

	psp_irq_handler_t sev_irq_handler;
	void *sev_irq_data;

	void *sev_data;
	void *tee_data;
	void *platform_access_data;
	void *dbc_data;

	unsigned int capability;
};

#define PSP_MUTEX_TIMEOUT 600000
struct psp_mutex {
	uint64_t locked;
};

struct psp_dev_data {
	struct psp_mutex mb_mutex;
};

struct psp_misc_dev {
	struct kref refcount;
	struct psp_dev_data *data_pg_aligned;
	struct miscdevice misc;
};

void psp_set_sev_irq_handler(struct psp_device *psp, psp_irq_handler_t handler,
			     void *data);
void psp_clear_sev_irq_handler(struct psp_device *psp);

struct psp_device *psp_get_master_device(void);

#define PSP_CAPABILITY_SEV			BIT(0)
#define PSP_CAPABILITY_TEE			BIT(1)
#define PSP_CAPABILITY_PSP_SECURITY_REPORTING	BIT(7)

#define PSP_CAPABILITY_PSP_SECURITY_OFFSET	8
/*
 * The PSP doesn't directly store these bits in the capability register
 * but instead copies them from the results of query command.
 *
 * The offsets from the query command are below, and shifted when used.
 */
#define PSP_SECURITY_FUSED_PART			BIT(0)
#define PSP_SECURITY_DEBUG_LOCK_ON		BIT(2)
#define PSP_SECURITY_TSME_STATUS		BIT(5)
#define PSP_SECURITY_ANTI_ROLLBACK_STATUS	BIT(7)
#define PSP_SECURITY_RPMC_PRODUCTION_ENABLED	BIT(8)
#define PSP_SECURITY_RPMC_SPIROM_AVAILABLE	BIT(9)
#define PSP_SECURITY_HSP_TPM_AVAILABLE		BIT(10)
#define PSP_SECURITY_ROM_ARMOR_ENFORCED		BIT(11)

#endif /* __PSP_DEV_H */
