// SPDX-License-Identifier: GPL-2.0-only
/*
 * HYGON Platform Security Processor (PSP) interface
 *
 * Copyright (C) 2024 Hygon Info Technologies Ltd.
 *
 * Author: Liyang Han <hanliyang@hygon.cn>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/slab.h>
#include <linux/psp.h>
#include <linux/psp-sev.h>
#include <linux/psp-csv.h>
#include "sev-dev.h"
#include "csv-dev.h"

/* Function pointers for hooks */
struct csv_hooks_table csv_hooks;

#ifdef CONFIG_HYGON_CSV

int csv_platform_cmd_set_secure_memory_region(struct sev_device *sev, int *error)
{
	int ret = 0;
	unsigned int i = 0;
	struct csv3_data_set_smr *cmd_set_smr;
	struct csv3_data_set_smcr *cmd_set_smcr;
	struct csv3_data_memory_region *smr_regions;

	if (!csv_smr || !csv_smr_num)
		return -EINVAL;

	cmd_set_smr = kzalloc(sizeof(*cmd_set_smr), GFP_KERNEL);
	if (!cmd_set_smr)
		return -ENOMEM;

	smr_regions = kcalloc(csv_smr_num, sizeof(*smr_regions),  GFP_KERNEL);
	if (!smr_regions) {
		ret = -ENOMEM;
		goto e_free_cmd_set_smr;
	}

	for (i = 0; i < csv_smr_num; i++) {
		smr_regions[i].base_address = csv_smr[i].start;
		smr_regions[i].size = csv_smr[i].size;
	}
	cmd_set_smr->smr_entry_size = 1 << csv_get_smr_entry_shift();
	cmd_set_smr->regions_paddr = __psp_pa(smr_regions);
	cmd_set_smr->nregions = csv_smr_num;
	ret = csv_hooks.sev_do_cmd(CSV3_CMD_SET_SMR, cmd_set_smr, error);
	if (ret) {
		pr_err("Fail to set SMR, ret %#x, error %#x\n", ret, *error);
		goto e_free_smr_area;
	}

	cmd_set_smcr = kzalloc(sizeof(*cmd_set_smcr), GFP_KERNEL);
	if (!cmd_set_smcr) {
		ret = -ENOMEM;
		goto e_free_smr_area;
	}

	cmd_set_smcr->base_address = csv_alloc_from_contiguous(1UL << CSV_MR_ALIGN_BITS,
						&node_online_map,
						get_order(1 << CSV_MR_ALIGN_BITS));
	if (!cmd_set_smcr->base_address) {
		pr_err("Fail to alloc SMCR memory\n");
		ret = -ENOMEM;
		goto e_free_cmd_set_smcr;
	}

	cmd_set_smcr->size = 1UL << CSV_MR_ALIGN_BITS;
	ret = csv_hooks.sev_do_cmd(CSV3_CMD_SET_SMCR, cmd_set_smcr, error);
	if (ret) {
		if (*error == SEV_RET_INVALID_COMMAND)
			ret = 0;
		else
			pr_err("set smcr ret %#x, error %#x\n", ret, *error);

		csv_release_to_contiguous(cmd_set_smcr->base_address,
					1UL << CSV_MR_ALIGN_BITS);
	}

e_free_cmd_set_smcr:
	kfree((void *)cmd_set_smcr);
e_free_smr_area:
	kfree((void *)smr_regions);
e_free_cmd_set_smr:
	kfree((void *)cmd_set_smr);

	if (ret)
		dev_warn(sev->dev,
			 "CSV3: fail to set secure memory region, CSV3 support unavailable\n");

	return ret;
}

#endif	/* CONFIG_HYGON_CSV */
