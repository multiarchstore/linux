/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * HYGON Platform Security Processor (PSP) interface driver
 *
 * Copyright (C) 2024 Hygon Info Technologies Ltd.
 *
 * Author: Liyang Han <hanliyang@hygon.cn>
 */

#ifndef __CSV_DEV_H__
#define __CSV_DEV_H__

#include <asm/csv.h>

/* Hooks table: a table of function pointers filled in when psp init */
extern struct csv_hooks_table {
	int (*sev_do_cmd)(int cmd, void *data, int *psp_ret);
} csv_hooks;

#ifdef CONFIG_HYGON_CSV

int csv_platform_cmd_set_secure_memory_region(struct sev_device *sev, int *error);

#else	/* !CONFIG_HYGON_CSV */

static inline int
csv_platform_cmd_set_secure_memory_region(struct sev_device *sev, int *error) { return 0; }

#endif	/* CONFIG_HYGON_CSV */

#endif	/* __CSV_DEV_H__ */
