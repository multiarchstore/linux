/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * HYGON Platform Security Processor (PSP) interface driver
 *
 * Copyright (C) 2016-2023 Hygon Info Technologies Ltd.
 *
 * Author: Baoshun Fang <baoshunfang@hygon.cn>
 */

#ifndef __PSP_RINGBUF_H__
#define __PSP_RINGBUF_H__

#include <linux/device.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/dmapool.h>
#include <linux/hw_random.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/irqreturn.h>
#include <linux/dmaengine.h>
#include <linux/psp-sev.h>
#include <linux/miscdevice.h>
#include <linux/capability.h>

int csv_queue_init(struct csv_queue *queue,
		   void *buffer, unsigned int size, size_t esize);
unsigned int csv_enqueue_cmd(struct csv_queue *queue,
			     const void *buf, unsigned int len);
unsigned int csv_dequeue_stat(struct csv_queue *queue,
			      void *buf, unsigned int len);

unsigned int csv_dequeue_cmd(struct csv_queue *ring_buf,
			     void *buf, unsigned int len);

unsigned int csv_cmd_queue_size(struct csv_queue *ring_buf);
#endif /* __PSP_RINGBUF_H__ */
