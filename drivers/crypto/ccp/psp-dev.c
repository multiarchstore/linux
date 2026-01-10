// SPDX-License-Identifier: GPL-2.0-only
/*
 * AMD Platform Security Processor (PSP) interface
 *
 * Copyright (C) 2016,2019 Advanced Micro Devices, Inc.
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 */

#include <linux/kernel.h>
#include <linux/irqreturn.h>
#include <linux/delay.h>
#include <linux/pci.h>
#include <linux/sort.h>
#include <linux/bsearch.h>
#include <linux/rwlock.h>

#include "sp-dev.h"
#include "psp-dev.h"
#include "sev-dev.h"
#include "tee-dev.h"
#include "platform-access.h"
#include "dbc.h"
#ifdef CONFIG_TDM_DEV_HYGON
#include "tdm-dev.h"
#endif

struct psp_device *psp_master;

struct psp_misc_dev *psp_misc;
int is_hygon_psp;
#define HYGON_PSP_IOC_TYPE 'H'
enum HYGON_PSP_OPCODE {
	HYGON_PSP_MUTEX_ENABLE = 1,
	HYGON_PSP_MUTEX_DISABLE,
	HYGON_VPSP_CTRL_OPT,
	HYGON_PSP_OPCODE_MAX_NR,
};

enum VPSP_DEV_CTRL_OPCODE {
	VPSP_OP_VID_ADD,
	VPSP_OP_VID_DEL,
	VPSP_OP_SET_DEFAULT_VID_PERMISSION,
	VPSP_OP_GET_DEFAULT_VID_PERMISSION,
};

struct vpsp_dev_ctrl {
	unsigned char op;
	union {
		unsigned int vid;
		// Set or check the permissions for the default VID
		unsigned int def_vid_perm;
		unsigned char reserved[128];
	} data;
};

int psp_mutex_enabled;
extern struct mutex sev_cmd_mutex;

uint64_t atomic64_exchange(uint64_t *dst, uint64_t val)
{
	return xchg(dst, val);
}

int psp_mutex_init(struct psp_mutex *mutex)
{
	if (!mutex)
		return -1;
	mutex->locked = 0;
	return 0;
}

int psp_mutex_trylock(struct psp_mutex *mutex)
{
	if (atomic64_exchange(&mutex->locked, 1))
		return 0;
	else
		return 1;
}

int psp_mutex_lock_timeout(struct psp_mutex *mutex, uint64_t ms)
{
	int ret = 0;
	unsigned long je;

	je = jiffies + msecs_to_jiffies(ms);
	do {
		if (psp_mutex_trylock(mutex)) {
			ret = 1;
			break;
		}
	} while ((ms == 0) || time_before(jiffies, je));

	return ret;
}

int psp_mutex_unlock(struct psp_mutex *mutex)
{
	if (!mutex)
		return -1;

	atomic64_exchange(&mutex->locked, 0);
	return 0;
}

static struct psp_device *psp_alloc_struct(struct sp_device *sp)
{
	struct device *dev = sp->dev;
	struct psp_device *psp;

	psp = devm_kzalloc(dev, sizeof(*psp), GFP_KERNEL);
	if (!psp)
		return NULL;

	psp->dev = dev;
	psp->sp = sp;

	snprintf(psp->name, sizeof(psp->name), "psp-%u", sp->ord);

	return psp;
}

static irqreturn_t psp_irq_handler(int irq, void *data)
{
	struct psp_device *psp = data;
	unsigned int status;

	/* Read the interrupt status: */
	status = ioread32(psp->io_regs + psp->vdata->intsts_reg);

	/* Clear the interrupt status by writing the same value we read. */
	iowrite32(status, psp->io_regs + psp->vdata->intsts_reg);

	/* invoke subdevice interrupt handlers */
	if (status) {
		if (psp->sev_irq_handler)
			psp->sev_irq_handler(irq, psp->sev_irq_data, status);
	}

	return IRQ_HANDLED;
}

#ifdef CONFIG_HYGON_PSP2CPU_CMD
static DEFINE_SPINLOCK(p2c_notifier_lock);
static p2c_notifier_t p2c_notifiers[P2C_NOTIFIERS_MAX] = {NULL};
int psp_register_cmd_notifier(uint32_t cmd_id, int (*notifier)(uint32_t id, uint64_t data))
{
	int ret = -ENODEV;
	unsigned long flags;

	spin_lock_irqsave(&p2c_notifier_lock, flags);
	if (cmd_id < P2C_NOTIFIERS_MAX && !p2c_notifiers[cmd_id]) {
		p2c_notifiers[cmd_id] = notifier;
		ret = 0;
	}
	spin_unlock_irqrestore(&p2c_notifier_lock, flags);

	return ret;
}
EXPORT_SYMBOL_GPL(psp_register_cmd_notifier);

int psp_unregister_cmd_notifier(uint32_t cmd_id, int (*notifier)(uint32_t id, uint64_t data))
{
	int ret = -ENODEV;
	unsigned long flags;

	spin_lock_irqsave(&p2c_notifier_lock, flags);
	if (cmd_id < P2C_NOTIFIERS_MAX && p2c_notifiers[cmd_id] == notifier) {
		p2c_notifiers[cmd_id] = NULL;
		ret = 0;
	}
	spin_unlock_irqrestore(&p2c_notifier_lock, flags);

	return ret;
}
EXPORT_SYMBOL_GPL(psp_unregister_cmd_notifier);

#define PSP2CPU_MAX_LOOP		100
static irqreturn_t psp_irq_handler_hygon(int irq, void *data)
{
	struct psp_device *psp = data;
	struct sev_device *sev = psp->sev_irq_data;
	unsigned int status;
	int reg;
	unsigned long flags;
	int count = 0;
	uint32_t p2c_cmd;
	uint32_t p2c_lo_data;
	uint32_t p2c_hi_data;
	uint64_t p2c_data;

	/* Read the interrupt status: */
	status = ioread32(psp->io_regs + psp->vdata->intsts_reg);

	while (status && (count++ < PSP2CPU_MAX_LOOP)) {
		/* Clear the interrupt status by writing the same value we read. */
		iowrite32(status, psp->io_regs + psp->vdata->intsts_reg);

		/* Check if it is command completion: */
		if (status & SEV_CMD_COMPLETE) {
			/* Check if it is SEV command completion: */
			reg = ioread32(psp->io_regs + psp->vdata->sev->cmdresp_reg);
			if (reg & PSP_CMDRESP_RESP) {
				sev->int_rcvd = 1;
				wake_up(&sev->int_queue);
			}
		}

		if (status & PSP_X86_CMD) {
			/* Check if it is P2C command completion: */
			reg = ioread32(psp->io_regs + psp->vdata->p2c_cmdresp_reg);
			if (!(reg & PSP_CMDRESP_RESP)) {
				p2c_lo_data = ioread32(psp->io_regs +
						     psp->vdata->p2c_cmdbuff_addr_lo_reg);
				p2c_hi_data = ioread32(psp->io_regs +
						     psp->vdata->p2c_cmdbuff_addr_hi_reg);
				p2c_data = (((uint64_t)(p2c_hi_data) << 32) +
						     ((uint64_t)(p2c_lo_data)));
				p2c_cmd = (uint32_t)(reg & SEV_CMDRESP_IOC);
				if (p2c_cmd < P2C_NOTIFIERS_MAX) {
					spin_lock_irqsave(&p2c_notifier_lock, flags);
					if (p2c_notifiers[p2c_cmd])
						p2c_notifiers[p2c_cmd](p2c_cmd, p2c_data);

					spin_unlock_irqrestore(&p2c_notifier_lock, flags);
				}

				reg |= PSP_CMDRESP_RESP;
				iowrite32(reg, psp->io_regs + psp->vdata->p2c_cmdresp_reg);
			}
		}
		status = ioread32(psp->io_regs + psp->vdata->intsts_reg);
	}

	return IRQ_HANDLED;
}
#endif

static int hygon_fixup_psp_caps(struct psp_device *psp)
{
	/* the hygon psp is unavailable if bit0 cleared in feature reg */
	if (!(psp->capability & PSP_CAPABILITY_SEV))
		return -ENODEV;

	psp->capability &= ~(PSP_CAPABILITY_TEE |
			     PSP_CAPABILITY_PSP_SECURITY_REPORTING);
	return 0;
}

static unsigned int psp_get_capability(struct psp_device *psp)
{
	unsigned int val = ioread32(psp->io_regs + psp->vdata->feature_reg);

	/*
	 * Check for a access to the registers.  If this read returns
	 * 0xffffffff, it's likely that the system is running a broken
	 * BIOS which disallows access to the device. Stop here and
	 * fail the PSP initialization (but not the load, as the CCP
	 * could get properly initialized).
	 */
	if (val == 0xffffffff) {
		dev_notice(psp->dev, "psp: unable to access the device: you might be running a broken BIOS.\n");
		return -ENODEV;
	}
	psp->capability = val;

	/*
	 * Fix capability of Hygon psp, the meaning of Hygon psp feature
	 * register is not exactly the same as AMD.
	 * Return -ENODEV directly if hygon psp not configured with CSV
	 * capability.
	 */
	if (boot_cpu_data.x86_vendor == X86_VENDOR_HYGON) {
		if (hygon_fixup_psp_caps(psp))
			return -ENODEV;
	}

	/* Detect if TSME and SME are both enabled */
	if (psp->capability & PSP_CAPABILITY_PSP_SECURITY_REPORTING &&
	    psp->capability & (PSP_SECURITY_TSME_STATUS << PSP_CAPABILITY_PSP_SECURITY_OFFSET) &&
	    cc_platform_has(CC_ATTR_HOST_MEM_ENCRYPT))
		dev_notice(psp->dev, "psp: Both TSME and SME are active, SME is unnecessary when TSME is active.\n");

	return 0;
}

static int psp_check_sev_support(struct psp_device *psp)
{
	/* Check if device supports SEV feature */
	if (!(psp->capability & PSP_CAPABILITY_SEV)) {
		dev_dbg(psp->dev, "psp does not support SEV\n");
		return -ENODEV;
	}

	return 0;
}

static int psp_check_tee_support(struct psp_device *psp)
{
	/* Check if device supports TEE feature */
	if (!(psp->capability & PSP_CAPABILITY_TEE)) {
		dev_dbg(psp->dev, "psp does not support TEE\n");
		return -ENODEV;
	}

	return 0;
}

static void psp_init_platform_access(struct psp_device *psp)
{
	int ret;

	ret = platform_access_dev_init(psp);
	if (ret) {
		dev_warn(psp->dev, "platform access init failed: %d\n", ret);
		return;
	}

	/* dbc must come after platform access as it tests the feature */
	ret = dbc_dev_init(psp);
	if (ret)
		dev_warn(psp->dev, "failed to init dynamic boost control: %d\n",
			 ret);
}

static int psp_init(struct psp_device *psp)
{
	int ret;

	if (!psp_check_sev_support(psp)) {
		ret = sev_dev_init(psp);
		if (ret)
			return ret;
	}

	if (!psp_check_tee_support(psp)) {
		ret = tee_dev_init(psp);
		if (ret)
			return ret;
	}

	if (psp->vdata->platform_access)
		psp_init_platform_access(psp);

#ifdef CONFIG_TDM_DEV_HYGON
	if (boot_cpu_data.x86_vendor == X86_VENDOR_HYGON) {
		ret = tdm_dev_init();
		if (ret)
			return ret;
	}
#endif

	return 0;
}

static int mmap_psp(struct file *filp, struct vm_area_struct *vma)
{
	unsigned long page;

	page = virt_to_phys((void *)psp_misc->data_pg_aligned) >> PAGE_SHIFT;

	if (remap_pfn_range(vma, vma->vm_start, page, (vma->vm_end - vma->vm_start),
				vma->vm_page_prot)) {
		printk(KERN_ERR "remap failed...");
		return -1;
	}
	vm_flags_mod(vma, VM_DONTDUMP | VM_DONTEXPAND, 0);
	printk(KERN_INFO "remap_pfn_rang page:[%lu] ok.\n", page);
	return 0;
}

static ssize_t read_psp(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	ssize_t remaining;

	if ((*ppos + count) > PAGE_SIZE) {
		printk(KERN_ERR "%s: invalid address range, pos %llx, count %lx\n",
				__func__, *ppos, count);
		return -EFAULT;
	}

	remaining = copy_to_user(buf, (char *)psp_misc->data_pg_aligned + *ppos, count);
	if (remaining)
		return -EFAULT;

	*ppos += count;

	return count;
}

static ssize_t write_psp(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	ssize_t remaining, written;

	if ((*ppos + count) > PAGE_SIZE) {
		printk(KERN_ERR "%s: invalid address range, pos %llx, count %lx\n",
				__func__, *ppos, count);
		return -EFAULT;
	}

	remaining = copy_from_user((char *)psp_misc->data_pg_aligned + *ppos, buf, count);
	written = count - remaining;
	if (!written)
		return -EFAULT;

	*ppos += written;

	return written;
}

DEFINE_RWLOCK(vpsp_rwlock);

/* VPSP_VID_MAX_ENTRIES determines the maximum number of vms that can set vid.
 * but, the performance of finding vid is determined by g_vpsp_vid_num,
 * so VPSP_VID_MAX_ENTRIES can be set larger.
 */
#define VPSP_VID_MAX_ENTRIES    2048
#define VPSP_VID_NUM_MAX        64

struct vpsp_vid_entry {
	uint32_t vid;
	pid_t pid;
};
static struct vpsp_vid_entry g_vpsp_vid_array[VPSP_VID_MAX_ENTRIES];
static uint32_t g_vpsp_vid_num;
static int compare_vid_entries(const void *a, const void *b)
{
	return ((struct vpsp_vid_entry *)a)->pid - ((struct vpsp_vid_entry *)b)->pid;
}
static void swap_vid_entries(void *a, void *b, int size)
{
	struct vpsp_vid_entry entry;

	memcpy(&entry, a, size);
	memcpy(a, b, size);
	memcpy(b, &entry, size);
}

/**
 * When 'allow_default_vid' is set to 1,
 * QEMU is allowed to use 'vid 0' by default
 * in the absence of a valid 'vid' setting.
 */
uint32_t allow_default_vid = 1;
void vpsp_set_default_vid_permission(uint32_t is_allow)
{
	allow_default_vid = is_allow;
}

int vpsp_get_default_vid_permission(void)
{
	return allow_default_vid;
}
EXPORT_SYMBOL_GPL(vpsp_get_default_vid_permission);

/**
 * When the virtual machine executes the 'tkm' command,
 * it needs to retrieve the corresponding 'vid'
 * by performing a binary search using 'kvm->userspace_pid'.
 */
int vpsp_get_vid(uint32_t *vid, pid_t pid)
{
	struct vpsp_vid_entry new_entry = {.pid = pid};
	struct vpsp_vid_entry *existing_entry = NULL;

	read_lock(&vpsp_rwlock);
	existing_entry = bsearch(&new_entry, g_vpsp_vid_array, g_vpsp_vid_num,
				sizeof(struct vpsp_vid_entry), compare_vid_entries);
	read_unlock(&vpsp_rwlock);

	if (!existing_entry)
		return -ENOENT;

	if (vid) {
		*vid = existing_entry->vid;
		pr_debug("PSP: %s %d, by pid %d\n", __func__, *vid, pid);
	}
	return 0;
}
EXPORT_SYMBOL_GPL(vpsp_get_vid);

/**
 * Upon qemu startup, this section checks whether
 * the '-device psp,vid' parameter is specified.
 * If set, it utilizes the 'vpsp_add_vid' function
 * to insert the 'vid' and 'pid' values into the 'g_vpsp_vid_array'.
 * The insertion is done in ascending order of 'pid'.
 */
static int vpsp_add_vid(uint32_t vid)
{
	pid_t cur_pid = task_pid_nr(current);
	struct vpsp_vid_entry new_entry = {.vid = vid, .pid = cur_pid};

	if (vpsp_get_vid(NULL, cur_pid) == 0)
		return -EEXIST;
	if (g_vpsp_vid_num == VPSP_VID_MAX_ENTRIES)
		return -ENOMEM;
	if (vid >= VPSP_VID_NUM_MAX)
		return -EINVAL;

	write_lock(&vpsp_rwlock);
	memcpy(&g_vpsp_vid_array[g_vpsp_vid_num++], &new_entry, sizeof(struct vpsp_vid_entry));
	sort(g_vpsp_vid_array, g_vpsp_vid_num, sizeof(struct vpsp_vid_entry),
				compare_vid_entries, swap_vid_entries);
	pr_info("PSP: add vid %d, by pid %d, total vid num is %d\n", vid, cur_pid, g_vpsp_vid_num);
	write_unlock(&vpsp_rwlock);
	return 0;
}

/**
 * Upon the virtual machine is shut down,
 * the 'vpsp_del_vid' function is employed to remove
 * the 'vid' associated with the current 'pid'.
 */
static int vpsp_del_vid(void)
{
	pid_t cur_pid = task_pid_nr(current);
	int i, ret = -ENOENT;

	write_lock(&vpsp_rwlock);
	for (i = 0; i < g_vpsp_vid_num; ++i) {
		if (g_vpsp_vid_array[i].pid == cur_pid) {
			--g_vpsp_vid_num;
			pr_info("PSP: delete vid %d, by pid %d, total vid num is %d\n",
				g_vpsp_vid_array[i].vid, cur_pid, g_vpsp_vid_num);
			memcpy(&g_vpsp_vid_array[i], &g_vpsp_vid_array[i + 1],
				sizeof(struct vpsp_vid_entry) * (g_vpsp_vid_num - i));
			ret = 0;
			goto end;
		}
	}

end:
	write_unlock(&vpsp_rwlock);
	return ret;
}

static int do_vpsp_op_ioctl(struct vpsp_dev_ctrl *ctrl)
{
	int ret = 0;
	unsigned char op = ctrl->op;

	switch (op) {
	case VPSP_OP_VID_ADD:
		ret = vpsp_add_vid(ctrl->data.vid);
		break;

	case VPSP_OP_VID_DEL:
		ret = vpsp_del_vid();
		break;

	case VPSP_OP_SET_DEFAULT_VID_PERMISSION:
		vpsp_set_default_vid_permission(ctrl->data.def_vid_perm);
		break;

	case VPSP_OP_GET_DEFAULT_VID_PERMISSION:
		ctrl->data.def_vid_perm = vpsp_get_default_vid_permission();
		break;

	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

static long ioctl_psp(struct file *file, unsigned int ioctl, unsigned long arg)
{
	unsigned int opcode = 0;
	struct vpsp_dev_ctrl vpsp_ctrl_op;
	int ret = -EFAULT;

	if (_IOC_TYPE(ioctl) != HYGON_PSP_IOC_TYPE) {
		printk(KERN_ERR "%s: invalid ioctl type: 0x%x\n", __func__, _IOC_TYPE(ioctl));
		return -EINVAL;
	}
	opcode = _IOC_NR(ioctl);
	switch (opcode) {
	case HYGON_PSP_MUTEX_ENABLE:
		psp_mutex_lock_timeout(&psp_misc->data_pg_aligned->mb_mutex, 0);
		// And get the sev lock to make sure no one is using it now.
		mutex_lock(&sev_cmd_mutex);
		psp_mutex_enabled = 1;
		mutex_unlock(&sev_cmd_mutex);
		// Wait 10ms just in case someone is right before getting the psp lock.
		mdelay(10);
		psp_mutex_unlock(&psp_misc->data_pg_aligned->mb_mutex);
		ret = 0;
		break;

	case HYGON_PSP_MUTEX_DISABLE:
		mutex_lock(&sev_cmd_mutex);
		// And get the psp lock to make sure no one is using it now.
		psp_mutex_lock_timeout(&psp_misc->data_pg_aligned->mb_mutex, 0);
		psp_mutex_enabled = 0;
		psp_mutex_unlock(&psp_misc->data_pg_aligned->mb_mutex);
		// Wait 10ms just in case someone is right before getting the sev lock.
		mdelay(10);
		mutex_unlock(&sev_cmd_mutex);
		ret = 0;
		break;

	case HYGON_VPSP_CTRL_OPT:
		if (copy_from_user(&vpsp_ctrl_op, (void __user *)arg,
						sizeof(struct vpsp_dev_ctrl)))
			return -EFAULT;
		ret = do_vpsp_op_ioctl(&vpsp_ctrl_op);
		if (!ret && copy_to_user((void __user *)arg, &vpsp_ctrl_op,
				sizeof(struct vpsp_dev_ctrl)))
			return -EFAULT;
		break;

	default:
		printk(KERN_ERR "%s: invalid ioctl number: %d\n", __func__, opcode);
		return -EINVAL;
	}
	return ret;
}

static const struct file_operations psp_fops = {
	.owner          = THIS_MODULE,
	.mmap		= mmap_psp,
	.read		= read_psp,
	.write		= write_psp,
	.unlocked_ioctl = ioctl_psp,
};

static int hygon_psp_additional_setup(struct sp_device *sp)
{
	struct device *dev = sp->dev;
	int ret = 0;

	if (!psp_misc) {
		struct miscdevice *misc;

		psp_misc = devm_kzalloc(dev, sizeof(*psp_misc), GFP_KERNEL);
		if (!psp_misc)
			return -ENOMEM;
		psp_misc->data_pg_aligned = (struct psp_dev_data *)get_zeroed_page(GFP_KERNEL);
		if (!psp_misc->data_pg_aligned) {
			dev_err(dev, "alloc psp data page failed\n");
			devm_kfree(dev, psp_misc);
			psp_misc = NULL;
			return -ENOMEM;
		}
		SetPageReserved(virt_to_page(psp_misc->data_pg_aligned));
		psp_mutex_init(&psp_misc->data_pg_aligned->mb_mutex);

		*(uint32_t *)((void *)psp_misc->data_pg_aligned + 8) = 0xdeadbeef;
		misc = &psp_misc->misc;
		misc->minor = MISC_DYNAMIC_MINOR;
		misc->name = "hygon_psp_config";
		misc->fops = &psp_fops;

		ret = misc_register(misc);
		if (ret)
			return ret;
		kref_init(&psp_misc->refcount);
	} else {
		kref_get(&psp_misc->refcount);
	}

	return ret;
}

static void hygon_psp_exit(struct kref *ref)
{
	struct psp_misc_dev *misc_dev = container_of(ref, struct psp_misc_dev, refcount);

	misc_deregister(&misc_dev->misc);
	ClearPageReserved(virt_to_page(misc_dev->data_pg_aligned));
	free_page((unsigned long)misc_dev->data_pg_aligned);
	psp_misc = NULL;
}

int psp_dev_init(struct sp_device *sp)
{
	struct device *dev = sp->dev;
	struct pci_dev *pdev = to_pci_dev(dev);
	struct psp_device *psp;
	int ret;

	ret = -ENOMEM;
	psp = psp_alloc_struct(sp);
	if (!psp)
		goto e_err;

	sp->psp_data = psp;

	psp->vdata = (struct psp_vdata *)sp->dev_vdata->psp_vdata;
	if (!psp->vdata) {
		ret = -ENODEV;
		dev_err(dev, "missing driver data\n");
		goto e_err;
	}

	psp->io_regs = sp->io_map;

	ret = psp_get_capability(psp);
	if (ret)
		goto e_disable;

	/* Disable and clear interrupts until ready */
	iowrite32(0, psp->io_regs + psp->vdata->inten_reg);
	iowrite32(-1, psp->io_regs + psp->vdata->intsts_reg);

	if (pdev->vendor == PCI_VENDOR_ID_HYGON) {
		is_hygon_psp = 1;
		psp_mutex_enabled = 0;
		ret = hygon_psp_additional_setup(sp);
		if (ret) {
			dev_err(dev, "psp: unable to do additional setup\n");
			goto e_err;
		}
	}

	/* Request an irq */
	if (pdev->vendor == PCI_VENDOR_ID_HYGON) {
#ifdef CONFIG_HYGON_PSP2CPU_CMD
		ret = sp_request_psp_irq(psp->sp, psp_irq_handler_hygon, psp->name, psp);
#else
		ret = sp_request_psp_irq(psp->sp, psp_irq_handler, psp->name, psp);
#endif
	} else {
		ret = sp_request_psp_irq(psp->sp, psp_irq_handler, psp->name, psp);
	}
	if (ret) {
		dev_err(dev, "psp: unable to allocate an IRQ\n");
		goto e_err;
	}

	/* master device must be set for platform access */
	if (psp->sp->set_psp_master_device)
		psp->sp->set_psp_master_device(psp->sp);

	ret = psp_init(psp);
	if (ret)
		goto e_irq;

	/* Enable interrupt */
	iowrite32(-1, psp->io_regs + psp->vdata->inten_reg);

	dev_notice(dev, "psp enabled\n");

	return 0;

e_irq:
	if (sp->clear_psp_master_device)
		sp->clear_psp_master_device(sp);

	sp_free_psp_irq(psp->sp, psp);
e_err:
	sp->psp_data = NULL;

	dev_notice(dev, "psp initialization failed\n");

	return ret;

e_disable:
	sp->psp_data = NULL;

	return ret;
}

void psp_dev_destroy(struct sp_device *sp)
{
	struct psp_device *psp = sp->psp_data;

	if (!psp)
		return;

#ifdef CONFIG_TDM_DEV_HYGON
	if (boot_cpu_data.x86_vendor == X86_VENDOR_HYGON)
		tdm_dev_destroy();
#endif

	sev_dev_destroy(psp);

	tee_dev_destroy(psp);

	if (is_hygon_psp && psp_misc)
		kref_put(&psp_misc->refcount, hygon_psp_exit);

	dbc_dev_destroy(psp);

	platform_access_dev_destroy(psp);

	sp_free_psp_irq(sp, psp);

	if (sp->clear_psp_master_device)
		sp->clear_psp_master_device(sp);
}

void psp_set_sev_irq_handler(struct psp_device *psp, psp_irq_handler_t handler,
			     void *data)
{
	psp->sev_irq_data = data;
	psp->sev_irq_handler = handler;
}

void psp_clear_sev_irq_handler(struct psp_device *psp)
{
	psp_set_sev_irq_handler(psp, NULL, NULL);
}

struct psp_device *psp_get_master_device(void)
{
	struct sp_device *sp = sp_get_psp_master_device();

	return sp ? sp->psp_data : NULL;
}

void psp_pci_init(void)
{
	psp_master = psp_get_master_device();

	if (!psp_master)
		return;

	sev_pci_init();
}

void psp_pci_exit(void)
{
	if (!psp_master)
		return;

	sev_pci_exit();
}
