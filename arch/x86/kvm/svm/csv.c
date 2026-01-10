// SPDX-License-Identifier: GPL-2.0-only
/*
 * CSV driver for KVM
 *
 * HYGON CSV support
 *
 * Copyright (C) Hygon Info Technologies Ltd.
 */

#include <linux/kvm_host.h>
#include <linux/psp.h>
#include <linux/psp-sev.h>
#include <linux/psp-csv.h>
#include <linux/memory.h>
#include <linux/kvm_types.h>
#include <linux/vmalloc.h>
#include <asm/cacheflush.h>
#include <asm/e820/api.h>
#include <asm/csv.h>
#include "kvm_cache_regs.h"
#include "svm.h"
#include "csv.h"
#include "x86.h"

#undef  pr_fmt
#define pr_fmt(fmt) "CSV: " fmt

struct encrypt_data_block {
	struct {
		u64 npages:	12;
		u64 pfn:	52;
	} entry[512];
};

union csv3_page_attr {
	struct {
		u64 reserved:	1;
		u64 rw:		1;
		u64 reserved1:	49;
		u64 mmio:	1;
		u64 reserved2:	12;
	};
	u64 val;
};

struct guest_paddr_block {
	struct {
		u64 share:	1;
		u64 reserved:	11;
		u64 gfn:	52;
	} entry[512];
};

struct trans_paddr_block {
	u64	trans_paddr[512];
};

struct vmcb_paddr_block {
	u64	vmcb_paddr[512];
};

enum csv3_pg_level {
	CSV3_PG_LEVEL_NONE,
	CSV3_PG_LEVEL_4K,
	CSV3_PG_LEVEL_2M,
	CSV3_PG_LEVEL_NUM
};

struct shared_page_block {
	struct list_head list;
	struct page **pages;
	u64 count;
};

struct kvm_csv_info {
	struct kvm_sev_info *sev;

	bool csv3_active;	/* CSV3 enabled guest */

	/* List of shared pages */
	u64 total_shared_page_count;
	struct list_head shared_pages_list;
	void *cached_shared_page_block;
	struct mutex shared_page_block_lock;

	struct list_head smr_list; /* List of guest secure memory regions */
	unsigned long nodemask; /* Nodemask where CSV3 guest's memory resides */
};

struct kvm_svm_csv {
	struct kvm_svm kvm_svm;
	struct kvm_csv_info csv_info;
};

struct secure_memory_region {
	struct list_head list;
	u64 npages;
	u64 hpa;
};

static struct kvm_x86_ops csv_x86_ops;

static inline struct kvm_svm_csv *to_kvm_svm_csv(struct kvm *kvm)
{
	return (struct kvm_svm_csv *)container_of(kvm, struct kvm_svm, kvm);
}

static int to_csv3_pg_level(int level)
{
	int ret;

	switch (level) {
	case PG_LEVEL_4K:
		ret = CSV3_PG_LEVEL_4K;
		break;
	case PG_LEVEL_2M:
		ret = CSV3_PG_LEVEL_2M;
		break;
	default:
		ret = CSV3_PG_LEVEL_NONE;
	}

	return ret;
}

static bool csv3_guest(struct kvm *kvm)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;

	return sev_es_guest(kvm) && csv->csv3_active;
}

static int csv_sync_vmsa(struct vcpu_svm *svm)
{
	struct sev_es_save_area *save = svm->sev_es.vmsa;

	/* Check some debug related fields before encrypting the VMSA */
	if (svm->vcpu.guest_debug || (svm->vmcb->save.dr7 & ~DR7_FIXED_1))
		return -EINVAL;

	memcpy(save, &svm->vmcb->save, sizeof(svm->vmcb->save));

	/* Sync registgers per spec. */
	save->rax = svm->vcpu.arch.regs[VCPU_REGS_RAX];
	save->rdx = svm->vcpu.arch.regs[VCPU_REGS_RDX];
	save->rip = svm->vcpu.arch.regs[VCPU_REGS_RIP];
	save->xcr0 = svm->vcpu.arch.xcr0;
	save->xss  = svm->vcpu.arch.ia32_xss;

	return 0;
}

static int __csv_issue_cmd(int fd, int id, void *data, int *error)
{
	struct fd f;
	int ret;

	f = fdget(fd);
	if (!f.file)
		return -EBADF;

	ret = sev_issue_cmd_external_user(f.file, id, data, error);

	fdput(f);
	return ret;
}

static int csv_issue_cmd(struct kvm *kvm, int id, void *data, int *error)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;

	return __csv_issue_cmd(sev->fd, id, data, error);
}

static inline void csv3_init_update_npt(struct csv3_data_update_npt *update_npt,
					gpa_t gpa, u32 error, u32 handle)
{
	memset(update_npt, 0x00, sizeof(*update_npt));

	update_npt->gpa = gpa & PAGE_MASK;
	update_npt->error_code = error;
	update_npt->handle = handle;
}

static int csv3_guest_init(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct kvm_csv3_init_data params;

	if (unlikely(csv->csv3_active))
		return -EINVAL;

	if (unlikely(!sev->es_active))
		return -EINVAL;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			   sizeof(params)))
		return -EFAULT;

	csv->csv3_active = true;
	csv->sev = sev;
	csv->nodemask = (unsigned long)params.nodemask;

	INIT_LIST_HEAD(&csv->shared_pages_list);
	INIT_LIST_HEAD(&csv->smr_list);
	mutex_init(&csv->shared_page_block_lock);

	return 0;
}

static bool csv3_is_mmio_pfn(kvm_pfn_t pfn)
{
	return !e820__mapped_raw_any(pfn_to_hpa(pfn),
				     pfn_to_hpa(pfn + 1) - 1,
				     E820_TYPE_RAM);
}

static int csv3_set_guest_private_memory(struct kvm *kvm)
{
	struct kvm_memslots *slots = kvm_memslots(kvm);
	struct kvm_memory_slot *memslot;
	struct secure_memory_region *smr;
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct csv3_data_set_guest_private_memory *set_guest_private_memory;
	struct csv3_data_memory_region *regions;
	nodemask_t nodemask;
	nodemask_t *nodemask_ptr;

	LIST_HEAD(tmp_list);
	struct list_head *pos, *q;
	u32 i = 0, count = 0, remainder;
	int ret = 0, error;
	u64 size = 0, nr_smr = 0, nr_pages = 0;
	u32 smr_entry_shift;
	int bkt;

	unsigned int flags = FOLL_HWPOISON;
	int npages;
	struct page *page;

	if (!csv3_guest(kvm))
		return -ENOTTY;

	nodes_clear(nodemask);
	for_each_set_bit(i, &csv->nodemask, BITS_PER_LONG)
		if (i < MAX_NUMNODES)
			node_set(i, nodemask);

	nodemask_ptr = csv->nodemask ? &nodemask : &node_online_map;

	set_guest_private_memory = kzalloc(sizeof(*set_guest_private_memory),
					GFP_KERNEL_ACCOUNT);
	if (!set_guest_private_memory)
		return -ENOMEM;

	regions = kzalloc(PAGE_SIZE, GFP_KERNEL_ACCOUNT);
	if (!regions) {
		kfree(set_guest_private_memory);
		return -ENOMEM;
	}

	/* Get guest secure memory size */
	kvm_for_each_memslot(memslot, bkt, slots) {
		npages = get_user_pages_unlocked(memslot->userspace_addr, 1,
						&page, flags);
		if (npages != 1)
			continue;

		nr_pages += memslot->npages;

		put_page(page);
	}

	/*
	 * NPT secure memory size
	 *
	 * PTEs_entries = nr_pages
	 * PDEs_entries = nr_pages / 512
	 * PDPEs_entries = nr_pages / (512 * 512)
	 * PML4Es_entries = nr_pages / (512 * 512 * 512)
	 *
	 * Totals_entries = nr_pages + nr_pages / 512 + nr_pages / (512 * 512) +
	 *		nr_pages / (512 * 512 * 512) <= nr_pages + nr_pages / 256
	 *
	 * Total_NPT_size = (Totals_entries / 512) * PAGE_SIZE = ((nr_pages +
	 *      nr_pages / 256) / 512) * PAGE_SIZE = nr_pages * 8 + nr_pages / 32
	 *      <= nr_pages * 9
	 *
	 */
	smr_entry_shift = csv_get_smr_entry_shift();
	size = ALIGN((nr_pages << PAGE_SHIFT), 1UL << smr_entry_shift) +
		ALIGN(nr_pages * 9, 1UL << smr_entry_shift);
	nr_smr = size >> smr_entry_shift;
	remainder = nr_smr;
	for (i = 0; i < nr_smr; i++) {
		smr = kzalloc(sizeof(*smr), GFP_KERNEL_ACCOUNT);
		if (!smr) {
			ret = -ENOMEM;
			goto e_free_smr;
		}

		smr->hpa = csv_alloc_from_contiguous((1UL << smr_entry_shift),
						nodemask_ptr,
						get_order(1 << smr_entry_shift));
		if (!smr->hpa) {
			kfree(smr);
			ret = -ENOMEM;
			goto e_free_smr;
		}

		smr->npages = ((1UL << smr_entry_shift) >> PAGE_SHIFT);
		list_add_tail(&smr->list, &tmp_list);

		regions[count].size = (1UL << smr_entry_shift);
		regions[count].base_address = smr->hpa;
		count++;

		if (count >= (PAGE_SIZE / sizeof(regions[0])) || (remainder == count)) {
			set_guest_private_memory->nregions = count;
			set_guest_private_memory->handle = sev->handle;
			set_guest_private_memory->regions_paddr = __sme_pa(regions);

			/* set secury memory region for launch enrypt data */
			ret = csv_issue_cmd(kvm, CSV3_CMD_SET_GUEST_PRIVATE_MEMORY,
					set_guest_private_memory, &error);
			if (ret)
				goto e_free_smr;

			memset(regions, 0, PAGE_SIZE);
			remainder -= count;
			count = 0;
		}
	}

	list_splice(&tmp_list, &csv->smr_list);

	goto done;

e_free_smr:
	if (!list_empty(&tmp_list)) {
		list_for_each_safe(pos, q, &tmp_list) {
			smr = list_entry(pos, struct secure_memory_region, list);
			if (smr) {
				csv_release_to_contiguous(smr->hpa,
							smr->npages << PAGE_SHIFT);
				list_del(&smr->list);
				kfree(smr);
			}
		}
	}
done:
	kfree(set_guest_private_memory);
	kfree(regions);
	return ret;
}

static int csv3_launch_encrypt_data(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct kvm_csv3_launch_encrypt_data params;
	struct csv3_data_launch_encrypt_data *encrypt_data = NULL;
	struct encrypt_data_block *blocks = NULL;
	u8 *data = NULL;
	u32 offset;
	u32 num_entries, num_entries_in_block;
	u32 num_blocks, num_blocks_max;
	u32 i, n;
	unsigned long pfn, pfn_sme_mask;
	int ret = 0;

	if (!csv3_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			   sizeof(params))) {
		ret = -EFAULT;
		goto exit;
	}

	if ((params.len & ~PAGE_MASK) || !params.len || !params.uaddr) {
		ret = -EINVAL;
		goto exit;
	}

	/* Allocate all the guest memory from CMA */
	ret = csv3_set_guest_private_memory(kvm);
	if (ret)
		goto exit;

	num_entries = params.len / PAGE_SIZE;
	num_entries_in_block = ARRAY_SIZE(blocks->entry);
	num_blocks = (num_entries + num_entries_in_block - 1) / num_entries_in_block;
	num_blocks_max = ARRAY_SIZE(encrypt_data->data_blocks);

	if (num_blocks >= num_blocks_max) {
		ret = -EINVAL;
		goto exit;
	}

	data = vzalloc(params.len);
	if (!data) {
		ret = -ENOMEM;
		goto exit;
	}
	if (copy_from_user(data, (void __user *)params.uaddr, params.len)) {
		ret = -EFAULT;
		goto data_free;
	}

	blocks = vzalloc(num_blocks * sizeof(*blocks));
	if (!blocks) {
		ret = -ENOMEM;
		goto data_free;
	}

	for (offset = 0, i = 0, n = 0; offset < params.len; offset += PAGE_SIZE) {
		pfn = vmalloc_to_pfn(offset + data);
		pfn_sme_mask = __sme_set(pfn << PAGE_SHIFT) >> PAGE_SHIFT;
		if (offset && ((blocks[n].entry[i].pfn + 1) == pfn_sme_mask))
			blocks[n].entry[i].npages += 1;
		else {
			if (offset) {
				i = (i + 1) % num_entries_in_block;
				n = (i == 0) ? (n + 1) : n;
			}
			blocks[n].entry[i].pfn = pfn_sme_mask;
			blocks[n].entry[i].npages = 1;
		}
	}

	encrypt_data = kzalloc(sizeof(*encrypt_data), GFP_KERNEL);
	if (!encrypt_data) {
		ret = -ENOMEM;
		goto block_free;
	}

	encrypt_data->handle = csv->sev->handle;
	encrypt_data->length = params.len;
	encrypt_data->gpa = params.gpa;
	for (i = 0; i <= n; i++) {
		encrypt_data->data_blocks[i] =
		__sme_set(vmalloc_to_pfn((void *)blocks + i * sizeof(*blocks)) << PAGE_SHIFT);
	}

	clflush_cache_range(data, params.len);
	ret = csv_issue_cmd(kvm, CSV3_CMD_LAUNCH_ENCRYPT_DATA,
			    encrypt_data, &argp->error);

	kfree(encrypt_data);
block_free:
	vfree(blocks);
data_free:
	vfree(data);
exit:
	return ret;
}

static int csv3_launch_encrypt_vmcb(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct csv3_data_launch_encrypt_vmcb *encrypt_vmcb = NULL;
	struct kvm_vcpu *vcpu;
	int ret = 0;
	unsigned long i = 0;

	if (!csv3_guest(kvm))
		return -ENOTTY;

	encrypt_vmcb = kzalloc(sizeof(*encrypt_vmcb), GFP_KERNEL);
	if (!encrypt_vmcb) {
		ret = -ENOMEM;
		goto exit;
	}

	kvm_for_each_vcpu(i, vcpu, kvm) {
		struct vcpu_svm *svm = to_svm(vcpu);

		ret = csv_sync_vmsa(svm);
		if (ret)
			goto e_free;
		clflush_cache_range(svm->sev_es.vmsa, PAGE_SIZE);
		clflush_cache_range(svm->vmcb, PAGE_SIZE);
		encrypt_vmcb->handle = csv->sev->handle;
		encrypt_vmcb->vcpu_id = i;
		encrypt_vmcb->vmsa_addr = __sme_pa(svm->sev_es.vmsa);
		encrypt_vmcb->vmsa_len = PAGE_SIZE;
		encrypt_vmcb->shadow_vmcb_addr = __sme_pa(svm->vmcb);
		encrypt_vmcb->shadow_vmcb_len = PAGE_SIZE;
		ret = csv_issue_cmd(kvm, CSV3_CMD_LAUNCH_ENCRYPT_VMCB,
				    encrypt_vmcb, &argp->error);
		if (ret)
			goto e_free;

		svm->current_vmcb->pa = encrypt_vmcb->secure_vmcb_addr;
		svm->vcpu.arch.guest_state_protected = true;
	}

e_free:
	kfree(encrypt_vmcb);
exit:
	return ret;
}

/* Userspace wants to query either header or trans length. */
static int
csv3_send_encrypt_data_query_lengths(struct kvm *kvm, struct kvm_sev_cmd *argp,
				     struct kvm_csv3_send_encrypt_data *params)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct csv3_data_send_encrypt_data data;
	int ret;

	memset(&data, 0, sizeof(data));
	data.handle = sev->handle;
	ret = csv_issue_cmd(kvm, CSV3_CMD_SEND_ENCRYPT_DATA, &data, &argp->error);

	params->hdr_len = data.hdr_len;
	params->trans_len = data.trans_len;

	if (copy_to_user((void __user *)(uintptr_t)argp->data, params, sizeof(*params)))
		ret = -EFAULT;

	return ret;
}

#define CSV3_SEND_ENCRYPT_DATA_MIGRATE_PAGE  0x00000000
#define CSV3_SEND_ENCRYPT_DATA_SET_READONLY  0x00000001
static int csv3_send_encrypt_data(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct csv3_data_send_encrypt_data data;
	struct kvm_csv3_send_encrypt_data params;
	void *hdr;
	void *trans_data;
	struct trans_paddr_block *trans_block;
	struct guest_paddr_block *guest_block;
	unsigned long pfn;
	u32 offset;
	int ret = 0;
	int i;

	if (!csv3_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			   sizeof(params)))
		return -EFAULT;

	/* userspace wants to query either header or trans length */
	if (!params.trans_len || !params.hdr_len)
		return csv3_send_encrypt_data_query_lengths(kvm, argp, &params);

	if (!params.trans_uaddr || !params.guest_addr_data ||
	    !params.guest_addr_len || !params.hdr_uaddr)
		return -EINVAL;

	if (params.guest_addr_len > sizeof(*guest_block))
		return -EINVAL;

	if (params.trans_len > ARRAY_SIZE(trans_block->trans_paddr) * PAGE_SIZE)
		return -EINVAL;

	if ((params.trans_len & PAGE_MASK) == 0 ||
	    (params.trans_len & ~PAGE_MASK) != 0)
		return -EINVAL;

	/* allocate memory for header and transport buffer */
	hdr = kzalloc(params.hdr_len, GFP_KERNEL_ACCOUNT);
	if (!hdr) {
		ret = -ENOMEM;
		goto exit;
	}

	guest_block = kzalloc(sizeof(*guest_block), GFP_KERNEL_ACCOUNT);
	if (!guest_block) {
		ret = -ENOMEM;
		goto e_free_hdr;
	}

	if (copy_from_user(guest_block,
			   (void __user *)(uintptr_t)params.guest_addr_data,
			   params.guest_addr_len)) {
		ret = -EFAULT;
		goto e_free_guest_block;
	}

	trans_block = kzalloc(sizeof(*trans_block), GFP_KERNEL_ACCOUNT);
	if (!trans_block) {
		ret = -ENOMEM;
		goto e_free_guest_block;
	}
	trans_data = vzalloc(params.trans_len);
	if (!trans_data) {
		ret = -ENOMEM;
		goto e_free_trans_block;
	}

	for (offset = 0, i = 0; offset < params.trans_len; offset += PAGE_SIZE) {
		pfn = vmalloc_to_pfn(offset + trans_data);
		trans_block->trans_paddr[i] = __sme_set(pfn_to_hpa(pfn));
		i++;
	}
	memset(&data, 0, sizeof(data));
	data.hdr_address = __psp_pa(hdr);
	data.hdr_len = params.hdr_len;
	data.trans_block = __psp_pa(trans_block);
	data.trans_len = params.trans_len;

	data.guest_block = __psp_pa(guest_block);
	data.guest_len = params.guest_addr_len;
	data.handle = sev->handle;

	clflush_cache_range(hdr, params.hdr_len);
	clflush_cache_range(trans_data, params.trans_len);
	clflush_cache_range(trans_block, PAGE_SIZE);
	clflush_cache_range(guest_block, PAGE_SIZE);

	data.flag = CSV3_SEND_ENCRYPT_DATA_SET_READONLY;
	ret = csv_issue_cmd(kvm, CSV3_CMD_SEND_ENCRYPT_DATA, &data, &argp->error);
	if (ret)
		goto e_free_trans_data;

	kvm_flush_remote_tlbs(kvm);

	data.flag = CSV3_SEND_ENCRYPT_DATA_MIGRATE_PAGE;
	ret = csv_issue_cmd(kvm, CSV3_CMD_SEND_ENCRYPT_DATA, &data, &argp->error);
	if (ret)
		goto e_free_trans_data;

	ret = -EFAULT;
	/* copy transport buffer to user space */
	if (copy_to_user((void __user *)(uintptr_t)params.trans_uaddr,
			 trans_data, params.trans_len))
		goto e_free_trans_data;

	/* copy guest address block to user space */
	if (copy_to_user((void __user *)(uintptr_t)params.guest_addr_data,
			 guest_block, params.guest_addr_len))
		goto e_free_trans_data;

	/* copy packet header to userspace. */
	if (copy_to_user((void __user *)(uintptr_t)params.hdr_uaddr, hdr,
			 params.hdr_len))
		goto e_free_trans_data;

	ret = 0;
e_free_trans_data:
	vfree(trans_data);
e_free_trans_block:
	kfree(trans_block);
e_free_guest_block:
	kfree(guest_block);
e_free_hdr:
	kfree(hdr);
exit:
	return ret;
}

/* Userspace wants to query either header or trans length. */
static int
csv3_send_encrypt_context_query_lengths(struct kvm *kvm, struct kvm_sev_cmd *argp,
					struct kvm_csv3_send_encrypt_context *params)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct csv3_data_send_encrypt_context data;
	int ret;

	memset(&data, 0, sizeof(data));
	data.handle = sev->handle;
	ret = csv_issue_cmd(kvm, CSV3_CMD_SEND_ENCRYPT_CONTEXT, &data, &argp->error);

	params->hdr_len = data.hdr_len;
	params->trans_len = data.trans_len;

	if (copy_to_user((void __user *)(uintptr_t)argp->data, params, sizeof(*params)))
		ret = -EFAULT;

	return ret;
}

static int csv3_send_encrypt_context(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct csv3_data_send_encrypt_context data;
	struct kvm_csv3_send_encrypt_context params;
	void *hdr;
	void *trans_data;
	struct trans_paddr_block *trans_block;
	unsigned long pfn;
	unsigned long i;
	u32 offset;
	int ret = 0;

	if (!csv3_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			   sizeof(params)))
		return -EFAULT;

	/* userspace wants to query either header or trans length */
	if (!params.trans_len || !params.hdr_len)
		return csv3_send_encrypt_context_query_lengths(kvm, argp, &params);

	if (!params.trans_uaddr || !params.hdr_uaddr)
		return -EINVAL;

	if (params.trans_len > ARRAY_SIZE(trans_block->trans_paddr) * PAGE_SIZE)
		return -EINVAL;

	/* allocate memory for header and transport buffer */
	hdr = kzalloc(params.hdr_len, GFP_KERNEL_ACCOUNT);
	if (!hdr) {
		ret = -ENOMEM;
		goto exit;
	}

	trans_block = kzalloc(sizeof(*trans_block), GFP_KERNEL_ACCOUNT);
	if (!trans_block) {
		ret = -ENOMEM;
		goto e_free_hdr;
	}
	trans_data = vzalloc(params.trans_len);
	if (!trans_data) {
		ret = -ENOMEM;
		goto e_free_trans_block;
	}

	for (offset = 0, i = 0; offset < params.trans_len; offset += PAGE_SIZE) {
		pfn = vmalloc_to_pfn(offset + trans_data);
		trans_block->trans_paddr[i] = __sme_set(pfn_to_hpa(pfn));
		i++;
	}

	memset(&data, 0, sizeof(data));
	data.hdr_address = __psp_pa(hdr);
	data.hdr_len = params.hdr_len;
	data.trans_block = __psp_pa(trans_block);
	data.trans_len = params.trans_len;
	data.handle = sev->handle;

	/* flush hdr, trans data, trans block, secure VMSAs */
	wbinvd_on_all_cpus();

	ret = csv_issue_cmd(kvm, CSV3_CMD_SEND_ENCRYPT_CONTEXT, &data, &argp->error);

	if (ret)
		goto e_free_trans_data;

	/* copy transport buffer to user space */
	if (copy_to_user((void __user *)(uintptr_t)params.trans_uaddr,
			 trans_data, params.trans_len)) {
		ret = -EFAULT;
		goto e_free_trans_data;
	}

	/* copy packet header to userspace. */
	if (copy_to_user((void __user *)(uintptr_t)params.hdr_uaddr, hdr,
			 params.hdr_len)) {
		ret = -EFAULT;
		goto e_free_trans_data;
	}

e_free_trans_data:
	vfree(trans_data);
e_free_trans_block:
	kfree(trans_block);
e_free_hdr:
	kfree(hdr);
exit:
	return ret;
}

static int csv3_receive_encrypt_data(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct csv3_data_receive_encrypt_data data;
	struct kvm_csv3_receive_encrypt_data params;
	void *hdr;
	void *trans_data;
	struct trans_paddr_block *trans_block;
	struct guest_paddr_block *guest_block;
	unsigned long pfn;
	int i;
	u32 offset;
	int ret = 0;

	if (!csv3_guest(kvm))
		return -ENOTTY;

	if (unlikely(list_empty(&csv->smr_list))) {
		/* Allocate all the guest memory from CMA */
		ret = csv3_set_guest_private_memory(kvm);
		if (ret)
			goto exit;
	}

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			   sizeof(params)))
		return -EFAULT;

	if (!params.hdr_uaddr || !params.hdr_len ||
	    !params.guest_addr_data || !params.guest_addr_len ||
	    !params.trans_uaddr || !params.trans_len)
		return -EINVAL;

	if (params.guest_addr_len > sizeof(*guest_block))
		return -EINVAL;

	if (params.trans_len > ARRAY_SIZE(trans_block->trans_paddr) * PAGE_SIZE)
		return -EINVAL;

	/* allocate memory for header and transport buffer */
	hdr = kzalloc(params.hdr_len, GFP_KERNEL_ACCOUNT);
	if (!hdr) {
		ret = -ENOMEM;
		goto exit;
	}

	if (copy_from_user(hdr,
			   (void __user *)(uintptr_t)params.hdr_uaddr,
			   params.hdr_len)) {
		ret = -EFAULT;
		goto e_free_hdr;
	}

	guest_block = kzalloc(sizeof(*guest_block), GFP_KERNEL_ACCOUNT);
	if (!guest_block) {
		ret = -ENOMEM;
		goto e_free_hdr;
	}

	if (copy_from_user(guest_block,
			   (void __user *)(uintptr_t)params.guest_addr_data,
			   params.guest_addr_len)) {
		ret = -EFAULT;
		goto e_free_guest_block;
	}

	trans_block = kzalloc(sizeof(*trans_block), GFP_KERNEL_ACCOUNT);
	if (!trans_block) {
		ret = -ENOMEM;
		goto e_free_guest_block;
	}
	trans_data = vzalloc(params.trans_len);
	if (!trans_data) {
		ret = -ENOMEM;
		goto e_free_trans_block;
	}

	if (copy_from_user(trans_data,
			   (void __user *)(uintptr_t)params.trans_uaddr,
			   params.trans_len)) {
		ret = -EFAULT;
		goto e_free_trans_data;
	}

	for (offset = 0, i = 0; offset < params.trans_len; offset += PAGE_SIZE) {
		pfn = vmalloc_to_pfn(offset + trans_data);
		trans_block->trans_paddr[i] = __sme_set(pfn_to_hpa(pfn));
		i++;
	}

	memset(&data, 0, sizeof(data));
	data.hdr_address = __psp_pa(hdr);
	data.hdr_len = params.hdr_len;
	data.trans_block = __psp_pa(trans_block);
	data.trans_len = params.trans_len;
	data.guest_block = __psp_pa(guest_block);
	data.guest_len = params.guest_addr_len;
	data.handle = sev->handle;

	clflush_cache_range(hdr, params.hdr_len);
	clflush_cache_range(trans_data, params.trans_len);
	clflush_cache_range(trans_block, PAGE_SIZE);
	clflush_cache_range(guest_block, PAGE_SIZE);
	ret = csv_issue_cmd(kvm, CSV3_CMD_RECEIVE_ENCRYPT_DATA, &data,
			    &argp->error);

e_free_trans_data:
	vfree(trans_data);
e_free_trans_block:
	kfree(trans_block);
e_free_guest_block:
	kfree(guest_block);
e_free_hdr:
	kfree(hdr);
exit:
	return ret;
}

static int csv3_receive_encrypt_context(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct csv3_data_receive_encrypt_context data;
	struct kvm_csv3_receive_encrypt_context params;
	void *hdr;
	void *trans_data;
	struct trans_paddr_block *trans_block;
	struct vmcb_paddr_block *shadow_vmcb_block;
	struct vmcb_paddr_block *secure_vmcb_block;
	unsigned long pfn;
	u32 offset;
	int ret = 0;
	struct kvm_vcpu *vcpu;
	unsigned long i;

	if (!csv3_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			   sizeof(params)))
		return -EFAULT;

	if (!params.trans_uaddr || !params.trans_len ||
	    !params.hdr_uaddr || !params.hdr_len)
		return -EINVAL;

	if (params.trans_len > ARRAY_SIZE(trans_block->trans_paddr) * PAGE_SIZE)
		return -EINVAL;

	/* allocate memory for header and transport buffer */
	hdr = kzalloc(params.hdr_len, GFP_KERNEL_ACCOUNT);
	if (!hdr) {
		ret = -ENOMEM;
		goto exit;
	}

	if (copy_from_user(hdr,
			   (void __user *)(uintptr_t)params.hdr_uaddr,
			   params.hdr_len)) {
		ret = -EFAULT;
		goto e_free_hdr;
	}

	trans_block = kzalloc(sizeof(*trans_block), GFP_KERNEL_ACCOUNT);
	if (!trans_block) {
		ret = -ENOMEM;
		goto e_free_hdr;
	}
	trans_data = vzalloc(params.trans_len);
	if (!trans_data) {
		ret = -ENOMEM;
		goto e_free_trans_block;
	}

	if (copy_from_user(trans_data,
			   (void __user *)(uintptr_t)params.trans_uaddr,
			   params.trans_len)) {
		ret = -EFAULT;
		goto e_free_trans_data;
	}

	for (offset = 0, i = 0; offset < params.trans_len; offset += PAGE_SIZE) {
		pfn = vmalloc_to_pfn(offset + trans_data);
		trans_block->trans_paddr[i] = __sme_set(pfn_to_hpa(pfn));
		i++;
	}

	secure_vmcb_block = kzalloc(sizeof(*secure_vmcb_block),
				    GFP_KERNEL_ACCOUNT);
	if (!secure_vmcb_block) {
		ret = -ENOMEM;
		goto e_free_trans_data;
	}

	shadow_vmcb_block = kzalloc(sizeof(*shadow_vmcb_block),
				    GFP_KERNEL_ACCOUNT);
	if (!shadow_vmcb_block) {
		ret = -ENOMEM;
		goto e_free_secure_vmcb_block;
	}

	memset(&data, 0, sizeof(data));

	kvm_for_each_vcpu(i, vcpu, kvm) {
		struct vcpu_svm *svm = to_svm(vcpu);

		if (i >= ARRAY_SIZE(shadow_vmcb_block->vmcb_paddr)) {
			ret = -EINVAL;
			goto e_free_shadow_vmcb_block;
		}
		shadow_vmcb_block->vmcb_paddr[i] = __sme_pa(svm->vmcb);
		data.vmcb_block_len += sizeof(shadow_vmcb_block->vmcb_paddr[0]);
	}

	data.hdr_address = __psp_pa(hdr);
	data.hdr_len = params.hdr_len;
	data.trans_block = __psp_pa(trans_block);
	data.trans_len = params.trans_len;
	data.shadow_vmcb_block = __psp_pa(shadow_vmcb_block);
	data.secure_vmcb_block = __psp_pa(secure_vmcb_block);
	data.handle = sev->handle;

	clflush_cache_range(hdr, params.hdr_len);
	clflush_cache_range(trans_data, params.trans_len);
	clflush_cache_range(trans_block, PAGE_SIZE);
	clflush_cache_range(shadow_vmcb_block, PAGE_SIZE);
	clflush_cache_range(secure_vmcb_block, PAGE_SIZE);

	ret = csv_issue_cmd(kvm, CSV3_CMD_RECEIVE_ENCRYPT_CONTEXT, &data,
			    &argp->error);
	if (ret)
		goto e_free_shadow_vmcb_block;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		struct vcpu_svm *svm = to_svm(vcpu);

		if (i >= ARRAY_SIZE(secure_vmcb_block->vmcb_paddr)) {
			ret = -EINVAL;
			goto e_free_shadow_vmcb_block;
		}

		svm->current_vmcb->pa = secure_vmcb_block->vmcb_paddr[i];
		svm->vcpu.arch.guest_state_protected = true;
	}

e_free_shadow_vmcb_block:
	kfree(shadow_vmcb_block);
e_free_secure_vmcb_block:
	kfree(secure_vmcb_block);
e_free_trans_data:
	vfree(trans_data);
e_free_trans_block:
	kfree(trans_block);
e_free_hdr:
	kfree(hdr);
exit:
	return ret;
}

static void csv3_mark_page_dirty(struct kvm_vcpu *vcpu, gva_t gpa,
				 unsigned long npages)
{
	gfn_t gfn;
	gfn_t gfn_end;

	gfn = gpa >> PAGE_SHIFT;
	gfn_end = gfn + npages;
#ifdef KVM_HAVE_MMU_RWLOCK
	write_lock(&vcpu->kvm->mmu_lock);
#else
	spin_lock(&vcpu->kvm->mmu_lock);
#endif
	for (; gfn < gfn_end; gfn++)
		kvm_vcpu_mark_page_dirty(vcpu, gfn);
#ifdef KVM_HAVE_MMU_RWLOCK
	write_unlock(&vcpu->kvm->mmu_lock);
#else
	spin_unlock(&vcpu->kvm->mmu_lock);
#endif
}

static int csv3_mmio_page_fault(struct kvm_vcpu *vcpu, gva_t gpa, u32 error_code)
{
	int r = 0;
	struct kvm_svm *kvm_svm = to_kvm_svm(vcpu->kvm);
	union csv3_page_attr page_attr = {.mmio = 1};
	union csv3_page_attr page_attr_mask = {.mmio = 1};
	struct csv3_data_update_npt *update_npt;
	int psp_ret;

	update_npt = kzalloc(sizeof(*update_npt), GFP_KERNEL);
	if (!update_npt) {
		r = -ENOMEM;
		goto exit;
	}

	csv3_init_update_npt(update_npt, gpa, error_code,
			     kvm_svm->sev_info.handle);
	update_npt->page_attr = page_attr.val;
	update_npt->page_attr_mask = page_attr_mask.val;
	update_npt->level = CSV3_PG_LEVEL_4K;

	r = csv_issue_cmd(vcpu->kvm, CSV3_CMD_UPDATE_NPT, update_npt, &psp_ret);

	if (psp_ret != SEV_RET_SUCCESS)
		r = -EFAULT;

	kfree(update_npt);
exit:
	return r;
}

static int __csv3_page_fault(struct kvm_vcpu *vcpu, gva_t gpa,
			     u32 error_code, struct kvm_memory_slot *slot,
			     int *psp_ret_ptr, kvm_pfn_t pfn, u32 level)
{
	int r = 0;
	struct csv3_data_update_npt *update_npt;
	struct kvm_svm *kvm_svm = to_kvm_svm(vcpu->kvm);
	int psp_ret = 0;

	update_npt = kzalloc(sizeof(*update_npt), GFP_KERNEL);
	if (!update_npt) {
		r = -ENOMEM;
		goto exit;
	}

	csv3_init_update_npt(update_npt, gpa, error_code,
			     kvm_svm->sev_info.handle);

	update_npt->spa = pfn << PAGE_SHIFT;
	update_npt->level = level;

	if (!csv3_is_mmio_pfn(pfn))
		update_npt->spa |= sme_me_mask;

	r = csv_issue_cmd(vcpu->kvm, CSV3_CMD_UPDATE_NPT, update_npt, &psp_ret);

	kvm_make_request(KVM_REQ_TLB_FLUSH, vcpu);
	kvm_flush_remote_tlbs(vcpu->kvm);

	csv3_mark_page_dirty(vcpu, update_npt->gpa, update_npt->npages);

	if (psp_ret_ptr)
		*psp_ret_ptr = psp_ret;

	kfree(update_npt);
exit:
	return r;
}

static int csv3_pin_shared_memory(struct kvm_vcpu *vcpu,
				  struct kvm_memory_slot *slot, gfn_t gfn,
				  kvm_pfn_t *pfn)
{
	struct page **pages, *page;
	u64 hva;
	int npinned;
	kvm_pfn_t tmp_pfn;
	struct kvm *kvm = vcpu->kvm;
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct shared_page_block *shared_page_block = NULL;
	u64 npages = PAGE_SIZE / sizeof(struct page *);
	bool write = !(slot->flags & KVM_MEM_READONLY);

	tmp_pfn = __gfn_to_pfn_memslot(slot, gfn, false, false, NULL, write,
				       NULL, NULL);
	if (unlikely(is_error_pfn(tmp_pfn)))
		return -ENOMEM;

	if (csv3_is_mmio_pfn(tmp_pfn)) {
		*pfn = tmp_pfn;
		return 0;
	}

	if (!page_maybe_dma_pinned(pfn_to_page(tmp_pfn))) {
		kvm_release_pfn_clean(tmp_pfn);
		if (csv->total_shared_page_count % npages == 0) {
			shared_page_block = kzalloc(sizeof(*shared_page_block),
						    GFP_KERNEL_ACCOUNT);
			if (!shared_page_block)
				return -ENOMEM;

			pages = kzalloc(PAGE_SIZE, GFP_KERNEL_ACCOUNT);
			if (!pages) {
				kfree(shared_page_block);
				return -ENOMEM;
			}

			shared_page_block->pages = pages;
			list_add_tail(&shared_page_block->list,
				      &csv->shared_pages_list);
			csv->cached_shared_page_block = shared_page_block;
		} else {
			shared_page_block = csv->cached_shared_page_block;
			pages = shared_page_block->pages;
		}

		hva = __gfn_to_hva_memslot(slot, gfn);
		npinned = pin_user_pages_fast(hva, 1, FOLL_WRITE | FOLL_LONGTERM,
					      &page);
		if (npinned != 1) {
			if (shared_page_block->count == 0) {
				list_del(&shared_page_block->list);
				kfree(pages);
				kfree(shared_page_block);
			}
			return -ENOMEM;
		}

		pages[csv->total_shared_page_count % npages] = page;
		shared_page_block->count++;
		csv->total_shared_page_count++;
		*pfn = page_to_pfn(page);
	} else {
		kvm_release_pfn_clean(tmp_pfn);
		*pfn = tmp_pfn;
	}

	return 0;
}

static int __pfn_mapping_level(struct kvm *kvm, gfn_t gfn,
			       const struct kvm_memory_slot *slot)
{
	int level = PG_LEVEL_4K;
	unsigned long hva;
	unsigned long flags;
	pgd_t pgd;
	p4d_t p4d;
	pud_t pud;
	pmd_t pmd;

	/*
	 * Note, using the already-retrieved memslot and __gfn_to_hva_memslot()
	 * is not solely for performance, it's also necessary to avoid the
	 * "writable" check in __gfn_to_hva_many(), which will always fail on
	 * read-only memslots due to gfn_to_hva() assuming writes.  Earlier
	 * page fault steps have already verified the guest isn't writing a
	 * read-only memslot.
	 */
	hva = __gfn_to_hva_memslot(slot, gfn);

	/*
	 * Disable IRQs to prevent concurrent tear down of host page tables,
	 * e.g. if the primary MMU promotes a P*D to a huge page and then frees
	 * the original page table.
	 */
	local_irq_save(flags);

	/*
	 * Read each entry once.  As above, a non-leaf entry can be promoted to
	 * a huge page _during_ this walk.  Re-reading the entry could send the
	 * walk into the weeks, e.g. p*d_large() returns false (sees the old
	 * value) and then p*d_offset() walks into the target huge page instead
	 * of the old page table (sees the new value).
	 */
	pgd = READ_ONCE(*pgd_offset(kvm->mm, hva));
	if (pgd_none(pgd))
		goto out;

	p4d = READ_ONCE(*p4d_offset(&pgd, hva));
	if (p4d_none(p4d) || !p4d_present(p4d))
		goto out;

	pud = READ_ONCE(*pud_offset(&p4d, hva));
	if (pud_none(pud) || !pud_present(pud))
		goto out;

	if (pud_large(pud)) {
		level = PG_LEVEL_1G;
		goto out;
	}

	pmd = READ_ONCE(*pmd_offset(&pud, hva));
	if (pmd_none(pmd) || !pmd_present(pmd))
		goto out;

	if (pmd_large(pmd))
		level = PG_LEVEL_2M;

out:
	local_irq_restore(flags);
	return level;
}

static int csv3_mapping_level(struct kvm_vcpu *vcpu, gfn_t gfn, kvm_pfn_t pfn,
			      struct kvm_memory_slot *slot)
{
	int level;
	int page_num;
	gfn_t gfn_base;

	if (csv3_is_mmio_pfn(pfn)) {
		level = PG_LEVEL_4K;
		goto end;
	}

	if (!PageCompound(pfn_to_page(pfn))) {
		level = PG_LEVEL_4K;
		goto end;
	}

	level = PG_LEVEL_2M;
	page_num = KVM_PAGES_PER_HPAGE(level);
	gfn_base = gfn & ~(page_num - 1);

	/*
	 * 2M aligned guest address in memslot.
	 */
	if ((gfn_base < slot->base_gfn) ||
	    (gfn_base + page_num > slot->base_gfn + slot->npages)) {
		level = PG_LEVEL_4K;
		goto end;
	}

	/*
	 * hva in memslot is 2M aligned.
	 */
	if (__gfn_to_hva_memslot(slot, gfn_base) & ~PMD_MASK) {
		level = PG_LEVEL_4K;
		goto end;
	}

	level = __pfn_mapping_level(vcpu->kvm, gfn, slot);

	/*
	 * Firmware supports 2M/4K level.
	 */
	level = level > PG_LEVEL_2M ? PG_LEVEL_2M : level;

end:
	return to_csv3_pg_level(level);
}

static int csv3_page_fault(struct kvm_vcpu *vcpu, struct kvm_memory_slot *slot,
			   gfn_t gfn, u32 error_code)
{
	int ret = 0;
	int psp_ret = 0;
	int level;
	kvm_pfn_t pfn;
	struct kvm_csv_info *csv = &to_kvm_svm_csv(vcpu->kvm)->csv_info;

	if (error_code & PFERR_PRESENT_MASK)
		level = CSV3_PG_LEVEL_4K;
	else {
		mutex_lock(&csv->shared_page_block_lock);
		ret = csv3_pin_shared_memory(vcpu, slot, gfn, &pfn);
		mutex_unlock(&csv->shared_page_block_lock);
		if (ret)
			goto exit;

		level = csv3_mapping_level(vcpu, gfn, pfn, slot);
	}

	ret = __csv3_page_fault(vcpu, gfn << PAGE_SHIFT, error_code, slot,
				&psp_ret, pfn, level);

	if (psp_ret != SEV_RET_SUCCESS)
		ret = -EFAULT;
exit:
	return ret;
}

static void csv_vm_destroy(struct kvm *kvm)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct list_head *head = &csv->shared_pages_list;
	struct list_head *pos, *q;
	struct shared_page_block *shared_page_block;
	struct kvm_vcpu *vcpu;
	unsigned long i = 0;

	struct list_head *smr_head = &csv->smr_list;
	struct secure_memory_region *smr;

	if (csv3_guest(kvm)) {
		mutex_lock(&csv->shared_page_block_lock);
		if (!list_empty(head)) {
			list_for_each_safe(pos, q, head) {
				shared_page_block = list_entry(pos,
						struct shared_page_block, list);
				unpin_user_pages(shared_page_block->pages,
						shared_page_block->count);
				kfree(shared_page_block->pages);
				csv->total_shared_page_count -=
					shared_page_block->count;
				list_del(&shared_page_block->list);
				kfree(shared_page_block);
			}
		}
		mutex_unlock(&csv->shared_page_block_lock);

		kvm_for_each_vcpu(i, vcpu, kvm) {
			struct vcpu_svm *svm = to_svm(vcpu);

			svm->current_vmcb->pa = __sme_pa(svm->vmcb);
		}
	}

	if (likely(csv_x86_ops.vm_destroy))
		csv_x86_ops.vm_destroy(kvm);

	if (!csv3_guest(kvm))
		return;

	/* free secure memory region */
	if (!list_empty(smr_head)) {
		list_for_each_safe(pos, q, smr_head) {
			smr = list_entry(pos, struct secure_memory_region, list);
			if (smr) {
				csv_release_to_contiguous(smr->hpa, smr->npages << PAGE_SHIFT);
				list_del(&smr->list);
				kfree(smr);
			}
		}
	}
}

static int csv3_handle_page_fault(struct kvm_vcpu *vcpu, gpa_t gpa,
				  u32 error_code)
{
	gfn_t gfn = gpa_to_gfn(gpa);
	struct kvm_memory_slot *slot = gfn_to_memslot(vcpu->kvm, gfn);
	int ret;
	int r = -EIO;

	if (kvm_is_visible_memslot(slot))
		ret = csv3_page_fault(vcpu, slot, gfn, error_code);
	else
		ret = csv3_mmio_page_fault(vcpu, gpa, error_code);

	if (!ret)
		r = 1;

	return r;
}

static int csv_handle_exit(struct kvm_vcpu *vcpu, fastpath_t exit_fastpath)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	u32 exit_code = svm->vmcb->control.exit_code;
	int ret = -EIO;

	/*
	 * NPF for csv3 is dedicated.
	 */
	if (csv3_guest(vcpu->kvm) && exit_code == SVM_EXIT_NPF) {
		gpa_t gpa = __sme_clr(svm->vmcb->control.exit_info_2);
		u64 error_code = svm->vmcb->control.exit_info_1;

		ret = csv3_handle_page_fault(vcpu, gpa, error_code);
	} else {
		if (likely(csv_x86_ops.handle_exit))
			ret = csv_x86_ops.handle_exit(vcpu, exit_fastpath);
	}

	return ret;
}

static void csv_guest_memory_reclaimed(struct kvm *kvm)
{
	if (!csv3_guest(kvm)) {
		if (likely(csv_x86_ops.guest_memory_reclaimed))
			csv_x86_ops.guest_memory_reclaimed(kvm);
	}
}

static int csv_mem_enc_op(struct kvm *kvm, void __user *argp)
{
	struct kvm_sev_cmd sev_cmd;
	int r = -EINVAL;

	if (!argp)
		return 0;

	if (copy_from_user(&sev_cmd, argp, sizeof(struct kvm_sev_cmd)))
		return -EFAULT;

	mutex_lock(&kvm->lock);

	switch (sev_cmd.id) {
	case KVM_CSV3_INIT:
		r = csv3_guest_init(kvm, &sev_cmd);
		break;
	case KVM_CSV3_LAUNCH_ENCRYPT_DATA:
		r = csv3_launch_encrypt_data(kvm, &sev_cmd);
		break;
	case KVM_CSV3_LAUNCH_ENCRYPT_VMCB:
		r = csv3_launch_encrypt_vmcb(kvm, &sev_cmd);
		break;
	case KVM_CSV3_SEND_ENCRYPT_DATA:
		r = csv3_send_encrypt_data(kvm, &sev_cmd);
		break;
	case KVM_CSV3_SEND_ENCRYPT_CONTEXT:
		r = csv3_send_encrypt_context(kvm, &sev_cmd);
		break;
	case KVM_CSV3_RECEIVE_ENCRYPT_DATA:
		r = csv3_receive_encrypt_data(kvm, &sev_cmd);
		break;
	case KVM_CSV3_RECEIVE_ENCRYPT_CONTEXT:
		r = csv3_receive_encrypt_context(kvm, &sev_cmd);
		break;
	default:
		mutex_unlock(&kvm->lock);
		if (likely(csv_x86_ops.mem_enc_ioctl))
			r = csv_x86_ops.mem_enc_ioctl(kvm, argp);
		goto out;
	}

	mutex_unlock(&kvm->lock);

	if (copy_to_user(argp, &sev_cmd, sizeof(struct kvm_sev_cmd)))
		r = -EFAULT;

out:
	return r;
}

void __init csv_init(struct kvm_x86_ops *ops)
{
	if (boot_cpu_has(X86_FEATURE_CSV3)) {
		memcpy(&csv_x86_ops, ops, sizeof(struct kvm_x86_ops));

		ops->mem_enc_ioctl = csv_mem_enc_op;
		ops->vm_destroy = csv_vm_destroy;
		ops->vm_size = sizeof(struct kvm_svm_csv);
		ops->handle_exit = csv_handle_exit;
		ops->guest_memory_reclaimed = csv_guest_memory_reclaimed;
	}
}
