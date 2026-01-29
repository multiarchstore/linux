// arch/loongarch/pci/fixup.c
#include <linux/pci.h>
#include <linux/logic_pio.h>
#include <linux/vmalloc.h>
#include <linux/ioport.h>
#include <linux/sizes.h>
#include <asm/loongson.h>
#include <asm/io.h>

/*
 * Fixup for LPC controller's I/O Space
 * Hardware provides ISA I/O at physical address 0x18000000 (64KB range).
 * This quirk establishes the mapping early during PCI enumeration.
 */
static void loongson_lpc_io_quirk(struct pci_dev *dev)
{
	struct logic_pio_hwaddr *range;
	unsigned long vaddr;
	int ret;

	pr_info("PCI: Setting up Legacy ISA I/O for Seewo CB.L3A6.MA01\n");

	range = kzalloc(sizeof(*range), GFP_KERNEL);
	if (!range) {
		pr_err("PCI: Failed to allocate PIO range descriptor\n");
		return;
	}

	range->fwnode = acpi_alloc_fwnode_static(); /* ACPI 已初始化，安全调用 */
	if (!range->fwnode) {
		pr_err("PCI: Failed to allocate ACPI fwnode\n");
		kfree(range);
		return;
	}

	range->size = round_up(SZ_64K, PAGE_SIZE);
	range->hw_start = LOONGSON_LIO_BASE;
	range->flags = LOGIC_PIO_CPU_MMIO;

	ret = logic_pio_register_range(range);
	if (ret) {
		pr_err("PCI: logic_pio_register_range failed (%d)\n", ret);
		acpi_free_fwnode_static(range->fwnode);
		kfree(range);
		return;
	}

	if (range->io_start != 0) {
		pr_crit("PCI: FATAL - ISA range not at logical start (io_start=%lu)\n",
			range->io_start);
		logic_pio_unregister_range(range);
		acpi_free_fwnode_static(range->fwnode);
		kfree(range);
		return;
	}

	vaddr = (unsigned long)(PCI_IOBASE + range->io_start);
	ret = vmap_page_range(vaddr, vaddr + range->size,
			      range->hw_start,
			      pgprot_device(PAGE_KERNEL));
	if (ret < 0) {
		pr_err("PCI: vmap_page_range failed (%d)\n", ret);
		logic_pio_unregister_range(range);
		acpi_free_fwnode_static(range->fwnode);
		kfree(range);
		return;
	}

	pr_info("PCI: Legacy ISA mapped [0x%08lx-0x%08lx] → [0x%08llx-0x%08llx]\n",
		vaddr, vaddr + range->size - 1,
		range->hw_start, range->hw_start + range->size - 1);
}

DECLARE_PCI_FIXUP_EARLY(PCI_VENDOR_ID_LOONGSON, 0x7a0c, loongson_lpc_io_quirk);
