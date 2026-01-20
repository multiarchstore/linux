// SPDX-License-Identifier: GPL-2.0
/*
 * Exceptions for specific devices. Usually work-arounds for fatal design flaws.
 */

#include <linux/pci.h>
#include <linux/logic_pio.h>
#include <linux/acpi.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/sizes.h>
#include <linux/mm.h>

#include <asm/loongson.h>
#include <asm/io.h>

/*
 * Find and fixup IO address for LPC Controller
 * According to the 2K2000 / 7A1000/2000 Chipset 
 * LPC Controller Specification, the IO address 
 * range of the LPC Controller is 64K, starting
 * from 0x1800,0000 to 0x1800,ffff
 */
static void pci_fixup_loongson_lpc_io(void)
{
	dev_info("LPC: Remapping LPC IO range to 0x18000000-0x1800ffff\n");
	unsigned long vaddr;
	struct logic_pio_hwaddr *range;
	struct fwnode_handle *fwnode;
	resource_size_t size;
	resource_size_t hw_start;
	struct pci_dev *dev;
    
    dev = pci_get_device(PCI_VENDOR_ID_LOONGSON, 0x7a0c, NULL);
	if (!dev) {
		dev_info("No LPC device found!\n");
		return;
	}

	fwnode = acpi_alloc_fwnode_static();
	hw_start = LOONGSON_LIO_BASE;
	size = SZ_64K;

	range = kzalloc(sizeof(*range), GFP_ATOMIC);
	if (!range) {
		acpi_free_fwnode_static(fwnode);
		return;
	}

	range->fwnode = fwnode;
	range->size = size = round_up(size, PAGE_SIZE);
	range->hw_start = hw_start;
	range->flags = LOGIC_PIO_CPU_MMIO;

	if (logic_pio_register_range(range)) {
		kfree(range);
		acpi_free_fwnode_static(fwnode);
		return;
	}

	/* Legacy ISA must placed at the start of PCI_IOBASE */
	if (range->io_start != 0) {
		logic_pio_unregister_range(range);
		kfree(range);
		acpi_free_fwnode_static(fwnode);
		return;
	}

	vaddr = (unsigned long)(PCI_IOBASE + range->io_start);
	vmap_page_range(vaddr, vaddr + size, hw_start, pgprot_device(PAGE_KERNEL));	
}
arch_initcall(pci_fixup_loongson_lpc_io);
