// SPDX-License-Identifier: GPL-2.0
/*
 * Exceptions for specific devices. Usually work-arounds for fatal design flaws.
 */

#include <linux/bitfield.h>
#include <linux/delay.h>
#include <linux/dmi.h>
#include <linux/pci.h>
#include <linux/ioport.h>
#include <linux/suspend.h>
#include <linux/vgaarb.h>

#include <asm/loongson.h>

static void pci_fixup_loongson_LPC(struct pci_dev *dev)
{
	/*
	 * 2K2000 / 7A1000/2000 Chipset LPC Controller
	 * Find and fixup IO address for LPC Controller
	 */
	 int i;
	 struct resource *res;
	 resource_size_t size, start, stop;
	 for (i = 0; i < PCI_NUM_RESOURCES; ++i) {
		res = pci_resource_n(dev, i);
		size = pci_resource_len(dev, i);
		start = LOONGSON_LIO_BASE;
		stop = LOONGSON_LIO_BASE + size - 1;

		if(!pci_release_resource(dev, i)) {
			pr_warn("Failed to adjust resource %d:", i);
			continue;
		}

		if(!adjust_resource(res, start, stop)) {
			pr_warn("Failed to adjust resource for %d\n", i);
			continue;
		}

		if(!pci_claim_resource(dev, i)) {
			pr_err("Failed to claim resource %d\n", i);
			continue;
		}

		pci_update_resource(dev, i);
	 }
}
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_LOONGSON, 0x7a0c, pci_fixup_loongson_LPC);