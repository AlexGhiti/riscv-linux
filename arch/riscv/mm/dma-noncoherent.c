// SPDX-License-Identifier: GPL-2.0-only
/*
 * DMA mapping implementation inspired from arm/mm/dma-mapping.c
 *
 * Copyright (c) 2021 Western Digital Corporation or its affiliates.
 */

#include <linux/dma-direct.h>
#include <linux/dma-map-ops.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/of.h>
#include <asm/cpu_ops.h>
#include <asm/sbi.h>
#include <asm/smp.h>

//TODO Do it through SBI
#include <soc/sifive/sifive_l2_cache.h>

u64 soc_uncached_offset;

void dma_non_coherent_setup(void)
{
	/* The uncached-offset property lies in the soc node, if it exists. */
	struct device_node *np;
	u64 uncached_offset;
	int ret;

	np = of_find_node_by_name(NULL, "soc");
	if (!np)
		return;

	ret = of_property_read_u64(np, "uncached-offset", &uncached_offset);
	if (!ret)
		soc_uncached_offset = uncached_offset;

	of_node_put(np);
}

void arch_sync_dma_for_device(phys_addr_t paddr, size_t size, enum dma_data_direction dir)
{
	if (soc_uncached_offset)
		sifive_l2_flush64_range(paddr, size);
}

void arch_sync_dma_for_cpu(phys_addr_t paddr, size_t size, enum dma_data_direction dir)
{
	if (soc_uncached_offset)
		sifive_l2_flush64_range(paddr, size);
}

void arch_setup_dma_ops(struct device *dev, u64 dma_base, u64 size,
		const struct iommu_ops *iommu, bool coherent)
{
	dev_info(dev, "coherent device %d dev->dma_coherent %d\n", coherent, dev->dma_coherent);
	dev->dma_coherent = coherent;
}

//TODO: We are supposed to invalidate the cache here
void arch_dma_prep_coherent(struct page *page, size_t size)
{
	if (soc_uncached_offset) {
		void *flush_addr = page_address(page);

		memset(flush_addr, 0, size);
		sifive_l2_flush64_range(__pa(flush_addr), size);
	}
}

void arch_dma_clear_uncached(void *addr, size_t size)
{
	if (soc_uncached_offset)
		memunmap(addr);
}

void *arch_dma_set_uncached(void *addr, size_t size)
{
	if (soc_uncached_offset) {
		phys_addr_t phys_addr = __pa(addr) + soc_uncached_offset;
		void *mem_base = NULL;

		mem_base = memremap(phys_addr, size, MEMREMAP_WT);
		if (!mem_base) {
			pr_err("%s memremap failed for addr %px\n", __func__, addr);
			return ERR_PTR(-EINVAL);
		}

		return mem_base;
	}

	return addr;
}
