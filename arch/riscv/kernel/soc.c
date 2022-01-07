// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020 Western Digital Corporation or its affiliates.
 */
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/libfdt.h>
#include <linux/pgtable.h>
#include <asm/image.h>
#include <asm/soc.h>

struct soc_cache riscv_soc_cache;

/*
 * This is called extremly early, before parse_dtb(), to allow initializing
 * SoC hardware before memory or any device driver initialization.
 */
void __init soc_early_init(void)
{
	void (*early_fn)(const void *fdt);
	const struct of_device_id *s;
	const void *fdt = dtb_early_va;

	for (s = (void *)&__soc_early_init_table_start;
	     (void *)s < (void *)&__soc_early_init_table_end; s++) {
		if (!fdt_node_check_compatible(fdt, 0, s->compatible)) {
			early_fn = s->data;
			early_fn(fdt);
			return;
		}
	}
}

static u64 __init soc_fdt_uncached_offset(uintptr_t dtb_pa)
{
	u64 *uncached_offset;
	int np, ret, len;

	np = fdt_path_offset((void *)dtb_pa, "/soc");
	if (np < 0)
		return 0;

	uncached_offset = fdt_getprop((void *)dtb_pa, np, "uncached-offset", &len);

	return *uncached_offset;
}

// TODO Should be SoC names
// Actually we should be able to get is_dma_coherent from the dtb, how does arm do?
static void __init thead_init(uintptr_t dtb_pa)
{
	//pr_err("THEAD !!");

	riscv_soc_cache.is_dma_coherent = false;
	riscv_soc_cache.has_custom_cmo = true;
	riscv_soc_cache.uncached_offset = 0;

	__riscv_custom_pte.cache = 0x7000000000000000;
	__riscv_custom_pte.mask  = 0xf800000000000000;
	__riscv_custom_pte.io    = BIT(63);
	__riscv_custom_pte.wc    = 0;
}

static void __init sifive_unmatched_init(uintptr_t dtb_pa)
{
	//pr_err("SiFIVE UNMATCHED\n");

	riscv_soc_cache.is_dma_coherent = true;
	riscv_soc_cache.has_custom_cmo = false;
	riscv_soc_cache.uncached_offset = 0;
}

static void __init starfive_beaglev_init(uintptr_t dtb_pa)
{
	//pr_err("STARFIVE BEAGLEV\n");

	riscv_soc_cache.is_dma_coherent = false;
	riscv_soc_cache.has_custom_cmo = false;
	riscv_soc_cache.uncached_offset = soc_fdt_uncached_offset(dtb_pa);
}

void __init soc_setup_vm(uintptr_t dtb_pa)
{
	int root_node;
	char *model;

	root_node = fdt_path_offset((void *)dtb_pa, "/");
	if (root_node < 0)
		return;

	model = fdt_getprop((void *)dtb_pa, root_node, "model", NULL);

	strcpy(riscv_soc_cache.model, model);

	if (!strcmp(model, "Allwinner D1 NeZha"))
		thead_init(dtb_pa);
	else if (!strcmp(model, "SiFive HiFive Unmatched A00"))
		sifive_unmatched_init(dtb_pa);
	else if (!strcmp(model, "BeagleV Starlight Beta"))
		starfive_beaglev_init(dtb_pa);
	//else
	//	pr_err("Don't know this SOC %s !!\n", model);
}
