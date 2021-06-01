// SPDX-License-Identifier: GPL-2.0-only
/*
 * This file contains the declaration of all the variables that at some point
 * in the boot process need to be fixup for XIP kernels: those are the variables
 * that are used *before* the MMU is enabled, when the XIP kernel is executed
 * in flash but writes to those variables in RAM.
 */
#include <linux/export.h>
#include <asm/pgtable.h>

#ifdef CONFIG_MMU
/* Offset between linear mapping virtual address and kernel load address */
unsigned long va_pa_offset __ro_after_init;
EXPORT_SYMBOL(va_pa_offset);

#ifdef CONFIG_64BIT
/* Offset between kernel mapping virtual address and kernel load address */
unsigned long va_kernel_pa_offset;
EXPORT_SYMBOL(va_kernel_pa_offset);
#endif

unsigned long va_kernel_xip_pa_offset;
EXPORT_SYMBOL(va_kernel_xip_pa_offset);

pgd_t trampoline_pg_dir[PTRS_PER_PGD] __page_aligned_bss;
pgd_t early_pg_dir[PTRS_PER_PGD] __initdata __aligned(PAGE_SIZE);

#ifndef __PAGETABLE_PMD_FOLDED
pmd_t trampoline_pmd[PTRS_PER_PMD] __page_aligned_bss;
pmd_t fixmap_pmd[PTRS_PER_PMD] __page_aligned_bss;
pmd_t early_pmd[PTRS_PER_PMD] __initdata __aligned(PAGE_SIZE);
#endif

pte_t fixmap_pte[PTRS_PER_PTE] __page_aligned_bss;

uintptr_t load_pa, load_sz;

#ifdef CONFIG_XIP_KERNEL
uintptr_t xiprom, xiprom_sz;
#endif

#endif /* CONFIG_MMU */

unsigned long kernel_virt_addr = KERNEL_LINK_ADDR;
EXPORT_SYMBOL(kernel_virt_addr);

void *_dtb_early_va __initdata;
uintptr_t _dtb_early_pa __initdata;

struct pt_alloc_ops _pt_ops __ro_after_init;

#include <asm/xip-fixup.h>
