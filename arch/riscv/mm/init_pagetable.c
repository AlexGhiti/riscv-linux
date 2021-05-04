// TODO copy paste from init.c, to change.
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/memblock.h>
#include <linux/initrd.h>
#include <linux/swap.h>
#include <linux/sizes.h>
#include <linux/of_fdt.h>
#include <linux/of_reserved_mem.h>
#include <linux/libfdt.h>
#include <linux/set_memory.h>
#include <linux/dma-map-ops.h>
#include <linux/crash_dump.h>

#include <asm/fixmap.h>
#include <asm/tlbflush.h>
#include <asm/sections.h>
#include <asm/soc.h>
#include <asm/io.h>
#include <asm/ptdump.h>
#include <asm/numa.h>

#include "../kernel/head.h"

#include "init_pagetable.h"

/*
 * All those functions are shared between setup_vm and setup_vm_final.
 *
 * All global variables used *before* the kernel mapping is established must be
 * 'fixup' for XIP kernel (since data in the flash cannot be written, their
 * addresses are modified using XIP_FIXUP before the MMU does that for us).
 * The goal is to continue sharing those functions, but they must not use global
 * variables as we will compile those functions without relocations *and* all the functions
 * before switching the MMU on will use relocations (so that we can relocate global
 * variables to the RAM automatically instead of doing it with XIP_FIXUP) and
 * we don't want to use relocations in setup_vm_final (as we would have to relocate
 * again the global variables...etc).
 *
 * setup_vm and before => relocatable
 * setup_vm_final => !relocatable
 * here => !relocatable
 *
 * Conclusion: those functions *must not* use global variables, only arguments
 * with preprocessed addresses are available!
 */

// TODO Not sure this is the best place to define those variables but they are
// shared between init.c and init_before_mmu.c
struct pt_alloc_ops pt_ops __ro_after_init;
pte_t fixmap_pte[PTRS_PER_PTE] __page_aligned_bss;
#ifndef __PAGETABLE_PMD_FOLDED
pmd_t fixmap_pmd[PTRS_PER_PMD] __page_aligned_bss;
#endif

void __init create_pte_mapping(pte_t *ptep,
				      uintptr_t va, phys_addr_t pa,
				      phys_addr_t sz, pgprot_t prot,
				      __attribute__((unused)) struct pt_alloc_ops *pt_ops)
{
	uintptr_t pte_idx = pte_index(va);

	BUG_ON(sz != PAGE_SIZE);

	if (pte_none(ptep[pte_idx]))
		ptep[pte_idx] = pfn_pte(PFN_DOWN(pa), prot);
}

void __init create_pmd_mapping(pmd_t *pmdp,
			       uintptr_t va, phys_addr_t pa,
			       phys_addr_t sz, pgprot_t prot,
			       struct pt_alloc_ops *pt_ops)
{
	pte_t *ptep;
	phys_addr_t pte_phys;
	uintptr_t pmd_idx = pmd_index(va);

	if (sz == PMD_SIZE) {
		if (pmd_none(pmdp[pmd_idx]))
			pmdp[pmd_idx] = pfn_pmd(PFN_DOWN(pa), prot);
		return;
	}

	if (pmd_none(pmdp[pmd_idx])) {
		pte_phys = pt_ops->alloc_pte(va);
		pmdp[pmd_idx] = pfn_pmd(PFN_DOWN(pte_phys), PAGE_TABLE);
		ptep = pt_ops->get_pte_virt(pte_phys);
		memset(ptep, 0, PAGE_SIZE);
	} else {
		pte_phys = PFN_PHYS(_pmd_pfn(pmdp[pmd_idx]));
		ptep = pt_ops->get_pte_virt(pte_phys);
	}

	create_pte_mapping(ptep, va, pa, sz, prot, pt_ops);
}

void __init create_pgd_mapping(pgd_t *pgdp,
			       uintptr_t va, phys_addr_t pa,
			       phys_addr_t sz, pgprot_t prot,
			       struct pt_alloc_ops *pt_ops)
{
	pgd_next_t *nextp;
	phys_addr_t next_phys;
	uintptr_t pgd_idx = pgd_index(va);

	if (sz == PGDIR_SIZE) {
		if (pgd_val(pgdp[pgd_idx]) == 0)
			pgdp[pgd_idx] = pfn_pgd(PFN_DOWN(pa), prot);
		return;
	}

	if (pgd_val(pgdp[pgd_idx]) == 0) {
		next_phys = alloc_pgd_next(va);
		pgdp[pgd_idx] = pfn_pgd(PFN_DOWN(next_phys), PAGE_TABLE);
		nextp = get_pgd_next_virt(next_phys);
		memset(nextp, 0, PAGE_SIZE);
	} else {
		next_phys = PFN_PHYS(_pgd_pfn(pgdp[pgd_idx]));
		nextp = get_pgd_next_virt(next_phys);
	}

	create_pgd_next_mapping(nextp, va, pa, sz, prot, pt_ops);
}

#ifdef CONFIG_XIP_KERNEL
void __init create_kernel_page_table(pgd_t *pgdir,
		uintptr_t map_size, uintptr_t kernel_vaddr,
		uintptr_t load_pa, uintptr_t load_sz,
		uintptr_t xiprom, uintptr_t xiprom_sz,
		struct pt_alloc_ops *pt_ops)
{
	uintptr_t va, end_va;

	/* Map the flash resident part */
	end_va = kernel_vaddr + xiprom_sz;
	for (va = kernel_vaddr; va < end_va; va += map_size)
		create_pgd_mapping(pgdir, va,
				   xiprom + (va - kernel_vaddr),
				   map_size, PAGE_KERNEL_EXEC);

	/* Map the data in RAM */
	end_va = kernel_vaddr + XIP_OFFSET + load_sz;
	for (va = kernel_vaddr + XIP_OFFSET; va < end_va; va += map_size)
		create_pgd_mapping(pgdir, va,
				   load_pa + (va - (kernel_vaddr + XIP_OFFSET)),
				   map_size, PAGE_KERNEL, pt_ops);
}
#else
void __init create_kernel_page_table(pgd_t *pgdir,
		uintptr_t map_size, uintptr_t kernel_vaddr,
		uintptr_t load_pa, uintptr_t load_sz,
		__attribute__((unused)) uintptr_t xiprom, __attribute__((unused)) uintptr_t xiprom_sz,
		struct pt_alloc_ops *pt_ops)
{
	uintptr_t va, end_va;

	end_va = kernel_vaddr + load_sz;
	for (va = kernel_vaddr; va < end_va; va += map_size)
		create_pgd_mapping(pgdir, va,
				   load_pa + (va - kernel_vaddr),
				   map_size, PAGE_KERNEL_EXEC, pt_ops);
}
#endif /* CONFIG_XIP_KERNEL */
