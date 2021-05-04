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

struct pt_alloc_ops {
	pte_t *(*get_pte_virt)(phys_addr_t pa);
	phys_addr_t (*alloc_pte)(uintptr_t va);
#ifndef __PAGETABLE_PMD_FOLDED
	pmd_t *(*get_pmd_virt)(phys_addr_t pa);
	phys_addr_t (*alloc_pmd)(uintptr_t va);
#endif
};

extern struct pt_alloc_ops pt_ops __ro_after_init;
extern pte_t fixmap_pte[PTRS_PER_PTE] __page_aligned_bss;
extern pmd_t fixmap_pmd[PTRS_PER_PMD] __page_aligned_bss;

#ifndef __PAGETABLE_PMD_FOLDED
#define pgd_next_t		pmd_t
#define alloc_pgd_next(__va)	pt_ops->alloc_pmd(__va)
#define get_pgd_next_virt(__pa)	pt_ops->get_pmd_virt(__pa)
#define create_pgd_next_mapping(__nextp, __va, __pa, __sz, __prot, __pt_ops)	\
	create_pmd_mapping(__nextp, __va, __pa, __sz, __prot, __pt_ops)
#define fixmap_pgd_next		fixmap_pmd
#else /* __PAGETABLE_PMD_FOLDED */
#define pgd_next_t		pte_t
#define alloc_pgd_next(__va)	pt_ops->alloc_pte(__va)
#define get_pgd_next_virt(__pa)	pt_ops->get_pte_virt(__pa)
#define create_pgd_next_mapping(__nextp, __va, __pa, __sz, __prot, __pt_ops)	\
	create_pte_mapping(__nextp, __va, __pa, __sz, __prot, __pt_ops)
#define fixmap_pgd_next		fixmap_pte
#endif /* __PAGETABLE_PMD_FOLDED */

void __init create_pte_mapping(pte_t *ptep,
				      uintptr_t va, phys_addr_t pa,
				      phys_addr_t sz, pgprot_t prot,
				      __attribute__((unused)) struct pt_alloc_ops *pt_ops);

void __init create_pmd_mapping(pmd_t *pmdp,
			       uintptr_t va, phys_addr_t pa,
			       phys_addr_t sz, pgprot_t prot,
			       struct pt_alloc_ops *pt_ops);

void __init create_pgd_mapping(pgd_t *pgdp,
			       uintptr_t va, phys_addr_t pa,
			       phys_addr_t sz, pgprot_t prot,
			       struct pt_alloc_ops *pt_ops);

void __init create_kernel_page_table(pgd_t *pgdir,
		uintptr_t map_size, uintptr_t kernel_vaddr,
		uintptr_t load_pa, uintptr_t load_sz,
		uintptr_t xiprom, uintptr_t xiprom_sz,
		struct pt_alloc_ops *pt_ops);
