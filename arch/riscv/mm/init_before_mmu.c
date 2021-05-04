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
 * This file needs to be relocatable since those functions are used before
 * MMU is enabled and then relocations are needed for all accesses to global
 * variables for xip kernels.
 */

pgd_t early_pg_dir[PTRS_PER_PGD] __initdata __aligned(PAGE_SIZE);
pgd_t trampoline_pg_dir[PTRS_PER_PGD] __page_aligned_bss;

pmd_t early_pmd[PTRS_PER_PMD] __initdata __aligned(PAGE_SIZE);
pmd_t trampoline_pmd[PTRS_PER_PMD] __page_aligned_bss;
pmd_t early_dtb_pmd[PTRS_PER_PMD] __initdata __aligned(PAGE_SIZE);

#define DTB_EARLY_BASE_VA      PGDIR_SIZE
void *_dtb_early_va __initdata;
uintptr_t _dtb_early_pa __initdata;

// TODO this is duplicated with init.c, but that should not go into init_pagetable.h, where so?
extern char _start[];
#ifdef CONFIG_XIP_KERNEL
extern char _xiprom[], _exiprom[];
extern char _sdata[], _edata[];
#endif /* CONFIG_XIP_KERNEL */

#ifdef CONFIG_XIP_KERNEL
/* called from head.S with MMU off */
asmlinkage void __init __copy_data(void)
{
	void *from = (void *)(&_sdata);
	void *end = (void *)(&_end);
	void *to = (void *)CONFIG_PHYS_RAM_BASE;
	size_t sz = (size_t)(end - from + 1);

	memcpy(to, from, sz);
}
#endif

static inline pte_t *__init get_pte_virt_early(phys_addr_t pa)
{
	return (pte_t *)((uintptr_t)pa);
}

static inline phys_addr_t __init alloc_pte_early(uintptr_t va)
{
	/*
	 * We only create PMD or PGD early mappings so we
	 * should never reach here with MMU disabled.
	 */
	BUG();
}

static pmd_t *__init get_pmd_virt_early(phys_addr_t pa)
{
	/* Before MMU is enabled */
	return (pmd_t *)((uintptr_t)pa);
}

static phys_addr_t __init alloc_pmd_early(uintptr_t va)
{
	BUG_ON((va - kernel_virt_addr) >> PGDIR_SHIFT);

	return (uintptr_t)early_pmd;
}

/*
 * setup_vm() is called from head.S with MMU-off.
 *
 * Following requirements should be honoured for setup_vm() to work
 * correctly:
 * 1) It should use PC-relative addressing for accessing kernel symbols.
 *    To achieve this we always use GCC cmodel=medany.
 * 2) The compiler instrumentation for FTRACE will not work for setup_vm()
 *    so disable compiler instrumentation when FTRACE is enabled.
 *
 * Currently, the above requirements are honoured by using custom CFLAGS
 * for init.o in mm/Makefile.
 */

#ifndef __riscv_cmodel_medany
#error "setup_vm() is called from head.S before relocate so it should not use absolute addressing."
#endif

#ifdef CONFIG_MMU
asmlinkage void __init setup_vm(uintptr_t dtb_pa)
{
	uintptr_t load_pa, load_sz;
	uintptr_t xiprom = 0, xiprom_sz = 0;
	uintptr_t __maybe_unused pa;
	uintptr_t map_size;
#ifndef __PAGETABLE_PMD_FOLDED
	pmd_t fix_bmap_spmd, fix_bmap_epmd;
#endif
#ifdef CONFIG_XIP_KERNEL
	xiprom = (uintptr_t)CONFIG_XIP_PHYS_ADDR;
	xiprom_sz = (uintptr_t)(&_exiprom) - (uintptr_t)(&_xiprom);

	load_pa = (uintptr_t)CONFIG_PHYS_RAM_BASE;
	load_sz = (uintptr_t)(&_end) - (uintptr_t)(&_sdata);

	va_kernel_xip_pa_offset = kernel_virt_addr - xiprom;
#else
	load_pa = (uintptr_t)(&_start);
	load_sz = (uintptr_t)(&_end) - load_pa;
#endif

	va_pa_offset = PAGE_OFFSET - load_pa;
#ifdef CONFIG_64BIT
	va_kernel_pa_offset = kernel_virt_addr - load_pa;
#endif

	pfn_base = PFN_DOWN(load_pa);

	/*
	 * Enforce boot alignment requirements of RV32 and
	 * RV64 by only allowing PMD or PGD mappings.
	 */
	map_size = PMD_SIZE;

	/* Sanity check alignment and size */
	BUG_ON((PAGE_OFFSET % PGDIR_SIZE) != 0);
	BUG_ON((load_pa % map_size) != 0);

	pt_ops.alloc_pte = alloc_pte_early;
	pt_ops.get_pte_virt = get_pte_virt_early;
#ifndef __PAGETABLE_PMD_FOLDED
	pt_ops.alloc_pmd = alloc_pmd_early;
	pt_ops.get_pmd_virt = get_pmd_virt_early;
#endif
	/* Setup early PGD for fixmap */
	create_pgd_mapping(early_pg_dir, FIXADDR_START,
			   (uintptr_t)fixmap_pgd_next, PGDIR_SIZE, PAGE_TABLE, &pt_ops);

#ifndef __PAGETABLE_PMD_FOLDED
	/* Setup fixmap PMD */
	create_pmd_mapping(fixmap_pmd, FIXADDR_START,
			   (uintptr_t)fixmap_pte, PMD_SIZE, PAGE_TABLE, &pt_ops);
	/* Setup trampoline PGD and PMD */
	create_pgd_mapping(trampoline_pg_dir, kernel_virt_addr,
			   (uintptr_t)trampoline_pmd, PGDIR_SIZE, PAGE_TABLE, &pt_ops);
#ifdef CONFIG_XIP_KERNEL
	create_pmd_mapping(trampoline_pmd, kernel_virt_addr,
			   xiprom, PMD_SIZE, PAGE_KERNEL_EXEC, &pt_ops);
#else
	create_pmd_mapping(trampoline_pmd, kernel_virt_addr,
			   load_pa, PMD_SIZE, PAGE_KERNEL_EXEC, &pt_ops);
#endif
#else
	/* Setup trampoline PGD */
	create_pgd_mapping(trampoline_pg_dir, kernel_virt_addr,
			   load_pa, PGDIR_SIZE, PAGE_KERNEL_EXEC, &pt_ops);
#endif

	/*
	 * Setup early PGD covering entire kernel which will allow
	 * us to reach paging_init(). We map all memory banks later
	 * in setup_vm_final() below.
	 */
	create_kernel_page_table(early_pg_dir, map_size, kernel_virt_addr,
				 load_pa, load_sz, xiprom, xiprom_sz, &pt_ops);

#ifndef __PAGETABLE_PMD_FOLDED
	/* Setup early PMD for DTB */
	create_pgd_mapping(early_pg_dir, DTB_EARLY_BASE_VA,
			   (uintptr_t)early_dtb_pmd, PGDIR_SIZE, PAGE_TABLE, &pt_ops);
#ifndef CONFIG_BUILTIN_DTB
	/* Create two consecutive PMD mappings for FDT early scan */
	pa = dtb_pa & ~(PMD_SIZE - 1);
	create_pmd_mapping(early_dtb_pmd, DTB_EARLY_BASE_VA,
			   pa, PMD_SIZE, PAGE_KERNEL, &pt_ops);
	create_pmd_mapping(early_dtb_pmd, DTB_EARLY_BASE_VA + PMD_SIZE,
			   pa + PMD_SIZE, PMD_SIZE, PAGE_KERNEL, &pt_ops);
	dtb_early_va = (void *)DTB_EARLY_BASE_VA + (dtb_pa & (PMD_SIZE - 1));
#else /* CONFIG_BUILTIN_DTB */
#ifdef CONFIG_64BIT
	/*
	 * __va can't be used since it would return a linear mapping address
	 * whereas dtb_early_va will be used before setup_vm_final installs
	 * the linear mapping.
	 */
	dtb_early_va = kernel_mapping_pa_to_va(XIP_FIXUP(dtb_pa));
#else
	dtb_early_va = __va(dtb_pa);
#endif /* CONFIG_64BIT */
#endif /* CONFIG_BUILTIN_DTB */
#else
#ifndef CONFIG_BUILTIN_DTB
	/* Create two consecutive PGD mappings for FDT early scan */
	pa = dtb_pa & ~(PGDIR_SIZE - 1);
	create_pgd_mapping(early_pg_dir, DTB_EARLY_BASE_VA,
			   pa, PGDIR_SIZE, PAGE_KERNEL, &pt_ops);
	create_pgd_mapping(early_pg_dir, DTB_EARLY_BASE_VA + PGDIR_SIZE,
			   pa + PGDIR_SIZE, PGDIR_SIZE, PAGE_KERNEL, &pt_ops);
	dtb_early_va = (void *)DTB_EARLY_BASE_VA + (dtb_pa & (PGDIR_SIZE - 1));
#else /* CONFIG_BUILTIN_DTB */
#ifdef CONFIG_64BIT
	dtb_early_va = kernel_mapping_pa_to_va(XIP_FIXUP(dtb_pa));
#else
	dtb_early_va = __va(dtb_pa);
#endif /* CONFIG_64BIT */
#endif /* CONFIG_BUILTIN_DTB */
#endif
	dtb_early_pa = dtb_pa;

	/*
	 * Bootime fixmap only can handle PMD_SIZE mapping. Thus, boot-ioremap
	 * range can not span multiple pmds.
	 */
	BUILD_BUG_ON((__fix_to_virt(FIX_BTMAP_BEGIN) >> PMD_SHIFT)
		     != (__fix_to_virt(FIX_BTMAP_END) >> PMD_SHIFT));

#ifndef __PAGETABLE_PMD_FOLDED
	/*
	 * Early ioremap fixmap is already created as it lies within first 2MB
	 * of fixmap region. We always map PMD_SIZE. Thus, both FIX_BTMAP_END
	 * FIX_BTMAP_BEGIN should lie in the same pmd. Verify that and warn
	 * the user if not.
	 */
	fix_bmap_spmd = fixmap_pmd[pmd_index(__fix_to_virt(FIX_BTMAP_BEGIN))];
	fix_bmap_epmd = fixmap_pmd[pmd_index(__fix_to_virt(FIX_BTMAP_END))];
	if (pmd_val(fix_bmap_spmd) != pmd_val(fix_bmap_epmd)) {
		WARN_ON(1);
		pr_warn("fixmap btmap start [%08lx] != end [%08lx]\n",
			pmd_val(fix_bmap_spmd), pmd_val(fix_bmap_epmd));
		pr_warn("fix_to_virt(FIX_BTMAP_BEGIN): %08lx\n",
			fix_to_virt(FIX_BTMAP_BEGIN));
		pr_warn("fix_to_virt(FIX_BTMAP_END):   %08lx\n",
			fix_to_virt(FIX_BTMAP_END));

		pr_warn("FIX_BTMAP_END:       %d\n", FIX_BTMAP_END);
		pr_warn("FIX_BTMAP_BEGIN:     %d\n", FIX_BTMAP_BEGIN);
	}
#endif
}
#else
asmlinkage void __init setup_vm(uintptr_t dtb_pa)
{
	dtb_early_va = (void *)dtb_pa;
	dtb_early_pa = dtb_pa;
}
#endif /* CONFIG_MMU */
