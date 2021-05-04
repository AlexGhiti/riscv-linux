// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2012 Regents of the University of California
 * Copyright (C) 2019 Western Digital Corporation or its affiliates.
 * Copyright (C) 2020 FORTH-ICS/CARV
 *  Nick Kossifidis <mick@ics.forth.gr>
 */

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

unsigned long kernel_virt_addr = KERNEL_LINK_ADDR;
EXPORT_SYMBOL(kernel_virt_addr);

unsigned long empty_zero_page[PAGE_SIZE / sizeof(unsigned long)]
							__page_aligned_bss;
EXPORT_SYMBOL(empty_zero_page);

static phys_addr_t dma32_phys_limit __ro_after_init;

static void __init zone_sizes_init(void)
{
	unsigned long max_zone_pfns[MAX_NR_ZONES] = { 0, };

#ifdef CONFIG_ZONE_DMA32
	max_zone_pfns[ZONE_DMA32] = PFN_DOWN(dma32_phys_limit);
#endif
	max_zone_pfns[ZONE_NORMAL] = max_low_pfn;

	free_area_init(max_zone_pfns);
}

static void __init setup_zero_page(void)
{
	memset((void *)empty_zero_page, 0, PAGE_SIZE);
}

#if defined(CONFIG_MMU) && defined(CONFIG_DEBUG_VM)
static inline void print_mlk(char *name, unsigned long b, unsigned long t)
{
	pr_notice("%12s : 0x%08lx - 0x%08lx   (%4ld kB)\n", name, b, t,
		  (((t) - (b)) >> 10));
}

static inline void print_mlm(char *name, unsigned long b, unsigned long t)
{
	pr_notice("%12s : 0x%08lx - 0x%08lx   (%4ld MB)\n", name, b, t,
		  (((t) - (b)) >> 20));
}

static void __init print_vm_layout(void)
{
	pr_notice("Virtual kernel memory layout:\n");
	print_mlk("fixmap", (unsigned long)FIXADDR_START,
		  (unsigned long)FIXADDR_TOP);
	print_mlm("pci io", (unsigned long)PCI_IO_START,
		  (unsigned long)PCI_IO_END);
	print_mlm("vmemmap", (unsigned long)VMEMMAP_START,
		  (unsigned long)VMEMMAP_END);
	print_mlm("vmalloc", (unsigned long)VMALLOC_START,
		  (unsigned long)VMALLOC_END);
	print_mlm("lowmem", (unsigned long)PAGE_OFFSET,
		  (unsigned long)high_memory);
#ifdef CONFIG_64BIT
	print_mlm("kernel", (unsigned long)KERNEL_LINK_ADDR,
		  (unsigned long)ADDRESS_SPACE_END);
#endif
}
#else
static void print_vm_layout(void) { }
#endif /* CONFIG_DEBUG_VM */

void __init mem_init(void)
{
#ifdef CONFIG_FLATMEM
	BUG_ON(!mem_map);
#endif /* CONFIG_FLATMEM */

	high_memory = (void *)(__va(PFN_PHYS(max_low_pfn)));
	memblock_free_all();

	mem_init_print_info(NULL);
	print_vm_layout();
}

void __init setup_bootmem(void)
{
	phys_addr_t vmlinux_end = __pa_symbol(&_end);
	phys_addr_t vmlinux_start = __pa_symbol(&_start);
	phys_addr_t dram_end = memblock_end_of_DRAM();
	phys_addr_t max_mapped_addr = __pa(~(ulong)0);

#ifdef CONFIG_XIP_KERNEL
	vmlinux_start = __pa_symbol(&_sdata);
#endif

	/* The maximal physical memory size is -PAGE_OFFSET. */
	memblock_enforce_memory_limit(-PAGE_OFFSET);

	/*
	 * Reserve from the start of the kernel to the end of the kernel
	 * and make sure we align the reservation on PMD_SIZE since we will
	 * map the kernel in the linear mapping as read-only: we do not want
	 * any allocation to happen between _end and the next pmd aligned page.
	 */
	memblock_reserve(vmlinux_start, (vmlinux_end - vmlinux_start + PMD_SIZE - 1) & PMD_MASK);

	/*
	 * memblock allocator is not aware of the fact that last 4K bytes of
	 * the addressable memory can not be mapped because of IS_ERR_VALUE
	 * macro. Make sure that last 4k bytes are not usable by memblock
	 * if end of dram is equal to maximum addressable memory.
	 */
	if (max_mapped_addr == (dram_end - 1))
		memblock_set_current_limit(max_mapped_addr - 4096);

	min_low_pfn = PFN_UP(memblock_start_of_DRAM());
	max_low_pfn = max_pfn = PFN_DOWN(dram_end);

	dma32_phys_limit = min(4UL * SZ_1G, (unsigned long)PFN_PHYS(max_low_pfn));
	set_max_mapnr(max_low_pfn - ARCH_PFN_OFFSET);

	reserve_initrd_mem();
	/*
	 * If DTB is built in, no need to reserve its memblock.
	 * Otherwise, do reserve it but avoid using
	 * early_init_fdt_reserve_self() since __pa() does
	 * not work for DTB pointers that are fixmap addresses
	 */
	if (!IS_ENABLED(CONFIG_BUILTIN_DTB))
		memblock_reserve(dtb_early_pa, fdt_totalsize(dtb_early_va));

	early_init_fdt_scan_reserved_mem();
	dma_contiguous_reserve(dma32_phys_limit);
	memblock_allow_resize();
}

extern char _start[];
#ifdef CONFIG_XIP_KERNEL
extern char _xiprom[], _exiprom[];
extern char _sdata[], _edata[];
#endif /* CONFIG_XIP_KERNEL */

#ifdef CONFIG_MMU
/* Offset between linear mapping virtual address and kernel load address */
unsigned long va_pa_offset __ro_after_init;
EXPORT_SYMBOL(va_pa_offset);
/* Offset between kernel mapping virtual address and kernel load address */
#ifdef CONFIG_64BIT
unsigned long va_kernel_pa_offset __ro_after_init;
EXPORT_SYMBOL(va_kernel_pa_offset);
#endif
unsigned long va_kernel_xip_pa_offset __ro_after_init;
EXPORT_SYMBOL(va_kernel_xip_pa_offset);
unsigned long pfn_base __ro_after_init;
EXPORT_SYMBOL(pfn_base);

pgd_t swapper_pg_dir[PTRS_PER_PGD] __page_aligned_bss;

void __set_fixmap(enum fixed_addresses idx, phys_addr_t phys, pgprot_t prot)
{
	unsigned long addr = __fix_to_virt(idx);
	pte_t *ptep;

	BUG_ON(idx <= FIX_HOLE || idx >= __end_of_fixed_addresses);

	ptep = &fixmap_pte[pte_index(addr)];

	if (pgprot_val(prot))
		set_pte(ptep, pfn_pte(phys >> PAGE_SHIFT, prot));
	else
		pte_clear(&init_mm, addr, ptep);
	local_flush_tlb_page(addr);
}

static inline pte_t *__init get_pte_virt_fixmap(phys_addr_t pa)
{
	clear_fixmap(FIX_PTE);
	return (pte_t *)set_fixmap_offset(FIX_PTE, pa);
}

static inline pte_t *get_pte_virt_late(phys_addr_t pa)
{
	return (pte_t *) __va(pa);
}

static inline phys_addr_t __init alloc_pte_fixmap(uintptr_t va)
{
	return memblock_phys_alloc(PAGE_SIZE, PAGE_SIZE);
}

static phys_addr_t alloc_pte_late(uintptr_t va)
{
	unsigned long vaddr;

	vaddr = __get_free_page(GFP_KERNEL);
	BUG_ON(!vaddr || !pgtable_pte_page_ctor(virt_to_page(vaddr)));

	return __pa(vaddr);
}

static pmd_t *__init get_pmd_virt_fixmap(phys_addr_t pa)
{
	clear_fixmap(FIX_PMD);
	return (pmd_t *)set_fixmap_offset(FIX_PMD, pa);
}

static pmd_t *get_pmd_virt_late(phys_addr_t pa)
{
	return (pmd_t *) __va(pa);
}

static phys_addr_t __init alloc_pmd_fixmap(uintptr_t va)
{
	return memblock_phys_alloc(PAGE_SIZE, PAGE_SIZE);
}

static phys_addr_t alloc_pmd_late(uintptr_t va)
{
	unsigned long vaddr;

	vaddr = __get_free_page(GFP_KERNEL);
	BUG_ON(!vaddr);
	return __pa(vaddr);
}

static uintptr_t __init best_map_size(phys_addr_t base, phys_addr_t size)
{
	/* Upgrade to PMD_SIZE mappings whenever possible */
	if ((base & (PMD_SIZE - 1)) || (size & (PMD_SIZE - 1)))
		return PAGE_SIZE;

	return PMD_SIZE;
}

#if defined(CONFIG_64BIT) && !defined(CONFIG_XIP_KERNEL)
void protect_kernel_linear_mapping_text_rodata(void)
{
	unsigned long text_start = (unsigned long)lm_alias(_start);
	unsigned long init_text_start = (unsigned long)lm_alias(__init_text_begin);
	unsigned long rodata_start = (unsigned long)lm_alias(__start_rodata);
	unsigned long data_start = (unsigned long)lm_alias(_data);

	set_memory_ro(text_start, (init_text_start - text_start) >> PAGE_SHIFT);
	set_memory_nx(text_start, (init_text_start - text_start) >> PAGE_SHIFT);

	set_memory_ro(rodata_start, (data_start - rodata_start) >> PAGE_SHIFT);
	set_memory_nx(rodata_start, (data_start - rodata_start) >> PAGE_SHIFT);
}
#endif

static void __init setup_vm_final(void)
{
	uintptr_t load_pa, load_sz;
	uintptr_t xiprom = 0, xiprom_sz = 0;
	uintptr_t va, map_size;
	phys_addr_t pa, start, end;
	u64 i;

#ifdef CONFIG_XIP_KERNEL
	xiprom = (uintptr_t)CONFIG_XIP_PHYS_ADDR;
	xiprom_sz = (uintptr_t)__pa(&_exiprom) - (uintptr_t)__pa(&_xiprom);

	load_pa = (uintptr_t)CONFIG_PHYS_RAM_BASE;
	load_sz = (uintptr_t)__pa(&_end) - (uintptr_t)__pa(&_sdata);
#else
	load_pa = (uintptr_t)__pa(&_start);
	load_sz = (uintptr_t)__pa(&_end) - load_pa;
#endif

	/**
	 * MMU is enabled at this point. But page table setup is not complete yet.
	 * fixmap page table alloc functions should be used at this point
	 */
	pt_ops.alloc_pte = alloc_pte_fixmap;
	pt_ops.get_pte_virt = get_pte_virt_fixmap;
#ifndef __PAGETABLE_PMD_FOLDED
	pt_ops.alloc_pmd = alloc_pmd_fixmap;
	pt_ops.get_pmd_virt = get_pmd_virt_fixmap;
#endif
	/* Setup swapper PGD for fixmap */
	create_pgd_mapping(swapper_pg_dir, FIXADDR_START,
			   __pa_symbol(fixmap_pgd_next),
			   PGDIR_SIZE, PAGE_TABLE, &pt_ops);

	/* Map all memory banks in the linear mapping */
	for_each_mem_range(i, &start, &end) {
		if (start >= end)
			break;
		if (start <= __pa(PAGE_OFFSET) &&
		    __pa(PAGE_OFFSET) < end)
			start = __pa(PAGE_OFFSET);

		map_size = best_map_size(start, end - start);
		for (pa = start; pa < end; pa += map_size) {
			va = (uintptr_t)__va(pa);
			create_pgd_mapping(swapper_pg_dir, va, pa,
					   map_size,
#ifdef CONFIG_64BIT
					   PAGE_KERNEL,
#else
					   PAGE_KERNEL_EXEC,
#endif
					   &pt_ops
					);

		}
	}

	// TODO maybe that could be stubbed for 32b and then we'd get rid of this ifdef.
#ifdef CONFIG_64BIT
	/* Map the kernel */
	create_kernel_page_table(swapper_pg_dir, PMD_SIZE, kernel_virt_addr,
				 load_pa, load_sz, xiprom, xiprom_sz, &pt_ops);
#endif

	/* Clear fixmap PTE and PMD mappings */
	clear_fixmap(FIX_PTE);
	clear_fixmap(FIX_PMD);

	/* Move to swapper page table */
	csr_write(CSR_SATP, PFN_DOWN(__pa_symbol(swapper_pg_dir)) | SATP_MODE);
	local_flush_tlb_all();

	/* generic page allocation functions must be used to setup page table */
	pt_ops.alloc_pte = alloc_pte_late;
	pt_ops.get_pte_virt = get_pte_virt_late;
#ifndef __PAGETABLE_PMD_FOLDED
	pt_ops.alloc_pmd = alloc_pmd_late;
	pt_ops.get_pmd_virt = get_pmd_virt_late;
#endif
}
#else
static inline void setup_vm_final(void)
{
}
#endif /* CONFIG_MMU */

#ifdef CONFIG_STRICT_KERNEL_RWX
void __init protect_kernel_text_data(void)
{
	unsigned long text_start = (unsigned long)_start;
	unsigned long init_text_start = (unsigned long)__init_text_begin;
	unsigned long init_data_start = (unsigned long)__init_data_begin;
	unsigned long rodata_start = (unsigned long)__start_rodata;
	unsigned long data_start = (unsigned long)_data;
	unsigned long max_low = (unsigned long)(__va(PFN_PHYS(max_low_pfn)));

	set_memory_ro(text_start, (init_text_start - text_start) >> PAGE_SHIFT);
	set_memory_ro(init_text_start, (init_data_start - init_text_start) >> PAGE_SHIFT);
	set_memory_nx(init_data_start, (rodata_start - init_data_start) >> PAGE_SHIFT);
	/* rodata section is marked readonly in mark_rodata_ro */
	set_memory_nx(rodata_start, (data_start - rodata_start) >> PAGE_SHIFT);
	set_memory_nx(data_start, (max_low - data_start) >> PAGE_SHIFT);
}

void mark_rodata_ro(void)
{
	unsigned long rodata_start = (unsigned long)__start_rodata;
	unsigned long data_start = (unsigned long)_data;

	set_memory_ro(rodata_start, (data_start - rodata_start) >> PAGE_SHIFT);

	debug_checkwx();
}
#endif

#ifdef CONFIG_KEXEC_CORE
/*
 * reserve_crashkernel() - reserves memory for crash kernel
 *
 * This function reserves memory area given in "crashkernel=" kernel command
 * line parameter. The memory reserved is used by dump capture kernel when
 * primary kernel is crashing.
 */
static void __init reserve_crashkernel(void)
{
	unsigned long long crash_base = 0;
	unsigned long long crash_size = 0;
	unsigned long search_start = memblock_start_of_DRAM();
	unsigned long search_end = memblock_end_of_DRAM();

	int ret = 0;

	/*
	 * Don't reserve a region for a crash kernel on a crash kernel
	 * since it doesn't make much sense and we have limited memory
	 * resources.
	 */
#ifdef CONFIG_CRASH_DUMP
	if (is_kdump_kernel()) {
		pr_info("crashkernel: ignoring reservation request\n");
		return;
	}
#endif

	ret = parse_crashkernel(boot_command_line, memblock_phys_mem_size(),
				&crash_size, &crash_base);
	if (ret || !crash_size)
		return;

	crash_size = PAGE_ALIGN(crash_size);

	if (crash_base == 0) {
		/*
		 * Current riscv boot protocol requires 2MB alignment for
		 * RV64 and 4MB alignment for RV32 (hugepage size)
		 */
		crash_base = memblock_find_in_range(search_start, search_end,
						    crash_size, PMD_SIZE);

		if (crash_base == 0) {
			pr_warn("crashkernel: couldn't allocate %lldKB\n",
				crash_size >> 10);
			return;
		}
	} else {
		/* User specifies base address explicitly. */
		if (!memblock_is_region_memory(crash_base, crash_size)) {
			pr_warn("crashkernel: requested region is not memory\n");
			return;
		}

		if (memblock_is_region_reserved(crash_base, crash_size)) {
			pr_warn("crashkernel: requested region is reserved\n");
			return;
		}


		if (!IS_ALIGNED(crash_base, PMD_SIZE)) {
			pr_warn("crashkernel: requested region is misaligned\n");
			return;
		}
	}
	memblock_reserve(crash_base, crash_size);

	pr_info("crashkernel: reserved 0x%016llx - 0x%016llx (%lld MB)\n",
		crash_base, crash_base + crash_size, crash_size >> 20);

	crashk_res.start = crash_base;
	crashk_res.end = crash_base + crash_size - 1;
}
#endif /* CONFIG_KEXEC_CORE */

#ifdef CONFIG_CRASH_DUMP
/*
 * We keep track of the ELF core header of the crashed
 * kernel with a reserved-memory region with compatible
 * string "linux,elfcorehdr". Here we register a callback
 * to populate elfcorehdr_addr/size when this region is
 * present. Note that this region will be marked as
 * reserved once we call early_init_fdt_scan_reserved_mem()
 * later on.
 */
static int elfcore_hdr_setup(struct reserved_mem *rmem)
{
	elfcorehdr_addr = rmem->base;
	elfcorehdr_size = rmem->size;
	return 0;
}

RESERVEDMEM_OF_DECLARE(elfcorehdr, "linux,elfcorehdr", elfcore_hdr_setup);
#endif

void __init paging_init(void)
{
	setup_vm_final();
	setup_zero_page();
}

void __init misc_mem_init(void)
{
	early_memtest(min_low_pfn << PAGE_SHIFT, max_low_pfn << PAGE_SHIFT);
	arch_numa_init();
	sparse_init();
	zone_sizes_init();
#ifdef CONFIG_KEXEC_CORE
	reserve_crashkernel();
#endif
	memblock_dump_all();
}

#ifdef CONFIG_SPARSEMEM_VMEMMAP
int __meminit vmemmap_populate(unsigned long start, unsigned long end, int node,
			       struct vmem_altmap *altmap)
{
	return vmemmap_populate_basepages(start, end, node, NULL);
}
#endif
