// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 SiFive
 * Copyright (C) 2020 Zong Li <zong.li@sifive.com>
 */

#include <linux/libfdt.h>
#include <linux/timex.h>
#include <linux/random.h>
#include <linux/set_memory.h>
#include <asm/cacheflush.h>

extern char _start[], _end[];
extern void *dtb_early_va;
extern phys_addr_t dtb_early_pa;
extern void secondary_random_target(void);
extern void kaslr_create_page_table(uintptr_t start, uintptr_t end);

uintptr_t secondary_next_target __initdata;
static uintptr_t kaslr_offset __initdata;

static const __init u32 *get_reg_address(int root_cells,
					 const u32 *value, u64 *result)
{
	int cell;
	*result = 0;

	for (cell = root_cells; cell > 0; --cell)
		*result = (*result << 32) + fdt32_to_cpu(*value++);

	return value;
}

static __init int get_node_addr_size_cells(const char *path, int *addr_cell,
					   int *size_cell)
{
	int node = fdt_path_offset(dtb_early_va, path);
	fdt64_t *prop;

	if (node < 0)
		return -EINVAL;

	prop = fdt_getprop_w(dtb_early_va, node, "#address-cells", NULL);
	if (!prop)
		return -EINVAL;
	*addr_cell = fdt32_to_cpu(*prop);

	prop = fdt_getprop_w(dtb_early_va, node, "#size-cells", NULL);
	if (!prop)
		return -EINVAL;
	*size_cell = fdt32_to_cpu(*prop);

	return node;
}

static __init void kaslr_get_mem_info(uintptr_t *mem_start,
				      uintptr_t *mem_size)
				      uintptr_t kernel_size, int find_index)
{
	int node, root, addr_cells, size_cells, idx = 0;
	u64 base, size;

	/* Get root node's address cells and size cells. */
	root = get_node_addr_size_cells("/", &addr_cells, &size_cells);
	if (root < 0)
		return;

	/* Get memory base address and size. */
	fdt_for_each_subnode(node, dtb_early_va, root) {
		const char *dev_type;
		const u32 *reg;

		dev_type = fdt_getprop(dtb_early_va, node, "device_type", NULL);
		if (!dev_type)
			continue;

		if (!strcmp(dev_type, "memory")) {
			reg = fdt_getprop(dtb_early_va, node, "reg", NULL);
			if (!reg)
				return;

			reg = get_reg_address(addr_cells, reg, &base);
			reg = get_reg_address(size_cells, reg, &size);

			if (size < (kernel_size * 2))
				continue;

			if (idx == find_index) {
				*mem_start = base;
				*mem_size = size;
				break;
			}

			idx++;
		}
	}
}

static __init int get_memory_nodes_num(uintptr_t kernel_size)
{
	int node, root, addr_cells, size_cells, total_nodes = 0;
	u64 base, size;

	/* Get root node's address cells and size cells. */
	root = get_node_addr_size_cells("/", &addr_cells, &size_cells);
	if (root < 0)
		return 0;

	/* Get memory base address and size. */
	fdt_for_each_subnode(node, dtb_early_va, root) {
		const char *dev_type;
		const u32 *reg;

		dev_type = fdt_getprop(dtb_early_va, node, "device_type", NULL);
		if (!dev_type)
			continue;

		if (!strcmp(dev_type, "memory")) {
			reg = fdt_getprop(dtb_early_va, node, "reg", NULL);
			if (!reg)
				return 0;

			reg = get_reg_address(addr_cells, reg, &base);
			reg = get_reg_address(size_cells, reg, &size);

			/* Candidate ensures that it don't overlap itself. */
			if (size > kernel_size * 2)
				total_nodes++;
		}
	}

	return total_nodes;
}

/* Return a default seed if there is no HW generator. */
static u64 kaslr_default_seed = ULL(-1);
static __init u64 kaslr_get_seed(void)
{
	int node, len;
	fdt64_t *prop;
	u64 ret;

	node = fdt_path_offset(dtb_early_va, "/chosen");
	if (node < 0)
		return kaslr_default_seed++;

	prop = fdt_getprop_w(dtb_early_va, node, "kaslr-seed", &len);
	if (!prop || len != sizeof(u64))
		return kaslr_default_seed++;

	ret = fdt64_to_cpu(*prop);

	/* Re-write to zero for checking whether get seed at second time */
	*prop = 0;

	return ret;
}

static __init const u8 *kaslr_get_cmdline(void)
{
	static const u8 default_cmdline[] __initconst = CONFIG_CMDLINE;

	if (!IS_ENABLED(CONFIG_CMDLINE_FORCE)) {
		int node;
		const u8 *prop;

		node = fdt_path_offset(dtb_early_va, "/chosen");
		if (node < 0)
			goto out;

		prop = fdt_getprop(dtb_early_va, node, "bootargs", NULL);
		if (!prop)
			goto out;

		return prop;
	}

out:
	return default_cmdline;
}

static __init bool kaslr_is_disabled(void)
{
	const u8 *cmdline = kaslr_get_cmdline();

	return strstr(cmdline, "nokaslr") != NULL;
}

static __init bool is_overlap(uintptr_t s1, uintptr_t e1, uintptr_t s2,
			      uintptr_t e2)
{
	return e1 >= s2 && e2 >= s1;
}

static __init bool is_overlap_reserved_mem(uintptr_t start_addr,
					   uintptr_t end_addr)
{
	int node, rsv_mem, addr_cells, size_cells;

	/* Get the reserved-memory node. */
	rsv_mem = get_node_addr_size_cells("/reserved-memory",
					   &addr_cells,
					   &size_cells);
	if (rsv_mem < 0)
		return false;

	/* Get memory base address and size. */
	fdt_for_each_subnode(node, dtb_early_va, rsv_mem) {
		uint64_t base, size;
		const uint32_t *reg;

		reg = fdt_getprop(dtb_early_va, node, "reg", NULL);
		if (!reg)
			return 0;

		reg = get_reg_address(addr_cells, reg, &base);
		reg = get_reg_address(size_cells, reg, &size);

		if (is_overlap(start_addr, end_addr, base, base + size))
			return true;
	}

	return false;
}

static __init bool is_overlap_initrd(uintptr_t start_addr, uintptr_t end_addr)
{
	int node;
	uintptr_t initrd_start, initrd_end;
	fdt64_t *prop;

	node = fdt_path_offset(dtb_early_va, "/chosen");
	if (node < 0)
		return false;

	prop = fdt_getprop_w(dtb_early_va, node, "linux,initrd-start", NULL);
	if (!prop)
		return false;

	initrd_start = fdt64_to_cpu(*prop);

	prop = fdt_getprop_w(dtb_early_va, node, "linux,initrd-end", NULL);
	if (!prop)
		return false;

	initrd_end = fdt64_to_cpu(*prop);

	return is_overlap(start_addr, end_addr, initrd_start, initrd_end);
}

static __init bool is_overlap_dtb(uintptr_t start_addr, uintptr_t end_addr)
{
	uintptr_t dtb_start = dtb_early_pa;
	uintptr_t dtb_end = dtb_start + fdt_totalsize(dtb_early_va);

	return is_overlap(start_addr, end_addr, dtb_start, dtb_end);
}

static __init bool has_regions_overlapping(uintptr_t start_addr,
					   uintptr_t end_addr)
{
	if (is_overlap_dtb(start_addr, end_addr))
		return true;

	if (is_overlap_initrd(start_addr, end_addr))
		return true;

	if (is_overlap_reserved_mem(start_addr, end_addr))
		return true;

	return false;
}

static inline __init unsigned long get_legal_offset_in_node(int random_index,
							    int max_index,
							    uintptr_t mem_start,
							    uintptr_t
							    kernel_size)
{
	uintptr_t start_addr, end_addr;
	int idx, stop_idx;

	idx = stop_idx = random_index;

	do {
		start_addr = mem_start + idx * SZ_2M + kernel_size;
		end_addr = start_addr + kernel_size;

		/* Check overlap to other regions. */
		if (!has_regions_overlapping(start_addr, end_addr))
			return idx * SZ_2M + kernel_size + (mem_start -
							    __pa(PAGE_OFFSET));

		if (idx-- < 0)
			idx = max_index;

	} while (idx != stop_idx);

	return 0;
}

#define MEM_RESERVE_START	__pa(PAGE_OFFSET)
static inline __init unsigned long get_legal_offset(u64 random,
						    uintptr_t kernel_size)
{
	int mem_nodes, idx, stop_idx, index;
	uintptr_t mem_start = 0, mem_size = 0, random_size, ret;

	mem_nodes = get_memory_nodes_num(kernel_size);

	idx = stop_idx = random % mem_nodes;

	do {
		kaslr_get_mem_info(&mem_start, &mem_size, kernel_size, idx);

		if (!mem_size)
			return 0;

		if (mem_start < MEM_RESERVE_START) {
			mem_size -= MEM_RESERVE_START - mem_start;
			mem_start = MEM_RESERVE_START;
		}

		/*
		 * Limit randomization range within 1G, so we can exploit
		 * early_pmd/early_pte during early page table phase.
		 */
		random_size = min_t(u64,
				    mem_size - (kernel_size * 2),
				    SZ_1G - (kernel_size * 2));

		if (!random_size || random_size < SZ_2M)
			return 0;

		/* The index of 2M block in whole available region */
		index = random % (random_size / SZ_2M);

		ret =
		    get_legal_offset_in_node(index, random_size / SZ_2M,
					     mem_start, kernel_size);
		if (ret)
			break;

		if (idx-- < 0)
			idx = mem_nodes - 1;

	} while (idx != stop_idx);

	return ret;
}

static inline __init u64 rotate_xor(u64 hash, const void *area, size_t size)
{
	size_t i;
	uintptr_t *ptr = (uintptr_t *) area;

	for (i = 0; i < size / sizeof(hash); i++) {
		/* Rotate by odd number of bits and XOR. */
		hash = (hash << ((sizeof(hash) * 8) - 7)) | (hash >> 7);
		hash ^= ptr[i];
	}

	return hash;
}

static __init uintptr_t get_random_offset(u64 seed, uintptr_t kernel_size)
{
	uintptr_t kernel_size_align = round_up(kernel_size, SZ_2M);
	u64 random = 0;
	cycles_t time_base;

	/* Attempt to create a simple but unpredictable starting entropy */
	random = rotate_xor(random, linux_banner, strlen(linux_banner));

	/*
	 * If there is no HW random number generator, use timer to get a random
	 * number. This is better than nothing but not enough secure.
	 */
	time_base = get_cycles() << 32;
	time_base ^= get_cycles();
	random = rotate_xor(random, &time_base, sizeof(time_base));

	if (seed)
		random = rotate_xor(random, &seed, sizeof(seed));

	return get_legal_offset(random, kernel_size_align);
}

void __init kaslr_late_init(void)
{
	uintptr_t kernel_size;

	/* Clear original kernel image. */
	if (kaslr_offset) {
		kernel_size = (uintptr_t) _end - (uintptr_t) _start;
		memset((void *)PAGE_OFFSET, 0, kernel_size);
		set_memory_nx(PAGE_OFFSET, kaslr_offset >> PAGE_SHIFT);
	}
}

uintptr_t __init kaslr_early_init(void)
{
	u64 seed;
	uintptr_t dest_start, dest_end;
	uintptr_t kernel_size = (uintptr_t) _end - (uintptr_t) _start;

	/* Get zero value at second time to avoid doing randomization again. */
	seed = kaslr_get_seed();
	if (!seed)
		return 0;

	/* Check whether disable kaslr by cmdline. */
	if (kaslr_is_disabled())
		return 0;

	/* Get the random number for kaslr offset. */
	kaslr_offset = get_random_offset(seed, kernel_size);

	/* Update kernel_virt_addr for get_kaslr_offset. */
	kernel_virt_addr += kaslr_offset;

	if (kaslr_offset) {
		dest_start = (uintptr_t) (PAGE_OFFSET + kaslr_offset);
		dest_end = dest_start + kernel_size;

		/* Create the new destination mapping for kernel image. */
		kaslr_create_page_table(dest_start, dest_end);

		/* Copy kernel image from orignial location. */
		memcpy((void *)dest_start, (void *)_start, kernel_size);
		flush_icache_range(dest_start, dest_end);

		/* Make secondary harts jump to new kernel image destination. */
		WRITE_ONCE(secondary_next_target,
			   __pa_symbol(secondary_random_target) + kaslr_offset);
	} else {
		WRITE_ONCE(secondary_next_target,
			   __pa_symbol(secondary_random_target));
	}

	return kaslr_offset;
}
