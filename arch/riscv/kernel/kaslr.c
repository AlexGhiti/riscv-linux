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
extern void secondary_random_target(void);
extern void kaslr_create_page_table(uintptr_t start, uintptr_t end);

uintptr_t secondary_next_target __initdata;
static uintptr_t kaslr_offset __initdata;

uintptr_t __init kaslr_early_init(void)
{
	uintptr_t dest_start, dest_end;
	uintptr_t kernel_size = (uintptr_t) _end - (uintptr_t) _start;

	/* Get zero value at second time to avoid doing randomization again. */
	if (kaslr_offset)
		return 0;

	/* Get the random number for kaslr offset. */
	kaslr_offset = 0x10000000;

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
