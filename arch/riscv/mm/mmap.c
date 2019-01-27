// SPDX-License-Identifier: GPL-2.0
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/sizes.h>
#include <linux/personality.h>
#include <linux/random.h>

/*
 * Leave enough space between the mmap area and the stack to honour ulimit in
 * the face of randomisation.
 */
#define MIN_GAP (SZ_128M)
#define MAX_GAP	(TASK_SIZE / 6 * 5)

static int mmap_is_legacy(struct rlimit *rlim_stack)
{
	if (current->personality & ADDR_COMPAT_LAYOUT)
		return 1;

	if (rlim_stack->rlim_cur == RLIM_INFINITY)
		return 1;

	return sysctl_legacy_va_layout;
}

static unsigned long arch_mmap_rnd(void)
{
	unsigned long rnd;

	rnd = get_random_long() & ((1UL << mmap_rnd_bits) - 1);

	return rnd << PAGE_SHIFT;
}

static unsigned long mmap_base(unsigned long rnd, struct rlimit *rlim_stack)
{
	unsigned long gap = rlim_stack->rlim_cur;

	if (gap < MIN_GAP)
		gap = MIN_GAP;
	else if (gap > MAX_GAP)
		gap = MAX_GAP;

	return PAGE_ALIGN(TASK_SIZE - gap - rnd);
}

/*
 * This function, called very early during the creation of a new process VM
 * image, sets up which VM layout function to use:
 */
void arch_pick_mmap_layout(struct mm_struct *mm, struct rlimit *rlim_stack)
{
	unsigned long random_factor = 0UL;

	if (current->flags & PF_RANDOMIZE)
		random_factor = arch_mmap_rnd();

	/*
	 * Fall back to the standard layout if the personality bit is set, or
	 * if the expected stack growth is unlimited:
	 */
	if (mmap_is_legacy(rlim_stack)) {
		mm->mmap_base = TASK_UNMAPPED_BASE + random_factor;
		mm->get_unmapped_area = arch_get_unmapped_area;
	} else {
		mm->mmap_base = mmap_base(random_factor, rlim_stack);
		mm->get_unmapped_area = arch_get_unmapped_area_topdown;
	}
}
