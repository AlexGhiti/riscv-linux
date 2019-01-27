#include <linux/mm.h>
#include <linux/sched/mm.h>

static int mmap_is_legacy(struct rlimit *rlim_stack)
{
	if (rlim_stack->rlim_cur == RLIM_INFINITY)
		return 1;

	return sysctl_legacy_va_layout;
}

void arch_pick_mmap_layout(struct mm_struct *mm, struct rlimit *rlim_stack)
{
	if (mmap_is_legacy(rlim_stack)) {
		mm->mmap_base = TASK_UNMAPPED_BASE;
		mm->get_unmapped_area = arch_get_unmapped_area;
	} else {
		mm->get_unmapped_area = arch_get_unmapped_area_topdown;
	}
}
