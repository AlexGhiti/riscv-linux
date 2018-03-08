// SPDX-License-Identifier: GPL-2.0
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/hugetlb.h>
#include <linux/pagemap.h>
#include <linux/err.h>
#include <linux/sysctl.h>
#include <linux/compat.h>
#include <asm/mman.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <asm/pgalloc.h>

#ifdef CONFIG_HUGETLB_PAGE
//static unsigned long hugetlb_get_unmapped_area_bottomup(struct file *file,
//		unsigned long addr, unsigned long len,
//		unsigned long pgoff, unsigned long flags)
//{
//	struct hstate *h = hstate_file(file);
//	struct vm_unmapped_area_info info;
//
//	info.flags = 0;
//	info.length = len;
//	info.low_limit = get_mmap_base(1);
//
//	/*
//	 * If hint address is above DEFAULT_MAP_WINDOW, look for unmapped area
//	 * in the full address space.
//	 */
//	info.high_limit = in_compat_syscall() ?
//		task_size_32bit() : task_size_64bit(addr > DEFAULT_MAP_WINDOW);
//
//	info.align_mask = PAGE_MASK & ~huge_page_mask(h);
//	info.align_offset = 0;
//	return vm_unmapped_area(&info);
//}
//
//static unsigned long hugetlb_get_unmapped_area_topdown(struct file *file,
//		unsigned long addr, unsigned long len,
//		unsigned long pgoff, unsigned long flags)
//{
//	struct hstate *h = hstate_file(file);
//	struct vm_unmapped_area_info info;
//
//	info.flags = VM_UNMAPPED_AREA_TOPDOWN;
//	info.length = len;
//	info.low_limit = PAGE_SIZE;
//	info.high_limit = get_mmap_base(0);
//
//	/*
//	 * If hint address is above DEFAULT_MAP_WINDOW, look for unmapped area
//	 * in the full address space.
//	 */
//	if (addr > DEFAULT_MAP_WINDOW && !in_compat_syscall())
//		info.high_limit += TASK_SIZE_MAX - DEFAULT_MAP_WINDOW;
//
//	info.align_mask = PAGE_MASK & ~huge_page_mask(h);
//	info.align_offset = 0;
//	addr = vm_unmapped_area(&info);
//
//	/*
//	 * A failed mmap() very likely causes application failure,
//	 * so fall back to the bottom-up function here. This scenario
//	 * can happen with large stack limits and large mmap()
//	 * allocations.
//	 */
//	if (addr & ~PAGE_MASK) {
//		VM_BUG_ON(addr != -ENOMEM);
//		info.flags = 0;
//		info.low_limit = TASK_UNMAPPED_BASE;
//		info.high_limit = TASK_SIZE_LOW;
//		addr = vm_unmapped_area(&info);
//	}
//
//	return addr;
//}
//
//unsigned long
//hugetlb_get_unmapped_area(struct file *file, unsigned long addr,
//		unsigned long len, unsigned long pgoff, unsigned long flags)
//{
//	struct hstate *h = hstate_file(file);
//	struct mm_struct *mm = current->mm;
//	struct vm_area_struct *vma;
//
//	if (len & ~huge_page_mask(h))
//		return -EINVAL;
//
//	addr = mpx_unmapped_area_check(addr, len, flags);
//	if (IS_ERR_VALUE(addr))
//		return addr;
//
//	if (len > TASK_SIZE)
//		return -ENOMEM;
//
//	/* No address checking. See comment at mmap_address_hint_valid() */
//	if (flags & MAP_FIXED) {
//		if (prepare_hugepage_range(file, addr, len))
//			return -EINVAL;
//		return addr;
//	}
//
//	if (addr) {
//		addr &= huge_page_mask(h);
//		if (!mmap_address_hint_valid(addr, len))
//			goto get_unmapped_area;
//
//		vma = find_vma(mm, addr);
//		if (!vma || addr + len <= vm_start_gap(vma))
//			return addr;
//	}
//
//get_unmapped_area:
//	if (mm->get_unmapped_area == arch_get_unmapped_area)
//		return hugetlb_get_unmapped_area_bottomup(file, addr, len,
//				pgoff, flags);
//	else
//		return hugetlb_get_unmapped_area_topdown(file, addr, len,
//				pgoff, flags);
//}
#endif /* CONFIG_HUGETLB_PAGE */

static __init int setup_hugepagesz(char *opt)
{
	unsigned long ps = memparse(opt, &opt);

	if (ps == PMD_SIZE) {
		hugetlb_add_hstate(PMD_SHIFT - PAGE_SHIFT);
	} else if (ps == PUD_SIZE) {
		hugetlb_add_hstate(PUD_SHIFT - PAGE_SHIFT);
	} else {
		hugetlb_bad_size();
		printk(KERN_ERR "hugepagesz: Unsupported page size %lu M\n",
			ps >> 20);
		return 0;
	}

	return 1;
}
__setup("hugepagesz=", setup_hugepagesz);

#ifdef CONFIG_ARCH_HAS_GIGANTIC_PAGE
static __init int gigantic_pages_init(void)
{
	if (!size_to_hstate(1UL << PUD_SHIFT))
		hugetlb_add_hstate(PUD_SHIFT - PAGE_SHIFT);

	return 0;
}
arch_initcall(gigantic_pages_init);
#endif
