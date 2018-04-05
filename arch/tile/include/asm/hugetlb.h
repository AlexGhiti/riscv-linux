/*
 * Copyright 2010 Tilera Corporation. All Rights Reserved.
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation, version 2.
 *
 *   This program is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE, GOOD TITLE or
 *   NON INFRINGEMENT.  See the GNU General Public License for
 *   more details.
 */

#ifndef _ASM_TILE_HUGETLB_H
#define _ASM_TILE_HUGETLB_H

#include <asm/page.h>

static inline int is_hugepage_only_range(struct mm_struct *mm,
					 unsigned long addr,
					 unsigned long len) {
	return 0;
}

/*
 * If the arch doesn't supply something else, assume that hugepage
 * size aligned regions are ok without further preparation.
 */
static inline int prepare_hugepage_range(struct file *file,
					 unsigned long addr, unsigned long len)
{
	struct hstate *h = hstate_file(file);
	if (len & ~huge_page_mask(h))
		return -EINVAL;
	if (addr & ~huge_page_mask(h))
		return -EINVAL;
	return 0;
}

#define __HAVE_ARCH_HUGE_SET_HUGE_PTE_AT
static inline void set_huge_pte_at(struct mm_struct *mm, unsigned long addr,
				   pte_t *ptep, pte_t pte)
{
	set_pte(ptep, pte);
}

static inline pte_t huge_pte_wrprotect(pte_t pte)
{
	return pte_wrprotect(pte);
}

static inline void huge_ptep_set_wrprotect(struct mm_struct *mm,
					   unsigned long addr, pte_t *ptep)
{
	ptep_set_wrprotect(mm, addr, ptep);
}

static inline int huge_ptep_set_access_flags(struct vm_area_struct *vma,
					     unsigned long addr, pte_t *ptep,
					     pte_t pte, int dirty)
{
	return ptep_set_access_flags(vma, addr, ptep, pte, dirty);
}

static inline pte_t huge_ptep_get(pte_t *ptep)
{
	return *ptep;
}

static inline void arch_clear_hugepage_flags(struct page *page)
{
}

#ifdef CONFIG_HUGETLB_SUPER_PAGES
static inline pte_t arch_make_huge_pte(pte_t entry, struct vm_area_struct *vma,
				       struct page *page, int writable)
{
	size_t pagesize = huge_page_size(hstate_vma(vma));
	if (pagesize != PUD_SIZE && pagesize != PMD_SIZE)
		entry = pte_mksuper(entry);
	return entry;
}
#define arch_make_huge_pte arch_make_huge_pte

/* Sizes to scale up page size for PTEs with HV_PTE_SUPER bit. */
enum {
	HUGE_SHIFT_PGDIR = 0,
	HUGE_SHIFT_PMD = 1,
	HUGE_SHIFT_PAGE = 2,
	HUGE_SHIFT_ENTRIES
};
extern int huge_shift[HUGE_SHIFT_ENTRIES];
#endif

#include <asm-generic/hugetlb.h>

#endif /* _ASM_TILE_HUGETLB_H */
