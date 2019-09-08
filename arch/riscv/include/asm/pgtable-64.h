/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 Regents of the University of California
 */

#ifndef _ASM_RISCV_PGTABLE_64_H
#define _ASM_RISCV_PGTABLE_64_H

#include <linux/const.h>

extern unsigned int pgtable_l4_enabled;

/* (pgtable_l4_enabled ? 39: 30) */
#define PGDIR_SHIFT      39
/* Size of region mapped by a page global directory */
#define PGDIR_SIZE      (_AC(1, UL) << PGDIR_SHIFT)
#define PGDIR_MASK      (~(PGDIR_SIZE - 1))

/* pud is folded into pgd in case of 3-level page table */
#define PUD_SHIFT	30
#define PUD_SIZE	(_AC(1, UL) << PUD_SHIFT)
#define PUD_MASK	(~(PUD_SIZE - 1))

#define PMD_SHIFT       21
/* Size of region mapped by a page middle directory */
#define PMD_SIZE        (_AC(1, UL) << PMD_SHIFT)
#define PMD_MASK        (~(PMD_SIZE - 1))

/* Page Upper Directory entry */
typedef struct {
	unsigned long pud;
} pud_t;

/* Page Middle Directory entry */
typedef struct {
	unsigned long pmd;
} pmd_t;

#define pmd_val(x)      ((x).pmd)
#define __pmd(x)        ((pmd_t) { (x) })
#define pud_val(x)      ((x).pud)
#define __pud(x)        ((pud_t) { (x) })

#define PTRS_PER_PMD    (PAGE_SIZE / sizeof(pmd_t))
#define PTRS_PER_PUD    (PAGE_SIZE / sizeof(pud_t))

#define pud_ERROR(pud)                          (pr_err("coucou"))

static inline void set_p4d(p4d_t *p4dp, p4d_t p4d)
{
	*p4dp = p4d;
}

static inline int p4d_none(p4d_t p4d)
{
	return (p4d_val(p4d) == 0);
}

static inline int p4d_present(p4d_t p4d)
{
	return (p4d_val(p4d) & _PAGE_PRESENT);
}

static inline int p4d_bad(p4d_t p4d)
{
	return !p4d_present(p4d);
}

static inline void p4d_clear(p4d_t *p4d)
{
	return set_p4d(p4d, __p4d(0));
}

static inline unsigned long p4d_page_vaddr(p4d_t p4d)
{
	return (unsigned long)pfn_to_virt(p4d_val(p4d) >> _PAGE_PFN_SHIFT);
}

#define pud_index(addr) (((addr) >> PUD_SHIFT) & (PTRS_PER_PUD - 1))

static inline pud_t *pud_offset(p4d_t *p4d, unsigned long address)
{
	return (pud_t *)p4d_page_vaddr(*p4d) + pud_index(address);
}

static inline int pud_present(pud_t pud)
{
	return (pud_val(pud) & _PAGE_PRESENT);
}

static inline int pud_none(pud_t pud)
{
	return (pud_val(pud) == 0);
}

static inline int pud_bad(pud_t pud)
{
	return !pud_present(pud);
}

static inline void set_pud(pud_t *pudp, pud_t pud)
{
	*pudp = pud;
}

static inline void pud_clear(pud_t *pudp)
{
	set_pud(pudp, __pud(0));
}

static inline pud_t pfn_pud(unsigned long pfn, pgprot_t prot)
{
	return __pud((pfn << _PAGE_PFN_SHIFT) | pgprot_val(prot));
}

static inline unsigned long _pud_pfn(pud_t pud)
{
	return pud_val(pud) >> _PAGE_PFN_SHIFT;
}

static inline unsigned long pud_page_vaddr(pud_t pud)
{
	return (unsigned long)pfn_to_virt(pud_val(pud) >> _PAGE_PFN_SHIFT);
}

#define pmd_index(addr) (((addr) >> PMD_SHIFT) & (PTRS_PER_PMD - 1))

static inline pmd_t *pmd_offset(pud_t *pud, unsigned long addr)
{
	return (pmd_t *)pud_page_vaddr(*pud) + pmd_index(addr);
}

static inline pmd_t pfn_pmd(unsigned long pfn, pgprot_t prot)
{
	return __pmd((pfn << _PAGE_PFN_SHIFT) | pgprot_val(prot));
}

static inline unsigned long _pmd_pfn(pmd_t pmd)
{
	return pmd_val(pmd) >> _PAGE_PFN_SHIFT;
}

#define pmd_ERROR(e) \
	pr_err("%s:%d: bad pmd %016lx.\n", __FILE__, __LINE__, pmd_val(e))

#endif /* _ASM_RISCV_PGTABLE_64_H */
