/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _ASM_RISCV_XIP_FIXUP_H
#define _ASM_RISCV_XIP_FIXUP_H

#include <asm/pgtable.h>

#ifndef __ASSEMBLY__
#ifndef CONFIG_XIP_KERNEL
#define XIP_FIXUP(addr)		(addr)
#else
#define XIP_FIXUP(addr) ({                                                      \
	uintptr_t __a = (uintptr_t)(addr);                                      \
	(__a >= CONFIG_XIP_PHYS_ADDR && __a < CONFIG_XIP_PHYS_ADDR + SZ_16M) ?  \
		__a - CONFIG_XIP_PHYS_ADDR + CONFIG_PHYS_RAM_BASE - XIP_OFFSET :\
		__a;                                                            \
	})
#endif /* CONFIG_XIP_KERNEL */

/* From here, fixup all the variables defined in mm/xip-fixup.c */
#ifdef CONFIG_MMU
extern unsigned long va_pa_offset;
#define va_pa_offset		(*((unsigned long *)XIP_FIXUP(&va_pa_offset)))

#ifdef CONFIG_64BIT
extern unsigned long va_kernel_pa_offset;
#define va_kernel_pa_offset	(*((unsigned long *)XIP_FIXUP(&va_kernel_pa_offset)))
#endif

extern unsigned long va_kernel_xip_pa_offset;
#define va_kernel_xip_pa_offset        (*((unsigned long *)XIP_FIXUP(&va_kernel_xip_pa_offset)))

extern pgd_t trampoline_pg_dir[PTRS_PER_PGD];
#define trampoline_pg_dir      ((pgd_t *)XIP_FIXUP(trampoline_pg_dir))
extern pgd_t early_pg_dir[PTRS_PER_PGD];
#define early_pg_dir           ((pgd_t *)XIP_FIXUP(early_pg_dir))

#ifndef __PAGETABLE_PMD_FOLDED
extern pmd_t trampoline_pmd[PTRS_PER_PMD];
#define trampoline_pmd ((pmd_t *)XIP_FIXUP(trampoline_pmd))
extern pmd_t fixmap_pmd[PTRS_PER_PMD];
#define fixmap_pmd     ((pmd_t *)XIP_FIXUP(fixmap_pmd))
extern pmd_t early_pmd[PTRS_PER_PMD];
#define early_pmd      ((pmd_t *)XIP_FIXUP(early_pmd))
#endif

extern pte_t fixmap_pte[PTRS_PER_PTE];
#define fixmap_pte             ((pte_t *)XIP_FIXUP(fixmap_pte))

extern uintptr_t load_pa, load_sz;
#define load_pa        (*((uintptr_t *)XIP_FIXUP(&load_pa)))
#define load_sz        (*((uintptr_t *)XIP_FIXUP(&load_sz)))

extern uintptr_t xiprom, xiprom_sz;
#define xiprom_sz      (*((uintptr_t *)XIP_FIXUP(&xiprom_sz)))
#define xiprom         (*((uintptr_t *)XIP_FIXUP(&xiprom)))

#endif /* CONFIG_MMU */

extern unsigned long kernel_virt_addr;
#define kernel_virt_addr       (*((unsigned long *)XIP_FIXUP(&kernel_virt_addr)))

extern void *_dtb_early_va;
extern uintptr_t _dtb_early_pa;
#if defined(CONFIG_XIP_KERNEL) && defined(CONFIG_MMU)
#define dtb_early_va    (*(void **)XIP_FIXUP(&_dtb_early_va))
#define dtb_early_pa    (*(uintptr_t *)XIP_FIXUP(&_dtb_early_pa))
#else
#define dtb_early_va    _dtb_early_va
#define dtb_early_pa    _dtb_early_pa
#endif /* CONFIG_XIP_KERNEL */

extern struct pt_alloc_ops _pt_ops;
#ifdef CONFIG_XIP_KERNEL
#define pt_ops (*(struct pt_alloc_ops *)XIP_FIXUP(&_pt_ops))
#else
#define pt_ops _pt_ops
#endif

#endif /* __ASSEMBLY__ */

#endif /* _ASM_RISCV_XIP_FIXUP_H */
