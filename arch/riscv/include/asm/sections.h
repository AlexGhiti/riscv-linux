/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2020 Western Digital Corporation or its affiliates.
 */
#ifndef __ASM_SECTIONS_H
#define __ASM_SECTIONS_H

#include <asm-generic/sections.h>
#include <linux/mm.h>

extern char _start[];
extern char _start_kernel[];
extern char __init_data_begin[], __init_data_end[];
extern char __init_text_begin[], __init_text_end[];
extern char __alt_start[], __alt_end[];

static inline bool is_va_kernel_text(uintptr_t va)
{
	return (va >= (uintptr_t)_start && va < (uintptr_t)__init_text_begin);
}

static inline bool is_va_kernel_lm_alias_text(uintptr_t va)
{
	return (va >= (uintptr_t)lm_alias(_start) && va < (uintptr_t)lm_alias(__init_text_begin));
}

static inline bool is_va_kernel_init_text(uintptr_t va)
{
	return (va >= (uintptr_t)__init_text_begin && va < (uintptr_t)__init_data_begin);
}

#endif /* __ASM_SECTIONS_H */
