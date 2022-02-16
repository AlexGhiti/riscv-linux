// SPDX-License-Identifier: GPL-2.0-only
/*
 * Based on arch/arm/kernel/io.c
 *
 * Copyright (C) 2012 ARM Ltd.
 * Copyright (C) 2021 Ventana Micro Systems Inc.
 */

#include <linux/export.h>
#include <linux/types.h>
#include <linux/io.h>

/*
 * Copy data from IO memory space to "real" memory space.
 */
void __memcpy_fromio(void *to, const volatile void __iomem *from, size_t count)
{
	while (count && !IS_ALIGNED((unsigned long)from, sizeof(long))) {
		*(u8 *)to = __raw_readb(from);
		from++;
		to++;
		count--;
	}

	while (count >= sizeof(long)) {
#ifdef CONFIG_64BIT
		*(u64 *)to = __raw_readq(from);
#else
		*(u32 *)to = __raw_readl(from);
#endif
		from += sizeof(long);
		to += sizeof(long);
		count -= sizeof(long);
	}

	while (count) {
		*(u8 *)to = __raw_readb(from);
		from++;
		to++;
		count--;
	}
}
EXPORT_SYMBOL(__memcpy_fromio);

/*
 * Copy data from "real" memory space to IO memory space.
 */
void __memcpy_toio(volatile void __iomem *to, const void *from, size_t count)
{
	while (count && !IS_ALIGNED((unsigned long)to, sizeof(long))) {
		__raw_writeb(*(u8 *)from, to);
		from++;
		to++;
		count--;
	}

	while (count >= sizeof(long)) {
#ifdef CONFIG_64BIT
		__raw_writeq(*(u64 *)from, to);
#else
		__raw_writel(*(u32 *)from, to);
#endif
		from += sizeof(long);
		to += sizeof(long);
		count -= sizeof(long);
	}

	while (count) {
		__raw_writeb(*(u8 *)from, to);
		from++;
		to++;
		count--;
	}
}
EXPORT_SYMBOL(__memcpy_toio);

/*
 * "memset" on IO memory space.
 */
void __memset_io(volatile void __iomem *dst, int c, size_t count)
{
	unsigned long qc = (u8)c;

	qc |= qc << 8;
	qc |= qc << 16;
#ifdef CONFIG_64BIT
	qc |= qc << 32;
#endif

	while (count && !IS_ALIGNED((unsigned long)dst, sizeof(long))) {
		__raw_writeb(c, dst);
		dst++;
		count--;
	}

	while (count >= sizeof(long)) {
#ifdef CONFIG_64BIT
		__raw_writeq(qc, dst);
#else
		__raw_writel(qc, dst);
#endif
		dst += sizeof(long);
		count -= sizeof(long);
	}

	while (count) {
		__raw_writeb(c, dst);
		dst++;
		count--;
	}
}
EXPORT_SYMBOL(__memset_io);
