/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022 Ventana Micro Sytems.
 *
 * Authors:
 *     Mayuresh Chitale <mchitale@ventanamicro.com>
 */

#include <linux/linkage.h>
#include <asm/asm.h>

       .text
       .altmacro
       .option norelax


ENTRY(__riscv_sfence_w_inval)
       /*
        * SFENCE.W.INVAL
        * 0001100 00000 00000 000 00000 1110011
        */
       .word 0x18000073
       ret
ENDPROC(__riscv_sfence_w_inval)

ENTRY(__riscv_sfence_inval_ir)
       /*
        * SFENCE.INVAL.IR
        * 0001100 00001 00000 000 00000 1110011
        */
       .word 0x18100073
       ret
ENDPROC(__riscv_sfence_inval_ir)
ENTRY(__riscv_sinval_vma_asid)
       /*
        * rs1 = VMA
        * rs2 = asid
        * SFENCE.W.INVAL
        * 0001011 01011 01010 000 00000 1110011
        */
       .word 0x16B50073
       ret
ENDPROC(__riscv_sinval_vma_asid)
ENTRY(__riscv_sinval_vma)
       /*
        * rs1 = vma
        * rs2 = 0
        * SFENCE.W.INVAL
        * 0001011 00000 01010 000 00000 1110011
        */
       .word 0x16050073
       ret
ENDPROC(__riscv_sinval_vma)
