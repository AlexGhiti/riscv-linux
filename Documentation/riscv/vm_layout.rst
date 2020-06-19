=====================================
Virtual Memory Layout on RISC-V Linux
====================================

:Author: Alexandre Ghiti <alex@ghiti.fr>
:Date: 16 June 2020

This document describes the virtual memory layout used by the RISC-V Linux
Kernel.

RISC-V Linux Kernel 32bit
=========================

RISC-V Linux Kernel SV32
------------------------

RISC-V Linux Kernel 64bit
=========================

On 64bit RISC-V Linux Kernel, the capabitilies of the underlying hardware is
probed at runtime during the boot in order to determine the size of the virtual
address space, either 39bit (SV39) or 48bit (SV48) (note that 57bit is defined
in the RISC-V Privileged specification but not supported yet by the kernel).

The RISC-V Linux Kernel is able to choose between 3-level and 4-level page
tables during
the boot, at runtime, which eliminates the need to have one kernel for SV39 and
one for SV48.

So by default, a SV39 capable hardware will boot using 3-level page tables
whereas a SV48 capable hardware will boot using a 4-level page tables. But a 4-level
page table comes with some drawbacks compared to a 3-level page table: the page
table memory occupation is more important and the number of memory accesses is
higher in case of a TLB miss. For those reasons, it is possible to explicitly
ask for a 3-level page on SV48 capable hardware by using the mmu-type property
of the cpu node of the device tree.

The RISC-V privileged architecture document states that the 64bit addresses
"must have bits 63–48 all equal to bit 47, or else a page-fault exception will
occur."

RISC-V Linux Kernel SV39
------------------------

RISC-V Linux Kernel virtual memory layout for 3-level page table::

  Start                 End                     Size            Use              
  -----------------------------------------------------------------------        
  0000000000000000      0000ffffffffffff         256TB          user             
  ffff000000000000      ffff7fffffffffff         128TB          kernel logical memory map
  ffff800000000000      ffff9fffffffffff          32TB          kasan shadow region
  ffffa00000000000      ffffa00007ffffff         128MB          bpf jit region

RISC-V Linux Kernel SV48
------------------------

3-level page table
------------------

Please refer to `RISC-V Linux Kernel SV39`_.

4-level page table
------------------

RISC-V Linux Kernel virtual memory layout for 3-level page table::

  Start                 End                     Size            Use              
  -----------------------------------------------------------------------        
  0000000000000000      0000ffffffffffff         256TB          user             
  ffff000000000000      ffff7fffffffffff         128TB          kernel logical memory map
  ffff800000000000      ffff9fffffffffff          32TB          kasan shadow region
  ffffa00000000000      ffffa00007ffffff         128MB          bpf jit region

