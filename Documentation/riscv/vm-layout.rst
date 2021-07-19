.. SPDX-License-Identifier: GPL-2.0

=====================================
Virtual Memory Layout on RISC-V Linux
=====================================

:Author: Alexandre Ghiti <alex@ghiti.fr>
:Date: 12 February 2021

This document describes the virtual memory layout used by the RISC-V Linux
Kernel.

Kernel mapping/Linear mapping
=============================

Early page table
----------------

The early page table (`early_pg_dir`) is populated very soon in the boot process (in `setup_vm`) and used as a temporary mapping until all the memory is discovered: `early_pg_dir` then only establishes a mapping for the *kernel* and not the *linear* mapping (Note: in 32-bit, the kernel mapping happens to lie in the linear mapping, but not in 64-bit).
This comes with a strong implication: before all the memory in the system is discovered, the address conversions macros will only work on *kernel* addresses, any attempt to use those macros on an address that lies in the linear mapping will trigger a BUG (concretely, those macros can be used when `phys_ram_base` is set).

Init page table
---------------

The init page table (`swapper_pg_dir`) contains all the kernel mappings used throughout the life of the kernel. The linear and the kernel mappings are installed in `setup_vm_final` while modules, BPF, vmalloc mappings and others will be added as the kernel needs them.


RISC-V Linux Kernel 32bit
=========================

RISC-V Linux Kernel SV32
------------------------

TODO

RISC-V Linux Kernel 64bit
=========================

The RISC-V privileged architecture document states that the 64bit addresses
"must have bits 63–48 all equal to bit 47, or else a page-fault exception will
occur.": that splits the virtual address space into 2 halves separated by a very
big hole, the lower half is where the userspace resides, the upper half is where
the RISC-V Linux Kernel resides.

RISC-V Linux Kernel SV39
------------------------

::

  ========================================================================================================================
      Start addr    |   Offset   |     End addr     |  Size   | VM area description
  ========================================================================================================================
                    |            |                  |         |
   0000000000000000 |    0       | 0000003fffffffff |  256 GB | user-space virtual memory, different per mm
  __________________|____________|__________________|_________|___________________________________________________________
                    |            |                  |         |
   0000004000000000 | +256    GB | ffffffbfffffffff | ~16M TB | ... huge, almost 64 bits wide hole of non-canonical
                    |            |                  |         |     virtual memory addresses up to the -256 GB
                    |            |                  |         |     starting offset of kernel mappings.
  __________________|____________|__________________|_________|___________________________________________________________
                                                              |
                                                              | Kernel-space virtual memory, shared between all processes:
  ____________________________________________________________|___________________________________________________________
                    |            |                  |         |
   ffffffc000000000 | -256    GB | ffffffc7ffffffff |   32 GB | kasan
   ffffffcefee00000 | -196    GB | ffffffcefeffffff |    2 MB | fixmap
   ffffffceff000000 | -196    GB | ffffffceffffffff |   16 MB | PCI io
   ffffffcf00000000 | -196    GB | ffffffcfffffffff |    4 GB | vmemmap
   ffffffd000000000 | -192    GB | ffffffdfffffffff |   64 GB | vmalloc/ioremap space
   ffffffe000000000 | -128    GB | ffffffff7fffffff |  124 GB | direct mapping of all physical memory
  __________________|____________|__________________|_________|____________________________________________________________
                                                              |
                                                              |
  ____________________________________________________________|____________________________________________________________
                    |            |                  |         |
   ffffffff00000000 |   -4    GB | ffffffff7fffffff |    2 GB | modules
   ffffffff80000000 |   -2    GB | ffffffffffffffff |    2 GB | kernel, BPF
  __________________|____________|__________________|_________|____________________________________________________________
