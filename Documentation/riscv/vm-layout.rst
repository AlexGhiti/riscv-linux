.. SPDX-License-Identifier: GPL-2.0

=====================================
Virtual Memory Layout on RISC-V Linux
=====================================

:Author: Alexandre Ghiti <alex@ghiti.fr>
:Date: 12 February 2021

This document describes the virtual memory layout used by the RISC-V Linux
Kernel.

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
   ffffffc5fee00000 | -232    GB | ffffffc5feffffff |    2 MB | fixmap
   ffffffc5ff000000 | -232    GB | ffffffc5ffffffff |   16 MB | PCI io
   ffffffc600000000 | -232    GB | ffffffc6ffffffff |    4 GB | vmemmap
   ffffffc700000000 | -228    GB | ffffffd6ffffffff |   64 GB | vmalloc/ioremap space
   ffffffd700000000 | -164    GB | fffffff6ffffffff |  128 GB | direct mapping of all physical memory
  __________________|____________|__________________|_________|____________________________________________________________
                                                              |
                                                              |
  ____________________________________________________________|____________________________________________________________
                    |            |                  |         |
   fffffff700000000 |  -36    GB | fffffffeffffffff |   32 GB | kasan
   ffffffff00000000 |   -4    GB | ffffffff7fffffff |    2 GB | modules, BPF
   ffffffff80000000 |   -2    GB | ffffffffffffffff |    2 GB | kernel
  __________________|____________|__________________|_________|____________________________________________________________


RISC-V Linux Kernel SV48
------------------------

::

 ========================================================================================================================
      Start addr    |   Offset   |     End addr     |  Size   | VM area description
 ========================================================================================================================
                    |            |                  |         |
   0000000000000000 |    0       | 00007fffffffffff |  128 TB | user-space virtual memory, different per mm
  __________________|____________|__________________|_________|___________________________________________________________
                    |            |                  |         |
   0000800000000000 | +128    TB | ffff7fffffffffff | ~16M TB | ... huge, almost 64 bits wide hole of non-canonical
                    |            |                  |         | virtual memory addresses up to the -128 TB
                    |            |                  |         | starting offset of kernel mappings.
  __________________|____________|__________________|_________|___________________________________________________________
                                                              |
                                                              | Kernel-space virtual memory, shared between all processes:
  ____________________________________________________________|___________________________________________________________
                    |            |                  |         |
   ffff800000000000 | -128    TB | ffff8fffffffffff |   16 TB | kasan
   ffff9dfffee00000 |  -94    TB | ffff9dfffeffffff |    2 MB | fixmap
   ffff9dffff000000 |  -94    TB | ffff9dffffffffff |   16 MB | PCI io
   ffff9e0000000000 |  -94    TB | ffff9fffffffffff |    2 TB | vmemmap
   ffffa00000000000 |  -92    TB | ffffbfffffffffff |   32 TB | vmalloc/ioremap space
   ffffc00000000000 |  -64    TB | fffffffeffffffff |   64 TB | direct mapping of all physical memory
  __________________|____________|__________________|_________|____________________________________________________________
                                                              |
                                                              | Identical layout to the 39-bit one from here on:
  ____________________________________________________________|____________________________________________________________
                    |            |                  |         |
   ffffffff00000000 |   -4    GB | ffffffff7fffffff |    2 GB | modules, BPF
   ffffffff80000000 |   -2    GB | ffffffffffffffff |    2 GB | kernel
  __________________|____________|__________________|_________|____________________________________________________________
