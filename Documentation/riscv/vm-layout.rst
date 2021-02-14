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

This allows to always have the RISC-V Linux Kernel to the same addresses, no
matter how large the address space is, making it possible to have a single
kernel image for both SV39 and SV48 (and future extensions) that does not need
to be relocated at runtime.

The RISC-V Linux Kernel probes the underlying hardware capabilities at runtime
very early in the boot process in order to determine the size of the virtual
address space, either 39bit (SV39) or 48bit (SV48). It then chooses between
3-level and 4-level page tables at runtime. So by default, a SV39 capable
hardware will boot using 3-level page tables whereas a SV48 capable hardware
will boot using a 4-level page tables.


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
   ffffffe000000000 | -128    GB | ffffffff7fffffff |  126 GB | direct mapping of all physical memory
  __________________|____________|__________________|_________|____________________________________________________________
                                                              |
                                                              | Identical layout to the 48-bit one from here on:
  ____________________________________________________________|____________________________________________________________
                    |            |                  |         |
   ffffffff80000000 |   -2    GB | ffffffffffffffff |    2 GB | kernel, BPF, modules
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
                    |            |                  |         |     virtual memory addresses up to the -128 TB
                    |            |                  |         |     starting offset of kernel mappings.
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
   ffffc00000000000 |  -64    TB | ffffffff7fffffff |   64 TB | direct mapping of all physical memory
  __________________|____________|__________________|_________|____________________________________________________________
                                                              |
                                                              | Identical layout to the 39-bit one from here on:
  ____________________________________________________________|____________________________________________________________
                    |            |                  |         |
   ffffffff00000000 |   -4    GB | ffffffff7fffffff |    2 GB | modules
   ffffffff80000000 |   -2    GB | ffffffffffffffff |    2 GB | kernel, BPF
  __________________|____________|__________________|_________|____________________________________________________________
