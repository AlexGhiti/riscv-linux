====================
Booting RISC-V Linux
====================

:Author: Alexandre Ghiti <alex@ghiti.fr>
:Date: 24 November 2021

This document describes what the RISC-V Linux Kernel expects from any bootloader
and vice-versa.

Boot image header in RISC-V Linux
=================================

For more details, please see `Boot image header in RISC-V Linux`_

RISC-V Linux Kernel requirements
================================

CSR
---

* `satp` must be equal to 0, i.e. the MMU must be off.


Registers
---------

* `a0` contains the hart id.
* `a1` contains the physical address of the device tree.

Memory map description
----------------------

The system memory map is expected to be passed into a device-tree.

Prior to v5.X, the physical memory below the kernel image load address
cannot be mapped, resulting in a misalignment between virtual and physical
addresses.

As of v5.X, the RISC-V Linux Kernel will map the physical memory starting
from 0x8000_0000, where usually some runtime services reside. That means
that the bootloader is expected to mark such region as "reserved" so that the
kernel does not use it: see devicetree/bindings/reserved-memory/reserved-memory.txt

Kernel location
---------------

The kernel must be aligned on `PMD_SIZE`, i.e. 4MB for a 32-bit kernel and 2MB
for a 64-bit kernel.
