====================                                                            
Booting RISC-V Linux                                                            
====================                                                            
                                                                                 
:Author: Alexandre Ghiti <alex@ghiti.fr>                                        
:Date: 16 June 2020
                                                                           
This document describes what the RISC-V Linux Kernel expects from any boot
loader and vice-versa.

Boot image header in RISC-V Linux 
=================================

For more details, please see `Boot image header in RISC-V Linux`_

RISC-V Linux Kernel requirements/recommendations
================================================

Memory map description
----------------------

The system memory map is expected to be passed into a device-tree.

Prior to v5.9, the physical memory below the kernel image load address
cannot be mapped, resulting in a misalignment between virtual and physical
addresses.

As of v5.9, the RISC-V Linux Kernel will map the physical memory starting
from 0x8000_0000, where usually some runtime services reside. That means
that the boot loader is expected to mark such region as "reserved" so
that the kernel does not use it: see devicetree/bindings/reserved-memory/reserved-memory.txt
