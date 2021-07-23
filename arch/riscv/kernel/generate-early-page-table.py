#!/usr/bin/env python

from os import path
import sys
import re

if len(sys.argv) != 2:
	print("Usage: %s PATH_TO_CONFIG" % sys.argv[0])
	sys.exit(1)

EARLY_PAGE_TABLE_LDS_PATH = path.join(path.dirname(path.abspath(__file__)), "early-page-table.lds.S")

# PAGE_SIZE / sizeof(uint64_t)
PTRS_PER_PGD = 512
PTRS_PER_PMD = 512
PTRS_PER_PTE = 512

KERNEL_PGDS_NR = int(PTRS_PER_PGD / 2)

PAGE_PFN_SHIFT = 10
PAGE_SHIFT = 12
PAGE_SIZE = 1 << PAGE_SHIFT
PMD_SIZE = 1 << 21
PGDIR_SIZE = 1 << 30

TASK_SIZE = int(PGDIR_SIZE * PTRS_PER_PGD / 2)
KERNEL_MAPPING_BASE_ADDR = 0xFFFFFFFFFFFFFFFF - TASK_SIZE + 1
KERNEL_LINK_ADDR = 0xFFFFFFFF80000000
FIXADDR_START = 0xFFFFFFCEFEE00000
DTB_EARLY_BASE_VA = PGDIR_SIZE

PAGE_KERNEL_EXEC = (1 << 1) | (1 << 2) | (1 << 0) | (1 << 6) | (1 << 7) | (1 << 5) | (1 << 3)
PAGE_TABLE = (1 << 0)

XIP_OFFSET = 8 * 1024 * 1024

def extract_addr_from_config(config_path):
	with open(config_path, "r") as fconfig:
		content = fconfig.read()
		p = re.compile('CONFIG_PHYS_RAM_BASE=.*').search(content)
		if p:
			phys_ram_base = p.group().split('=')[1]
		else:
			print("Can't find CONFIG_PHYS_RAM_BASE in .config!")
			sys.exit(1)

		p = re.compile("CONFIG_XIP_PHYS_ADDR=.*").search(content)
		if p:
			xip_phys_addr = p.group().split('=')[1]
		else:
			print("Can't find CONFIG_XIP_PHYS_ADDR in .config!")
			sys.exit(1)

		p = re.compile("CONFIG_BUILTIN_DTB.*").search(content)
		if p:
			builtin_dtb = True if p.group() == "CONFIG_BUILTIN_DTB=y" else False
		else:
			builtin_dtb = False

	return (phys_ram_base, xip_phys_addr, builtin_dtb)

def pte_page_table(phys_addr):
	return "((({}) >> {}) << {}) | 0x{:x}".format(phys_addr, PAGE_SHIFT, PAGE_PFN_SHIFT, PAGE_TABLE)

def pte_page_kernel_exec(phys_addr):
	return "((({}) >> {}) << {}) | 0x{:x}".format(phys_addr, PAGE_SHIFT, PAGE_PFN_SHIFT, PAGE_KERNEL_EXEC)

def pgd_entry_index(addr):
	if addr >= KERNEL_MAPPING_BASE_ADDR:
		return int((addr  - KERNEL_MAPPING_BASE_ADDR) / PGDIR_SIZE) + KERNEL_PGDS_NR
	else:
		return int(addr / PGDIR_SIZE)

def pmd_entry_index(addr):
	offset_in_pgdir = addr & (PGDIR_SIZE - 1)
	return int(offset_in_pgdir / PMD_SIZE)

def pte_entry_index(addr):
	offset_in_pgdir = addr & (PMD_SIZE - 1)
	return int(offset_in_pgdir / PAGE_SIZE)

def create_kernel_page_table():
	pgdir_kernel_mapping_entry = pgd_entry_index(KERNEL_LINK_ADDR)
	early_pg_dir[pgdir_kernel_mapping_entry] = pte_page_table("XIP_PHYS_ADDR(early_pmd)")

	# First half resides in flash
	for i in range(0, int(XIP_OFFSET / PMD_SIZE)):
		early_pmd[i] = pte_page_kernel_exec(str(hex(int(xip_phys_addr, 0) + i * PMD_SIZE)))

	# Second half is in RAM
	for i in range(int(XIP_OFFSET / PMD_SIZE), int(2 * XIP_OFFSET / PMD_SIZE)):
		early_pmd[i] = pte_page_kernel_exec(str(hex(int(phys_ram_base, 0) + i * PMD_SIZE - XIP_OFFSET)))

def create_fixaddr_page_table():
	pgdir_fixaddr_entry = pgd_entry_index(FIXADDR_START)
	early_pg_dir[pgdir_fixaddr_entry] = pte_page_table("RAM_PHYS_ADDR(fixmap_pmd)")

	pmd_fixaddr_entry = pmd_entry_index(FIXADDR_START)
	fixmap_pmd[pmd_fixaddr_entry] = pte_page_table("RAM_PHYS_ADDR(fixmap_pte)")

def create_fdt_early_page_table():
	pgdir_fdt_entry = pgd_entry_index(DTB_EARLY_BASE_VA)
	early_pg_dir[pgdir_fdt_entry] = pte_page_table("RAM_PHYS_ADDR(early_dtb_pmd)")

	pmd_fdt_entry = pmd_entry_index(DTB_EARLY_BASE_VA)
	early_dtb_pmd[pmd_fdt_entry] = pte_page_kernel_exec("XIP_PHYS_ADDR(__dtb_start)")
	early_dtb_pmd[pmd_fdt_entry + 1] = pte_page_kernel_exec("XIP_PHYS_ADDR(__dtb_start) + {}".format(PMD_SIZE))

def setup_vm():
	create_kernel_page_table()
	create_fixaddr_page_table()
	if not builtin_dtb:
		create_fdt_early_page_table()

def dump_macros(f):
	f.write("#define XIP_PHYS_ADDR(x) ((x) - KERNEL_LINK_ADDR + {})\n".format(xip_phys_addr))
	f.write("#define RAM_PHYS_ADDR(x) ((x) - KERNEL_LINK_ADDR + {} - 0x{:x})\n".format(phys_ram_base, XIP_OFFSET))
	f.write("\n")

def dump_section_header(f):
	f.write(".init.early_page_table :\n")
	f.write("{\n")

def dump_section_footer(f):
	f.write("}\n")

def dump_page_table_level(f, ptl, nr_entries, ptl_name):
	f.write("\t{} = .;\n".format(ptl_name))
	for i in range(0, nr_entries):
		f.write("\tQUAD({})\n".format(ptl[i]))

def dump_page_table(f):
	dump_page_table_level(f, early_pg_dir, PTRS_PER_PGD, "early_pg_dir")
	dump_page_table_level(f, early_pmd, PTRS_PER_PMD, "early_pmd")
	dump_page_table_level(f, fixmap_pmd, PTRS_PER_PMD, "fixmap_pmd")
	dump_page_table_level(f, fixmap_pte, PTRS_PER_PTE, "fixmap_pte")
	if not builtin_dtb:
		dump_page_table_level(f, early_dtb_pmd, PTRS_PER_PMD, "early_dtb_pmd")

early_pg_dir = [ "0" ] * PTRS_PER_PGD
early_pmd = [ "0" ] * PTRS_PER_PMD
fixmap_pmd = [ "0" ] * PTRS_PER_PMD
fixmap_pte = [ "0" ] * PTRS_PER_PTE
early_dtb_pmd = [ "0" ] * PTRS_PER_PMD

(phys_ram_base, xip_phys_addr, builtin_dtb) = extract_addr_from_config(sys.argv[1])

setup_vm()

with open(EARLY_PAGE_TABLE_LDS_PATH, "w") as flds:
	dump_macros(flds)
	dump_section_header(flds)
	dump_page_table(flds)
	dump_section_footer(flds)
