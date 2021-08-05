#include <asm/pgtable.h>

__section((".xip_pgtable")) unsigned long fixaddr_start = FIXADDR_START;
__section((".xip_pgtable")) unsigned long pmd_size = PMD_SIZE;
