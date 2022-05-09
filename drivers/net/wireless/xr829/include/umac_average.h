#ifndef UMAC_AVERAGE_H
#define UMAC_AVERAGE_H

#include <linux/average.h>

DECLARE_EWMA(umac, 1024, 8);

#endif
