# SPDX-License-Identifier: GPL-2.0
ifneq ($(CONFIG_SOC_CANAAN_K210_DTB_SOURCE),"")
dtb-y += $(strip $(shell echo $(CONFIG_SOC_CANAAN_K210_DTB_SOURCE))).dtb
obj-$(CONFIG_BUILTIN_DTB) += $(addsuffix .o, $(dtb-y))
endif
