# SPDX-License-Identifier: GPL-2.0
# External Kbuild, using the matching CONFIG_IEE_RKSPOTTER kernel.
ifeq ($(CONFIG_IEE_RKSPOTTER),y)
obj-m += rkspotter.o
CFLAGS_REMOVE_rkspotter.o += $(CC_FLAGS_FTRACE)
KASAN_SANITIZE_rkspotter.o := n
KCSAN_SANITIZE_rkspotter.o := n
UBSAN_SANITIZE_rkspotter.o := n
KCOV_INSTRUMENT_rkspotter.o := n
GCOV_PROFILE_rkspotter.o := n
endif
