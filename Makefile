obj-m += rkspotter.o

KDIR ?= /lib/modules/$(shell uname -r)/build
ARCH ?= riscv
CROSS_COMPILE ?= riscv64-unknown-linux-gnu-

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) ARCH=$(ARCH) \
		CROSS_COMPILE=$(CROSS_COMPILE) modules
clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) ARCH=$(ARCH) \
		CROSS_COMPILE=$(CROSS_COMPILE) clean
