# normal makefile
KDIR ?= /lib/modules/`uname -r`/build

obj-m += pn532_spi.o
obj-m += test_spi.o

all:
	$(MAKE) -C $(KDIR) M=$$PWD $(VERBOSE) modules

install:
	$(MAKE) -C $(KDIR) M=$$PWD modules_install


clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions \
	       modules.order Module.symvers

