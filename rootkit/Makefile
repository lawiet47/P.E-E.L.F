obj-m += r3kroot.o


r3kroot-objs := rootkit.o

KDIR    := /lib/modules/$(shell uname -r)/build
PWD    := $(shell pwd)
 
modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	-rm -f *.o *.ko .*.cmd .*.flags *.mod.c
	$(MAKE) -C $(KDIR) M=$(PWD) clean
