obj-m	:= mmap.o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
KVER      :=(shell uname -r)
#KERNELDIR ?= /lib/modules/2.6.18-8.el5/build/

PWD       := $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
clean:
	rm -rf *.o *.ko *.mod.c	
