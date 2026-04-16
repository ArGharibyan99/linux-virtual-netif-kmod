ifneq ($(KERNELRELEASE),)
obj-m := vnetif.o
vnetif-y := src/vnetif.o
else
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(CURDIR)
BUILD_DIR := $(PWD)/build
MODULE := vnetif

.PHONY: all clean

all:
	mkdir -p $(BUILD_DIR)
	$(MAKE) -C $(KDIR) M=$(PWD) MO=$(BUILD_DIR) modules
	cp $(BUILD_DIR)/$(MODULE).ko $(PWD)/$(MODULE).ko

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) MO=$(BUILD_DIR) clean
	rm -rf $(BUILD_DIR)
	rm -f $(PWD)/$(MODULE).ko
endif
