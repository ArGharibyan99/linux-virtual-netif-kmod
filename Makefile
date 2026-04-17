KDIR      := /lib/modules/$(shell uname -r)/build
PWD       := $(CURDIR)
BUILD_DIR := $(PWD)/build
MODULE    := vnetif

.PHONY: all clean test

all:
	mkdir -p $(BUILD_DIR)
	printf 'obj-m    := vnetif.o\nvnetif-y := ../src/vnetif.o\n' \
		> $(BUILD_DIR)/Kbuild
	$(MAKE) -C $(KDIR) M=$(BUILD_DIR) modules

clean:
	rm -rf $(BUILD_DIR)

test: all
	cmake -S tests -B $(BUILD_DIR)/tests -DCMAKE_BUILD_TYPE=Release
	cmake --build $(BUILD_DIR)/tests --parallel
	sudo $(BUILD_DIR)/tests/vnetif_tests
