# SPDX-License-Identifier: GPL-2.0
# Copyright 2023 Hewlett Packard Enterprise Development LP

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(CURDIR)
SPARSE_OPTS := "-Wptr-subtraction-blows -Wcast-to-as -Wshadow -Wundef"

.PHONY: tests install check build_info

all default: modules tests build_info

modules:: kdreg2_kernel_skew.h build_info

kdreg2_kernel_skew.h:
	$(MAKE) -C config all

build_info:
	@echo \#define KDREG2_BUILD_DATE \"`date`\" > kdreg2_build.h
	@echo \#define KDREG2_BUILD_HASH \"`git rev-parse --short HEAD`\" >> kdreg2_build.h

install: modules
	-/usr/sbin/rmmod kdreg2
	/usr/sbin/insmod kdreg2.ko

modules clean::
	$(MAKE) -C $(KDIR) M=$(PWD) $@

sparse:
	$(MAKE) -C $(KDIR) M=$(PWD) CF=${SPARSE_OPTS} C=2 modules

check: modules tests
	./cassini-vm/run_tests_vm.sh

tests:
	$(MAKE) -C tests $@

clean::
	$(MAKE) -C tests clean
	$(MAKE) -C config clean
	rm -f kdreg2_kernel_skew.h kdreg2_build.h
