# SPDX-License-Identifier: GPL-2.0
# Copyright 2023 Hewlett Packard Enterprise Development LP

$(info Building with KERNELRELEASE = ${KERNELRELEASE})

obj-m := kdreg2.o

kdreg2-y := kdreg2_main.o \
            kdreg2_context.o \
	    kdreg2_class.o \
            kdreg2_event_queue.o \
            kdreg2_file.o \
            kdreg2_mmu_notifier.o \
	    kdreg2_monitoring_data.o \
            kdreg2_region.o \
            kdreg2_status_data.o \
            kdreg2_vm.o

ccflags-y += -DDEBUG -Werror -I$(PWD)/include

