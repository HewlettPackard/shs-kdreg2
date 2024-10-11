# SPDX-License-Identifier: GPL-2.0
# Copyright 2023 Hewlett Packard Enterprise Development LP
#
# This makefile attempts to detect which version of the various
# kernel APIs are present.  Different distros backport fixes at
# different times.  This results in skew between the distros.
#
# The strategy here is to compile very minimal code snippets
# which attempt to use the APIs which have changed over time.
# The assumption is that if the snippet compiles then the
# support for that version of the API and the underlying
# functionality that kdreg2 needs is present.
#
# This is really a stripped down version of autoconf.
#
# I apologize in advance for the recursive usage of make.

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(CURDIR)

SNIPPET_FILE = snippets.c
EXTERNAL_DEPENDS = Makefile ./configure_snippet.sh $(SNIPPET_FILE)

SKEW_FILES = class_create.h \
	class_device.h \
	mmap_write_lock.h \
	mmu_notifier.h \
	rb_root_cached.h

SNIPPET_OBJ = $(SNIPPET_FILE:.c=.o)

# Note: because we re-compile the snippet file for each
# configuration, the build can not be parallelized.
.NOTPARALLEL:

all: ../kdreg2_kernel_skew.h

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	-rm -f $(SKEW_FILES) $(SNIPPET_OBJ)

../kdreg2_kernel_skew.h: $(SKEW_FILES)
	cat $(SKEW_FILES) > $@

mmu_notifier.h: $(EXTERNAL_DEPENDS)
	./configure_snippet.sh $@ KDREG2_MMU_NOTIFIER_VERSION "1 2"

rb_root_cached.h: $(EXTERNAL_DEPENDS)
	./configure_snippet.sh $@ KDREG2_HAS_RB_ROOT_CACHED "0 1"

mmap_write_lock.h: $(EXTERNAL_DEPENDS)
	./configure_snippet.sh $@ KDREG2_HAS_MMAP_WRITE_LOCK "1 0"

class_device.h: $(EXTERNAL_DEPENDS)
	./configure_snippet.sh $@ KDREG2_CLASS_DEVICE_CONST "1 0"

class_create.h: $(EXTERNAL_DEPENDS)
	./configure_snippet.sh $@ KDREG2_CLASS_CREATE_WITH_MODULE "1 0"

$(SNIPPET_OBJ):
	$(MAKE) -C $(KDIR) M=$(PWD) $@
