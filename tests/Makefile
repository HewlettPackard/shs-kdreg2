# SPDX-License-Identifier: GPL-2.0
#
# Makefile for tests for kdreg2 module
#
# Copyright (C) 2012 Cray Inc. All Rights Reserved.
# Copyright (C) 2020-2023 Hewlett Packard Enterprise Development LC
#
# Distributed under the GNU Public License Version 2 (See LICENSE).
#
.SUFFIXES:
.SUFFIXES: .c .h .o

DEBUG := -g
#DEBUG := -O3

CC ?= gcc
CFLAGS := $(DEBUG)
CFLAGS += -fno-common

CFLAGS += -std=gnu11
CFLAGS += -Werror -Wall -Wno-unused
CFLAGS += -W -Wpointer-arith
CFLAGS += -Wcast-align -Wcast-qual -Wbad-function-cast
CFLAGS += -Wmissing-prototypes -Wmissing-declarations
CFLAGS += -Wnested-externs
CFLAGS += -Wshadow -Wredundant-decls
CFLAGS += -I../include

ifeq ($(CC),gcc)
# -Wstrict-prototypes
endif

ifeq ($(CC),clang)
CFLAGS += -Wno-format-security -Wno-cast-align
endif

# source files

TEST_SRC := test_basic.c \
            test_open_close.c \
            test_multi_open.c \
            test_fork.c \
            test_fork2.c \
            test_fork3.c \
            test_threads.c \
            test_resize.c

MR_SRC := test_mr.c

# derived objects

TEST_OBJ := $(TEST_SRC:.c=.o)
TESTS    := $(TEST_SRC:.c=)
EXES     := $(TESTS) test_ranks.sh test_fork3_reversed.sh

MR_OBJ := $(MR_SRC:.c=.o)

OBJ := $(TEST_OBJ) $(MR_OBJ)

LIB := -lpthread

.PHONY: all clean FORCE check tests

all tests: $(EXES)

kdreg2.h:
	ln -s ../include/kdreg2.h kdreg2.h

$(OBJ): Makefile kdreg2.h

$(MR_OBJ): test_mr.h dlist.h

test_threads.o: test_mr.h

test_threads: test_threads.o $(MR_OBJ)
	$(CC) $(DEBUG) $^ -o $@ $(LIB)

%.o: %.c
	$(CC) $(DEBUG) -c $<

%: %.o
	$(CC) $(DEBUG) $< -o $@

clean::
	-rm -f $(OBJ) $(TESTS) tags kdreg2.h

echo_tests: $(EXES)
	echo "$(EXES)"

check test run_tests: $(EXES) run_tests.sh
	./run_tests.sh
