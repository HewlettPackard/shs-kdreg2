/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2023 Hewlett Packard Enterprise Development LP
 */

#include "kdreg2.h"

#include <stdio.h>

struct test_mr_context;

struct test_mr_context * test_mr_allocate_context(void);
int test_mr_free_context(struct test_mr_context * context);
int test_mr_start(struct test_mr_context * context,
		  size_t max_regions);
int test_mr_stop(struct test_mr_context * context);
int test_mr_register(struct test_mr_context * context,
		     void * addr, size_t len, kdreg2_cookie_t cookie);
int test_mr_unregister(struct test_mr_context * context,
		       kdreg2_cookie_t cookie);
void test_mr_show_stats(struct test_mr_context * context, FILE *file);
