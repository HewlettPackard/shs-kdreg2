/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2023 Hewlett Packard Enterprise Development LP
 *
 * Code snippets of APIs which have changed in the kernel.
 *
 * Each snippet has section of this file, and determines one
 * API.
 */

#include "./snippets.h"

/* **************************************************************** */
/* Determine the version of class_create().                         */
/* **************************************************************** */

#if defined(KDREG2_CLASS_CREATE_WITH_MODULE)

#include <linux/cdev.h>

#define CLASS_NAME "class_name"

#if (KDREG2_CLASS_CREATE_WITH_MODULE == 1)

struct class * try_to_create(void)
{
  return class_create(THIS_MODULE, CLASS_NAME);
}

#else

struct class * try_to_create(void)
{
  return class_create(CLASS_NAME);
}

#endif /* (KDREG2_CLASS_CREATE_WITH_MODULE == 1) */

#endif /* defined(KDREG2_CLASS_CREATE_WITH_MODULE) */

/* **************************************************************** */
/* Determine the version of the 'dev_uevent' function.              */
/* **************************************************************** */

#if defined(KDREG2_CLASS_DEVICE_CONST)

#include <linux/cdev.h>

#if (KDREG2_CLASS_DEVICE_CONST == 1)

static int my_dev_uevent(const struct device *dev,
			 struct kobj_uevent_env *env)
{
	return 0;
}

#else

static int my_dev_uevent(struct device *dev,
			 struct kobj_uevent_env *env)
{
	return 0;
}

#endif /* (KDREG2_CLASS_DEVICE_CONST == 1) */

static const struct class my_class = {
	.dev_uevent = my_dev_uevent,
};

#endif /* defined(KDREG2_CLASS_DEVICE_CONST) */

/* **************************************************************** */
/* Determine the method for locking the memory map.                 */
/* **************************************************************** */

#if defined(KDREG2_HAS_MMAP_WRITE_LOCK)

#include <linux/mm.h>
#include <linux/mm_types.h>

#if (KDREG2_HAS_MMAP_WRITE_LOCK == 0)

static inline void mmap_write_lock(struct mm_struct *mm)
{
	down_write(&mm->mmap_sem);
}

static inline void mmap_write_unlock(struct mm_struct *mm)
{
	up_write(&mm->mmap_sem);
}

#else

void test_func(struct mm_struct *mm)
{
	mmap_write_lock(mm);
	mmap_write_unlock(mm);
}

#endif /* (KDREG2_HAS_MMAP_WRITE_LOCK == 0) */

#endif /* defined(KDREG2_HAS_MMAP_WRITE_LOCK) */

/* **************************************************************** */
/* Determine the version of 'invalidate_range_end' function of the  */
/* mmu_notifier.                                                    */
/* **************************************************************** */

#if defined(KDREG2_MMU_NOTIFIER_VERSION)

#include <linux/mmu_notifier.h>

#if (KDREG2_MMU_NOTIFIER_VERSION == 1)

static void
kdreg2_invalidate_range_end(struct mmu_notifier *notifier,
			    struct mm_struct *mm,
			    unsigned long start,
			    unsigned long end)
{
	pr_info("mmu_notifier using older API.\n");
}

#elif (KDREG2_MMU_NOTIFIER_VERSION == 2)

static void
kdreg2_invalidate_range_end(struct mmu_notifier *notifier,
			    const struct mmu_notifier_range *range)
{
	pr_info("mmu_notifier using newer API.\n");
}

#else
#error "MMU_NOTIFIER_VERSION unknown/undefined."
#endif /* (KDREG2_MMU_NOTIFIER_VERSION == 1) */

static const struct mmu_notifier_ops kdreg2_mmuops = {
	.invalidate_range_end   = kdreg2_invalidate_range_end,
};

#endif /* defined(KDREG2_MMU_NOTIFIER_VERSION) */

/* **************************************************************** */
/* Determine whether the interval tree uses a rb_root or            */
/* rb_root_cached object.                                           */
/* **************************************************************** */

#if defined(KDREG2_HAS_RB_ROOT_CACHED)

#include <linux/interval_tree_generic.h>

struct dummy_interval {
	struct rb_node node;
	int     start;
	int     last;
	int     subtree_last;
};

int dummy_start(struct dummy_interval *d)
{
	return d->start;
}

int dummy_last(struct dummy_interval *d)
{
	return d->last;
}

INTERVAL_TREE_DEFINE(struct dummy_interval,
		     node,
		     int,
		     subtree_last,
		     dummy_start,
		     dummy_last,
		     /* static */,
		     dummy_tree)

#if (KDREG2_HAS_RB_ROOT_CACHED == 0)
struct rb_root          root;
#else
struct rb_root_cached   root;
#endif /* (KDREG2_HAS_RB_ROOT_CACHED == 0) */

void insert_interval(struct dummy_interval *d)
{
	dummy_tree_insert(d, &root);
}

#endif /* defined(KDREG2_HAS_RB_ROOT_CACHED) */
