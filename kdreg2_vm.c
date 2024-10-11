/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2012-2019 Cray(R)
 * Copyright (C) 2020-2023 Hewlett Packard Enterprise Development LP
 *
 * KDREG2 functions for mapping kernel memory to user space.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "LICENSE" in the main directory for more details.
 *
 * Derived in part from dreg.c by Pete Wyckoff.
 * Copyright (C) 2004-5 Pete Wyckoff <pw@osc.edu>
 * Distributed under the GNU Public License Version 2 (See LICENSE)
 */

#include "kdreg2_priv.h"

#include <linux/mm.h>
#include <linux/mman.h>

#ifndef INSTALL_GDB_HOOK
#define INSTALL_GDB_HOOK 0
#endif

#if INSTALL_GDB_HOOK && defined(CONFIG_HAVE_IOREMAP_PROT)

/* See:
 * https://stackoverflow.com/questions/654393/examining-mmaped-addresses-using-gdb
 *
 * This should allow using gdb to access the mapped memory from the user space
 * side.
 *
 * This gets called, but doesn't seem to work on all distros....
 */

static int my_access(struct vm_area_struct *vma, unsigned long addr,
		     void *buf, int len, int write)
{
	int ret = generic_access_phys(vma, addr, buf, len, write);

	pr_info("Accessing 0x%lx size %i flags 0x%lx, ret = %i\n",
		addr, len, vma->vm_flags, ret);
	return ret;
}

static const struct vm_operations_struct mmap_mem_ops = {
	.access = my_access,
};

#endif

/* These functions were introduced in 5.4.  But it seems
 * they may have been backported to the later 5.3.18 updated
 * releases as well.  So the preprocessor test may be off
 * slightly.
 *
 * RHEL appears to have backported these functions to even
 * earlier kernel versions, including 4.18.0 (rhel 8.7).
 *
 * In later kernels, the name 'mmap_sem' is changed to
 * 'mmap_lock'.  Using the functions hides this change and
 * is the preferred method going forward.
 */

#if KDREG2_HAS_MMAP_WRITE_LOCK == 0
static inline void mmap_write_lock(struct mm_struct *mm)
{
	down_write(&mm->mmap_sem);
}

static inline void mmap_write_unlock(struct mm_struct *mm)
{
	up_write(&mm->mmap_sem);
}
#endif

void kdreg2_init_vm_map(struct kdreg2_vm_map *vm_map)
{
	vm_map->size        = 0;
	vm_map->user_addr   = NULL;
	vm_map->kernel_addr = NULL;
	vm_map->vma         = NULL;
}

/*
 * kdreg2_create_vm_map - Create space writable from
 * the kernel but read-only from user-space.
 *
 * Allows user-space to get data without a system call.
 */

int kdreg2_create_vm_map(struct kdreg2_vm_map *vm_map,
			 size_t mapping_size,
			 const char *purpose)
{
	int                     ret = 0;
	void __user             *user_virtual_addr;
	void                    *kern_virtual_addr;
	struct vm_area_struct   *vma;
	const unsigned long     vm_flags = (MAP_ANONYMOUS | MAP_SHARED);

	KDREG2_DEBUG(KDREG2_DEBUG_ALL, 1,
		     "Creating mapping for %zi bytes for %s.",
		     mapping_size, purpose);

	if (!mapping_size) {
		vm_map->user_addr   = (void __user *) NULL;
		vm_map->kernel_addr = NULL;
		vm_map->size        = 0;
		vm_map->vma         = NULL;

		KDREG2_DEBUG(KDREG2_DEBUG_INIT, 1,
			     "Success: created mapping for %zi bytes, "
			     "user_addr = 0x%px, kern_addr 0x%px.",
			     vm_map->size, vm_map->user_addr,
			     vm_map->kernel_addr);
		return 0;
	}

	/* get pages filled with zeroes */

	KDREG2_DEBUG(KDREG2_DEBUG_INIT, 1,
		     "Allocating space for %zu bytes.",
		     mapping_size);

	kern_virtual_addr = vmalloc_user(mapping_size);

	if (!kern_virtual_addr) {
		pr_warn("Unable to allocate %zu bytes for mapping",
			mapping_size);
		return -ENOMEM;
	}

	/* Find room in process address space for the virtual addresses. */

	KDREG2_DEBUG(KDREG2_DEBUG_INIT, 1,
		     "Looking for user-space addresses for %zi bytes.",
		     mapping_size);

	user_virtual_addr = (void __user *) vm_mmap(NULL, 0, mapping_size,
						    PROT_READ, vm_flags, 0);

	if (IS_ERR(user_virtual_addr)) {
		ret = PTR_ERR(user_virtual_addr);
		pr_warn("Unable to find user-space addresses for %zi bytes",
			mapping_size);
		goto error_vm_mmap;
	}

	KDREG2_DEBUG(KDREG2_DEBUG_INIT, 1,
		     "Found user-space address 0x%px for %zi bytes.",
		     user_virtual_addr, mapping_size);

	/* Find the vma for this user-space address */

	mmap_write_lock(current->mm);

	vma = find_vma(current->mm, (unsigned long) user_virtual_addr);
	if (!vma) {
		ret = -EINVAL;
		goto error_find_vma;
	}

	KDREG2_DEBUG(KDREG2_DEBUG_INIT, 1,
		     "VMA: start: 0x%lx, end: 0x%lx, flags: 0x%lx",
		     vma->vm_start, vma->vm_end, vma->vm_flags);

	/* Map page read-only into the process address space. */

	ret = remap_vmalloc_range(vma, kern_virtual_addr, 0);

	if (ret) {
		pr_warn("Unable to map kern virtual address 0x%px "
			"to user virtual address 0x%px.",
			kern_virtual_addr, user_virtual_addr);
		goto error_remap_vmalloc_range;
	}

#if INSTALL_GDB_HOOK && defined(CONFIG_HAVE_IOREMAP_PROT)

	/* Hook in the generic access method so that gdb can access this space. */

	vma->vm_ops = &mmap_mem_ops;
#endif

	mmap_write_unlock(current->mm);

	/* record the results in the mapping struct */

	vm_map->user_addr   = user_virtual_addr;
	vm_map->kernel_addr = kern_virtual_addr;
	vm_map->size        = mapping_size;
	vm_map->vma         = vma;

	KDREG2_DEBUG(KDREG2_DEBUG_ALL, 1,
		     "Success: created mapping for %zi bytes, "
		     "user_addr = 0x%px, kern_addr 0x%px.",
		     vm_map->size, vm_map->user_addr,
		     vm_map->kernel_addr);
	return 0;

error_remap_vmalloc_range:
error_find_vma:

	mmap_write_unlock(current->mm);
	vm_munmap((unsigned long) user_virtual_addr, mapping_size);

error_vm_mmap:

	vfree(kern_virtual_addr);
	pr_warn("Return with error: %i.", ret);

	return ret;
}

/* kdreg2_vm_destroy_mapping - destroy mapped address range and pages */

void kdreg2_destroy_vm_map(struct kdreg2_vm_map *vm_map)
{
	KDREG2_DEBUG(KDREG2_DEBUG_ALL, 1,
		     "Removing mapping: user_addr = 0x%px kern_addr 0x%px",
		     vm_map->user_addr, vm_map->kernel_addr);

	if (!vm_map->size)
		return;

	/*
	 * Remove the region from the process address space, if address space
	 * is present.
	 */

	if (current->mm)
		vm_munmap((unsigned long) vm_map->user_addr, vm_map->size);

	/*
	 * free the physical page
	 */

	vfree(vm_map->kernel_addr);

	/* Clear our pointers */

	kdreg2_init_vm_map(vm_map);
}
