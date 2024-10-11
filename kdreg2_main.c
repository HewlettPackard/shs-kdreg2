/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2012-2019 Cray(R)
 * Copyright (C) 2020-2023 Hewlett Packard Enterprise Development LP
 *
 * Kernel level memory registration cache monitoring interface (KDREG2).
 *
 * The purpose of this driver is to allow processes to safely cache
 * memory registration information in user space.  An application using
 * kdreg2 supplies the driver with 'monitor' requests.  A monitor
 * request specifies a region in the process's virtual address space that
 * should be 'monitored' by kdreg2, and report back to user space
 * when a virtual memory operation has occurred which would cause
 * the cached memory registration information to be invalid.  The
 * application is responsible for doing the hardware device specific
 * memory deregistration and cache cleanup.
 *
 * KDREG2 uses the mmu_notifier interface to monitor for changes in
 * the virtual address space of the process/thread group.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "LICENSE" in the main directory for more details.
 *
 * Derived in part from dreg.c by Pete Wyckoff.
 * Copyright (C) 2004-5 Pete Wyckoff <pw@osc.edu>
 * Distributed under the GNU Public License Version 2 (See LICENSE)
 */

#include "kdreg2_priv.h"
#include "kdreg2_version.h"
#include "kdreg2_build.h"

#include <linux/module.h>
#include <linux/slab.h>

MODULE_AUTHOR("Pete Wyckoff");
MODULE_AUTHOR("Cray Inc.");
MODULE_AUTHOR("Hewlett Packard Enterprise Development LP");
MODULE_DESCRIPTION("Dynamic registration cache monitoring using mmu notifiers");
MODULE_LICENSE("GPL v2");

static const char * const copyright[] = {
	"Copyright (C) 2004-5 Pete Wyckoff",
	"Copyright (C) 2012-2019 Cray(R)",
	"Copyright (C) 2020-2023 Hewlett Packard Development LP",
};

struct kdreg2_global kdreg2_global = {
	.driver_string           = "Kernel Dynamic Registration (KDREG2) Interface",
	.driver_copyright        = copyright,
	.num_copyright           = ARRAY_SIZE(copyright),
	.driver_name             = KDREG2_DRIVER_NAME,
	.class_name              = KDREG2_CLASS_NAME,
	.build_string            = KDREG2_BUILD_DATE " " KDREG2_BUILD_HASH,
	.driver_version          = KDREG2_DRIVER_VERSION,
	.driver_lock             = __MUTEX_INITIALIZER(kdreg2_global.driver_lock),
	.dev_id                  = 0,
	.major_dev               = 0,
	.driver_numdev           = 1,
	.num_contexts            = 0,
	.debug_level             = KDREG2_DEBUG_LEVEL,
	.debug_mask              = KDREG2_DEBUG_MASK,
	.class                   = NULL,
	.class_device            = NULL,
	.kdreg2_dev              = { },
};

static struct file_operations kdreg2_fops = {
	.owner          = THIS_MODULE,
	.read           = kdreg2_read,
	.write          = kdreg2_write,
	.poll           = kdreg2_poll,
	.unlocked_ioctl = kdreg2_ioctl,
	.open           = kdreg2_open,
	.release        = kdreg2_release,
};

/*
 * Module initialization
 */

static int __init kdreg2_module_init(void)
{
	int ret;
	size_t i;

	pr_info("%s - version 0x%llx\n", kdreg2_global.driver_string,
		kdreg2_global.driver_version);

	for (i = 0; i < kdreg2_global.num_copyright; i++)
		pr_info("%s\n", kdreg2_global.driver_copyright[i]);

	/* Register driver */
	if (!kdreg2_global.major_dev) {
		ret = alloc_chrdev_region(&kdreg2_global.dev_id, 0,
					  kdreg2_global.driver_numdev,
					  kdreg2_global.driver_name);
		kdreg2_global.major_dev = MAJOR(kdreg2_global.dev_id);
	} else {
		kdreg2_global.dev_id = MKDEV(kdreg2_global.major_dev, 0);
		ret = register_chrdev_region(kdreg2_global.dev_id,
					     kdreg2_global.driver_numdev,
					     kdreg2_global.driver_name);
	}
	if (ret)
		goto err_alloc_chrdev;

	/* Set the device file operations */

	cdev_init(&kdreg2_global.kdreg2_dev.cdev, &kdreg2_fops);
	ret = cdev_add(&kdreg2_global.kdreg2_dev.cdev,
		       kdreg2_global.dev_id,
		       kdreg2_global.driver_numdev);
	if (ret)
		goto err_cdev_add;

	/* set up the kdreg2 class */

	KDREG2_DEBUG(KDREG2_DEBUG_INIT, 2,
		     "creating class %s", kdreg2_global.class_name);

#if KDREG2_CLASS_CREATE_WITH_MODULE
	kdreg2_global.class = class_create(THIS_MODULE,
					   kdreg2_global.class_name);
#else
	kdreg2_global.class = class_create(kdreg2_global.class_name);
#endif
	if (IS_ERR(kdreg2_global.class)) {
		ret = PTR_ERR(kdreg2_global.class);
		pr_warn("couldn't create class %s\n",
			kdreg2_global.class_name);
		goto err_class_create;
	}

	kdreg2_global.class->dev_uevent = kdreg2_dev_uevent;

	/* create class device */

	KDREG2_DEBUG(KDREG2_DEBUG_INIT, 2,
		     "creating %s device", kdreg2_global.class_name);

	kdreg2_global.class_device =
		device_create(kdreg2_global.class, NULL,
			      kdreg2_global.dev_id, NULL,
			      "%s", kdreg2_global.driver_name);

	if (IS_ERR(kdreg2_global.class_device)) {
		ret = PTR_ERR(kdreg2_global.class_device);
		pr_warn("class_device_create() returned error %d\n", ret);
		goto err_class_dev;
	}

	ret = kdreg2_create_class_device_files();
	if (ret) {
		pr_warn("couldn't create attribute files.\n");
		goto err_class_dev_attr_files;
	}

	pr_info("data mode: %s\n", KDREG2_DB_MODE_NAME);
	pr_info("Module installed successfully.\n");

	return 0;

err_class_dev_attr_files:

	device_destroy(kdreg2_global.class,
		       kdreg2_global.kdreg2_dev.cdev.dev);

err_class_dev:

	class_destroy(kdreg2_global.class);

err_class_create:

	cdev_del(&kdreg2_global.kdreg2_dev.cdev);

err_cdev_add:

	unregister_chrdev_region(kdreg2_global.dev_id,
				 kdreg2_global.driver_numdev);

err_alloc_chrdev:

	pr_warn("Module installation aborted: %i.\n", ret);

	return ret;
}

/*
 * Module removal.
 */

static void __exit kdreg2_module_exit(void)
{
	KDREG2_DEBUG(KDREG2_DEBUG_EXIT, 1,
		     "Cleaning up kdreg2 module resources");

	/* clean up sys fs stuff first, then destroy the device, etc. */
	kdreg2_remove_class_device_files();
	device_destroy(kdreg2_global.class,
		       kdreg2_global.kdreg2_dev.cdev.dev);
	class_destroy(kdreg2_global.class);
	cdev_del(&kdreg2_global.kdreg2_dev.cdev);

	unregister_chrdev_region(kdreg2_global.dev_id,
				 kdreg2_global.driver_numdev);

	pr_info("Module uninstalled.\n");

}

module_init(kdreg2_module_init);
module_exit(kdreg2_module_exit);
