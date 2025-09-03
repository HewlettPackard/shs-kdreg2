/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2012-2019 Cray(R)
 * Copyright (C) 2020-2023 Hewlett Packard Enterprise Development LP
 *
 * KDREG2 functions related to module class.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "LICENSE" in the main directory for more details.
 *
 * Derived in part from dreg.c by Pete Wyckoff.
 * Copyright (C) 2004-5 Pete Wyckoff <pw@osc.edu>
 * Distributed under the GNU Public License Version 2 (See LICENSE)
 */

#include "kdreg2_priv.h"

/*
 * kdreg2_show_contexts - output number of contexts
 *
 */
static ssize_t kdreg2_show_contexts(struct device *class_dev,
				    struct device_attribute *attr,
				    char *buf)
{
	int num_contexts;

	kdreg2_global_lock();

	num_contexts = kdreg2_global.num_contexts;

	kdreg2_global_unlock();

	return scnprintf(buf, PAGE_SIZE, "%d\n", num_contexts);
}

/*
 * kdreg2_show_version - output kdreg2 version
 */
static ssize_t kdreg2_show_version(struct device *class_dev,
				   struct device_attribute *attr,
				   char *buf)
{
	/* can't be changed, no need to lock */

	return scnprintf(buf, PAGE_SIZE, "0x%llx\n",
			 kdreg2_global.driver_version);
}

/*
 * kdreg2_show_build_string - output kdreg2 build string
 */
static ssize_t kdreg2_show_build_string(struct device *class_dev,
					struct device_attribute *attr,
					char *buf)
{
	/* can't be changed, no need to lock */

	return scnprintf(buf, PAGE_SIZE, "%s\n",
			 kdreg2_global.build_string);
}

/*
 * kdreg2_show_debug_mask - output current kdreg2 debug mask
 */
static ssize_t kdreg2_show_debug_mask(struct device *class_dev,
				      struct device_attribute *attr,
				      char *buf)
{
	uint32_t debug_mask;

	kdreg2_global_lock();

	debug_mask = kdreg2_global.debug_mask;

	kdreg2_global_unlock();

	return scnprintf(buf, PAGE_SIZE, "0x%x\n", debug_mask);
}

/*
 * kdreg2_set_debug_mask - set the kdreg2 debug mask
 */
static ssize_t kdreg2_set_debug_mask(struct device *class_dev,
				     struct device_attribute *attr,
				     const char *buf, size_t count)
{
	uint32_t value;

	if (kstrtou32(buf, 16, &value))
		return -EINVAL;

	kdreg2_global_lock();

	kdreg2_global.debug_mask = value;

	kdreg2_global_unlock();

	return count;
}

/*
 * kdreg2_show_debug_level - output current kdreg2 debug level
 */
static ssize_t kdreg2_show_debug_level(struct device *class_dev,
				       struct device_attribute *attr,
				       char *buf)
{
	uint32_t debug_level;

	kdreg2_global_lock();

	debug_level = kdreg2_global.debug_level;

	kdreg2_global_unlock();

	return scnprintf(buf, PAGE_SIZE, "%u\n", debug_level);
}

/*
 * kdreg2_set_debug_level - set the kdreg2 debug level
 */
static ssize_t kdreg2_set_debug_level(struct device *class_dev,
				      struct device_attribute *attr,
				      const char *buf,
				      size_t count)
{
	uint32_t value;

	if (kstrtou32(buf, 10, &value))
		return -EINVAL;

	if (value > KDREG2_MAX_DEBUG_LEVEL)
		return -EINVAL;

	kdreg2_global_lock();

	kdreg2_global.debug_level = value;

	kdreg2_global_unlock();

	return count;
}

#define INIT_DEV_ATTR __ATTR   /* from <linux/sysfs.h> */

static struct device_attribute device_attrs[] = {
	INIT_DEV_ATTR(contexts,
		      S_IRUGO,
		      kdreg2_show_contexts,
		      NULL),
	INIT_DEV_ATTR(version,
		      S_IRUGO,
		      kdreg2_show_version,
		      NULL),
	INIT_DEV_ATTR(build_string,
		      S_IRUGO,
		      kdreg2_show_build_string,
		      NULL),
	INIT_DEV_ATTR(debug_mask,
		      S_IRUGO | S_IWUSR,
		      kdreg2_show_debug_mask,
		      kdreg2_set_debug_mask),
	INIT_DEV_ATTR(debug_level,
		      S_IRUGO | S_IWUSR,
		      kdreg2_show_debug_level,
		      kdreg2_set_debug_level),
};

#undef INIT_DEV_ATTR

/*
 * create all class device attributes
 */
int kdreg2_create_class_device_files(void)
{
	struct device_attribute *attr = device_attrs;
	size_t i;
	int ret;

	/* create all the attributes */

	for (i = ARRAY_SIZE(device_attrs); i; i--, attr++) {
		ret = device_create_file(kdreg2_global.class_device, attr);
		if (ret) {
			KDREG2_WARN(KDREG2_LOG_NORMAL, "couldn't create '%s' attribute file\n",
			            attr->attr.name);
			break;
		}
	}

	if (!ret)
		return 0;

	/* Undo the ones that were successfully created. */

	for (i++, attr--; i <= ARRAY_SIZE(device_attrs); i++, attr--)
		device_remove_file(kdreg2_global.class_device, attr);

	return ret;
}

/*
 * kdreg2_remove_cldev_files - remove all class device attribute file
 */
void kdreg2_remove_class_device_files(void)
{
	struct device_attribute *attr = device_attrs;
	size_t i;

	for (i = ARRAY_SIZE(device_attrs); i; i--, attr++)
		device_remove_file(kdreg2_global.class_device, attr);
}

/*
 * Function to set the file mode to 666 when the actual device
 * is created.
 */

#if (KDREG2_CLASS_DEVICE_CONST == 1)
int kdreg2_dev_uevent(const struct device *dev, struct kobj_uevent_env *env)
#else
int kdreg2_dev_uevent(struct device *dev, struct kobj_uevent_env *env)
#endif
{
	add_uevent_var(env, "DEVMODE=%#o", 0666);
	return 0;
}
