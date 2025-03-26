/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2012-2019 Cray(R)
 * Copyright (C) 2020-2023 Hewlett Packard Enterprise Development LP
 *
 * KDREG2 file operations.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "LICENSE" in the main directory for more details.
 *
 * Derived in part from dreg.c by Pete Wyckoff.
 * Copyright (C) 2004-5 Pete Wyckoff <pw@osc.edu>
 * Distributed under the GNU Public License Version 2 (See LICENSE)
 */

#include "kdreg2_priv.h"

#include <linux/module.h>
#include <linux/poll.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

/*
 * Open operation:
 *   Create the context for this instance.  A context is tied to an
 * mm instance, which is shared by all threads in a process, but does
 * not span processes.
 */

int kdreg2_open(struct inode *inode,
		struct file *file)
{
	struct kdreg2_context  *context;
	int ret;

	KDREG2_DEBUG(KDREG2_DEBUG_OPEN, 1, "Open initiated.");

	if (!try_module_get(THIS_MODULE))
		return -ENODEV;

	/* Allocate a new context structure */

	KDREG2_DEBUG(KDREG2_DEBUG_OPEN, 2, "Allocating new context.");

	context = kzalloc(sizeof(*context), GFP_KERNEL);
	if (!context) {
		ret = -ENOMEM;
		goto err_ret;
	}

	KDREG2_DEBUG(KDREG2_DEBUG_OPEN, 2,
		     "Context successfully allocated.");

	/* We increment the ref count for mm while setting up the context.
	 * We can use the value of mm to detect copy-on-exec and fork
	 * since each process has its own mm.
	 */

	context->mm = get_task_mm(current);

	if (!context->mm) {
		ret = -ENODEV;
		goto err_with_context;
	}
	KDREG2_DEBUG(KDREG2_DEBUG_OPEN, 2,
		     "Incremented reference to mm 0x%px", context->mm);

	/* initialize the context */

	ret = kdreg2_context_init(context, 0);
	if (ret)
		goto err_with_mm;

	kdreg2_global_lock();

	/* Cache context with the file struct. */

	file->private_data = context;
	kdreg2_global.num_contexts++;

	kdreg2_global_unlock();

	pr_info("Instance opened.\n");

	return 0;

err_with_mm:

	mmput(context->mm);

err_with_context:

	kfree(context);

err_ret:

	module_put(THIS_MODULE);
	pr_info("Instance opening failed: %i.\n", ret);
	return ret;
}

/* Counterpart to kdreg2_open(): kdreg2_release() is called when
 * the file descriptor obtained from kdreg2_open() is closed.
 * Note: the kernel may call this function from either the original
 * process or a fork.
 */

int kdreg2_release(struct inode *inode,
		   struct file *file)
{
	struct kdreg2_context *context;
	struct mm_struct *mm;

	KDREG2_DEBUG(KDREG2_DEBUG_CLOSE, 1,
		     "Release (close) initiated.");

	kdreg2_global_lock();

	if (!file || !file->private_data) {
		kdreg2_global_unlock();
		pr_info("Instance closed, nothing to do.\n");
		return 0;
	}

	context = file->private_data;
	file->private_data = NULL;
	kdreg2_global.num_contexts--;

	kdreg2_global_unlock();

	/* Destroy all internal kdreg2 resources associated with
	 * the context and free it.
	 */

	mm = context->mm;
	kdreg2_context_destroy(context);
	kfree(context);

	/* Release reference to mm_struct we obtained in kdreg2_open. */

	if (mm) {
		mmput(mm);
		KDREG2_DEBUG(KDREG2_DEBUG_CLOSE, 2,
			     "Decremented reference to mm 0x%px", mm);
	}

	module_put(THIS_MODULE);
	pr_info("Instance closed.\n");

	return 0;
}

/*
 * Handle notification to userspace.  Reading on the device
 * will give an indication that the kernel has detected mapping
 * changes for a monitored region.  Poll is also implemented and
 * will return pending read data when a notification is posted.
 *
 * Blocking and Non-blocking reads are supported.
 */
ssize_t kdreg2_read(struct file *file,
		    char __user *buf,
		    size_t len,
		    loff_t *ppos)
{
	struct kdreg2_context     *context     = file->private_data;
	bool non_blocking = (file->f_flags & O_NONBLOCK) ? true : false;
	ssize_t ret;

	KDREG2_DEBUG(KDREG2_DEBUG_READ, 2, "Read len %zi, offset %llu",
		     len, *ppos);

	ret = kdreg2_detect_fork(context);
	if (ret)
		return ret;

	if (*ppos != file->f_pos)    /* pread not supported */
		return -ESPIPE;

	if (!len)                    /* you want 0 bytes, you got 'em. */
		return 0;

	kdreg2_context_lock(context);

	ret = kdreg2_event_queue_read(context, buf, len, non_blocking);

	kdreg2_context_unlock(context);

	KDREG2_DEBUG(KDREG2_DEBUG_READ, 2, "Read returns %zi", ret);

	return ret;
}

ssize_t kdreg2_write(struct file *file,
		     const char __user *ubuf,
		     size_t len,
		     loff_t *ppos)
{
	struct kdreg2_context *context = file->private_data;
	int ret;

	KDREG2_DEBUG(KDREG2_DEBUG_WRITE, 1,
		     "Write of %zi bytes attempted.", len);

	ret = kdreg2_detect_fork(context);

	return (ret) ? ret : -EOPNOTSUPP;   /* operation not supported */
}

/* Poll implementation for kdreg2 device */

__poll_t kdreg2_poll(struct file *file,
		     struct poll_table_struct *wait)
{
	struct kdreg2_context     *context     = file->private_data;
	struct kdreg2_event_queue *event_queue = &context->event_queue;
	wait_queue_head_t         *wait_queue  = &context->wait_queues.poll_queue;
	__poll_t                  mask = 0;

	/* These casts are ugly but not all kernel versions support the
	 * cleaner EPOLL* variants.
	 */
	const __poll_t  error_mask = (__force __poll_t) (POLLERR |
							 POLLIN  | POLLRDNORM |
							 POLLOUT | POLLWRNORM);
	const __poll_t  read_mask  = (__force __poll_t) (POLLIN  | POLLRDNORM);

	/* Return POLLERR if detect we are the child
	 * process after fork.
	 *
	 * There is really no way to return an error code
	 * from poll() itself.  By setting POLLIN and POLLOUT
	 * the user will be steered to calling read() or write().
	 * When they do, they get a real error code.
	 */

	if (kdreg2_detect_fork(context))
		return error_mask;

	kdreg2_context_lock(context);

	poll_wait(file, wait_queue, wait);

	/* If we have any events waiting signal ready for reading. */

	if (kdreg2_event_queue_get_num_pending(event_queue) > 0)
		mask = read_mask;

	kdreg2_context_unlock(context);

	KDREG2_DEBUG(KDREG2_DEBUG_POLL, 1, "Poll returns 0x%x", mask);

	return mask;
}

/* arg is a pointer to a kdreg2_config_data structure */

static long ioctl_config_data(struct kdreg2_context *context,
			      unsigned long arg)
{
	struct kdreg2_config_data  config;
	int ret;

	void __user *arg_addr = (void __user *) arg;

	KDREG2_DEBUG(KDREG2_DEBUG_IOCTL, 2, "arg 0x%px", arg_addr);

	if (copy_from_user(&config, arg_addr, sizeof(config)))
		return -EFAULT;

	config.status_data = context->status.user_addr;

	if (copy_to_user(arg_addr, &config, sizeof(config)))
		return -EFAULT;

	KDREG2_DEBUG(KDREG2_DEBUG_IOCTL, 1,
		     "Setting max_regions to %zi.",
		     config.max_regions);

	ret = kdreg2_context_resize(context, config.max_regions);

	KDREG2_DEBUG(KDREG2_DEBUG_IOCTL, 1, "Returns %i", ret);

	return ret;
}

static long ioctl_monitor(struct kdreg2_context *context,
			  unsigned long arg)
{
	struct kdreg2_ioctl_monitor   monitor;
	struct kdreg2_ioctl_unmonitor unmonitor;
	struct kdreg2_region_db       *region_db = &context->region_db;
	uint64_t num_active_regions;
	int ret;

	if (copy_from_user(&monitor, (void __user *) arg, sizeof(monitor)))
		return -EFAULT;

	if (monitor.length <= 0)
		return -EINVAL;

	if (monitor.cookie == KDREG2_BAD_COOKIE_VALUE)
		return -EINVAL;

	kdreg2_context_lock(context);

	ret = kdreg2_monitor_region(context, &monitor);
	if (ret) {
		KDREG2_DEBUG(KDREG2_DEBUG_IOCTL, 1,
			     "Monitor request fails %i", ret);
		goto unlock_return;
	}

	if (copy_to_user((void __user *) arg, &monitor, sizeof(monitor))) {
		ret = -EFAULT;
		KDREG2_DEBUG(KDREG2_DEBUG_IOCTL, 1,
			     "Monitor success, unable to copy result (error %i), unmonitoring",
			     ret);
		goto unmonitor;
	}

	/* the number of regions should only change on success */

	num_active_regions = kdreg2_region_db_get_num_regions(region_db);
	kdreg2_status_set_num_active_regions(&context->status,
					     num_active_regions);

	kdreg2_context_unlock(context);

	return 0;

unmonitor:

	unmonitor.cookie = monitor.cookie;
	unmonitor.monitoring_params = monitor.monitoring_params;
	kdreg2_unmonitor_region(context, &unmonitor);

unlock_return:

	kdreg2_context_unlock(context);
	return ret;
}

static long ioctl_unmonitor(struct kdreg2_context *context,
			    unsigned long arg)
{
	struct kdreg2_region_db         *region_db = &context->region_db;
	struct kdreg2_ioctl_unmonitor   unmonitor;
	uint64_t num_active_regions;
	int ret;

	if (copy_from_user(&unmonitor, (void __user *) arg,
			   sizeof(unmonitor)))
		return -EFAULT;

	if (unmonitor.monitoring_params.location >=
	    kdreg2_get_num_monitoring_state(&context->monitoring_data)) {
		return -EINVAL;
	};

	kdreg2_context_lock(context);

	ret = kdreg2_unmonitor_region(context, &unmonitor);
	if (ret)
		goto unlock_return;

	num_active_regions = kdreg2_region_db_get_num_regions(region_db);
	kdreg2_status_set_num_active_regions(&context->status,
					     num_active_regions);

	kdreg2_context_unlock(context);

	return 0;

unlock_return:

	kdreg2_context_unlock(context);
	return ret;
}

static long ioctl_unmonitor_all(struct kdreg2_context *context,
				unsigned long arg)   /* unused */
{
	struct kdreg2_region_db         *region_db = &context->region_db;
	size_t num_active_regions;
	int ret;

	kdreg2_context_lock(context);

	ret = kdreg2_unmonitor_all(context);

	num_active_regions = kdreg2_region_db_get_num_regions(region_db);
	kdreg2_status_set_num_active_regions(&context->status,
					     num_active_regions);

	kdreg2_context_unlock(context);
	return ret;
}

static long ioctl_flush(struct kdreg2_context *context,
			unsigned long arg) /* unused */
{
	int ret;

	kdreg2_context_lock(context);

	ret = kdreg2_event_queue_flush(context);

	kdreg2_context_unlock(context);

	return ret;
}

static long ioctl_dump_stats(struct kdreg2_context *context,
			     unsigned long arg) /* unused */
{
	struct kdreg2_region_db *region_db = &context->region_db;

	kdreg2_context_lock(context);

	pr_info("Region allocations: %zu, frees: %zu (difference %zi)\n",
		region_db->num_allocs, region_db->num_frees,
		region_db->num_allocs-region_db->num_frees);

	kdreg2_context_unlock(context);

	return 0;
}

/*
 * kdreg2_ioctl - The ioctl() implementation for kdreg2
 *
 * positive return values are propagated back to caller.
 * negative return values are moved to errno.
 */
long kdreg2_ioctl(struct file *file,
		   unsigned int cmd,
		   unsigned long arg)
{
	struct kdreg2_context *context = file->private_data;
	int ret;
	size_t i;

#define IOCTL_DATA(x_, y_, z_)     { x_, #x_, y_, z_ }
	static const struct {
		unsigned long cmd;
		const char    *ioctl_name;
		long          (*func)(struct kdreg2_context *context,
				      unsigned long arg);
		bool          has_arg;
	} ioctl_data[] = {
		IOCTL_DATA(KDREG2_IOCTL_CONFIG_DATA,   ioctl_config_data,   true),
		IOCTL_DATA(KDREG2_IOCTL_MONITOR,       ioctl_monitor,       true),
		IOCTL_DATA(KDREG2_IOCTL_UNMONITOR,     ioctl_unmonitor,     true),
		IOCTL_DATA(KDREG2_IOCTL_UNMONITOR_ALL, ioctl_unmonitor_all, false),
		IOCTL_DATA(KDREG2_IOCTL_FLUSH,         ioctl_flush,         false),
		IOCTL_DATA(KDREG2_IOCTL_DUMP_STATS,    ioctl_dump_stats,    false),
	};
#undef IOCTL_DATA

	/* sanity check on magic */
	if (_IOC_TYPE(cmd) != KDREG2_IOC_MAGIC) {
		pr_warn("Received bad command: 0x%x, arg: 0x%lx", cmd, arg);
		return -ENOTTY;   /* historical return code for bad command */
	}

	ret = kdreg2_detect_fork(context);
	if (ret)
		return ret;

	for (i = 0; i < ARRAY_SIZE(ioctl_data); i++) {
		if (ioctl_data[i].cmd != cmd)
			continue;

		if (!arg && ioctl_data[i].has_arg) {
			pr_warn("Bad arg to Ioctl, command: 0x%x, arg: 0x%lx",
				cmd, arg);
			return -EINVAL;
		}

		KDREG2_DEBUG(KDREG2_DEBUG_IOCTL, 1,
			     "Command is %s, arg: 0x%lx",
			     ioctl_data[i].ioctl_name, arg);

		ret = (*ioctl_data[i].func)(context, arg);

		if (ret)
			pr_warn_ratelimited("%s: failure %i",
					    ioctl_data[i].ioctl_name, ret);
		else
			KDREG2_DEBUG(KDREG2_DEBUG_IOCTL, 1,
				     "%s: success.",
				     ioctl_data[i].ioctl_name);
		return ret;
	}

	pr_warn("Received unknown command: 0x%x, arg: 0x%lx",
		cmd, arg);
	return -ENOTTY;
}
