/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2012-2019 Cray(R)
 * Copyright (C) 2020-2023 Hewlett Packard Enterprise Development LP
 *
 * KDREG2 module internal header file.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "LICENSE" in this directory for more details.
 *
 * Derived in part from dreg.c by Pete Wyckoff.
 * Copyright (C) 2004-5 Pete Wyckoff <pw@osc.edu>
 * Distributed under the GNU Public License Version 2 (See LICENSE)
 */

#ifndef _KDREG2_PRIV_H_
#define _KDREG2_PRIV_H_

#include <linux/version.h>

#ifdef RHEL_RELEASE_CODE
#  if RHEL_RELEASE_VERSION(8, 4) > RHEL_RELEASE_CODE
#error "This kernel module not supported for RHEL versions < 8.4"
#  endif
#else
#  if KERNEL_VERSION(4, 12, 14) > LINUX_VERSION_CODE
#error "This kernel module not supported for kernel versions < 4.12.14"
#  endif
#endif

#include "kdreg2_config.h"
#include "kdreg2_kernel_skew.h"

#define KDREG2_DRIVER_NAME KBUILD_MODNAME
#define KDREG2_CLASS_NAME  KBUILD_MODNAME

/* Define a format prefix for the pr_* family of functions.
 * See Documentation/core-api/printk-basics.rst in the Linux source.
 */

#include <linux/cdev.h>
#include <linux/mm.h>
#include <linux/mmu_notifier.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) "[%d] %s:%s: " fmt, current->pid, KBUILD_MODNAME, __func__

/* The kernel and user-space don't always agree on type names.
 * Note: these must equate to the same actual type or chaos ensues.
 */

#ifdef __KERNEL__
typedef u_int32_t  uint32_t;
typedef u_int64_t  uint64_t;
#endif

#include "include/kdreg2.h"

static __always_inline
void kdreg2_set_counter(struct kdreg2_counter *counter,
			uint64_t value)
{
	WRITE_ONCE(counter->val, value);

	/* Force synchronization across threads */
	smp_mb();
}

static __always_inline
void kdreg2_inc_counter(struct kdreg2_counter *counter)
{
	WRITE_ONCE(counter->val, READ_ONCE(counter->val) + 1);

	/* Force synchronization across threads */
	smp_mb();
}

#if   (KDREG2_DB_MODE == KDREG2_DB_MODE_DLLIST)
#define KDREG2_DB_MODE_NAME "List"
#elif (KDREG2_DB_MODE == KDREG2_DB_MODE_RBTREE)
#define KDREG2_DB_MODE_NAME "RBTree"
#else
#error "KDREG2_DB_MODE must be defined in kdreg2_config.h."
#endif

#if KDREG2_DB_MODE == KDREG2_DB_MODE_RBTREE
#include <linux/interval_tree_generic.h>
#endif

/* kdreg2 is a character device. */

struct kdreg2_dev {
	struct cdev cdev;       /* Char device structure              */
};

/* Structure to hold data about the regions we are tracking */

struct kdreg2_region {
	unsigned long           addr;       /* user space address */
	unsigned long           last;       /* last byte in region */
	size_t                  len;        /* size of space */
	kdreg2_cookie_t         cookie;
	size_t                  monitoring_state_index;
#if KDREG2_DB_MODE == KDREG2_DB_MODE_DLLIST
	struct list_head        region_list;
#elif KDREG2_DB_MODE == KDREG2_DB_MODE_RBTREE
	struct cookie_tree {
		struct rb_node  node;
	} cookie_tree;
	struct interval_tree {
		struct rb_node  node;
		unsigned long   subtree_last;
	} interval_tree;
#endif
};

/* Container for region data */

struct kdreg2_region_db {
	size_t                 max_regions;
	size_t                 num_regions;
	size_t                 num_allocs;
	size_t                 num_frees;
#if KDREG2_DB_MODE == KDREG2_DB_MODE_DLLIST
	struct cookie_db {
		kdreg2_cookie_t biggest_cookie;
	} cookie_db;
	struct list_db {
		struct list_head head;
	} list_db;
#elif KDREG2_DB_MODE == KDREG2_DB_MODE_RBTREE
	struct cookie_tree_db {
		struct rb_root  root;
		kdreg2_cookie_t biggest_cookie;
	} cookie_tree;
	struct interval_tree_db {
#if KDREG2_HAS_RB_ROOT_CACHED == 0
		struct rb_root        root;
#else
		struct rb_root_cached root;
#endif
	} interval_tree;
#endif
	struct kmem_cache      *region_cache;
};

/* Struct for vm mapping shared with the user */

struct kdreg2_vm_map {
	size_t                 size;
	void __user            *user_addr;
	void                   *kernel_addr;
	struct vm_area_struct  *vma;
};

/* Interface to mmu_notifier */

struct kdreg2_mmu_notifier_data {
	struct mmu_notifier    mmu_notifier;
	bool                   registered;
};

/* Queue of events waiting to be read. */

struct kdreg2_event_queue {
	struct kdreg2_event     *pending;
	size_t                  max_events;
	size_t                  num_pending;
	size_t                  cons;
	size_t                  prod;
	bool                    overflow;
};

/* Container for the status_data */

struct kdreg2_status {
	struct kdreg2_vm_map             vm_map;
	struct kdreg2_status_data __user *user_addr;
	struct kdreg2_status_data        *kern_addr;
};

/* Container for the monitoring state */

struct kdreg2_monitoring_data {
	struct kdreg2_vm_map                   vm_map;
	size_t                                 num_monitoring_state;
	size_t                                 next_monitoring_state_index;
	ssize_t                                free_list_head_index;
	uint32_t                               next_generation;
	struct kdreg2_monitoring_state __user  *user_addr;
	struct kdreg2_monitoring_state         *kern_addr;
};

/* Kdreg2 context. Created when /dev/kdreg2 is opened.
 * All threads in process share a mm.  We tie a kdreg2 context to a mm.
 */

struct kdreg2_context {

	/* contexts are mapped 1-to-1 to a mm */

	struct mm_struct       *mm;

	struct mutex           lock;

	/* database of regions we monitor */

	struct kdreg2_region_db region_db;

	/* Area to queue events and pass them back
	 * on read() operations.
	 */

	struct kdreg2_event_queue         event_queue;

	/* Mapping for the status data */

	struct kdreg2_status              status;

	/* Mappings for the monitor state data */

	struct kdreg2_monitoring_data     monitoring_data;

	/* Interface to mmu_notifier */

	struct kdreg2_mmu_notifier_data   mmu_notifier_data;

	/* wait queues for blocking operations */

	struct wait_queues {
		wait_queue_head_t      read_queue;
		wait_queue_head_t      poll_queue;
	} wait_queues;

	/* Warn once about fork() detection. */

	bool    warn_on_fork_detected;
};

/* Module-wide data */

struct kdreg2_global {
	const char         *driver_string;
	const char         * const *driver_copyright;
	size_t             num_copyright;
	const char         *driver_name;
	const char         *class_name;
	const char         *build_string;
	const uint64_t     driver_version;
	struct mutex       driver_lock;
	dev_t              dev_id;
	int                major_dev;
	int                driver_numdev;
	int                num_contexts;
	uint32_t           debug_level;
	uint32_t           debug_mask;
	struct class       *class;
	struct device      *class_device;
	struct kdreg2_dev  kdreg2_dev;
};

extern struct kdreg2_global kdreg2_global;

#define KDREG2_DEBUG_NONE        0x0000
#define KDREG2_DEBUG_INIT        0x0001
#define KDREG2_DEBUG_EXIT        0x0002
#define KDREG2_DEBUG_OPEN        0x0004
#define KDREG2_DEBUG_CLOSE       0x0008
#define KDREG2_DEBUG_READ        0x0010
#define KDREG2_DEBUG_WRITE       0x0020
#define KDREG2_DEBUG_MMUNOT      0x0040
#define KDREG2_DEBUG_REGION      0x0080
#define KDREG2_DEBUG_IOCTL       0x0100
#define KDREG2_DEBUG_POLL        0x0200
#define KDREG2_DEBUG_ALL         0xffff

#define KDREG2_MIN_DEBUG_LEVEL   0
#define KDREG2_MAX_DEBUG_LEVEL   4

/* Log output types for KDREG2 logging macros */
#define KDREG2_LOG_NORMAL       0
#define KDREG2_LOG_RATELIMITED  1
#define KDREG2_LOG_ONCE         2

#if   KDREG2_DEBUG_MODE == KDREG2_DEBUG_MODE_VERBOSE

#define KDREG2_DEBUG_LEVEL KDREG2_MAX_DEBUG_LEVEL
#define KDREG2_DEBUG_MASK  KDREG2_DEBUG_ALL

#elif KDREG2_DEBUG_MODE == KDREG2_DEBUG_MODE_QUIET

#define KDREG2_DEBUG_LEVEL KDREG2_MIN_DEBUG_LEVEL
#define KDREG2_DEBUG_MASK  KDREG2_DEBUG_ALL

#else
#error "KDREG2_DEBUG_MODE not defined in kdreg2_config.h."
#endif

static __always_inline
bool KDREG2_DEBUG_ON(uint32_t type, uint32_t level)
{
	return ((kdreg2_global.debug_level >= level) &&
		(kdreg2_global.debug_mask & type)) ? true : false;
}

#define KDREG2_DEBUG_PRINT(format, a...) pr_debug(format, ##a)

#define KDREG2_DEBUG(type, level, format, a...)        \
do {                                                   \
	if (KDREG2_DEBUG_ON(type, level)) {	       \
		KDREG2_DEBUG_PRINT(format, ##a);       \
	}                                              \
} while (0)

#define KDREG2_INFO(log_type, format, a...)       \
do {                                              \
    if (log_type == KDREG2_LOG_RATELIMITED)       \
        pr_info_ratelimited(format, ##a);         \
    else if (log_type == KDREG2_LOG_ONCE)         \
        pr_info_once(format, ##a);                \
    else                                          \
        pr_info(format, ##a);                     \
} while (0)

#define KDREG2_WARN(log_type, format, a...)       \
do {                                              \
    if (log_type == KDREG2_LOG_RATELIMITED)       \
        pr_warn_ratelimited(format, ##a);         \
    else if (log_type == KDREG2_LOG_ONCE)         \
        pr_warn_once(format, ##a);                \
    else                                          \
        pr_warn(format, ##a);                     \
} while (0)

#define KDREG2_NOTICE(log_type, format, a...)     \
do {                                              \
    if (log_type == KDREG2_LOG_RATELIMITED)       \
        pr_notice_ratelimited(format, ##a);       \
    else if (log_type == KDREG2_LOG_ONCE)         \
        pr_notice_once(format, ##a);              \
    else                                          \
        pr_notice(format, ##a);                   \
} while (0)

__maybe_unused
static struct kdreg2_monitoring_state _bad_index =
{
	.u.raw = (unsigned) -1,
};

#define BAD_INDEX (_bad_index.u.bits.data)

static __always_inline
int kdreg2_detect_fork(struct kdreg2_context *context)
{
	/* Return error EIO if current->mm != context->mm.
	 * This will happen in the new process after fork if
	 * the device file was not opened with O_CLOEXEC.
	 */

	if (current->mm == context->mm)
		return 0;

	KDREG2_DEBUG(KDREG2_DEBUG_ALL, 2, "fork detected: %px != %px",
		     current->mm, context->mm);

	if (context->warn_on_fork_detected) {
		KDREG2_WARN(KDREG2_LOG_RATELIMITED,
		            "Fork() detected - monitoring not supported in child");
		context->warn_on_fork_detected = false;
	}

	return -EIO;
}

/* **************** kdreg2_class.c **************** */

int kdreg2_create_class_device_files(void);
void kdreg2_remove_class_device_files(void);
#if (KDREG2_CLASS_DEVICE_CONST == 1)
int kdreg2_dev_uevent(const struct device *dev, struct kobj_uevent_env *env);
#else
int kdreg2_dev_uevent(struct device *dev, struct kobj_uevent_env *env);
#endif

/* **************** kdreg2_context.c **************** */

int kdreg2_context_init(struct kdreg2_context *context,
			const size_t num_entities);
void kdreg2_context_destroy(struct kdreg2_context *context);
int kdreg2_context_resize(struct kdreg2_context *context,
			  const size_t max_regions);
void kdreg2_context_wakeup(struct kdreg2_context *context);

static __always_inline
void kdreg2_context_lock(struct kdreg2_context *context)
{
	int    ret;

	/* 0 -> mutex acquired
	 * -EINTR -> interrupted
	 */

	KDREG2_DEBUG(KDREG2_DEBUG_ALL, 4,
		     "acquiring context lock");

	do {
		ret = mutex_lock_interruptible(&context->lock);
	}
	while(ret);

	KDREG2_DEBUG(KDREG2_DEBUG_ALL, 4,
		     "context lock acquired");
}

static __always_inline
void kdreg2_context_unlock(struct kdreg2_context *context)
{
	mutex_unlock(&context->lock);

	KDREG2_DEBUG(KDREG2_DEBUG_ALL, 4,
		     "context lock released");

}

/* **************** kdreg2_event_queue.c **************** */

int kdreg2_event_queue_init(struct kdreg2_event_queue *event_queue,
			    const size_t num_entities);

void kdreg2_event_queue_destroy(struct kdreg2_event_queue *event_queue);
int kdreg2_event_queue_resize(struct kdreg2_context *context,
			      const size_t num_entities);
ssize_t kdreg2_event_queue_read(struct kdreg2_context *context,
				char __user *buf, size_t len, bool non_blocking);
int kdreg2_event_queue_insert(struct kdreg2_context *context,
			      struct kdreg2_event *event);
int kdreg2_event_queue_flush(struct kdreg2_context *context);

static __always_inline
size_t kdreg2_event_queue_get_num_pending(struct kdreg2_event_queue *event_queue)
{
	return event_queue->num_pending;
}

/* **************** kdreg2_file.c **************** */

int kdreg2_open(struct inode *inode, struct file *file);
int kdreg2_release(struct inode *inode, struct file *file);
ssize_t kdreg2_read(struct file *file, char __user *buf,
		    size_t len, loff_t *ppos);
ssize_t kdreg2_write(struct file *file, const char __user *ubuf,
		     size_t len, loff_t *ppos);
__poll_t kdreg2_poll(struct file *file, struct poll_table_struct *wait);
long kdreg2_ioctl(struct file *file, unsigned int cmd,
		  unsigned long arg);

/* **************** kdreg2_main.c **************** */

static __always_inline
void kdreg2_global_lock(void)
{
	int ret;

	/* TODO: does this need to interruptible or not? */
	do {
		ret = mutex_lock_interruptible(&kdreg2_global.driver_lock);
	}
	while(ret);
}

static __always_inline
void kdreg2_global_unlock(void)
{
	mutex_unlock(&kdreg2_global.driver_lock);
}

/* **************** kdreg2_mmu_notifier.c **************** */

int kdreg2_mmu_notifier_data_init(struct kdreg2_mmu_notifier_data *notifier_data);
void kdreg2_mmu_notifier_data_destroy(struct kdreg2_mmu_notifier_data *notifier_data);
int kdreg2_mmu_notifier_enable(struct kdreg2_context *context);
int kdreg2_mmu_notifier_disable(struct kdreg2_context *context);

/* **************** kdreg2_monitoring_data.c **************** */

int kdreg2_monitoring_data_init(struct kdreg2_monitoring_data *monitoring_data,
				 const size_t num_entities);
void kdreg2_monitoring_data_destroy(struct kdreg2_monitoring_data *monitoring_data);
int kdreg2_monitoring_data_resize(struct kdreg2_context *context,
				  const size_t num_entities);
ssize_t find_free_monitoring_state_index(struct kdreg2_context *context);

static __always_inline
size_t kdreg2_get_num_monitoring_state(struct kdreg2_monitoring_data *monitoring_data)
{
	return monitoring_data->num_monitoring_state;
}

static __always_inline
void kdreg2_set_monitoring_state(struct kdreg2_monitoring_state *monitoring_state,
				 bool in_use,
				 unsigned int data)
{
	struct kdreg2_monitoring_state ms = {
		.u.bits = { .in_use = (in_use) ? 1 : 0,
			    .data   = data },
	};

	WRITE_ONCE(monitoring_state->u.state.val, ms.u.state.val);

	/* force synchronization across threads */
	smp_mb();
}

static __always_inline
uint32_t kdreg2_get_monitoring_state(struct kdreg2_monitoring_state *ms)
{
	return ms->u.state.val;
}

static __always_inline
void kdreg2_monitoring_state_free(struct kdreg2_context *context,
				  const size_t monitoring_state_index)
{
	struct kdreg2_monitoring_data  *monitoring_data = &context->monitoring_data;
	struct kdreg2_monitoring_state *base            = monitoring_data->kern_addr;
	ssize_t head_index                              = monitoring_data->free_list_head_index;

	/* link this entry into the free list */

	kdreg2_set_monitoring_state(base + monitoring_state_index,
				    false, head_index);

	monitoring_data->free_list_head_index = monitoring_state_index;
}

static __always_inline
uint32_t kdreg2_monitoring_state_get_state(struct kdreg2_context *context,
					   const size_t monitoring_state_index)
{
	struct kdreg2_monitoring_state *base = context->monitoring_data.kern_addr;

	return base[monitoring_state_index].u.state.val;
}

/* **************** kdreg2_region.c **************** */

ssize_t kdreg2_monitor_region(struct kdreg2_context *context,
			      struct kdreg2_ioctl_monitor *monitor);
ssize_t kdreg2_unmonitor_region(struct kdreg2_context *context,
				struct kdreg2_ioctl_unmonitor *unmonitor);
int kdreg2_unmonitor_all(struct kdreg2_context *context);
void kdreg2_destroy_range(struct kdreg2_context *context,
			  unsigned long start,
			  unsigned long end);

int kdreg2_region_db_init(struct kdreg2_region_db *region_db,
			  const size_t num_entities);
void kdreg2_region_db_destroy(struct kdreg2_region_db *region_db);
int kdreg2_region_db_resize(struct kdreg2_context *context,
			    const size_t num_entities);
size_t kdreg2_region_db_get_num_regions(struct kdreg2_region_db *region_db);
size_t kdreg2_region_db_get_max_regions(struct kdreg2_region_db *region_db);

/* **************** kdreg2_status_data.c **************** */

int kdreg2_status_init(struct kdreg2_status *status,
		       const size_t num_entities);
void kdreg2_status_destroy(struct kdreg2_status *status);
void kdreg2_status_set_monitoring_state_base(struct kdreg2_status *status,
	     struct kdreg2_monitoring_state __user *monitoring_state_base);
void kdreg2_status_set_max_regions(struct kdreg2_status *status,
				   const size_t max_regions);

static __always_inline
void kdreg2_status_set_pending_events(struct kdreg2_status *status,
				      const uint64_t value)
{
	kdreg2_set_counter(&status->kern_addr->pending_events, value);
}

static __always_inline
void kdreg2_status_inc_total_events(struct kdreg2_status *status)
{
	kdreg2_inc_counter(&status->kern_addr->total_events);
}

static __always_inline
void kdreg2_status_set_num_active_regions(struct kdreg2_status *status,
					  const uint64_t value)
{
	kdreg2_set_counter(&status->kern_addr->num_active_regions, value);
}

/* **************** kdreg2_vm.c **************** */

void kdreg2_init_vm_map(struct kdreg2_vm_map *vm_map);

int kdreg2_create_vm_map(struct kdreg2_vm_map *vm_map,
			  const size_t mapping_size,
			  const char *purpose);

void kdreg2_destroy_vm_map(struct kdreg2_vm_map *vm_map);

#endif /*_KDREG2_PRIV_H_ */
