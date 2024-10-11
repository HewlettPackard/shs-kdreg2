/*
 * Copyright (C) 2012-2019 Cray(R)
 * Copyright (C) 2020-2023 Hewlett Packard Enterprise Development LP
 *
 * KDREG2 user API header file.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "LICENSE" in this directory for more details.
 *
 * Derived in part from dreg.h by Pete Wyckoff.
 * Copyright (C) 2004-5 Pete Wyckoff <pw@osc.edu>
 * Distributed under the GNU Public License Version 2 (See LICENSE)
 */

#ifndef _KDREG2_PUB_H_
#define _KDREG2_PUB_H_

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <sys/ioctl.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Macro to detect errors at compile time that the preprocessor can't
 * find.  See:
 * https://scaryreasoner.wordpress.com/2009/02/28/checking-sizeof-at-compile-time/
 * (This technique is used by (stolen from?) the Linux kernel).
 *
 * The 'condition' argument must be capable of full evaluation at compile time.
 *
 * If the condition evaluates to a non-zero value, a compile time
 * error results.
 *
 * If the condition evaluates to zero, the resulting code snippet is
 * discarded by the compiler as an expression with no effect.
 *
 * Example usage: BUILD_BUG_ON(sizeof(char) != 1);
 *
 * Note: this macro adds no code overhead when the condition evaluates to 0.
 * Note: this macro will not work at global scope.
 */

#ifndef BUILD_BUG_ON
#define BUILD_BUG_ON(condition) ((void) sizeof(char[1-2*!!(condition)]))
#endif

/* This file defines the API used by user-space programs to access
 * the kernel module.  As such, it must compile in both regimes.
 *
 * The kernel and user-space don't always agree on type names.
 * In particular, no commonality exists for the atomic types.
 *
 * These types are defined in <linux/types.h> for the kernel.
 * The corresponding types are in <stdatomic.h> for user-space.
 *
 * The definitions in <stdatomic.h> are not super-helpful.
 * They provide types with sizes of 'at least' a certain number of
 * bits but no way to specify a type with the desired number of bits.
 */

#ifndef __KERNEL__
#define atomic_t   atomic_uint
#define atomic64_t atomic_long
#define __user
#endif

/* Dummy function to test at compile time that we selected the
 * proper atomic* types.  If this doesn't compile, change the
 * atomic types from <stdatomic.h> (the right-hand-side of the
 * #define's above).  The only atomic types available in the
 * kernel are atomic_t and atomic64_t.
 */

static inline __attribute__((unused, always_inline))
void _dummy_func_to_confirm_types_are_compatible(void)
{
	/* It would be nice to test:
	 *     sizeof(atomic_t) != sizeof(atomic_uint)
	 * but these types exist in different spaces.
	 */

	BUILD_BUG_ON(sizeof(atomic_t)   != 4);
	BUILD_BUG_ON(sizeof(atomic64_t) != 8);
}

/*
 * Users supply a cookie at registration time.
 * The same cookie value is returned from the
 * read() operation in the struct kdreg2_event.
 */

typedef uint64_t kdreg2_cookie_t;
#define KDREG2_BAD_COOKIE_VALUE ((kdreg2_cookie_t) -1)

/* There are multiple ways to communicate with kdreg2:
 *
 * 1) Ioctl's for
 *    a) getting general information about kdreg2 configuration
 *    b) registering regions for monitoring
 *    c) unregistering regions for monitoring
 *
 * 2) Reading from the kdreg2 file descriptor for:
 *    a) mapping change events for monitored regions
 *
 * 3) Reading from the pending_events and total_events counters
 *
 * 4) Querying the specific mapping changes using the
 *      kdreg2_mapping_changed() function
 */

struct kdreg2_monitoring_params {
	size_t     location;
	uint32_t   generation;
};

struct kdreg2_monitoring_state {
	union {
		struct {
			unsigned int   in_use : 1;
			unsigned int   data   : 31;
		} bits __attribute__((packed));
		uint32_t      raw;
		atomic_t      state;
	} u;
};

static inline __attribute__((unused, always_inline))
void _dummy_func2_to_confirm_types_are_compatible(void)
{
	BUILD_BUG_ON(sizeof(struct kdreg2_monitoring_state) != sizeof(atomic_t));
}


/* Ioctl for setting the configurable parameters.
 *
 * Usage:
 *
 *     struct kdreg2_config_data   config_data;
 *
 *     int ret = ioctl(fd, KDREG2_IOCTL_CONFIG_DATA, &config_data);
 *
 * The value of config_data.status_data after a successful ioctl()
 * call is a pointer to READ-ONLY kdreg2_status_data structure
 * (described above).
 *
 * Return values:
 * 0 - success in allocating data structures and setting
 *     status_data member.
 * non-zero - failure, error is stored in errno.
 *
 * Errors: ioctl() interface documents common cases.
 * Error specific to this module:
 * EFAULT - &config_data points to bad memory location
 * ENOTTY - bad value for ioctl 'request' (2nd) parameter
 * EIO    - child of fork detected.  (Reopen file in child to fix).
 * EINVAL - arg is NULL
 * ENOMEM - unable to allocate data structures (max_regions too large?).
 * EBUSY  - Resize attempted with actively monitored regions present
 * ENOSPC - max_regions too large
 *
 * Note: it is possible to call this function more than once to
 * change max_regions but only if:
 *    there are no regions are currently being monitored and
 *    there are no pending notifications to be read.
 * Use ioctl(fd, KDREG2_IOCTL_UNMONITOR_ALL) to remove all regions
 * from monitoring, then read all the pending notifications from the
 * file descriptor.
 */

struct kdreg2_status_data;

struct kdreg2_config_data {

	/*
	 * IN
	 * Maximum number of regions to monitor.
	 * This parameter is required.  The default is 0, so
	 * without setting this parameter no regions may be
	 * monitored.
	 */

	size_t           max_regions;

	/*
	 * OUT
	 * Pointer to the READ-ONLY kdreg2_status_data area.
	 *
	 */

	const struct kdreg2_status_data __user *status_data;
};

/*
 * Read-only area which provides status of monitored regions, etc.
 *
 * Users get a pointer to this data from the
 *     KDREG_IOCTL_CONFIG_DATA ioctl().
 */

struct kdreg2_status_data {

	/*
	 * Module version
	 */

	uint64_t         version;

	/*
	 * Maximum number of regions that can be monitored.
	 */

	size_t           max_regions;

	/*
	 * Number of events waiting to be
	 * read from the kdreg2 file descriptor.
	 *
	 * Read with kdreg2_read_counter().
	 */

	atomic64_t       pending_events;

	/*
	 * Total number of events generated
	 * since file descriptor was opened.
	 *
	 * Read with kdreg2_read_counter().
	 */

	atomic64_t       total_events;

	/*
	 * Number of regions currently being monitored.
	 *
	 * Read with kdreg2_read_counter().
	 */

	atomic64_t       num_active_regions;

	/*
	 * User space location of the monitoring state array.
	 *
	 * This should be treated as an opaque data area
	 * by the application and only used in conjunction
	 * with the kdreg2_mapping_changed() function.
	 */

	const struct kdreg2_monitoring_state __user *monitoring_state_base;
};

/* Helper functions to retrieve the value of the unmap counters
 * from the user data.
 */

#ifndef __KERNEL__
static inline __attribute__((always_inline))
uint64_t kdreg2_read_counter(const atomic64_t *counter)
{
	return atomic_load_explicit(counter, memory_order_acquire);
}
#endif

/* Ioctl for registering regions for monitoring
 *
 * struct kdreg2_ioctl_monitor   arg;
 *
 * int ret = ioctl(fd, KDREG2_IOCTL_MONITOR, &arg);
 *
 * Users supply addr, length, cookie.
 *
 * Only one region may have give cookie value.
 *
 * A region may be monitored multiple times (with
 * different cookies).
 *
 * On success, ioctl() will fill in monitoring_params, which is used
 * in the kdreg2_mapping_changed() function.
 *
 * Return values:
 * 0 - success in register region for monitoring.
 * non-zero - failure, error is stored in errno.
 *
 * Errors: ioctl() interface documents common cases.
 * Error specific to this module:
 * EFAULT - arg points to bad memory location
 * ENOTTY - bad value for ioctl 'request' (2nd) parameter
 * EIO    - child of fork detected.  (Reopen file in child to fix).
 * EINVAL - arg is NULL
 * EINVAL - length is 0
 * EINVAL - cookie is KDREG2_BAD_COOKIE_VALUE
 * ENOSPC - maximum number of regions already being monitored
 * ENOMEM - unable to allocate memory for monitoring
 * EBUSY  - cookie duplicates region already being monitored
 */

struct kdreg2_ioctl_monitor {
	/*
	 * IN
	 * Starting address of region to monitor
	 */

	const void __user        *addr;

	/*
	 * IN
	 * Length of region to monitor
	 */

	size_t                   length;

	/*
	 * IN
	 * Cookie value to return when mapping changes
	 * are detected for this region.
	 */

	kdreg2_cookie_t          cookie;

	/*
	 * OUT
	 * Data returned from the ioctl() which represents the
	 * monitoring state when monitoring started.
	 * This struct is used with the function kdreg2_mapping_changed()
	 * to determine if the monitored memory region has
	 * been remapped, etc.
	 */

	struct kdreg2_monitoring_params  monitoring_params;
};

/* Function to determine if the virtual memory mapping for
 * a monitored region has changed.
 *
 * The value of status_data is obtained from
 *    ioctl(fd, KDREG2_IOCTL_CONFIG_DATA, ...).
 * The value of monitoring_params is from
 *    ioctl(fd, KDREG2_IOCTL_MONITOR, ...).
 */

#ifndef __KERNEL__
static inline __attribute__((always_inline))
bool kdreg2_mapping_changed(const struct kdreg2_status_data *status_data,
			    const struct kdreg2_monitoring_params *monitoring_params)
{
	const struct kdreg2_monitoring_state *ms;
	uint32_t     current_generation;

	/* Check of for index out of range.  This can happen if entry
	 * is stale and monitor has been resized.
	 */

	if (status_data->max_regions < monitoring_params->location)
		return true;

	ms = status_data->monitoring_state_base + monitoring_params->location;

	current_generation = atomic_load_explicit(&ms->u.state,
						  memory_order_acquire);

	return current_generation != monitoring_params->generation;
}
#endif

/* Ioctl for unregistering regions for monitoring
 *
 * struct kdreg2_ioctl_unmonitor   arg;
 *
 * int ret = ioctl(fd, KDREG2_IOCTL_UNMONITOR, &arg);
 *
 * User supplies cookie, monitoring_params.
 * Ioctl() result is whether the entry was found and
 * removed.
 *
 * Errors: ioctl() interface documents common cases.
 * Error specific to this module:
 * EFAULT - arg points to bad memory location
 * ENOTTY - bad value for ioctl 'request' (2nd) parameter
 * EIO    - child of fork detected.  (Reopen file in child to fix).
 * EINVAL - arg is NULL
 * EINVAL - monitoring_params.location is outside of range
 * ESRCH  - cookie value not found
 * EBADSLT - monitoring_params does not correspond to this cookie
 *           (Cookie may have been reused).
 */

struct kdreg2_ioctl_unmonitor {

	/* IN
	 * Cookie value of monitored region to stop monitoring.
	 */

	kdreg2_cookie_t     cookie;

	/* IN
	 * monitoring_params when region was originally monitored.
	 *
	 * By requiring this value, cookie reuse can be detected.
	 */

	struct kdreg2_monitoring_params  monitoring_params;
};

/* Reading from the kdreg2 file descriptor yields
 *    struct kdreg2_event
 * items.
 *
 * Poll may be used to detect when items are available.
 */

enum kdreg2_event_type {
	KDREG2_EVENT_MAPPING_CHANGE = 1,
};

struct kdreg2_event {
	/*
	 * One of the kdreg2_event_type values.
	 */

	uint32_t type;
	uint32_t _alignment;      /* alignment for union member */

	union {
		struct kdreg2_mapping_change {
			/*
			 * Starting address of region where mapping
			 * change was detected.
			 */

			const void __user  *addr;

			/*
			 * Length of region in bytes.
			 */

			size_t len;

			/*
			 * Cookie value supplied when monitoring this
			 * region.
			 */

			kdreg2_cookie_t  cookie;
		} mapping_change;
	} u;
};

/* IOCTL commands.
 * Note: I think 'K' is already taken by the kernel.
 */
#define KDREG2_IOC_MAGIC   'k'

#define KDREG2_IOCTL_CONFIG_DATA  \
	_IOWR(KDREG2_IOC_MAGIC, 1, struct kdreg2_config_data)
#define KDREG2_IOCTL_MONITOR      \
	_IOWR(KDREG2_IOC_MAGIC, 2, struct kdreg2_ioctl_monitor)
#define KDREG2_IOCTL_UNMONITOR    \
	_IOW(KDREG2_IOC_MAGIC,  3, struct kdreg2_ioctl_unmonitor)

/*
 * Remove all regions from monitoring
 */
#define KDREG2_IOCTL_UNMONITOR_ALL _IO(KDREG2_IOC_MAGIC,   4)
/*
 * Discard all pending events
 */
#define KDREG2_IOCTL_FLUSH         _IO(KDREG2_IOC_MAGIC,   5)

/*
 * Dump stats to kernel log
 */
#define KDREG2_IOCTL_DUMP_STATS    _IO(KDREG2_IOC_MAGIC,   6)


/* kdreg2 module and device name */
#ifndef KDREG2_MODNAME
#define KDREG2_MODNAME "kdreg2"
#endif
#define KDREG2_DEVICE_NAME "/dev/" KDREG2_MODNAME

#ifdef	__cplusplus
}
#endif

#endif /*_KDREG2_PUB_H_*/
