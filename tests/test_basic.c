/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Check basic functionality of kdreg2 module.
 *
 * Copyright (C) 2012 Cray Inc. All Rights Reserved.
 * Copyright (C) 2020-2023 Hewlett Packard Enterprise Development LP
 *
 * Distributed under the GNU Public License Version 2 (See LICENSE).
 */

#include "kdreg2.h"

#include <sys/mman.h>

#include <alloca.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(_x) (sizeof(_x)/sizeof((_x)[0]))
#endif

/* Note: local data arrays of size MAX_COOKIES can
 * overflow the stack, so make them static. */

#define DEFAULT_LEN    (8 * 1024)
// #define MAX_COOKIES    (64 * 1024)
// #define MAX_COOKIES (2 * 1024)
// #define MAX_COOKIES 128
#define MAX_COOKIES    (512 * 1024)

static int len = DEFAULT_LEN;
static bool silent = false;

struct cookie_data {
	kdreg2_cookie_t           value;
	struct kdreg2_monitoring_params  monitoring_params;
	int                       seen;
};

struct cookie_jar {
	size_t               num_cookies;
	size_t               jar_size;
	struct cookie_data   cookies[MAX_COOKIES];
};

struct common_data {
	int                        fd;
	struct cookie_data         cookies[4];
	struct cookie_jar          jar;
	struct kdreg2_config_data  config_data;
	const struct kdreg2_status_data  *status_data;
};

static void __test_message(const char * type, const char * format, va_list args)
{
	fprintf(stderr, "%s: ", type);
	vfprintf(stderr, format, args);
	fprintf(stderr, "\n");
}

__attribute__((format(printf,1,2)))
static void test_start(const char * format, ...)
{
	static int test_number = 0;
	test_number++;

	if (silent)
		return;

	va_list args;

	fprintf(stderr, "------------------------------------------------\n");
	fprintf(stderr, "TEST %i: ", test_number);
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	fprintf(stderr, "\n");
}

__attribute__((format(printf,1,2)))
static void test_pass(const char * format, ...)
{
	va_list args;

	if (silent)
		return;

	va_start(args, format);
	__test_message("PASS", format, args);
	va_end(args);
}

__attribute__((noreturn, format(printf,1,2)))
static void test_fail(const char * format, ...)
{
	va_list args;

	va_start(args, format);
	__test_message("FAIL", format, args);
	va_end(args);

	sleep(2);

	exit(-1);
}

__attribute__((format(printf,1,2)))
static void test_info(const char * format, ...)
{
	va_list args;

	if (silent)
		return;

	va_start(args, format);
	__test_message("INFO", format, args);
	va_end(args);
}

static void * mmap_private_create(size_t bytes)
{
	test_info("Attempting to MMAP region of size %lu.", bytes);

	static const char *fill = "abcdefghijklmnopqrstuvwxyz"
		"abcdefghijklmnopqrstuvwxyz";
	static const char *cur_fill;
	static bool first = true;
	if (first) {
		cur_fill = fill;
		first = false;
	}

	char *buf = mmap(NULL, bytes, (PROT_READ | PROT_WRITE),
			 (MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE),
			 -1, 0);

	if (buf == MAP_FAILED) {
		perror("mmap failed");
		test_fail("Unable to create anonymous-private region.");
	}

	if (!silent) {
		char c = *cur_fill;
		cur_fill++;
		if (!*cur_fill) cur_fill = fill;

		for(size_t i = 0; i < bytes; i++) {
			buf[i] = c;
		}
	}

	test_info("MMAP created region at %p, length %zu.", buf, bytes);

	return buf;
}

static void mmap_free(void *addr, size_t bytes)
{
	test_info("Unmapping the region at %p, length %zu.", addr, bytes);

	int ret = munmap(addr, bytes);

	if (ret < 0) {
		perror("munmap returned error");
		test_fail("Unmap failure.");
	}

	test_info("Unmapping of region %p, length %zu successful.", addr, bytes);
}

static void test_pending_events_counter(struct common_data * data,
					const uint64_t expected_value,
					int num_loops)
{
	test_info("Checking pending_events for value %lu.", expected_value);

	uint64_t pending = 0;

	/* read the counter at least once */

	while(1) {
		pending = kdreg2_read_counter(&data->status_data->pending_events);

		if (expected_value == pending)
			break;

		if (--num_loops <= 0)
			break;

		test_info("Pending events %lu less than expected %lu, sleeping.",
			  pending, expected_value);

		sleep(1);
	}

	if (expected_value != pending) {
		test_fail("Pending_events is %lu, expected %lu", pending, expected_value);
	}

	test_info("Pending_events = %lu as expected.", pending);
}

static void purge_pending_events(struct common_data * data)
{
	test_info("Purging pending events.");

	int ret = ioctl(data->fd, KDREG2_IOCTL_FLUSH, 0);

	if (ret)
		test_fail("KDREG2_IOCTL_FLUSH fails: %i", errno);

	test_pending_events_counter(data, 0, 1);
}

static void test_num_active_regions_counter(struct common_data * data,
					    const uint64_t expected_value)
{
	test_info("Checking num_active_regions for value %lu.", expected_value);

	uint64_t num_regions = kdreg2_read_counter(&data->status_data->num_active_regions);

	if (expected_value != num_regions) {
		test_fail("num_active_regions is %lu, expected %lu", num_regions, expected_value);
	}

	test_info("num_active_regions = %lu as expected.", num_regions);
}

static uint64_t get_total_events_counter(struct common_data * data)
{
	return kdreg2_read_counter(&data->status_data->total_events);
}

static void test_total_events_counter(struct common_data * data, const uint64_t expected_value)
{
	test_info("Checking total_events for value %lu.", expected_value);

	uint64_t total = get_total_events_counter(data);

	if (expected_value != total) {
		test_fail("total_events is %lu, expected %lu", total, expected_value);
	}

	test_info("total_events = %lu as expected.", total);
}

static bool test_readable(int fd)
{
	struct pollfd  pollfd = { .fd = fd, .events = POLLIN };
	int ret;

	while(1) {
		ret = poll(&pollfd, 1, 0);
		if (ret >= 0)
			break;
		if ((ret < 0) && (EINTR == errno))
			continue;
		if (ret < 0) {
			test_fail("fd poll error: %i", ret);
		}
	};

	if (0 == ret)
		return false;

	return (pollfd.revents & POLLIN) ? true : false;
}

static void test_empty_read(struct common_data *data)
{
	test_info("Checking for no events to read.");

	int old_flags = fcntl(data->fd, F_GETFL);
	if (!(old_flags & O_NONBLOCK)) {
		int ret2 = fcntl(data->fd, F_SETFL, O_NONBLOCK | old_flags);
		if (ret2)
			test_fail("Unable to set non-blocking mode: %i", errno);
	}

	struct kdreg2_event   event;

	memset(&event, -1, sizeof(event));

	ssize_t ret = read(data->fd, &event, sizeof(event));

	if (ret < 0) {
		int err = errno;
		switch(err) {
		case EAGAIN:       /* these are expected */
#if EWOULDBLOCK != EAGAIN
		case EWOULDBLOCK:
#endif
			break;
		default:
			perror("Read from monitor fd");
			test_fail("Unable to read from monitor fd.");
		}
	} else if (ret > 0) {
		test_fail("Read %zi bytes from monitor fd, expected 0.", ret);
	}

	if (!(old_flags & O_NONBLOCK)) {
		int ret2 = fcntl(data->fd, F_SETFL, old_flags);
		if (ret2)
			test_fail("Unable to clear non-blocking mode: %i", errno);
	}

	test_info("No events available to read.");
}

static bool test_writable(int fd)
{
	struct pollfd  pollfd;

	pollfd.fd = fd;
	pollfd.events = POLLOUT;

	int ret;

	while(1) {
		ret = poll(&pollfd, 1, 0);
		if (ret >= 0)
			break;
		if ((ret < 0) && (EINTR == errno))
			continue;
		if (ret < 0) {
			test_fail("fd poll error: %i", ret);
		}
	};

	if (0 == ret)
		return false;

	return (pollfd.revents & POLLOUT) ? true : false;
}

static void test_failing_write(struct common_data *data)
{
	test_info("Checking for failing write.");

	int old_flags = fcntl(data->fd, F_GETFL);
	if (!(old_flags & O_NONBLOCK)) {
		int ret2 = fcntl(data->fd, F_SETFL, O_NONBLOCK | old_flags);
		if (ret2)
			test_fail("Unable to set non-blocking mode: %i", errno);
	}

	char buf[1];

	memset(&buf, -1, sizeof(buf));

	ssize_t ret = write(data->fd, buf, sizeof(buf));

	if (ret > 0) {
		test_fail("Wrote %zi bytes to fd, expected error.", ret);
	}

	if (ret < 0) {
		test_info("Unable to write to fd: errno = %i. (Failure is expected.)", errno);
	}

	if (!(old_flags & O_NONBLOCK)) {
		int ret2 = fcntl(data->fd, F_SETFL, old_flags);
		if (ret2)
			test_fail("Unable to clear non-blocking mode: %i", errno);
	}
}

static void dump_stats(struct common_data *data)
{
	int ret = 0;

	ret = ioctl(data->fd, KDREG2_IOCTL_DUMP_STATS, 0);

	if (!ret)
		return;

	test_fail("KDREG2_IOCTL_DUMP_STATS fails: %i\n", errno);
}

static void read_cookies(int fd, kdreg2_cookie_t *cookies, size_t num_cookies)
{
	test_info("Attempting to read %zu cookies.", num_cookies);

	struct kdreg2_event   *events;
	ssize_t bytes = num_cookies * sizeof(*events);
	events = malloc(bytes);
	void *memory_to_free = events;

	ssize_t ret = read(fd, events, bytes);

	if (ret < 0) {
		perror("read returned error");
		test_fail("Event read failure.");
	}
	if (ret < bytes) {
		test_fail("Broken cookies: read %zu bytes, expected %zu.",
			ret, bytes);
	}

	test_info("Read %zu cookies.", num_cookies);

	for(; num_cookies; num_cookies--, events++, cookies++)
	{
		*cookies = events->u.mapping_change.cookie;
		test_info("Cookie %lu, addr %p, len %zu",
			  events->u.mapping_change.cookie,
			  events->u.mapping_change.addr,
			  events->u.mapping_change.len);
	}

	free(memory_to_free);
}

static void contains_cookie(kdreg2_cookie_t *cookies, size_t num, kdreg2_cookie_t value)
{
	test_info("Searching for cookie %lu", value);

	for(; num; cookies++, num--) {
		if (*cookies == value) {
			test_info("Cookie %lu found.", value);
			return;
		}
	}

	test_fail("Cookie %lu not found.", value);
}

static void empty_cookie_jar(struct cookie_jar * jar)
{
	struct cookie_data *cookie_data = jar->cookies;

	for(size_t i = ARRAY_SIZE(jar->cookies); i; i--, cookie_data++)
	{
		cookie_data->value = KDREG2_BAD_COOKIE_VALUE;
		cookie_data->seen = 0;
	}
	jar->num_cookies = 0;
	jar->jar_size = ARRAY_SIZE(jar->cookies);
}

static struct cookie_data * find_cookie(struct cookie_jar *jar, kdreg2_cookie_t value)
{
	for(size_t i = 0; i < jar->jar_size; i++)
	{
		if (jar->cookies[i].value == value)
			return jar->cookies + i;
	}
	return NULL;
}

static void saw_cookie(struct cookie_jar *jar, const unsigned long value)
{
	test_info("Saw cookie %lu.", value);

	struct cookie_data *cookie_data = find_cookie(jar, value);

	if (cookie_data) {
		++cookie_data->seen;
	} else {
		test_fail("Unknown cookie value received: %lu", value);
	}
}

static struct cookie_data * add_cookie(struct cookie_jar *jar,
				       kdreg2_cookie_t value,
				       struct kdreg2_monitoring_params *monitoring_params)
{
	if (jar->num_cookies >= jar->jar_size) {
		test_fail("Internal error: cookie jar over-full.");
		return NULL;
	}

	struct cookie_data *cookie = jar->cookies + jar->num_cookies;

	cookie->value             = value;
	cookie->monitoring_params = *monitoring_params;

	jar->num_cookies++;

	test_info("Put cookie %lu, generation %u, location %zu in jar.",
		  value, monitoring_params->generation,
		  monitoring_params->location);

	return cookie;
}

static void remove_cookie(struct cookie_jar *jar, kdreg2_cookie_t value)
{
	if (!jar->num_cookies)
		test_fail("Trying to remove cookie %lu from empty jar.", value);

	struct cookie_data * cookie_data = find_cookie(jar, value);

	if (cookie_data) {
		cookie_data->value = KDREG2_BAD_COOKIE_VALUE;
		jar->num_cookies--;
		return;
	}

	test_fail("Trying to remove non-existent cookie %lu from jar.", value);
}

static void test_cookies_seen(struct cookie_jar *jar)
{
	test_info("Checking that all cookies were seen.");

	size_t num_cookies = jar->num_cookies;
	struct cookie_data *cookie_data = jar->cookies;

	for(; num_cookies; num_cookies--, cookie_data++)
	{
		if (1 == cookie_data->seen)
			continue;

		test_fail("Cookie %lu seen %i times, expected 1.",
			  cookie_data->value, cookie_data->seen);
		exit(-1);
	}

	test_info("All cookies seen.");
}

static void register_region_fast(struct common_data * data,
				 void *addr,
				 size_t length,
				 kdreg2_cookie_t cookie_value,
				 struct kdreg2_ioctl_monitor *monitor)
{
	monitor->addr   = addr;
	monitor->length = length;
	monitor->cookie = cookie_value;

	int ret = ioctl(data->fd, KDREG2_IOCTL_MONITOR, monitor);

	if (ret < 0) {
		perror(__FUNCTION__);
		test_fail("Register region failed: %i.", ret);
	}
}

static struct cookie_data *register_region(struct common_data * data,
					   void *addr,
					   size_t length,
					   kdreg2_cookie_t cookie_value)
{
	test_info("Attempting to register %p, len %zi, cookie %lu.",
		  addr, length, cookie_value);

	struct kdreg2_ioctl_monitor monitor;

	register_region_fast(data, addr, length, cookie_value, &monitor);

	struct cookie_data * cookie_data = add_cookie(&data->jar, cookie_value,
						      &monitor.monitoring_params);

	test_info("Write of registration data succeeded.");

	return cookie_data;
}

static void test_registered(struct common_data *data, size_t num_registered)
{
	test_info("Verifying registration of %zi regions.", num_registered);

	if (data->jar.num_cookies < num_registered)
		test_fail("Not enough cookies in jar: %zi present, %zi wanted.",
			  data->jar.num_cookies, num_registered);

	for(size_t i = 0; i < num_registered; i++) {
		struct cookie_data *cookie_data = data->jar.cookies + i;

		if (!kdreg2_mapping_changed(data->status_data, &cookie_data->monitoring_params)) {
			test_info("Registration %zi state %u, as expected.",
				  i, cookie_data->monitoring_params.generation);
			continue;
		}

		const struct kdreg2_monitoring_state  *ms;

		ms = data->status_data->monitoring_state_base +
			cookie_data->monitoring_params.location;

		test_fail("Registration data invalid cookie %zi: found %u, expected %u.",
			  i, ms->u.state.val, cookie_data->monitoring_params.generation);
	}

	test_info("Verification of %zi registered regions successful.", num_registered);
}

static void unregister_region_fast(struct common_data *data, struct cookie_data *cookie_data)
{
	struct kdreg2_ioctl_unmonitor unmonitor = {
		.cookie            = cookie_data->value,
		.monitoring_params = cookie_data->monitoring_params,
	};

	int ret = ioctl(data->fd, KDREG2_IOCTL_UNMONITOR, &unmonitor);

	if (ret < 0) {
		perror(__FUNCTION__);
		test_fail("Unregister with cookie %lu failed %i.",
			  cookie_data->value, ret);
	}

}

static void unregister_region(struct common_data * data, kdreg2_cookie_t cookie_value)
{
	test_info("Attempting to unregister cookie %lu.", cookie_value);

	/* find the cookie in the jar */

	struct cookie_data * cookie_data = find_cookie(&data->jar, cookie_value);

	if (!cookie_data) {
		test_fail("Unknown cookie %lu", cookie_value);
		return;
	}

	unregister_region_fast(data, cookie_data);

	remove_cookie(&data->jar, cookie_value);

	test_info("Unregistration with cookie %lu succeeded.", cookie_value);
}

static void test_unregistered(struct common_data *data, size_t num_unregistered)
{
	test_info("Verifying unregistration of %zi regions.", num_unregistered);

#if 0
	if (data->jar.num_cookies < num_unregistered)
		test_fail("Not enough cookies in jar: %zi present, %zi wanted.",
			  data->jar.num_cookies, num_unregistered);
#endif
	for(size_t i = 0; i < num_unregistered; i++) {
		struct cookie_data *cookie_data = data->jar.cookies + i;

		if (!kdreg2_mapping_changed(data->status_data, &cookie_data->monitoring_params))
			test_fail("Registration %zi is valid (expected invalid).", i);

		const struct kdreg2_monitoring_state *ms;

		ms = data->status_data->monitoring_state_base +
			cookie_data->monitoring_params.location;

		test_info("Registration data is invalid cookie %zi: found %u, orig %u. (this is good).",
			  i, ms->u.state.val, cookie_data->monitoring_params.generation);
	}

	test_info("Verification of %zi unregistered regions successful.", num_unregistered);
}

static void * compute_address(void *addr, size_t offset)
{
	return ((char *) addr) + offset;
}

static void test1(struct common_data *data)
{
	static const char * test_name = "Open the kdreg2 device.";

	test_start("%s", test_name);

	data->fd = open(KDREG2_DEVICE_NAME, O_RDWR);
	if (data->fd < 0) {
		perror("Problem opening kdreg2");
		test_fail("Open kdreg2 device, first time.");
	}

	test_info("Open kdreg2 device, fd = %i", data->fd);

	test_pass("%s", test_name);
}

static void test2(struct common_data __attribute__((unused)) *data)
{
	static const char * test_name = "Open the kdreg2 device second time.";

	test_start("%s", test_name);

	int fd2 = open(KDREG2_DEVICE_NAME, O_RDWR);

	if (fd2 < 0) {
		test_fail("Second open should have succeeded, fd = %i (expected >0 0)", fd2);
		exit(-1);
	}

	test_info("fd = %i (expected >= 0).", fd2);

	int ret = close(fd2);

	if (ret) {
		test_fail("Second instance close should have succeeded, errno = %i\n", errno);
		exit(-1);
	}

	test_pass("%s", test_name);
}

static void test3(struct common_data *data)
{
	static const char * test_name = "Testing IOCTL for getting the status_data.";

	test_start("%s", test_name);

	int ret = ioctl(data->fd, KDREG2_IOCTL_CONFIG_DATA, &data->config_data);
	if (ret < 0) {
		perror(__FUNCTION__);
		test_fail("Getting the config_data feature: %i.", ret);
	}

	test_info("ioctl KDREG2_IOCTL_CONFIG_DATA returned status_data %p.",
		  data->config_data.status_data);

	if (!data->config_data.status_data)
		test_fail("config_data.status_data NULL.");

	data->status_data = data->config_data.status_data;

	test_pass("%s", test_name);
}

static int test_free_list(const struct kdreg2_status_data *status_data)
{
	const struct kdreg2_monitoring_state *ms;

	ms = status_data->monitoring_state_base;

	for(size_t i = 0; i < status_data->max_regions-1; i++, ms++) {

		uint32_t gen = ms->u.state.val;
		uint32_t next = gen >> 1;

		if ((gen & 0x01) ||
		    (next != i+1)) {
			test_fail("Error: generation entry %zu invalid: %ui\n", i, gen);
		}
	}

	uint32_t gen = ms->u.state.val;
	uint32_t next = gen >> 1;
	uint32_t bad_index = (((uint32_t) -1) << 1) >> 1;

	if ((gen & 0x01) || (next != bad_index)) {
		test_fail("Error: last generation entry invalid: %ui\n", gen);
	}

	return 0;
}

static void test4(struct common_data *data)
{
	static const char * test_name = "Initial state test.";

	test_start("%s", test_name);

	test_info("status_data.version = 0x%lx", data->status_data->version);
	test_info("status_data.max_regions = %zu", data->status_data->max_regions);

	if (data->status_data->max_regions != data->config_data.max_regions)
		test_fail("Status_data.max_regions != config_data.max_regions: %zi %zi",
			  data->status_data->max_regions, data->config_data.max_regions);

	test_pending_events_counter(data, 0, 1);
	test_total_events_counter(data, 0);
	test_num_active_regions_counter(data, 0);

	test_info("status_data.monitoring_state_base = %p", data->status_data->monitoring_state_base);

	if (!data->status_data->monitoring_state_base)
		test_fail("monitoring_state_base pointer %p invalid.", data->status_data->monitoring_state_base);

	/* try to read all the valid data */

	test_info("Trying to read all the generation data.");

	test_free_list(data->status_data);

	test_info("All generation data correct.");

	if (test_readable(data->fd))
		test_fail("fd polls readable, expected not readable.");
	else
		test_info("fd polls not-readable, as expected.");

	test_empty_read(data);

	if (test_writable(data->fd))
		test_fail("fd poll writable, expected not writable.");
	else
		test_info("fd polls not writable, as expected.");

	test_failing_write(data);

	test_pass("%s", test_name);
}

static void test5(struct common_data *data)
{
	static const char * const test_name = "Test monitor and unmonitor.";

	test_start("%s", test_name);

	void * space = mmap_private_create(len);

	empty_cookie_jar(&data->jar);

	register_region(data, space, len, 42);

	test_registered(data, 1);

	test_num_active_regions_counter(data, 1);

	unregister_region(data, 42);

	test_unregistered(data, 1);

	test_num_active_regions_counter(data, 0);

	test_pass("%s", test_name);
}

static void test6(struct common_data *data)
{
	static const char * test_name = "Monitor overlapping regions at head multiple times.";

	test_start("%s", test_name);

	void * mmap_ptr = mmap_private_create(len);

	/* set monitoring of several pieces of vm space, all at the head */

	empty_cookie_jar(&data->jar);

	register_region(data, mmap_ptr, len,   10);
	register_region(data, mmap_ptr, len/2, 11);
	register_region(data, mmap_ptr, len/4, 12);

	int num_expected = 3;

	/* now do the munmap */

	mmap_free(mmap_ptr, len);

	test_info("Reading back cookies and validating.");

	kdreg2_cookie_t  cookie_value;

	for(int n = num_expected; n; n--) {
		test_pending_events_counter(data, n, 2);
		read_cookies(data->fd, &cookie_value, 1);
		saw_cookie(&data->jar, cookie_value);
	}

	/* should be none left in the queue */

	test_pending_events_counter(data, 0, 1);
	test_empty_read(data);
	test_cookies_seen(&data->jar);

	test_pass("%s", test_name);
}

static void test7(struct common_data *data)
{
	static const char * test_name = "Unmonitor a region.";

	test_start("%s", test_name);

	void * mmap_ptr = mmap_private_create(len);

	empty_cookie_jar(&data->jar);

	register_region(data, mmap_ptr, len, 111);
	unregister_region(data, 111);

	mmap_free(mmap_ptr, len);

	test_pending_events_counter(data, 0, 1);
	test_empty_read(data);

	test_pass("%s", test_name);
}

static void test8(struct common_data * data)
{
	static const char * test_name = "Monitor several non-overlapping regions.";

	test_start("%s", test_name);

	void * mmap_ptr = mmap_private_create(len);

	empty_cookie_jar(&data->jar);

	void *addr = ((char *) mmap_ptr) + (3 * len)/4;  /* 3/4 way over */

	register_region(data, mmap_ptr, len/2, 15);
	register_region(data, addr, len/4, 20);

	int num_expected = 2;

	/* now do the munmap */

	mmap_free(mmap_ptr, len);

	kdreg2_cookie_t cookie_value;

	for(int n = num_expected; n; n--) {
		test_pending_events_counter(data, n, 2);
		read_cookies(data->fd, &cookie_value, 1);
		saw_cookie(&data->jar, cookie_value);
	}

	test_pending_events_counter(data, 0, 1);
	test_empty_read(data);

	test_pass("%s", test_name);
}

static void test9(struct common_data *data)
{
	static const char * test_name = "Multi-cookie read feature.";

	test_start("%s", test_name);

	void * mmap_ptr = mmap_private_create(len);

	/* set monitoring of several pieces of vm space */

	empty_cookie_jar(&data->jar);

	register_region(data, mmap_ptr, len,   30);
	register_region(data, mmap_ptr, len/2, 31);

	int num_expected = 2;

	/* now do the munmap */

	mmap_free(mmap_ptr, len);

	test_pending_events_counter(data, num_expected, 2);

	kdreg2_cookie_t  cookie_vec[3];

	read_cookies(data->fd, cookie_vec, num_expected);

	for(int n = 0; n < num_expected; n++) {
		saw_cookie(&data->jar, cookie_vec[n]);
	}

	test_cookies_seen(&data->jar);

	test_pending_events_counter(data, 0, 1);
	test_empty_read(data);

	test_pass("%s", test_name);
}

static void test10(struct common_data *data)
{
	static const char * test_name = "Test poll() api.";

	test_start("%s", test_name);

	empty_cookie_jar(&data->jar);

	size_t size = 4 * len;

	void * addr = mmap_private_create(size);
	register_region(data, addr, size, 99);

	if (test_readable(data->fd)) {
		test_fail("File should be not readable, but is.\n");
	} else {
		test_info("File is initially not readable.");
	}

	mmap_free(addr, size);

	if (test_readable(data->fd)) {
		test_info("File is readable, and should be.");
	} else {
		test_fail("File is not readable, and should be.");
	}

	int num_expected = 1;

	test_pending_events_counter(data, num_expected, 2);

	kdreg2_cookie_t  cookie_vec[3];
	read_cookies(data->fd, cookie_vec, num_expected);

	for(int n = 0; n < num_expected; n++) {
		saw_cookie(&data->jar, cookie_vec[n]);
	}

	test_cookies_seen(&data->jar);

	test_pending_events_counter(data, 0, 1);
	test_empty_read(data);

	test_pass("%s", test_name);
}

static struct timespec get_clock()
{
	struct timespec t;
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t);
	return t;
}

static struct timespec time_delta(struct timespec *start, struct timespec *end)
{
	struct timespec delta = { end->tv_sec - start->tv_sec,
				  end->tv_nsec - start->tv_nsec };

	if (delta.tv_nsec < 0) {
		delta.tv_sec -= 1;
		delta.tv_nsec += 1000 * 1000 * 1000;
	}

	return delta;
}

static char * deltatime_str(struct timespec *delta)
{
	static char buf[16][64];
	static size_t bufidx = 0;

	if (bufidx >= ARRAY_SIZE(buf))
		bufidx = 0;

	sprintf(buf[bufidx], "%li.%09li", delta->tv_sec, delta->tv_nsec);

	return buf[bufidx++];
}

static void test11(struct common_data *data)
{
	static const char * test_name = "One-off test.";
	size_t pgsz = sysconf(_SC_PAGESIZE);

	test_start("%s", test_name);

	void * space = mmap_private_create(5 * pgsz);                 /*   |a---b|c---d|e---f|g---h|i---j| */

	struct {
		void * addr;
		size_t len;
		bool   monitor;
		kdreg2_cookie_t cookie;
	} piece[] = {
		{ compute_address(space, 0 * pgsz), pgsz, true, 0 },  /* 0  a---b                          */
		{ compute_address(space, 1 * pgsz), pgsz, true, 0 },  /* 1        c---d                    */
		{ compute_address(space, 2 * pgsz), pgsz, true, 0 },  /* 2              e---f              */
		{ compute_address(space, 3 * pgsz), pgsz, true, 0 },  /* 3                    g---h        */
		{ compute_address(space, 4 * pgsz), pgsz, false, 0 }, /* 4                          i---j  */
		{ compute_address(space, pgsz - 1), pgsz + 1, true, 0 },  /* 5      b|----d                    */
		{ compute_address(space, 3 * pgsz - 1), 2, true, 0 }, /* 6                  f|g            */
	};

#define UNMAP(_i)     mmap_free(piece[_i].addr, piece[_i].len)
#define REGISTER(_i)  register_region(data, piece[_i].addr, piece[_i].len, piece[_i].cookie)

	kdreg2_cookie_t   cookies[3];
	size_t            num_regions = 0;

	for(size_t i = 0; i < ARRAY_SIZE(piece); i++)
	{
		piece[i].cookie = i;
		if (piece[i].monitor) {
			REGISTER(i);
			num_regions++;
		}
	}

	test_num_active_regions_counter(data, num_regions);

	/* unmap 4, nothing should be evicted */

	test_info("Unmapping unmonitored region.");

	UNMAP(4);
	test_pending_events_counter(data, 0, 1);
	test_num_active_regions_counter(data, num_regions);

	/* unmap 3, (3,6) should be evicted */

	test_info("Unmapping region spanning 1 other by 1 byte.");

	UNMAP(3);
	test_pending_events_counter(data, 2, 2);
	num_regions -= 2;
	test_num_active_regions_counter(data, num_regions);
	read_cookies(data->fd, cookies, 2);
	contains_cookie(cookies, 3, piece[3].cookie);
	contains_cookie(cookies, 3, piece[6].cookie);

	/* unmap 1, 5 should be evicted as well */

	test_info("Unmapping simple overlap.");

	UNMAP(1);
	test_pending_events_counter(data, 2, 2);
	num_regions -= 2;
	test_num_active_regions_counter(data, num_regions);
	read_cookies(data->fd, cookies, 2);
	contains_cookie(cookies, 2, piece[1].cookie);
	contains_cookie(cookies, 2, piece[5].cookie);

	/* unmap 0 - no overlaps */

	test_info("Unmapping lone regions.");

	UNMAP(0);
	test_pending_events_counter(data, 1, 2);
	test_num_active_regions_counter(data, --num_regions);
	UNMAP(2);
	test_pending_events_counter(data, 2, 2);
	test_num_active_regions_counter(data, --num_regions);
	read_cookies(data->fd, cookies, 2);
	contains_cookie(cookies, 2, piece[0].cookie);
	contains_cookie(cookies, 2, piece[2].cookie);

#undef UNMAP
#undef REGISTER

	test_pass("%s", test_name);
}

static int cookie_compare(const void *c1, const void *c2)
{
	const kdreg2_cookie_t cookie1 = *(const kdreg2_cookie_t *) c1;
	const kdreg2_cookie_t cookie2 = *(const kdreg2_cookie_t *) c2;

	if (cookie1 == cookie2) return 0;
	return (cookie1 < cookie2) ? -1 : 1;
}

struct region_data {
	void * space;
	struct cookie_data * cookie_data;
};

#if 0
static int addr_compare(const void *rd1, const void *rd2)
{
	const struct region_data *region1 = (const struct region_data *) rd1;
	const struct region_data *region2 = (const struct region_data *) rd2;

	if (region1->space == region2->space) return 0;
	return (region1->space < region2->space) ? -1 : 1;
}
#endif

static void test12(struct common_data *data)
{
	static const char * test_name = "Maximum number of regions.";

	test_start("%s", test_name);
	test_info("MAX_COOKIES = %i", MAX_COOKIES);

	empty_cookie_jar(&data->jar);

	size_t size = 2 * 4096;

	dump_stats(data);

	/* static to avoid stack overflow */
	static struct region_data region_data[MAX_COOKIES];

	/* ************************************************ */

	test_info("Mapping %zu regions.", ARRAY_SIZE(region_data));
	silent = true;

	struct timespec tstart, tend;

	tstart = get_clock();
	for(size_t i = 0; i < ARRAY_SIZE(region_data); i++)
	{
		region_data[i].space = mmap_private_create(size);
		if ((region_data[i].space == MAP_FAILED) ||
		    (region_data[i].space == NULL))
			test_fail("Unable map region %zu", i);
	}
	tend = get_clock();
	struct timespec mmap_time = time_delta(&tstart, &tend);
	silent = false;

#if 0
	/* Test that regions are unique */

	size_t expected = ARRAY_SIZE(region_data);

	qsort(region_data, expected, sizeof(region_data[0]), addr_compare);

	for(size_t i = 0; i < expected - 1; i++) {
		if (region_data[i].space != region_data[i+1].space)
			continue;
		test_fail("Mapped regions not unique: %p %zu %zu",
				  region_data[i].space, i, i+1);
	}
#endif
	/* ************************************************ */

	test_info("Monitoring %zu regions.", ARRAY_SIZE(region_data));

	uint64_t starting_evictions = get_total_events_counter(data);
	silent = true;
	tstart = get_clock();

	for(size_t i = 0; i < ARRAY_SIZE(region_data); i++)
	{
		region_data[i].cookie_data = register_region(data, region_data[i].space, size, i);
	}

	tend = get_clock();
	silent = false;
	struct timespec register_time = time_delta(&tstart, &tend);

	/* We may get evictions while registering so we have to wait for
	 * them to arrive.
	 */

	sleep(1);
	dump_stats(data);
	size_t expected = ARRAY_SIZE(region_data);

	uint64_t new_evictions = get_total_events_counter(data) - starting_evictions;
	if (new_evictions > 0)
		test_info("%li evictions detected while registering.", new_evictions);

	expected -= new_evictions;
	test_num_active_regions_counter(data, expected);
	purge_pending_events(data);

	/* ************************************************ */

	test_info("Unmonitoring %zu regions.", ARRAY_SIZE(region_data));
	silent = true;
	tstart = get_clock();

	for(size_t i = 0; i < ARRAY_SIZE(region_data); i++)
	{
		unregister_region_fast(data, region_data[i].cookie_data);
	}

	tend = get_clock();
	silent = false;
	struct timespec unregister_time = time_delta(&tstart, &tend);

	dump_stats(data);
	test_num_active_regions_counter(data, 0);

	/* ************************************************ */

	test_info("Remonitoring %zu regions.", ARRAY_SIZE(region_data));

	starting_evictions = get_total_events_counter(data);
	silent = true;
	tstart = get_clock();

	struct kdreg2_ioctl_monitor monitor;

	for(size_t i = 0; i < ARRAY_SIZE(region_data); i++)
	{
		register_region_fast(data, region_data[i].space, size,
				     region_data[i].cookie_data->value, &monitor);
	}

	tend = get_clock();
	silent = false;
	struct timespec reregister_time = time_delta(&tstart, &tend);

	sleep(1);
	dump_stats(data);
	new_evictions = get_total_events_counter(data) - starting_evictions;
	expected = ARRAY_SIZE(region_data) - new_evictions;
	if (new_evictions)
		test_info("%li evictions detected while remonitoring.", new_evictions);

	test_num_active_regions_counter(data, expected);
	purge_pending_events(data);

	/* ************************************************ */

	test_info("Unmapping %zu regions.", expected);
	silent = true;
	tstart = get_clock();

	for(size_t i = 0; i < ARRAY_SIZE(region_data); i++)
	{
		mmap_free(region_data[i].space, size);
	}

	tend = get_clock();
	silent = false;
	struct timespec unmap_time = time_delta(&tstart, &tend);
	dump_stats(data);
	test_pending_events_counter(data, expected, 10);
	test_num_active_regions_counter(data, 0);

	/* ************************************************ */

	test_info("Reading %zu cookies.", expected);

	silent = true;

	static kdreg2_cookie_t cookies[ARRAY_SIZE(region_data)];

	read_cookies(data->fd, cookies, expected);

	silent = false;

	if (expected == ARRAY_SIZE(region_data))
	{
		test_info("Sorting %zu cookies.", ARRAY_SIZE(region_data));

		qsort(cookies, ARRAY_SIZE(cookies), sizeof(cookies[0]), cookie_compare);

		test_info("Testing %zu cookies.", ARRAY_SIZE(region_data));

		for(size_t i = 0; i < ARRAY_SIZE(region_data); i++)
		{
			if (cookies[i] == region_data[i].cookie_data->value)
				continue;
			test_fail("Cookie %zu value found: %zi, value expected: %zi",
				  i, region_data[i].cookie_data->value, cookies[i]);
		}
	}

	test_info("Timings:");
	test_info("%10s: %s", "mmap",       deltatime_str(&mmap_time));
	test_info("%10s: %s", "register",   deltatime_str(&register_time));
	test_info("%10s: %s", "unregister", deltatime_str(&unregister_time));
	test_info("%10s: %s", "reregister", deltatime_str(&reregister_time));
	test_info("%10s: %s", "unmap",      deltatime_str(&unmap_time));
	test_pass("%s", test_name);
}

/* static to avoid stack overflow with lots of cookies */

static struct common_data common_data = {
	.config_data.max_regions = MAX_COOKIES,
};

int main(void)
{
	/* Note: these tests are not independent.  The state of
	 * the common_data is built up during the first 4 tests.
	 */

	void (*tests[])(struct common_data *) =
	{
		test1,
		test2,
		test3,
		test4,
		test5,
		test6,
		test7,
		test8,
		test9,
		test10,
		test11,
		test12,
	};

	for(size_t i = 0; i < ARRAY_SIZE(tests); i++)
	{
		(*tests[i])(&common_data);
	}

	test_start("All sub-tests pass.");

	return 0;

}
