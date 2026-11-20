// SPDX-License-Identifier: GPL-2.0
/* Regression for UNMONITOR_ALL accounting and monitoring-slot recovery. */
#define _GNU_SOURCE
#include "kdreg2.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static void check(int failed, const char *operation)
{
	if (failed) {
		perror(operation);
		exit(EXIT_FAILURE);
	}
}

static void *map_region(size_t length)
{
	void *address = mmap(NULL, length, PROT_READ | PROT_WRITE,
			     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	check(address == MAP_FAILED, "mmap");
	memset(address, 0, length);
	return address;
}

static struct kdreg2_ioctl_monitor monitor(int fd, void *address,
					   size_t length, uint64_t cookie)
{
	struct kdreg2_ioctl_monitor request = {
		.addr = address, .length = length, .cookie = cookie,
	};

	check(ioctl(fd, KDREG2_IOCTL_MONITOR, &request), "monitor");
	return request;
}

static int test_capacity_recovery(void)
{
	enum { CAPACITY = 129 };
	struct kdreg2_config_data config = { .max_regions = CAPACITY };
	struct kdreg2_ioctl_monitor watches[CAPACITY], extra;
	struct kdreg2_event events[CAPACITY];
	struct pollfd poll_fd;
	bool seen[CAPACITY] = { false };
	size_t page_size = sysconf(_SC_PAGESIZE);
	void *page = map_region(page_size);
	unsigned int i, delivered = 0;
	int fd = open(KDREG2_DEVICE_NAME, O_RDWR | O_CLOEXEC | O_NONBLOCK);

	check(fd < 0, "open unconfigured kdreg2");
	memset(&extra, 0, sizeof(extra));
	extra.addr = page;
	extra.length = page_size;
	extra.cookie = CAPACITY + 1;
	errno = 0;
	check(ioctl(fd, KDREG2_IOCTL_MONITOR, &extra) != -1 ||
	      errno != ENOSPC, "monitor without capacity");
	check(ioctl(fd, KDREG2_IOCTL_CONFIG_DATA, &config), "configure capacity");

	for (i = 0; i < CAPACITY; i++)
		watches[i] = monitor(fd, page, page_size, i + 1);
	errno = 0;
	check(ioctl(fd, KDREG2_IOCTL_MONITOR, &extra) != -1 ||
	      errno != ENOSPC, "monitor beyond capacity");
	check(ioctl(fd, KDREG2_IOCTL_UNMONITOR_ALL, 0), "unmonitor all");
	check(kdreg2_read_counter(&config.status_data->num_active_regions),
	      "active regions after unmonitor all");
	for (i = 0; i < CAPACITY; i++) {
		check(!kdreg2_mapping_changed(config.status_data,
					      &watches[i].monitoring_params),
		      "unmonitor all validity");
		watches[i] = monitor(fd, page, page_size, i + 1);
	}

	check(munmap(page, page_size), "unmap capacity watches");
	for (i = 0; i < CAPACITY; i++)
		check(!kdreg2_mapping_changed(config.status_data,
					      &watches[i].monitoring_params),
		      "batched invalidation validity");

	poll_fd.fd = fd;
	poll_fd.events = POLLIN;
	while (delivered < CAPACITY) {
		ssize_t bytes;
		size_t j;

		check(poll(&poll_fd, 1, 5000) != 1 ||
		      !(poll_fd.revents & POLLIN), "wait for batched events");
		bytes = read(fd, events, sizeof(events));
		check(bytes <= 0 || bytes % sizeof(events[0]),
		      "read batched events");
		for (j = 0; j < (size_t)bytes / sizeof(events[0]); j++) {
			kdreg2_cookie_t cookie = events[j].u.mapping_change.cookie;

			check(events[j].type != KDREG2_EVENT_MAPPING_CHANGE ||
			      cookie < 1 || cookie > CAPACITY,
			      "batched event cookie");
			check(seen[cookie - 1], "duplicate batched event");
			seen[cookie - 1] = true;
			delivered++;
		}
	}

	/* Re-enable full capacity after the retired records have been freed. */
	page = map_region(page_size);
	for (i = 0; i < CAPACITY; i++)
		watches[i] = monitor(fd, page, page_size, i + 1);
	check(ioctl(fd, KDREG2_IOCTL_UNMONITOR_ALL, 0), "final unmonitor all");
	config.max_regions = 0;
	check(ioctl(fd, KDREG2_IOCTL_CONFIG_DATA, &config), "disable capacity");
	check(!kdreg2_mapping_changed(config.status_data,
				      &watches[0].monitoring_params),
	      "validity check after disabling capacity");
	check(close(fd), "close capacity test");
	check(munmap(page, page_size), "unmap capacity test");
	printf("Capacity recovery: watches=%u events=%u\n", CAPACITY, delivered);
	return 0;
}

int main(void)
{
	alarm(120);
	return test_capacity_recovery();
}
