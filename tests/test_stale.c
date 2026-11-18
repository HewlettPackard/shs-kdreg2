// SPDX-License-Identifier: GPL-2.0
/*
 * Invalidation must be visible as soon as munmap() returns, even while
 * another thread holds the context mutex in a faulting read().
 */

#define _GNU_SOURCE

#include "kdreg2.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#define NUM_HELPERS 7
#define NUM_ROUNDS 100000
#define REGION_SIZE (64UL << 10)

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

static int open_monitor(struct kdreg2_config_data *config)
{
	int fd = open(KDREG2_DEVICE_NAME, O_RDWR | O_CLOEXEC | O_NONBLOCK);

	check(fd < 0, "open kdreg2");
	config->max_regions = 256;
	check(ioctl(fd, KDREG2_IOCTL_CONFIG_DATA, config), "configure kdreg2");
	return fd;
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

static void unmonitor(int fd, const struct kdreg2_ioctl_monitor *request)
{
	struct kdreg2_ioctl_unmonitor remove = {
		.cookie = request->cookie,
		.monitoring_params = request->monitoring_params,
	};

	check(ioctl(fd, KDREG2_IOCTL_UNMONITOR, &remove), "unmonitor");
}

struct blocked_read {
	int fd;
	void *buffer;
	ssize_t result;
};

static void *read_event(void *argument)
{
	struct blocked_read *reader = argument;

	reader->result = read(reader->fd, reader->buffer,
			      sizeof(struct kdreg2_event));
	return NULL;
}

/*
 * userfaultfd stops copy_to_user() while read() owns context->lock. The
 * main thread then unmaps another monitored region and checks its state
 * before resolving the fault, so deferred work cannot hide the bug.
 */
static int test_blocked_read(void)
{
	struct kdreg2_config_data config;
	struct kdreg2_ioctl_monitor victim, unaffected;
	struct uffdio_api api = { .api = UFFD_API };
	struct uffdio_register registration;
	struct uffdio_copy copy;
	struct uffd_msg message;
	struct blocked_read reader;
	struct pollfd poll_fd;
	pthread_t thread;
	size_t page_size = sysconf(_SC_PAGESIZE);
	void *fault_page, *zero_page, *seed_page, *control_page, *victim_page;
	int uffd, fd, stale, control_changed;

	uffd = syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
	if (uffd < 0 && (errno == EPERM || errno == ENOSYS || errno == EACCES)) {
		printf("SKIP blocked-read test: userfaultfd unavailable\n");
		return 0;
	}
	check(uffd < 0, "userfaultfd");
	check(ioctl(uffd, UFFDIO_API, &api), "UFFDIO_API");

	fd = open_monitor(&config);
	seed_page = map_region(page_size);
	victim_page = map_region(page_size);
	control_page = map_region(page_size);
	zero_page = map_region(page_size);
	fault_page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
			  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	check(fault_page == MAP_FAILED, "mmap fault page");

	memset(&registration, 0, sizeof(registration));
	registration.range.start = (unsigned long)fault_page;
	registration.range.len = page_size;
	registration.mode = UFFDIO_REGISTER_MODE_MISSING;
	check(ioctl(uffd, UFFDIO_REGISTER, &registration), "UFFDIO_REGISTER");

	monitor(fd, seed_page, page_size, 1);
	victim = monitor(fd, victim_page, page_size, 2);
	unaffected = monitor(fd, control_page, page_size, 3);
	check(munmap(seed_page, page_size), "munmap seed");
	poll_fd.fd = fd;
	poll_fd.events = POLLIN;
	check(poll(&poll_fd, 1, 5000) != 1 || !(poll_fd.revents & POLLIN),
	      "wait for seed event");

	reader.fd = fd;
	reader.buffer = fault_page;
	check(pthread_create(&thread, NULL, read_event, &reader), "pthread_create");
	poll_fd.fd = uffd;
	check(poll(&poll_fd, 1, 5000) != 1 || !(poll_fd.revents & POLLIN),
	      "wait for user fault");
	check(read(uffd, &message, sizeof(message)) != sizeof(message),
	      "read user fault");
	check(message.event != UFFD_EVENT_PAGEFAULT, "expected page fault");

	check(munmap(victim_page, page_size), "munmap victim");
	stale = !kdreg2_mapping_changed(config.status_data,
					&victim.monitoring_params);
	control_changed = kdreg2_mapping_changed(config.status_data,
						  &unaffected.monitoring_params);

	memset(&copy, 0, sizeof(copy));
	copy.src = (unsigned long)zero_page;
	copy.dst = (unsigned long)fault_page;
	copy.len = page_size;
	check(ioctl(uffd, UFFDIO_COPY, &copy), "UFFDIO_COPY");
	check(pthread_join(thread, NULL), "pthread_join");
	check(reader.result != sizeof(struct kdreg2_event), "read seed event");

	/* The queued event must retain the invalidated registration's cookie. */
	poll_fd.fd = fd;
	check(poll(&poll_fd, 1, 5000) != 1 || !(poll_fd.revents & POLLIN),
	      "wait for victim event");
	check(read(fd, fault_page, sizeof(struct kdreg2_event)) !=
	      sizeof(struct kdreg2_event), "read victim event");
	check(((struct kdreg2_event *)fault_page)->type !=
	      KDREG2_EVENT_MAPPING_CHANGE ||
	      ((struct kdreg2_event *)fault_page)->u.mapping_change.cookie !=
	      victim.cookie, "victim event cookie");

	unmonitor(fd, &unaffected);
	check(close(fd), "close kdreg2");
	check(close(uffd), "close userfaultfd");
	check(munmap(fault_page, page_size), "munmap fault page");
	check(munmap(zero_page, page_size), "munmap zero page");
	check(munmap(control_page, page_size), "munmap control");

	printf("Blocked read: stale=%d unaffected_changed=%d\n",
	       stale, control_changed);
	return stale || control_changed;
}

/* FLUSH must cover retired watches as well as events already in the ring. */
static int test_flush_notifications(void)
{
	enum { WATCHES = 129 };
	struct kdreg2_config_data config;
	struct kdreg2_ioctl_monitor first, request;
	struct kdreg2_event event;
	struct pollfd pfd;
	size_t page_size = sysconf(_SC_PAGESIZE);
	uint64_t expected_total = 0;
	unsigned int round, i;
	int fd = open_monitor(&config);
	const struct kdreg2_counter *total = &config.status_data->total_events;

	pfd.fd = fd;
	pfd.events = POLLIN;
	for (round = 0; round < 16; round++) {
		void *page = map_region(page_size);

		first = monitor(fd, page, page_size, 1);
		for (i = 1; i < WATCHES; i++)
			monitor(fd, page, page_size, i + 1);
		check(munmap(page, page_size), "unmap before flush");
		check(ioctl(fd, KDREG2_IOCTL_FLUSH, 0), "flush retired watches");
		expected_total += WATCHES;
		check(kdreg2_read_counter(total) != expected_total,
		      "flush must account for retired watches");
		check(ioctl(fd, KDREG2_IOCTL_FLUSH, 0), "repeat flush");
		check(kdreg2_read_counter(total) != expected_total,
		      "repeat flush must not count retired watches twice");
		check(!kdreg2_mapping_changed(config.status_data,
					      &first.monitoring_params),
		      "flush must not restore validity");
		check(poll(&pfd, 1, 10) != 0, "event delivered after flush");

		/* Notifications generated after the flush must still arrive. */
		page = map_region(page_size);
		request = monitor(fd, page, page_size, 1000);
		check(munmap(page, page_size), "unmap after flush");
		check(poll(&pfd, 1, 5000) != 1 || !(pfd.revents & POLLIN),
		      "wait for post-flush event");
		check(read(fd, &event, sizeof(event)) != sizeof(event),
		      "read post-flush event");
		check(event.type != KDREG2_EVENT_MAPPING_CHANGE ||
		      event.u.mapping_change.cookie != request.cookie,
		      "post-flush event identity");
		expected_total++;
		check(kdreg2_read_counter(total) != expected_total,
		      "post-flush event count");
	}

	/* Leave the ring unread. FLUSH counts only events that would fit. */
	for (round = 0; round < 2; round++) {
		void *page = map_region(page_size);

		for (i = 0; i < config.max_regions; i++)
			monitor(fd, page, page_size, i + 1);
		check(munmap(page, page_size), "unmap without reading events");
	}
	check(ioctl(fd, KDREG2_IOCTL_FLUSH, 0), "flush full ring");
	check(kdreg2_read_counter(total) != expected_total + config.max_regions,
	      "flush overflow accounting");
	check(kdreg2_read_counter(&config.status_data->pending_events) != 0,
	      "pending events after overflow flush");
	check(close(fd), "close flush test");
	printf("Flush notifications: delivery, total events, and overflow passed\n");
	return 0;
}

struct helper {
	int fd;
	unsigned int id;
	atomic_bool *stop;
	pthread_barrier_t *barrier;
};

static void *contend(void *argument)
{
	struct helper *helper = argument;
	void *address = map_region(REGION_SIZE);
	uint64_t cookie = (uint64_t)helper->id << 48;

	pthread_barrier_wait(helper->barrier);
	while (!atomic_load(helper->stop)) {
		struct kdreg2_ioctl_monitor request =
			monitor(helper->fd, address, REGION_SIZE, cookie++);

		unmonitor(helper->fd, &request);
	}
	check(munmap(address, REGION_SIZE), "munmap helper");
	return NULL;
}

static int test_contention(unsigned long rounds)
{
	struct kdreg2_config_data config;
	struct helper helpers[NUM_HELPERS];
	pthread_t threads[NUM_HELPERS];
	pthread_barrier_t barrier;
	atomic_bool stop = ATOMIC_VAR_INIT(false);
	unsigned long round, stale = 0;
	unsigned int i;
	int fd = open_monitor(&config);

	check(pthread_barrier_init(&barrier, NULL, NUM_HELPERS + 1),
	      "pthread_barrier_init");
	for (i = 0; i < NUM_HELPERS; i++) {
		helpers[i].fd = fd;
		helpers[i].id = i + 1;
		helpers[i].stop = &stop;
		helpers[i].barrier = &barrier;
		check(pthread_create(&threads[i], NULL, contend, &helpers[i]),
		      "pthread_create");
	}
	pthread_barrier_wait(&barrier);

	for (round = 0; round < rounds; round++) {
		struct kdreg2_event event;
		void *address = map_region(REGION_SIZE);
		struct kdreg2_ioctl_monitor request =
			monitor(fd, address, REGION_SIZE, round);

		check(munmap(address, REGION_SIZE), "munmap main");
		if (!kdreg2_mapping_changed(config.status_data,
					    &request.monitoring_params))
			stale++;
		unmonitor(fd, &request);
		while (read(fd, &event, sizeof(event)) == sizeof(event))
			;
		check(errno != EAGAIN, "drain events");
	}

	atomic_store(&stop, true);
	for (i = 0; i < NUM_HELPERS; i++)
		check(pthread_join(threads[i], NULL), "pthread_join");
	check(pthread_barrier_destroy(&barrier), "pthread_barrier_destroy");
	check(close(fd), "close kdreg2");
	printf("Contention: rounds=%lu helpers=%d stale=%lu\n",
	       rounds, NUM_HELPERS, stale);
	return stale != 0;
}

int main(int argc, char **argv)
{
	unsigned long rounds = NUM_ROUNDS;
	int failed;

	if (argc > 1) {
		char *end;

		errno = 0;
		rounds = strtoul(argv[1], &end, 10);
		if (errno || !argv[1][0] || *end || !rounds) {
			fprintf(stderr, "Usage: %s [positive rounds]\n", argv[0]);
			return EXIT_FAILURE;
		}
	}
	alarm(120);
	failed = test_blocked_read();
	failed |= test_flush_notifications();
	failed |= test_contention(rounds);
	return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
