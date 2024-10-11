/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2023 Hewlett Packard Enterprise Development LP
 */

#include "test_mr.h"
#include "./dlist.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>   /* for memset */
#include <unistd.h>

#define EVICTOR_THREAD_ATTR NULL
#define INFINITE_TIMEOUT -1

struct test_mr_entry {
	void * addr;
	size_t len;
	kdreg2_cookie_t cookie;
	struct kdreg2_monitoring_params monitoring_params;
	struct dlist_entry dlist;
};

struct test_mr_context {
	int fd;
	const struct kdreg2_status_data *status_data;
	pthread_mutex_t  mr_lock;
	struct dlist_entry dlist_head;
	uint64_t  cache_hits;
	uint64_t  cache_misses;
	uint64_t  eviction_hits;
	uint64_t  eviction_misses;
	pthread_t evictor_thread;
	int       evictor_return;
};

int test_mr_start_evictor(struct test_mr_context * context);
int test_mr_stop_evictor(struct test_mr_context * context);
void * test_mr_evictor(void * arg);
void test_mr_evictor_cleanup(void *arg);

struct test_mr_entry *
test_mr_allocate_entry(struct test_mr_context * context);
void test_mr_free_entry(struct test_mr_context * context,
			struct test_mr_entry * entry);
void test_mr_insert_entry(struct test_mr_context * context,
			  struct test_mr_entry * entry);
void test_mr_remove_entry(struct test_mr_context * context,
			  struct test_mr_entry * entry);

int test_mr_enter(struct test_mr_context *context);
int test_mr_exit(struct test_mr_context *context, int ret);
struct test_mr_entry *
test_mr_find_entry(struct test_mr_context * context,
		   kdreg2_cookie_t cookie);

int test_mr_read_evictions(struct test_mr_context *context);
int test_mr_evict(struct test_mr_context *context,
		  kdreg2_cookie_t cookie);

struct test_mr_context *
test_mr_allocate_context()
{
	struct test_mr_context * context = malloc(sizeof(*context));
	if (!context)
		return context;

	context->fd = -1;
	context->status_data = 0;
	dlist_init(&context->dlist_head);
	context->cache_hits = 0;
	context->cache_misses = 0;
	context->eviction_hits = 0;
	context->eviction_misses = 0;
	context->evictor_thread = 0;
	context->evictor_return = 0;

	/*
	 * We need a robust mutex to avoid undefined behavior
	 * in test_mr_evictor_cleanup().
	 */

	pthread_mutexattr_t   mutex_attr;

	pthread_mutexattr_init(&mutex_attr);
	pthread_mutexattr_setrobust(&mutex_attr, PTHREAD_MUTEX_ROBUST);

	pthread_mutex_init(&context->mr_lock, &mutex_attr);

	pthread_mutexattr_destroy(&mutex_attr);

	return context;
}

int test_mr_free_context(struct test_mr_context * context)
{
	int ret = pthread_mutex_trylock(&context->mr_lock);

	switch(ret){
	case 0:
		break;
	case EOWNERDEAD:
		pthread_mutex_unlock(&context->mr_lock);
		ret = 0;
		break;
	case EBUSY:    /* locked */
	default:
		return -ret;
	}

	if (!dlist_empty(&context->dlist_head))
		return -EBUSY;

	pthread_mutex_destroy(&context->mr_lock);

	free(context);

	return 0;
}

void test_mr_insert_entry(struct test_mr_context * context,
			  struct test_mr_entry * entry)
{
	dlist_insert_before(&entry->dlist, &context->dlist_head);
}

void test_mr_remove_entry(struct test_mr_context * __attribute__((unused)) context,
			  struct test_mr_entry * entry)
{
	dlist_remove_init(&entry->dlist);
}

int test_mr_start(struct test_mr_context * context,
		  size_t max_regions)
{
	int   ret = 0;

	ret = pthread_mutex_lock(&context->mr_lock);
	if (ret)
		goto exit_ret;

	if (context->fd >= 0)
		goto exit_locked;

	context->fd = open(KDREG2_DEVICE_NAME, O_RDWR | O_NONBLOCK);

	if (context->fd <= 0)
		goto exit_errno;

	struct kdreg2_config_data config_data = {
		.max_regions = max_regions,
	};

	ret = ioctl(context->fd, KDREG2_IOCTL_CONFIG_DATA, &config_data);
	if (ret)
		goto exit_errno;

	context->status_data = config_data.status_data;

	ret = test_mr_start_evictor(context);
	if (ret)
		goto exit_close;

	goto exit_locked;

exit_errno:

	ret = -errno;

exit_close:

	close(context->fd);
	context->fd = -1;

exit_locked:

	pthread_mutex_unlock(&context->mr_lock);

exit_ret:

	return (ret > 0) ? -ret : ret;
}

int test_mr_stop(struct test_mr_context * context)
{
	int ret = 0;

	test_mr_stop_evictor(context);

	ret = pthread_mutex_lock(&context->mr_lock);
	if (ret)
		goto exit_ret;

	struct test_mr_entry   *entry;
	struct dlist_entry     *tmp;
	dlist_foreach_container_safe(&context->dlist_head,
				     struct test_mr_entry,
				     entry, dlist, tmp) {
		test_mr_remove_entry(context, entry);
		test_mr_free_entry(context, entry);
	}

	if (context->fd > 0) {
		close(context->fd);
		context->fd = -1;
		context->status_data = 0;
	}

	pthread_mutex_unlock(&context->mr_lock);

exit_ret:

	return (ret > 0) ? -ret : ret;
}

int test_mr_register(struct test_mr_context * context,
		     void * addr, size_t len, kdreg2_cookie_t cookie)
{
	int ret = test_mr_enter(context);
	if (ret)
		return ret;

	/* We have the lock.  So the evictor thread can't run.
	 *
	 * If we find our entry is invalid, remove it and try
	 * again.  (The eviction event should be in flight.)
	 *
	 * If we find our entry is valid, and the range matches,
	 * we are done with success.
	 *
	 * If we find our entry is valid and the range doesn't match,
	 * it's an error.
	 */

	struct test_mr_entry * entry = NULL;

	while(NULL != (entry = test_mr_find_entry(context, cookie))) {

		bool valid = !kdreg2_mapping_changed(context->status_data,
						     &entry->monitoring_params);
		if (!valid) {
			test_mr_remove_entry(context, entry);
			test_mr_free_entry(context, entry);
			continue;
		}

		if ((entry->addr == addr) && (entry->len == len)) {
			context->cache_hits++;
			ret = 0;
		} else {
			ret = EINVAL;
		}

		return test_mr_exit(context, ret);
	}

	/* We have no existing entry.  Make one. */

	entry = test_mr_allocate_entry(context);
	if (!entry) {
		return test_mr_exit(context, -ENOMEM);
	}

	entry->addr = addr;
	entry->len  = len;
	entry->cookie = cookie;

	struct kdreg2_ioctl_monitor   monitor = {
		.addr = addr,
		.length  = len,
		.cookie = cookie
	};

	ret = ioctl(context->fd, KDREG2_IOCTL_MONITOR, &monitor);
	if (ret) {
		goto exit_entry;
	}

	entry->monitoring_params = monitor.monitoring_params;

	test_mr_insert_entry(context, entry);
	context->cache_misses++;

	return test_mr_exit(context, 0);

exit_entry:

	test_mr_free_entry(context, entry);

	return test_mr_exit(context, ret);
}

int test_mr_unregister(struct test_mr_context * context,
		       kdreg2_cookie_t cookie)
{
	int ret = 0;

	ret = test_mr_enter(context);
	if (ret)
		return ret;

	/* We have the lock.  So the evictor thread can't run.
	 *
	 * If we find our entry is invalid, remove it and try
	 * again.  (The eviction event should be in flight.)
	 *
	 * It's possible we may not find a valid entry.
	 */

	struct test_mr_entry * entry = NULL;

	while(NULL != (entry = test_mr_find_entry(context, cookie))) {

		bool valid = !kdreg2_mapping_changed(context->status_data,
						     &entry->monitoring_params);

		if (valid)
			break;

		test_mr_remove_entry(context, entry);
		test_mr_free_entry(context, entry);
	}

	if (!entry)
		return test_mr_exit(context, 0);

	struct kdreg2_ioctl_unmonitor  unmonitor = {
		.cookie            = cookie,
		.monitoring_params = entry->monitoring_params,
	};

	ret = ioctl(context->fd, KDREG2_IOCTL_UNMONITOR, &unmonitor);

	if (-ESRCH == ret)
		ret = 0;

	test_mr_remove_entry(context, entry);
	test_mr_free_entry(context, entry);

	return test_mr_exit(context, ret);
}

int test_mr_start_evictor(struct test_mr_context * context)
{
	int ret = pthread_create(&context->evictor_thread,
				 EVICTOR_THREAD_ATTR,
				 test_mr_evictor,
				 context);

	return ret;
}

int test_mr_stop_evictor(struct test_mr_context * context)
{
	if (!context->evictor_thread)
		return 0;

	int ret = pthread_cancel(context->evictor_thread);
	if (ret)
		return ret;

	void *result;
	ret = pthread_join(context->evictor_thread, &result);

	return ret;
}

void * test_mr_evictor(void * arg)
{
	struct test_mr_context * context = (struct test_mr_context *) arg;

	int old_state;
	int ret = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &old_state);
	if (ret)
		goto error_ret;

	pthread_cleanup_push(test_mr_evictor_cleanup, context);

	struct pollfd pollfd = {
		.fd = context->fd,
		.events = POLLIN,
	};

	while(1) {

		/* wait until there are events to read */

		int n = poll(&pollfd, 1, INFINITE_TIMEOUT);

		if (0 == n)        /* timeout(?) */
			continue;

		if (n < 0) {
			switch(errno) {
			case EINTR:
				continue;
			default:
				ret = errno;
				goto error_ret;
			}
		}

		/* We need to get the lock because each read
		 * decrements the unmap count.  This prevents
		 * the other threads from racing when the count
		 * goes to 0.
		 */

		ret = pthread_mutex_lock(&context->mr_lock);

		if (ret)
			goto error_ret;

		ret = test_mr_read_evictions(context);

		pthread_mutex_unlock(&context->mr_lock);

		if (ret)
			goto error_ret;
	}

	/* Due to the way pthread_cleanup_push is implemented as a macro, we
	 * need to have a matching pop or it won't compile.  Even if it's
	 * unreachable.  Really.
	 */

	pthread_cleanup_pop(0);

error_ret:

	context->evictor_return = ret;
	return &context->evictor_return;
}

void test_mr_evictor_cleanup(void * arg)
{
	struct test_mr_context * context = (struct test_mr_context *) arg;

	/* try to prevent wedge if evictor is killed while
	 * it holds the mutex.
	 */

	pthread_mutex_unlock(&context->mr_lock);
}

struct test_mr_entry * test_mr_allocate_entry(struct test_mr_context * __attribute__((unused)) context)
{
	struct test_mr_entry * entry = malloc(sizeof(*entry));

	if (!entry)
		return NULL;

	entry->addr   = NULL;
	entry->len    = 0;
	entry->cookie = KDREG2_BAD_COOKIE_VALUE;
	dlist_init(&entry->dlist);

	return entry;
}

void test_mr_free_entry(struct test_mr_context * __attribute__((unused)) context,
			struct test_mr_entry * entry)
{
	assert(dlist_empty(&entry->dlist));
	free(entry);
}

int test_mr_enter(struct test_mr_context *context)
{
	int ret = pthread_mutex_lock(&context->mr_lock);

	if (ret)
		return ret;

	ret = test_mr_read_evictions(context);

	if (ret)
		pthread_mutex_unlock(&context->mr_lock);

	return ret;
}

int test_mr_exit(struct test_mr_context *context, int ret)
{
	if (!ret)
		ret = pthread_mutex_unlock(&context->mr_lock);

	return ret;
}

struct test_mr_entry * test_mr_find_entry(struct test_mr_context * context,
					  kdreg2_cookie_t cookie)
{
	struct test_mr_entry *entry;

	dlist_foreach_container(&context->dlist_head, struct test_mr_entry,
				entry, dlist) {
		if (entry->cookie == cookie)
			return entry;
	}

	return NULL;
}

int test_mr_read_evictions(struct test_mr_context *context)
{
	struct kdreg2_event  event;

	while(kdreg2_read_counter(&context->status_data->pending_events) > 0) {

		ssize_t bytes = read(context->fd, &event, sizeof(event));

		if (0 > bytes) {
			int err = errno;

			/* EINTR means we caught a signal */
			if (EINTR == err)
				continue;

			/* Nothing left */
			if ((EAGAIN == err) ||
			    (EWOULDBLOCK == err))
				return 0;

			/* all other errors */
			return err;
		}

		switch(event.type) {
		case KDREG2_EVENT_MAPPING_CHANGE:

			test_mr_evict(context, event.u.mapping_change.cookie);
			break;

		default:

			return ENOMSG;
		}
	}

	return 0;
}




int test_mr_evict(struct test_mr_context * context,
		  kdreg2_cookie_t cookie)
{
	struct test_mr_entry * entry = test_mr_find_entry(context, cookie);

	if (!entry) {
		context->eviction_misses++;
		return 0;
	}

	test_mr_remove_entry(context, entry);
	test_mr_free_entry(context, entry);
	context->eviction_hits++;

	return 0;
}

void test_mr_show_stats(struct test_mr_context * context, FILE *file)
{
	pthread_mutex_lock(&context->mr_lock);

	fprintf(file,
		"cache hits: %lu\n"
		"cache miss: %lu\n"
		"-------------------\n"
		"evict hits: %lu\n"
		"evict miss: %lu\n"
		"evict pend: %lu\n"
		"evict total: %lu\n",
		context->cache_hits,
		context->cache_misses,
		context->eviction_hits,
		context->eviction_misses,
		kdreg2_read_counter(&context->status_data->pending_events),
		kdreg2_read_counter(&context->status_data->total_events));

	pthread_mutex_unlock(&context->mr_lock);
}
