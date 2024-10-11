/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2023 Hewlett Packard Enterprise Development LP
 */

#define _GNU_SOURCE 1

#include "test_mr.h"

#include <sys/mman.h>
#include <sys/syscall.h>

#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(_x) (sizeof(_x)/sizeof(_x[0]))
#endif

#define MAX_REGIONS (1024 * 512)
// #define MAX_REGIONS (1024 * 64)

#define NUM_WORKERS 20
#define NUM_LOOPS 50000

#define DEFAULT_MUTEX_ATTR NULL
#define DEFAULT_THREAD_ATTR NULL

#define PAGE_SIZE 4096
#define MMAP_OPTS   (MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK)
#define MMAP_PROT   (PROT_READ | PROT_WRITE)
#define MMAP_ANY_ADDR NULL
#define MMAP_NO_FD -1
#define MMAP_OFFSET 0

#define COUNT(x_)  (sizeof(x_)/sizeof(x_[0]))

#define DEBUG_PRINT 0

#if DEBUG_PRINT
__attribute__((format (printf, 3, 4)))
void pprintf_implementation(const char *func, int line, const char *fmt, ...);
#define pprintf(...) pprintf_implementation(__FUNCTION__, __LINE__, __VA_ARGS__)
#else
#define pprintf(...)
#endif

#if 0
static inline pid_t gettid()
{
	return (pid_t) syscall(__NR_gettid);
}
#endif

typedef kdreg2_cookie_t cookie_t;

struct test_context {
	struct test_mr_context * mr_context;
	struct timespec start_time;
	struct timespec finish_time;
};


struct worker_data {
	struct test_context * context;
	pthread_t pthreadid;
	pid_t tid;
	size_t loop;
	void * address;
	size_t len;
	bool in_use;
	bool registered;
	cookie_t cookie_base;
	cookie_t cookie;
};

void test_context_init(struct test_context * context);
void test_context_destroy(struct test_context * context);

void start_mr(struct test_context * context);
void stop_mr(struct test_context * context);
void register_mr(struct test_context * context, void * addr,
		 size_t len, cookie_t cookie);

void test_func(struct test_context *context);
void * worker_main(void *arg);
void print_stats(struct test_context * context);

void ret_check(int ret);
void errno_check(bool failed);

struct timespec time_delta(struct timespec *start, struct timespec *end);
char * deltatime_str(struct timespec *delta);
struct timespec get_clock(void);

int main()
{
	struct test_context context;

	test_context_init(&context);

	start_mr(&context);

	context.start_time = get_clock();

	test_func(&context);

	context.finish_time = get_clock();

	print_stats(&context);

	stop_mr(&context);

	test_context_destroy(&context);

	return 0;
}

void test_context_init(struct test_context * context)
{
	context->mr_context = test_mr_allocate_context();
}

void test_context_destroy(struct test_context * context)
{
	if (context->mr_context) {
		test_mr_free_context(context->mr_context);
		context->mr_context =0;
	}
}

void start_mr(struct test_context * context)
{
	int ret = test_mr_start(context->mr_context, MAX_REGIONS);
	ret_check(ret);
}

void stop_mr(struct test_context * context)
{
	int ret = test_mr_stop(context->mr_context);
	ret_check(ret);
}

void register_mr(struct test_context * context, void * addr,
		 size_t len, cookie_t cookie)
{
	int ret = test_mr_register(context->mr_context, addr, len, cookie);
	ret_check(ret);
}

static struct worker_data worker_data[NUM_WORKERS];
static pthread_mutex_t data_lock;

void test_func(struct test_context *context) {

	int ret = pthread_mutex_init(&data_lock, DEFAULT_MUTEX_ATTR);
	ret_check(ret);

	struct worker_data * data = worker_data;
	struct worker_data * const data_start = worker_data;
	struct worker_data * const data_end = worker_data + COUNT(worker_data);

	for(data = data_start; data < data_end; data++) {
		data->context = context;
		data->cookie_base = 1000 * 1000 * (data - data_start);
		pthread_create(&data->pthreadid, DEFAULT_THREAD_ATTR,
			       worker_main, data);
	}

	for(data = data_start; data < data_end; data++) {
		pthread_join(data->pthreadid, NULL);
	}
}

void * worker_main(void * arg)
{
	struct worker_data * data = (struct worker_data *) arg;

	pprintf("worker starting, thread_id 0x%lx, tid %i\n",
		data->pthreadid, gettid());

	int ret = 0;

	for(data->loop = 0; data->loop < NUM_LOOPS; data->loop++) {

		data->address = mmap(MMAP_ANY_ADDR, PAGE_SIZE, MMAP_PROT,
				     MMAP_OPTS, MMAP_NO_FD, MMAP_OFFSET);
		errno_check(data->address == MAP_FAILED);

		data->len = PAGE_SIZE;
		data->in_use = false;
		data->registered = false;
		data->cookie = data->cookie_base + data->loop;

		pprintf("worker registering address %p, cookie %lu\n",
			data->address, data->cookie);
		register_mr(data->context, data->address,
			    data->len, data->cookie);
		ret_check(ret);
		data->in_use = true;

		pprintf("worker unmapping begin address %p\n", data->address);
		ret = munmap(data->address, data->len);
		errno_check(ret);
		pprintf("worker unmapping done  address %p\n", data->address);
	}

	pprintf("worker done\n");

	return NULL;
}

void print_stats(struct test_context *context)
{
	struct timespec delta = time_delta(&context->start_time,
					   &context->finish_time);
	printf("test time: %s\n", deltatime_str(&delta));

	test_mr_show_stats(context->mr_context, stdout);

	printf("The tests passes if:\n"
	       "   cache hits = 0\n"
	       "   cache miss = evict hits + evict pend = evict total\n");

}

void ret_check(int ret)
{
	if (ret)
	exit(ret);
}

void errno_check(bool failed)
{
	if (failed)
	exit(errno);
}

struct timespec get_clock(void)
{
	struct timespec t;
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t);
	return t;
}

struct timespec time_delta(struct timespec *start, struct timespec *end)
{
	struct timespec delta = { end->tv_sec - start->tv_sec,
				  end->tv_nsec - start->tv_nsec };

	if (delta.tv_nsec < 0) {
		delta.tv_sec -= 1;
		delta.tv_nsec += 1000 * 1000 * 1000;
	}

	return delta;
}

char * deltatime_str(struct timespec *delta)
{
	static char buf[16][64];
	static size_t bufidx = 0;

	if (bufidx >= ARRAY_SIZE(buf))
		bufidx = 0;

	sprintf(buf[bufidx], "%li.%09li", delta->tv_sec, delta->tv_nsec);

	return buf[bufidx++];
}

#if DEBUG_PRINT
#include <stdio.h>
__attribute__((format (printf, 3, 4)))
void pprintf_implementation(const char *func, int line, const char *fmt, ...)
{
	char buf[512];
	va_list ap;
	char *buf_ptr = buf;

	buf_ptr += sprintf(buf_ptr, "[%i] %s:%i ", gettid(), func, line);
	va_start(ap, fmt);
	buf_ptr += vsprintf(buf_ptr, fmt, ap);
	va_end(ap);

	write(2, buf, buf_ptr - buf);
	fsync(2);
}
#endif
