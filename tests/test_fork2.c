/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2023 Hewlett Packard Enterprise Development LP
 */

#include "kdreg2.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int fd = -1;
pid_t child_pid = 0;
void test_poll(bool is_child);

int main()
{
	fd = open(KDREG2_DEVICE_NAME, O_RDWR);

	if (fd < 0) {
		char buf[512];
		sprintf(buf, "Unable to open %s", KDREG2_DEVICE_NAME);
		perror(buf);
		exit(errno);
	}

	child_pid = fork();

	test_poll(0 == child_pid);

	return 0;
}

void test_poll(bool is_child)
{
	struct pollfd  pollfd = { .fd = fd, .events = (POLLIN | POLLOUT) };

	int ret = poll(&pollfd, 1, 1);
	const short POLL_BITS = (POLLERR | POLLIN | POLLOUT);

	if (0 > ret) {
		char buf[64];
		sprintf(buf, "%s fails poll: %i", (is_child) ? "Child" : "Parent", errno);
		perror(buf);
	} else {
		fprintf(stderr, "%s sees %i file descriptors ready.\n",
			(is_child) ? "Child" : "Parent", ret);
	}

	if (is_child) {
		if (ret < 0)
			fprintf(stderr, "Child fails poll() (SUCCESS is desired).\n");
		else if (ret == 0)
			fprintf(stderr, "Child no fd on poll() (1 is desired).\n");
		else if ( (pollfd.revents & POLL_BITS) == POLL_BITS)
			fprintf(stderr, "Child poll() revents bits as expected.\n");
		else
			fprintf(stderr, "Child poll() revent bits = 0x%x, expected 0x%x\n",
				pollfd.revents & POLL_BITS, POLL_BITS);
	} else {
		if (0 < ret)
			fprintf(stderr, "Parent fails poll().  (SUCCESS is desired).\n");
		else if (0 == ret)
			fprintf(stderr, "Parent success on poll() as expected.\n");
		else
			fprintf(stderr, "Parent poll() fd > 0 (EXPECTED 0).\n");
	}
}
