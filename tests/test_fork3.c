/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2023 Hewlett Packard Enterprise Development LP
 */

#include "kdreg2.h"

#include <sys/mman.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* This test calls fork(), creating 2 processes each with a
 * reference to the open kdreg2 instance.
 *
 * Each process exits, but one sleeps for a short time first.
 *
 * NETCASSINI-5620 outlines a problem where if the forked child
 * exited and attempted to cleanup the kdreg2 instance a kernel
 * hang resulted.
 *
 * Running this test with fixed code does not result in the hang,
 * no matter which process exits first.
 */

#define NUM_REGIONS (1 * 1024)
#define SLEEP_SECONDS 2

int main(int argc, const char *argv[])
{
	int fd = open(KDREG2_DEVICE_NAME, O_NONBLOCK | O_RDWR);

	if (fd < 0) {
		char buf[512];
		sprintf(buf, "Unable to open %s", KDREG2_DEVICE_NAME);
		perror(buf);
		exit(errno);
	}

	struct kdreg2_config_data  config_data = {
		.max_regions = NUM_REGIONS,
	};

	int ret = ioctl(fd, KDREG2_IOCTL_CONFIG_DATA, &config_data);

	if (ret) {
		char buf[64];
		sprintf(buf, "Config ioctl fails: %i", ret);
		perror(buf);
		exit(ret);
	}

	pid_t child_pid = fork();

	bool  reversed = (argc > 1);
	bool  is_child = (child_pid == 0);

	if (is_child)
		return (reversed) ? sleep(SLEEP_SECONDS) : 0;
	else
		return (reversed) ? 0 : sleep(SLEEP_SECONDS);
}
