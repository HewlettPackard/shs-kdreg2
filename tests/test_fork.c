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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int fd = -1;
pid_t child_pid = 0;
void test_ioctl(bool is_child);

int main()
{
	fd = open(KDREG2_DEVICE_NAME, O_NONBLOCK | O_RDWR);

	if (fd < 0) {
		char buf[512];
		sprintf(buf, "Unable to open %s", KDREG2_DEVICE_NAME);
		perror(buf);
		exit(errno);
	}

	child_pid = fork();

	test_ioctl(0 == child_pid);

	return 0;
}

void test_ioctl(bool is_child)
{
	struct kdreg2_config_data  config_data = {
		.max_regions = 5,
	};

	int ret = ioctl(fd, KDREG2_IOCTL_CONFIG_DATA, &config_data);

	if (ret) {
		char buf[64];
		sprintf(buf, "%s fails ioctl: %i", (is_child) ? "Child" : "Parent", errno);
		perror(buf);
	}


	if (is_child) {
		if (ret)
			fprintf(stderr, "Child fails ioctl() as expected.\n");
		else
			fprintf(stderr, "Child success on ioctl() (FAILURE is desired).\n");
	} else {
		if (ret)
			fprintf(stderr, "Parent fails ioctl().  (SUCCESS is desired).\n");
		else
			fprintf(stderr, "Parent success on ioctl() as expected.\n");
	}
}
