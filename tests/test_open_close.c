/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2023 Hewlett Packard Enterprise Development LP
 */

#include "kdreg2.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main()
{
	int fd = open(KDREG2_DEVICE_NAME, O_RDWR);
	if (fd < 0) {
		perror("Open failure");
		exit(errno);
	}

	int ret = close(fd);
	if (ret) {
		perror("Close failure");
		exit(errno);
	}

	printf("Test passes.\n");

	return 0;
}
