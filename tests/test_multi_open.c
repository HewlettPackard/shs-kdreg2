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
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define NFILES 3
#define COUNT(_x) (sizeof(_x)/sizeof(_x[0]))

__attribute__((format (printf, 2, 3), noreturn))
void die(int code, const char *fmt, ...);

int main()
{
	int fd[NFILES];

	for(int i = 0; i < COUNT(fd); i++) {

		fd[i] = open(KDREG2_DEVICE_NAME, O_RDWR);
		if (fd[i] < 0) {
			die(errno, "Open failure %i", i);
		}
	}

	for(int i = 0; i < COUNT(fd); i++) {

		int ret = close(fd[i]);
		if (ret) {
			die(errno, "Close failure %i", i);
		}
	}

	printf("Test passes.\n");

	return 0;
}

void die(int code, const char *fmt, ...)
{
	char    buf[128];
	va_list args;

	va_start(args, fmt);

	vsnprintf(buf, sizeof(buf), fmt, args);

	va_end(args);

	perror(buf);
	exit(code);
}
