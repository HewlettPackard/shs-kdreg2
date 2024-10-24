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

int test_free_list(const struct kdreg2_config_data *config);

int main()
{
	int fd = open(KDREG2_DEVICE_NAME, O_RDWR);
	if (fd < 0) {
		perror("Open failure");
		exit(errno);
	}

	size_t num_entities = 8;
	for(int i = 0; i < 18; i++, num_entities <<= 1) {
		struct kdreg2_config_data config = { .max_regions = num_entities };
		fprintf(stderr, "Attempting reconfiguration %zu entities.\n", num_entities);
		int ret = ioctl(fd, KDREG2_IOCTL_CONFIG_DATA, &config);
		fprintf(stderr, "max_regions = %zu.\n", config.status_data->max_regions);
		if (ret) {
			perror("Config failure");
			exit(1);
		}
		ret = test_free_list(&config);
		if (ret)
			exit(2);
	}

	int ret = close(fd);
	if (ret) {
		perror("Close failure");
		exit(errno);
	}

	printf("Test passes.\n");

	return 0;
}

int test_free_list(const struct kdreg2_config_data *config)
{
	const struct kdreg2_monitoring_state *ms;

	ms = config->status_data->monitoring_state_base;

	for(size_t i = 0; i < config->max_regions-1; i++, ms++) {

		uint32_t gen = ms->u.state.val;
		uint32_t next = gen >> 1;

		if ((gen & 0x01) ||
		    (next != i+1)) {
			fprintf(stderr, "Error: generation entry %zu invalid: %ui\n", i, gen);
			return -4;
		}
	}

	uint32_t gen = ms->u.state.val;
	uint32_t next = gen >> 1;
	uint32_t bad_index = (((uint32_t) -1) << 1) >> 1;

	if ((gen & 0x01) || (next != bad_index)) {
		fprintf(stderr, "Error: last generation entry invalid: %ui\n", gen);
		return -5;
	}

	return 0;
}
