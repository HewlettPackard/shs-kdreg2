/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2012-2019 Cray(R)
 * Copyright (C) 2020-2023 Hewlett Packard Enterprise Development LP
 *
 * KDREG2 status data operations.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "LICENSE" in the main directory for more details.
 *
 * Derived in part from dreg.c by Pete Wyckoff.
 * Copyright (C) 2004-5 Pete Wyckoff <pw@osc.edu>
 * Distributed under the GNU Public License Version 2 (See LICENSE)
 */

#include "kdreg2_priv.h"

/*
 * Allocate and initialize config member.
 */

int kdreg2_status_init(struct kdreg2_status *status,
		       const size_t num_entities)
{
	int ret;

	KDREG2_DEBUG(KDREG2_DEBUG_INIT, 1, "Initializing status data");

	/* create and map an area for the status_data */

	kdreg2_init_vm_map(&status->vm_map);

	ret = kdreg2_create_vm_map(&status->vm_map,
				   sizeof(*status->user_addr),
				   "status_data");

	if (ret) {
		pr_warn("Failure: %i", ret);
		return ret;
	}

	/* Save pointers as struct types instead of void * */

	status->user_addr = status->vm_map.user_addr;
	status->kern_addr = status->vm_map.kernel_addr;

	status->kern_addr->version = kdreg2_global.driver_version;
	status->kern_addr->max_regions = num_entities;
	kdreg2_set_counter(&status->kern_addr->pending_events, 0);
	kdreg2_set_counter(&status->kern_addr->total_events, 0);
	kdreg2_set_counter(&status->kern_addr->num_active_regions, 0);

	KDREG2_DEBUG(KDREG2_DEBUG_INIT, 2,
		     "Status data: user_addr 0x%px, kern_addr 0x%px, bytes %zi",
		     status->user_addr,
		     status->kern_addr,
		     status->vm_map.size);

	KDREG2_DEBUG(KDREG2_DEBUG_INIT, 2,
		     "Status data: version 0x%llx, max_regions %zi",
		     status->kern_addr->version,
		     status->kern_addr->max_regions);

	KDREG2_DEBUG(KDREG2_DEBUG_INIT, 1, "Success");

	return 0;
}

void kdreg2_status_destroy(struct kdreg2_status *status)
{
	kdreg2_destroy_vm_map(&status->vm_map);

	KDREG2_DEBUG(KDREG2_DEBUG_INIT, 1, "status_data destroyed");
}

void kdreg2_status_set_monitoring_state_base(struct kdreg2_status *status,
	     struct kdreg2_monitoring_state __user *monitoring_state_base)
{
	status->kern_addr->monitoring_state_base = monitoring_state_base;

	KDREG2_DEBUG(KDREG2_DEBUG_INIT, 3,
		     "Status data: monitoring_state 0x%px",
		     status->kern_addr->monitoring_state_base);
}

void kdreg2_status_set_max_regions(struct kdreg2_status *status,
				   size_t max_regions)
{
	status->kern_addr->max_regions = max_regions;

	KDREG2_DEBUG(KDREG2_DEBUG_INIT, 3,
		     "Status data: max_regions %zi",
		     status->kern_addr->max_regions);
}
