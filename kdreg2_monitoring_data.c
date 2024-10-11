/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2012-2019 Cray(R)
 * Copyright (C) 2020-2023 Hewlett Packard Enterprise Development LP
 *
 * KDREG2 monitoring_data and monitoring_state implementation.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "LICENSE" in the main directory for more details.
 *
 * Derived in part from dreg.c by Pete Wyckoff.
 * Copyright (C) 2004-5 Pete Wyckoff <pw@osc.edu>
 * Distributed under the GNU Public License Version 2 (See LICENSE)
 */

#include "kdreg2_priv.h"

int kdreg2_monitoring_data_init(struct kdreg2_monitoring_data *monitoring_data,
				const size_t num_entities)
{
	struct kdreg2_monitoring_state *ms;
	size_t i;
	int ret;

	KDREG2_DEBUG(KDREG2_DEBUG_INIT, 1,
		     "Creating monitor state %zu entities",
		     num_entities);

	/* create and map an area for the monitoring_state entities */

	kdreg2_init_vm_map(&monitoring_data->vm_map);

	monitoring_data->num_monitoring_state        = num_entities;
	monitoring_data->next_monitoring_state_index = 0;

	ret = kdreg2_create_vm_map(&monitoring_data->vm_map,
				   sizeof(*monitoring_data->user_addr) *
				   monitoring_data->num_monitoring_state,
				   "monitoring_state");

	if (ret) {
		pr_warn("Failure: %i", ret);
		return ret;
	}

	monitoring_data->user_addr = monitoring_data->vm_map.user_addr;
	monitoring_data->kern_addr = monitoring_data->vm_map.kernel_addr;

	KDREG2_DEBUG(KDREG2_DEBUG_INIT, 2,
		     "Monitor state: user_addr 0x%px, kern_addr 0x%px, bytes %zi",
		     monitoring_data->user_addr,
		     monitoring_data->kern_addr,
		     monitoring_data->vm_map.size);

	KDREG2_DEBUG(KDREG2_DEBUG_INIT, 2,
		     "Monitor state: num_monitoring_state %lu",
		     monitoring_data->num_monitoring_state);

	if (!num_entities)
		return 0;

	/* Put all the monitoring_data entries on the free list.
	 * Use the data field of the state as an index to the next entry
	 * on the free list.
	 */

	for (i = 0; i < num_entities-1; i++) {
		ms = monitoring_data->kern_addr + i;
		kdreg2_set_monitoring_state(ms, false, i+1);
	}

	ms = monitoring_data->kern_addr + num_entities - 1;
	kdreg2_set_monitoring_state(ms, false, BAD_INDEX);

	monitoring_data->free_list_head_index = 0;
	monitoring_data->next_generation = 0;

	KDREG2_DEBUG(KDREG2_DEBUG_INIT, 1,
		     "monitoring_data created for %zu entities", num_entities);

	return 0;
}

void kdreg2_monitoring_data_destroy(struct kdreg2_monitoring_data *monitoring_data)
{
	size_t old_size = monitoring_data->num_monitoring_state;

	kdreg2_destroy_vm_map(&monitoring_data->vm_map);

	monitoring_data->user_addr            = (void __user *) NULL;
	monitoring_data->kern_addr            = NULL;
	monitoring_data->num_monitoring_state = 0;
	monitoring_data->next_monitoring_state_index = 0;
	monitoring_data->free_list_head_index = -1;

	if (old_size > 0)
		KDREG2_DEBUG(KDREG2_DEBUG_INIT, 1, "monitoring_data destroyed");
}

int kdreg2_monitoring_data_resize(struct kdreg2_context *context,
				  const size_t num_entities)
{
	struct kdreg2_monitoring_data *monitoring_data = &context->monitoring_data;

	kdreg2_monitoring_data_destroy(monitoring_data);

	return kdreg2_monitoring_data_init(monitoring_data, num_entities);
}

ssize_t find_free_monitoring_state_index(struct kdreg2_context *context)
{
	struct kdreg2_monitoring_data  *monitoring_data = &context->monitoring_data;
	struct kdreg2_monitoring_state *ms, state;

	ssize_t index = monitoring_data->free_list_head_index;

	if (index < 0)
		return index;

	if (index == BAD_INDEX)
		return -1;

	ms = monitoring_data->kern_addr + index;

	/* this one should be free.  See if in_use bit is set. */

	state.u.raw = kdreg2_get_monitoring_state(ms);

	if (state.u.bits.in_use)
		return -2;

	monitoring_data->free_list_head_index = state.u.bits.data;
	kdreg2_set_monitoring_state(ms, true, monitoring_data->next_generation);
	monitoring_data->next_generation++;

	return index;
}
