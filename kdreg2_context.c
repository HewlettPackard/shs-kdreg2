/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2012-2019 Cray(R)
 * Copyright (C) 2020-2023 Hewlett Packard Enterprise Development LP
 *
 * KDREG2 context implementation.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "LICENSE" in the main directory for more details.
 *
 * Derived in part from dreg.c by Pete Wyckoff.
 * Copyright (C) 2004-5 Pete Wyckoff <pw@osc.edu>
 * Distributed under the GNU Public License Version 2 (See LICENSE)
 */

#include "kdreg2_priv.h"

int kdreg2_context_init(struct kdreg2_context *context,
			const size_t num_entities)
{
	int ret;

	KDREG2_DEBUG(KDREG2_DEBUG_INIT, 1, "Initializing context");

	mutex_init(&context->lock);

	/* Initialize the region database */

	ret = kdreg2_region_db_init(&context->region_db, num_entities);
	if (ret)
		goto err;

	/* initialize the event queue areas */

	ret = kdreg2_event_queue_init(&context->event_queue,
				      num_entities);

	if (ret)
		goto err_with_region_db;

	/* create, map and initialize an area for the status_data */

	ret = kdreg2_status_init(&context->status, num_entities);

	if (ret)
		goto err_with_event_queue;

	/* create, map and initialize an area for the monitoring_state */

	ret = kdreg2_monitoring_data_init(&context->monitoring_data,
					  num_entities);

	if (ret)
		goto err_with_status_data;

	/* Copy the info about the monitoring_data into the status_data.
	 * This enables the kdreg2_mapping_changed() function to work.
	 */

	kdreg2_status_set_monitoring_state_base(&context->status,
				context->monitoring_data.user_addr);

	/* Initialize the kernel notifier struct */

	ret = kdreg2_mmu_notifier_data_init(&context->mmu_notifier_data);
	if (ret != 0)
		goto err_with_monitoring_data;

	/* Initialize the read and poll wait queues */

	init_waitqueue_head(&context->wait_queues.read_queue);
	init_waitqueue_head(&context->wait_queues.poll_queue);

	context->warn_on_fork_detected = true;

	KDREG2_DEBUG(KDREG2_DEBUG_INIT, 1, "Success");

	return 0;

err_with_monitoring_data:

	kdreg2_monitoring_data_destroy(&context->monitoring_data);

err_with_status_data:

	kdreg2_status_destroy(&context->status);

err_with_event_queue:

	kdreg2_event_queue_destroy(&context->event_queue);

err_with_region_db:

	kdreg2_region_db_destroy(&context->region_db);

err:

	KDREG2_WARN(KDREG2_LOG_NORMAL, "Failure: %i", ret);
	return ret;
}

void kdreg2_context_destroy(struct kdreg2_context *context)
{
	/*
	 * Stop the mmu_notifier from calling us.
	 */

	kdreg2_context_lock(context);

	kdreg2_mmu_notifier_disable(context);
	kdreg2_mmu_notifier_data_destroy(&context->mmu_notifier_data);

	/*
	 * now free any regions associated with the context
	 */

	kdreg2_unmonitor_all(context);

	/* Destroy our region and event queue data */

	kdreg2_region_db_destroy(&context->region_db);
	kdreg2_event_queue_destroy(&context->event_queue);

	/*
	 * Free monitoring data.  Note: the monitored regions have
	 * references to the monitored state data, so they must be destroyed
	 * first.
	 */

	kdreg2_monitoring_data_destroy(&context->monitoring_data);
	kdreg2_status_destroy(&context->status);

	kdreg2_context_unlock(context);
}

int kdreg2_context_resize(struct kdreg2_context *context,
			  const size_t num_entities)
{
	struct kdreg2_region_db    *region_db   = &context->region_db;
	struct kdreg2_event_queue  *event_queue = &context->event_queue;

	static int (*resizers[]) (struct kdreg2_context *, size_t) = {
		kdreg2_monitoring_data_resize,
		kdreg2_region_db_resize,
		kdreg2_event_queue_resize,
	};
	int ret;
	size_t i, bad_index;

	KDREG2_INFO(KDREG2_LOG_RATELIMITED, "resize to %zu entities", num_entities);

	/* The free list uses the data field in the monitoring_data
	 * as an index.  So we can only handle as many entities
	 * as there is index range.
	 */

	if (num_entities >= BAD_INDEX)
		return -ENOSPC;

	kdreg2_context_lock(context);

	if (context->region_db.max_regions == num_entities) {
		ret = 0;
		goto out_unlock;
	}

	if ((kdreg2_region_db_get_num_regions(region_db) > 0) ||
	    (kdreg2_event_queue_get_num_pending(event_queue) > 0)) {
		ret = -EBUSY;
		goto error_unlock;
	}

	/* Resizing triggers mmu notifications.  Disable them. */

	kdreg2_mmu_notifier_disable(context);

	for (i = 0; i < ARRAY_SIZE(resizers); i++) {
		ret = (*resizers[i])(context, num_entities);
		if (!ret)
			continue;
		bad_index = i;
		goto error_rollback;
	}

	kdreg2_status_set_max_regions(&context->status, num_entities);
	kdreg2_status_set_monitoring_state_base(&context->status,
				context->monitoring_data.user_addr);

	/* Re-enable the mmu notifier only if we can do something with
	 * the notifications.
	 */

	if (num_entities > 0)
		kdreg2_mmu_notifier_enable(context);

out_unlock:

	kdreg2_context_unlock(context);

	KDREG2_DEBUG(KDREG2_DEBUG_INIT, 2,
		     "Resize success %zu entities.", num_entities);

	return 0;

error_rollback:

	for (i = 0; i < ARRAY_SIZE(resizers); i++) {
		if (bad_index == i)
			continue;
		(*resizers[i])(context, 0);
	}

	kdreg2_status_set_max_regions(&context->status, 0);
	kdreg2_status_set_monitoring_state_base(&context->status, NULL);

error_unlock:

	kdreg2_context_unlock(context);

	KDREG2_WARN(KDREG2_LOG_NORMAL, "Resize fails for %zu entities: %i.",
	            num_entities, ret);
	return ret;
}

void kdreg2_context_wakeup(struct kdreg2_context *context)
{
	wake_up_interruptible(&context->wait_queues.read_queue);
	wake_up_interruptible(&context->wait_queues.poll_queue);
}
