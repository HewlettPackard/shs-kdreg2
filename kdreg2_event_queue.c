/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2012-2019 Cray(R)
 * Copyright (C) 2020-2023 Hewlett Packard Enterprise Development LP
 *
 * KDREG2 event queue implementation.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "LICENSE" in the main directory for more details.
 *
 * Derived in part from dreg.c by Pete Wyckoff.
 * Copyright (C) 2004-5 Pete Wyckoff <pw@osc.edu>
 * Distributed under the GNU Public License Version 2 (See LICENSE)
 */

#include "kdreg2_priv.h"

#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

int kdreg2_event_queue_init(struct kdreg2_event_queue *event_queue,
			    const size_t num_entities)
{
	size_t bytes;

	KDREG2_DEBUG(KDREG2_DEBUG_INIT, 1,
		     "Creating event queue %zu entities",
		     num_entities);

	event_queue->max_events    = num_entities;
	event_queue->num_pending   = 0;
	event_queue->cons          = 0;
	event_queue->prod          = 0;
	event_queue->overflow      = false;

	if (!num_entities) {
		event_queue->pending = NULL;
		goto out;
	}

	/*
	 * Allocate enough space that we can store pending notifications
	 * for all the regions that we track.
	 */

	bytes = num_entities * sizeof(*event_queue->pending);

	KDREG2_DEBUG(KDREG2_DEBUG_ALL, 1,
		     "Allocating pending buffer %zu bytes", bytes);

	event_queue->pending = vmalloc(bytes);

	if (!event_queue->pending)
		/* checkpatch.sh requires no error message here
		 * pr_warn("Unable to allocate %zu bytes for pending buffer",
		 * bytes);
		 */
		return -ENOMEM;
out:
	if (num_entities > 0)
		KDREG2_DEBUG(KDREG2_DEBUG_INIT, 1,
			     "event_queue created for %zu entities",
			     num_entities);

	return 0;
}

void kdreg2_event_queue_destroy(struct kdreg2_event_queue *event_queue)
{
	size_t old_size = event_queue->max_events;

	KDREG2_DEBUG(KDREG2_DEBUG_INIT, 1,
		     "Destroying event queue");

	if (event_queue->pending) {
		vfree(event_queue->pending);
		event_queue->pending = NULL;
	}

	event_queue->max_events    = 0;
	event_queue->num_pending   = 0;
	event_queue->cons          = 0;
	event_queue->prod          = 0;
	event_queue->overflow      = false;

	if (old_size > 0)
		KDREG2_DEBUG(KDREG2_DEBUG_INIT, 1,
			     "event_queue destroyed");
}

int kdreg2_event_queue_resize(struct kdreg2_context *context,
			      const size_t num_entities)
{
	struct kdreg2_event_queue *event_queue = &context->event_queue;

	kdreg2_event_queue_destroy(event_queue);

	return kdreg2_event_queue_init(event_queue, num_entities);
}

static ssize_t kdreg2_copy_to_user(char __user *buf,
				   const void *from,
				   size_t n)
{
	const char *src = (const char *) from;
	size_t bytes_copied, bytes_not_copied;

	while (n > 0) {

		KDREG2_DEBUG(KDREG2_DEBUG_READ, 3,
			     "Attempting to copy %zi bytes from 0x%p to 0x%p",
			     n, src, buf);

		bytes_not_copied = copy_to_user(buf, src, n);

		/* see if we copied anything */
		if (n == bytes_not_copied) {
			KDREG2_DEBUG(KDREG2_DEBUG_READ, 1,
				     "Attempted to copy %zi bytes, none copied",
				     n);
			return -EACCES;
		}

		if (!bytes_not_copied) {
			KDREG2_DEBUG(KDREG2_DEBUG_READ, 3, "All bytes copied");
			return 0;
		}

		bytes_copied = n - bytes_not_copied;

		KDREG2_DEBUG(KDREG2_DEBUG_READ, 3,
			     "Attempted to copy %zi bytes, only copied %zi",
			     n, bytes_copied);

		buf += bytes_copied;
		src += bytes_copied;
		n    = bytes_not_copied;
	}

	return n;

}

ssize_t kdreg2_event_queue_read(struct kdreg2_context *context,
				char __user *buf,
				size_t len,
				bool non_blocking)
{
	wait_queue_head_t *wait_queue     = &context->wait_queues.read_queue;
	struct kdreg2_event_queue *event_queue = &context->event_queue;
	const size_t orig_prod            = event_queue->prod;
	const size_t orig_cons            = event_queue->cons;
	const size_t orig_num_pending     = event_queue->num_pending;
	size_t  num_events                = 0;
	ssize_t bytes_copied              = 0;
	size_t event_slots;
	size_t bytes_to_copy;
	int ret;
	DEFINE_WAIT(wait);

	KDREG2_DEBUG(KDREG2_DEBUG_READ, 1, "Read initiating");

	event_slots = len / sizeof(*event_queue->pending);

	if (event_slots < 1)
		return -EINVAL;

	if (event_queue->overflow) {

		/* Return no-space.  This can only happen if the
		 * user is not servicing the event queue and
		 * there are too many events pending.
		 *
		 * We allocate the same number of events as there
		 * are slots for monitoring regions.  But if the user
		 * continues to monitor more regions as pending events
		 * are generated (without clearing them by reading) the
		 * 'pending' queue will eventually overflow.
		 *
		 * There are 2 ways to clear this condition:
		 * 1) close and reopen the file descriptor
		 * 2) use the KDREG2_IOCTL_FLUSH to discard all pending
		 *    events
		 */

		return -ENOSPC;
	}

again:

	/* This loop puts entries from the circular buffer 'pending' directly
	 * into the caller's buffer.  Since the pending queue is circular,
	 * we can copy all the pending requests out in 2 copy operations.
	 */

	while ((event_queue->num_pending > 0) && (event_slots > 0)) {

		size_t num_avail = (event_queue->cons < event_queue->prod) ?
			event_queue->prod - event_queue->cons :
			event_queue->max_events - event_queue->cons;

		size_t num_copy  = (event_slots >= num_avail) ?
			num_avail : event_slots;

		bytes_to_copy = num_copy * sizeof(*event_queue->pending);

		KDREG2_DEBUG(KDREG2_DEBUG_READ, 3,
			     "Attempting to copy %zi bytes to buffer",
			     bytes_to_copy);

		/* copy from 'pending' into the caller's buf */

		ret = kdreg2_copy_to_user(buf,
					  event_queue->pending + event_queue->cons,
					  bytes_to_copy);

		if (ret < 0)
			goto restore_out;

		if (KDREG2_DEBUG_ON(KDREG2_DEBUG_READ, 3)) {
			size_t i;
			struct kdreg2_event *pending;

			pending = event_queue->pending + event_queue->cons;
			for (i = 0; i < num_copy; i++, pending++) {
				KDREG2_DEBUG_PRINT("Unmap event: addr 0x%px, "
						   "len %zi, cookie %llu",
						   pending->u.mapping_change.addr,
						   pending->u.mapping_change.len,
						   pending->u.mapping_change.cookie);
			}
		}

		/* advance our pointers to account for the entries removed
		 * from the pending queue.
		 */

		buf         += bytes_to_copy;
		num_events  += num_copy;
		event_slots -= num_copy;

		event_queue->num_pending -= num_copy;
		event_queue->cons        += num_copy;
		if (event_queue->cons >= event_queue->max_events)
			event_queue->cons = 0;

	}

	if (num_events > 0)
		goto out;

	/* If we get here we don't have any events yet.
	 * 1) if we are non-blocking, return -EAGAIN.
	 * 2) if we are blocking, block and try again.
	 */

	if (non_blocking) {
		KDREG2_DEBUG(KDREG2_DEBUG_READ, 1,
			     "Non-blocking read returns with no data.");
		ret = -EAGAIN;
		goto restore_out;
	}

	/* Blocking read */

	while (1) {
		KDREG2_DEBUG(KDREG2_DEBUG_READ, 1,
			     "Blocking read waiting for events.");

		prepare_to_wait(wait_queue, &wait, TASK_INTERRUPTIBLE);

		if (event_queue->num_pending > 0) {
			KDREG2_DEBUG(KDREG2_DEBUG_READ, 1,
				     "Unblocking - events have arrived.");
			finish_wait(wait_queue, &wait);
			goto again;
		}

		/* we got interrupted */

		if (!signal_pending(current)) {
			KDREG2_DEBUG(KDREG2_DEBUG_READ, 1,
				     "Interrupted while blocking.");

			kdreg2_context_unlock(context);
			schedule();
			kdreg2_context_lock(context);

			continue;
		}
		/* If we don't get any events and subsequently exit
		 * return -ERESTARTSYS.  (This is admittedly magic).
		 */
		ret = -ERESTARTSYS;
		finish_wait(wait_queue, &wait);
		goto restore_out;
	}

out:

	/* Emit an info message if we read from a full queue and reduce it
	 * to non-full, thus avoiding an overflow.
	 */

	if (unlikely((orig_num_pending >= event_queue->max_events) &&
		     (event_queue->num_pending < event_queue->max_events))) {
		pr_info("Notification queue reduced from %zi to %zi\n",
			orig_num_pending, event_queue->num_pending);
	}

	bytes_copied = num_events * sizeof(*event_queue->pending);

	kdreg2_status_set_pending_events(&context->status,
					 event_queue->num_pending);

	KDREG2_DEBUG(KDREG2_DEBUG_READ, 1,
		     "Read returns with %zi events, %zu bytes",
		     num_events, bytes_copied);

	return bytes_copied;

restore_out:

	event_queue->cons        = orig_cons;
	event_queue->prod        = orig_prod;
	event_queue->num_pending = orig_num_pending;

	KDREG2_DEBUG(KDREG2_DEBUG_READ, 1,
		     "Read returns with error: %i", ret);

	return ret;
}

int kdreg2_event_queue_insert(struct kdreg2_context *context,
			      struct kdreg2_event *event)
{
	struct kdreg2_event_queue  *event_queue = &context->event_queue;

	if (unlikely(event_queue->num_pending >= event_queue->max_events)) {
		pr_warn("Notification queue overflow, discarding event for cookie %llu\n",
			event->u.mapping_change.cookie);
		event_queue->overflow = true;
		return -ENOSPC;
	}

	event_queue->pending[event_queue->prod++] = *event;
	event_queue->num_pending++;

	if (event_queue->prod == event_queue->max_events)
		event_queue->prod = 0;

	if (unlikely(event_queue->num_pending >= event_queue->max_events)) {
		pr_notice("Notification queue at max: %zi queued\n",
			  event_queue->max_events);
	}

	kdreg2_status_set_pending_events(&context->status,
					 event_queue->num_pending);
	kdreg2_status_inc_total_events(&context->status);

	KDREG2_DEBUG(KDREG2_DEBUG_MMUNOT, 2,
		     "Inserted notification into pending buffer cookie %llu.",
		     event->u.mapping_change.cookie);

	kdreg2_context_wakeup(context);

	return 0;
}

int kdreg2_event_queue_flush(struct kdreg2_context *context)
{
	struct kdreg2_event_queue *event_queue = &context->event_queue;

	event_queue->num_pending = 0;
	event_queue->cons        = 0;
	event_queue->prod        = 0;
	event_queue->overflow    = false;

	kdreg2_status_set_pending_events(&context->status, 0);

	KDREG2_DEBUG(KDREG2_DEBUG_IOCTL, 2, "Event queue flushed.");

	return 0;
}
