/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2012-2019 Cray(R)
 * Copyright (C) 2020-2023 Hewlett Packard Enterprise Development LP
 *
 * KDREG2 mmu_notifier related operations and callback function definitions.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "LICENSE" in the this directory  for more details.
 *
 * Derived in part from dreg.c by Pete Wyckoff.
 * Copyright (C) 2004-5 Pete Wyckoff <pw@osc.edu>
 * Distributed under the GNU Public License Version 2 (See LICENSE)
 */

#include "kdreg2_priv.h"

/*
 * MMU notifier callback for invalidating a range of pages. kdreg2
 * only uses the invalidate_range_end component of the notifier
 * ops struct.
 */

#if KDREG2_MMU_NOTIFIER_VERSION == 2
static void
kdreg2_invalidate_range_end(struct mmu_notifier *notifier,
			    const struct mmu_notifier_range *range)
{
	struct kdreg2_context *context =
		container_of(notifier,
			     struct kdreg2_context,
			     mmu_notifier_data.mmu_notifier);

	if (!context) {
		KDREG2_WARN(KDREG2_LOG_NORMAL, "mmu_notifier callback given null argument.");
		return;
	}

	if (kdreg2_detect_fork(context))
		return;

	KDREG2_DEBUG(KDREG2_DEBUG_MMUNOT, 3, "start 0x%lx, end 0x%lx",
		     range->start, range->end);

	kdreg2_destroy_range_trylock(context, range->start, range->end);
}

#elif KDREG2_MMU_NOTIFIER_VERSION == 1

static void
kdreg2_invalidate_range_end(struct mmu_notifier *notifier,
			    struct mm_struct *mm,
			    unsigned long start,
			    unsigned long end)
{
	struct kdreg2_context *context =
		container_of(notifier,
			     struct kdreg2_context,
			     mmu_notifier_data.mmu_notifier);

	if (!context) {
		KDREG2_WARN(KDREG2_LOG_NORMAL, "mmu_notifier callback given null argument.");
		return;
	}

	if (kdreg2_detect_fork(context))
		return;

	KDREG2_DEBUG(KDREG2_DEBUG_MMUNOT, 3, "start 0x%lx, end 0x%lx",
		     start, end);

	kdreg2_destroy_range_trylock(context, start, end);
}
#else
#error "KDREG2_MMU_NOTIFIER_VERSION unknown/undefined."
#endif

static const struct mmu_notifier_ops kdreg2_mmuops = {
	.invalidate_range_end   = kdreg2_invalidate_range_end,
};

int
kdreg2_mmu_notifier_data_init(struct kdreg2_mmu_notifier_data *notifier_data)
{
	notifier_data->mmu_notifier.ops = &kdreg2_mmuops;
	notifier_data->registered       = false;

	KDREG2_DEBUG(KDREG2_DEBUG_INIT, 1, "mmu_notifier_data initialized");

	return 0;
}

void
kdreg2_mmu_notifier_data_destroy(struct kdreg2_mmu_notifier_data *notifier_data)
{
	if (notifier_data->registered)
		KDREG2_WARN(KDREG2_LOG_NORMAL, "mmu_notifier still registered");

	KDREG2_DEBUG(KDREG2_DEBUG_INIT, 1, "mmu_notifier_data destroyed");
}

int kdreg2_mmu_notifier_enable(struct kdreg2_context *context)
{
	struct kdreg2_mmu_notifier_data *notifier_data = &context->mmu_notifier_data;
	int ret;

	if (notifier_data->registered)
		return 0;

	if (kdreg2_detect_fork(context))
		return -EIO;

	ret = mmu_notifier_register(&notifier_data->mmu_notifier,
				    context->mm);

	if (!ret) {
		notifier_data->registered = true;
		KDREG2_DEBUG(KDREG2_DEBUG_INIT, 1, "mmu_notifier enabled");
	} else {
		KDREG2_WARN(KDREG2_LOG_NORMAL, "mmu_notifier enable failed: %i", ret);
	}

	return ret;
}

int kdreg2_mmu_notifier_disable(struct kdreg2_context *context)
{
	struct kdreg2_mmu_notifier_data *notifier_data = &context->mmu_notifier_data;

	if (!notifier_data->registered)
		return 0;

	mmu_notifier_unregister(&notifier_data->mmu_notifier, context->mm);
	notifier_data->registered = false;

	KDREG2_DEBUG(KDREG2_DEBUG_INIT, 1, "mmu_notifier disabled");

	return 0;
}
