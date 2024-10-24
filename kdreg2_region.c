/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2012-2019 Cray(R)
 * Copyright (C) 2020-2023 Hewlett Packard Enterprise Development LP
 *
 * KDREG2 functions pertaining to tracking regions.
 *
 * NOTE: there are 2 implementations:
 *   1) reference implementation using a doubly-linked list
 *   2) production implementation using red-black trees.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "LICENSE" in this directory for more details.
 *
 * Derived in part from dreg.c by Pete Wyckoff.
 * Copyright (C) 2004-5 Pete Wyckoff <pw@osc.edu>
 * Distributed under the GNU Public License Version 2 (See LICENSE)
 */

#include "kdreg2_priv.h"

#include <linux/slab.h>

/* The slab allocator doesn't define a macro for named caches.  So define one. */
#define KDREG2_NAMED_CACHE(__name, __struct, __flags) \
	kmem_cache_create(__name, sizeof(struct __struct), \
			  __alignof__(struct __struct), __flags, NULL)


#if KDREG2_DB_MODE == KDREG2_DB_MODE_DLLIST
struct kdreg2_region_db_overlap_state {
	unsigned long         start;
	unsigned long         last;
	struct list_head      *head;
	struct list_head      *entry;
	struct list_head      *next;
};
#endif

#if KDREG2_DB_MODE == KDREG2_DB_MODE_RBTREE
struct kdreg2_region_db_overlap_state {
	unsigned long         start;
	unsigned long         last;
	struct kdreg2_region  *entry;
	struct kdreg2_region  *next;
};
#endif

static struct kdreg2_region *
kdreg2_region_allocate(struct kdreg2_region_db *region_db);

static void
kdreg2_region_free(struct kdreg2_region_db *region_db,
		   struct kdreg2_region *region);

static int
kdreg2_region_db_insert(struct kdreg2_region_db *region_db,
			struct kdreg2_region *region);

static int
kdreg2_region_db_remove(struct kdreg2_region_db *region_db,
			struct kdreg2_region *region);

static struct kdreg2_region *
kdreg2_region_db_find_by_cookie(struct kdreg2_region_db *region_db,
				kdreg2_cookie_t cookie);

static void
kdreg2_region_db_overlap_state_init(struct kdreg2_region_db *region_db,
		    struct kdreg2_region_db_overlap_state *overlap_state,
		    unsigned long start,
		    unsigned long last);

static struct kdreg2_region *
kdreg2_region_db_next_overlap(struct kdreg2_region_db_overlap_state *overlap_state);

/* Support functions */

static void notify_user(struct kdreg2_context *context,
			struct kdreg2_region *region);

static inline bool region_db_full(const struct kdreg2_region_db *region_db)
{
	return (region_db->num_regions >= region_db->max_regions);
}

static inline size_t inc_num_regions(struct kdreg2_region_db *region_db)
{
	region_db->num_regions += 1;
	return region_db->num_regions;
}

static inline size_t dec_num_regions(struct kdreg2_region_db *region_db)
{
	region_db->num_regions -= 1;
	return region_db->num_regions;
}

static int create_region_cache(struct kdreg2_region_db *region_db)
{
	char     cache_name[64];
	void     *tmp_region;

	/* Create a unique name for this memory cache */

	snprintf(cache_name, ARRAY_SIZE(cache_name), "%s_%d",
		 KDREG2_MODNAME, current->pid);

	region_db->region_cache = KDREG2_NAMED_CACHE(cache_name, kdreg2_region,
						     SLAB_ACCOUNT);

	if (region_db->region_cache) {
		KDREG2_DEBUG(KDREG2_DEBUG_INIT, 2,
			     "Created region cache %s", cache_name);
	} else {
		KDREG2_DEBUG(KDREG2_DEBUG_INIT, 1,
			     "Unable to create region cache %s", cache_name);
		return -ENOMEM;
	}

	tmp_region = kmem_cache_alloc(region_db->region_cache, GFP_KERNEL);
	KDREG2_DEBUG(KDREG2_DEBUG_INIT, 3,
		     "Region cache allocation size: %zu bytes", ksize(tmp_region));
	kmem_cache_free(region_db->region_cache, tmp_region);

	return 0;
}

static void destroy_region_cache(struct kdreg2_region_db *region_db)
{
	if (!region_db->region_cache)
		return;

	kmem_cache_destroy(region_db->region_cache);
	region_db->region_cache = NULL;
}

/* **************************************************************** */

/*
 * Register a new region for monitoring.
 */

ssize_t
kdreg2_monitor_region(struct kdreg2_context *context,
		      struct kdreg2_ioctl_monitor *monitor)
{
	struct kdreg2_region_db *region_db = &context->region_db;
	struct kdreg2_region    *region = NULL;
	ssize_t                 ret = 0;
	ssize_t                 monitoring_state_index;
	size_t                  new_location;

	KDREG2_DEBUG(KDREG2_DEBUG_REGION, 3,
		     "Add region: addr 0x%px len %zi cookie %llu",
		     monitor->addr, monitor->length, monitor->cookie);

	if (unlikely(region_db_full(region_db))) {
		if (!region_db->max_regions)
			pr_warn("Attempt to register region when max_regions 0.");
		else
			pr_warn("Region database full, rejecting request to monitor region.");
		ret = -ENOSPC;
		goto err;
	}

	/* build a new region */

	region = kdreg2_region_allocate(region_db);
	if (unlikely(!region)) {
		pr_warn("Unable to allocate region data");
		ret = -ENOMEM;
		goto err;
	}

	/* Remember the monitoring_state_index in case it gets overwritten
	 * in kdreg2_region_db_insert().  This can happen if the
	 * region is an exact duplicate (addr, length, cookie) of
	 * a previous monitoring request.
	 */

	monitoring_state_index = find_free_monitoring_state_index(context);

	if (unlikely(monitoring_state_index < 0)) {
		ret = -ENOSPC;
		goto err_with_region;
	}

	region->addr                   = (unsigned long) monitor->addr;
	region->last                   = region->addr + monitor->length - 1;
	region->len                    = monitor->length;
	region->cookie                 = monitor->cookie;
	region->monitoring_state_index = monitoring_state_index;

	ret = kdreg2_region_db_insert(region_db, region);

	switch (ret) {
	case 0:
		inc_num_regions(region_db);
		break;
	case -EEXIST:
		KDREG2_DEBUG(KDREG2_DEBUG_REGION, 2,
			     "Duplicate region detected");
		/* Exact entry already exists.  Copy the monitoring_params to the
		 * caller and delete the new region.
		 */
		new_location = region->monitoring_state_index;
		monitor->monitoring_params.location = new_location;
		monitor->monitoring_params.generation =
			   kdreg2_monitoring_state_get_state(context, new_location);
		KDREG2_DEBUG(KDREG2_DEBUG_REGION, 3,
			     "Attempt to monitor duplicate region 0x%px detected, "
			     "location %li, generation %u",
			     region, monitor->monitoring_params.location,
			     monitor->monitoring_params.generation);
		kdreg2_monitoring_state_free(context, monitoring_state_index);
		kdreg2_region_free(region_db, region);
		return 0;
	default:
		goto err_with_monitoring_state;
	}

	/* Tell the user about the new region */

	monitor->monitoring_params.location = region->monitoring_state_index;
	monitor->monitoring_params.generation =
		   kdreg2_monitoring_state_get_state(context,
						     region->monitoring_state_index);

	KDREG2_DEBUG(KDREG2_DEBUG_REGION, 3,
		     "Region 0x%px added, monitoring_location %li, generation %u",
		     region, monitor->monitoring_params.location,
		     monitor->monitoring_params.generation);

	return 0;               /* success */

err_with_monitoring_state:

	kdreg2_monitoring_state_free(context, monitoring_state_index);

err_with_region:

	kdreg2_region_free(region_db, region);

err:

	memset(&monitor->monitoring_params, 0, sizeof(monitor->monitoring_params));
	monitor->monitoring_params.location = -1;

	return ret;
}

/*
 * Deregister a region, invoked when user explicitly
 * removes a region from the monitor list.
 */

ssize_t
kdreg2_unmonitor_region(struct kdreg2_context *context,
			struct kdreg2_ioctl_unmonitor *unmonitor)
{
	struct kdreg2_region_db *region_db = &context->region_db;
	struct kdreg2_region    *region;

	KDREG2_DEBUG(KDREG2_DEBUG_REGION, 3, "Remove region: cookie %llu",
		     unmonitor->cookie);

	region = kdreg2_region_db_find_by_cookie(region_db, unmonitor->cookie);

	if (!region) {
		KDREG2_DEBUG(KDREG2_DEBUG_REGION, 3,
			     "Unable to find region with cookie %llu",
			     unmonitor->cookie);
		return 0;
	}

	/* A region could be invalidated, and another region with
	 * the same cookie be registered before we get this unregister
	 * request.  To detect this, we ensure the monitoring data is
	 * the same.
	 */

	if ((region->monitoring_state_index !=
	     unmonitor->monitoring_params.location) ||
	    (unmonitor->monitoring_params.generation !=
	     kdreg2_monitoring_state_get_state(context,
					       region->monitoring_state_index))) {
		KDREG2_DEBUG(KDREG2_DEBUG_REGION, 1,
			     "Attempt to unmonitor invalid region cookie %llu "
			     "monitoring_location %lu",
			     unmonitor->cookie,
			     unmonitor->monitoring_params.location);
		return -EBADSLT;
	}

	kdreg2_region_db_remove(region_db, region);
	dec_num_regions(region_db);

	kdreg2_monitoring_state_free(context, region->monitoring_state_index);
	kdreg2_region_free(region_db, region);

	KDREG2_DEBUG(KDREG2_DEBUG_REGION, 3,
		     "Region found with cookie %llu and unmonitored location %lu",
		     unmonitor->cookie, unmonitor->monitoring_params.location);

	return 0;
}

/*
 * Removes all regions from the region_db.
 */

int
kdreg2_unmonitor_all(struct kdreg2_context *context)
{
	struct kdreg2_region_db   *region_db = &context->region_db;
	struct kdreg2_region      *region;
	struct kdreg2_region_db_overlap_state   overlap_state;
	size_t num_found = 0;

	kdreg2_region_db_overlap_state_init(region_db, &overlap_state, 0, ~0);

	while (NULL != (region = kdreg2_region_db_next_overlap(&overlap_state))) {

		num_found++;
		KDREG2_DEBUG(KDREG2_DEBUG_REGION, 3,
			     "Unmonitor region: addr 0x%lx, len %lx",
			     region->addr, region->len);

		kdreg2_region_db_remove(region_db, region);

		kdreg2_region_free(region_db, region);
	}

	if (num_found)
		KDREG2_DEBUG(KDREG2_DEBUG_IOCTL, 2,
			     "%zu regions unmonitored", num_found);
	else
		KDREG2_DEBUG(KDREG2_DEBUG_IOCTL, 2,
			     "No regions found to unmonitor");

	return 0;
}

/*
 * invalidate regions with addresses between start and end (inclusive)
 */

void
kdreg2_destroy_range(struct kdreg2_context *context,
		     unsigned long start,
		     unsigned long end)
{
	struct kdreg2_region_db *region_db = &context->region_db;
	struct kdreg2_region    *region;
	size_t                  num_found = 0;
	unsigned long           last = end - 1;
	size_t                  num_active_regions;
	struct kdreg2_region_db_overlap_state   overlap_state;

	KDREG2_DEBUG(KDREG2_DEBUG_REGION, 3,
		     "Destroy range: start 0x%lx last 0x%lx",
		     start, last);

	kdreg2_context_lock(context);

	kdreg2_region_db_overlap_state_init(region_db, &overlap_state,
					    start, last);

	while (NULL != (region = kdreg2_region_db_next_overlap(&overlap_state))) {
		num_found++;
		num_active_regions = dec_num_regions(region_db);
		kdreg2_region_db_remove(region_db, region);
		notify_user(context, region);
		kdreg2_status_set_num_active_regions(&context->status,
						     num_active_regions);
		kdreg2_monitoring_state_free(context,
					     region->monitoring_state_index);
		kdreg2_region_free(region_db, region);
	}

	kdreg2_context_unlock(context);

	KDREG2_DEBUG(KDREG2_DEBUG_REGION, 3,
		     "%zu regions found to invalidate.", num_found);
}

size_t kdreg2_region_db_get_num_regions(struct kdreg2_region_db *region_db)
{
	return region_db->num_regions;
}

size_t kdreg2_region_db_get_max_regions(struct kdreg2_region_db *region_db)
{
	return region_db->max_regions;
}

/*
 * Notify user that, according to mmu_notifier, a region
 * needs to be invalidated in user registration cache.
 */
static void
notify_user(struct kdreg2_context *context,
	    struct kdreg2_region *region)
{
	struct kdreg2_event       event;
	int ret;

	KDREG2_DEBUG(KDREG2_DEBUG_REGION, 3,
		     "Posting mapping change event addr 0x%lx, len %lu, cookie %llu",
		     region->addr, region->len, region->cookie);

	event.type                    = KDREG2_EVENT_MAPPING_CHANGE;
	event.u.mapping_change.cookie = region->cookie;
	event.u.mapping_change.addr   = (void __user *) region->addr;
	event.u.mapping_change.len    = region->len;

	ret = kdreg2_event_queue_insert(context, &event);

	if (!ret)
		kdreg2_context_wakeup(context);
}

/* **************************************************************** */
/* Implementation using doubly-linked lists.                        */
/* **************************************************************** */

#if KDREG2_DB_MODE == KDREG2_DB_MODE_DLLIST

/*
 * initialize region list data
 */

int
kdreg2_region_db_init(struct kdreg2_region_db *region_db,
		      const size_t num_entities)
{
	int      ret;

	KDREG2_DEBUG(KDREG2_DEBUG_INIT | KDREG2_DEBUG_REGION, 1,
		     "Creating region database %zu entities",
		     num_entities);

	region_db->max_regions   = num_entities;
	region_db->num_regions   = 0;
	region_db->num_allocs    = 0;
	region_db->num_frees     = 0;
	region_db->cookie_db.biggest_cookie = 0;

	ret = create_region_cache(region_db);
	if (ret)
		return ret;

	INIT_LIST_HEAD(&region_db->list_db.head);

	if (num_entities > 0)
		KDREG2_DEBUG(KDREG2_DEBUG_INIT, 1,
			     "region_db created for %zu entities",
			     num_entities);

	return 0;
}

void
kdreg2_region_db_destroy(struct kdreg2_region_db *region_db)
{
	destroy_region_cache(region_db);

	if (region_db->max_regions > 0)
		KDREG2_DEBUG(KDREG2_DEBUG_INIT, 1,
			     "region_db destroyed");
}

static struct kdreg2_region *
kdreg2_region_allocate(struct kdreg2_region_db *region_db)
{
	struct kdreg2_region  *region;

	region = kmem_cache_alloc(region_db->region_cache, GFP_KERNEL);
	if (unlikely(!region))
		return NULL;

	region_db->num_allocs++;

	region->addr   = 0;
	region->last   = 0;
	region->len    = 0;
	region->cookie = KDREG2_BAD_COOKIE_VALUE;
	region->monitoring_state_index = -1;

	INIT_LIST_HEAD(&region->region_list);

	return region;
}

static void
kdreg2_region_free(struct kdreg2_region_db *region_db,
		   struct kdreg2_region *region)
{
	region_db->num_frees++;

	kmem_cache_free(region_db->region_cache, region);
}

static int
kdreg2_region_db_insert(struct kdreg2_region_db *region_db,
			struct kdreg2_region *region)
{
	struct kdreg2_region *existing =
		kdreg2_region_db_find_by_cookie(region_db, region->cookie);

	if (existing) {
		bool identical = ((existing->addr == region->addr) &&
				  (existing->last == region->last));

		if (!identical)
			return -EBUSY;

		/* pass back the monitoring_state_index */

		region->monitoring_state_index = existing->monitoring_state_index;

		return -EEXIST;
	}

	list_add(&region->region_list, &region_db->list_db.head);

	if (region->cookie > region_db->cookie_db.biggest_cookie)
		region_db->cookie_db.biggest_cookie = region->cookie;

	return 0;
}

static int
kdreg2_region_db_remove(struct kdreg2_region_db *region_db,
			struct kdreg2_region *region)
{
	list_del_init(&region->region_list);
	return 0;
}

static struct kdreg2_region *
kdreg2_region_db_find_by_cookie(struct kdreg2_region_db *region_db,
				kdreg2_cookie_t cookie)
{
	struct kdreg2_region *region;

	if (region_db->cookie_db.biggest_cookie < cookie)
		return NULL;

	list_for_each_entry(region, &region_db->list_db.head, region_list) {
		if (region->cookie == cookie)
			return region;
	}

	return NULL;
}

static void
kdreg2_region_db_overlap_state_init(struct kdreg2_region_db *region_db,
		    struct kdreg2_region_db_overlap_state *overlap_state,
		    unsigned long start,
		    unsigned long last)
{
	overlap_state->start = start;
	overlap_state->last  = last;
	overlap_state->head  = &region_db->list_db.head;
	overlap_state->entry = overlap_state->head;
	overlap_state->next  = overlap_state->head->next;
}

/* generates the next entry which overlaps the range */
static struct kdreg2_region *
kdreg2_region_db_next_overlap(struct kdreg2_region_db_overlap_state *overlap_state)
{
	struct kdreg2_region *region;

	while (1) {
		if (overlap_state->next == overlap_state->head)
			return NULL;

		overlap_state->entry = overlap_state->next;
		overlap_state->next  = overlap_state->entry->next;

		region = list_entry(overlap_state->entry,
				    struct kdreg2_region,
				    region_list);

		if (region->last < overlap_state->start)
			continue;

		if (region->addr > overlap_state->last)
			continue;

		KDREG2_DEBUG(KDREG2_DEBUG_REGION, 4,
			     "Iterator returns region 0x%px, cookie %llu, "
			     "addr 0x%lx, last 0x%lx",
			     region, region->cookie,
			     region->addr, region->last);

		return region;
	}
}

#endif /* KDREG2_DB_MODE_DLLIST */

/* **************************************************************** */
/* Implementation using red-black trees.                            */
/*                                                                  */
/* See                                                              */
/*    Documentation/core-api/rbtree.rst and                         */
/*    include/linux/interval_tree_generic.h                         */
/* in the Linux source tree.                                        */
/* **************************************************************** */

#if KDREG2_DB_MODE == KDREG2_DB_MODE_RBTREE

static __always_inline
unsigned long kdreg2_region_start(struct kdreg2_region *region)
{
	return region->addr;
}

static __always_inline
unsigned long kdreg2_region_last(struct kdreg2_region *region)
{
	return region->last;
}

static int kdreg2_cookie_tree_insert(struct kdreg2_region *region,
				     struct cookie_tree_db *cookie_db)
{
	struct rb_node        **new = &cookie_db->root.rb_node;
	struct rb_node        *parent_node = NULL;
	struct kdreg2_region  *parent_region;

	while (*new) {
		parent_node = *new;
		parent_region = rb_entry(parent_node, struct kdreg2_region,
					 cookie_tree.node);

		if (region->cookie > parent_region->cookie)
			new = &parent_node->rb_left;
		else if (region->cookie < parent_region->cookie)
			new = &parent_node->rb_right;
		else {
			/* We found a duplicate.
			 * See if addr and last are identical.
			 */

			bool identical = ((parent_region->addr == region->addr) &&
					  (parent_region->last == region->last));

			if (!identical)
				return -EBUSY;

			/* pass back the monitoring_state_index */

			region->monitoring_state_index =
				parent_region->monitoring_state_index;

			return -EEXIST;
		}
	}

	rb_link_node(&region->cookie_tree.node, parent_node, new);
	rb_insert_color(&region->cookie_tree.node, &cookie_db->root);

	if (cookie_db->biggest_cookie < region->cookie)
		cookie_db->biggest_cookie = region->cookie;

	return 0;
}

static int kdreg2_cookie_tree_remove(struct kdreg2_region *region,
				     struct cookie_tree_db *cookie_db)
{
	rb_erase(&region->cookie_tree.node, &cookie_db->root);
	RB_CLEAR_NODE(&region->cookie_tree.node);

	return 0;
}

/* Instantiate the interval tree functions.  This will create:
 *
 * kdreg2_interval_tree_compute_subtree_last()
 * kdreg2_interval_tree_insert()
 * kdreg2_interval_tree_remove()
 * kdreg2_interval_tree_subtree_search()
 * kdreg2_interval_tree_iter_first()
 * kdreg2_interval_tree_iter_next()
 *
 * And we need to create:
 * kdreg2_region_start:      extract first address in interval from region struct
 * kdreg2_region_last:       extract last  address in interval from region struct
 */

INTERVAL_TREE_DEFINE(
	/* ITSTRUCT:   type of the interval tree nodes */
	struct kdreg2_region,
	/* ITRB:       name of struct rb_node field within ITSTRUCT */
	interval_tree.node,
	/* ITTYPE:     type of the interval endpoints */
	unsigned long,
	/* ITSUBTREE:  name of ITTYPE field within ITSTRUCT
	 * holding last-in-subtree.
	 */
	interval_tree.subtree_last,
	/* ITSTART(n): start endpoint of ITSTRUCT node n */
	kdreg2_region_start,
	/* ITLAST(n):  last endpoint of ITSTRUCT node n */
	kdreg2_region_last,
	/* ITSTATIC:   'static' or empty */
	static,
	/* ITPREFIX:   prefix to use for the inline tree definitions */
	kdreg2_interval_tree)

int
kdreg2_region_db_init(struct kdreg2_region_db *region_db,
		      const size_t num_entities)
{
	int      ret;

	KDREG2_DEBUG(KDREG2_DEBUG_INIT | KDREG2_DEBUG_REGION, 1,
		     "Creating region database %zu entities", num_entities);

	region_db->max_regions      = num_entities;
	region_db->num_regions      = 0;
	region_db->cookie_tree.root = RB_ROOT;
	region_db->cookie_tree.biggest_cookie = 0;

	ret = create_region_cache(region_db);
	if (ret)
		return ret;

#if KDREG2_HAS_RB_ROOT_CACHED == 0
	region_db->interval_tree.root = RB_ROOT;
#else
	region_db->interval_tree.root = RB_ROOT_CACHED;
#endif

	if (num_entities > 0)
		KDREG2_DEBUG(KDREG2_DEBUG_INIT, 1,
			     "region_db created for %zu entities", num_entities);

	return 0;
}

void
kdreg2_region_db_destroy(struct kdreg2_region_db *region_db)
{
	destroy_region_cache(region_db);

	if (region_db->max_regions > 0)
		KDREG2_DEBUG(KDREG2_DEBUG_INIT, 1,
			     "region_db destroyed");
}

int kdreg2_region_db_resize(struct kdreg2_context *context,
			    const size_t num_entities)
{
	struct kdreg2_region_db *region_db = &context->region_db;

	kdreg2_region_db_destroy(region_db);

	return kdreg2_region_db_init(region_db, num_entities);
}

static struct kdreg2_region *
kdreg2_region_allocate(struct kdreg2_region_db *region_db)
{
	struct kdreg2_region *region;

	region = kmem_cache_alloc(region_db->region_cache, GFP_KERNEL);
	if (unlikely(!region))
		return NULL;

	region_db->num_allocs++;

	region->addr   = 0;
	region->last   = 0;
	region->len    = 0;
	region->cookie = KDREG2_BAD_COOKIE_VALUE;
	region->monitoring_state_index = -1;

	RB_CLEAR_NODE(&region->cookie_tree.node);
	RB_CLEAR_NODE(&region->interval_tree.node);

	return region;
}

static void
kdreg2_region_free(struct kdreg2_region_db *region_db,
		   struct kdreg2_region *region)
{
	region_db->num_frees++;

	kmem_cache_free(region_db->region_cache, region);
}

static int
kdreg2_region_db_insert(struct kdreg2_region_db *region_db,
			struct kdreg2_region *region)
{
	int ret = kdreg2_cookie_tree_insert(region,
					    &region_db->cookie_tree);
	if (ret)
		return ret;

	kdreg2_interval_tree_insert(region,
				    &region_db->interval_tree.root);
	return 0;
}

static int
kdreg2_region_db_remove(struct kdreg2_region_db *region_db,
			struct kdreg2_region *region)
{
	kdreg2_interval_tree_remove(region,
				    &region_db->interval_tree.root);
	RB_CLEAR_NODE(&region->interval_tree.node);

	return kdreg2_cookie_tree_remove(region,
					 &region_db->cookie_tree);
}

static struct kdreg2_region *
kdreg2_region_db_find_by_cookie(struct kdreg2_region_db *region_db,
				kdreg2_cookie_t cookie)
{
	struct rb_root        *root = &region_db->cookie_tree.root;
	struct rb_node        *node = root->rb_node;
	struct kdreg2_region  *region;

	if (region_db->cookie_tree.biggest_cookie < cookie)
		return NULL;

	while (node) {
		region = rb_entry(node, struct kdreg2_region,
				  cookie_tree.node);

		if (region->cookie == cookie)
			return region;

		if (region->cookie < cookie)
			node = node->rb_left;
		else
			node = node->rb_right;
	}

	return NULL;
}

static void
kdreg2_region_db_overlap_state_init(struct kdreg2_region_db *region_db,
		    struct kdreg2_region_db_overlap_state *overlap_state,
		    unsigned long start,
		    unsigned long last)
{
	KDREG2_DEBUG(KDREG2_DEBUG_REGION, 2,
		     "Initializing iterator: start 0x%lx, last 0x%lx",
		     start, last);

	overlap_state->start = start;
	overlap_state->last  = last;
	overlap_state->entry =
		kdreg2_interval_tree_iter_first(&region_db->interval_tree.root,
						start, last);
	if (!overlap_state->entry)
		overlap_state->next = NULL;
	else
		overlap_state->next =
			kdreg2_interval_tree_iter_next(overlap_state->entry,
						       start, last);
}

/* generates the next entry which overlaps the range */
static struct kdreg2_region *
kdreg2_region_db_next_overlap(struct kdreg2_region_db_overlap_state *overlap_state)
{
	struct kdreg2_region *region = overlap_state->entry;

	overlap_state->entry = overlap_state->next;
	if (!overlap_state->entry)
		overlap_state->next = NULL;
	else
		overlap_state->next =
			kdreg2_interval_tree_iter_next(overlap_state->entry,
						       overlap_state->start,
						       overlap_state->last);

	if (region)
		KDREG2_DEBUG(KDREG2_DEBUG_REGION, 4,
			     "Iterator returns region 0x%px, cookie %llu, "
			     "addr 0x%lx, last 0x%lx",
			     region, region->cookie,
			     region->addr, region->last);

	return region;
}

#endif /* KDREG2_DB_MODE_RBTREE */
