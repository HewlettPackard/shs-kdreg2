/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2012-2019 Cray(R)
 * Copyright (C) 2020-2023 Hewlett Packard Enterprise Development LP
 *
 * KDREG2 module configuration parameters
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "LICENSE" in this directory for more details.
 *
 * Derived in part from dreg.c by Pete Wyckoff.
 * Copyright (C) 2004-5 Pete Wyckoff <pw@osc.edu>
 * Distributed under the GNU Public License Version 2 (See LICENSE)
 */

#ifndef _KDREG2_CONFIG_H_
#define _KDREG2_CONFIG_H_

/* **************************************************************** */

/*
 * The region database has 2 implementations:
 * 1) a reference implementation using doubly-linked lists
 * 2) a production quality version using Red-Black trees
 */

#define KDREG2_DB_MODE_DLLIST 1
#define KDREG2_DB_MODE_RBTREE 2

/* Pick a region database implementation here */

#if 0
#define KDREG2_DB_MODE KDREG2_DB_MODE_DLLIST
#else
#define KDREG2_DB_MODE KDREG2_DB_MODE_RBTREE
#endif

/* **************************************************************** */

/* The class device has configuration parameters in
 *    /sys/class/kdreg2/kdreg2
 * in particular, debug_level and debug_mask can
 * have default values for either quiet or verbose
 * modes.
 */

#define KDREG2_DEBUG_MODE_VERBOSE 1
#define KDREG2_DEBUG_MODE_QUIET   2

/* Pick a debug mode here */

#if 0
#define KDREG2_DEBUG_MODE KDREG2_DEBUG_MODE_VERBOSE
#else
#define KDREG2_DEBUG_MODE KDREG2_DEBUG_MODE_QUIET
#endif

/* **************************************************************** */

/* Kernel mapped memory is normally not accessible from user space
 * via gdb. By installing a custom hook, this memory should be
 * viewable in gdb.
 *
 * The presence or absence of this hook has no performance impact
 * on the module.
 */

#define INSTALL_GDB_HOOK 1

#endif /*_KDREG2_CONFIG_H_ */
