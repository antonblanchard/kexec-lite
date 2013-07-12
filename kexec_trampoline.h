/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) IBM Corporation, 2013
 *
 * Author: Anton Blanchard <anton@au.ibm.com>
 */

#ifndef KEXEC_TRAMPOLINE_H
#define KEXEC_TRAMPOLINE_H

#define KERNEL_ADDR_OFFSET		0x200
#define DEVICE_TREE_ADDR_OFFSET		0x204

/* Fixed offset in device tree for storing the physical ID of the boot CPU */
#define DT_CPU_OFFSET			28

#ifndef __ASSEMBLY__

extern char __trampoline_start[];
extern char __trampoline_end[];

static inline void trampoline_set_kernel(void *p, unsigned long addr)
{
	unsigned int *v;

	v = (p + KERNEL_ADDR_OFFSET);
	*v = addr;
}

static inline void trampoline_set_device_tree(void *p, unsigned long addr)
{
	unsigned int *v;

	v = (p + DEVICE_TREE_ADDR_OFFSET);
	*v = addr;
}

#endif

#endif
