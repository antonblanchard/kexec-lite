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

#ifndef SIMPLE_ALLOCATOR_H
#define SIMPLE_ALLOCATOR_H

#include "list.h"

struct free_entry {
	unsigned long start;
	unsigned long size;
	struct list_node list;
};

struct free_map {
	struct list_head entries;
};

struct free_map *simple_init(void);
void simple_destroy(struct free_map *map);

unsigned long simple_alloc_at(struct free_map *map, unsigned long size, unsigned long align);
unsigned long simple_alloc_low(struct free_map *map, unsigned long size, unsigned long align);
unsigned long simple_alloc_high(struct free_map *map, unsigned long size, unsigned long align);
void simple_free(struct free_map *map, unsigned long address, unsigned long size);

void simple_iterate_free(struct free_map *map, void (* func)(unsigned long start, unsigned long size));
void simple_dump_free_map(struct free_map *map);

#endif
