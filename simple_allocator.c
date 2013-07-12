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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "list.h"
#include "simple_allocator.h"

#define ALIGN_UP(VAL, SIZE)	(((VAL) + (SIZE-1)) & ~(SIZE-1))
#define ALIGN_DOWN(VAL, SIZE)	((VAL) & ~(SIZE-1))

#undef DEBUG
#ifdef DEBUG
#define debug_printf(A...) fprintf(stderr, A)
#else
#define debug_printf(A...) do { } while (0)
#endif

struct free_map *simple_init(void)
{
	struct free_map *map;

	map = malloc(sizeof(struct free_map));
	if (!map) {
		perror("simple_init: malloc of free_map failed");
		return NULL;
	}

	memset(map, 0, sizeof(struct free_map));

	list_head_init(&map->entries);

	return map;
}

void simple_destroy(struct free_map *map)
{
	struct free_entry *e;
	struct free_entry *next;

	list_for_each_safe(&map->entries, e, next, list) {
		list_del(&e->list);
		free(e);
	}

	free(map);
}

static unsigned long __alloc(struct free_entry *e, unsigned long start, unsigned long size)
{
	unsigned long end = start + size;

	/* It won't fit in this region */
	if (start < e->start || (e->start + e->size) < end)
		return -1;

	if ((start == e->start) && (end == (e->start + e->size))) {
		/* Consume the entire region */
		list_del(&e->list);
		free(e);
		debug_printf("consuming entire region\n");
		return start;

	} else if (start == e->start) {
		/* Remove from the start of region */
		e->start += size;
		e->size -= size;
		debug_printf("consuming from start\n");
		return start;

	} else if (end == (e->start + e->size)) {
		/* Remove from the end of region */
		e->size -= size;
		debug_printf("consuming from end\n");
		return start;

	} else {
		/* Split the region in two */
		struct free_entry *n;
		debug_printf("splitting region\n");

		n = malloc(sizeof(struct free_entry));
		if (!n) {
			perror("malloc");
			return -1;
		}
		memset(n, 0, sizeof(struct free_entry));

		n->start = end;
		n->size = e->start + e->size - end;
		e->size = start - e->start;

		list_add((struct list_head *)&e->list, &n->list);

		return start;
	}

	return -1;
}

unsigned long simple_alloc_at(struct free_map *map, unsigned long start, unsigned long size)
{
	struct free_entry *e;
	unsigned long ret;

	list_for_each(&map->entries, e, list) {
		if (start >= e->start && (start + size) <= (e->start + e->size)) {
			ret = __alloc(e, start, size);
			if (ret != -1)
				return ret;
		}
	}

	return -1;
}

unsigned long simple_alloc_low(struct free_map *map, unsigned long size, unsigned long align)
{
	struct free_entry *e;

	if (align == 0)
		align = 1;

	list_for_each(&map->entries, e, list) {
		unsigned long aligned_start = ALIGN_UP(e->start, align);
		unsigned long ret;

		ret = __alloc(e, aligned_start, size);
		if (ret != -1)
			return ret;
	}

	return -1;
}

unsigned long simple_alloc_high(struct free_map *map, unsigned long size, unsigned long align)
{
	struct free_entry *e;

	if (align == 0)
		align = 1;

	list_for_each_rev(&map->entries, e, list) {
		unsigned long aligned_start = ALIGN_DOWN(e->start + e->size - size, align);
		unsigned long ret;

		ret = __alloc(e, aligned_start, size);
		if (ret != -1)
			return ret;
	}

	return -1;
}

void simple_free(struct free_map *map, unsigned long start, unsigned long size)
{
	struct free_entry *e;
	struct free_entry *n;

	debug_printf("simple_free\n");

	list_for_each(&map->entries, e, list) {
		if (e->start < (start + size) && start < (e->start + e->size)) {
			fprintf(stderr, "double free of region 0x%lx of size %ld bytes\n", start, size);
			return;
		}

		/* Try and extend an existing region */
		if (e->start == (start + size)) {
			debug_printf("extending start\n");
			e->start -= size;
			e->size += size;
			return;

		} else if ((e->start + e->size) == start) {
			debug_printf("extending end\n");
			e->size += size;
			return;
		}

		if (e->start > start)
			break;
	}

	debug_printf("creating new entry\n");
	n = malloc(sizeof(struct free_entry));
	if (!n) {
		perror("malloc");
		return;
	}
	memset(n, 0, sizeof(struct free_entry));

	n->start = start;
	n->size = size;

	list_add_tail((struct list_head *)&e->list, &n->list);
}

void simple_iterate_free(struct free_map *map, void (* func)(unsigned long start, unsigned long size))
{
	struct free_entry *e;

	list_for_each(&map->entries, e, list)
		func(e->start, e->size);
}

void simple_dump_free_map(struct free_map *map)
{
	struct free_entry *e;

	list_for_each(&map->entries, e, list)
		fprintf(stderr, "0x%08lx-0x%08lx\n", e->start,
			e->start + e->size);
}

#if 0
static double uniform_deviate(int seed)
{
	return seed * (1.0 / (RAND_MAX + 1.0));
}

int main()
{
	struct free_map *m;
	int i;

	m = simple_init();

	simple_free(m, 0, 128 * 1024 * 1024);

	printf("%lx\n", simple_alloc_at(m, 64*1024*1024, 2*1024*1024));
	simple_free(m, 64*1024*1024, 1*1024*1024);
	simple_free(m, 65*1024*1024, 1*1024*1024);
	printf("%lx\n", simple_alloc_at(m, 64*1024*1024, 2*1024*1024));

	simple_dump_free_map(m);

	for (i = 0; i < 32; i++)
		printf("%lx\n", simple_alloc_high(m, 1*1024, 2*1024));

	for (i = 0; i < 1024; i++) {
		unsigned long addr, size;
		addr = uniform_deviate(rand()) * 128 * 1024 * 1024;
		size = uniform_deviate(rand()) * 128 * 1024 * 1024;


		printf("%lx\n", simple_alloc_high(m, addr, size));
		printf("%lx\n", simple_alloc_low(m, addr, size));
		simple_free(m, addr, size);


	}

	simple_dump_free_map(m);

	simple_destroy(m);

	return 0;
}
#endif
