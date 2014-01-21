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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <libfdt.h>
#include "simple_allocator.h"
#include "kexec_memory_map.h"

#undef DEBUG

#define MEMORY_CAP (2UL * 1024 * 1024 * 1024)

static unsigned long mem_top = 0;

struct free_map *kexec_map;


static int getprop_u32(const void *fdt, int nodeoffset, const char *name, uint32_t *val)
{
	int len;
	const fdt32_t *prop;

	prop = fdt_getprop(fdt, nodeoffset, name, &len);
	if (!prop && len == -FDT_ERR_NOTFOUND)
		return -1;

	if (!prop) {
		fprintf(stderr, "getprop_u32 %s returned %d\n", name, len);
		return -1;
	}

	if (len != sizeof(uint32_t)) {
		fprintf(stderr, "getprop_u32 %s unexpected length %d\n", name, len);
		return -1;
	}

	*val = fdt32_to_cpu(*prop);
	return 0;
}

static int getprop_u64(const void *fdt, int nodeoffset, const char *name, uint64_t *val)
{
	int len;
	const fdt64_t *prop;

	prop = fdt_getprop(fdt, nodeoffset, name, &len);
	if (!prop && len == -FDT_ERR_NOTFOUND)
		return -1;

	if (!prop) {
		fprintf(stderr, "getprop_u64 %s returned %d\n", name, len);
		return -1;
	}

	if (len != sizeof(uint64_t)) {
		fprintf(stderr, "getprop_u64 %s unexpected length %d\n", name, len);
		return -1;
	}

	*val = fdt64_to_cpu(*prop);
	return 0;
}

static int new_style_reservation(void *fdt, int reserve_initrd)
{
	int nodeoffset;
	const void *p;
	fdt64_t *ranges, *range;
	char *names, *name;
	int ranges_len, names_len;

	nodeoffset = fdt_path_offset(fdt, "/");
	if (nodeoffset < 0) {
		fprintf(stderr, "Device tree has no root node\n");
		exit(1);
	}

	p = fdt_getprop(fdt, nodeoffset, "reserved-ranges", &ranges_len);
	if (!p && ranges_len == -FDT_ERR_NOTFOUND)
		return 0;

	if (!p) {
		fprintf(stderr, "getprop reserved-ranges returned %d\n",
			ranges_len);
		exit(1);
	}

	ranges = malloc(ranges_len);
	if (!ranges) {
		perror("malloc");
		exit(1);
	}
	memcpy(ranges, p, ranges_len);

	p = fdt_getprop(fdt, nodeoffset, "reserved-names", &names_len);
	if (!p && names_len == -FDT_ERR_NOTFOUND)
		return 0;

	if (!p) {
		fprintf(stderr, "getprop reserved-names returned %d\n",
			names_len);
		exit(1);
	}

	names = malloc(names_len);
	if (!names) {
		perror("malloc");
		exit(1);
	}
	memcpy(names, p, names_len);

	name = names;
	range = ranges;
	while (ranges_len > 0 && names_len > 0) {
		uint64_t start, size;

		start = fdt64_to_cpu(*range++);
		size = fdt64_to_cpu(*range++);

#ifdef DEBUG
		printf("%s %lx %lx\n", name, start, size);
#endif

		if (!reserve_initrd && !strcmp(name, "linux,initramfs"))
			continue;

		simple_alloc_at(kexec_map, start, size);

		if (fdt_add_mem_rsv(fdt, start, size))
			perror("fdt_add_mem_rsv");

		ranges_len -= 2 * sizeof(uint64_t);
		names_len -= strlen(name) + 1;
		name += strlen(name) + 1;
	}

	free(ranges);
	free(names);

	return 1;
}

void kexec_memory_map(void *fdt, int reserve_initrd)
{
	uint64_t start, size, end;
	int nodeoffset;
	int lpar = 0;

	kexec_map = simple_init();

	/* Work out if we are in LPAR mode */
	nodeoffset = fdt_path_offset(fdt, "/rtas");
	if (nodeoffset >= 0) {
		if (fdt_getprop(fdt, nodeoffset, "ibm,hypertas-functions", NULL))
			lpar = 1;
	}

	/* First find our memory */
	nodeoffset = fdt_path_offset(fdt, "/");
	if (nodeoffset < 0) {
		fprintf(stderr, "Device tree has no root node\n");
		exit(1);
	}

	while (1) {
		const char *name;
		int len;
		const fdt64_t *reg;

		nodeoffset = fdt_next_node(fdt, nodeoffset, NULL);
		if (nodeoffset < 0)
			break;

		name = fdt_get_name(fdt, nodeoffset, NULL);

		if (!name || strncmp(name, "memory", strlen("memory")))
			continue;

		reg = fdt_getprop(fdt, nodeoffset, "reg", &len);

		while (len) {
			start = fdt64_to_cpu(*reg++);
			size = fdt64_to_cpu(*reg++);
			len -= 2 * sizeof(uint64_t);

			if (lpar == 1) {
				/* Only use the RMA region for LPAR */
				if (start == 0) {
					if (size > MEMORY_CAP)
						size = MEMORY_CAP;
					simple_free(kexec_map, 0, size);
					mem_top = size;
				}
			} else {
				if (start >= MEMORY_CAP)
					continue;

				if ((start + size) > MEMORY_CAP)
					size = MEMORY_CAP - start;

				simple_free(kexec_map, start, size);

				if ((start + size) > mem_top)
					mem_top = start + size;
			}
		}
	}

	/* Reserve the kernel */
	nodeoffset = fdt_path_offset(fdt, "/chosen");
	if (nodeoffset < 0) {
		fprintf(stderr, "Device tree has no chosen node\n");
		exit(1);
	}

	/*
	 * XXX FIXME: Need to add linux,kernel-start property to the
	 * kernel to handle relocatable kernels.
	 */
	start = 0;
	if (getprop_u64(fdt, nodeoffset, "linux,kernel-end", &end)) {
		fprintf(stderr, "getprop linux,kernel-end failed\n");
		exit(1);
	}

	simple_alloc_at(kexec_map, start, end - start);

	/* Reserve the MMU hashtable in non LPAR mode */
	if (lpar == 0) {
		if (getprop_u64(fdt, nodeoffset, "linux,htab-base", &start) ||
		    getprop_u64(fdt, nodeoffset, "linux,htab-size", &size)) {
			fprintf(stderr, "Could not find linux,htab-base or "
				"linux,htab-size properties\n");
			exit(1);
		}

		if (start < mem_top)
			simple_alloc_at(kexec_map, start, size);
	}

	/* XXX FIXME: Reserve TCEs in kexec_map */

	if (new_style_reservation(fdt, reserve_initrd))
		return;

	/* Reserve the initrd if requested */
	if (reserve_initrd &&
            !getprop_u64(fdt, nodeoffset, "linux,initrd-start", &start) &&
	    !getprop_u64(fdt, nodeoffset, "linux,initrd-end", &end)) {

		if (start < mem_top)
			simple_alloc_at(kexec_map, start, end - start);
	}

	/* Reserve RTAS */
	nodeoffset = fdt_path_offset(fdt, "/rtas");
	if (nodeoffset > 0) {
		uint32_t rtas_start, rtas_size;

		if (getprop_u32(fdt, nodeoffset, "linux,rtas-base", &rtas_start)) {
			fprintf(stderr, "getprop linux,rtas-base failed\n");
			exit(1);
		}

		if (getprop_u32(fdt, nodeoffset, "rtas-size", &rtas_size)) {
			fprintf(stderr, "getprop rtas-size failed\n");
			exit(1);
		}

		simple_alloc_at(kexec_map, rtas_start, rtas_size);

		if (fdt_add_mem_rsv(fdt, rtas_start, rtas_size))
			perror("fdt_add_mem_rsv");
	}

	nodeoffset = fdt_path_offset(fdt, "/ibm,opal");
	if (nodeoffset > 0) {
		uint64_t opal_start, opal_size;

		if (getprop_u64(fdt, nodeoffset, "opal-base-address",
				&opal_start)) {
			fprintf(stderr, "getprop opal-base-address failed\n");
			exit(1);
		}

		if (getprop_u64(fdt, nodeoffset, "opal-runtime-size",
				&opal_size)) {
			fprintf(stderr, "getprop opal-runtime-size failed\n");
			exit(1);
		}

		simple_alloc_at(kexec_map, opal_start, opal_size);

		if (fdt_add_mem_rsv(fdt, opal_start, opal_size))
			perror("fdt_add_mem_rsv");
	}
}
