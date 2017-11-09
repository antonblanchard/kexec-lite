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

/*
 * The master enters at the start of this chunk with:
 * r3 = physical cpu id
 * r4 = physical address of this chunk
 *
 * The slaves enter 0x60 into this chunk with:
 * r3 = physical cpu id
 *
 * The previous kernel has copied the first 0x100 bytes of
 * this chunk down to 0x0 so the secondaries can spin on it.
 */

#define __ASSEMBLY__
#include "kexec_trampoline.h"

#define	r2	2
#define	r3	3
#define	r4	4
#define	r5	5
#define	r6	6
#define	r7	7
#define	r8	8
#define	r9	9

#ifdef __powerpc64__
#define LOAD	ld
#define RFI	rfid
#else
#define LOAD	lwz
#define RFI	rfi
#endif

#if defined(__LITTLE_ENDIAN__)
#define STWX_BE	stwbrx
#elif defined(__BIG_ENDIAN__)
#define STWX_BE	stwx
#else
#error no endianness defined!
#endif

.globl	__trampoline_start
__trampoline_start:
	b	start

	/*
	 * We copy the first 0x100 bytes of the kernel minus
	 * the branch here
	 */

. = 0x100
start:
	or	r2,r2,r2

	/*
	 * Kernel calling convention:
	 * r3 = physical address of device tree
	 * r4 = physical address of kernel
	 * r5 = 0
	 * r6 = ePAPR cookie
	 * r7 = 0
	 */
	bl	1f
1:	mflr	r6

	LOAD	r7,(device_tree_addr - 1b)(r6)
	/* We save the physical cpu id in the device tree header */
	addi	r5,r7,DT_CPU_OFFSET
	STWX_BE	r3,0,r5
	mr	r3,r7

	LOAD	r4,(kernel_addr - 1b)(r6)

	li	r5,0

	mtsrr0	r4

	mfmsr	r5
	clrrdi	r5,r5,1 	/* Clear MSR_LE */
	mtsrr1	r5

	li	r5,0

	/* Put ePAPR cookie 0x65504150 */
	lis	r6,0x6550
	addi	r6,r6,0x4150

	li	r7,0

	RFI

. = KERNEL_ADDR_OFFSET
kernel_addr:
	.dc.a	0x0
. = DEVICE_TREE_ADDR_OFFSET
device_tree_addr:
	.dc.a	0x0

.globl	__trampoline_end
__trampoline_end:
