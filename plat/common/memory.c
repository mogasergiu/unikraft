/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Authors: Costin Lupu <costin.lupu@cs.pub.ro>
 *
 * Copyright (c) 2018, NEC Europe Ltd., NEC Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <uk/plat/common/bootinfo.h>
#include <uk/asm/limits.h>
#include <uk/alloc.h>
#include <stddef.h>
#include <stdbool.h>

static struct uk_alloc *plat_allocator;

int ukplat_memallocator_set(struct uk_alloc *a)
{
	UK_ASSERT(a != NULL);

	if (plat_allocator != NULL)
		return -1;

	plat_allocator = a;

	_ukplat_mem_mappings_init();

	return 0;
}

struct uk_alloc *ukplat_memallocator_get(void)
{
	return plat_allocator;
}


#if !defined(LINUXUPLAT)
#if defined(__X86_64__)
#define PLATFORM_MAX_MEM_ADDR 0x00100000000 /* 4 GiB */
#elif defined(__ARM_64__)
#define PLATFORM_MAX_MEM_ADDR 0x10000000000 /* 512 GiB */
#endif
static inline bool is_in_static_pt(__paddr_t addr)
{
	return addr < PLATFORM_MAX_MEM_ADDR;
}

void *ukplat_memregion_alloc(__sz size, int type)
{
	struct ukplat_memregion_desc *mrd;
	__paddr_t pstart, pend;
	__paddr_t ostart, olen;
	int rc;

	size = ALIGN_UP(size, __PAGE_SIZE);
	ukplat_memregion_foreach(&mrd, UKPLAT_MEMRT_FREE, 0, 0) {
		UK_ASSERT(mrd->pbase <= __U64_MAX - size);
		pstart = ALIGN_UP(mrd->pbase, __PAGE_SIZE);
		pend   = pstart + size;

		if (!is_in_static_pt(pend) || pend > mrd->pbase + mrd->len)
			continue;

		UK_ASSERT((mrd->flags & UKPLAT_MEMRF_PERMS) ==
			  (UKPLAT_MEMRF_READ | UKPLAT_MEMRF_WRITE));

		ostart = mrd->pbase;
		olen   = mrd->len;

		/* If fragmenting this memory region leaves it with length 0,
		 * then simply overwrite and return it instead.
		 */
		if (olen - (pstart - ostart) == size) {
			mrd->pbase = pstart;
			mrd->vbase = pstart;
			mrd->len = pend - pstart;
			mrd->type = type;
			mrd->flags = UKPLAT_MEMRF_READ |
				     UKPLAT_MEMRF_WRITE |
				     UKPLAT_MEMRF_MAP;

			return (void *)pstart;
		}

		/* Adjust free region */
		mrd->len  -= pend - mrd->pbase;
		mrd->pbase = pend;

		mrd->vbase = (__vaddr_t)mrd->pbase;

		/* Insert allocated region */
		rc = ukplat_memregion_list_insert(&ukplat_bootinfo_get()->mrds,
			&(struct ukplat_memregion_desc){
				.vbase = pstart,
				.pbase = pstart,
				.len   = size,
				.type  = type,
				.flags = UKPLAT_MEMRF_READ |
					 UKPLAT_MEMRF_WRITE |
					 UKPLAT_MEMRF_MAP,
			});
		if (unlikely(rc < 0)) {
			/* Restore original region */
			mrd->vbase = ostart;
			mrd->len   = olen;

			return NULL;
		}

		return (void *)pstart;
	}

	return NULL;
}
#endif
