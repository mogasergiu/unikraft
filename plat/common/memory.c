/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Authors: Costin Lupu <costin.lupu@cs.pub.ro>
 *          Sergiu Moga <sergiu.moga@protonmail.com>
 *
 * Copyright (c) 2018, NEC Europe Ltd., NEC Corporation. All rights reserved.
 * Copyright (c) 2023, University Politehnica of Bucharest. All rights reserved.
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
#define PLATFORM_MAX_MEM_ADDR 0x00080000000 /* 2 GiB */
#endif
static inline bool is_in_static_pt(__paddr_t addr)
{
	return addr < PLATFORM_MAX_MEM_ADDR;
}

void *ukplat_memregion_alloc(__sz size, int type)
{
	struct ukplat_memregion_desc *mrd, alloc_mrd = {0};
	struct ukplat_bootinfo *bi;
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

		if((mrd->flags & UKPLAT_MEMRF_PERMS) !=
			    (UKPLAT_MEMRF_READ | UKPLAT_MEMRF_WRITE))
			return NULL;

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
		alloc_mrd.vbase = pstart;
		alloc_mrd.pbase = pstart;
		alloc_mrd.len   = size;
		alloc_mrd.type  = type;
		alloc_mrd.flags = UKPLAT_MEMRF_READ  |
				  UKPLAT_MEMRF_WRITE |
				  UKPLAT_MEMRF_MAP;

		bi = ukplat_bootinfo_get();
		if (unlikely(!bi))
			return NULL;

		rc = ukplat_memregion_list_insert(&bi->mrds, &alloc_mrd);
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

/* We want a criteria based on which we decide which memory region to keep,
 * split or discard when coalescing.
 * - UKPLAT_MEMRT_RESERVED is of highest priority since we should not touch it
 * - UKPLAT_MEMRT_FREE is of lowest priority since it is supposedly free
 * - the others are all allocated for Unikraft so they will have the same
 * priority
 */
static inline int get_mrd_prio(struct ukplat_memregion_desc *const m)
{
	switch (m->type) {
	case UKPLAT_MEMRT_FREE:
		return 0;
	case UKPLAT_MEMRT_INITRD:
	case UKPLAT_MEMRT_CMDLINE:
	case UKPLAT_MEMRT_STACK:
	case UKPLAT_MEMRT_DEVICETREE:
	case UKPLAT_MEMRT_KERNEL:
		return 1;
	case UKPLAT_MEMRT_RESERVED:
		return 2;
	default:
		return -1;
	}
}

/* Memory region with lower priority must be adjusted in favor of the one
 * with higher priority, e.g. if left memory region is of lower priority but
 * contains the right memory region of higher priority, then split the left one
 * in two, by adjusting the current left one and inserting a new memory region
 * descriptor.
 */
static inline void overlapping_mrd_fixup(struct ukplat_memregion_list *list,
					 struct ukplat_memregion_desc *const ml,
					 struct ukplat_memregion_desc *const mr,
					 int ml_prio, int mr_prio,
					 __u32 lidx __unused, __u32 ridx)
{
	/* If left memory region is of higher priority */
	if (ml_prio > mr_prio) {
		/* If the right region is contained within the left region,
		 * drop it entirely
		 */
		if (RANGE_CONTAIN(ml->pbase, ml->len, mr->pbase, mr->len)) {
			mr->len = 0;

		/* If the right region has a part of itself in the left region,
		 * drop that part of the right region only
		 */
		} else {
			mr->len -= ml->pbase + ml->len - mr->pbase;
			mr->pbase = ml->pbase + ml->len;
			mr->vbase = mr->pbase;
		}

	/* If left memory region is of lower priority */
	} else {
		/* If the left memory region is contained within the right
		 * region, drop it entirely
		 */
		if (RANGE_CONTAIN(mr->pbase, mr->len, ml->pbase, ml->len)) {
			ml->len = 0;

		/* If the left region has a part of itself in the right region,
		 * drop that part of the left region only and split by creating
		 * a new one if the left region is larger than the right region.
		 */
		} else {
			if (RANGE_CONTAIN(ml->pbase, ml->len,
					  mr->pbase, mr->len))
				/* Ignore insertion failure as there is nothing
				 * we can do about it and it is not worth caring
				 * about.
				 */
				ukplat_memregion_list_insert_at_idx(list,
					&(struct ukplat_memregion_desc){
						.vbase = mr->pbase + mr->len,
						.pbase = mr->pbase + mr->len,
						.len   = ml->pbase + ml->len -
							 mr->pbase - mr->len,
						.type  = ml->type,
						.flags = ml->flags
					}, ridx + 1);

			ml->len = mr->pbase - ml->pbase;
		}
	}
}

int ukplat_memregion_list_coalesce(struct ukplat_memregion_list *list)
{
	struct ukplat_memregion_desc *m, *ml, *mr;
	int ml_prio, mr_prio;
	__u32 i;

	i = 0;
	m = list->mrds;
	while (i + 1 < list->count) {
		/* Make sure first that they are ordered. If not, swap them */
		if (m[i].pbase > m[i + 1].pbase ||
		    (m[i].pbase == m[i + 1].pbase &&
		     m[i].pbase + m[i].len > m[i + 1].pbase + m[i + 1].len)) {
			struct ukplat_memregion_desc tmp;

			tmp = m[i];
			m[i] = m[i + 1];
			m[i + 1] = tmp;
		}
		ml = &m[i];
		mr = &m[i + 1];
		ml_prio = get_mrd_prio(ml);
		mr_prio = get_mrd_prio(mr);

		/* If they overlap */
		if (RANGE_OVERLAP(ml->pbase,  ml->len, mr->pbase, mr->len)) {
			/* If they are not of the same priority */
			if (ml_prio != mr_prio) {
				/* If the overlapping memory region of type
				 * UKPLAT_MEMRT_KERNEL is of lower priority,
				 * then something is definetely wrong => abort!
				 */
				if ((ml_prio < mr_prio &&
				     ml->type == UKPLAT_MEMRT_KERNEL) ||
				    (ml_prio > mr_prio &&
				    mr->type == UKPLAT_MEMRT_KERNEL))
					return -EINVAL;


				overlapping_mrd_fixup(list, ml, mr, ml_prio,
						      mr_prio, i, i + 1);

				/* Remove dropped regions */
				if (ml->len == 0)
					ukplat_memregion_list_delete(list, i);
				else if (mr->len == 0)
					ukplat_memregion_list_delete(list,
								     i + 1);
				else
					i++;

			/* If they are of the same priority and different flags,
			 * it either means that is one of our manually
			 * inserted memory region descriptors for command-line
			 * or initrd or devicetree or stack, which have the same
			 * priority as the kernel type memory region descriptor,
			 * or it could most likely be something abnormal,
			 * in which case we will return an error. For the
			 * former case, we choose to keep the manually inserted
			 * memory region descriptor, since its type was
			 * inserted by us.
			 */
			} else if (ml->flags != mr->flags) {
				if (ml->type == UKPLAT_MEMRT_KERNEL)
					ukplat_memregion_list_delete(list, i);
				else if (mr->type == UKPLAT_MEMRT_KERNEL)
					ukplat_memregion_list_delete(list,
								     i + 1);
				else
					return -EINVAL;

			/* If they have the same priority and same flags, merge
			 * them. If they are contained within each other, drop
			 * the contained one.
			 */
			} else {
				/* If the left region is contained within the
				 * right region, drop it
				 */
				if (RANGE_CONTAIN(mr->pbase, mr->len,
						  ml->pbase, ml->len)) {
					ukplat_memregion_list_delete(list, i);

					continue;

				/* If the right region is contained within the
				 * left region, drop it
				 */
				} else if (RANGE_CONTAIN(ml->pbase, ml->len,
							 mr->pbase, mr->len)) {
					ukplat_memregion_list_delete(list,
								     i + 1);

					continue;
				}

				/* If they are not contained within each other,
				 * merge them.
				 */
				ml->len += mr->len;

				/* In case they overlap, delete duplicate
				 * overlapping region
				 */
				ml->len -= ml->pbase + ml->len - mr->pbase;

				/* Delete the memory region we just merged into
				 * the previous region.
				 */
				ukplat_memregion_list_delete(list, i + 1);
			}

		/* If they do not overlap but they are contiguous and have the
		 * same flags and priority.
		 */
		} else if (ml->pbase + ml->len == mr->pbase &&
			   ml_prio == mr_prio && ml->flags == mr->flags) {
			ml->len += mr->len;
			ukplat_memregion_list_delete(list, i + 1);
		} else {
			i++;
		}
	}

	return 0;
}

int ukplat_memregion_count(void)
{
	struct ukplat_bootinfo *bi = ukplat_bootinfo_get();

	UK_ASSERT(bi);

	return (int)bi->mrds.count;
}

int ukplat_memregion_get(int i, struct ukplat_memregion_desc **mrd)
{
	struct ukplat_bootinfo *bi = ukplat_bootinfo_get();

	UK_ASSERT(bi);
	UK_ASSERT(i >= 0);

	if (unlikely((__u32)i >= bi->mrds.count))
		return -1;

	*mrd = &bi->mrds.mrds[i];
	return 0;
}
