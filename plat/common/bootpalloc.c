#include <uk/plat/common/bootinfo.h>
#include <uk/arch/paging.h>

extern const unsigned long PLATFORM_MAX_MEM_ADDR;

/**
 * Allocates page-aligned memory by taking it away from the free physical
 * memory. Only memory up to PLATFORM_MAX_MEM_ADDR is used so that it is
 * accessible also with the static 1:1 boot page table. Note, the memory
 * cannot be released!
 *
 * @param size
 *   The size to allocate. Will be rounded up to next multiple of page size.
 * @param type
 *   Memory region type to use for the allocated memory. Can be 0.
 *
 * @return
 *   A pointer to the allocated memory on success, NULL otherwise
 */
void *bootmemory_palloc(__sz size, int type, __u16 flags)
{
	struct ukplat_memregion_desc *mrd;
	__paddr_t pstart, pend;
	__paddr_t ostart, olen;
	int rc;

	size = ALIGN_UP(size, PAGE_SIZE);
	ukplat_memregion_foreach(&mrd, UKPLAT_MEMRT_FREE, 0, 0) {
		UK_ASSERT(mrd->pbase <= __U64_MAX - size);
		pstart = ALIGN_UP(mrd->pbase, PAGE_SIZE);
		pend   = pstart + size;

		if (pend > PLATFORM_MAX_MEM_ADDR || pend > mrd->pbase + mrd->len)
			continue;

		UK_ASSERT((mrd->flags & UKPLAT_MEMRF_PERMS) ==
			  (UKPLAT_MEMRF_READ | UKPLAT_MEMRF_WRITE));

		ostart = mrd->pbase;
		olen   = mrd->len;

		/* If fragmenting this memory region leaves it with length 0,
		 * then simply overwrite flags and type
		 */
		if (pend - mrd->pbase == mrd->len) {
			mrd->type = type;
			mrd->flags = UKPLAT_MEMRF_READ | UKPLAT_MEMRF_WRITE |
				     UKPLAT_MEMRF_MAP;

			return (void *)pstart;
		}

		/* Adjust free region otherwise and insert the new region */
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
				.flags = flags | UKPLAT_MEMRF_MAP,
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
