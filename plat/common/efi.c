#include <uk/plat/common/bootinfo.h>
#include <uk/plat/common/efi.h>

/* As per UEFI specification, the call to the get memory map routine following
 * the dummy one, must have a surplus amount of memory region descriptors in
 * size. Usually, 2 to 4 is enough, but allocate 10, just in case. We do not
 * care afterwards anyway.
 */
#define UK_EFI_SURPLUS_MEM_DESC_COUNT				10
#define uk_efi_crash(str)  ukplat_crash()

uk_efi_sys_tab_t *uk_efi_st;
uk_efi_runtime_services_t *uk_efi_rs;
uk_efi_boot_services_t *uk_efi_bs;
uk_efi_hndl_t uk_efi_sh;

static uk_efi_uintn_t uk_efi_map_key;

static inline void uk_efi_cls()
{
	uk_efi_st->con_out->clear_screen(uk_efi_st->con_out);
}

static inline void uk_efi_init_vars(uk_efi_hndl_t self_hndl,
				    uk_efi_sys_tab_t *sys_tab)
{
	uk_efi_st = sys_tab;
	uk_efi_bs = sys_tab->boot_services;
	uk_efi_rs = sys_tab->runtime_services;
	uk_efi_sh = self_hndl;
}

static inline void uk_efi_md_to_bi_mrd(uk_efi_mem_desc_t *const md,
				       struct ukplat_memregion_desc *const mrd)
{
	mrd->pbase = md->physical_start;
	mrd->vbase = mrd->pbase;
	mrd->len = md->number_of_pages * UK_EFI_PAGE_SIZE;

	switch (md->type) {
        case UK_EFI_RESERVED_MEMORY_TYPE:
	case UK_EFI_ACPI_RECLAIM_MEMORY:
	case UK_EFI_RUNTIME_SERVICES_CODE:
	case UK_EFI_RUNTIME_SERVICES_DATA:
	case UK_EFI_UNUSABLE_MEMORY:
	case UK_EFI_ACPI_MEMORY_NVS:
	case UK_EFI_MEMORY_MAPPED_IO:
	case UK_EFI_MEMORY_MAPPED_IO_PORT_SPACE:
	case UK_EFI_PAL_CODE:
	case UK_EFI_PERSISTENT_MEMORY:
		mrd->type = UKPLAT_MEMRT_RESERVED;

		mrd->flags = UKPLAT_MEMRF_READ | UKPLAT_MEMRF_MAP;

		break;
        case UK_EFI_LOADER_CODE:
		mrd->type = UKPLAT_MEMRT_KERNEL;

		mrd->flags = UKPLAT_MEMRF_READ | UKPLAT_MEMRF_EXECUTE;

		break;
	case UK_EFI_LOADER_DATA:
		mrd->type = UKPLAT_MEMRT_KERNEL;

		mrd->flags = UKPLAT_MEMRF_READ | UKPLAT_MEMRF_WRITE;

		break;
	case UK_EFI_BOOT_SERVICES_CODE:
	case UK_EFI_BOOT_SERVICES_DATA:
	case UK_EFI_CONVENTIONAL_MEMORY:
		mrd->type = UKPLAT_MEMRT_FREE;

		mrd->flags = UKPLAT_MEMRF_READ | UKPLAT_MEMRF_WRITE;

		break;
	}
}

static void uk_efi_get_mmap(uk_efi_mem_desc_t **map, uk_efi_uintn_t *map_sz,
			    uk_efi_uintn_t *desc_sz)
{
	uk_efi_status_t status;
	__u32 desc_ver;

	/* As the UEFI Spec says:
	 * If the MemoryMap buffer is too small, the EFI_BUFFER_TOO_SMALL
	 * error code is returned and the MemoryMapSize value contains the
	 * size of the buffer needed to contain the current memory map. The
	 * actual size of the buffer allocated for the consequent call to
	 * GetMemoryMap() should be bigger then the value returned in
	 * MemoryMapSize, since allocation of the new buffer may potentially
	 * increase memory map size.
	 */
	*map_sz = 0;  /* force EFI_BUFFER_TOO_SMALL */
	*map = NULL;
	status = uk_efi_bs->get_memory_map(map_sz, *map, &uk_efi_map_key,
					   desc_sz, &desc_ver);
	if (status != UK_EFI_BUFFER_TOO_SMALL)
		uk_efi_crash("Failed to call initial dummy get_memory_map\n");

	/* Make sure the actual allocated buffer is bigger */
	*map_sz += *desc_sz * UK_EFI_SURPLUS_MEM_DESC_COUNT;
	status = uk_efi_bs->allocate_pool(UK_EFI_LOADER_DATA, *map_sz,
					  (void **)map);
	if (status != UK_EFI_SUCCESS)
		uk_efi_crash("Failed to allocate memory for map\n");

	status = uk_efi_bs->get_memory_map(map_sz, *map, &uk_efi_map_key,
					   desc_sz, &desc_ver);
	if (status != UK_EFI_SUCCESS)
		uk_efi_crash("Failed to get memory map\n");
}

/* We want a criteria based on which we decide which memory region to keep
 * or split or discard when coalescing.
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

/* Memory region with lower priority must be adjusted in favor of the one with
 * with higher priority
 */
static inline void overlapping_mrd_fixup(struct ukplat_memregion_desc *const ml,
					 struct ukplat_memregion_desc *const mr,
					 int ml_prio, int mr_prio)
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
		}

	/* If left memory region is of lower priority */
	} else {
		/* If the left memory region is contained within the right
		 * region, drop it entirely
		 */
		if (RANGE_CONTAIN(mr->pbase, mr->len, ml->pbase, ml->len)) {
			ml->len = 0;

		/* If the left region has a part of itself in the right region,
		 * drop that part of the left region only
		 */
		} else {
			ml->len = ml->pbase + ml->len - mr->pbase;
		}
	}
}

static void uk_efi_coalesce_bi_mrds(struct ukplat_memregion_list *const mrds)
{
	struct ukplat_memregion_desc *m, *ml, *mr;
	int ml_prio, mr_prio;
	__u32 i;

	i = 0;
	m = mrds->mrds;
	while (i + 1 < mrds->count) {
		/* Make sure first that they are ordered. If not, swap them */
		if (m[i].pbase > m[i + 1].pbase) {
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
				overlapping_mrd_fixup(ml, mr, ml_prio, mr_prio);

				/* Remove dropped regions */
				if (ml->len == 0)
					ukplat_memregion_list_delete(mrds, i);
				else if (mr->len == 0)
					ukplat_memregion_list_delete(mrds,
								     i + 1);
				else
					i++;

			} else if (ml->flags != mr->flags) {
				uk_efi_crash("Found overlapping memory "
						     "regions with different "
						     "permission flags");

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
					ukplat_memregion_list_delete(mrds, i);

					continue;

				/* If the right region is contained within the
				 * left region, drop it
				 */
				} else if (RANGE_CONTAIN(ml->pbase, ml->len,
					                 mr->pbase, mr->len)) {
					ukplat_memregion_list_delete(mrds,
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
				ukplat_memregion_list_delete(mrds, i + 1);
			}

		/* If they do not overlap but they are contiguous and have the
		 * same flags and priority.
		 */
		} else if (ml->pbase + ml->len == mr->pbase &&
			   ml_prio == mr_prio && ml->flags == mr->flags) {
			ml->len += mr->len;
			ukplat_memregion_list_delete(mrds, i + 1);
			i++;
		} else {
			i++;
		}
	}
}


static void uk_efi_setup_bootinfo_mrds(struct ukplat_bootinfo *const bi)
{
	uk_efi_mem_desc_t *map_start, *map_end, *md;
	struct ukplat_memregion_desc mrd = {0};
	uk_efi_uintn_t map_sz, desc_sz;

	uk_efi_get_mmap(&map_start, &map_sz, &desc_sz);

	map_end = (struct uk_efi_mem_desc *)((__u8 *)map_start + map_sz);
	for (md = map_start; md < map_end;
	     md = (struct uk_efi_mem_desc *)((__u8 *)md + desc_sz)) {
		if (md->physical_start <= 0x100000)
			continue;

		uk_efi_md_to_bi_mrd(md, &mrd);

		ukplat_memregion_list_insert(&bi->mrds,  &mrd);
	}

	uk_efi_coalesce_bi_mrds(&bi->mrds);
}

static void uk_efi_setup_bootinfo()
{
	struct ukplat_bootinfo *bi;
	const char *const bl = "UK_EFI_STUB";
	const char *const bp = "EFI";

	bi = ukplat_bootinfo_get();
	if (unlikely(!bi))
		uk_efi_crash("Failed to get bootinfo\n");

	uk_efi_bs->copy_mem(bi->bootloader, bl, sizeof(bl));

	uk_efi_bs->copy_mem(bi->bootprotocol, bp, sizeof(bp));

	uk_efi_setup_bootinfo_mrds(bi);
}

static inline void uk_efi_exit_bs()
{
	uk_efi_status_t status;

	status = uk_efi_bs->exit_boot_services(uk_efi_sh, uk_efi_map_key);
	if (status != UK_EFI_SUCCESS)
		uk_efi_crash("Failed to handle loaded image protocol\n");
}

uk_efi_status_t __uk_efi_api uk_efi_main(uk_efi_hndl_t self_hndl,
					 uk_efi_sys_tab_t *sys_tab)
{
	uk_efi_init_vars(self_hndl, sys_tab);

	uk_efi_cls();

	uk_efi_setup_bootinfo();

	uk_efi_exit_bs();

	return uk_efi_jmp_to_kern();
}
