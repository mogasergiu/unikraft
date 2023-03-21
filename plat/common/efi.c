#include <uk/plat/common/bootinfo.h>
#include <uk/plat/common/efi.h>

/* As per UEFI specification, the call to the get memory map routine following
 * the dummy one, must have a surplus amount of memory region descriptors in
 * size. Usually, 2 to 4 is enough, but allocate 10, just in case. We do not
 * care afterwards anyway.
 */
#define UK_EFI_SURPLUS_MEM_DESC_COUNT				10
#define uk_efi_crash(str)					ukplat_crash()

/* For x86 we must make sure that no zone below the 1MiB ends up in the memory
 * region descriptors list. If a memory region happens to have a part below it
 * as well as above it, keep only what is above.
 */
#if defined(__X86_64__)
#define MiB1							0x100000
static inline void x86_adjust_below_1MiB(uk_efi_mem_desc_t *md) {
	__sz len;

	len = md->number_of_pages * UK_EFI_PAGE_SIZE;
	if (md->physical_start < MiB1)
		if (md->physical_start + len > MiB1) {
			len -= MiB1 - md->physical_start;
			md->physical_start = MiB1;
		} else {
			len = 0;
		}

	md->number_of_pages = len / UK_EFI_PAGE_SIZE;
}
#endif

static inline void uk_efi_arch_adjust_md(uk_efi_mem_desc_t *md)
{
#if defined(__X86_64__)
	x86_adjust_below_1MiB(md);
#endif
}

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

static void uk_efi_md_to_bi_mrd(uk_efi_mem_desc_t *const md,
				 struct ukplat_memregion_desc *const mrd)
{
	uk_efi_arch_adjust_md(md);
	if (!md->number_of_pages)
		return;

	switch (md->type) {
	case UK_EFI_RESERVED_MEMORY_TYPE:
	case UK_EFI_ACPI_RECLAIM_MEMORY:
	case UK_EFI_UNUSABLE_MEMORY:
	case UK_EFI_ACPI_MEMORY_NVS:
	case UK_EFI_MEMORY_MAPPED_IO:
	case UK_EFI_MEMORY_MAPPED_IO_PORT_SPACE:
	case UK_EFI_PAL_CODE:
	case UK_EFI_PERSISTENT_MEMORY:
		mrd->type = UKPLAT_MEMRT_RESERVED;

		mrd->flags = UKPLAT_MEMRF_READ | UKPLAT_MEMRF_MAP;

		break;
	case UK_EFI_RUNTIME_SERVICES_CODE:
	case UK_EFI_RUNTIME_SERVICES_DATA:
		/* Already added */
		mrd->len = 0;

		return;
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

	mrd->pbase = md->physical_start;
	mrd->vbase = mrd->pbase;
	mrd->len = md->number_of_pages * UK_EFI_PAGE_SIZE;
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

static void uk_efi_rt_md_to_bi_mrds(struct ukplat_memregion_desc **const rt_mrds,
				    __u32 *const rt_mrds_count)
{
	struct ukplat_memregion_desc *rt_mrd;
	uk_efi_mem_attr_tab_t *mat;
	uk_efi_mem_desc_t *mat_md;
	uk_efi_status_t status;
	uk_efi_cfg_tab_t *ct;
	uk_efi_uintn_t i;
	__sz desc_sz;

	for (i = 0; i < uk_efi_st->number_of_table_entries; i++) {
		ct = &uk_efi_st->configuration_table[i];

		if (!memcmp(&ct->vendor_guid,
			    UK_EFI_MEMORY_ATTRIBUTES_TABLE_GUID,
			    sizeof(ct->vendor_guid))) {
			mat = ct->vendor_table;
			break;
		}
	}

	if (!mat)
		uk_efi_crash("Could not find Memory Attribute Table.");

	desc_sz = mat->descriptor_size;
	status = uk_efi_bs->allocate_pool(UK_EFI_LOADER_DATA,
					  mat->number_of_entries * desc_sz,
					  (void **)rt_mrds);
	if (status != UK_EFI_SUCCESS)
		uk_efi_crash("Failed to allocate memory for Memory Sub-region"
			     "Descriptors.\n");

	*rt_mrds_count = 0;
	mat_md = (uk_efi_mem_desc_t *)mat->entry;
	for (i = 0; i < mat->number_of_entries; i++) {
		if (!(mat_md->attribute & UK_EFI_MEMORY_RUNTIME))
			continue;

		uk_efi_arch_adjust_md(mat_md);
		if (!mat_md->number_of_pages)
			continue;

		rt_mrd = *rt_mrds + *rt_mrds_count;
		rt_mrd->pbase = mat_md->physical_start;
		rt_mrd->len = mat_md->number_of_pages * UK_EFI_PAGE_SIZE;
		rt_mrd->vbase = rt_mrd->pbase;
		rt_mrd->type = UKPLAT_MEMRT_RESERVED;
		rt_mrd->flags = UKPLAT_MEMRF_READ | UKPLAT_MEMRF_MAP;
		if (mat_md->attribute & UK_EFI_MEMORY_XP)
			rt_mrd->flags |= UKPLAT_MEMRF_EXECUTE;

		(*rt_mrds_count)++;
		mat_md = (uk_efi_mem_desc_t *)((__u8 *)mat_md + desc_sz);
	}
}

static void uk_efi_setup_bootinfo_mrds(struct ukplat_bootinfo *const bi)
{
	struct ukplat_memregion_desc mrd = {0}, *rt_mrds;
	uk_efi_mem_desc_t *map_start, *map_end, *md;
	uk_efi_uintn_t map_sz, desc_sz;
	uk_efi_status_t status;
	__u32 rt_mrds_count, i;

	uk_efi_rt_md_to_bi_mrds(&rt_mrds, &rt_mrds_count);
	for (i = 0; i < rt_mrds_count; i++)
		ukplat_memregion_list_insert(&bi->mrds, &rt_mrds[i]);

	status = uk_efi_bs->free_pool(rt_mrds);
	if (status != UK_EFI_SUCCESS)
		uk_efi_crash("Failed to free rt_mrds.");

	uk_efi_get_mmap(&map_start, &map_sz, &desc_sz);

	map_end = (struct uk_efi_mem_desc *)((__u8 *)map_start + map_sz);
	for (md = map_start; md < map_end;
	     md = (struct uk_efi_mem_desc *)((__u8 *)md + desc_sz)) {
		uk_efi_md_to_bi_mrd(md, &mrd);
		if (!mrd.len)
			continue;

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
