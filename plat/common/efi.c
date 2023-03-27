#include <uk/plat/common/bootinfo.h>
#include <uk/plat/common/efi.h>

/* As per UEFI specification, the call to the get memory map routine following
 * the dummy one, must have a surplus amount of memory region descriptors in
 * size. Usually, 2 to 4 is enough, but allocate 10, just in case. We do not
 * care afterwards anyway.
 */
#define UK_EFI_MAXPATHLEN					4096
#define UK_EFI_SURPLUS_MEM_DESC_COUNT				10

#define uk_efi_crash(str)  ukplat_crash()

uk_efi_sys_tab_t *uk_efi_st;
uk_efi_runtime_services_t *uk_efi_rs;
uk_efi_boot_services_t *uk_efi_bs;
uk_efi_hndl_t uk_efi_sh;

static uk_efi_uintn_t uk_efi_map_key;

static inline __sz ascii_to_utf16(const char *str, char *str16)
{
	__sz i = 0;

	while (str[i >> 1]) {
		str16[i] = str[i >> 1];
		str16[i + 1] = '\0';
		i += 2;
	}

	str16[i] = str16[i + 1] = '\0';

	return i + 2;
}

static inline __sz utf16_to_ascii(const char *str16, char *str)
{
	__sz i = 0;

	while (*str16) {
		str[i++] = *str16;
		str16 += 2;
	}

	str[i] = '\0';

	return i + 1;
}

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

			/* If they are of the same priority and different flags,
			 * it either means that is one of our manually
			 * introduced memory region descriptors for commandline
			 * or initrd or devicetree or stack, which have the same
			 * priority as the kernel type memory region descriptor,
			 * which got automatically added by uk_efi_md_to_bi_mrd
			 * as UKPLAT_MEMRT_KERNEL since it was allocated as
			 * UK_EFI_LOADER_DATA, or it could be something abnormal,
			 * in which case we will crash the application. For the
			 * former case, we choose to keep the manually inserted
			 * memory region descriptor, since its type is more
			 * specific.
			 */
			} else if (ml->flags != mr->flags) {
				if (ml->type == UKPLAT_MEMRT_KERNEL)
					ukplat_memregion_list_delete(mrds, i);
				else if (mr->type == UKPLAT_MEMRT_KERNEL)
					ukplat_memregion_list_delete(mrds,
								     i + 1);
				else
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

static uk_efi_ld_img_hndl_t* uk_efi_get_uk_img_hndl()
{
	static uk_efi_ld_img_hndl_t *uk_img_hndl;
	uk_efi_status_t status;

	if (uk_img_hndl)
		return uk_img_hndl;

	status = uk_efi_bs->handle_protocol(uk_efi_sh,
					    UK_EFI_LOADED_IMAGE_PROTOCOL_GUID,
					    (void **)&uk_img_hndl);
	if (status != UK_EFI_SUCCESS)
		uk_efi_crash("Failed to handle loaded image protocol\n");

	return uk_img_hndl;
}

static void uk_efi_read_file(uk_efi_hndl_t dev_h, const char *const file_name,
			     char **buf, __sz *len)
{
	uk_efi_file_prot_t *volume, *file_hndl;
	__s16 file_name16[UK_EFI_MAXPATHLEN];
	uk_efi_simple_fs_prot_t *sfs_prot;
	uk_efi_file_info_id_t *file_info;
	__sz len16, file_info_len;
	uk_efi_status_t status;

	status = uk_efi_bs->handle_protocol(dev_h,
					    UK_EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID,
					    &sfs_prot);
	if (status != UK_EFI_SUCCESS)
		uk_efi_crash("Failed to handle Simple Filesystem Protocol.");

	status = sfs_prot->open_volume(sfs_prot, &volume);
	if (status != UK_EFI_SUCCESS)
		uk_efi_crash("Failed to open Volume.");

	len16 = ascii_to_utf16(file_name, (char *)file_name16);
	if (len16 > UK_EFI_MAXPATHLEN)
		uk_efi_crash("File path too long.");

	status = volume->open(volume, &file_hndl, file_name16,
			      UK_EFI_FILE_MODE_READ,
			      UK_EFI_FILE_READ_ONLY | UK_EFI_FILE_HIDDEN);
	if (status != UK_EFI_SUCCESS)
		uk_efi_crash("Failed to open file.");

	file_info_len = 0;
	file_info = NULL;
	status = file_hndl->get_info(file_hndl, UK_EFI_FILE_INFO_ID_GUID,
				     &file_info_len, file_info);
	if (status != UK_EFI_BUFFER_TOO_SMALL)
		uk_efi_crash("Dummy call to get_info failed.");

	status = uk_efi_bs->allocate_pool(UK_EFI_LOADER_DATA, file_info_len,
					  (void **)&file_info);
	if (status != UK_EFI_SUCCESS)
		uk_efi_crash("Failed to allocate memory for file_info\n");

	status = file_hndl->get_info(file_hndl, UK_EFI_FILE_INFO_ID_GUID,
				     &file_info_len, file_info);
	if (status != UK_EFI_SUCCESS)
		uk_efi_crash("Failed to get file_info.");

	*len = file_info->file_size;
	status = uk_efi_bs->allocate_pool(UK_EFI_LOADER_DATA, *len + 1,
					  (void **)buf);
	if (status != UK_EFI_SUCCESS)
		uk_efi_crash("Failed to allocate memory for file contents\n");

	status = file_hndl->read(file_hndl, len, *buf);
	if (status != UK_EFI_SUCCESS)
		uk_efi_crash("Failed to read file.");

	status = uk_efi_bs->free_pool(file_info);
	if (status != UK_EFI_SUCCESS)
		uk_efi_crash("Failed to free file_info.");

	(*buf)[*len] = '\0';
}

static void uk_efi_setup_bootinfo_cmdl(struct ukplat_bootinfo *const bi)
{
	struct ukplat_memregion_desc mrd = {0};
	uk_efi_ld_img_hndl_t *uk_img_hndl;
	uk_efi_status_t status;
	char *cmdl;
	__sz len;

	uk_img_hndl = uk_efi_get_uk_img_hndl();

	/* We can either have the command line provided by the user when this
	 * very specific instance of the image was launched, in which case this
	 * one takes priority, or we can have it provided through
	 * CONFIG_UK_EFI_STUB_CMDLINE_PATH as a path on the same device.
	 */
	if (uk_img_hndl->load_options && uk_img_hndl->load_options_size) {
		len = (uk_img_hndl->load_options_size >> 1) + 1;

		status = uk_efi_bs->allocate_pool(UK_EFI_LOADER_DATA, len,
						  (void **)&cmdl);
		if (status != UK_EFI_SUCCESS)
			uk_efi_crash("Failed to allocate memory for cmdl\n");

		/* Update  actual size */
		len = utf16_to_ascii(uk_img_hndl->load_options, cmdl);
	} else {
		if (sizeof(CONFIG_UK_EFI_STUB_CMDLINE_FNAME) <= 1)
			return;

		uk_efi_read_file(uk_img_hndl->device_handle,
				 "\\EFI\\BOOT\\"CONFIG_UK_EFI_STUB_CMDLINE_FNAME,
				 &cmdl, &len);
	}

	mrd.pbase = (__paddr_t) cmdl;
	mrd.vbase = (__vaddr_t) cmdl;
	mrd.len = len;
	mrd.type = UKPLAT_MEMRT_CMDLINE;
	mrd.flags = UKPLAT_MEMRF_READ | UKPLAT_MEMRF_MAP;
	ukplat_memregion_list_insert(&bi->mrds,  &mrd);

	bi->cmdline = (__u64)cmdl;
}

static void uk_efi_setup_bootinfo()
{
	struct ukplat_bootinfo *bi;
	const char *const bl = "UK_EFI_STUB";
	const char *const bp = "EFI";

	bi = ukplat_bootinfo_get();
	if (unlikely(!bi))
		uk_efi_crash("Failed to get bootinfo\n");

	uk_efi_setup_bootinfo_cmdl(bi);

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
