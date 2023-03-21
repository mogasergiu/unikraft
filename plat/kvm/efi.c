/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2023, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */
#include <kvm/efi.h>
#include <uk/plat/common/bootinfo.h>

uk_efi_runtime_services_t *uk_efi_rs;
uk_efi_boot_services_t *uk_efi_bs;
uk_efi_sys_tab_t *uk_efi_st;
uk_efi_hndl_t uk_efi_sh;

static uk_efi_uintn_t uk_efi_map_key;

/* As per UEFI specification, the call to the GetMemoryMap routine following
 * the dummy one, must have a surplus amount of memory region descriptors in
 * size. Usually, 2 to 4 is enough, but allocate 10, just in case.
 */
#define UK_EFI_SURPLUS_MEM_DESC_COUNT				10

void uk_efi_jmp_to_kern(void) __noreturn;

/* Overlysimplified conversion from ASCII to UTF-16 */
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

/* Overlysimplified conversion from UTF-16 to ASCII */
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

static inline void _uk_efi_crash(void)
{
	const char reset_data[] = "UK EFI SYSTEM CRASH";

	uk_efi_rs->reset_system(UK_EFI_RESET_SHUTDOWN, UK_EFI_SUCCESS,
				sizeof(reset_data), (void *)reset_data);
}

#ifdef CONFIG_KVM_BOOT_EFI_STUB_DEBUG
#define UK_EFI_MAX_CRASH_STR_LEN				256
/* UEFI for proper \n, we must also use CRLF */
#define uk_efi_crash(str)							\
	do {									\
		__s16 str16[UK_EFI_MAX_CRASH_STR_LEN];				\
										\
		ascii_to_utf16("[uk_efi]: "str"\r", (char *)str16);		\
		uk_efi_st->con_out->output_string(uk_efi_st->con_out, str16);	\
		_uk_efi_crash();						\
	} while (0)
#else
#define uk_efi_crash(str)					_uk_efi_crash()
#endif

static inline void uk_efi_cls()
{
	uk_efi_st->con_out->clear_screen(uk_efi_st->con_out);
}

/* Initialize global variables */
static inline void uk_efi_init_vars(uk_efi_hndl_t self_hndl,
				    uk_efi_sys_tab_t *sys_tab)
{
	uk_efi_st = sys_tab;
	uk_efi_bs = sys_tab->boot_services;
	uk_efi_rs = sys_tab->runtime_services;
	uk_efi_sh = self_hndl;
}

/* Convert an EFI Memory Descriptor to a ukplat_memregion_desc */
static int uk_efi_md_to_bi_mrd(uk_efi_mem_desc_t *const md,
			       struct ukplat_memregion_desc *const mrd)
{
	__paddr_t start, end;

	switch (md->type) {
	case UK_EFI_RESERVED_MEMORY_TYPE:
	case UK_EFI_ACPI_RECLAIM_MEMORY:
	case UK_EFI_UNUSABLE_MEMORY:
	case UK_EFI_ACPI_MEMORY_NVS:
	case UK_EFI_PAL_CODE:
	case UK_EFI_PERSISTENT_MEMORY:
		mrd->type = UKPLAT_MEMRT_RESERVED;
		mrd->flags = UKPLAT_MEMRF_READ | UKPLAT_MEMRF_MAP;

		break;
	case UK_EFI_MEMORY_MAPPED_IO:
	case UK_EFI_MEMORY_MAPPED_IO_PORT_SPACE:
		mrd->type = UKPLAT_MEMRT_RESERVED;
		mrd->flags = UKPLAT_MEMRF_READ | UKPLAT_MEMRF_WRITE |
			     UKPLAT_MEMRF_MAP;

		break;
	case UK_EFI_RUNTIME_SERVICES_CODE:
	case UK_EFI_RUNTIME_SERVICES_DATA:
		/* Already added through uk_efi_rt_md_to_bi_mrds() */
		return -EEXIST;
	case UK_EFI_LOADER_CODE:
	case UK_EFI_LOADER_DATA:
		/* Already added through mkbootinfo.py and relocated through
		 * do_ukreloc
		 */
		return -EEXIST;
	case UK_EFI_BOOT_SERVICES_CODE:
	case UK_EFI_BOOT_SERVICES_DATA:
	case UK_EFI_CONVENTIONAL_MEMORY:
		/* These are freed after ExitBootServices is called */
		mrd->type = UKPLAT_MEMRT_FREE;

		mrd->flags = UKPLAT_MEMRF_READ | UKPLAT_MEMRF_WRITE;

		break;
	}

	/* Ignore zero-page */
	start = MAX(md->physical_start, __PAGE_SIZE);
	end = md->physical_start + md->number_of_pages * UK_EFI_PAGE_SIZE;
	if (unlikely(end <= start || end - start < __PAGE_SIZE))
		return -ENOMEM;

	mrd->pbase = start;
	mrd->vbase = start;
	mrd->len = end - start;

	return 0;
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
	if (unlikely(status != UK_EFI_BUFFER_TOO_SMALL))
		uk_efi_crash("Failed to call initial dummy get_memory_map\n");

	/* Make sure the actual allocated buffer is bigger */
	*map_sz += *desc_sz * UK_EFI_SURPLUS_MEM_DESC_COUNT;
	status = uk_efi_bs->allocate_pool(UK_EFI_LOADER_DATA, *map_sz,
					  (void **)map);
	if (unlikely(status != UK_EFI_SUCCESS))
		uk_efi_crash("Failed to allocate memory for map\n");

	/* Now we call it for real */
	status = uk_efi_bs->get_memory_map(map_sz, *map, &uk_efi_map_key,
					   desc_sz, &desc_ver);
	if unlikely((status != UK_EFI_SUCCESS))
		uk_efi_crash("Failed to get memory map\n");
}

/* Runtime Services memory regions in the Memory Attribute Table have a higher
 * granularity regarding sizes and permissions: the ones resulted from
 * GetMemoryMap only differentiate between Runtime Services Data/Code, while
 * the MAT also differentiates between permissions of the Runtime Services'
 * PE sections (Runtime Services can basically be thought of as loaded Portable
 * Executable format drivers).
 */
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

	/* Search for the MAT in UEFI System Table's Configuration Tables */
	for (i = 0; i < uk_efi_st->number_of_table_entries; i++) {
		ct = &uk_efi_st->configuration_table[i];

		if (!memcmp(&ct->vendor_guid,
			    UK_EFI_MEMORY_ATTRIBUTES_TABLE_GUID,
			    sizeof(ct->vendor_guid))) {
			mat = ct->vendor_table;
			break;
		}
	}
	if (unlikely(!mat))
		uk_efi_crash("Could not find Memory Attribute Table\n");

	desc_sz = mat->descriptor_size;
	*rt_mrds_count = mat->number_of_entries;
	status = uk_efi_bs->allocate_pool(UK_EFI_LOADER_DATA,
					  *rt_mrds_count * sizeof(**rt_mrds),
					  (void **)rt_mrds);
	if (unlikely(status != UK_EFI_SUCCESS))
		uk_efi_crash("Failed to allocate memory for Memory Sub-region"
			     "Descriptors\n");

	/* Convert the EFI Runtime Services Memory descriptors to
	 * ukplat_memregion_desc's
	 */
	mat_md = (uk_efi_mem_desc_t *)mat->entry;
	for (i = 0; i < *rt_mrds_count; i++) {
		if (!(mat_md->attribute & UK_EFI_MEMORY_RUNTIME))
			continue;

		rt_mrd = *rt_mrds + i;
		rt_mrd->pbase = mat_md->physical_start;
		rt_mrd->len = mat_md->number_of_pages * UK_EFI_PAGE_SIZE;
		rt_mrd->vbase = rt_mrd->pbase;
		rt_mrd->type = UKPLAT_MEMRT_RESERVED;
		rt_mrd->flags = UKPLAT_MEMRF_MAP;
		if (mat_md->attribute & UK_EFI_MEMORY_XP)
			if (mat_md->attribute & UK_EFI_MEMORY_RO)
				rt_mrd->flags |= UKPLAT_MEMRF_READ;
			else
				rt_mrd->flags |= UKPLAT_MEMRF_READ |
						 UKPLAT_MEMRF_WRITE;
		else
			rt_mrd->flags |= UKPLAT_MEMRF_READ |
					 UKPLAT_MEMRF_EXECUTE;

		mat_md = (uk_efi_mem_desc_t *)((__u8 *)mat_md + desc_sz);
	}
}

static void uk_efi_setup_bootinfo_mrds(struct ukplat_bootinfo *bi)
{
	struct ukplat_memregion_desc mrd = {0}, *rt_mrds;
	uk_efi_mem_desc_t *map_start, *map_end, *md;
	uk_efi_uintn_t map_sz, desc_sz;
	uk_efi_status_t status;
	__u32 rt_mrds_count, i;
	int rc;

#if defined(__X86_64__)
	rc = ukplat_memregion_list_insert_legacy_hi_mem(&bi->mrds);
	if (unlikely(rc < 0))
		uk_efi_crash("Failed to insert legacy high memory region\n");
#endif

	/* Fetch the Runtime Services memory regions from the MAT */
	uk_efi_rt_md_to_bi_mrds(&rt_mrds, &rt_mrds_count);
	for (i = 0; i < rt_mrds_count; i++) {
		rc = ukplat_memregion_list_insert(&bi->mrds, &rt_mrds[i]);
		if (unlikely(rc < 0))
			uk_efi_crash("Failed to insert rt_mrd\n");
	}

	/* We no longer need the list of Runtime Services memory regions */
	status = uk_efi_bs->free_pool(rt_mrds);
	if (unlikely(status != UK_EFI_SUCCESS))
		uk_efi_crash("Failed to free rt_mrds\n");

	/* Get memory map through GetMemoryMap */
	uk_efi_get_mmap(&map_start, &map_sz, &desc_sz);

	map_end = (struct uk_efi_mem_desc *)((__u8 *)map_start + map_sz);
	for (md = map_start; md < map_end;
	     md = (struct uk_efi_mem_desc *)((__u8 *)md + desc_sz)) {
		if (uk_efi_md_to_bi_mrd(md, &mrd) < 0)
			continue;

		rc = ukplat_memregion_list_insert(&bi->mrds,  &mrd);
		if (unlikely(rc < 0))
			uk_efi_crash("Failed to insert mrd\n");
	}

	ukplat_memregion_list_coalesce(&bi->mrds);

#if defined(__X86_64__)
	ukplat_memregion_alloc_sipi_vect(&bi->mrds);
#endif
}

static void uk_efi_setup_bootinfo(void)
{
	struct ukplat_bootinfo *bi;
	const char bl[] = "EFI_STUB";
	const char bp[] = "EFI";

	bi = ukplat_bootinfo_get();
	if (unlikely(!bi))
		uk_efi_crash("Failed to get bootinfo\n");

	memcpy(bi->bootloader, bl, sizeof(bl));
	memcpy(bi->bootprotocol, bp, sizeof(bp));

	uk_efi_setup_bootinfo_mrds(bi);

	bi->efi_st = (__u64)uk_efi_st;
}

static inline void uk_efi_exit_bs(void)
{
	uk_efi_status_t status;

	status = uk_efi_bs->exit_boot_services(uk_efi_sh, uk_efi_map_key);
	if (unlikely(status != UK_EFI_SUCCESS))
		uk_efi_crash("Failed to to exit Boot Services\n");
}

void __uk_efi_api __noreturn uk_efi_main(uk_efi_hndl_t self_hndl,
					 uk_efi_sys_tab_t *sys_tab)
{
	uk_efi_init_vars(self_hndl, sys_tab);
	uk_efi_cls();
	uk_efi_setup_bootinfo();
	uk_efi_exit_bs();

	/* Jump to arch specific post-EFI entry */
	uk_efi_jmp_to_kern();
}
