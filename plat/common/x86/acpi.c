/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Authors: Cristian Vijelie <cristianvijelie@gmail.com>
 *
 * Copyright (c) 2021, University POLITEHNICA of Bucharest. All rights reserved.
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
 *
 */

#include <uk/print.h>
#include <uk/assert.h>
#include <x86/acpi/acpi.h>
#include <string.h>
#include <errno.h>
#include <kvm/efi.h>
#include <uk/plat/common/bootinfo.h>

#define RSDP10_LEN		20
#define EBDA_START		0xE0000UL
#define EBDA_END		0xFFFFFUL
#define EBDA_STEP		16

static struct acpi_madt *acpi_madt;
static __u8 acpi_rsdt_entries;
static void *acpi_rsdt;
static __u8 acpi10;

static inline __paddr_t get_rsdt_entry(int idx)
{
	__u8 *entryp = (__u8 *)acpi_rsdt + sizeof(struct acpi_sdt_hdr);
	if (acpi10)
		return ((__u32 *)entryp)[idx];

	return ((__u64 *)entryp)[idx];
}

int acpi_get_table(const char *const signature, void * *const tbl)
{
	int i;
	struct acpi_sdt_hdr *h;

	UK_ASSERT(acpi_rsdt);

	for (i = 0; i < acpi_rsdt_entries; i++) {
		h = (struct acpi_sdt_hdr *)get_rsdt_entry(i);

		if (!memcmp(h->signature, signature, ACPI_SDT_SIGNATURE_LEN)) {
			if (get_acpi_checksum(h, h->tab_len) != 0) {

				uk_pr_err("ACPI %s corrupted\n", signature);

				return -ENOENT;
			}

			*tbl = h;

			return 0;
		}
	}

	return -ENOENT;
}

/*
 * Print the detected ACPI tables to the debug output.
 */
#ifdef UK_DEBUG
static void acpi_list_tables(void)
{
	int i;
	struct acpi_sdt_hdr *h;

	UK_ASSERT(acpi_rsdt);

	uk_pr_debug("%d ACPI tables found\n", acpi_rsdt_entries);
	for (i = 0; i < acpi_rsdt_entries; i++) {
		h = (struct acpi_sdt_hdr *)get_rsdt_entry(i);
		uk_pr_debug("%p: %.4s\n", h, h->signature);
	}
}
#endif /* UK_DEBUG */

static struct acpi_rsdp *get_efi_st_rsdp()
{
	struct ukplat_bootinfo *bi = ukplat_bootinfo_get();
	uk_efi_uintn_t ct_count, i;
	struct acpi_rsdp *rsdp;
	uk_efi_cfg_tab_t *ct;

	UK_ASSERT(bi);

	if (!bi->efi_st)
		return NULL;

	ct = ((uk_efi_sys_tab_t *)bi->efi_st)->configuration_table;
	ct_count = ((uk_efi_sys_tab_t *)bi->efi_st)->number_of_table_entries;

	UK_ASSERT(ct);
	UK_ASSERT(ct_count);

	rsdp = NULL;
	for (i = 0; i < ct_count; i++)
		if (!memcmp(&ct[i].vendor_guid, UK_EFI_ACPI20_TABLE_GUID,
			    sizeof(ct[i].vendor_guid)))
			return ct[i].vendor_table;
		else if (!memcmp(&ct[i].vendor_guid, UK_EFI_ACPI10_TABLE_GUID,
				 sizeof(ct[i].vendor_guid)))
			rsdp = ct[i].vendor_table;

	return rsdp;
}

static struct acpi_rsdp *get_bios_rom_rsdp()
{
	__paddr_t ptr;

	for (ptr = EBDA_START; ptr < EBDA_END; ptr += EBDA_STEP)
		if (!memcmp((void *)ptr, RSDP_SIGNATURE,
			     sizeof(RSDP_SIGNATURE) - 1)) {
			uk_pr_debug("ACPI RSDP present at %lx\n", ptr);

			return (struct acpi_rsdp *)ptr;
		}

	return NULL;
}

static struct acpi_rsdp *get_rsdp()
{
	struct acpi_rsdp *rsdp;

	rsdp = get_efi_st_rsdp();
	if (rsdp)
		return rsdp;

	return get_bios_rom_rsdp();
}

/*
 * Detect ACPI version and discover ACPI tables.
 */
int acpi_init(void)
{
	struct acpi_rsdp *rsdp;
	struct acpi_sdt_hdr *h;
	int ret;

	rsdp = get_rsdp();
	if (unlikely(!rsdp))
		return -ENOENT;

	if (get_acpi_checksum(rsdp, RSDP10_LEN) != 0) {
		uk_pr_err("ACPI1.0 RSDP corrupted\n");

		return -ENOENT;
	}

	if (rsdp->revision == 0) {
		h = (struct acpi_sdt_hdr *)((__uptr)rsdp->rsdt_paddr);
		acpi_rsdt_entries = (h->tab_len - sizeof(*h)) / 4;
		acpi10 = 1;
	} else {
		if (get_acpi_checksum(rsdp, sizeof(*rsdp)) != 0) {
			uk_pr_err("ACPI1.0 RSDP corrupted\n");

			return -ENOENT;
		}

		h = (struct acpi_sdt_hdr *)rsdp->xsdt_paddr;
		acpi_rsdt_entries = (h->tab_len - sizeof(*h)) / 8;
	}

	UK_ASSERT(h);

	if (unlikely(get_acpi_checksum(h, h->tab_len) != 0)) {
		uk_pr_err("ACPI RSDT corrupted\n");

		return -ENOENT;
	}

	acpi_rsdt = h;

	ret = acpi_get_table(ACPI_MADT_SIGNATURE, (void **const)&acpi_madt);
	if (unlikely(ret < 0) || unlikely(!acpi_madt))
		return ret;

#ifdef UK_DEBUG
	acpi_list_tables();
#endif

	return 0;
}


/*
 * Return the Multiple APIC Descriptor Table (MADT).
 */
struct acpi_madt *acpi_get_madt(void)
{
	UK_ASSERT(acpi_madt);

	return acpi_madt;
}
