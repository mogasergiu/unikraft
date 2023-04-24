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

#ifndef __PLAT_CMN_X86_ACPI_H__
#define __PLAT_CMN_X86_ACPI_H__

#include <x86/acpi/sdt.h>
#include <x86/acpi/madt.h>

struct acpi_rsdp {
	char signature[8];
	__u8 checksum;
	char oem_id[ACPI_OEM_ID_LEN];
	__u8 revision;
	__u32 rsdt_paddr;
	__u32 tab_len;
	__u64 xsdt_paddr;
	__u8 xchecksum;
	__u8 reserved[3];
} __packed;

/**
 * Check an ACPI structure against its checksum
 *
 * @param buf
 *   The pointer to the ACPI structure
 * @param len
 *   The size of the ACPI structure
 *
 * @return
 *   0 on correct checksum, != 0 otherwise
 */
static inline __u8 get_acpi_checksum(void *const buf, const __sz len)
{
	const __u8 *const ptr_end = (__u8 *)buf + len;
	const __u8 *ptr = (__u8 *)buf;
	__u8 checksum = 0;

	while (ptr < ptr_end)
		checksum += *ptr++;

	return checksum;
}

/**
 * Detect ACPI version and discover ACPI tables.
 *
 * @return 0 on success, -errno otherwise.
 */
int acpi_init(void);

/**
 * Return the detected ACPI version.
 *
 * @return 0 if ACPI is not initialized or initialization failed, ACPI version
 *    otherwise.
 */
int acpi_get_version(void);

#endif /* __PLAT_CMN_X86_ACPI_H__ */
