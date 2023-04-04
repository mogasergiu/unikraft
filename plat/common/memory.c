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

#include <uk/plat/memory.h>
#include <uk/plat/common/memory.h>
#include <uk/plat/common/bootinfo.h>
#include <uk/alloc.h>
#include <stddef.h>

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

struct ukplat_memregion_desc *ukplat_memregion_get_initrd0()
{
	static struct ukplat_memregion_desc *initrd0;
	int rc;

	/* Avoid unnecessary lookup for something that does not exist */
	if (initrd0 || !ukplat_bootinfo_have_initrd())
		return initrd0;

	rc = ukplat_memregion_find_next(-1, UKPLAT_MEMRT_INITRD, 0, 0, &initrd0);
	if (unlikely(rc < 0))
		return NULL;

	return initrd0;

}

struct ukplat_memregion_desc *ukplat_memregion_get_dtb()
{
	static struct ukplat_memregion_desc *dtb;
	int rc;

	/* Avoid unnecessary lookup for something that does not exist */
	if (dtb || !ukplat_bootinfo_have_devicetree())
		return dtb;

	rc = ukplat_memregion_find_next(-1, UKPLAT_MEMRT_DEVICETREE,
					0, 0, &dtb);
	if (unlikely(rc < 0))
		return NULL;

	return dtb;

}

struct ukplat_memregion_desc *ukplat_memregion_get_cmdl()
{
	static struct ukplat_memregion_desc *cmdl;
	int rc;

	if (cmdl)
		return cmdl;

	rc = ukplat_memregion_find_next(-1, UKPLAT_MEMRT_CMDLINE, 0, 0, &cmdl);
	if (unlikely(rc < 0))
		return NULL;

	return cmdl;
}
