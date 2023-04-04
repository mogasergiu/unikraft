/* SPDX-License-Identifier: ISC */
/*
 * Authors: Wei Chen <Wei.Chen@arm.com>
 *
 * Copyright (c) 2018 Arm Ltd.
 *
 * Permission to use, copy, modify, and/or distribute this software
 * for any purpose with or without fee is hereby granted, provided
 * that the above copyright notice and this permission notice appear
 * in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <uk/config.h>
#include <libfdt.h>
#include <uk/arch/paging.h>
#include <uk/plat/common/sections.h>
#include <uk/plat/common/bootinfo.h>
#include <uart/pl011.h>
#ifdef CONFIG_RTC_PL031
#include <rtc/pl031.h>
#endif /* CONFIG_RTC_PL031 */
#include <uk/assert.h>
#include <kvm/intctrl.h>
#include <arm/cpu.h>
#include <arm/arm64/cpu.h>
#include <arm/smccc.h>
#include <uk/arch/limits.h>

#ifdef CONFIG_ARM64_FEAT_PAUTH
#include <arm/arm64/pauth.h>
#endif /* CONFIG_ARM64_FEAT_PAUTH */

#ifdef CONFIG_HAVE_MEMTAG
#include <uk/arch/memtag.h>
#endif /* CONFIG_HAVE_MEMTAG */

#ifdef CONFIG_PAGING
#include <uk/plat/paging.h>
#include <uk/plat/common/w_xor_x.h>
#include <uk/falloc.h>

struct uk_pagetable kernel_pt;
#endif /* CONFIG_PAGING */

const unsigned long max_addr = 0x8000000000;  /* 512 GiB */

void *bootmemory_palloc(__sz size, int type, __u16 flags);

static const char *appname = CONFIG_UK_NAME;

smccc_conduit_fn_t smccc_psci_call;

#define _libkvmplat_newstack(sp) ({				\
	__asm__ __volatile__("mov sp, %0\n" ::"r" (sp));	\
})

static void _init_dtb(void *dtb_pointer)
{
	int ret;

	if ((ret = fdt_check_header(dtb_pointer)))
		UK_CRASH("Invalid DTB: %s\n", fdt_strerror(ret));

	ret = ukplat_memregion_list_insert(&ukplat_bootinfo_get()->mrds,
	        &(struct ukplat_memregion_desc){
			.vbase = (__vaddr_t)dtb_pointer,
			.pbase = (__vaddr_t)dtb_pointer,
			.len   = fdt_totalsize(dtb_pointer),
			.type  = UKPLAT_MEMRT_DEVICETREE,
			.flags = UKPLAT_MEMRF_READ | UKPLAT_MEMRF_MAP,
		});
	if (unlikely(ret < 0))
		UK_CRASH("Could not insert DT memory descriptor");

	ukplat_bootinfo_get()->flags |= UKPLAT_BOOTINFO_HAVE_DEVICETREE;

	uk_pr_info("Found device tree on: %p\n", dtb_pointer);
}

static void _dtb_get_psci_method(void *dtb_pointer)
{
	int fdtpsci, len;
	const char *fdtmethod;

	/*
	 * We just support PSCI-0.2 and PSCI-1.0, the PSCI-0.1 would not
	 * be supported.
	 */
	fdtpsci = fdt_node_offset_by_compatible(dtb_pointer, -1, "arm,psci-1.0");
	if (fdtpsci < 0)
		fdtpsci = fdt_node_offset_by_compatible(dtb_pointer,
							-1, "arm,psci-0.2");

	if (fdtpsci < 0) {
		uk_pr_info("No PSCI conduit found in DTB\n");
		goto enomethod;
	}

	fdtmethod = fdt_getprop(dtb_pointer, fdtpsci, "method", &len);
	if (!fdtmethod || (len <= 0)) {
		uk_pr_info("No PSCI method found\n");
		goto enomethod;
	}

	if (!strcmp(fdtmethod, "hvc"))
		smccc_psci_call = smccc_hvc;
	else if (!strcmp(fdtmethod, "smc"))
		smccc_psci_call = smccc_smc;
	else {
		uk_pr_info("Invalid PSCI conduit method: %s\n",
			   fdtmethod);
		goto enomethod;
	}
	uk_pr_info("PSCI method: %s\n", fdtmethod);
	return;

enomethod:
	uk_pr_info("Support PSCI from PSCI-0.2\n");
	smccc_psci_call = NULL;
}

static void _init_dtb_mem(void *dtb_pointer)
{
	int fdt_mem, prop_len = 0, prop_min_len;
	int naddr, nsize, rc;
	const uint64_t *regs;
	uint64_t mem_base, mem_size;

	/* search for assigned VM memory in DTB */
	if (fdt_num_mem_rsv(dtb_pointer) != 0)
		uk_pr_warn("Reserved memory is not supported\n");

	fdt_mem = fdt_node_offset_by_prop_value(dtb_pointer, -1,
						"device_type",
						"memory", sizeof("memory"));
	if (fdt_mem < 0) {
		uk_pr_warn("No memory found in DTB\n");
		return;
	}

	naddr = fdt_address_cells(dtb_pointer, fdt_mem);
	if (naddr < 0 || naddr >= FDT_MAX_NCELLS)
		UK_CRASH("Could not find proper address cells!\n");

	nsize = fdt_size_cells(dtb_pointer, fdt_mem);
	if (nsize < 0 || nsize >= FDT_MAX_NCELLS)
		UK_CRASH("Could not find proper size cells!\n");

	/*
	 * QEMU will always provide us at least one bank of memory.
	 * unikraft will use the first bank for the time-being.
	 */
	regs = fdt_getprop(dtb_pointer, fdt_mem, "reg", &prop_len);

	/*
	 * The property must contain at least the start address
	 * and size, each of which is 8-bytes.
	 */
	prop_min_len = (int)sizeof(fdt32_t) * (naddr + nsize);
	if (regs == NULL || prop_len < prop_min_len)
		UK_CRASH("Bad 'reg' property: %p %d\n", regs, prop_len);

	/* If we have more than one memory bank, give a warning messasge */
	if (prop_len > prop_min_len)
		uk_pr_warn("Currently, we support only one memory bank!\n");

	mem_base = fdt64_to_cpu(regs[0]);
	mem_size = fdt64_to_cpu(regs[1]);
	if (mem_base > __TEXT)
		UK_CRASH("Fatal: Image outside of RAM\n");

        rc = ukplat_memregion_list_insert(&ukplat_bootinfo_get()->mrds,
		&(struct ukplat_memregion_desc){
			.vbase = (__vaddr_t)mem_base,
			.pbase = (__paddr_t)mem_base,
			.len   = mem_size,
			.type  = UKPLAT_MEMRT_FREE,
			.flags = UKPLAT_MEMRF_READ |
                                 UKPLAT_MEMRF_WRITE,
		});
	if (unlikely(rc < 0))
		UK_CRASH("Could not add free memory descriptor\n");

        ukplat_memregion_coalesce_mrds();
}

static char *cmdline;
static __sz cmdline_len;

static void _dtb_get_cmdline(void *dtb_pointer)
{
	struct ukplat_memregion_desc *cmdl_mrd;
	int fdtchosen, len;
	const char *fdtcmdline;

	/* TODO: Proper error handling */
	fdtchosen = fdt_path_offset(dtb_pointer, "/chosen");
	if (!fdtchosen)
		goto enocmdl;
	fdtcmdline = fdt_getprop(dtb_pointer, fdtchosen, "bootargs",
				 &len);
	if (!fdtcmdline || (len <= 0))
		goto enocmdl;

        cmdline = bootmemory_palloc(len, UKPLAT_MEMRT_CMDLINE,
				    UKPLAT_MEMRF_READ);
	if (unlikely(!cmdline))
		UK_CRASH("Command-line alloc failed\n");

	/* Ensure it has been added properly and cache it */
	cmdl_mrd = ukplat_memregion_get_cmdl();
	if (!cmdl_mrd)
		UK_CRASH("Command-line memory region descriptor failed "
			 "to get added");

	strncpy(cmdline, fdtcmdline, len);
	/* ensure null termination */
	cmdline[len - 1] = '\0';

	/* Tag this scratch cmdline as a kernel resource, to distinguish it
	 * from the original cmdline obtained above
	 */
	cmdline = bootmemory_palloc(cmdl_mrd->len, UKPLAT_MEMRT_KERNEL,
				    UKPLAT_MEMRF_READ);
	if (unlikely(!cmdline))
		UK_CRASH("Could not allocate scratch command-line memory");

	strncpy(cmdline, (const char *)cmdl_mrd->vbase, cmdl_mrd->len);
	cmdline_len = cmdl_mrd->len;

	uk_pr_info("Command line: %s\n", cmdline);

	return;

enocmdl:
	uk_pr_info("No command line found\n");
}

#ifdef CONFIG_PAGING

int _init_paging(void)
{
	int rc;
	uint64_t start;
	uint64_t len;
	unsigned long frames;
	__sz free_memory, res_memory;
        void *pt_base, *bstack;
        struct ukplat_memregion_descriptor *mrd;

        rc = ukplat_memregion_find_next(-1, UKPLAT_MEMRT_FREE, 0, 0, &mrd);
        if (unlikely(rc < 0))
                return rc;

	/* Assign all available memory beyond the boot stack
	 * to the frame allocator.
	 */
	start = ALIGN_UP(mrd->pbase, PAGE_SIZE);
	len   = mrd->pbase + mrd->len - start;
	rc = ukplat_pt_init(&kernel_pt, start, len);
	if (unlikely(rc))
		return rc;

	/* Switch to the new page tables */
	rc = ukplat_pt_set_active(&kernel_pt);
	if (unlikely(rc))
		return rc;

	/* Unmap all available memory */
	rc = ukplat_page_unmap(&kernel_pt, start, len >> PAGE_SHIFT,
			       PAGE_FLAG_KEEP_FRAMES);
	if (unlikely(rc))
		return rc;

	/* Reserve memory for the new pagetables that will be created
	 * by the frame allocator for new mappings. Assume the worst
	 * case, that is page size.
	 */
        res_memory = PT_PAGES(len >> PAGE_SHIFT) << PAGE_SHIFT;
        pt_base = bootmemory_pallloc(PT_PAGES(len >> PAGE_SHIFT) << PAGE_SHIFT,
                                     UKPLAT_MEMRT_RESERVED, UKPLAT_MEMRF_READ);
	if (unlikely(!pt_base))
		UK_CRASH("Page tables alloc failed\n");

        rc = ukplat_memregion_find_next(-1, UKPLAT_MEMRT_STACK, 0, 0, &mrd)
        if (unlikely(rc < 0))
                UK_CRASH("No available heap memory");

	frames = mrd->len >> PAGE_SHIFT;
        rc = ukplat_page_map(&kernel_pt, bstack, __PADDR_ANY, frames,
                             PAGE_ATTR_PROT_RW, 0);
	if (unlikely(rc))
		return rc;

        rc = ukplat_memregion_find_next(-1, UKPLAT_MEMRT_FREE, 0, 0, &mrd)
        if (unlikely(rc < 0))
                UK_CRASH("No available heap memory");

        frames = mrd->len >> PAGE_SHIFT;
	rc = ukplat_page_map(&kernel_pt, mrd->vbase, __PADDR_ANY, frames,
                             PAGE_ATTR_PROT_RW | PAGE_ATTR_TYPE_NORMAL_WB_TAGGED,
                             0);
	if (unlikely(rc))
		return rc;

	return 0;
}
#endif /* CONFIG_PAGING */

void __no_pauth _libkvmplat_start(void *dtb_pointer)
{
        struct ukplat_memregion_desc *mrd;
	void *bstack;
	int ret;

	_init_dtb(dtb_pointer);

	pl011_console_init(dtb_pointer);

	uk_pr_info("Entering from KVM (arm64)...\n");

        /* Initialize memory from DTB */
	_init_dtb_mem(dtb_pointer);

        /* Allocate boot stack */
        bstack = bootmemory_palloc(__STACK_SIZE, UKPLAT_MEMRT_STACK,
				   UKPLAT_MEMRF_READ | UKPLAT_MEMRF_WRITE);
	if (unlikely(!bstack))
		UK_CRASH("Boot stack alloc failed\n");
	bstack = (void *)((__uptr)bstack + __STACK_SIZE);

	/* Get command line from DTB */
	_dtb_get_cmdline(dtb_pointer);

	/* Get PSCI method from DTB */
	_dtb_get_psci_method(dtb_pointer);

#ifdef CONFIG_PAGING
	/* Initialize paging */
	ret = _init_paging();
	if (unlikely(ret))
		UK_CRASH("Could not initialize paging (%d)\n", ret);
#ifdef CONFIG_ENFORCE_W_XOR_X
	enforce_w_xor_x();
#endif /* CONFIG_ENFORCE_W_XOR_X */
#endif /* CONFIG_PAGING */

#ifdef CONFIG_ARM64_FEAT_PAUTH
	ret = ukplat_pauth_init();
	if (unlikely(ret))
		UK_CRASH("Could not initialize PAuth (%d)\n", ret);
#endif /* CONFIG_ARM64_FEAT_PAUTH */

#ifdef CONFIG_HAVE_MEMTAG
	ret = ukarch_memtag_init();
	if (unlikely(ret))
		UK_CRASH("Could not initialize MTE (%d)\n", ret);
#endif /* CONFIG_HAVE_MEMTAG */

#ifdef CONFIG_RTC_PL031
	/* Initialize RTC */
	pl031_init_rtc(dtb_pointer);
#endif /* CONFIG_RTC_PL031 */

	/* Initialize interrupt controller */
	intctrl_init();

	/* Initialize logical boot CPU */
	ret = lcpu_init(lcpu_get_bsp());
	if (unlikely(ret))
		UK_CRASH("Failed to initialize bootstrapping CPU: %d\n", ret);

#ifdef CONFIG_HAVE_SMP
	ret = lcpu_mp_init(CONFIG_UKPLAT_LCPU_RUN_IRQ,
			   CONFIG_UKPLAT_LCPU_WAKEUP_IRQ,
			   dtb_pointer);
	if (unlikely(ret))
		UK_CRASH("SMP initialization failed: %d.\n", ret);
#endif /* CONFIG_HAVE_SMP */

	/*
	 * Switch away from the bootstrap stack as early as possible.
	 */
	uk_pr_info("Switch from bootstrap stack to stack @%p\n",
		   (void *) bstack);

	_libkvmplat_newstack(bstack);

	mrd = ukplat_memregion_get_cmdl();
	if (!mrd)
		UK_CRASH("Command-line memory region descriptor failed to get "
			 "added");

	ukplat_entry_argp(DECONST(char *, appname),
			  (char *)mrd->vbase, mrd->len);
}
