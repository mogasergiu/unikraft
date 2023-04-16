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
#include <uk/plat/lcpu.h>
#include <uk/plat/common/lcpu.h>
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
#endif /* CONFIG_PAGING */

smccc_conduit_fn_t smccc_psci_call;

#define _libkvmplat_newstack(sp) ({				\
	__asm__ __volatile__("mov sp, %0\n" ::"r" (sp));	\
})

static void _init_dtb(void *dtb_pointer)
{
	int ret;

	if ((ret = fdt_check_header(dtb_pointer)))
		UK_CRASH("Invalid DTB: %s\n", fdt_strerror(ret));

	/* If the previous boot phase did not update it already, we will do so.
	 * Note that we are not marking it as UKPLAT_MEMRF_MAP. Since we can
	 * read it, it means we already have it mapped into our static page
	 * tables. However, since we only know how to unmap the first DRAM
	 * bank, we must be cautios and not touch this memory region because
	 * we do not know where the previous boot phase mapped it for us.
	 * Otherwise, this could easily make `ukplat_paging_init` generate
	 * an -EEXIST error code.
	 */
	if (!ukplat_bootinfo_get()->dtb) {
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

		ukplat_bootinfo_get()->dtb = (__u64)dtb_pointer;
	}

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

static int _init_dtb_mem(void *dtb_pointer)
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
		return fdt_mem;
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

        return ukplat_memregion_list_coalesce(&ukplat_bootinfo_get()->mrds);
}

#ifdef CONFIG_PAGING
#define DRAM_START					0x40000000
#define DRAM_LEN					0x40000000
static int mem_init()
{
	struct ukplat_memregion_desc *mrd;
	int rc;

	ukplat_memregion_foreach(&mrd, 0, 0, 0)
		if (!IN_RANGE(mrd->pbase, DRAM_START, DRAM_LEN))
			mrd->flags &= ~UKPLAT_MEMRF_MAP;

	rc = ukplat_paging_init(ukplat_bootinfo_get());
	if (unlikely(rc < 0))
		return rc;

#ifdef CONFIG_LIBUKBOOT_HEAP_BASE
	rc = ukplat_page_unmap(ukplat_pt_get_active(),
			       CONFIG_LIBUKBOOT_HEAP_BASE,
			       ukplat_pt_get_active()->fa->free_memory >> PAGE_SHIFT,
			     PAGE_FLAG_KEEP_PTES);
	if (unlikely(rc))
		return rc;
#endif

	return 0;
}
#else
#define L0_PT0_START_PAGE				0x40000000
#define L0_PT0_LEN					0x00200000
extern __pte_t arm64_bpt_l0_pt0[];

static int mem_init()
{
	struct ukplat_memregion_desc *mrd;
	__paddr_t paddr, pstart, pend;
	__pte_t pte_attr;
	__sz len, idx;

	ukplat_memregion_foreach(&mrd, 0, UKPLAT_MEMRF_MAP, UKPLAT_MEMRF_MAP) {
		pstart = PAGE_ALIGN_UP(mrd->pbase);
		len = PAGE_ALIGN_DOWN(mrd->len - (pstart - mrd->pbase));

		if (unlikely(len == 0))
			continue;

		if (!RANGE_CONTAIN(L0_PT0_START_PAGE, L0_PT0_LEN, pstart, len))
			continue;

		if (mrd->flags & UKPLAT_MEMRF_WRITE)
			pte_attr = PTE_ATTR_NORMAL_RW | PTE_TYPE_PAGE;
		else if (mrd->flags & UKPLAT_MEMRF_EXECUTE)
			pte_attr = PTE_ATTR_NORMAL_RX | PTE_TYPE_PAGE;
		else
			pte_attr = PTE_ATTR_NORMAL_RO | PTE_TYPE_PAGE;

		pend = pstart + len;
		for (paddr = pstart; paddr < pend; paddr += PAGE_SIZE) {
			idx = (paddr - L0_PT0_START_PAGE) >> PAGE_SHIFT;
			arm64_bpt_l0_pt0[idx] = paddr + pte_attr;
		}
	}

	return 0;
}
#endif

static char *cmdline;
static __sz cmdline_len;

static void _dtb_get_cmdline(void *dtb_pointer)
{
	int fdtchosen, len;
	const char *fdtcmdline;

	if (ukplat_bootinfo_get()->cmdline) {
		len = strlen((const char *)ukplat_bootinfo_get()->cmdline);
		fdtcmdline = (const char *)ukplat_bootinfo_get()->cmdline;
	} else {
		/* TODO: Proper error handling */
		fdtchosen = fdt_path_offset(dtb_pointer, "/chosen");
		if (!fdtchosen)
			goto enocmdl;
	fdtcmdline = fdt_getprop(dtb_pointer, fdtchosen, "bootargs",
				 &len);
	if (!fdtcmdline || (len <= 0))
		goto enocmdl;

        cmdline = ukplat_memregion_alloc(len, UKPLAT_MEMRT_CMDLINE,
                                         UKPLAT_MEMRF_READ | UKPLAT_MEMRF_MAP);
	if (unlikely(!cmdline))
		UK_CRASH("Command-line alloc failed\n");

	/* Ensure it has been added properly and cache it */
	ukplat_bootinfo_get()->cmdline = (__u64)cmdline;
	strncpy(cmdline, fdtcmdline, len);
	/* ensure null termination */
	cmdline[len - 1] = '\0';

	}
	/* Tag this scratch cmdline as a kernel resource, to distinguish it
	 * from the original cmdline obtained above
	 */
	cmdline = ukplat_memregion_alloc(len + 1, UKPLAT_MEMRT_KERNEL,
					 UKPLAT_MEMRF_READ |
					 UKPLAT_MEMRF_WRITE |
					 UKPLAT_MEMRF_MAP);
	if (unlikely(!cmdline))
		UK_CRASH("Could not allocate scratch command-line memory");

	strncpy(cmdline, fdtcmdline, len);
	cmdline_len = len;

	uk_pr_info("Command line: %s\n", cmdline);

	return;

enocmdl:
	uk_pr_info("No command line found\n");
}

#ifdef CONFIG_PAGING
#endif

static void __noreturn _ukplat_entry2(void)
{
#ifndef CONFIG_UK_EFI_STUB
	ukplat_entry_argp(DECONST(char *, CONFIG_UK_NAME), cmdline, cmdline_len);
#else
	ukplat_entry_argp(NULL, cmdline, cmdline_len);
#endif
	ukplat_lcpu_halt();
}

void __no_pauth _libkvmplat_start(void *dtb_pointer)
{
	void *bstack;
	int ret;

	_init_dtb(dtb_pointer);

	pl011_console_init(dtb_pointer);

	uk_pr_info("Entering from KVM (arm64)...\n");

        /* Initialize memory from DTB */
	ret = _init_dtb_mem(dtb_pointer);
        if (unlikely(ret))
		UK_CRASH("Could not initialize memory regions (%d)\n", ret);

        /* Allocate boot stack */
        bstack = ukplat_memregion_alloc(__STACK_SIZE, UKPLAT_MEMRT_STACK,
					UKPLAT_MEMRF_READ |
					UKPLAT_MEMRF_WRITE |
					UKPLAT_MEMRF_MAP);
	if (unlikely(!bstack))
		UK_CRASH("Boot stack alloc failed\n");
	bstack = (void *)((__uptr)bstack + __STACK_SIZE);

	/* Get command line from DTB */
	_dtb_get_cmdline(dtb_pointer);

	/* Get PSCI method from DTB */
	_dtb_get_psci_method(dtb_pointer);

	/* Initialize paging */
	ret = mem_init();
	if (unlikely(ret))
		UK_CRASH("Could not initialize paging (%d)\n", ret);
#if defined(PAGING) && defined(ENFORCE_W_XOR_X)
	enforce_w_xor_x();
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
	uk_pr_info("Switch from bootstrap stack to stack @%p\n", bstack);

	lcpu_arch_jump_to(bstack, _ukplat_entry2);
}
