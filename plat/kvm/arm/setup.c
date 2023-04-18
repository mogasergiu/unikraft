/* SPDX-License-Identifier: ISC */
/*
 * Authors: Wei Chen <Wei.Chen@arm.com>
 *          Sergiu Moga <sergiu.moga@protonmail.com>
 *
 * Copyright (c) 2018 Arm Ltd.
 * Copyright (c) 2023 University Politehnica of Bucharest.
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
#include <uk/arch/paging.h>

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

extern struct ukplat_memregion_desc bpt_unmap_mrd;

smccc_conduit_fn_t smccc_psci_call;

static void _dtb_get_psci_method(void *fdt)
{
	int fdtpsci, len;
	const char *fdtmethod;

	/*
	 * We just support PSCI-0.2 and PSCI-1.0, the PSCI-0.1 would not
	 * be supported.
	 */
	fdtpsci = fdt_node_offset_by_compatible(fdt, -1,
						"arm,psci-1.0");
	if (fdtpsci < 0)
		fdtpsci = fdt_node_offset_by_compatible(fdt,
							-1, "arm,psci-0.2");

	if (fdtpsci < 0) {
		uk_pr_info("No PSCI conduit found in DTB\n");
		goto enomethod;
	}

	fdtmethod = fdt_getprop(fdt, fdtpsci, "method", &len);
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

<<<<<<< HEAD
=======
static int _init_dtb_mem(void *dtb_pointer)
{
	int fdt_mem, prop_len = 0, prop_min_len;
	int naddr, nsize, rc;
	const __u64 *regs;
	__u64 mem_base, mem_size;

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
#define DRAM_START					0x40000000UL
#define DRAM_LEN					0x40000000UL
static int mem_init(void)
{
	struct ukplat_memregion_desc *mrd;
	struct uk_pagetable *pt;
	int rc;

	ukplat_memregion_foreach(&mrd, 0, 0, 0)
		if (!IN_RANGE(mrd->pbase, DRAM_START, DRAM_LEN))
			mrd->flags &= ~UKPLAT_MEMRF_MAP;

	rc = ukplat_paging_init();
	if (unlikely(rc < 0))
		return rc;

#ifdef CONFIG_LIBUKBOOT_HEAP_BASE
	pt = ukplat_pt_get_active();
	rc = ukplat_page_unmap(pt, CONFIG_LIBUKBOOT_HEAP_BASE,
			       pt->fa->free_memory >> PAGE_SHIFT,
			       PAGE_FLAG_KEEP_PTES);
	if (unlikely(rc))
		return rc;
#endif

	return 0;
}
#else
#define L0_PT0_START_PAGE				0x40000000UL
#define L0_PT0_LEN					0x00200000UL
extern __pte_t arm64_bpt_l0_pt0[];

static int mem_init(void)
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

static inline int cmdline_init(struct ukplat_bootinfo *bi)
{
	char *cmdl = (bi->cmdline) ? (char *)bi->cmdline : CONFIG_UK_NAME;

	cmdline_len = strlen(cmdl) + 1;

	/* This is not the original command-line, but one that will be thrashed
	 * by `ukplat_entry_argp` to obtain argc/argv. So mark it as a kernel
	 * resource instead.
	 */
	cmdline = ukplat_memregion_alloc(cmdline_len, UKPLAT_MEMRT_KERNEL,
					 UKPLAT_MEMRF_READ |
					 UKPLAT_MEMRF_WRITE |
					 UKPLAT_MEMRF_MAP);
	if (unlikely(!cmdline))
		UK_CRASH("Could not allocate scratch command-line memory");

	strncpy(cmdline, cmdl, len);
	cmdline_len = len;

	uk_pr_info("Command line: %s\n", cmdline);

	return;

enocmdl:
	uk_pr_info("No command line found\n");
}

static void __noreturn _ukplat_entry2(void)
{
	ukplat_entry_argp(NULL, cmdline, cmdline_len);

	ukplat_lcpu_halt();
}

void __no_pauth _ukplat_entry(struct ukplat_bootinfo *bi)
{
	void *bstack;
	void *fdt;
	int rc;

	fdt = (void *)bi->dtb;

	pl011_console_init(fdt);

	rc = cmdline_init(bi);
	if (unlikely(rc < 0))
		UK_CRASH("Failed to initialize command-line\n");

	/* Allocate boot stack */
	bstack = ukplat_memregion_alloc(__STACK_SIZE, UKPLAT_MEMRT_STACK,
					UKPLAT_MEMRF_READ |
					UKPLAT_MEMRF_WRITE |
					UKPLAT_MEMRF_MAP);
	if (unlikely(!bstack))
		UK_CRASH("Boot stack alloc failed\n");
	bstack = (void *)((__uptr)bstack + __STACK_SIZE);

	/* Get PSCI method from DTB */
	_dtb_get_psci_method(fdt);

	/* Initialize paging */
	rc = ukplat_mem_init();
	if (unlikely(rc))
		UK_CRASH("Could not initialize paging (%d)\n", rc);

#if defined(ENFORCE_W_XOR_X) && defined(PAGING)
	enforce_w_xor_x();
#endif /* CONFIG_ENFORCE_W_XOR_X && CONFIG_PAGING */

#ifdef CONFIG_ARM64_FEAT_PAUTH
	rc = ukplat_pauth_init();
	if (unlikely(rc))
		UK_CRASH("Could not initialize PAuth (%d)\n", rc);
#endif /* CONFIG_ARM64_FEAT_PAUTH */

#ifdef CONFIG_HAVE_MEMTAG
	rc = ukarch_memtag_init();
	if (unlikely(rc))
		UK_CRASH("Could not initialize MTE (%d)\n", rc);
#endif /* CONFIG_HAVE_MEMTAG */

#ifdef CONFIG_RTC_PL031
	/* Initialize RTC */
	pl031_init_rtc(fdt);
#endif /* CONFIG_RTC_PL031 */

	/* Initialize interrupt controller */
	intctrl_init();

	/* Initialize logical boot CPU */
	rc = lcpu_init(lcpu_get_bsp());
	if (unlikely(rc))
		UK_CRASH("Failed to initialize bootstrapping CPU: %d\n", rc);

#ifdef CONFIG_HAVE_SMP
	rc = lcpu_mp_init(CONFIG_UKPLAT_LCPU_RUN_IRQ,
			   CONFIG_UKPLAT_LCPU_WAKEUP_IRQ,
			   fdt);
	if (unlikely(rc))
		UK_CRASH("SMP initialization failed: %d.\n", rc);
#endif /* CONFIG_HAVE_SMP */

	/*
	 * Switch away from the bootstrap stack as early as possible.
	 */
	uk_pr_info("Switch from bootstrap stack to stack @%p\n", bstack);

	lcpu_arch_jump_to(bstack, _ukplat_entry2);
}
