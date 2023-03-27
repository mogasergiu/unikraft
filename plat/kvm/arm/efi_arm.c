#include <uk/plat/common/sections.h>
#include <uk/plat/common/bootinfo.h>
#include <kvm/efi.h>
#include <uk/arch/paging.h>
#include <uk/plat/lcpu.h>

void __no_pauth _libkvmplat_start(void *dtb_pointer);
extern __paddr_t vector_table;

static __u8 uk_efi_bootstack[__PAGE_SIZE];

static inline void uk_efi_mask_daif()
{
	__asm __volatile( "msr daifset, #15" : : : "memory" );
}

#define uk_efi_set_sp_el1(sp)							\
	__asm__ __volatile__("mov sp, %0\n" ::"r" (sp));

static __u8 __align(16) bootstack[4096];

uk_efi_status_t uk_efi_jmp_to_kern()
{
	uk_efi_mask_daif();

	clean_and_invalidate_dcache_range(__BASE_ADDR, __END);

	SYSREG_WRITE64(sctlr_el1, SCTLR_EL1_SA_BIT	|
				  SCTLR_EL1_SA0_BIT	|
				  SCTLR_EL1_CP15BEN_BIT	|
				  SCTLR_EL1_EOS_BIT	|
				  SCTLR_EL1_nTWI_BIT	|
				  SCTLR_EL1_nTWE_BIT	|
				  SCTLR_EL1_EIS_BIT	|
				  SCTLR_EL1_SPAN_BIT);
	SYSREG_WRITE64(contextidr_el1, 0);
	SYSREG_WRITE64(VBAR_EL1, &vector_table);
	SYSREG_WRITE64(tcr_el1, TCR_INIT_FLAGS);
	SYSREG_WRITE64(spsr_el1, 0);
	SYSREG_WRITE64(elr_el1, 0);
	SYSREG_WRITE64(cntv_cval_el0, 0);
	SYSREG_WRITE64(sp_el0, 0);
	SYSREG_WRITE64(tpidr_el0, 0);

	start_mmu();

	uk_efi_set_sp_el1(bootstack + 4096);

	_ukplat_entry(ukplat_bootinfo_get());

	return -1;
}
