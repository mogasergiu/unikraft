#if defined(__X86_64__)
#include <x86/uk_reloc.h>
#include <x86/cpu.h>
#elif defined(__ARM_64__)
#include <arm/arm64/uk_reloc.h>
#include <arm/cpu.h>
#else
#error "For relocation support, add uk_reloc.h for current architecture."
#endif

void __used do_uk_reloc(__paddr_t r_paddr, __vaddr_t r_vaddr)
{
	static struct uk_reloc_hdr __uk_reloc ur_hdr;
	struct uk_reloc *ur;
	void *baddr;
	__u64 val;

	/* Check .uk_reloc signature */
	while (ur_hdr.signature != UK_RELOC_SIGNATURE) { halt(); }

	st_curr_baddr(&baddr);

	if (r_paddr == 0)
		r_paddr = (__paddr_t) baddr;

	if (r_vaddr == 0)
		r_vaddr = (__vaddr_t) baddr;

	for (ur = ur_hdr.urs; ur->r_sz; ur++) {
		if (ur->flags & UK_RELOC_FLAGS_PHYS_REL)
			val = (__u64) r_paddr + ur->r_val_off;
		else
			val = (__u64) r_vaddr + ur->r_val_off;

		apply_uk_reloc(ur, val, baddr);
	}
}
