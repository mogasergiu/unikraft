#if defined(__X86_64__)
#include <x86/uk_reloc.h>
#include <x86/cpu.h>
#elif defined(__ARM_64__)
#include <arm/arm64/uk_reloc.h>
#include <arm/cpu.h>
#else
#error "For relocation support, add uk_reloc.h for current architecture."
#endif

void __used do_uk_reloc(volatile __paddr_t r_paddr, volatile __vaddr_t r_vaddr)
{
	static volatile struct uk_reloc __uk_reloc first_ur;
	volatile struct uk_reloc *ur;
	volatile void * volatile baddr;
	__u64 val;

	/* Check .uk_reloc signature */
	while (*((__u32 *) &first_ur) != UK_RELOC_SIGNATURE) { halt(); }

	st_curr_baddr(&baddr);

	if (r_paddr == 0)
		r_paddr = (volatile __paddr_t) baddr;

	if (r_vaddr == 0)
		r_vaddr = (volatile __vaddr_t) baddr;

	ur = (volatile void *) &first_ur + 4;
	for (; ur->r_sz != 0; ur++) {
		if (ur->flags & UK_RELOC_FLAGS_PHYS_REL)
			val = (__u64) r_paddr + ur->r_val_off;
		else
			val = (__u64) r_vaddr + ur->r_val_off;

		apply_uk_reloc(ur, val, baddr);
	}
}
