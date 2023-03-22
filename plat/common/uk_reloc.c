#include <uk/plat/common/uk_reloc.h>

#if defined(__X86_64__)
#include <x86/cpu.h>
#elif defined(__ARM_64__)
#include <arm/cpu.h>
#endif

#include <uk/plat/memory.h>

static __u8 __section(".uk_reloc") __used
uk_reloc_sec[UKPLAT_UK_RELOC_SIZE];

void __used do_uk_reloc(__paddr_t r_paddr, __vaddr_t r_vaddr)
{
	struct ukplat_memregion_desc *mrdp;
	struct uk_reloc_hdr *ur_hdr;
	struct uk_reloc *ur;
	__u64 val;

	/* Check .uk_reloc signature */
	ur_hdr = (struct uk_reloc_hdr *)uk_reloc_sec;
	while (ur_hdr->signature != UK_RELOC_SIGNATURE)
		halt();

	if (r_paddr == 0)
		r_paddr = (__paddr_t)__BASE_ADDR;

	if (r_vaddr == 0)
		r_vaddr = (__vaddr_t)__BASE_ADDR;

	for (ur = ur_hdr->urs; ur->r_sz; ur++) {
		if (ur->flags & UK_RELOC_FLAGS_PHYS_REL)
			val = (__u64)r_paddr + ur->r_val_off;
		else
			val = (__u64)r_vaddr + ur->r_val_off;

		apply_uk_reloc(ur, val, (void *)__BASE_ADDR);
	}

	/* Since we may have been placed at a random physical address, adjust
	 * the initial memory region descriptors added through mkbootinfo.py
	 * since they contain the link-time addresses, relative to __BASE_ADDR
	 */
	ukplat_memregion_foreach(&mrdp, 0, 0, 0) {
		mrdp->pbase -= (__paddr_t)__BASE_ADDR;
		mrdp->pbase += r_paddr;
		mrdp->vbase = mrdp->pbase;
	}
}
