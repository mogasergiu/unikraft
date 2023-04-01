#include <uk/plat/common/uk_reloc.h>

#if defined(__X86_64__)
#include <x86/cpu.h>

static inline unsigned long get_baddr()
{
	return	__BASE_ADDR;
}
#elif defined(__ARM_64__)
#include <arm/cpu.h>

static inline unsigned long get_baddr()
{
	unsigned long baddr;

	__asm__ __volatile__(
		"adrp x0, _base_addr\n\t"
		"add x0, x0, :lo12:_base_addr\n\t"
		"str x0, %0\n\t"
		: "=m"(baddr)
		:
		: "x0", "memory"
	);

	return baddr;
}
#endif

#include <uk/plat/memory.h>

static __u8 __section(".uk_reloc") __used
uk_reloc_sec[UKPLAT_UK_RELOC_SIZE];

void __used do_uk_reloc(__paddr_t r_paddr, __vaddr_t r_vaddr)
{
	struct ukplat_memregion_desc *mrdp;
	struct uk_reloc_hdr *ur_hdr;
	struct uk_reloc *ur;
	unsigned long baddr;
	__u64 val;

	/* Check .uk_reloc signature */
	ur_hdr = (struct uk_reloc_hdr *)uk_reloc_sec;
	while (ur_hdr->signature != UK_RELOC_SIGNATURE)
		halt();

	baddr = get_baddr();

	if (r_paddr == 0)
		r_paddr = (__paddr_t)baddr;

	if (r_vaddr == 0)
		r_vaddr = (__vaddr_t)baddr;

	for (ur = ur_hdr->urs; ur->r_sz; ur++) {
		if (ur->flags & UK_RELOC_FLAGS_PHYS_REL)
			val = (__u64)r_paddr + ur->r_val_off;
		else
			val = (__u64)r_vaddr + ur->r_val_off;

		apply_uk_reloc(ur, val, (void *)baddr);
	}

	/* Since we may have been placed at a random physical address, adjust
	 * the initial memory region descriptors added through mkbootinfo.py
	 * since they contain the link-time addresses, relative to __BASE_ADDR
	 */
	ukplat_memregion_foreach(&mrdp, 0, 0, 0) {
		mrdp->pbase -= (__paddr_t)baddr;
		mrdp->pbase += r_paddr;
		mrdp->vbase = mrdp->pbase;
	}
}
