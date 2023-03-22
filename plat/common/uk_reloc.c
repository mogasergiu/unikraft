#include <uk/plat/common/uk_reloc.h>
#include <uk/plat/memory.h>

/* Use `get_rt_baddr()` to obtain the runtime base address */
#if defined(__X86_64__)
#include <x86/cpu.h>

/* For x86, this is resolved to a `%rip` relative access anyway */
static inline unsigned long get_rt_baddr(void)
{
	return	__BASE_ADDR;
}
#elif defined(__ARM_64__)
#include <arm/cpu.h>

static inline unsigned long get_rt_baddr(void)
{
	unsigned long rt_baddr;

	__asm__ __volatile__(
		"adrp	x0, _base_addr\n\t"
		"add	x0, x0, :lo12:_base_addr\n\t"
		"str	x0, %0\n\t"
		: "=m"(rt_baddr)
		:
		: "x0", "memory"
	);

	return rt_baddr;
}
#endif

static __u64 __section(".uk_reloc") __used uk_reloc_sec;

static inline struct uk_reloc_hdr *get_uk_reloc_hdr()
{
	struct uk_reloc_hdr *ur_hdr;

	ur_hdr = (struct uk_reloc_hdr *)&uk_reloc_sec;
	if (unlikely(!ur_hdr) &&
	    unlikely(ur_hdr->signature != UK_RELOC_SIGNATURE))
		return NULL;

	return ur_hdr;
}

void __used do_uk_reloc(__paddr_t r_paddr, __vaddr_t r_vaddr)
{
	/* `lt_baddr` contains the link time absolute symbol value of
	 * `_base_addr`, while `rt_baddr` will end up, through `get_rt_baddr()`,
	 * to contain the current, runtime, base address of the loaded image.
	 * This works because `lt_baddr` will make the linker generate an
	 * absolute 64-bit value relocation, that will be statically resolved
	 * anyway  in the final binary.
	 */
	static unsigned long lt_baddr = __BASE_ADDR;
	unsigned long rt_baddr, bkp_lt_baddr;
	struct ukplat_memregion_desc *mrdp;
	struct uk_reloc_hdr *ur_hdr;
	struct uk_reloc *ur;
	__u64 val;

	/* Check .uk_reloc signature */
	ur_hdr = get_uk_reloc_hdr();
	if (!ur_hdr)
		halt();

	rt_baddr = get_rt_baddr();
	if (r_paddr == 0)
		r_paddr = (__paddr_t)rt_baddr;
	if (r_vaddr == 0)
		r_vaddr = (__vaddr_t)rt_baddr;

	/* Since we may have been placed at a random physical address, adjust
	 * the initial memory region descriptors added through mkbootinfo.py
	 * since they contain the link-time addresses, relative to rt_baddr.
	 * Do this before anything else, since `lt_baddr`'s relocation has
	 * no been resolved yet and contains the link time address.
	 */
	ukplat_memregion_foreach(&mrdp, 0, 0, 0) {
		mrdp->pbase -= (__paddr_t)lt_baddr;
		mrdp->pbase += r_paddr;
		mrdp->vbase = mrdp->pbase;
	}

	/* Back up the original link time base address. We are going to lose
	 * it once we apply all relocations. Instead of impacting the runtime
	 * performance of the relocator by doing a check for every relocation
	 * address to be different from &lt_baddr, restore it at the end, when
	 * the relocator has finished its job.
	 */
	bkp_lt_baddr = lt_baddr;

	for (ur = ur_hdr->urs; ur->r_sz; ur++) {
		if (ur->flags & UK_RELOC_FLAGS_PHYS_REL)
			val = (__u64)r_paddr + ur->r_val_off;
		else
			val = (__u64)r_vaddr + ur->r_val_off;

		apply_uk_reloc(ur, val, (void *)rt_baddr);
	}

	/* Restore link time base address previously relocated to contain the
	 * runtime base address.
	 */
	lt_baddr = bkp_lt_baddr;
}
