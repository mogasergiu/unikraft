#ifndef __UKRELOC_H__
#define __UKRELOC_H__

#define UKRELOC_FLAGS_PHYS_REL		(1 << 0)
#define UKRELOC_PLACEHOLDER		0xB00B
#define UKRELOC_SIGNATURE		0xBADB0111
#define UKRELOC_ALIGNMENT		0x1000

#ifdef __ASSEMBLY__

.macro ur_sec_updt
.pushsection .ukreloc
	.quad	0x0  /* r_mem_off */
	.quad	0x0  /* r_addr */
	.long	0x0  /* r_sz */
	.long	0x0  /* flags */
.popsection
.endm

.macro ur_data type:req, sym:req, bytes:req, phys
#ifdef CONFIG_OPTIMIZE_PIE
.globl \sym\()_ukreloc_data\bytes\()\phys\()
.set \sym\()_ukreloc_data\bytes\()\phys\(), .
	.\type	UKRELOC_PLACEHOLDER
	ur_sec_updt
#else
	.\type	\sym
#endif
.endm

/**
 * For proper positional independence we require that whatever page table
 * related entries in the static page table we may have, they must be
 * relocatable against a dynamic physical address.
 */
.macro ur_pte pte_sym:req, pte:req
#ifdef CONFIG_OPTIMIZE_PIE
	ur_data	quad, \pte_sym, 8, _phys
.globl \pte_sym\()_ukreloc_pte_attr0
.set \pte_sym\()_ukreloc_pte_attr0, \pte
#else
	ur_data	quad, (\pte_sym + \pte), 8, _phys
#endif
.endm

#ifndef CONFIG_OPTIMIZE_PIE
do_ukreloc:
	ret
#endif

#else  /* __ASSEMBLY__ */

#include <uk/arch/types.h>
#include <uk/essentials.h>

struct ukreloc {
	__u64 r_mem_off;
	__u64 r_addr;
	__u32 r_sz;
	__u32 flags;
} __packed;

#define UKRELOC_ENTRY(ur_r_mem_off, ur_r_addr, ur_r_sz, ur_flags)	\
	{								\
		.r_mem_off	= (ur_r_mem_off),			\
		.r_addr		= (ur_r_addr),				\
		.r_sz		= (ur_r_sz),				\
		.flags		= (ur_flags),				\
	}

struct ukreloc_hdr {
	__u32 signature;
	struct ukreloc urs[];
} __packed __align(__SIZEOF_LONG__);

/* Misaligned access here is never going to happen for a non-x86 architecture
 * as there are no ukreloc_imm relocation types defined for them.
 * We need this for x86 to patch early boot code, so it's a false positive.
 * An alignment exception (#AC if CR0.AM=1 and RFLAGS.AC=1) on x86 can only
 * occur in userspace, which Unikraft does not deal with anyway.
 * If someone, in the future, adds a ukreloc type that allows
 * misalignments on architectures that do not allow this, it's most likely
 * not needed and an alternative solution should be considered.
 */
#if defined(__X86_64__)
#define X86_64_NO_SANITIZE_ALIGNMENT __attribute__((no_sanitize("alignment")))
#else
#define X86_64_NO_SANITIZE_ALIGNMENT
#endif
static inline void X86_64_NO_SANITIZE_ALIGNMENT
apply_ukreloc(struct ukreloc *ur, __u64 val, void *baddr)
{
	switch (ur->r_sz) {
	case 2:
		*(__u16 *)((__u8 *)baddr + ur->r_mem_off) = (__u16)val;
		break;
	case 4:
		*(__u32 *)((__u8 *)baddr + ur->r_mem_off) = (__u32)val;
		break;
	case 8:
		*(__u64 *)((__u8 *)baddr + ur->r_mem_off) = (__u64)val;
		break;
	}
}

void do_ukreloc(__paddr_t r_paddr, __vaddr_t r_vaddr);

#endif /* !__ASSEMBLY__ */

#endif /* __UKRELOC_H__ */
