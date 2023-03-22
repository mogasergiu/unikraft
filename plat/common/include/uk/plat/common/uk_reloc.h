#ifndef __UK_RELOC_H__
#define __UK_RELOC_H__

#define UK_RELOC_FLAGS_PHYS_REL	(1 << 0)
#define UK_RELOC_PLACEHOLDER		0xB00B
#define UK_RELOC_SIGNATURE		0xBADB0111
#define UK_RELOC_ALIGNMENT		0x1000

#ifdef __ASSEMBLY__

.macro ur_sec_updt
.pushsection .uk_reloc
	.quad	0x0  /* m_off */
	.quad	0x0  /* r_val_off */
	.long	0x0  /* r_sz */
	.long	0x0  /* flags */
.popsection
.endm

.macro ur_data type:req, sym:req, bytes:req, phys
#ifdef CONFIG_OPTIMIZE_PIE
.globl \sym\()_uk_reloc_data\bytes\()\phys\()
.set \sym\()_uk_reloc_data\bytes\()\phys\(), .
	.\type	UK_RELOC_PLACEHOLDER
	ur_sec_updt
#else
	.\type	\sym
#endif
.endm

#ifndef CONFIG_OPTIMIZE_PIE
do_uk_reloc:
	ret
#endif

#else  /* __ASSEMBLY__ */

#include <uk/arch/types.h>
#include <uk/plat/common/sections.h>
#include <uk/essentials.h>

struct uk_reloc {
	__u64 m_off;
	__u64 r_val_off;
	__u32 r_sz;
	__u32 flags;
} __packed;

#define UK_RELOC_ENTRY(ur_m_off, ur_r_val_off, ur_r_sz, ur_flags)	\
	{								\
		.m_off		= (ur_m_off),				\
		.r_val_off	= (ur_r_val_off),			\
		.r_sz		= (ur_r_sz),				\
		.flags		= (ur_flags),				\
	}

struct uk_reloc_hdr {
	__u32 signature;
	struct uk_reloc urs[];
} __packed __align(__SIZEOF_LONG__);

/* Misaligned access here is never going to happen for a non-x86 architecture
 * as there are no uk_reloc_imm relocation types defined for them.
 * We need this for x86 to patch early boot code, so it's a false positive.
 * An alignment exception (#AC if CR0.AM=1 and RFLAGS.AC=1) on x86 can only
 * occur in userspace, which Unikraft does not deal with anyway.
 * If someone, in the future, adds a uk_reloc type that allows
 * misalignments on architectures that do not allow this, it's most likely
 * not needed and an alternative solution should be considered.
 */
#if defined(__X86_64__)
#define X86_64_NO_SANITIZE_ALIGNMENT __attribute__((no_sanitize("alignment")))
#else
#define X86_64_NO_SANITIZE_ALIGNMENT
#endif
static inline void X86_64_NO_SANITIZE_ALIGNMENT
apply_uk_reloc(struct uk_reloc *ur, __u64 val, void *baddr)
{
	switch (ur->r_sz) {
	case 2:
		*(__u16 *)((__u8 *)baddr  + ur->m_off) = (__u16)val;
		break;
	case 4:
		*(__u32 *)((__u8 *)baddr  + ur->m_off) = (__u32)val;
		break;
	case 8:
		*(__u64 *)((__u8 *)baddr  + ur->m_off) = (__u64)val;
		break;
	}
}

void do_uk_reloc(__paddr_t r_paddr, __vaddr_t r_vaddr);

#endif /* !__ASSEMBLY__ */

#endif /* __UK_RELOC_H__ */
