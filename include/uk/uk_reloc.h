#ifndef __UK_RELOC_H__
#define __UK_RELOC_H__

#define UK_RELOC_FLAGS_PHYS_REL	(1 << 0)
#define UK_RELOC_PLACEHOLDER		0xB00B
#define UK_RELOC_SIGNATURE		0xBADB0111
#define UK_RELOC_ALIGNMENT		0x1000

#ifdef __ASSEMBLY__

.macro ur_data type:req, sym:req, bytes:req, phys
#ifdef CONFIG_OPTIMIZE_PIE
.globl \sym\()_uk_reloc_data\bytes\()\phys\()
.set \sym\()_uk_reloc_data\bytes\()\phys\(), .
	.\type	UK_RELOC_PLACEHOLDER
#else
	.\type	\sym
#endif
.endm

#ifndef CONFIG_OPTIMIZE_PIE
do_uk_reloc:
	ret
#endif

/**
 * For proper positional independence we require that whatever page table
 * related entries in the static page table we may have, they must be
 * relocatable against a dynamic physical address.
 */
.macro ur_pte pte_sym:req, pte:req
#ifdef CONFIG_OPTIMIZE_PIE
	ur_data quad, \pte_sym, 8, _phys
.globl \pte_sym\()_uk_reloc_pte_attr0
.set \pte_sym\()_uk_reloc_pte_attr0, \pte
#else
	ur_data quad, (\pte_sym + \pte), 8, _phys
#endif
.endm

#else  /* __ASSEMBLY__ */

#include <uk/arch/types.h>
#include <uk/plat/common/sections.h>
#include <uk/essentials.h>

#define __uk_reloc __section(".uk_reloc") __used

struct uk_reloc {
	__u64 m_off;
	__u64 r_val_off;
	__u32 r_sz;
	__u32 flags;
} __packed;

struct uk_reloc_hdr {
	__u64 signature;
	struct uk_reloc urs[];
} __packed __align(__SIZEOF_LONG__);

#define UK_RELOC_ENTRY(ur_m_off, ur_r_val_off, ur_r_sz, ur_flags)		\
	{									\
		.m_off		= (ur_m_off),					\
		.r_val_off	= (ur_r_val_off),				\
		.r_sz		= (ur_r_sz),					\
		.flags		= (ur_flags),					\
	}

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
		*(__u16 *) ((__u8 *) baddr  + ur->m_off) = (__u16) val;
		break;
	case 4:
		*(__u32 *) ((__u8 *) baddr  + ur->m_off) = (__u32) val;
		break;
	case 8:
		*(__u64 *) ((__u8 *) baddr  + ur->m_off) = (__u64) val;
		break;
	}
}

void do_uk_reloc(__paddr_t r_paddr, __vaddr_t r_vaddr);

#endif /* !__ASSEMBLY__ */

#endif /* __UK_RELOC_H__ */
