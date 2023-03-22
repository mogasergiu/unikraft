#ifndef __UK_RELOC_H__
#define __UK_RELOC_H__

#define UK_RELOC_FLAGS_PHYS_REL		(1 << 0)
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

#endif /* !__ASSEMBLY__ */

#endif /* __UK_RELOC_H__ */
