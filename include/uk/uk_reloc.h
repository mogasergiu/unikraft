#ifndef __UK_RELOC_H__
#define __UK_RELOC_H__

#define UK_RELOC_FLAGS_PHYS_REL	(1 << 0)
#define UK_RELOC_PLACEHOLDER		0xB00B
#define UK_RELOC_SIGNATURE		0xBADB0111
#define UK_RELOC_ALIGNMENT		0x1000

#ifdef __ASSEMBLY__

.macro ur_data type:req, sym:req, bytes:req, phys
.globl \sym\()_uk_reloc_data\bytes\()\phys\()
.set \sym\()_uk_reloc_data\bytes\()\phys\(), .
	.\type	UK_RELOC_PLACEHOLDER
.endm

#else  /* __ASSEMBLY__ */

#include <uk/arch/types.h>
#include <uk/plat/common/sections.h>

#define __uk_reloc __section(".uk_reloc") __used

struct uk_reloc {
	__u64 m_off;
	__u64 r_val_off;
	__u32 r_sz;
	__u32 flags;
} __packed;

#define UK_RELOC_ENTRY(ur_m_off, ur_r_val_off, ur_r_sz, ur_flags)		\
	{									\
		.m_off		= (ur_m_off),					\
		.r_val_off	= (ur_r_val_off),				\
		.r_sz		= (ur_r_sz),					\
		.flags		= (ur_flags),					\
	}

static inline void apply_uk_reloc(volatile struct uk_reloc *ur, __u64 val,
				  volatile void * volatile baddr)
{
	switch (ur->r_sz) {
	case 2:
		*(volatile __u16 * volatile) (baddr  + ur->m_off) = (__u16) val;
		break;
	case 4:
		*(volatile __u32 * volatile) (baddr  + ur->m_off) = (__u32) val;
		break;
	case 8:
		*(volatile __u64 * volatile) (baddr  + ur->m_off) = (__u64) val;
		break;
	}
}

#endif /* !__ASSEMBLY__ */

#endif /* __UK_RELOC_H__ */
