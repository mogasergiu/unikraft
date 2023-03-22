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

#endif /* !__ASSEMBLY__ */

#endif /* __UKRELOC_H__ */
