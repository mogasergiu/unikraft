/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2023, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

#ifndef __UKRELOC_H__
#define __UKRELOC_H__

#define UKRELOC_FLAGS_PHYS_REL		(1 << 0)
#define UKRELOC_PLACEHOLDER		0xB00B
#define UKRELOC_SIGNATURE		0xBADB0111
#define UKRELOC_ALIGNMENT		0x1000

#ifdef __ASSEMBLY__

/* Used to append an entry to the initial .ukreloc section, before mkukreloc.py
 * adds prepends the .rela.dyn entries. Furthermore, also append an entry to
 * .rela.dyn to ensure the symbol is not discarded and is seen as a relocation
 * by the linker
 */
#if defined(__X86_64__)
#define RELA_DYN_ENTRY_TYPE R_X86_64_64
#elif defined(__ARM_64__)
#define RELA_DYN_ENTRY_TYPE R_AARCH64_ABS64
#endif
.macro ur_sec_updt sym:req, loc:req
.pushsection .ukreloc
	.quad	0x0			/* r_mem_off */
	.quad	0x0			/* r_addr */
	/* Note: Must be in-between so there is room before and after for
	 * when the static linker resolves these relcations with absolute
	 * initial addresses. We assume that the \loc's displacement cannot be
	 * higher/lower than +/-8 bytes since no immediate is that big at this
	 * moment in time. The actual .reloc does not take up any space, it
	 * merely makes the linker place an additional .rela.dyn entry as well
	 * as statically resolve a relocation at the indicated spot (our \loc).
	 */
	.reloc	\loc, RELA_DYN_ENTRY_TYPE, \sym
	.long	0x0			/* r_sz */
	.long	0x0			/* flags */
.popsection
.endm

/* If CONFIG_OPTIMIZE_PIE is enabled, this will create a ukreloc symbol that
 * mkukreloc.py will process. Example usage:
 * ```
 * ur_data	quad, gdt64, 8, _phys
 * ```
 * The above will make mkukreloc.py process the symbol gdt64_ukeloc_data8_phys
 * representing in memory where this data is placed and the following entry:
 * struct ukreloc {
 *        __u64 r_mem_off = gdt64_ukeloc_data8_phys - __BASE_ADDR
 *        __u64 r_addr = gdt64 - __BASE_ADDR
 *        __u32 r_sz = 8 from gdt64_ukeloc_data[8]_phys
 *        __u32 flags = UKRELOC_FLAGS_PHYS_REL from gdt64_ukreloc_data8[_phys]
 * } __packed;
 *
 * If CONFIG_OPTIMIZE_PIE is not enabled then it will be simply resolved to
 * ```
 * .quad gdt64
 * ```
 * @param type The type GAS directive, i.e. quad, long, short, etc.
 * @param sym The symbol to relocate
 * @param bytes The size in bytes of the relocation
 * @param phys Optional, if value is _phys, UKRELOC_FLAGS_PHYS_REL is set
 */
.macro ur_data type:req, sym:req, bytes:req, phys
#ifdef CONFIG_OPTIMIZE_PIE
.globl \sym\()_ukreloc_data\bytes\()\phys\()
.set \sym\()_ukreloc_data\bytes\()\phys\(), .
	.\type	UKRELOC_PLACEHOLDER
	ur_sec_updt	\sym, .
#else
	.\type	\sym
#endif
.endm

/**
 * For proper positional independence we require that whatever page table
 * related entries in the static page table we may have, they must be
 * relocatable against a dynamic physical address. In addition to what
 * `ur_data` does, `ur_pte` also creates a ukreloc symbol with `pte_attr0`
 * suffix, containing the value of the PTE attribute. Example usage:
 * ```
 * ur_pte	x86_bpt_pd0_0, PTE_RW
 * ```
 * The above will make mkukreloc.py process the symbol
 * x86_bpt_pd0_0_ukeloc_data8_phys representing in memory where this data is
 * placed, x86_bpt_pd0_0_ukeloc_pte_attr0 representing the value of the
 * page table entry attributes and the following entry:
 * struct ukreloc {
 *        __u64 r_mem_off = x86_bpt_pd0_0_ukeloc_data8_phys - __BASE_ADDR
 *        __u64 r_addr = x86_bpt_pd0_0 - __BASE_ADDR + PTE_RW
 *        __u32 r_sz = 8 from x86_bpt_pd0_0_ukeloc_data[8]_phys
 *        __u32 flags = UKRELOC_FLAGS_PHYS_REL from x86_bpt_pd0_0_ukreloc_data8[_phys]
 * } __packed;
 *
 * @param sym The symbol to relocate
 * @param pte The page table entry's attribute flags
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
	/* Offset relative to runtime base address where to apply relocation */
	__u64 r_mem_off;
	/* Relative address value of the relocation */
	__u64 r_addr;
	/* Size of the relocation */
	__u32 r_sz;
	/* Relocation flags to change relocator behavior for this entry */
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
	/* Signature of the .ukreloc section */
	__u32 signature;
	/* The ukreloc entries to be iterated upon by the relocator */
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
 *
 * @param ur Pointer to the ukreloc entry to apply
 * @param val The value of the relocation
 * @param baddr The base address relative to which the relocation is applied
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

/* Relocates initial mkbootinfo.py memory regions and applies all ukreloc
 * entries in the current image's .ukreloc section.
 *
 * @param r_paddr The physical address relative to which we apply a relocation,
 *                used if UKRELOC_FLAGS_PHYS_REL flag is set
 * @param r_vaddr The virtual address relative to which we apply a relocation
 */
void do_ukreloc(__paddr_t r_paddr, __vaddr_t r_vaddr);

#endif /* !__ASSEMBLY__ */

#endif /* __UKRELOC_H__ */