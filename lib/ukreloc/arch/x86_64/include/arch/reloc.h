#ifndef __X86_64_UK_RELOC_H__
#define __X86_64_UK_RELOC_H__

#include "../../../include/uk/reloc.h"

#ifdef __ASSEMBLY__

.macro ur_mov sym:req, reg:req, bytes:req, phys
#ifdef CONFIG_OPTIMIZE_PIE
/* UKRELOC_PLACEHODER is 16 bytes, so in 64-bit code we must force a `movabs`
 * to ensure that the last amount of opcodes are meant for the immediate
 */
.ifeq  (8 - \bytes)
	movabs	$UKRELOC_PLACEHOLDER, \reg
.endif
.ifgt  (8 - \bytes)
	mov	$UKRELOC_PLACEHOLDER, \reg
.endif
.globl \sym\()_ukreloc_imm\bytes\()\phys\()
.set \sym\()_ukreloc_imm\bytes\()\phys\(), . - \bytes
	nop
	ur_sec_updt
#else
	mov	$\sym, \reg
#endif
.endm

#endif /* __ASSEMBLY__ */

#endif /* __X86_64_UK_RELOC_H__ */
