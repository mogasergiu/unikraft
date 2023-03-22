#ifndef __X86_UK_RELOC_H__
#define __X86_UK_RELOC_H__

#include <uk/plat/common/uk_reloc.h>

#ifdef __ASSEMBLY__

.macro ur_mov sym:req, reg:req, bytes:req, phys
#ifdef CONFIG_OPTIMIZE_PIE
	mov	$UK_RELOC_PLACEHOLDER, \reg
.globl \sym\()_uk_reloc_imm\bytes\()\phys\()
.set \sym\()_uk_reloc_imm\bytes\()\phys\(), . - \bytes
	nop
	ur_sec_updt
#else
	mov	$\sym, \reg
#endif
.endm

#endif /* __ASSEMBLY__ */

#endif /* __X86_UK_RELOC_H__ */
