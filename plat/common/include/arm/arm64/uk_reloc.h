#ifndef __ARM_64_UK_RELOC_H__
#define __ARM_64_UK_RELOC_H__

#include <uk/plat/common/uk_reloc.h>

#ifdef __ASSEMBLY__

.macro ur_ldr reg:req, sym:req
	adrp	\reg, \sym
	add	\reg, \reg, :lo12:\sym
.endm

#endif /* __ASSEMBLY__ */

#endif /* __ARM_64_UK_RELOC_H__ */
