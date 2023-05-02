#ifndef __ARM_64_UK_RELOC_H__
#define __ARM_64_UK_RELOC_H__

#include "../../../include/uk/reloc.h"

#ifdef __ASSEMBLY__

.macro ur_ldr reg:req, sym:req
#ifdef CONFIG_OPTIMIZE_PIE
	adrp	\reg, \sym
	add	\reg, \reg, :lo12:\sym
#else
	ldr	\reg, =\sym
#endif
.endm

#endif /* __ASSEMBLY__ */

#endif /* __ARM_64_UK_RELOC_H__ */
