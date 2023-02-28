#ifndef __ARM_64_UK_RELOC_H__
#define __ARM_64_UK_RELOC_H__

#include <uk/plat/common/sections.h>
#include <uk/uk_reloc.h>

static inline void st_curr_baddr(volatile void * volatile * baddr)
{
	__asm__ __volatile__(
		"adrp x0, _base_addr\n"
		"add x0, x0, :lo12:_base_addr\n"
		"str x0, %0\n"
		:
		: "m"(*baddr)
		: "x0"
	);
}

#endif /* __ARM_64_UK_RELOC_H__ */
