#ifndef __X86_UK_RELOC_H__
#define __X86_UK_RELOC_H__

#include <uk/plat/common/sections.h>
#include <uk/uk_reloc.h>

static inline void st_curr_baddr(void **baddr)
{
	volatile __off offset = 0;

	/* Get negative offset from `do_uk_reloc`'s symbolic value to the base
	 * of the loaded unikernel
	*/
	__asm__ __volatile__(
		"movq $(_base_addr - do_uk_reloc), %0"
		:
		: "m"(offset)
	);

	/* Add the negative offset to `do_uk_reloc`, thus obtaining our current
	 * load address
	 */
	*baddr = (void *) ((__s64) do_uk_reloc + (__s64) offset);
}

#endif /* __X86_UK_RELOC_H__ */
