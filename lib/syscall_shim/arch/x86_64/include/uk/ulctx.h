#ifndef __UK_SYSCALL_H__
#error Do not include this header directly
#endif

#define UKARCH_ULCTX_SIZE			16

#if !__ASSEMBLY__

#include <uk/essentials.h>

/* Architecture specific userland context */
struct ukarch_ulctx {
	/* The current value of %gs's gs_base register of the application.
	 * On syscall entry, this will be updated to hold the value of
	 * MSR_KERNEL_GS_BASE following a swapgs instruction.
	 */
	__uptr gs_base;

	__uptr fs_base;
};

UK_CTASSERT(sizeof(struct ukarch_ulctx) == UKARCH_ULCTX_SIZE);

#endif /* !__ASSEMBLY__ */
