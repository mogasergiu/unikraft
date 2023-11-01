#ifndef __UK_SYSCALL_H_
#error Do not include this header directly
#endif

#if !__ASSEMBLY__

#include <uk/essentials.h>

/* Architecture specific userland context */
struct ukarch_ulctx {
	/* The current value of %gs's gs_base register of the application.
	 * On syscall entry, this will be updated to hold the value of
	 * MSR_KERNEL_GS_BASE following a swapgs instruction */
	__uptr gs_base;

	__uptr fs_base;
};

#endif /* !__ASSEMBLY__ */
