#ifndef __UK_SYSCALL_H_
#error Do not include this header directly
#endif

#if !__ASSEMBLY__

#include <uk/essentials.h>

/* Architecture specific userland context */
struct ukarch_ulctx {
	__uptr tpidr_el0;
};

#endif /* !__ASSEMBLY__ */
