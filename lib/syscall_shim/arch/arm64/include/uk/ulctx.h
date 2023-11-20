#ifndef __UK_SYSCALL_H__
#error Do not include this header directly
#endif

#define UKARCH_ULCTX_SIZE			8

#if !__ASSEMBLY__

#include <uk/essentials.h>

/* Architecture specific userland context */
struct ukarch_ulctx {
	__uptr tpidr_el0;
};
UK_CTASSERT(sizeof(struct ukarch_ulctx) == UKARCH_ULCTX_SIZE);

#endif /* !__ASSEMBLY__ */
