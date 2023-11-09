/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2023, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */
#include <uk/arch/ctx.h>
#include <uk/arch/lcpu.h>
#include <uk/arch/types.h>
#include <uk/assert.h>
#include <uk/essentials.h>
#include <uk/plat/common/cpu.h>
#include <uk/thread.h>
#include <uk/syscall.h>

#if CONFIG_LIBSYSCALL_SHIM_HANDLER_ULTLS
__uptr ukarch_ulctx_get_tlsp(struct ukarch_ulctx *ulctx)
{
	UK_ASSERT(ulctx);

	return ulctx->fs_base;
}

void ukarch_ulctx_set_tlsp(struct ukarch_ulctx *ulctx, __uptr tlsp)
{
	UK_ASSERT(ulctx);

	uk_pr_debug("System call updated userland TLS pointer register to %p (before: %p)\n",
		    (void *)ulctx->fs_base, (void *)tlsp);

	ulctx->fs_base = tlsp;
}

void ukarch_ulctx_switchoff_tls(struct ukarch_ulctx *ulctx)
{
	struct uk_thread *t = uk_thread_current();

	UK_ASSERT(ulctx);
	UK_ASSERT(t);

	ulctx->fs_base = ukplat_tlsp_get();
	ukplat_tlsp_set(t->uktlsp);
	t->tlsp = t->uktlsp;
}

void ukarch_ulctx_switchon_tls(struct ukarch_ulctx *ulctx)
{
	struct uk_thread *t = uk_thread_current();

	UK_ASSERT(ulctx);
	UK_ASSERT(t);

	ukplat_tlsp_set(ulctx->fs_base);
	t->tlsp = ulctx->fs_base;
}
#endif /* CONFIG_LIBSYSCALL_SHIM_HANDLER_ULTLS */
