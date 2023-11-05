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

void ukarch_ulctx_store(struct ukarch_ulctx *ulctx)
{
	UK_ASSERT(ulctx);
	UK_ASSERT(!(ulctx->flags & UKARCH_ULCTX_FLAGS_NEWCLONE));

	if (!(ulctx->flags & UKARCH_ULCTX_FLAGS_INSYSCALL))
		return;

	/* This can only be called from Unikraft ctx in bincompat mode.
	 * Therefore, X86_MSR_GS_BASE holds the current `struct lcpu` and
	 * X86_MSR_KERNEL_GS_BASE contains the app-saved gs_base.
	 */
	ulctx->gs_base = rdmsrl(X86_MSR_KERNEL_GS_BASE);
}

void ukarch_ulctx_load(struct ukarch_ulctx *ulctx)
{
	UK_ASSERT(ulctx);
	UK_ASSERT(lcpu_get_current());

	if (!(ulctx->flags & UKARCH_ULCTX_FLAGS_INSYSCALL))
		return;

	/* This can only be called from Unikraft ctx in bincompat mode.
	 * Therefore, X86_MSR_GS_BASE must hold the current `struct lcpu` and
	 * X86_MSR_KERNEL_GS_BASE should contain the preserved app
	 * gs_base register value.
	 */
	if (ulctx->flags & UKARCH_ULCTX_FLAGS_NEWCLONE) {
		wrmsrl(X86_MSR_KERNEL_GS_BASE, (__u64)lcpu_get_current());
		wrmsrl(X86_MSR_GS_BASE, ulctx->gs_base);

		ulctx->flags &= ~UKARCH_ULCTX_FLAGS_NEWCLONE;
	} else {
		wrmsrl(X86_MSR_GS_BASE, (__u64)lcpu_get_current());
		wrmsrl(X86_MSR_KERNEL_GS_BASE, ulctx->gs_base);
	}
}

#if CONFIG_LIBSYSCALL_SHIM_HANDLER_ULTLS
__uptr ukarch_ulctx_get_tlsp(struct ukarch_ulctx *u)
{
	UK_ASSERT(u);

	return u->fs_base;
}

void ukarch_ulctx_set_tlsp(struct ukarch_ulctx *u, __uptr tlsp)
{
	UK_ASSERT(u);

	uk_pr_debug("System call updated userland TLS pointer register to %p (before: %p)\n",
		    (void *)u->fs_base, (void *)tlsp);

	u->fs_base = tlsp;
}
#endif /* CONFIG_LIBSYSCALL_SHIM_HANDLER_ULTLS */
