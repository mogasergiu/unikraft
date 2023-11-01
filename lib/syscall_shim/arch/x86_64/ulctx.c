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

#define IS_LCPU_PTR(ptr)						\
	(IN_RANGE((ptr),						\
		  (__uptr)lcpu_get(0),					\
		  (__uptr)lcpu_get(ukplat_lcpu_count()) -		\
		  (__uptr)lcpu_get(0)))					\

void ukarch_ulctx_switchoff(struct ukarch_ulctx *ulctx)
{
	UK_ASSERT(ulctx);
	UK_ASSERT(lcpu_get_current());
	UK_ASSERT(!IS_LCPU_PTR(rdmsrl(X86_MSR_KERNEL_GS_BASE)));

	/* This can only be called from Unikraft ctx in bincompat mode.
	 * Therefore, X86_MSR_GS_BASE holds the current `struct lcpu` and
	 * X86_MSR_KERNEL_GS_BASE contains the app-saved gs_base.
	 */
	u->gs_base = rdmsrl(X86_MSR_KERNEL_GS_BASE);

#if CONFIG_LIBSYSCALL_SHIM_HANDLER_ULTLS
	ukarch_ulctx_switchoff_tls(ulctx);
#endif /* CONFIG_LIBSYSCALL_SHIM_HANDLER_ULTLS */
}

void ukarch_ulctx_switchon(struct ukarch_ulctx *ulctx)
{
	UK_ASSERT(ulctx);
	UK_ASSERT(lcpu_get_current());
	UK_ASSERT(IS_LCPU_PTR(rdmsrl(X86_MSR_KERNEL_GS_BASE)));

	/* This can only be called from Unikraft ctx in bincompat mode.
	 * Therefore, X86_MSR_GS_BASE holds the current `struct lcpu` and
	 * X86_MSR_KERNEL_GS_BASE contains the app-saved gs_base.
	 */
	wrmsrl(X86_MSR_GS_BASE, (__u64)lcpu_get_current());
	wrmsrl(X86_MSR_KERNEL_GS_BASE, ulctx->gs_base);

#if CONFIG_LIBSYSCALL_SHIM_HANDLER_ULTLS
	ukarch_ulctx_switchon_tls(ulctx);
#endif /* CONFIG_LIBSYSCALL_SHIM_HANDLER_ULTLS */
}

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
