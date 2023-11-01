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

void ukarch_ulctx_store(struct ukarch_ulctx *ulctx)
{
	UK_ASSERT(ulctx);

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
	wrmsrl(X86_MSR_GS_BASE, lcpu_get_current());
	wrmsrl(X86_MSR_KERNEL_GS_BASE, ulctx->gs_base);
}
