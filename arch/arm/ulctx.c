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
}

void ukarch_ulctx_load(struct ukarch_ulctx *ulctx)
{
	UK_ASSERT(ulctx);
}

#if CONFIG_LIBSYSCALL_SHIM_HANDLER_ULTLS
__uptr ukarch_ulctx_get_tlsp(struct ukarch_ulctx *u)
{
	UK_ASSERT(u);

	return u->tpidr_el0;
}

void ukarch_ulctx_set_tlsp(struct ukarch_ulctx *u, __uptr tlsp)
{
	UK_ASSERT(u);

	u->tpidr_el0 = tlsp;
}
#endif /* CONFIG_LIBSYSCALL_SHIM_HANDLER_ULTLS */
