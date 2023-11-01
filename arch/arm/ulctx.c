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
}

void ukarch_ulctx_load(struct ukarch_ulctx *ulctx)
{
	UK_ASSERT(ulctx);
}
