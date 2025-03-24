/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2024, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

#define _GNU_SOURCE /* struct clone_args */

#include <sched.h>
#include <signal.h>

#include <uk/essentials.h>
#include <uk/process.h>
#include <uk/sched.h>
#include <uk/syscall.h>

#include "process.h"

#if UK_LIBC_SYSCALLS
#if CONFIG_ARCH_X86_64
pid_t vfork(void);
__asm__(
	".global vfork\n\t"
	"vfork:\n\t"
	"jmp	uk_syscall_e_vfork\n\t"
);
#elif CONFIG_ARCH_ARM_64
__asm__(
	".global vfork\n\t"
	"vfork:\n\t"
	"b	uk_syscall_e_vfork\n\t"
);
#else /* !CONFIG_ARCH_X86_64 && !CONFIG_ARCH_ARM_64 */
#error Unknown architecture selected
#endif /* !CONFIG_ARCH_X86_64 && !CONFIG_ARCH_ARM_64 */
#endif /* UK_LIBC_SYSCALLS */

UK_LLSYSCALL_R_E_DEFINE(pid_t, vfork)
{
	struct posix_process *child_proc;
	struct clone_args cl_args = {0};
	pid_t child_tid;

	cl_args.flags       = CLONE_VM | CLONE_VFORK;
	cl_args.exit_signal = SIGCHLD;

	child_tid = uk_clone(&cl_args, sizeof(cl_args), execenv);
	if (unlikely(child_tid < 0)) {
		uk_pr_err("Could not clone thread\n");
		return child_tid;
	}

	child_proc = tid2pprocess(child_tid);
	UK_ASSERT(child_proc);

	return child_proc->pid;
}
