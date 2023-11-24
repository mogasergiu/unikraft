/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Authors: Yuri Volchkov <yuri.volchkov@neclab.eu>
 *          Simon Kuenzer <simon.kuenzer@neclab.eu>
 *
 *
 * Copyright (c) 2019, NEC Laboratories Europe GmbH, NEC Corporation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __UK_SYSCALL_H__
#define __UK_SYSCALL_H__

#include <uk/ulctx.h>

#if defined(__X86_64__)
/* 512 for the actual structure + 64 bytes for the XSAVE header */
#define UKARCH_ECTX_SAVE_MAX_SIZE			578
#define UKARCH_ECTX_SAVE_MAX_ALIGN			64
#elif defined(__ARM_64__)
/* 32 * 2 * 8 bytes + 4 bytes (FPSR) + 4 bytes (FPCR) */
#define UKARCH_ECTX_SAVE_MAX_SIZE			520
#define UKARCH_ECTX_SAVE_MAX_ALIGN			16
#else /* !__X86_64__ && !__ARM_64__ */
#error "Undefined architecture"
#endif

/* We must make sure that ECTX is aligned, so we make use of some padding,
 * whose size is equal to what we need to add to UKARCH_ECTX_SAVE_MAX_SIZE
 * to make it aligned with UKARCH_ECTX_SAVE_MAX_ALIGN
 */
#define UK_SYSCALL_PAD_SIZE				\
	(ALIGN_UP(UKARCH_ECTX_SAVE_MAX_SIZE,		\
		 UKARCH_ECTX_SAVE_MAX_ALIGN) -		\
	 UKARCH_ECTX_SAVE_MAX_SIZE)
/* If we make sure that the in-memory structure's end address is aligned to
 * the ECTX alignment, then subtracting from that end address a value that is
 * also a multiple of that alignment, guarantees that the resulted address
 * is also ECTX aligned.
 */
#define UK_SYSCALL_REGS_END_ALIGN			\
	UKARCH_ECTX_SAVE_MAX_ALIGN
#define UK_SYSCALL_REGS_SIZE				\
	(UK_SYSCALL_PAD_SIZE +				\
	 UKARCH_ECTX_SAVE_MAX_SIZE +			\
	 UKARCH_ULCTX_SIZE +				\
	 __REGS_SIZEOF)

#if !__ASSEMBLY__
#include <uk/config.h>
#include <uk/essentials.h>
#include <uk/errptr.h>
#include <errno.h>
#include <stdarg.h>
#include <uk/print.h>
#include "legacy_syscall.h"
#include <uk/thread.h>

#ifdef __cplusplus
extern "C" {
#endif

struct uk_syscall_regs {
	struct __regs regs;
	struct ukarch_ulctx ulctx;
	__u8 ectx[UKARCH_ECTX_SAVE_MAX_SIZE];
	__u8 pad[UK_SYSCALL_PAD_SIZE];
};

UK_CTASSERT(sizeof(struct uk_syscall_regs) == UK_SYSCALL_REGS_SIZE);
UK_CTASSERT(IS_ALIGNED(UK_SYSCALL_PAD_SIZE + UKARCH_ECTX_SAVE_MAX_SIZE,
		       UKARCH_ECTX_SAVE_MAX_ALIGN));

/*
 * Whenever the hidden Config.uk option LIBSYSCALL_SHIM_NOWRAPPER
 * is set, the creation of libc-style wrappers are disable by the
 * UK_SYSCALL_DEFINE() and UK_SYSCALL_R_DEFINE() macros. Alternatively,
 * UK_LIBC_SYSCALLS can be set to 0 through compilation flags.
 */
#ifndef UK_LIBC_SYSCALLS
#if CONFIG_LIBSYSCALL_SHIM && CONFIG_LIBSYSCALL_SHIM_NOWRAPPER
#define UK_LIBC_SYSCALLS (0)
#else
#define UK_LIBC_SYSCALLS (1)
#endif /* CONFIG_LIBSYSCALL_SHIM && CONFIG_LIBSYSCALL_SHIM_NOWRAPPER */
#endif /* UK_LIBC_SYSCALLS */

#ifdef CONFIG_LIBSYSCALL_SHIM
/**
 * Library-internal thread-local variable containing the return address
 * of the caller of the currently called system call.
 * NOTE: Use the `uk_syscall_return_addr()` macro to retrieve the return address
 *       within a system call implementation. Please note that this macro is
 *       only available if `lib/syscall_shim` is part of the build.
 *       This implies that every system call implementation that require to know
 *       the return address have a dependency to `lib/syscall_shim`.
 */
extern __uk_tls __uptr _uk_syscall_return_addr;

/**
 * Returns the return address of the currently called system call.
 */
#define uk_syscall_return_addr()					\
	((__uptr)((_uk_syscall_return_addr != 0x0)			\
		  ? _uk_syscall_return_addr : __return_addr(0)))

#define __UK_SYSCALL_RETADDR_ENTRY();					\
	do { _uk_syscall_return_addr = uk_syscall_return_addr(); } while (0)

#if CONFIG_LIBSYSCALL_SHIM_HANDLER_ULTLS
/*
 * In the case the support for userland TLS pointers is enabled, we assume that
 * some system calls (like `arch_prctl` on `x86_64`) can change the TLS pointer.
 * In such a case, we need a safe way to access `_uk_syscall_return_addr` for
 * clearing after a system call handler was executed.
 */
#include <uk/thread.h>

#define __UK_SYSCALL_RETADDR_CLEAR();					\
	do { (uk_thread_uktls_var(uk_thread_current(),			\
				  _uk_syscall_return_addr)) = 0x0; } while (0)
#else /* !CONFIG_LIBSYSCALL_SHIM_HANDLER_ULTLS */
/* Without userland TLS pointer support, we assume that we do not have any
 * system call that changes the TLS pointer (harmfully). This means that we do
 * not need to rely on `lib/uksched`.
 */
#define __UK_SYSCALL_RETADDR_CLEAR();					\
	do { _uk_syscall_return_addr = 0x0; } while (0)
#endif /* !CONFIG_LIBSYSCALL_SHIM_HANDLER_ULTLS */

#else /* !CONFIG_LIBSYSCALL_SHIM */

/*
 * NOTE: The usage of `uk_syscall_return_addr()` requires the `syscall_shim`
 *       library to be present. In order to avoid mis-configurations, we
 *       inject an always failing compile-time assertion to stop compilation.
 */
#define uk_syscall_return_addr()					\
	({ UK_CTASSERT(0x0); 0xDEADB0B0; })

#define __UK_SYSCALL_RETADDR_ENTRY();					\
	do { } while (0)
#define __UK_SYSCALL_RETADDR_CLEAR();					\
	do { } while (0)
#endif /* !CONFIG_LIBSYSCALL_SHIM */

#if CONFIG_LIBSYSCALL_SHIM_HANDLER_ULTLS
#include <uk/thread.h>

/**
 * Library-internal thread-local variable containing the current userland
 * TLS pointer.
 * NOTE: Use the `uk_syscall_ultlsp()` macro to retrieve the userland TLS
 *       pointer.
 * NOTE: Userland TLS pointers are only supported on binary system calls.
 */
extern __uk_tls __uptr _uk_syscall_ultlsp;

/**
 * Returns the userland TLS pointer if it is not equal to the Unikraft tlsp of
 * the current thread and if it was set. Please note that we must be called
 * from a binary system call request.
 */
static inline __uptr uk_syscall_ultlsp(void)
{
	__uptr ultlsp = _uk_syscall_ultlsp;
	struct uk_thread *self = uk_thread_current();

	UK_ASSERT(self);
	if (ultlsp && (ultlsp != self->uktlsp))
		return ultlsp;
	return 0x0;
}
#else /* !CONFIG_LIBSYSCALL_SHIM_HANDLER_ULTLS */

/**
 * If we do not support binary system calls and userland TLS pointers, we do not
 * know any caller TLS pointer, so we can always return 0.
 */
static inline __uptr uk_syscall_ultlsp(void)
{
	return 0x0;
}
#endif /* !CONFIG_LIBSYSCALL_SHIM_HANDLER_ULTLS */

#define __uk_scc(X) ((long) (X))
typedef long uk_syscall_arg_t;

#define __UK_NAME2SCALLE_FN(name) UK_CONCAT(uk_syscall_e_, name)
#define __UK_NAME2SCALLR_FN(name) UK_CONCAT(uk_syscall_r_, name)

#define UK_USR_MAP0(...)
/* Taken from regmap_linuxabi.h, but defined differently so as not to
 * needlessly contaminate the namespace of source files including this header
 */
#if (defined __X86_64__)
#define usr_arg0		rdi
#define usr_arg1		rsi
#define usr_arg2		rdx
#define usr_arg3		r10
#define usr_arg4		r8
#define usr_arg5		r9
#elif (defined __ARM_64__)
#define usr_arg0		x[0]
#define usr_arg1		x[1]
#define usr_arg2		x[2]
#define usr_arg3		x[3]
#define usr_arg4		x[4]
#define usr_arg5		x[5]
#else
#error "Missing register mappings for selected target architecture"
#endif  /* !__X86_64__ && !__ARM_64__ */

#define UK_USR_MAP2_1(m, type, arg) (type)usr->regs.usr_arg0

#define UK_USR_MAP2_2(m, type, arg) (type)usr->regs.usr_arg1
#define UK_USR_MAP4_2(m, type, arg, ...)					\
	(type)usr->regs.usr_arg0, UK_USR_MAP2_2(m, __VA_ARGS__)

#define UK_USR_MAP2_3(m, type, arg) (type)usr->regs.usr_arg2
#define UK_USR_MAP4_3(m, type, arg, ...)					\
	(type)usr->regs.usr_arg1, UK_USR_MAP2_3(m, __VA_ARGS__)
#define UK_USR_MAP6_3(m, type, arg, ...)					\
	(type)usr->regs.usr_arg0, UK_USR_MAP4_3(m, __VA_ARGS__)

#define UK_USR_MAP2_4(m, type, arg) (type)usr->regs.usr_arg3
#define UK_USR_MAP4_4(m, type, arg, ...)					\
	(type)usr->regs.usr_arg2, UK_USR_MAP2_4(m, __VA_ARGS__)
#define UK_USR_MAP6_4(m, type, arg, ...)					\
	(type)usr->regs.usr_arg1, UK_USR_MAP4_4(m, __VA_ARGS__)
#define UK_USR_MAP8_4(m, type, arg, ...)					\
	(type)usr->regs.usr_arg0, UK_USR_MAP6_4(m, __VA_ARGS__)

#define UK_USR_MAP2_5(m, type, arg) (type)usr->regs.usr_arg4
#define UK_USR_MAP4_5(m, type, arg, ...)					\
	(type)usr->regs.usr_arg3, UK_USR_MAP2_5(m, __VA_ARGS__)
#define UK_USR_MAP6_5(m, type, arg, ...)					\
	(type)usr->regs.usr_arg2, UK_USR_MAP4_5(m, __VA_ARGS__)
#define UK_USR_MAP8_5(m, type, arg, ...)					\
	(type)usr->regs.usr_arg1, UK_USR_MAP6_5(m, __VA_ARGS__)
#define UK_USR_MAP10_5(m, type, arg, ...)					\
	(type)usr->regs.usr_arg0, UK_USR_MAP8_5(m, __VA_ARGS__)

#define UK_USR_MAP2_6(m, type, arg) (type)usr->regs.usr_arg5
#define UK_USR_MAP4_6(m, type, arg, ...)					\
	(type)usr->regs.usr_arg4, UK_USR_MAP2_6(m, __VA_ARGS__)
#define UK_USR_MAP6_6(m, type, arg, ...)					\
	(type)usr->regs.usr_arg3, UK_USR_MAP4_6(m, __VA_ARGS__)
#define UK_USR_MAP8_6(m, type, arg, ...)					\
	(type)usr->regs.usr_arg2, UK_USR_MAP6_6(m, __VA_ARGS__)
#define UK_USR_MAP10_6(m, type, arg, ...)					\
	(type)usr->regs.usr_arg1, UK_USR_MAP8_6(m, __VA_ARGS__)
#define UK_USR_MAP12_6(m, type, arg, ...)				\
	(type)usr->regs.usr_arg0, UK_USR_MAP10_6(m, __VA_ARGS__)
#define UK_USR_MAPx(nr_args, nr_actual_args, ...)				\
	UK_CONCAT(UK_CONCAT(UK_USR_MAP, nr_args),			\
		  _##nr_actual_args)(__VA_ARGS__)

#define  UK_ARG_MAP0(...)
#define  UK_ARG_MAP2(m, type, arg) m(type, arg)
#define  UK_ARG_MAP4(m, type, arg, ...) m(type, arg), UK_ARG_MAP2(m, __VA_ARGS__)
#define  UK_ARG_MAP6(m, type, arg, ...) m(type, arg), UK_ARG_MAP4(m, __VA_ARGS__)
#define  UK_ARG_MAP8(m, type, arg, ...) m(type, arg), UK_ARG_MAP6(m, __VA_ARGS__)
#define UK_ARG_MAP10(m, type, arg, ...) m(type, arg), UK_ARG_MAP8(m, __VA_ARGS__)
#define UK_ARG_MAP12(m, type, arg, ...) m(type, arg), UK_ARG_MAP10(m, __VA_ARGS__)
#define UK_ARG_MAP14(m, type, arg, ...) m(type, arg), UK_ARG_MAP12(m, __VA_ARGS__)
#define UK_ARG_MAPx(nr_args, ...) UK_CONCAT(UK_ARG_MAP, nr_args)(__VA_ARGS__)

/* Variant of UK_ARG_MAPx() but prepends a comma if nr_args > 0 */
#define  UK_ARG_EMAP0(...)
#define  UK_ARG_EMAP2(m, type, arg) , m(type, arg)
#define  UK_ARG_EMAP4(m, type, arg, ...) , m(type, arg), UK_ARG_MAP2(m, __VA_ARGS__)
#define  UK_ARG_EMAP6(m, type, arg, ...) , m(type, arg), UK_ARG_MAP4(m, __VA_ARGS__)
#define  UK_ARG_EMAP8(m, type, arg, ...) , m(type, arg), UK_ARG_MAP6(m, __VA_ARGS__)
#define UK_ARG_EMAP10(m, type, arg, ...) , m(type, arg), UK_ARG_MAP8(m, __VA_ARGS__)
#define UK_ARG_EMAP12(m, type, arg, ...) , m(type, arg), UK_ARG_MAP10(m, __VA_ARGS__)
#define UK_ARG_EMAP14(m, type, arg, ...) , m(type, arg), UK_ARG_MAP12(m, __VA_ARGS__)
#define UK_ARG_EMAPx(nr_args, ...) UK_CONCAT(UK_ARG_EMAP, nr_args)(__VA_ARGS__)

#define UK_S_ARG_LONG(type, arg)   long arg
#define UK_S_ARG_ACTUAL(type, arg) type arg
#define UK_S_ARG_LONG_MAYBE_UNUSED(type, arg)   long arg __maybe_unused
#define UK_S_ARG_ACTUAL_MAYBE_UNUSED(type, arg) type arg __maybe_unused
#define UK_S_ARG_CAST_LONG(type, arg)   (long) arg
#define UK_S_ARG_CAST_ACTUAL(type, arg) (type) arg

#if CONFIG_LIBSYSCALL_SHIM_DEBUG_SYSCALLS || CONFIG_LIBUKDEBUG_PRINTD
#define UK_ARG_FMT_MAP0(...)
#define UK_ARG_FMT_MAP2(m, type, arg) m(type, arg)
#define UK_ARG_FMT_MAP4(m, type, arg, ...) m(type, arg) ", " UK_ARG_FMT_MAP2(m, __VA_ARGS__)
#define UK_ARG_FMT_MAP6(m, type, arg, ...) m(type, arg) ", " UK_ARG_FMT_MAP4(m, __VA_ARGS__)
#define UK_ARG_FMT_MAP8(m, type, arg, ...) m(type, arg) ", " UK_ARG_FMT_MAP6(m, __VA_ARGS__)
#define UK_ARG_FMT_MAP10(m, type, arg, ...) m(type, arg) ", " UK_ARG_FMT_MAP8(m, __VA_ARGS__)
#define UK_ARG_FMT_MAP12(m, type, arg, ...) m(type, arg) ", " UK_ARG_FMT_MAP10(m, __VA_ARGS__)
#define UK_ARG_FMT_MAP14(m, type, arg, ...) m(type, arg) ", " UK_ARG_FMT_MAP12(m, __VA_ARGS__)
#define UK_ARG_FMT_MAPx(nr_args, ...) UK_CONCAT(UK_ARG_FMT_MAP, nr_args)(__VA_ARGS__)

#define UK_S_ARG_FMT_LONG(type, arg)  "(" STRINGIFY(type) ") %ld"
#define UK_S_ARG_FMT_LONGX(type, arg)  "(" STRINGIFY(type) ") 0x%lx"

#define __UK_SYSCALL_PRINTD(x, rtype, fname, ...)			\
	_uk_printd(uk_libid_self(), __STR_BASENAME__, __LINE__,		\
		   "(" STRINGIFY(rtype) ") " STRINGIFY(fname)		\
		   "(" UK_ARG_FMT_MAPx(x, UK_S_ARG_FMT_LONGX, __VA_ARGS__) ")\n" \
		   UK_ARG_EMAPx(x, UK_S_ARG_CAST_LONG, __VA_ARGS__) )
#else
#define __UK_SYSCALL_PRINTD(...) do {} while(0)
#endif /* CONFIG_LIBSYSCALL_SHIM_DEBUG || CONFIG_LIBUKDEBUG_PRINTD */

/* System call implementation that uses errno and returns -1 on errors */
/* TODO: `void` as return type is currently not supported.
 * NOTE: Workaround is to use `int` instead.
 */
/*
 * UK_LLSYSCALL_DEFINE()
 * Low-level variant, does not provide a libc-style wrapper
 */
#define __UK_LLSYSCALL_DEFINE(x, rtype, name, ename, rname, ...)	\
	long ename(UK_ARG_MAPx(x, UK_S_ARG_LONG, __VA_ARGS__));		\
	long rname(UK_ARG_MAPx(x, UK_S_ARG_LONG, __VA_ARGS__))		\
	{								\
		int _errno = errno;					\
		long ret;						\
									\
		__UK_SYSCALL_RETADDR_ENTRY();				\
		errno = 0;						\
		ret = ename(						\
			UK_ARG_MAPx(x, UK_S_ARG_CAST_LONG, __VA_ARGS__)); \
		if (ret == -1)						\
			ret = errno ? -errno : -EFAULT;			\
		errno = _errno;						\
		__UK_SYSCALL_RETADDR_CLEAR();				\
		return ret;						\
	}								\
	static inline rtype __##ename(UK_ARG_MAPx(x,			\
					UK_S_ARG_ACTUAL, __VA_ARGS__)); \
	long ename(UK_ARG_MAPx(x, UK_S_ARG_LONG, __VA_ARGS__))		\
	{								\
		long ret;						\
									\
		__UK_SYSCALL_PRINTD(x, rtype, ename, __VA_ARGS__);	\
		__UK_SYSCALL_RETADDR_ENTRY();				\
		ret = (long) __##ename(					\
			UK_ARG_MAPx(x, UK_S_ARG_CAST_ACTUAL, __VA_ARGS__)); \
		__UK_SYSCALL_RETADDR_CLEAR();				\
		return ret;						\
	}								\
	static inline rtype __##ename(UK_ARG_MAPx(x,			\
						  UK_S_ARG_ACTUAL_MAYBE_UNUSED,\
						  __VA_ARGS__))
#define _UK_LLSYSCALL_DEFINE(...) __UK_LLSYSCALL_DEFINE(__VA_ARGS__)
#define UK_LLSYSCALL_DEFINE(rtype, name, ...)				\
	_UK_LLSYSCALL_DEFINE(UK_NARGS(__VA_ARGS__),			\
			     rtype,					\
			     name,					\
			     __UK_NAME2SCALLE_FN(name),			\
			     __UK_NAME2SCALLR_FN(name),			\
			     __VA_ARGS__)

/*
 * UK_SYSCALL_DEFINE()
 * Based on UK_LLSYSCALL_DEFINE and provides a libc-style wrapper
 * in case UK_LIBC_SYSCALLS is enabled
 */
#if UK_LIBC_SYSCALLS
#define __UK_SYSCALL_DEFINE(x, rtype, name, ename, rname, ...)		\
	long ename(UK_ARG_MAPx(x, UK_S_ARG_LONG, __VA_ARGS__));		\
	rtype name(UK_ARG_MAPx(x, UK_S_ARG_ACTUAL, __VA_ARGS__))	\
	{								\
		rtype ret;						\
									\
		__UK_SYSCALL_RETADDR_ENTRY();				\
		ret = (rtype) ename(					\
			UK_ARG_MAPx(x, UK_S_ARG_CAST_LONG, __VA_ARGS__)); \
		__UK_SYSCALL_RETADDR_CLEAR();				\
		return ret;						\
	}								\
	__UK_LLSYSCALL_DEFINE(x, rtype, name, ename, rname, __VA_ARGS__)
#define _UK_SYSCALL_DEFINE(...) __UK_SYSCALL_DEFINE(__VA_ARGS__)
#define UK_SYSCALL_DEFINE(rtype, name, ...)				\
	_UK_SYSCALL_DEFINE(UK_NARGS(__VA_ARGS__),			\
			   rtype,					\
			   name,					\
			   __UK_NAME2SCALLE_FN(name),			\
			   __UK_NAME2SCALLR_FN(name),			\
			   __VA_ARGS__)
#else
#define UK_SYSCALL_DEFINE(rtype, name, ...)				\
	_UK_LLSYSCALL_DEFINE(UK_NARGS(__VA_ARGS__),			\
			     rtype,					\
			     name,					\
			     __UK_NAME2SCALLE_FN(name),			\
			     __UK_NAME2SCALLR_FN(name),			\
			     __VA_ARGS__)
#endif /* UK_LIBC_SYSCALLS */

/* Raw system call implementation that is returning negative codes on errors */
/* TODO: `void` as return type is currently not supported.
 * NOTE: Workaround is to use `int` instead.
 */
/*
 * UK_LLSYSCALL_R_DEFINE()
 * Low-level variant, does not provide a libc-style wrapper
 */
#define __UK_LLSYSCALL_R_DEFINE(x, rtype, name, ename, rname, ...)	\
	long rname(UK_ARG_MAPx(x, UK_S_ARG_LONG, __VA_ARGS__));		\
	long ename(UK_ARG_MAPx(x, UK_S_ARG_LONG, __VA_ARGS__))		\
	{								\
		long ret;						\
									\
		__UK_SYSCALL_RETADDR_ENTRY();				\
		ret = rname(						\
			UK_ARG_MAPx(x, UK_S_ARG_CAST_LONG, __VA_ARGS__)); \
		__UK_SYSCALL_RETADDR_CLEAR();				\
		if (ret < 0 && PTRISERR(ret)) {				\
			errno = -(int) PTR2ERR(ret);			\
			return -1;					\
		}							\
		return ret;						\
	}								\
	static inline rtype __##rname(UK_ARG_MAPx(x, UK_S_ARG_ACTUAL,	\
						 __VA_ARGS__));		\
	long rname(UK_ARG_MAPx(x, UK_S_ARG_LONG, __VA_ARGS__))		\
	{								\
		long ret;						\
									\
		__UK_SYSCALL_PRINTD(x, rtype, rname, __VA_ARGS__);	\
		__UK_SYSCALL_RETADDR_ENTRY();				\
		ret = (long) __##rname(					\
			UK_ARG_MAPx(x, UK_S_ARG_CAST_ACTUAL, __VA_ARGS__)); \
		__UK_SYSCALL_RETADDR_CLEAR();				\
		return ret;						\
	}								\
	static inline rtype __##rname(UK_ARG_MAPx(x,			\
						  UK_S_ARG_ACTUAL_MAYBE_UNUSED,\
						  __VA_ARGS__))
#define _UK_LLSYSCALL_R_DEFINE(...) __UK_LLSYSCALL_R_DEFINE(__VA_ARGS__)
#define UK_LLSYSCALL_R_DEFINE(rtype, name, ...)				\
	_UK_LLSYSCALL_R_DEFINE(UK_NARGS(__VA_ARGS__),			\
			       rtype,					\
			       name,					\
			       __UK_NAME2SCALLE_FN(name),		\
			       __UK_NAME2SCALLR_FN(name),		\
			       __VA_ARGS__)

#if defined(__X86_64__)
#define UK_SYSCALL_USR_PROLOGUE_DEFINE(pname, fname, x, ...)		\
	long __used __naked						\
	pname(UK_ARG_MAPx(x, UK_S_ARG_LONG_MAYBE_UNUSED, __VA_ARGS__))	\
	{								\
		__asm__ __volatile__(					\
		"cli\n\t"						\
		"movq   %%rsp, %%gs:(0x28)\n\t"				\
		"movq	%%gs:(0x20), %%rsp\n\t"				\
		"andq	$("STRINGIFY(~(UK_SYSCALL_REGS_END_ALIGN - 1))	\
				"), %%rsp\n\t"				\
		"subq	$("STRINGIFY(UK_SYSCALL_REGS_SIZE -		\
				     __REGS_SIZEOF)"), %%rsp\n\t"	\
		"pushq	$(0x10)\n\t"					\
		"subq	$8, %%rsp\n\t"					\
		"pushfq\n\t"						\
		"pushq	$(0x8)\n\t"					\
		"subq	$8, %%rsp\n\t"					\
		"pushq	%%rdi\n\t"					\
		"movq	%%gs:(0x28), %%rdi\n\t"				\
		"movq	%%rdi, 32(%%rsp)\n\t"				\
		"movq	(%%rdi), %%rdi\n\t"				\
		"movq	%%rdi, 8(%%rsp)\n\t"				\
		"popq	%%rdi\n\t"					\
		"pushq	%%rax\n\t"					\
		"pushq	%%rdi\n\t"					\
		"pushq	%%rsi\n\t"					\
		"pushq	%%rdx\n\t"					\
		"pushq	%%rcx\n\t"					\
		"pushq	%%rax\n\t"					\
		"pushq	%%r8\n\t"					\
		"pushq	%%r9\n\t"					\
		"pushq	%%r10\n\t"					\
		"pushq	%%r11\n\t"					\
		"pushq	%%rbx\n\t"					\
		"pushq	%%rbp\n\t"					\
		"pushq	%%r12\n\t"					\
		"pushq	%%r13\n\t"					\
		"pushq	%%r14\n\t"					\
		"pushq	%%r15\n\t"					\
		"subq	$(8), %%rsp\n\t"				\
		"movq	%%rsp, %%rdi\n\t"				\
		"addq	$("STRINGIFY(__REGS_SIZEOF +			\
				     UKARCH_ULCTX_SIZE)"), %%rdi\n\t"	\
		"call	ukarch_ectx_store\n\t"				\
		"movq	%%rsp, %%rdi\n\t"				\
		"addq	$("STRINGIFY(__REGS_SIZEOF)"), %%rdi\n\t"	\
		"call	ukarch_ulctx_switchoff\n\t"			\
		"movq	%%rsp, %%rdi\n\t"				\
		"sti\n\t"						\
		"call	"STRINGIFY(fname)"\n\t"				\
		"addq	$(8), %%rsp\n\t"				\
		"popq	%%r15\n\t"					\
		"popq	%%r14\n\t"					\
		"popq	%%r13\n\t"					\
		"popq	%%r12\n\t"					\
		"popq	%%rbp\n\t"					\
		"popq	%%rbx\n\t"					\
		"movq   %%gs:(0x28), %%rsp\n\t"				\
		"ret\n\n"						\
		::							\
		);							\
									\
		return 0;						\
	}
#elif defined(__ARM_64__)
#define UK_SYSCALL_USR_PROLOGUE_DEFINE(pname, fname, x, ...)		\
	long __used __naked						\
	pname(UK_ARG_MAPx(x, UK_S_ARG_LONG_MAYBE_UNUSED, __VA_ARGS__))	\
	{								\
		__asm__ __volatile__(					\
		"msr	daifset, #2\n\t"				\
		"msr	tpidrro_el0, x0\n\t"				\
		"mrs	x0, tpidr_el1\n\t"				\
		"str	x0, [x0, #0x20]\n\t"				\
		"bic	x0, x0, #"					\
			STRINGIFY(UK_SYSCALL_REGS_END_ALIGN - 1)"\n\t"	\
		"sub	x0, x0, #"STRINGIFY(UK_SYSCALL_REGS_SIZE)"\n\t"	\
		"add	sp, sp, x0\n\t"					\
		"sub	x0, sp, x0\n\t"					\
		"sub	sp, sp, x0\n\t"					\
		"str	x0, [sp, #"STRINGIFY(__SP_OFFSET)"]\n\t"	\
		"mrs	x0, tpidrro_el0\n\t"				\
		"stp	x0, x1, [sp, #16 * 0]\n\t"			\
		"stp	x2, x3, [sp, #16 * 1]\n\t"			\
		"stp	x4, x5, [sp, #16 * 2]\n\t"			\
		"stp	x6, x7, [sp, #16 * 3]\n\t"			\
		"stp	x8, x9, [sp, #16 * 4]\n\t"			\
		"stp	x10, x11, [sp, #16 * 5]\n\t"			\
		"stp	x12, x13, [sp, #16 * 6]\n\t"			\
		"stp	x14, x15, [sp, #16 * 7]\n\t"			\
		"stp	x16, x17, [sp, #16 * 8]\n\t"			\
		"stp	x18, x19, [sp, #16 * 9]\n\t"			\
		"stp	x20, x21, [sp, #16 * 10]\n\t"			\
		"stp	x22, x23, [sp, #16 * 11]\n\t"			\
		"stp	x24, x25, [sp, #16 * 12]\n\t"			\
		"stp	x26, x27, [sp, #16 * 13]\n\t"			\
		"stp	x28, x29, [sp, #16 * 14]\n\t"			\
		"mrs	x21, elr_el1\n\t"				\
		"stp	x30, x21, [sp, #16 * 15]\n\t"			\
		"mrs	x22, spsr_el1\n\t"				\
		"mrs	x23, esr_el1\n\t"				\
		"stp	x22, x23, [sp, #16 * 16]\n\t"			\
		"mov	x0, sp\n\t"					\
		"add	x0, x0, #("STRINGIFY(__REGS_SIZEOF +		\
				     UKARCH_ULCTX_SIZE)")\n\t"		\
		"bl	ukarch_ectx_store\n\t"				\
		"mov	x0, sp\n\t"					\
		"add	x0, x0, #"STRINGIFY(__REGS_SIZEOF)"\n\t"	\
		"bl	ukarch_ulctx_switchoff\n\t"			\
		"mov	x0, sp\n\t"					\
		"msr	daifclr, #2\n\t"				\
		"bl	"STRINGIFY(fname)"\n\t"				\
		"ldr	x30, [sp, #16 * 15]\n\t"			\
		"ldp	x28, x29, [sp, #16 * 14]\t\n"			\
		"ldp	x26, x27, [sp, #16 * 13]\t\n"			\
		"ldp	x24, x25, [sp, #16 * 12]\t\n"			\
		"ldp	x22, x23, [sp, #16 * 11]\t\n"			\
		"ldp	x20, x21, [sp, #16 * 10]\t\n"			\
		"ldp	x18, x19, [sp, #16 * 9]\t\n"			\
		"ldr	x9, [sp, #"STRINGIFY(__SP_OFFSET)"]\n\t"	\
		"mov	sp, x9\n\t"					\
		"ret\n\t"						\
		::							\
		);							\
									\
		return 0;						\
	}
#else /* !__X86_64__ && !__ARM_64__ */
#error "Undefined architecture"
#endif

/*
 * UK_SYSCALL_R_DEFINE()
 * Based on UK_LLSYSCALL_R_DEFINE and provides a libc-style wrapper
 * in case UK_LIBC_SYSCALLS is enabled
 */
#if UK_LIBC_SYSCALLS
#define __UK_SYSCALL_R_DEFINE(x, rtype, name, ename, rname, ...)	\
	long ename(UK_ARG_MAPx(x, UK_S_ARG_LONG, __VA_ARGS__));		\
	rtype name(UK_ARG_MAPx(x, UK_S_ARG_ACTUAL, __VA_ARGS__))	\
	{								\
		rtype ret;						\
									\
		__UK_SYSCALL_RETADDR_ENTRY();				\
		ret = (rtype) ename(					\
			UK_ARG_MAPx(x, UK_S_ARG_CAST_LONG, __VA_ARGS__)); \
		__UK_SYSCALL_RETADDR_CLEAR();				\
		return ret;						\
	}								\
	__UK_LLSYSCALL_R_DEFINE(x, rtype, name, ename, rname, __VA_ARGS__)
#define _UK_SYSCALL_R_DEFINE(...) __UK_SYSCALL_R_DEFINE(__VA_ARGS__)
#define UK_SYSCALL_R_DEFINE(rtype, name, ...)				\
	_UK_SYSCALL_R_DEFINE(UK_NARGS(__VA_ARGS__),			\
			     rtype,					\
			     name,					\
			     __UK_NAME2SCALLE_FN(name),			\
			     __UK_NAME2SCALLR_FN(name),			\
			     __VA_ARGS__)
#else
#define UK_SYSCALL_R_DEFINE(rtype, name, ...)				\
	_UK_LLSYSCALL_R_DEFINE(UK_NARGS(__VA_ARGS__),			\
			       rtype,					\
			       name,					\
			       __UK_NAME2SCALLE_FN(name),		\
			       __UK_NAME2SCALLR_FN(name),		\
			       __VA_ARGS__)
#endif /* UK_LIBC_SYSCALLS */


#define __UK_SPROTO_ARGS_TYPE long
#define __UK_SPROTO_ARGS0()  void
#define __UK_SPROTO_ARGS1()  __UK_SPROTO_ARGS_TYPE a
#define __UK_SPROTO_ARGS2()  __UK_SPROTO_ARGS1(), __UK_SPROTO_ARGS_TYPE b
#define __UK_SPROTO_ARGS3()  __UK_SPROTO_ARGS2(), __UK_SPROTO_ARGS_TYPE c
#define __UK_SPROTO_ARGS4()  __UK_SPROTO_ARGS3(), __UK_SPROTO_ARGS_TYPE d
#define __UK_SPROTO_ARGS5()  __UK_SPROTO_ARGS4(), __UK_SPROTO_ARGS_TYPE e
#define __UK_SPROTO_ARGS6()  __UK_SPROTO_ARGS5(), __UK_SPROTO_ARGS_TYPE f
#define __UK_SPROTO_ARGS7()  __UK_SPROTO_ARGS6(), __UK_SPROTO_ARGS_TYPE g
#define __UK_SPROTO_ARGSx(args_nr)  \
	UK_CONCAT(__UK_SPROTO_ARGS, args_nr)()

#define UK_SYSCALL_E_PROTO(args_nr, syscall_name)			\
	long __UK_NAME2SCALLE_FN(syscall_name)(__UK_SPROTO_ARGSx(args_nr))
#define UK_SYSCALL_R_PROTO(args_nr, syscall_name)			\
	long __UK_NAME2SCALLR_FN(syscall_name)(__UK_SPROTO_ARGSx(args_nr))

#define uk_syscall_e_stub(syscall_name) ({				\
			uk_pr_debug("System call \"" syscall_name	\
				    "\" is not available (-ENOSYS)\n");	\
			errno = -ENOSYS;				\
			-1;						\
		})

#define uk_syscall_r_stub(syscall_name) ({				\
			uk_pr_debug("System call \"" syscall_name	\
				    "\" is not available (-ENOSYS)\n");	\
			-ENOSYS;					\
		})


#ifdef CONFIG_LIBSYSCALL_SHIM
#include <uk/bits/syscall_nrs.h>
#include <uk/bits/syscall_map.h>
#include <uk/bits/syscall_provided.h>
#include <uk/bits/syscall_stubs.h>
#include <uk/bits/syscall_static.h>
#include <uk/bits/syscall_r_static.h>

/* System call, returns -1 and sets errno on errors */
long uk_syscall(long nr, ...);
long uk_vsyscall(long nr, va_list arg);
long uk_syscall6(long nr, long arg1, long arg2, long arg3,
		 long arg4, long arg5, long arg6);

/*
 * Use this variant instead of `uk_syscall()` whenever the system call number
 * is a constant. This macro maps the function call directly to the target
 * handler instead of doing a look-up at runtime
 */
#define uk_syscall_static0(syscall_nr, ...) \
	UK_CONCAT(uk_syscall0_fn, syscall_nr)()
#define uk_syscall_static1(syscall_nr, a) \
	UK_CONCAT(uk_syscall1_fn, syscall_nr)(a)
#define uk_syscall_static2(syscall_nr, a, b) \
	UK_CONCAT(uk_syscall2_fn, syscall_nr)(a, b)
#define uk_syscall_static3(syscall_nr, a, b, c) \
	UK_CONCAT(uk_syscall3_fn, syscall_nr)(a, b, c)
#define uk_syscall_static4(syscall_nr, a, b, c, d) \
	UK_CONCAT(uk_syscall4_fn, syscall_nr)(a, b, c, d)
#define uk_syscall_static5(syscall_nr, a, b, c, d, e) \
	UK_CONCAT(uk_syscall5_fn, syscall_nr)(a, b, c, d, e)
#define uk_syscall_static6(syscall_nr, a, b, c, d, e, f) \
	UK_CONCAT(uk_syscall6_fn, syscall_nr)(a, b, c, d, e, f)

#define uk_syscall_static(syscall_nr, ...)			\
	UK_CONCAT(uk_syscall_static,				\
		  UK_NARGS(__VA_ARGS__))(syscall_nr, __VA_ARGS__)

/* Raw system call, returns negative codes on errors */
long uk_syscall_r(long nr, ...);
long uk_vsyscall_r(long nr, va_list arg);
long uk_syscall6_r(long nr, long arg1, long arg2, long arg3,
		   long arg4, long arg5, long arg6);

/*
 * Use this variant instead of `uk_syscall_r()` whenever the system call number
 * is a constant. This macro maps the function call directly to the target
 * handler instead of doing a look-up at runtime
 */
#define uk_syscall_r_static0(syscall_nr, ...) \
	UK_CONCAT(uk_syscall_r0_fn, syscall_nr)()
#define uk_syscall_r_static1(syscall_nr, a) \
	UK_CONCAT(uk_syscall_r1_fn, syscall_nr)(a)
#define uk_syscall_r_static2(syscall_nr, a, b) \
	UK_CONCAT(uk_syscall_r2_fn, syscall_nr)(a, b)
#define uk_syscall_r_static3(syscall_nr, a, b, c) \
	UK_CONCAT(uk_syscall_r3_fn, syscall_nr)(a, b, c)
#define uk_syscall_r_static4(syscall_nr, a, b, c, d) \
	UK_CONCAT(uk_syscall_r4_fn, syscall_nr)(a, b, c, d)
#define uk_syscall_r_static5(syscall_nr, a, b, c, d, e) \
	UK_CONCAT(uk_syscall_r5_fn, syscall_nr)(a, b, c, d, e)
#define uk_syscall_r_static6(syscall_nr, a, b, c, d, e, f) \
	UK_CONCAT(uk_syscall_r6_fn, syscall_nr)(a, b, c, d, e, f)

#define uk_syscall_r_static(syscall_nr, ...)			\
	UK_CONCAT(uk_syscall_r_static,				\
		  UK_NARGS(__VA_ARGS__))(syscall_nr, __VA_ARGS__)

/**
 * Returns a string with the name of the system call number `nr`.
 *
 * @param nr
 *  System call number of current architecture
 * @return
 *  - (const char *): name of system call
 *  - (NULL): if system call number is unknown
 */
const char *uk_syscall_name(long nr);

/**
 * Returns a string with the name of the system call number `nr`.
 * This function is similar to `uk_syscall_name` but it uses
 * a smaller lookup table internally. This table contains only
 * system call name mappings of provided calls.
 *
 * @param nr
 *  System call number of current architecture
 * @return
 *  - (const char *): name of provided system call
 *  - (NULL): if system call is not provided
 */
const char *uk_syscall_name_p(long nr);

/*
 * Format flags for system call print functions `uk_snprsyscall()`  and
 * `uk_vsnprsyscall()`
 */
/* Append a newline at the end of the generated string */
#define UK_PRSYSCALL_FMTF_NEWLINE   0x1
/* Apply syntax highlighting with ANSI color sequences */
#define UK_PRSYSCALL_FMTF_ANSICOLOR 0x2

/**
 * Pretty prints a system call request and response to a given C-string buffer.
 * The function ensures that the generated string is NULL terminated. The
 * function truncates the output string if there is not enough space on the
 * target buffer.
 *
 * @param buf
 *  Reference to a buffer where the resulting string is stored
 * @param maxlen
 *  Maximum length that can be used omn the buffer. If it is shorter than
 *  the generated string, the string will be truncated but NULL-terminated
 *  to fit into the buffer
 * @param fmtf
 *  Format flags that influence the generated string
 * @param syscall_num
 *  The system call number
 * @param sysret
 *  The return code of the system call
 * @param ...
 *  The system call arguments, each of it has to be passed as `long`
 * @return
 *  Number of characters of the generated string written to the buffer
 *  (excluding terminating '\0')
 */
int uk_snprsyscall(char *buf, __sz maxlen, int fmtf, long syscall_num,
		   long sysret, ...);

/**
 * Pretty prints a system call request and response to a given C-string buffer.
 * The function ensures that the generated string is NULL terminated. The
 * function truncates the output string if there is not enough space on the
 * target buffer.
 *
 * @param buf
 *  Reference to a buffer where the resulting string is stored
 * @param maxlen
 *  Maximum length that can be used omn the buffer. If it is shorter than
 *  the generated string, the string will be truncated but NULL-terminated
 *  to fit into the buffer
 * @param fmtf
 *  Format flags that influence the generated string
 * @param syscall_num
 *  The system call number
 * @param sysret
 *  The return code of the system call
 * @param args
 *  Variadic list of the system call arguments, each of it has to be passed
 *  as `long`
 * @return
 *  Number of bytes of the generated string written to the buffer
 *  (excluding terminating '\0')
 */
int uk_vsnprsyscall(char *buf, __sz maxlen, int fmtf, long syscall_num,
		    long sysret, va_list args);

#endif /* CONFIG_LIBSYSCALL_SHIM */

#ifdef __cplusplus
}
#endif
#endif /* !__ASSEMBLY__ */

#endif /* __UK_SYSCALL_H__ */
