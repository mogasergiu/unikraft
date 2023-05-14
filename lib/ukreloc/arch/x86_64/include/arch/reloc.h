/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2023, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

#ifndef __X86_64_UK_RELOC_H__
#define __X86_64_UK_RELOC_H__

#include "../../../include/uk/reloc.h"

#ifdef __ASSEMBLY__

/* Relocation friendly ur_mov to replace mov instructions incompatible with
 * a PIE binary. Usage example:
 * ```
 * ur_mov	gdt64_ptr, %eax, 4
 * ```
 * The above will make mkukreloc.py process the symbol gdt64_ptr_ukeloc_imm4
 * representing in memory where this data is placed and the following entry:
 * struct ukreloc {
 *        __u64 r_mem_off = gdt64_ptr_ukeloc_imm4 - __BASE_ADDR
 *        __u64 r_addr = gdt64_ptr - __BASE_ADDR
 *        __u32 r_sz = 4 from gdt64_ptr_ukeloc_imm[4]
 *        __u32 flags = 0
 * } __packed;
 *
 * If CONFIG_OPTIMIZE_PIE is not enabled then it will be simply resolved to
 * ```
 * mov	$gdt64_ptr, %eax
 * ```
 *
 * @param sym The symbol to relocate
 * @param req The register into which to place the value
 * @param bytes The size in bytes of the relocation
 * @param phys Optional, if value is _phys, UKRELOC_FLAGS_PHYS_REL is set
 */
.macro ur_mov sym:req, reg:req, bytes:req, flags
#ifdef CONFIG_OPTIMIZE_PIE
/* UKRELOC_PLACEHODER is 16 bytes, so in 64-bit code we must force a `movabs`
 * to ensure that the last amount of opcodes are meant for the immediate
 */
.ifeq  (8 - \bytes)
	movabs	$UKRELOC_PLACEHOLDER, \reg
.endif
.ifgt  (8 - \bytes)
	mov	$UKRELOC_PLACEHOLDER, \reg
.endif
	ur_sym	\sym\()_ukreloc_imm\bytes\()\flags\(), (. - \bytes)
	nop
	ur_sec_updt	\sym, (. - \bytes)
#else
	mov	$\sym, \reg
#endif
.endm

#define SAVE_REG32_COUNT				6

/* Expects the lower 32 bits of the base virtual address in %edi
 * and the higher 32 bt in %esi (hopefully a KASLR randomized value).
 * Also place the base load address in %edx. The macro can either create its
 * own scratch stack to save register state or use the already existing one,
 * if there.
 *
 * @param have_stack Boolean value to tell whether the caller already has a
 *                   stack available or not
 */
.macro do_ukreloc32 have_stack:req
#ifdef CONFIG_OPTIMIZE_PIE
.code32
.align 8
.if !\have_stack
	/* Setup ukreloc32 scratch stack of size SAVE_REG32_COUNT */
	movl	%edx, %esp
	subl	$(_base_addr - start_ukreloc32), %esp

	jmp	start_ukreloc32

.align 8
ukreloc32_stack:
.rept SAVE_REG32_COUNT
.long 0x0
.endr

.endif

.align 8
start_ukreloc32:
	/* Preserve caller's registers.
	 * Place the final 8-byte relocation base virtual address
	 * at +8(%esp) and the base physical address at +12(%esp).
	 * Since we are in Protected Mode, it is safe to assume that
	 * our physical load base address can fix into four bytes.
	 */
	pushl	%eax
	pushl	%ebx
	pushl	%ecx
	pushl	%edx
	pushl	%edi
	pushl	%esi

	/* Place load paddr into %esi, assuming _base_addr as first
	 * loaded symbol
	 */
	movl	%edx, %esi

	/* Put in %ecx memory offset from load address to start of .ukreloc */
	xorl	%ecx, %ecx
.lookup_ukreloc_signature:
	addl	$UKRELOC_ALIGNMENT, %ecx
	cmpl	$UKRELOC_SIGNATURE, (%esi,%ecx)
	jne	.lookup_ukreloc_signature

	addl	$4, %ecx
	movl	%esi, %ebx
	addl	%ecx, %ebx

.foreach_ukreloc32:
	xorl	%ecx, %ecx
	movb	16(%ebx), %cl	/* Store r_sz in %ecx */
	test	%ecx, %ecx  /* Check whether we reached sentinel or not */
	jz	.finish_ukreloc32
	movl	%esi, %edx
	addl	0(%ebx), %edx		/* Add m_off to load vaddr */
	/* Check for relocation relative to physical load base address */
	xorl	%eax, %eax
	movb	20(%ebx), %al
	test	%eax, UKRELOC_FLAGS_PHYS_REL
	jnz	.ukreloc32_phys

	movl	8(%ebx), %eax	/* Store lower 32 bits of r_val_off in %eax */
	movl	12(%ebx), %edi	/* Store higher 32 bits of r_val_off in %edi */
	addl	4(%esp), %eax	/* Add lower 32 bits load vaddr to r_val_off */
	/* If the offset is so big that adding the two lower 32-bits values
	 * results in a CF flag being set (highly unlikely, but still)
	 * add the carry to %edi
	 */
	jnc	.ukreloc32_r_val_off_no_carry
	inc	%edi

.ukreloc32_r_val_off_no_carry:
	addl	0(%esp), %edi	/* Add higher 32 bits load vaddr to r_val_off */
	jmp	.foreach_r_val_off_32
.ukreloc32_phys:
	/* For a physical relocation, since we are in 32-bit mode with no MMU,
	 * the higher 32 bits of the relocation should be 0, otherwise you
	 * must have done something wrong :).
	 */
	movl	8(%ebx), %eax	/* Store lower 32 bits of r_val_off in %eax */
	addl	8(%esp), %eax	/* Add load paddr to r_val_off */
	xorl	%edi, %edi	/* Zero-out the supposed higher 32 bits value */

/* We now have in %eax the relocation value, in %ecx the byte count and in %edx
 * the place in memory where we have to place the relocation
 */
.foreach_r_val_off_32:
	movb	%al, 0(%edx)
	inc	%edx
	shr	$8, %eax
	jnz	.foreach_r_val_off_32

	xchg	%edi, %eax
	test	%edi, %edi
	jnz	.foreach_r_val_off_32

	addl	$0x18, %ebx
	jmp	.foreach_ukreloc32

.finish_ukreloc32:
	/* Restore caller's registers */
	popl	%esi
	popl	%edi
	popl	%edx
	popl	%ecx
	popl	%ebx
	popl	%eax
#endif
.endm

#endif /* __ASSEMBLY__ */

#endif /* __X86_64_UK_RELOC_H__ */
