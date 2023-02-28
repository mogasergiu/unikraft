#ifndef __X86_UK_RELOC_H__
#define __X86_UK_RELOC_H__

#include <uk/plat/common/sections.h>
#include <uk/uk_reloc.h>

#ifdef __ASSEMBLY__

.macro ur_mov sym:req, reg:req, bytes:req, phys
#ifdef CONFIG_OPTIMIZE_PIE
	mov	$UK_RELOC_PLACEHOLDER, \reg
.globl \sym\()_uk_reloc_imm\bytes\()\phys\()
.set \sym\()_uk_reloc_imm\bytes\()\phys\(), . - \bytes
	nop
#else
	mov	$\sym, \reg
#endif
.endm

#define SAVE_REG32_COUNT	6

/* Expects the lower 32 bits of the base virtual address in %edi
 * and the higher 32 bt in %esi (hopefully a KASLR randomized value).
 * Also place the base load address in %edx.
 */
.macro do_uk_reloc32 have_stack:req
#ifdef CONFIG_OPTIMIZE_PIE
.code32
.align 8
.if !\have_stack
	/* Setup uk_reloc32 scratch stack of size SAVE_REG32_COUNT */
	movl %edx, %esp
	subl $(_base_addr - start_uk_reloc32), %esp

	jmp start_uk_reloc32

.align 8
uk_reloc32_stack:
.rept SAVE_REG32_COUNT
.long 0x0
.endr

.endif

.align 8
start_uk_reloc32:
	/* Preserve caller's registers.
	 * Place the final 8-byte relocation base virtual address
	 * at +8(%esp) and the base physical address at +12(%esp).
	 * Since we are in Protected Mode, it is safe to assume that
	 * our physical load base address can fix into four bytes.
	 */
	pushl %eax
	pushl %ebx
	pushl %ecx
	pushl %edx
	pushl %edi
	pushl %esi

	/* Place load paddr into %esi, assuming _base_addr as first
	 * loaded symbol
	 */
	movl %edx, %esi

	/* Put in %ecx memory offset from load address to start of .uk_reloc */
	xorl %ecx, %ecx
.lookup_uk_reloc_signature:
	addl $UK_RELOC_ALIGNMENT, %ecx
	cmpl $UK_RELOC_SIGNATURE, (%esi,%ecx)
	jne .lookup_uk_reloc_signature

	addl $4, %ecx
	movl %esi, %ebx
	addl %ecx, %ebx

.foreach_uk_reloc32:
	xorl %ecx, %ecx
	movb	16(%ebx), %cl	/* Store r_sz in %ecx */
	test %ecx, %ecx  /* Check whether we reached sentinel or not */
	jz	.finish_uk_reloc32
	movl	%esi, %edx
	addl	0(%ebx), %edx		/* Add m_off to load vaddr */
	/* Check for relocation relative to physical load base address */
	xorl %eax, %eax
	movb	20(%ebx), %al
	test	%eax, UK_RELOC_FLAGS_PHYS_REL
	jnz	.uk_reloc32_phys

	movl	8(%ebx), %eax	/* Store lower 32 bits of r_val_off in %eax */
	movl	12(%ebx), %edi	/* Store higher 32 bits of r_val_off in %edi */
	addl	4(%esp), %eax	/* Add lower 32 bits load vaddr to r_val_off */
	/* If the offset is so big that adding the two lower 32-bits values
	 * results in a CF flag being set (highly unlikely, but still)
	 * add the carry to %edi
	 */
	jnc	.uk_reloc32_r_val_off_no_carry
	inc	%edi

.uk_reloc32_r_val_off_no_carry:
	addl	0(%esp), %edi	/* Add higher 32 bits load vaddr to r_val_off */
	jmp .foreach_r_val_off_32
.uk_reloc32_phys:
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
	inc %edx
	shr	$8, %eax
	jnz	.foreach_r_val_off_32

	xchg %edi, %eax
	test %edi, %edi
	jnz	.foreach_r_val_off_32

	addl $0x18, %ebx
	jmp .foreach_uk_reloc32

.finish_uk_reloc32:
	/* Restore caller's registers */
	popl %esi
	popl %edi
	popl %edx
	popl %ecx
	popl %ebx
	popl %eax
#endif
.endm

#else /* __ASSEMBLY__ */

static inline void st_curr_baddr(volatile void * volatile * baddr)
{
	volatile __off offset = 0;

	/* Get negative offset from `do_uk_reloc`'s symbolic value to the base
	 * of the loaded unikernel
	*/
	__asm__ __volatile__(
		"movq $(_base_addr - do_uk_reloc), %0"
		:
		: "m"(offset)
	);

	/* Add the negative offset to `do_uk_reloc`, thus obtaining our current
	 * load address
	 */
	*baddr = (volatile void *) ((__s64)do_uk_reloc + (__s64)(offset));
}

#endif /* !__ASSEMBLY__ */

#endif /* __X86_UK_RELOC_H__ */
