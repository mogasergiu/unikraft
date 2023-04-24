#include <uk/config.h>
#include <uk/asm.h>

.section .text
ENTRY(uk_efi_entry64)
	/* EFI gives us a stack misaligned by 8 */
	and	$~0xf, %rsp

	xorq	%rdi, %rdi
	xorq	%rsi, %rsi
	pushq	%rdx
	pushq	%rcx
	call	do_ukreloc
	popq	%rcx
	popq	%rdx

	call	uk_efi_main

uk_efi_fail:
	hlt
	jmp	uk_efi_fail
END(uk_efi_entry64)
