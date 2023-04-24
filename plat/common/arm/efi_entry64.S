#include <uk/config.h>
#include <uk/asm.h>
#include <uk/plat/common/pe.h>

.section .text
uk_efi_entry64:
	stp	x0, x1, [sp, #16]

	mov	x0, xzr
	mov	x1, xzr
	bl	do_uk_reloc
	ldp	x0, x1, [sp, #16]

	bl	uk_efi_main

uk_efi_fail:
	wfi
	b	uk_efi_fail
