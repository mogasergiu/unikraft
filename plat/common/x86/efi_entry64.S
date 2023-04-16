#include <uk/config.h>
#include <uk/asm.h>
#include <uk/plat/common/pe.h>

#define PE_HDR_OFF			0x1000

.section .pe_header
.align 0x1000
pe_hdr:
  .long PE_MAGIC

coff_header:
  .word IMAGE_FILE_MACHINE_AMD64	/* Machine */
  .word 5				/* NumberOfSections */
  .long 0				/* TimeDateStamp */
  .long 0				/* PointerToSymbolTable */
  .long 0				/* NumberOfSymbols */
  .word section_tab - opt_hdr		/* SizeOfOptionalHeader */
  .word IMAGE_FILE_EXECUTABLE_IMAGE     | \
	IMAGE_FILE_DEBUG_STRIPPED       | \
	IMAGE_FILE_LINE_NUMS_STRIPPED	/* Characteristics */

opt_hdr:
  .word PE_OPT_HDR_MAGIC_PE32PLUS	/* Magic */
  .byte 0				/* MajorLinkerVersion */
  .byte 0				/* MinorLinkerVersion */
  .long 0				/* SizeOfCode */
  .long 0				/* SizeOfInitializedData */
  .long 0				/* SizeOfUninitializedData */
  .long 0				/* AddressOfEntryPoint */
  .long 0				/* BaseOfCode */

xhdr_fields:
  .quad 0x1000000/* ImageBase */
  .long 0x1000				/* SectionAlignment */
  .long 0x1000				/* FileAlignment */
  .word 0				/* MajorOperatingSystemVersion */
  .word 0				/* MinorOperatingSystemVersion */
  .word 0				/* MajorImageVersion */
  .word 0				/* MinorImageVersion */
  .word 0				/* MajorSubsystemVersion */
  .word 0				/* MinorSubsystemVersion */
  .long 0				/* Win32VersionValue */
  .long 0				/* SizeOfImage */
  .long 0x2000				/* SizeOfHeaders */
  .long 0				/* CheckSum */
  .word IMAGE_SUBSYSTEM_EFI_APPLICATION	/* Subsystem */
  .word 0				/* DllCharacteristics */
  .quad 0				/* SizeOfStackReserve */
  .quad 0				/* SizeOfStackCommit */
  .quad 0				/* SizeOfHeapReserve */
  .quad 0				/* SizeOfHeapCommit */
  .long 0				/* LoaderFlags */
  .long (section_tab - .) / 8		/* NumberOfRvaAndSizes */
  .quad 0				/* ExportTable */
  .quad 0				/* ImportTable */
  .quad 0				/* ResourceTable */
  .quad 0				/* ExceptionTable */
  .quad 0				/* CertificationTable */
  .quad 0				/* BaseRelocationTable */

section_tab:
  .ascii ".reloc\0\0"			/* Name */
  .long 0				/* VirtualSize */
  .long . - pe_hdr + 0xc		/* VirtualAddress */
  .long 0				/* SizeOfRawData */
  .long . - pe_hdr + 0x4		/* PointerToRawData */
  .long 0				/* PointerToRelocations */
  .long 0				/* PointerToLineNumbers */
  .word 0				/* NumberOfRelocations */
  .word 0				/* NumberOfLineNumbers */
  .long IMAGE_SCN_CNT_INITIALIZED_DATA  | \
	IMAGE_SCN_MEM_READ		| \
	IMAGE_SCN_MEM_DISCARDABLE	| \
	IMAGE_SCN_ALIGN_1BYTES		/* Characteristics */

  .ascii  ".text\0\0\0"			/* Name */
  .long 0				/* VirtualSize */
  .long 0				/* VirtualAddress */
  .long 0				/* SizeOfRawData */
  .long 0				/* PointerToRawData */
  .long 0				/* PointerToRelocations */
  .long 0				/* PointerToLineNumbers */
  .word 0				/* NumberOfRelocations */
  .word 0				/* NumberOfLineNumbers */
  .long IMAGE_SCN_CNT_CODE		| \
	IMAGE_SCN_MEM_READ		| \
	IMAGE_SCN_MEM_EXECUTE		| \
	IMAGE_SCN_ALIGN_4096BYTES	/* Characteristics */

  .ascii  ".rdata\0\0"			/* Name */
  .long 0				/* VirtualSize */
  .long 0				/* VirtualAddress */
  .long 0				/* SizeOfRawData */
  .long 0				/* PointerToRawData */
  .long 0				/* PointerToRelocations */
  .long 0				/* PointerToLineNumbers */
  .word 0				/* NumberOfRelocations */
  .word 0				/* NumberOfLineNumbers */
  .long IMAGE_SCN_CNT_INITIALIZED_DATA	| \
	IMAGE_SCN_MEM_READ		| \
	IMAGE_SCN_ALIGN_4096BYTES	/* Characteristics */

  .ascii  ".data\0\0\0"			/* Name */
  .long 0				/* VirtualSize */
  .long 0				/* VirtualAddress */
  .long 0				/* SizeOfRawData */
  .long 0				/* PointerToRawData */
  .long 0				/* PointerToRelocations */
  .long 0				/* PointerToLineNumbers */
  .word 0				/* NumberOfRelocations */
  .word 0				/* NumberOfLineNumbers */
  .long IMAGE_SCN_CNT_INITIALIZED_DATA	| \
	IMAGE_SCN_MEM_READ		| \
	IMAGE_SCN_MEM_WRITE		| \
	IMAGE_SCN_ALIGN_4096BYTES	/* Characteristics */

  .ascii  ".tdata\0\0\0"		/* Name */
  .long 0				/* VirtualSize */
  .long 0				/* VirtualAddress */
  .long 0				/* SizeOfRawData */
  .long 0				/* PointerToRawData */
  .long 0				/* PointerToRelocations */
  .long 0				/* PointerToLineNumbers */
  .word 0				/* NumberOfRelocations */
  .word 0				/* NumberOfLineNumbers */
  .long IMAGE_SCN_CNT_INITIALIZED_DATA	| \
	IMAGE_SCN_MEM_READ		| \
	IMAGE_SCN_MEM_WRITE		| \
	IMAGE_SCN_ALIGN_4096BYTES	/* Characteristics */

.section .text
.align 8
uk_efi_entry64:
	/* EFI gives us a stack misaligned by 8 */
	and $~0xf, %rsp

	xorq %rdi, %rdi
	xorq %rsi, %rsi
	pushq %rdx
	pushq %rcx
	call do_uk_reloc
	popq %rcx
	popq %rdx

	call uk_efi_main

uk_efi_fail:
	hlt
	jmp uk_efi_fail
