#include <uk/config.h>
#include <uk/asm.h>
#include <uk/plat/common/pe.h>

#define PE_HDR_OFF                      0x1000

.section .pe_header
.align 12
pe_hdr:
  .long PE_MAGIC

coff_header:
  .short IMAGE_FILE_MACHINE_ARM64        /* Machine */
  .short 5                               /* NumberOfSections */
  .long 0                               /* TimeDateStamp */
  .long 0                               /* PointerToSymbolTable */
  .long 0                               /* NumberOfSymbols */
  .short section_tab - opt_hdr           /* SizeOfOptionalHeader */
  .short IMAGE_FILE_EXECUTABLE_IMAGE     | \
        IMAGE_FILE_DEBUG_STRIPPED       | \
        IMAGE_FILE_LINE_NUMS_STRIPPED   /* Characteristics */

opt_hdr:
  .short PE_OPT_HDR_MAGIC_PE32PLUS       /* Magic */
  .byte 0                               /* MajorLinkerVersion */
  .byte 0                               /* MinorLinkerVersion */
  .long 0                               /* SizeOfCode */
  .long 0                               /* SizeOfInitializedData */
  .long 0                               /* SizeOfUninitializedData */
  .long 0                               /* AddressOfEntryPoint */
  .long 0                               /* BaseOfCode */

xhdr_fields:
  .quad _base_addr                      /* ImageBase */
  .long 0x1000                          /* SectionAlignment */
  .long 0x1000                          /* FileAlignment */
  .short 0                               /* MajorOperatingSystemVersion */
  .short 0                               /* MinorOperatingSystemVersion */
  .short 0                               /* MajorImageVersion */
  .short 0                               /* MinorImageVersion */
  .short 0                               /* MajorSubsystemVersion */
  .short 0                               /* MinorSubsystemVersion */
  .long 0                               /* Win32VersionValue */
  .long 0                               /* SizeOfImage */
  .long 0x2000                          /* SizeOfHeaders */
  .long 0                               /* CheckSum */
  .short IMAGE_SUBSYSTEM_EFI_APPLICATION /* Subsystem */
  .short 0                               /* DllCharacteristics */
  .quad 0                               /* SizeOfStackReserve */
  .quad 0                               /* SizeOfStackCommit */
  .quad 0                               /* SizeOfHeapReserve */
  .quad 0                               /* SizeOfHeapCommit */
  .long 0                               /* LoaderFlags */
  .long (section_tab - .) / 8           /* NumberOfRvaAndSizes */
  .quad 0                               /* ExportTable */
  .quad 0                               /* ImportTable */
  .quad 0                               /* ResourceTable */
  .quad 0                               /* ExceptionTable */
  .quad 0                               /* CertificationTable */
  .quad 0                               /* BaseRelocationTable */

section_tab:
  .ascii ".reloc\0\0"                   /* Name */
  .long 0                               /* VirtualSize */
  .long . - pe_hdr + 0xc                /* VirtualAddress */
  .long 0                               /* SizeOfRawData */
  .long . - pe_hdr + 0x4                /* PointerToRawData */
  .long 0                               /* PointerToRelocations */
  .long 0                               /* PointerToLineNumbers */
  .short 0                               /* NumberOfRelocations */
  .short 0                               /* NumberOfLineNumbers */
  .long IMAGE_SCN_CNT_INITIALIZED_DATA  | \
        IMAGE_SCN_MEM_READ              | \
        IMAGE_SCN_MEM_DISCARDABLE       | \
        IMAGE_SCN_ALIGN_1BYTES            /* Characteristics */

  .ascii  ".text\0\0\0"                 /* Name */
  .long 0                               /* VirtualSize */
  .long 0                               /* VirtualAddress */
  .long 0                               /* SizeOfRawData */
  .long 0                               /* PointerToRawData */
  .long 0                               /* PointerToRelocations */
  .long 0                               /* PointerToLineNumbers */
  .short 0                               /* NumberOfRelocations */
  .short 0                               /* NumberOfLineNumbers */
  .long IMAGE_SCN_CNT_CODE              | \
        IMAGE_SCN_MEM_EXECUTE           | \
        IMAGE_SCN_MEM_WRITE             | \
        IMAGE_SCN_ALIGN_4096BYTES       /* Characteristics */

  .ascii  ".rdata\0\0"                  /* Name */
  .long 0                               /* VirtualSize */
  .long 0                               /* VirtualAddress */
  .long 0                               /* SizeOfRawData */
  .long 0                               /* PointerToRawData */
  .long 0                               /* PointerToRelocations */
  .long 0                               /* PointerToLineNumbers */
  .short 0                               /* NumberOfRelocations */
  .short 0                               /* NumberOfLineNumbers */
  .long IMAGE_SCN_CNT_INITIALIZED_DATA  | \
        IMAGE_SCN_MEM_WRITE             | \
        IMAGE_SCN_ALIGN_4096BYTES       /* Characteristics */

  .ascii  ".data\0\0\0"                 /* Name */
  .long 0                               /* VirtualSize */
  .long 0                               /* VirtualAddress */
  .long 0                               /* SizeOfRawData */
  .long 0                               /* PointerToRawData */
  .long 0                               /* PointerToRelocations */
  .long 0                               /* PointerToLineNumbers */
  .short 0                               /* NumberOfRelocations */
  .short 0                               /* NumberOfLineNumbers */
  .long IMAGE_SCN_CNT_INITIALIZED_DATA  | \
        IMAGE_SCN_MEM_WRITE             | \
        IMAGE_SCN_ALIGN_4096BYTES       /* Characteristics */

  .ascii  ".tdata\0\0\0"                /* Name */
  .long 0                               /* VirtualSize */
  .long 0                               /* VirtualAddress */
  .long 0                               /* SizeOfRawData */
  .long 0                               /* PointerToRawData */
  .long 0                               /* PointerToRelocations */
  .long 0                               /* PointerToLineNumbers */
  .short 0                               /* NumberOfRelocations */
  .short 0                               /* NumberOfLineNumbers */
  .long IMAGE_SCN_CNT_INITIALIZED_DATA  | \
        IMAGE_SCN_MEM_WRITE             | \
        IMAGE_SCN_ALIGN_4096BYTES       /* Characteristics */

.section .text
uk_efi_entry64:
  stp x0, x1, [sp, #16]
  mov x0, xzr
  mov x1, xzr
  bl do_uk_reloc
  ldp x0, x1, [sp, #16]

  bl uk_efi_main

uk_efi_fail:
  wfi
  b uk_efi_fail
