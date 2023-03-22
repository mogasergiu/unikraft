#ifndef __START16_HELPERS_H__
#define __START16_HELPERS_H__

extern __vaddr_t x86_start16_addr; /* target address */
extern void *x86_start16_begin[];
extern void *x86_start16_end[];

#define X86_START16_SIZE						\
	((__uptr)x86_start16_end - (__uptr)x86_start16_begin)

#define START16_UK_RELOC_MOV_SYM(sym, sz)				\
	start16_##sym##_uk_reloc_imm##sz##_phys

#define START16_UK_RELOC_DATA_SYM(sym, sz)				\
	start16_##sym##_uk_reloc_data##sz##_phys

#define IMPORT_START16_UK_RELOC_SYM(sym, sz, type)			\
	extern void *sym[];						\
	extern void *START16_UK_RELOC_##type##_SYM(sym, sz)[]

#define START16_UK_RELOC_MOV_OFF(sym, sz)				\
	((void *)START16_UK_RELOC_MOV_SYM(sym, sz) -			\
	(void *)x86_start16_begin)

#define START16_UK_RELOC_DATA_OFF(sym, sz)				\
	((void *)START16_UK_RELOC_DATA_SYM(sym, sz) -			\
	(void *)x86_start16_begin)

#define START16_UK_RELOC_ENTRY(sym, sz, type)				\
	UK_RELOC_ENTRY(START16_UK_RELOC_##type##_OFF(sym, sz),		\
		       (void *)sym - (void *)x86_start16_begin,		\
		       sz, UK_RELOC_FLAGS_PHYS_REL)

#endif  /* __START16_HELPERS_H__ */
