#include <uk/arch/limits.h> /* for __PAGE_SIZE */

PHDRS
{
	dynamic PT_DYNAMIC;
}

SECTIONS {
	_dyn_start = .;
	.dynamic :
	{
		*(.dynamic)
	} :dynamic :data

	.dynsym :
	{
		*(.dynsym)
	} :data

	.dynstr :
	{
		*(.dynstr)
	} :data
	_dyn_end = .;

	. = ALIGN(__PAGE_SIZE);
	_uk_reloc_start = .;
	.uk_reloc :
	{
		KEEP(*(.uk_reloc))
	} :data

	.rela.dyn :
	{
		*(.rela)
		*(.rela.*)
	} :data
}
INSERT BEFORE .bss
