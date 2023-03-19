#include <uk/arch/limits.h> /* for __PAGE_SIZE */

PHDRS
{
	dynamic PT_DYNAMIC;
}

SECTIONS
{
	. = ALIGN(__PAGE_SIZE);
	_uk_reloc_start = .;
	.uk_reloc :
	{
		KEEP(*(.uk_reloc))
	} :data

	/* For whatever reason, .dynsym wants to stay before .rela.dyn.
	 * This does not bother us, even if we strip it, since we are compiling
	 * statically, .dynsym will be insignificantly small.
	 */
	.dynsym :
	{
		*(.dynsym)
	} :data

	.rela.dyn :
	{
		*(.rela)
		*(.rela.*)
	} :data
	_uk_reloc_end = .;
}
INSERT BEFORE .bss

/******************************************************************************/
/****************************** .bss section **********************************/
/******************************************************************************/

/******************************************************************************/
/**************************** .comment section ********************************/
/******************************************************************************/

SECTIONS
{
	.dynamic :
	{
		*(.dynamic)
	} :dynamic :data

	.dynstr :
	{
		*(.dynstr)
	} :data
}
INSERT AFTER .comment
