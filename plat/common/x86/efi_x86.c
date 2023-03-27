#include <uk/plat/common/bootinfo.h>
#include <uk/plat/common/efi.h>
#include <uk/arch/paging.h>
#include <uk/plat/lcpu.h>
#include <x86/cpu.h>

#define PIC1_DATA					0x21
#define PIC2_DATA					0xA1

extern __u64 _ukplat_entry;
extern void *x86_bpt_pml4;

void lcpu_start64(void *, void *);

static __u8 uk_efi_bootstack[__PAGE_SIZE];

static struct {
	void (* entry_fn)(void *, void *);
	void *bootstack;
} uk_efi_boot_startup_args = {
	.entry_fn = &_ukplat_entry,
	.bootstack = (__u8 *)uk_efi_bootstack + __PAGE_SIZE,
};

static inline void unmask_8259_pic()
{
	outb(PIC1_DATA, 0);
	outb(PIC2_DATA, 0);
}

uk_efi_status_t uk_efi_jmp_to_kern()
{
	ukplat_lcpu_disable_irq();

	ukarch_pt_write_base((__paddr_t)&x86_bpt_pml4);

	unmask_8259_pic();

	lcpu_start64(&uk_efi_boot_startup_args, ukplat_bootinfo_get());

	return -1;
}
