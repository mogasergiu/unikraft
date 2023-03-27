#include <uk/plat/common/bootinfo.h>
#include <uk/plat/common/efi.h>
#include <uk/arch/paging.h>
#include <x86/apic_defs.h>
#include <uk/plat/lcpu.h>
#include <x86/cpu.h>

#define LAPIC_TMICT					0xFEE00380

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
	outb(PIC1_DATA, 0xb8);
	outb(PIC2_DATA, 0x8e);
}

static inline void lapic_sw_disable()
{
	volatile __u32 *volatile lapic_tmict = LAPIC_TMICT;
	__u32 eax, edx, tmict;

	/* Check if APIC is active */
	rdmsr(APIC_MSR_BASE, &eax, &edx);
	if (unlikely(!(eax & APIC_BASE_EN)))
		return;

	*lapic_tmict = 0x0;
}

static inline void piix_elcr2_level_irq10_11()
{
	outb(0x4d1, 0xc);
}

uk_efi_status_t uk_efi_jmp_to_kern()
{
	ukplat_lcpu_disable_irq();

	ukarch_pt_write_base((__paddr_t)&x86_bpt_pml4);

	unmask_8259_pic();

	lapic_sw_disable();

	piix_elcr2_level_irq10_11();

	lcpu_start64(&uk_efi_boot_startup_args, ukplat_bootinfo_get());

	return -1;
}
