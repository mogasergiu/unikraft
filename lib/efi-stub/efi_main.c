#include <efi.h>
#include <efilib.h>
#include "efi_guid.h"

/*
 * Maybe I am doing something wrong but I failed to get these to be includable
 * between < > so yeah just throw them into the same directory for now and
 * figure out Unikraft's build system later (perhaps would be better to have a
 * separate repository in the organisation for this stub?).
 */
#include "multiboot.h"
#include "elfdefinitions.h"

#define EBDA_START 0xA0000
#define EBDA_END 0x100000
#define MAX_CMDLINE_SIZE 8192
#define MULTIBOOT_INFO_PHYSICAL_ADDRESS 0x9000
#define MULTIBOOT_MAGIC 0x1BADB002

#define UEFI_GOP_DEFAULT_PIXEL_FORMAT PixelBlueGreenRedReserved8BitPerColor

struct RSDPDescriptor {
	char Signature[8];
	uint8_t Checksum;
	char OEMID[6];
	uint8_t Revision;
	uint32_t RsdtAddress;
} __attribute__ ((packed));

struct RSDPDescriptor20 {
	struct RSDPDescriptor rsdt;

	uint32_t Length;
	uint64_t XsdtAddress;
	uint8_t ExtendedChecksum;
	uint8_t reserved[3];
} __attribute__ ((packed));

struct ACPISDTHeader {
	char Signature[4];
	uint32_t Length;
	uint8_t Revision;
	uint8_t Checksum;
	char OEMID[6];
	char OEMTableID[8];
	uint32_t OEMRevision;
	uint32_t CreatorID;
	uint32_t CreatorRevision;
} __attribute__ ((packed));

struct RSDT {
	struct ACPISDTHeader h;
	uint32_t Entry[];
} __attribute__ ((packed));

struct XSDT {
	struct ACPISDTHeader h;
	uint64_t Entry[];
} __attribute__ ((packed));

struct PCI_ECAM {
	uint64_t addr;
	uint16_t seg;
	uint8_t start_bus;
	uint8_t end_bus;
	uint32_t reserved;
} __attribute__ ((packed));

struct MCFG {
	struct ACPISDTHeader h;
	uint64_t Reserved;
	struct PCI_ECAM pe[];
} __attribute__ ((packed));

struct pci_hdr {
	uint16_t vendor_id;
	uint16_t device_id;
	uint16_t cmd;
	uint16_t status;
	uint8_t rev_id;
	uint8_t prog_if;
	uint8_t subclass;
	uint8_t class_code;
	uint8_t cache_line_size;
	uint8_t latency_timer;
#define TYPE_0_HEADER_SIZE 0x40
#define TYPE_1_HEADER_SIZE 0x40
#define TYPE_2_HEADER_SIZE 0x48
	uint8_t header_type;
	uint8_t bist;
	/*... whatever other fields there are I only care about enumeration atm */
} __attribute__ ((packed));
/*
 * Basic Protected Mode, Ring 0 GDT
 */
typedef struct gdt_entry {
	uint8_t limit0_15[2];
        uint8_t base0_23[3];
        uint8_t access;
        uint8_t flags : 4;
        uint8_t limit16_20 : 4;
        uint8_t base24_31;
} __attribute__((packed)) gdt_entry_t;

gdt_entry_t GDT[] = {
	{
		.limit0_15 = { 0x00, 0x00 },
		.base0_23 = { 0, 0, 0 },
		.access = 0b00000000,
		.flags = 0b0000,
		.limit16_20 = 0b0000,
		.base24_31 = 0,
	},
	{
		.limit0_15 = { 0xff, 0xff },
		.base0_23 = { 0, 0, 0 },
		.access = 0b10011010,
		.flags = 0b1100,
		.limit16_20 = 0b1111,
		.base24_31 = 0,
	},
	{
		.limit0_15 = { 0xff, 0xff },
		.base0_23 = { 0, 0, 0 },
		.access = 0b10010010,
		.flags = 0b1100,
		.limit16_20 = 0b1111,
		.base24_31 = 0,
	},
};

typedef struct gdtr {
	uint16_t size;
	uint64_t addr;
} __attribute__((packed)) gdtr_t;

gdtr_t GDTR = {
	.size = sizeof(GDT) - 1,
	.addr = (uint64_t) &GDT,
};

static CHAR8 uk_img __attribute__((section(".uk_img")));

static VOID stringify_load_options(IN CHAR16 *lo16, IN UINT32 len16,
                                   OUT CHAR8 *lo8)
{
        UINT8 *c = (UINT8 *) lo16;
        UINT32 len8 = len16 >> 1;
        UINT32 i16 = 0;
        UINT32 i8 = 0;

        while (i16 < len16 && i8 < len8) {
                if (c[i16] != '\0') {
                        lo8[i8] = c[i16];
                        i8++;
                }

                i16++;
        }
}

static VOID EFIAPI fill_e820_entry(IN OUT multiboot_memory_map_t *e820_e,
                                   IN multiboot_uint64_t paddr,
                                   IN multiboot_uint64_t len,
                                   IN multiboot_uint32_t type)
{
        /*
         * Since we are the ones that manually generate e820 instead of a
         * legacy BIOS, we do not need to take into account memory holes
         * between the e820 entries
         */
        e820_e->size = sizeof(*e820_e);
        e820_e->addr = paddr;
        e820_e->len = len;
        e820_e->type = type;
}

static VOID EFIAPI efi_to_e820_mmap(IN EFI_MEMORY_DESCRIPTOR *efi_mmap,
                                    IN UINTN efi_desc_cnt,
                                    IN UINTN efi_desc_size,
                                    IN OUT multiboot_memory_map_t *e820_mmap)
{
        EFI_MEMORY_DESCRIPTOR *efi_mmap_entry = efi_mmap;
        multiboot_uint64_t paddr, len;
        int i;

        for (i = 0; i < efi_desc_cnt && i < 128; i++)
        {
                efi_mmap_entry = (EFI_MEMORY_DESCRIPTOR *)
                                  ((CHAR8 *) efi_mmap_entry + efi_desc_size);
                paddr = efi_mmap_entry->PhysicalStart;
                len = efi_mmap_entry->NumberOfPages << EFI_PAGE_SHIFT;
/*
                Print(L">%d UEFI: 0x%lx, %lu",
                        i, efi_mmap_entry->PhysicalStart,
			efi_mmap_entry->NumberOfPages * EFI_PAGE_SIZE);
*/
                switch (efi_mmap_entry->Type) {
                case EfiACPIReclaimMemory:
                        fill_e820_entry(e820_mmap, paddr,
                                        len,
                                        MULTIBOOT_MEMORY_ACPI_RECLAIMABLE);
                        break;
                case EfiRuntimeServicesCode:
                        fill_e820_entry(e820_mmap, paddr,
                                        len,
                                        MULTIBOOT_MEMORY_BADRAM);
                        break;
                case EfiRuntimeServicesData:
                case EfiReservedMemoryType:
                case EfiMemoryMappedIO:
                case EfiMemoryMappedIOPortSpace:
                case EfiUnusableMemory:
                case EfiPalCode:
                        fill_e820_entry(e820_mmap, paddr,
                                        len,
                                        MULTIBOOT_MEMORY_AVAILABLE);
                        break;
                case EfiLoaderCode:
                case EfiLoaderData:
                case EfiBootServicesCode:
                case EfiBootServicesData:
                case EfiConventionalMemory:
                        if (paddr < EBDA_START)
                                if (paddr + len >= EBDA_END) {
                                        // We reached a memory split
                                        fill_e820_entry(e820_mmap, paddr,
                                                        EBDA_START - paddr,
                                                        MULTIBOOT_MEMORY_AVAILABLE);
/*					Print(L" - E820: 0x%lx, %lu",
					      e820_mmap->addr,
					      e820_mmap->len);*/
					i++;
                                        fill_e820_entry(e820_mmap, EBDA_END,
                                                        paddr + len - EBDA_END,
                                                        MULTIBOOT_MEMORY_AVAILABLE);
                                } else if (paddr + len > EBDA_START)
                                        fill_e820_entry(e820_mmap, paddr,
                                                        EBDA_START - paddr,
                                                        MULTIBOOT_MEMORY_AVAILABLE);
                                else
                                        fill_e820_entry(e820_mmap, paddr,
                                                        len,
                                                        MULTIBOOT_MEMORY_AVAILABLE);
                        else if (paddr >= EBDA_START && paddr <= EBDA_END)
                                fill_e820_entry(e820_mmap, EBDA_END,
                                                paddr + len - EBDA_END,
                                                MULTIBOOT_MEMORY_AVAILABLE);
                        else
                                fill_e820_entry(e820_mmap, paddr,
                                                len,
                                                MULTIBOOT_MEMORY_AVAILABLE);

                        break;
                case EfiACPIMemoryNVS:
                        fill_e820_entry(e820_mmap, paddr,
                                        len,
                                        MULTIBOOT_MEMORY_NVS);
                        break;
                }

/*                Print(L" - E820 %x: 0x%lx, %lu, %u\n",
		      e820_mmap, e820_mmap->addr, e820_mmap->len, e820_mmap->type);*/
                                e820_mmap = (multiboot_memory_map_t *)
                        ((CHAR8 *)e820_mmap + (sizeof(*e820_mmap) +
                                sizeof(multiboot_uint32_t)));

        }
}

/*
 * Yea I need this Memory Key to be global for now, beautification comes later.
 */
static UINTN KEY;

static EFI_STATUS EFIAPI setup_multiboot_info_mmap(IN OUT multiboot_info_t *mbi)
{
        UINTN efi_mmap_size = 0, e820_mmap_size;
        EFI_MEMORY_DESCRIPTOR *efi_mmap = NULL;
        UINTN efi_desc_size, desc_cnt;
        EFI_STATUS status;
        UINT32 efi_desc_ver;
        UINTN efi_mmap_key;

        // First a dummy call to find out the size of the UEFI Memory Map
        status = uefi_call_wrapper(BS->GetMemoryMap, 5,
                                   &efi_mmap_size, efi_mmap, &efi_mmap_key,
                                   &efi_desc_size,
                                   &efi_desc_ver);
        if (status != EFI_BUFFER_TOO_SMALL && EFI_ERROR(status)) {
		status = EFIERR(status);
                Print(L"Could not get UEFI Memory Map size 0x%x\n", status);
                while (1);
        }

        /*
         * Now that the previous call gave us the size of the Memory Map...
         * We do not care about the memory type for the UEFI Memory Map Buffer
         * since we are going to convert it to E820 anyway
         */
        efi_mmap_size += efi_desc_size * 10;
        status = uefi_call_wrapper(BS->AllocatePool, 3,
                                   EfiLoaderData,
                                   efi_mmap_size,
                                   (void **) &efi_mmap);
        if (EFI_ERROR(status)) {
		status = EFIERR(status);
                Print(L"Could not allocate UEFI Memory Map buffer %x\n", status);
                while (1);
        }

        /*
         * Use the newly allocated buffer with the correct size to store the
         * UEFI Memory Map
         * Repeat the previous function call to GetMemoryMap
         */
        status = uefi_call_wrapper(BS->GetMemoryMap, 5,
                                   &efi_mmap_size, efi_mmap, &efi_mmap_key,
                                   &efi_desc_size,
                                   &efi_desc_ver);
        if (EFI_ERROR(status)) {
		status = EFIERR(status);
                Print(L"Could not get UEFI Memory Map %x\n", status);
                while (1);
        }

        /*
         * Allocate memory for the e820 Memory Map.
         * Since it is possible that we may reach a memory split (i.e. a memory
         * area that also encompasses the Extended Bios Data Area), allocate an
         * additional entry.
         */
        desc_cnt = efi_mmap_size / efi_desc_size - 1;
        e820_mmap_size = (desc_cnt + 1) * (sizeof(multiboot_memory_map_t) +
			  sizeof(multiboot_uint32_t));
        mbi->mmap_addr = EBDA_START;
        status = uefi_call_wrapper(BS->AllocatePages, 4,
                                   AllocateMaxAddress, EfiLoaderData,
                                   EFI_SIZE_TO_PAGES(e820_mmap_size),
                                   (EFI_PHYSICAL_ADDRESS *) &mbi->mmap_addr);
        if (EFI_ERROR(status)) {
		status = EFIERR(status);
                Print(L"Could not allocate E820 Memory Map 0x%x\n", status);
                while (1);
        }
	Print(L"Allocated Multiboot Info Memory Map at 0x%x\n", mbi->mmap_addr);
        efi_to_e820_mmap(efi_mmap, desc_cnt, efi_desc_size,
                         (multiboot_memory_map_t *) (uintptr_t) mbi->mmap_addr);
	mbi->mmap_length = e820_mmap_size;

        status = uefi_call_wrapper(BS->GetMemoryMap, 5,
                                   &efi_mmap_size, efi_mmap, &efi_mmap_key,
                                   &efi_desc_size,
                                   &efi_desc_ver);
        if (status != EFI_BUFFER_TOO_SMALL && EFI_ERROR(status)) {
		status = EFIERR(status);
                Print(L"Could not get UEFI Memory Map size 0x%x\n", status);
                while (1);
        }

        KEY = efi_mmap_key;

        /*
        status = uefi_call_wrapper(BS->FreePool, 1,
                                   (void *) efi_mmap);
        if (EFI_ERROR(status)) {
		status = EFIERR(status);
                Print(L"Could not free UEFI Memory Map buffer 0x%x\n", status);
                while (1);
        }
*/
        return EFI_SUCCESS;
}

/*
 * TODO: Add initrd
 */
static EFI_STATUS EFIAPI setup_multiboot_info(OUT multiboot_info_t **mbi,
                                              EFI_LOADED_IMAGE *li)
{
        EFI_STATUS status;

        *mbi = (multiboot_info_t *) EBDA_START;

        // Allocate memory for multiboot_info
        status = uefi_call_wrapper(BS->AllocatePages, 4,
                                   AllocateMaxAddress, EfiLoaderData,
                                   EFI_SIZE_TO_PAGES(sizeof(**mbi)),
                                   (EFI_PHYSICAL_ADDRESS *) &(*mbi));
        if (EFI_ERROR(status)) {
		status = EFIERR(status);
                Print(L"Could not allocate Multiboot Info 0x%x\n", status);
                while (1);
        }

	Print(L"Allocated Multiboot Info at 0x%x\n", mbi);
        /*
         * Since Unikraft, before paging, does not really have many pages
         * staticaly allocated, in the lower memory, just make sure that
         * everything we need from multiboot_info is also in the lower memory,
         * between multiboot_info and the VGA buffer, namely the pages that
	 * Unikraft can touch before the page frame allocator kicks in.
         */
        (*mbi)->cmdline = EBDA_START;
        // Allocate memory for mbi->cmdline
        status = uefi_call_wrapper(BS->AllocatePages, 4,
                                   AllocateMaxAddress, EfiLoaderData,
                                   EFI_SIZE_TO_PAGES(MAX_CMDLINE_SIZE),
                                   (EFI_PHYSICAL_ADDRESS *) &(*mbi)->cmdline);
        if (EFI_ERROR(status)) {
		status = EFIERR(status);
                Print(L"Could not allocate Multiboot Info Command Line 0x%x\n",
		      status);
                while (1);
        }
	Print(L"Allocated Multiboot Info Command Line at 0x%x\n", (*mbi)->cmdline);
        // Retarded conversion from Unicode to ASCII
        stringify_load_options(li->LoadOptions, li->LoadOptionsSize,
                               (CHAR8 *) (uintptr_t) (*mbi)->cmdline);

        status = setup_multiboot_info_mmap(*mbi);
        if (EFI_ERROR(status)) {
		status = EFIERR(status);
                Print(L"Could not setup Multiboot Info Memory Map 0x%x\n",
			status);
                while (1);
        }

        return EFI_SUCCESS;
}

EFI_STATUS EFIAPI efi_main (IN EFI_HANDLE self_h, IN EFI_SYSTEM_TABLE *st)
{
	UINTN i, gop_info_size, gop_initial_mode, gop_best_mode;
	EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *gop_info = NULL;
	CHAR8 *uk_img_ptr, *load_addr, *load_addr_end;
	UINT32 gop_vertical_res, gop_horizontal_res;
	EFI_GRAPHICS_OUTPUT_PROTOCOL *gop = NULL;
	CHAR8 *uk_img_bss_ptr, *uk_img_bss_end;
        EFI_LOADED_IMAGE *li = NULL;
        multiboot_info_t *mbi;
        EFI_STATUS status;

	/*
	 * GNU-EFI specific only
	 */
        InitializeLib(self_h, st);

	uefi_call_wrapper(ST->ConOut->ClearScreen, 1, ST->ConOut);

	/*
	 * Obtain a handle to this very image loaded into memory and its
	 * environment
	 */
        status = uefi_call_wrapper(BS->HandleProtocol, 3,
                                   self_h, &LoadedImageProtocol, (void **) &li);
        if (EFI_ERROR(status)) {
		status = EFIERR(status);
                Print(L"Could not access LoadedImageProtocol 0x%x\n", status);
		/*
		 * Throw in an infinite loop so that my laptop stops restarting
		 * and I can actually see my logging prints...
		 */
                while (1);
        }

        Print(L"Image base: 0x%lx efi_main %x\n", li->ImageBase, &efi_main);
        Print(L"CLI Args: %s\nCLI Size %u", li->LoadOptions,
					    li->LoadOptionsSize);

	/*
	 * Normally this should be iterated upon, since there could be
	 * multiple GPU's and displays - a GOP handle corresponds to a
	 * display... but we are just testing the waters so... whatever for now
	 */
	status = uefi_call_wrapper(BS->LocateProtocol, 3,
                                   &GraphicsOutputProtocol, NULL,
				   (void **) &gop);
        if (EFI_ERROR(status)) {
		status = EFIERR(status);
                Print(L"Could not initialize GOP 0x%x\n", status);
                while (1);
        }

	/*
	 * Find the current display's GOP mode
	 */
	status = uefi_call_wrapper(gop->QueryMode, 4,
				   gop,
				   gop->Mode == NULL ? 0 : gop->Mode->Mode,
				   &gop_info_size, &gop_info);
        if (EFI_ERROR(status)) {
		status = EFIERR(status);
                Print(L"Could not Query GOP current mode 0x%x\n", status);
                while (1);
        }

	/*
	 * Switch to the highest display resolution and pixel format
	 * Unikraft in Full HD
	 */
	gop_initial_mode = gop_best_mode = gop->Mode->Mode;
	gop_horizontal_res = gop_info->HorizontalResolution;
	gop_vertical_res = gop_info->VerticalResolution;
	for (i = 0; i < gop->Mode->MaxMode; i++) {
		status = uefi_call_wrapper(gop->QueryMode, 4,
					   gop, i, &gop_info_size, &gop_info);
		if (EFI_ERROR(status)) {
			status = EFIERR(status);
	                Print(L"Could not Query GOP mode %lu 0x%x\n", i, status);
		        while (1);
		}

		if (gop_info->PixelFormat == UEFI_GOP_DEFAULT_PIXEL_FORMAT &&
		    gop_info->HorizontalResolution * gop_info->VerticalResolution
		    > gop_horizontal_res * gop_vertical_res) {
			gop_horizontal_res = gop_info->HorizontalResolution;
			gop_vertical_res = gop_info->VerticalResolution;
			gop_best_mode = i;
		}

		Print(L"mode %03lu width %d height %d format %x\n",
			i,
			gop_info->HorizontalResolution,
			gop_info->VerticalResolution,
			gop_info->PixelFormat);
        }

	Print(L"GOP best mode is %lu\n", gop_best_mode);

	status = uefi_call_wrapper(gop->SetMode, 2,
				   gop, gop_best_mode);
	if (EFI_ERROR(status)) {
		status = EFIERR(status);
                Print(L"Could not set GOP mode to %lu 0x%x\n",
		      gop_best_mode, status);
                while (1);
        }

	Print(L"FB address %x size %d, width %d height %d pixelsperline %d\n",
		gop->Mode->FrameBufferBase,
		gop->Mode->FrameBufferSize,
		gop->Mode->Info->HorizontalResolution,
		gop->Mode->Info->VerticalResolution,
		gop->Mode->Info->PixelsPerScanLine
	);

	EFI_CONFIGURATION_TABLE *ct = st->ConfigurationTable;
	UINTN nte = st->NumberOfTableEntries;
	struct RSDPDescriptor *rsdp;
	struct RSDPDescriptor20 *xsdp;
	struct RSDT *rsdt = NULL;
	struct XSDT *xsdt = NULL;
	for (i = 0; i < nte; i++)
		switch (ct[i].VendorGuid.Data1) {
		case _MPS_TABLE_GUID:
			Print(L"Found MPS Table at 0x%x\n", ct[i].VendorTable);

			break;
		case _ACPI_TABLE_GUID:
			Print(L"Found ACPI Table at 0x%x\n", ct[i].VendorTable);
			rsdp = ct[i].VendorTable;
			rsdt = rsdp->RsdtAddress;

			break;
		case _ACPI_20_TABLE_GUID:
			Print(L"Found ACPI_20 Table at 0x%x\n", ct[i].VendorTable);
			xsdp = ct[i].VendorTable;
			xsdt = xsdp->XsdtAddress;

			break;
		case _SMBIOS_TABLE_GUID:
			Print(L"Found SMBIOS Table at 0x%x\n", ct[i].VendorTable);

			break;
		case _SMBIOS3_TABLE_GUID:
			Print(L"Found SMBIOS3 Table at 0x%x\n", ct[i].VendorTable);

			break;
		case _SAL_SYSTEM_TABLE_GUID:
			Print(L"Found SAL_SYSTEM Table at 0x%x\n", ct[i].VendorTable);

			break;
		case _HCDP_TABLE_GUID:
			Print(L"Found HCDP Table at 0x%x\n", ct[i].VendorTable);

			break;
		case _UV_SYSTEM_TABLE_GUID:
			Print(L"Found UV_SYSTEM Table at 0x%x\n", ct[i].VendorTable);

			break;
		case _EFI_SYSTEM_RESOURCE_TABLE_GUID:
			Print(L"Found EFI_SYSTEM_RESOURCE Table at 0x%x\n", ct[i].VendorTable);

			break;
		case _EFI_PROPERTIES_TABLE_GUID:
			Print(L"Found EFI_PROPERTIES Table at 0x%x\n", ct[i].VendorTable);

			break;
		case _EFI_MEMORY_ATTRIBUTES_TABLE_GUID:
			Print(L"Found EFI_MEMORY_ATTRIBUTES_TABLE_GUID Table at 0x%x\n", ct[i].VendorTable);

			break;
		case _EFI_RT_PROPERTIES_TABLE_GUID:
			Print(L"Found EFI_RT_PROPERTIES_TABLE_GUID Table at 0x%x\n", ct[i].VendorTable);

			break;
		case _EFI_DXE_SERVICES_TABLE_GUID:
			Print(L"Found EFI_DXE_SERVICES Table at 0x%x\n", ct[i].VendorTable);

			break;
		}

	/*
	 * Spec says to use XSDT instead of RSDT if present but meh
	 */
	UINTN rsdt_entry_count = rsdt->h.Length - sizeof(struct ACPISDTHeader);
	rsdt_entry_count /= sizeof(*rsdt->Entry);
	for (i = 0; i < rsdt_entry_count; i++) {
		struct ACPISDTHeader *ah = (struct ACPISDTHeader *) (uintptr_t)
					   rsdt->Entry[i];

		Print(L"RSDT: Found %c%c%c%c at 0x%x\n", ah->Signature[0],
		      ah->Signature[1], ah->Signature[2], ah->Signature[3],
		      rsdt->Entry[i]);
	}

	struct MCFG *mcfg = NULL;
	if (xsdt) {
		UINTN xsdt_entry_count = xsdt->h.Length -
					 sizeof(struct ACPISDTHeader);
		xsdt_entry_count /= sizeof(*xsdt->Entry);
		for (i = 0; i < xsdt_entry_count; i++) {
			struct ACPISDTHeader *ah = (struct ACPISDTHeader *)
						   (uintptr_t) xsdt->Entry[i];

			Print(L"XSDT: Found %c%c%c%c at 0x%x\n", ah->Signature[0],
			      ah->Signature[1], ah->Signature[2], ah->Signature[3],
			      xsdt->Entry[i]);

			/* No memcmp... */
			if (ah->Signature[0] == 'M' &&
			    ah->Signature[1] == 'C' &&
			    ah->Signature[2] == 'F' &&
			    ah->Signature[3] == 'G')
				mcfg = (struct MCFG *) xsdt->Entry[i];
		}
	}

	if (mcfg) {
		UINTN pci_ecam_count = mcfg->h.Length -
				       sizeof(struct ACPISDTHeader);
		pci_ecam_count /= sizeof(*mcfg->pe);

		for (i = 0; i < pci_ecam_count; i++) {
			Print(L"Found PCIe ECAM at 0x%x, seg 0x%x, start_bus "
			      "0x%x, end_bus 0x%x\n", mcfg->pe[i].addr,
			      mcfg->pe[i].seg, mcfg->pe[i].start_bus,
			      mcfg->pe[i].end_bus);

			/* EFI does not map these pages... yet..
			 * will look into it so that I can see the devices
			*/
			struct pci_hdr *p;
			for (int bus = 0; bus < mcfg->pe[i].end_bus; bus++)
				for (int dev = 0; dev < 32; dev++)
					for (int func = 0; func < 8; func++) {
						p = (struct pci_hdr *)
						    (mcfg->pe[i].addr +
						    ((bus - mcfg->pe[i].start_bus) <<
						    20 | dev << 15 | func << 12));

						if (p->vendor_id == 0xffff)
							continue;

						Print(L"Probing PCIe dev at 0x%x"
						      ", vendor_id 0x%x, "
						      "device_id 0x%x\n",
						      p, p->vendor_id, p->device_id);
					}
		}
	}

	/*
	 * Start building the multiboot struct...
	 * Perhaps this would be better written as a generic boot protocol
	 * function that configure the structure depending on defined configs
	 * referencin the currently chosen boot protocol.
	 * Or, better yet, just write our own custom boot protocol that
	 * allows for booting directly into 64-bit mode... instead of
	 * building a struct for a not-so-UEFI-compatible boot protocol (
	 * Multiboot2 may be UEFI compatible... but mostly for ia-32 efi systems
	 * - the Multiboot2 spec is vague for ia-32e/amd64 UEFI systems).
	 * You shouldn't have to make the bootloader switch to an inferior
	 * CPU operating mode just to accomodate the pre-kernel.
	 */
        status = setup_multiboot_info(&mbi, li);
        if (EFI_ERROR(status)) {
		status = EFIERR(status);
                Print(L"Failed to setup Multiboot Info 0x%x\n", status);
                while (1);
        }

	/*
	 * Just needlessly filling the Multiboot's FB fields that Unikraft
	 * is not aware of anyway, but i will use it to know whether Unikraft
	 * did successfully boot on baremetal or not by filling the GPU's VRAM
	 * instead of a `Hello World!` which would require a framebuffer driver
	 * that can make use of fonts to draw actual letters... like most
	 * Linux distro's do with PSF font for their TTY's.
	 */
	mbi->framebuffer_addr = gop->Mode->FrameBufferBase;
	mbi->framebuffer_pitch = 4 * gop->Mode->Info->PixelsPerScanLine;
	mbi->framebuffer_width = gop->Mode->Info->HorizontalResolution;
	mbi->framebuffer_height = gop->Mode->Info->VerticalResolution;
/*
 * Do not mind this, I need this here for debugging purposes because sometimes
 * the ELF image embedded into the PE would not export segments as expected.
 * Also used this to ensure that Unikraft cannot be legitimately loaded
 * in EFI Driver Execution Environment at address 0x100000, since there
 * usually might be some firmware routines loaded.
	Elf64_Ehdr *uk =(Elf64_Ehdr *) &uk_img;
	Elf64_Phdr *p = (Elf64_Phdr *) ((CHAR8 *) uk + uk->e_phoff);
	UINTN p_cnt = uk->e_phnum;
	for (i = 0; i < p_cnt; i++)
		switch (p[i].p_type) {
		case PT_LOAD:
			status = uefi_call_wrapper(BS->AllocatePages, 4,
						   AllocateAddress,
						   EfiLoaderData,
						   EFI_SIZE_TO_PAGES(p[i].p_memsz),
						   (EFI_PHYSICAL_ADDRESS *) &p[i].p_vaddr);
		        if (EFI_ERROR(status)) {
				status = EFIERR(status);
		                Print(L"Could not allocate ELF Program Header"
				      "%lu 0x%x\n", i, status);
				while (1);
			}

			memcpy((void *) p[i].p_vaddr,
			       (void *) ((CHAR8 *) uk + p[i].p_offset),
			       p[i].p_filesz);

			break;
		}
*/
	/*
	 * Look for the Multiboot header in the Unikernel image
	 */
	UINT32 *hdr = (UINT32 *) &uk_img;
	for (; *hdr != MULTIBOOT_MAGIC; hdr++);

	struct multiboot_header *mbh = (struct multiboot_header *) hdr;

	/*
	 * What I am about to do is not recommended with Boot Services on so
	 * exit them anyway
	 */
	status = uefi_call_wrapper(BS->ExitBootServices, 2,
				   self_h, KEY);
	if (EFI_ERROR(status)) {
		status = EFIERR(status);
                Print(L"Could not ExitBootServices 0x%x\n", status);
                while (1);
        }

	/*
	 * memcpy the Unikraft ELF image embedded into .uk_img section
	 * to the address indicated by Multiboot header.
	 * Normally done through UEFI's MemoryCopy, but... whatever for now
	 */
	uk_img_ptr = (CHAR8 *) mbh;
	load_addr = (CHAR8 *) (uintptr_t) mbh->load_addr;
	load_addr_end = (void *) (uintptr_t) mbh->load_end_addr;
	while (load_addr < load_addr_end)
		*load_addr++ = *uk_img_ptr++;

	/*
	 * Zero out the BSS area
	 * Without this, Unikraft triple faults while loading the TSS
	 */
	uk_img_bss_ptr = (CHAR8 *) (uintptr_t) mbh->load_end_addr;
	uk_img_bss_end = (CHAR8 *) (uintptr_t) mbh->bss_end_addr;
	while (uk_img_bss_ptr < uk_img_bss_end)
		*uk_img_bss_ptr++ = 0;

	/*
	 * This should do for now... I guess...
	 * I had to modify Unikraft's Multiboot entry though to jump
	 * straight to 64 bit, reload its own GDT and keep the UEFI
	 * page mappings since jumping from UEFI's 64-bit mode to Protected
	 * Mode somehow fails after the far return... (look below).
	 */
	__asm__ __volatile__(
		"movq $0x2BADB002 , %%rax;\n"
	        "movq %0, %%rbx;\n"
		"cli;\n"
		"jmp *%1;\n"
	        :
		: "r" (mbi), "r" ((uintptr_t) mbh->entry_addr)
	        : "rax", "rbx"
	);

/*
 * Failed attempt at far return from 64bit to Compatibility Mode to Protected
 * Mode to accomodate Multiboot boot environment
	GDTR.addr = (uint64_t) &GDT;
	GDTR.size = sizeof(GDT) - 1;

	__asm__ __volatile__(
		"cli;\n"
		"movq %0, %%rax;\n"
		"movq %1, %%rbx;\n"
		"lgdt 0(%%rax);\n"
		"sgdt 0(%%rax);\n"  // to check in gdb if the correct address is loaded
		"pushq $0x8;\n"
		"leaq pmode(%%rip), %%rax;\n"
		"pushq %%rax;\n"
		"lretq;\n"  // somehow execution jumps to erroneous address
	".code32\n"
	"pmode:\n"
		"movl $0x10, %%eax;\n"
		"movl %%eax, %%ds;\n"
		"movl %%eax, %%es;\n"
		"movl %%eax, %%fs;\n"
		"movl %%eax, %%gs;\n"
		"movl %%eax, %%ss;\n"

		"movl %%cr0, %%ecx;;\n"
		"andl $0x7fffffff, %%ecx;\n"
		"movl %%ecx, %%cr0;\n"

		"movl $0x2BADB002, %%eax;\n"
		"jmp *%k2;\n"
		:: "r" (&GDTR), "r" (mbi), "r" (mbh->entry_addr) :);
 */

        return EFI_SUCCESS;
}
