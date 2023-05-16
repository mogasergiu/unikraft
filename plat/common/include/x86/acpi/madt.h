/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Authors: Cristian Vijelie <cristianvijelie@gmail.com>
 *          Sergiu Moga <sergiu.moga@protonmail.com>
 *
 * Copyright (c) 2023, University POLITEHNICA of Bucharest. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef __PLAT_CMN_X86_MADT_H__
#define __PLAT_CMN_X86_MADT_H__

#include <x86/acpi/sdt.h>

#define MADT_LAPIC				0x00
#define MADT_IO_APIC				0x01
#define MADT_INT_SRC_OVERRIDE			0x02
#define MADT_NMI_SOURCE				0x03
#define MADT_LAPIC_NMI				0x04
#define MADT_LAPIC_ADDRESS_OVERRIDE		0x05
#define MADT_IO_SAPIC				0x06
#define MADT_LSAPIC				0x07
#define MADT_PLATFORM_INT_SOURCES		0x08
#define MADT_LX2APIC				0x09
#define MADT_LX2APIC_NMI			0x0a
#define MADT_GICC				0x0b
#define MADT_GICD				0x0c
#define MADT_GIC_MSI				0x0d
#define MADT_GICR				0x0e
#define MADT_GIC_ITS				0x0f
#define MADT_MP_WAKEUP				0x10

/*
 * The following structures are declared according to the ACPI
 * specification version 6.3.
 *
 * TODO: This header includes structures that are not related to x86. However,
 * we move the header when integrating other architectures.
 */

/* Processor Local APIC Structure */
struct acpi_madt_lapic {
        struct acpi_subsdt_hdr hdr;
	__u8 cpu_id;
        __u8 lapic_id;
	__u32 flags;
} __packed;

#define MADT_LAPIC_FLAGS_ENABLED			0x01
#define MADT_LAPIC_FLAGS_ONLINE_CAPABLE			0x02

/* I/O APIC Structure */
struct acpi_madt_ioapic {
        struct acpi_subsdt_hdr hdr;
	__u8 ioapic_id;
	__u8 reserved;
	__u32 ioapic_paddr;
	__u32 gsi_base;
} __packed;

/* Interrupt Source Override Structure */
struct acpi_madt_irq_src_override {
        struct acpi_subsdt_hdr hdr;
	__u8 bus;
	__u8 src_irq;
	__u32 gsi;
	__u16 flags;
} __packed;

/* Non-Maskable Interrupt (NMI) Source Structure */
struct acpi_madt_nmi_src {
        struct acpi_subsdt_hdr hdr;
	__u16 flags;
	__u32 gsi;
} __packed;

/* Local APIC NMI Structure */
struct acpi_madt_lapic_nmi {
        struct acpi_subsdt_hdr hdr;
	__u8 cpu_id;
	__u16 flags;
	__u8 lint;
} __packed;

/* Local APIC Address Override Structure */
struct acpi_madt_lapic_addr_override {
        struct acpi_subsdt_hdr hdr;
	__u16 reserved;
	__u64 lapic_paddr;
} __packed;

/* I/O SAPIC Structure */
struct acpi_madt_iosapic {
        struct acpi_subsdt_hdr hdr;
	__u8 iosapic_id;
	__u8 reserved;
	__u32 gsi_base;
	__u64 iosapic_paddr;
} __packed;

/* Local SAPIC Structure */
struct acpi_madt_lsapic {
        struct acpi_subsdt_hdr hdr;
	__u8 cpu_id;
	__u8 lsapic_id;
	__u8 lsapic_eid;
	__u8 reserved[3];
	__u32 flags;
	__u32 uid;
	char uid_string[1];
} __packed;

/* Platform Interrupt Source Structure */
struct acpi_madt_irq_src {
        struct acpi_subsdt_hdr hdr;
	__u16 mps_inti_flags;
	__u8 irq_type;
	__u8 cpu_id;
	__u8 cpu_eid;
	__u8 io_sapic_vector;
	__u32 gsi;
	__u32 flags;
} __packed;

/* Processor Local x2APIC Structure */
struct acpi_madt_x2apic {
        struct acpi_subsdt_hdr hdr;
	__u16 reserved;
	__u32 lapic_id;
	__u32 flags;
	__u32 uid;
} __packed;

#define MADT_X2APIC_FLAGS_ENABLED			0x01
#define MADT_X2APIC_FLAGS_ONLINE_CAPABLE		0x02

/* Local x2APIC NMI Structure */
struct acpi_madt_x2apic_nmi {
        struct acpi_subsdt_hdr hdr;
	__u16 mps_inti_flags;
	__u32 uid;
	__u8 lint;
	__u8 reserved[3];
} __packed;

/* GIC CPU Interface (GICC) Structure */
struct acpi_madt_gicc {
        struct acpi_subsdt_hdr hdr;
	__u16 reserved;
	__u32 cpu_if;
	__u32 uid;
	__u32 flags;
	__u32 parking_version;
	__u32 perf_mon_gsiv;
	__u64 parked_paddr;
	__u64 paddr;
	__u64 gicv;
	__u64 gich;
	__u32 vgic_maintenance_gsiv;
	__u64 gicr_paddr;
	__u64 mpidr;
	__u8 power_efficiency;
	__u8 reserved2;
	__u16 spe_gsiv;
} __packed;

/* GIC Distributor (GICD) Structure */
struct acpi_madt_gicd {
        struct acpi_subsdt_hdr hdr;
	__u16 reserved;
	__u32 gic_id;
	__u64 paddr;
	__u32 gsi_base;
	__u8 version;
	__u8 reserved2[3];
} __packed;

/* GIC MSI Frame Structure */
struct acpi_madt_gic_msi_frame {
        struct acpi_subsdt_hdr hdr;
	__u16 reserved;
	__u32 msi_frame_id;
	__u64 paddr;
	__u32 flags;
	__u16 spi_count;
	__u16 spi_base;
} __packed;

/* GIC Redistributor (GICR) Structure */
struct acpi_madt_gicr {
        struct acpi_subsdt_hdr hdr;
	__u16 reserved;
	__u64 paddr;
	__u64 len;
} __packed;

/* GIC Interrupt Translation Service (ITS) Structure */
struct acpi_madt_gic_its {
        struct acpi_subsdt_hdr hdr;
	__u16 reserved;
	__u32 id;
	__u64 paddr;
	__u32 reserved2;
} __packed;

/* Multiprocessor Wakeup Structure */
struct acpi_madt_mp_wakeup_src {
        struct acpi_subsdt_hdr hdr;
	__u16 mbox_version;
	__u32 reserved;
	__u64 mbox_paddr;
} __packed;

/**
 * Return the Multiple APIC Descriptor Table (MADT). ACPI needs to be
 * initialized first.
 *
 * @return Pointer to MADT.
 */
struct acpi_madt *acpi_get_madt(void);

#endif /* __PLAT_CMN_X86_MADT_H__ */
