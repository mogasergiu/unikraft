#!/usr/bin/env python3

import argparse
import subprocess
import os
import re

ELF64_EHDR_LEN = 64
MS_DOS_SIGNATURE = 0x5a4d

# Get the absolute value of symbol, as seen through `nm`
def get_sym_val(elf, sym):
    exp = r'^\s*' + r'([a-f0-9]+)' + r'\s+[A-Za-z]\s+' + sym + r'$'
    out = subprocess.check_output(['nm', elf])

    re_out = re.findall(exp, out.decode('ASCII'), re.MULTILINE)
    if len(re_out) != 1:
        raise Exception('Found no ' + sym + ' symbol.')

    return int(re_out[0], 16)

# Get a list of the PT_LOAD Program Headers. Must be 4. If more, then
# the PE header must be modified accordingly by adding another dummy
# PE section and increasing the header size. If less, the opposite.
# But we should have 4 of them if everything was built correctly:
# - a PT_LOAD with all RE sections (.text)
# - a PT_LOAD with all RO sections
# - a PT_LOAD with all RW sections
# - a PT_LOAD dedicated to .tdata
HEXNUM_EXP = r'0x[a-f0-9]+'
def get_loadable_phdrs(elf):
    exp = (r'^\s*' + r'LOAD' + r'\s*' +
           r'(' + HEXNUM_EXP + r')' + r'\s*' +
           r'(' + HEXNUM_EXP + r')' + r'\s*' +
           HEXNUM_EXP + r'\s*' +
           r'(' + HEXNUM_EXP + r')' + r'\s*' +
           r'(' + HEXNUM_EXP + r')' + r'\s*' +
           r'(' + r'[RWE ]+' + r')' + r'\s*' +
           HEXNUM_EXP + r'$')
    out = subprocess.check_output(["readelf", "-l", elf],
                                   stderr=subprocess.DEVNULL)
    re_out = re.findall(exp, out.decode('ASCII'), re.MULTILINE)
    if len(re_out) != 4:
        raise Exception('Expected 4 loadable Program Headers but '
                        'found ' + str(len(re_out)) + ' instead.')

    return [{
                "Offset"    : int(r[0], 16),
                "VirtAddr"  : int(r[1], 16),
                "FileSiz"   : int(r[2], 16),
                "MemSiz"    : int(r[3], 16),
                "Flags"     : r[4].replace(' ', '')
            } for r in re_out]

def main():
    parser = argparse.ArgumentParser(
    description='Update the fake PE32 header with the required metadata to'
                'be bootable by a UEFI environment and overwrite the ELF64'
                'Header with an empty MS-DOS stub')
    parser.add_argument('elf', help='path to ELF64 binary to process')
    opt = parser.parse_args()

    # We need to operate on the debug image for symbol values. But as far as
    # ELF sections go, using the final image is enough.
    elf_dbg = opt.elf + ".dbg"

    ld_phdrs = get_loadable_phdrs(opt.elf)

    # Grab the PT_LOAD Program Header containing code.
    # We will use it as the base Program Header, since it is the first loaded.
    for p in ld_phdrs:
        if p['Flags'] == 'RE':
            pe_text = p
            break
    # Remove it to avoid conflicts when iterating
    ld_phdrs.remove(pe_text)

    # Again, all addresses relative to the very base of the file.
    # Use the first function in our EFI stub as the entry point.
    entry_rva = get_sym_val(elf_dbg, r'uk_efi_entry64')
    entry_rva += pe_text['Offset'] - pe_text['VirtAddr']

    # Image size in memory is equal to the last PT_LOAD + its size
    img_sz = 0
    base_addr = get_sym_val(elf_dbg, r'_base_addr')
    for p in ld_phdrs:
        if img_sz < p['VirtAddr'] + p['MemSiz']:
            img_sz = p['VirtAddr'] + p['MemSiz']

    # img_sz is Address of last loadable section (.bss) + its size, so to get
    # the final size of the loaded image in memory subtract the base_address
    img_sz -= base_addr

    # Since it is a PE, the Header and MS-DOS stub will also get loaded, so add
    # their size as well
    img_sz += 0x1000

    # Re-adjust start addresses of the other PT_LOAD's
    for lp in ld_phdrs:
        lp['VirtAddr'] += pe_text['Offset'] - pe_text['VirtAddr']

    # Store the offset to the PE Header before updating the .text section
    pe_hdr_off = pe_text['Offset']

    # Final adjustments for the .text section
    # Subtract size of the PE Header
    pe_text['FileSiz'] -= 0x1000
    # Subtract the size of the PE Header
    pe_text['MemSiz'] -= 0x1000
    # Skip the PE Header when loading .text
    pe_text['Offset'] += 0x1000
    # VirtualAddress is actually the Relative Virtual Address to ImageBase
    pe_text['VirtAddr'] = pe_text['Offset']

    # PE is loaded by sections, thus the fake PE Header encodes the PT_LOAD's
    # as follows:
    # - dummy .reloc section since UEFI wants relocatable PE's
    # - .text which contains the PT_LOAD with all RE sections (.text)
    # - .rdata which contains the PT_LOAD with all RO sections
    # - .data which contains the PT_LOAD with all RW sections
    # - .tdata which contains the PT_LOAD dedicated to .tdata
    with open(opt.elf, 'r+b') as elf_file,                                \
         open(opt.elf + ".efi", 'wb') as efi_file:
         efi_file.write(elf_file.read())

    with open(opt.elf + ".efi", 'r+b') as efi:
        # Zero out the ELF64 Header
        efi.write(bytes(ELF64_EHDR_LEN))
        efi.seek(0)

        # Write the MS-DOS signature
        efi.write(MS_DOS_SIGNATURE.to_bytes(2, 'little'))

        # Jump to the end of the MS-DOS stub, where the value of the offset to
        # the actual PE Header is expected.
        efi.seek(0x3c)
        efi.write(pe_hdr_off.to_bytes(4, 'little'))

        # Jump to the PE Header and skip over MS-DOS stub
        efi.seek(pe_hdr_off)
        # Skip to optional_header
        efi.seek(24, 1)
        # Skip to SizeOfCode
        efi.seek(4, 1)
        efi.write(pe_text['FileSiz'].to_bytes(4, 'little'))  # SizeOfCode
        # Skip to AddressOfEntryPoint
        efi.seek(8, 1)
        efi.write(entry_rva.to_bytes(4, 'little'))          # AddressOfEntryPoint
        efi.write(pe_text['Offset'].to_bytes(4, 'little'))  # BaseOfCode

        # Jump to xhdr_fields from PE Header and skip optional_header
        efi.seek(pe_hdr_off + 48)
        # Skip to SizeOfImage
        efi.seek(32, 1)
        efi.write(img_sz.to_bytes(4, 'little'))             # SizeOfImage

        # Jump to .reloc section header.
        # We are writing a dummy .reloc. We will make UEFI overwrite the
        # unneeded last fields of the header (PointerToRelocations,
        # PointerToLineNumbers, NumberOfRelocations, NumberOfLineNumbers and
        # Characteristics) thinking of it as a relocation by overwriting
        # VirtualAddress and PointerToRawData to point to these sections.
        efi.seek(pe_hdr_off + 184)
        # Skip Name and VirtualSize and go to Virtual Address
        efi.seek(8 + 4, 1)
        efi.write((efi.tell() + 12).to_bytes(4, 'little'))  # VirtualAddress
        # Skip SizeOfRawData and go to PointerToRawData
        efi.seek(4, 1)
        efi.write((efi.tell() + 4).to_bytes(4, 'little'))   # PointerToRawData

        def apply_phdr_to_sec(p, sec_off):
            efi.seek(sec_off)

            # Skip Name and go to VirtualSize
            efi.seek(8, 1)
            efi.write(p['MemSiz'].to_bytes(4, 'little'))    # VirtualSize
            efi.write(p['VirtAddr'].to_bytes(4, 'little'))  # VirtualAddress
            efi.write(p['FileSiz'].to_bytes(4, 'little'))   # SizeOfRawData
            efi.write(p['Offset'].to_bytes(4, 'little'))    # PointerToRawData

            # Skip the other fields of the .text section header:
            # PointerToRelocations, PointerToLineNumbers, NumberOfRelocations,
            # NumberOfLineNumbers and Characteristics.
            efi.seek(16, 1)

        # Jump to .text section (offset to .reloc section header + size of .reloc
        # section header)
        efi.seek(pe_hdr_off + 184 + 40)

        apply_phdr_to_sec(pe_text, efi.tell())

        # We are now at the .rdata section header, followed by the section headers
        # of .data and .tdata.
        for p in ld_phdrs:
            apply_phdr_to_sec(p, efi.tell())

if __name__ == '__main__':
    main()
