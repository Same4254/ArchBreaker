use std::{fs, path::PathBuf};
use std::collections::HashMap;

use crate::util::*;

pub const DATA_SECTION: &'static str = ".data";

pub const RDATA_SECTION: &'static str = ".rdata";

pub const TEXT_SECTION: &'static str = ".text";

#[derive(Debug)]
pub enum PEParsingError {
    UnrecognizedMachineType,
    UnrecognizedPEType,
    IOError(std::io::Error),
    StringParseError(std::str::Utf8Error)
}

// Implement conversion from std::io::Error
impl From<std::io::Error> for PEParsingError {
    fn from(err: std::io::Error) -> PEParsingError {
        PEParsingError::IOError(err)
    }
}

// Implement conversion from std::io::Error
impl From<std::str::Utf8Error> for PEParsingError {
    fn from(err: std::str::Utf8Error) -> PEParsingError {
        PEParsingError::StringParseError(err)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum PEType {
    PE32,
    PE32P
}

#[derive(Debug)]
#[repr(u16)]
#[allow(non_camel_case_types)]
pub enum Characteristics {
    // Image only, Windows CE, and Microsoft Windows NT and later. This indicates that the file does not contain base relocations and must therefore be loaded at its preferred base address. If the base address is not available, the loader reports an error. The default behavior of the linker is to strip base relocations from executable (EXE) files.
    IMAGE_FILE_RELOCS_STRIPPED = 0x0001,
    // Image only. This indicates that the image file is valid and can be run. If this flag is not set, it indicates a linker error.
    IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002,
    // COFF line numbers have been removed. This flag is deprecated and should be zero.
    IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004,
    // COFF symbol table entries for local symbols have been removed. This flag is deprecated and should be zero.
    IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008,
    // Obsolete. Aggressively trim working set. This flag is deprecated for Windows 2000 and later and must be zero.
    IMAGE_FILE_AGGRESSIVE_WS_TRIM = 0x0010,
    // Application can handle > 2-GB addresses.
    IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020,
    // This flag is reserved for future use.
    // Reserved = 0x0040,
    // Little endian: the least significant bit (LSB) precedes the most significant bit (MSB) in memory. This flag is deprecated and should be zero.
    IMAGE_FILE_BYTES_REVERSED_LO = 0x0080,
    // Machine is based on a 32-bit-word architecture.
    IMAGE_FILE_32BIT_MACHINE = 0x0100,
    // Debugging information is removed from the image file.
    IMAGE_FILE_DEBUG_STRIPPED = 0x0200,
    // If the image is on removable media, fully load it and copy it to the swap file.
    IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400,
    // If the image is on network media, fully load it and copy it to the swap file.
    IMAGE_FILE_NET_RUN_FROM_SWAP = 0x0800,
    // The image file is a system file, not a user program.
    IMAGE_FILE_SYSTEM = 0x1000,
    // The image file is a dynamic-link library (DLL). Such files are considered executable files for almost all purposes, although they cannot be directly run.
    IMAGE_FILE_DLL = 0x2000,
    // The file should be run only on a uniprocessor machine.
    IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000,
    // Big endian: the MSB precedes the LSB in memory. This flag is deprecated and should be zero.
    IMAGE_FILE_BYTES_REVERSED_HI = 0x8000,
}

fn parse_characteristics(value: u16) -> Vec<Characteristics> {
    let mut to_ret = Vec::new();

    if value & Characteristics::IMAGE_FILE_RELOCS_STRIPPED as u16 > 0{
        to_ret.push(Characteristics::IMAGE_FILE_RELOCS_STRIPPED);
    }

    if value & Characteristics::IMAGE_FILE_EXECUTABLE_IMAGE as u16 > 0 {
        to_ret.push(Characteristics::IMAGE_FILE_EXECUTABLE_IMAGE);
    }

    if value & Characteristics::IMAGE_FILE_LINE_NUMS_STRIPPED as u16 > 0 {
        to_ret.push(Characteristics::IMAGE_FILE_LINE_NUMS_STRIPPED);
    }

    if value & Characteristics::IMAGE_FILE_LOCAL_SYMS_STRIPPED as u16 > 0 {
        to_ret.push(Characteristics::IMAGE_FILE_LOCAL_SYMS_STRIPPED);
    }

    if value & Characteristics::IMAGE_FILE_AGGRESSIVE_WS_TRIM as u16 > 0 {
        to_ret.push(Characteristics::IMAGE_FILE_AGGRESSIVE_WS_TRIM);
    }

    if value & Characteristics::IMAGE_FILE_LARGE_ADDRESS_AWARE as u16 > 0 {
        to_ret.push(Characteristics::IMAGE_FILE_LARGE_ADDRESS_AWARE);
    }

    if value & Characteristics::IMAGE_FILE_BYTES_REVERSED_LO as u16 > 0 {
        to_ret.push(Characteristics::IMAGE_FILE_BYTES_REVERSED_LO);
    }

    if value & Characteristics::IMAGE_FILE_32BIT_MACHINE as u16 > 0 {
        to_ret.push(Characteristics::IMAGE_FILE_32BIT_MACHINE);
    }

    if value & Characteristics::IMAGE_FILE_DEBUG_STRIPPED as u16 > 0 {
        to_ret.push(Characteristics::IMAGE_FILE_DEBUG_STRIPPED);
    }

    if value & Characteristics::IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP as u16 > 0 {
        to_ret.push(Characteristics::IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP);
    }

    if value & Characteristics::IMAGE_FILE_NET_RUN_FROM_SWAP as u16 > 0 {
        to_ret.push(Characteristics::IMAGE_FILE_NET_RUN_FROM_SWAP);
    }

    if value & Characteristics::IMAGE_FILE_SYSTEM as u16 > 0 {
        to_ret.push(Characteristics::IMAGE_FILE_SYSTEM);
    }

    if value & Characteristics::IMAGE_FILE_DLL as u16 > 0 {
        to_ret.push(Characteristics::IMAGE_FILE_DLL);
    }

    if value & Characteristics::IMAGE_FILE_UP_SYSTEM_ONLY as u16 > 0 {
        to_ret.push(Characteristics::IMAGE_FILE_UP_SYSTEM_ONLY);
    }

    if value & Characteristics::IMAGE_FILE_BYTES_REVERSED_HI as u16 > 0 {
        to_ret.push(Characteristics::IMAGE_FILE_BYTES_REVERSED_HI);
    }

    to_ret
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum MachineType {
    // The content of this field is assumed to be applicable to any machine type
    IMAGE_FILE_MACHINE_UNKNOWN = 0x0,
    // Alpha AXP, 32-bit address space
    IMAGE_FILE_MACHINE_ALPHA = 0x184,
    // Alpha 64, 64-bit address space
    //IMAGE_FILE_MACHINE_ALPHA64 = 0x284,
    // Matsushita AM33
    IMAGE_FILE_MACHINE_AM33 = 0x1d3,
    // x64
    IMAGE_FILE_MACHINE_AMD64 = 0x8664,
    // ARM little endian
    IMAGE_FILE_MACHINE_ARM = 0x1c0,
    // ARM64 little endian
    IMAGE_FILE_MACHINE_ARM64 = 0xaa64,
    // ARM Thumb-2 little endian
    IMAGE_FILE_MACHINE_ARMNT = 0x1c4,
    // AXP 64 (Same as Alpha 64)
    IMAGE_FILE_MACHINE_AXP64 = 0x284,
    // EFI byte code
    IMAGE_FILE_MACHINE_EBC = 0xebc,
    // Intel 386 or later processors and compatible processors
    IMAGE_FILE_MACHINE_I386 = 0x14c,
    // Intel Itanium processor family
    IMAGE_FILE_MACHINE_IA64 = 0x200,
    // LoongArch 32-bit processor family
    IMAGE_FILE_MACHINE_LOONGARCH32 = 0x6232,
    // LoongArch 64-bit processor family
    IMAGE_FILE_MACHINE_LOONGARCH64 = 0x6264,
    // Mitsubishi M32R little endian
    IMAGE_FILE_MACHINE_M32R = 0x9041,
    // MIPS16
    IMAGE_FILE_MACHINE_MIPS16 = 0x266,
    // MIPS with FPU
    IMAGE_FILE_MACHINE_MIPSFPU = 0x366,
    // MIPS16 with FPU
    IMAGE_FILE_MACHINE_MIPSFPU16 = 0x466,
    // Power PC little endian
    IMAGE_FILE_MACHINE_POWERPC = 0x1f0,
    // Power PC with floating point support
    IMAGE_FILE_MACHINE_POWERPCFP = 0x1f1,
    // MIPS I compatible 32-bit big endian
    IMAGE_FILE_MACHINE_R3000BE = 0x160,
    // MIPS I compatible 32-bit little endian
    IMAGE_FILE_MACHINE_R3000 = 0x162,
    // MIPS III compatible 64-bit little endian
    IMAGE_FILE_MACHINE_R4000 = 0x166,
    // MIPS IV compatible 64-bit little endian
    IMAGE_FILE_MACHINE_R10000 = 0x168,
    // RISC-V 32-bit address space
    IMAGE_FILE_MACHINE_RISCV32 = 0x5032,
    // RISC-V 64-bit address space
    IMAGE_FILE_MACHINE_RISCV64 = 0x5064,
    // RISC-V 128-bit address space
    IMAGE_FILE_MACHINE_RISCV128 = 0x5128,
    // Hitachi SH3
    IMAGE_FILE_MACHINE_SH3 = 0x1a2,
    // Hitachi SH3 DSP
    IMAGE_FILE_MACHINE_SH3DSP = 0x1a3,
    // Hitachi SH4
    IMAGE_FILE_MACHINE_SH4 = 0x1a6,
    // Hitachi SH5
    IMAGE_FILE_MACHINE_SH5 = 0x1a8,
    // Thumb
    IMAGE_FILE_MACHINE_THUMB = 0x1c2,
    // MIPS little-endian WCE v2
    IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x169,
}

impl TryFrom<i64> for MachineType {
    type Error = PEParsingError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0x0    => Ok(MachineType::IMAGE_FILE_MACHINE_UNKNOWN),
            0x184  => Ok(MachineType::IMAGE_FILE_MACHINE_ALPHA),
            0x1d3  => Ok(MachineType::IMAGE_FILE_MACHINE_AM33),
            0x8664 => Ok(MachineType::IMAGE_FILE_MACHINE_AMD64),
            0x1c0  => Ok(MachineType::IMAGE_FILE_MACHINE_ARM),
            0xaa64 => Ok(MachineType::IMAGE_FILE_MACHINE_ARM64),
            0x1c4  => Ok(MachineType::IMAGE_FILE_MACHINE_ARMNT),
            0x284  => Ok(MachineType::IMAGE_FILE_MACHINE_AXP64),
            0xebc  => Ok(MachineType::IMAGE_FILE_MACHINE_EBC),
            0x14c  => Ok(MachineType::IMAGE_FILE_MACHINE_I386),
            0x200  => Ok(MachineType::IMAGE_FILE_MACHINE_IA64),
            0x6232 => Ok(MachineType::IMAGE_FILE_MACHINE_LOONGARCH32),
            0x6264 => Ok(MachineType::IMAGE_FILE_MACHINE_LOONGARCH64),
            0x9041 => Ok(MachineType::IMAGE_FILE_MACHINE_M32R),
            0x266  => Ok(MachineType::IMAGE_FILE_MACHINE_MIPS16),
            0x366  => Ok(MachineType::IMAGE_FILE_MACHINE_MIPSFPU),
            0x466  => Ok(MachineType::IMAGE_FILE_MACHINE_MIPSFPU16),
            0x1f0  => Ok(MachineType::IMAGE_FILE_MACHINE_POWERPC),
            0x1f1  => Ok(MachineType::IMAGE_FILE_MACHINE_POWERPCFP),
            0x160  => Ok(MachineType::IMAGE_FILE_MACHINE_R3000BE),
            0x162  => Ok(MachineType::IMAGE_FILE_MACHINE_R3000),
            0x166  => Ok(MachineType::IMAGE_FILE_MACHINE_R4000),
            0x168  => Ok(MachineType::IMAGE_FILE_MACHINE_R10000),
            0x5032 => Ok(MachineType::IMAGE_FILE_MACHINE_RISCV32),
            0x5064 => Ok(MachineType::IMAGE_FILE_MACHINE_RISCV64),
            0x5128 => Ok(MachineType::IMAGE_FILE_MACHINE_RISCV128),
            0x1a2  => Ok(MachineType::IMAGE_FILE_MACHINE_SH3),
            0x1a3  => Ok(MachineType::IMAGE_FILE_MACHINE_SH3DSP),
            0x1a6  => Ok(MachineType::IMAGE_FILE_MACHINE_SH4),
            0x1a8  => Ok(MachineType::IMAGE_FILE_MACHINE_SH5),
            0x1c2  => Ok(MachineType::IMAGE_FILE_MACHINE_THUMB),
            0x169  => Ok(MachineType::IMAGE_FILE_MACHINE_WCEMIPSV2),
            _ => Err(PEParsingError::UnrecognizedMachineType),
        }
    }
}


#[derive(Debug)]
pub struct CommonObjectFileHeader {
    // The number that identifies the type of target machine
    machine: MachineType,
    // The number of sections. This indicates the size of the section table, which immediately follows the headers.
    num_sections: u16,
    // The low 32 bits of the number of seconds since 00:00 January 1, 1970 (a C run-time time_t value), which indicates when the file was created.
    timestamp: u32,
    // The file offset of the COFF symbol table, or zero if no COFF symbol table is present. This value should be zero for an image because COFF debugging information is deprecated
    symbol_table_offset: u32,
    // The number of entries in the symbol table. This data can be used to locate the string table, which immediately follows the symbol table. This value should be zero for an image because COFF debugging information is deprecated.
    symbol_table_count: u32,
    // The size of the optional header, which is required for executable files but not for object files. This value should be zero for an object file. For a description of the header format
    optional_header_length: u16,
    // The flags that indicate the attributes of the file
    characteristics: Vec<Characteristics>,
}

#[derive(Debug)]
pub struct OptionalHeaderStandardFields {
    // The unsigned integer that identifies the state of the image file. The most common number is 0x10B, which identifies it as a normal executable file. 0x107 identifies it as a ROM image, and 0x20B identifies it as a PE32+ executable
    pub pe_type: PEType,

    // The linker major version number
    pub linker_version_major: u8,
    
    // The linker minor version number.
    pub linker_version_minor: u8,
    
    // The size of the code (text) section, or the sum of all code sections if there are multiple sections
    pub code_length: u32,
    
    // The size of the initialized data section, or the sum of all such sections if there are multiple data sections
    pub init_data_length: u32,
    
    // The size of the uninitialized data section (BSS), or the sum of all such sections if there are multiple BSS sections
    pub uninit_data_length: u32,

    // The address of the entry point relative to the image base when the executable file is loaded into memory. For program images, this is the starting address. For device drivers, this is the address of the initialization function. An entry point is optional for DLLs. When no entry point is present, this field must be zero.
    pub entry_point_offset: u32,
    
    // The address that is relative to the image base of the beginning-of-code section when it is loaded into memory.
    pub base_of_code_offset: u32,

    // only in PE32, not PE32+
    // The address that is relative to the image base of the beginning-of-data section when it is loaded into memory
    pub base_of_data_offset: Option<u32>,
}

#[derive(Debug)]
pub struct SectionHeader {
    // An 8-byte, null-padded UTF-8 encoded string. If the string is exactly 8 characters long, there is no terminating null
    pub name: String,
    // The total size of the section when loaded into memory. If this value is greater than SizeOfRawData, the section is zero-padded. This field is valid only for executable images and should be set to zero for object files
    pub length: u32,
    // For executable images, the address of the first byte of the section relative to the image base when the section is loaded into memory. For object files, this field is the address of the first byte before relocation is applied
    pub offset: u32,
    // The size of the section (for object files) or the size of the initialized data on disk (for image files)
    pub data_length: u32,
    // The file pointer to the first page of the section within the COFF file. For executable images, this must be a multiple of FileAlignment from the optional header. For object files, the value should be aligned on a 4-byte boundary for best performance. When a section contains only uninitialized data, this field should be zero
    pub data_offset: u32,
    // The file pointer to the beginning of relocation entries for the section. This is set to zero for executable images or if there are no relocations
    pub reloc_offset: u32,
    // The file pointer to the beginning of line-number entries for the section. This is set to zero if there are no COFF line numbers. This value should be zero for an image because COFF debugging information is deprecated.
    pub line_numbers_offset: u32,
    // The number of relocation entries for the section. This is set to zero for executable images
    pub reloc_count: u16,
    // The number of line-number entries for the section. This value should be zero for an image because COFF debugging information is deprecated.
    pub line_numbers_count: u16,
    // The flags that describe the characteristics of the section
    pub characteristics: Vec<SectionCharacteristics>,
}

#[derive(Debug)]
pub enum SectionCharacteristics {
    // // Reserved for future use.
    // RESERVED_1 = 0x00000000,
    // // Reserved for future use.
    // RESERVED_2 = 0x00000001,
    // // Reserved for future use.
    // RESERVED_3 = 0x00000002,
    // // Reserved for future use.
    // RESERVED_4 = 0x00000004,
    // The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files.
    SCN_TYPE_NO_PAD = 0x00000008,
    // Reserved for future use.
    // RESERVED_5 = 0x00000010,
    // The section contains executable code.
    CNT_CODE = 0x00000020,
    // The section contains initialized data.
    GE_SCN_CNT_INITIALIZED_DATA = 0x00000040,
    // The section contains uninitialized data.
    IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080,
    // Reserved for future use.
    IMAGE_SCN_LNK_OTHER = 0x00000100,
    // The section contains comments or other information. The .drectve section has this type. This is valid for object files only.
    IMAGE_SCN_LNK_INFO = 0x00000200,
    // Reserved for future use.
    // RESERVED_6 = 0x00000400,
    // The section will not become part of the image. This is valid only for object files.
    IMAGE_SCN_LNK_REMOVE = 0x00000800,
    // The section contains COMDAT data. For more information, see COMDAT Sections (Object Only). This is valid only for object files.
    IMAGE_SCN_LNK_COMDAT = 0x00001000,
    // The section contains data referenced through the global pointer (GP).
    IMAGE_SCN_GPREL = 0x00008000,
    // Reserved for future use.
    // IMAGE_SCN_MEM_PURGEABLE = 0x00020000,
    // Reserved for future use.
    // IMAGE_SCN_MEM_16BIT = 0x00020000,
    // Reserved for future use.
    IMAGE_SCN_MEM_LOCKED = 0x00040000,
    // Reserved for future use.
    IMAGE_SCN_MEM_PRELOAD = 0x00080000,
    // Align data on a 1-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_1BYTES = 0x00100000,
    // Align data on a 2-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_2BYTES = 0x00200000,
    // Align data on a 4-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_4BYTES = 0x00300000,
    // Align data on an 8-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_8BYTES = 0x00400000,
    // Align data on a 16-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_16BYTES = 0x00500000,
    // Align data on a 32-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_32BYTES = 0x00600000,
    // Align data on a 64-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_64BYTES = 0x00700000,
    // Align data on a 128-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_128BYTES = 0x00800000,
    // Align data on a 256-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_256BYTES = 0x00900000,
    // Align data on a 512-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_512BYTES = 0x00A00000,
    // Align data on a 1024-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000,
    // Align data on a 2048-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000,
    // Align data on a 4096-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000,
    // Align data on an 8192-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000,
    // The section contains extended relocations.
    IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000,
    // The section can be discarded as needed.
    IMAGE_SCN_MEM_DISCARDABLE = 0x02000000,
    // The section cannot be cached.
    IMAGE_SCN_MEM_NOT_CACHED = 0x04000000,
    // The section is not pageable.
    IMAGE_SCN_MEM_NOT_PAGED = 0x08000000,
    // The section can be shared in memory.
    IMAGE_SCN_MEM_SHARED = 0x10000000,
    // The section can be executed as code.
    IMAGE_SCN_MEM_EXECUTE = 0x20000000,
    // The section can be read.
    IMAGE_SCN_MEM_READ = 0x40000000,
    // The section can be written to.
    IMAGE_SCN_MEM_WRITE = 0x80000000,
}

fn parse_section_characteristic(value: u32) -> Vec<SectionCharacteristics> {
    let mut to_ret = Vec::new();

    if value & 0x00000008 > 0 { 
        to_ret.push(SectionCharacteristics::SCN_TYPE_NO_PAD);
    }
    if value & 0x00000020 > 0 { 
        to_ret.push(SectionCharacteristics::CNT_CODE);
    }
    if value & 0x00000040 > 0 { 
        to_ret.push(SectionCharacteristics::GE_SCN_CNT_INITIALIZED_DATA);
    }
    if value & 0x00000080 > 0 { 
        to_ret.push(SectionCharacteristics::IMAGE_SCN_CNT_UNINITIALIZED_DATA);
    }
    if value & 0x00000100 > 0 { 
        to_ret.push(SectionCharacteristics::IMAGE_SCN_LNK_OTHER);
    }
    if value & 0x00000200 > 0 { 
        to_ret.push(SectionCharacteristics::IMAGE_SCN_LNK_INFO);
    }
    if value & 0x00000800 > 0 { 
        to_ret.push(SectionCharacteristics::IMAGE_SCN_LNK_REMOVE);
    }
    if value & 0x00001000 > 0 { 
        to_ret.push(SectionCharacteristics::IMAGE_SCN_LNK_COMDAT);
    }
    if value & 0x00008000 > 0 { 
        to_ret.push(SectionCharacteristics::IMAGE_SCN_GPREL);
    }
    if value & 0x00040000 > 0 { 
        to_ret.push(SectionCharacteristics::IMAGE_SCN_MEM_LOCKED);
    }
    if value & 0x00080000 > 0 { 
        to_ret.push(SectionCharacteristics::IMAGE_SCN_MEM_PRELOAD);
    }
    if value & 0x00100000 > 0 { 
        to_ret.push(SectionCharacteristics::IMAGE_SCN_ALIGN_1BYTES);
    }
    if value & 0x00200000 > 0 { 
        to_ret.push(SectionCharacteristics::IMAGE_SCN_ALIGN_2BYTES);
    }
    if value & 0x00300000 > 0 { 
        to_ret.push(SectionCharacteristics::IMAGE_SCN_ALIGN_4BYTES);
    }
    if value & 0x00400000 > 0 { 
        to_ret.push(SectionCharacteristics::IMAGE_SCN_ALIGN_8BYTES);
    }
    if value & 0x00500000 > 0 { 
        to_ret.push(SectionCharacteristics::IMAGE_SCN_ALIGN_16BYTES);
    }
    if value & 0x00600000 > 0 { 
        to_ret.push(SectionCharacteristics::IMAGE_SCN_ALIGN_32BYTES);
    }
    if value & 0x00700000 > 0 { 
        to_ret.push(SectionCharacteristics::IMAGE_SCN_ALIGN_64BYTES);
    }
    if value & 0x00800000 > 0 { 
        to_ret.push(SectionCharacteristics::IMAGE_SCN_ALIGN_128BYTES);
    }
    if value & 0x00900000 > 0 { 
        to_ret.push(SectionCharacteristics::IMAGE_SCN_ALIGN_256BYTES);
    }
    if value & 0x00A00000 > 0 { 
        to_ret.push(SectionCharacteristics::IMAGE_SCN_ALIGN_512BYTES);
    }
    if value & 0x00B00000 > 0 { 
        to_ret.push(SectionCharacteristics::IMAGE_SCN_ALIGN_1024BYTES);
    }
    if value & 0x00C00000 > 0 { 
        to_ret.push(SectionCharacteristics::IMAGE_SCN_ALIGN_2048BYTES);
    }
    if value & 0x00D00000 > 0 { 
        to_ret.push(SectionCharacteristics::IMAGE_SCN_ALIGN_4096BYTES);
    }
    if value & 0x00E00000 > 0 { 
        to_ret.push(SectionCharacteristics::IMAGE_SCN_ALIGN_8192BYTES);
    }
    if value & 0x01000000 > 0 { 
        to_ret.push(SectionCharacteristics::IMAGE_SCN_LNK_NRELOC_OVFL);
    }
    if value & 0x02000000 > 0 { 
        to_ret.push(SectionCharacteristics::IMAGE_SCN_MEM_DISCARDABLE);
    }
    if value & 0x04000000 > 0 { 
        to_ret.push(SectionCharacteristics::IMAGE_SCN_MEM_NOT_CACHED);
    }
    if value & 0x08000000 > 0 { 
        to_ret.push(SectionCharacteristics::IMAGE_SCN_MEM_NOT_PAGED);
    }
    if value & 0x10000000 > 0 { 
        to_ret.push(SectionCharacteristics::IMAGE_SCN_MEM_SHARED);
    }
    if value & 0x20000000 > 0 { 
        to_ret.push(SectionCharacteristics::IMAGE_SCN_MEM_EXECUTE);
    }
    if value & 0x40000000 > 0 { 
        to_ret.push(SectionCharacteristics::IMAGE_SCN_MEM_READ);
    }
    if value & 0x80000000 > 0 { 
        to_ret.push(SectionCharacteristics::IMAGE_SCN_MEM_WRITE);
    }

    to_ret
}

#[derive(Debug)]
pub enum DLLCharacteristics {
    HIGH_ENTROPY_VA,
    DYNAMIC_BASE,
    FORCE_INTEGRITY,
    NX_COMPAT,
    NO_ISOLATION,
    NO_SEH,
    NO_BIND,
    APPCONTAINER,
    WDM_DRIVER,
    GUARD_CF,
    TERMINAL_SERVER_AWARE,
}

fn parse_dll_characteristics(value: u16) -> Vec<DLLCharacteristics> {
    let mut to_ret = Vec::new();

    if value & 0x0020 > 0 {
        to_ret.push(DLLCharacteristics::HIGH_ENTROPY_VA);
    }
    if value & 0x0040 > 0 {
        to_ret.push(DLLCharacteristics::DYNAMIC_BASE);
    } 
    if value & 0x0000 > 0 {
        to_ret.push(DLLCharacteristics::FORCE_INTEGRITY);
    }
    if value & 0x0000 > 0 {
        to_ret.push(DLLCharacteristics::NX_COMPAT);
    }
    if value & 0x0000 > 0 {
        to_ret.push(DLLCharacteristics::NO_ISOLATION);
    }
    if value & 0x0000 > 0 {
        to_ret.push(DLLCharacteristics::NO_SEH);
    }
    if value & 0x0000 > 0 {
        to_ret.push(DLLCharacteristics::NO_BIND);
    }
    if value & 0x0000 > 0 {
        to_ret.push(DLLCharacteristics::APPCONTAINER);
    }
    if value & 0x0000 > 0 {
        to_ret.push(DLLCharacteristics::WDM_DRIVER);
    }
    if value & 0x0000 > 0 {
        to_ret.push(DLLCharacteristics::GUARD_CF);
    }
    if value & 0x0000 > 0 {
        to_ret.push(DLLCharacteristics::TERMINAL_SERVER_AWARE);
    }

    to_ret
}

#[derive(Debug)]
pub struct WindowsFields {
    // Size: (PE32/PE32+) 4/8
    // The preferred address of the first byte of image when loaded into memory; must be a multiple of 64 K. The default for DLLs is 0x10000000. The default for Windows CE EXEs is 0x00010000. The default for Windows NT, Windows 2000, Windows XP, Windows 95, Windows 98, and Windows Me is 0x00400000.
    image_base: u64,

    // The alignment (in bytes) of sections when they are loaded into memory. It must be greater than or equal to FileAlignment. The default is the page size for the architecture.
    section_alignment: u32,
    
    // The alignment factor (in bytes) that is used to align the raw data of sections in the image file. The value should be a power of 2 between 512 and 64 K, inclusive. The default is 512. If the SectionAlignment is less than the architecture's page size, then FileAlignment must match SectionAlignment.
    file_alignment: u32,

    // The major version number of the required operating system.
    os_major_version: u16,

    // The major version number of the required operating system.
    os_minor_version: u16,

    // The major version number of the image.
    image_major_version: u16,

    // The minor version number of the image.
    image_minor_version: u16,

    // The major version number of the subsystem.
    subsystem_major_version: u16,

    // The minor version number of the subsystem.
    subsystem_minor_version: u16,

    // Reserved, must be zero.
    win32_version_value: u32,

    // The size (in bytes) of the image, including all headers, as the image is loaded in memory. It must be a multiple of SectionAlignment.
    size_of_image: u32,

    // The combined size of an MS-DOS stub, PE header, and section headers rounded up to a multiple of FileAlignment.
    size_of_headers: u32,

    // The image file checksum. The algorithm for computing the checksum is incorporated into IMAGHELP.DLL. The following are checked for validation at load time: all drivers, any DLL loaded at boot time, and any DLL that is loaded into a critical Windows process.
    checksum: u32,

    // The subsystem that is required to run this image.
    subsystem: u16,

    dll_characteristics: Vec<DLLCharacteristics>,

    // Size: (PE32/PE32+) 4/8
    // The size of the stack to reserve. Only SizeOfStackCommit is committed; the rest is made available one page at a time until the reserve size is reached.
    stack_reserve_size: u64,

    // Size: (PE32/PE32+) 4/8
    // The size of the stack to commit
    stack_commit_size: u64,

    // Size: (PE32/PE32+) 4/8
    // The size of the local heap space to reserve. Only SizeOfHeapCommit is committed; the rest is made available one page at a time until the reserve size is reached.
    heap_researve_size: u64,

    // Size: (PE32/PE32+) 4/8
    // The size of the local heap space to commit
    heap_researve_commit: u64,

    // Reserved, must be 0
    loader_flags: u32,

    // The number of data-directory entries in the remainder of the optional header. Each describes a location and size.
    rva_and_sizes: u32,
}

#[derive(Debug)]
pub struct DataDirectories {
    export_table_offset: u32,
    export_table_length: u32,

    import_table_offset: u32,
    import_table_length: u32,

    resource_table_offset: u32,
    resource_table_length: u32,

    exception_table_offset: u32,
    exception_table_length: u32,

    certificate_table_offset: u32,
    certificate_table_length: u32,

    base_reloc_table_offset: u32,
    base_reloc_table_length: u32,

    debug_table_offset: u32,
    debug_table_length: u32,

    arch: u64,

    global_ptr_table_offset: u32,
    global_ptr_table_length: u32,

    tls_table_offset: u32,
    tls_table_length: u32,

    load_config_table_offset: u32,
    load_config_table_length: u32,

    bound_import_table_offset: u32,
    bound_import_table_length: u32,

    iat_table_offset: u32,
    iat_table_length: u32,

    delay_import_offset: u32,
    delay_import_length: u32,

    clr_import_offset: u32,
    clr_import_length: u32,

    reserved: u64,
}

pub struct WindowsEXE {
    pub optional_header: OptionalHeaderStandardFields,
    pub win_fields: WindowsFields,
    pub data_directories: DataDirectories,
    pub section_headers: HashMap<String, SectionHeader>,
}

pub fn parse_windows_exe(path: PathBuf) -> Result<(WindowsEXE, MyReader), PEParsingError>
{
    let mut reader = MyReader {
        buff: fs::read(path.to_path_buf())?.into_boxed_slice(),
        cursor: 0,
    };

    let exe_header_offset = { 
        reader.seek(0x3c)?;
        let bytes = reader.take_bytes(2)?;
        bytes_to_int(bytes)
    };

    println!("{:x}", exe_header_offset);

    reader.seek(exe_header_offset as usize)?;

    let pe_header_magic = {
        let bytes = reader.take_bytes(4)?;
        bytes_to_int(bytes)
    };

    println!("{:x}", pe_header_magic);

    let coff = CommonObjectFileHeader {
        machine: MachineType::try_from(bytes_to_int(reader.take_bytes(2)?))?,
        num_sections: bytes_to_int(reader.take_bytes(2)?) as u16,
        timestamp: bytes_to_int(reader.take_bytes(4)?) as u32,
        symbol_table_offset: bytes_to_int(reader.take_bytes(4)?) as u32,
        symbol_table_count: bytes_to_int(reader.take_bytes(4)?) as u32,
        optional_header_length: bytes_to_int(reader.take_bytes(2)?) as u16,
        characteristics: parse_characteristics(bytes_to_int(reader.take_bytes(2)?) as u16),
    };

    println!("{:#x?}", coff);

    let opt_header_magic = {
        let bytes = reader.take_bytes(2)?;
        let magic = bytes_to_int(bytes);
        match magic {
            0x10b => PEType::PE32,
            0x20b => PEType::PE32P,
            _ => return Err(PEParsingError::UnrecognizedPEType),
        }
    };

    let opt_header = {
        OptionalHeaderStandardFields {
            pe_type: opt_header_magic.clone(),
            linker_version_major: reader.take_byte()?,
            linker_version_minor: reader.take_byte()?,
            code_length: bytes_to_int(reader.take_bytes(4)?) as u32,
            init_data_length: bytes_to_int(reader.take_bytes(4)?) as u32,
            uninit_data_length: bytes_to_int(reader.take_bytes(4)?) as u32,
            entry_point_offset: bytes_to_int(reader.take_bytes(4)?) as u32,
            base_of_code_offset: bytes_to_int(reader.take_bytes(4)?) as u32,
            base_of_data_offset: match opt_header_magic {
                PEType::PE32 => Some(bytes_to_int(reader.take_bytes(4)?) as u32),
                _ => None,
            },
        }
    };

    let win_fields = {
        WindowsFields {
            image_base: match opt_header_magic {
                PEType::PE32  => bytes_to_int(reader.take_bytes(4)?) as u64,
                PEType::PE32P => bytes_to_int(reader.take_bytes(8)?) as u64,
            },

            section_alignment: bytes_to_int(reader.take_bytes(4)?) as u32,
            file_alignment: bytes_to_int(reader.take_bytes(4)?) as u32,
            os_major_version: bytes_to_int(reader.take_bytes(2)?) as u16,
            os_minor_version: bytes_to_int(reader.take_bytes(2)?) as u16,
            image_major_version: bytes_to_int(reader.take_bytes(2)?) as u16,
            image_minor_version: bytes_to_int(reader.take_bytes(2)?) as u16,
            subsystem_major_version: bytes_to_int(reader.take_bytes(2)?) as u16,
            subsystem_minor_version: bytes_to_int(reader.take_bytes(2)?) as u16,
            win32_version_value: bytes_to_int(reader.take_bytes(4)?) as u32,
            size_of_image: bytes_to_int(reader.take_bytes(4)?) as u32,
            size_of_headers: bytes_to_int(reader.take_bytes(4)?) as u32,
            checksum: bytes_to_int(reader.take_bytes(4)?) as u32,
            subsystem: bytes_to_int(reader.take_bytes(2)?) as u16,
            dll_characteristics: parse_dll_characteristics(bytes_to_int(reader.take_bytes(2)?) as u16),
            stack_reserve_size: match opt_header_magic {
                PEType::PE32  => bytes_to_int(reader.take_bytes(4)?) as u64,
                PEType::PE32P => bytes_to_int(reader.take_bytes(8)?) as u64,
            },
            stack_commit_size: match opt_header_magic {
                PEType::PE32  => bytes_to_int(reader.take_bytes(4)?) as u64,
                PEType::PE32P => bytes_to_int(reader.take_bytes(8)?) as u64,
            },
            heap_researve_size: match opt_header_magic {
                PEType::PE32  => bytes_to_int(reader.take_bytes(4)?) as u64,
                PEType::PE32P => bytes_to_int(reader.take_bytes(8)?) as u64,
            },
            heap_researve_commit: match opt_header_magic {
                PEType::PE32  => bytes_to_int(reader.take_bytes(4)?) as u64,
                PEType::PE32P => bytes_to_int(reader.take_bytes(8)?) as u64,
            },
            loader_flags: bytes_to_int(reader.take_bytes(4)?) as u32,
            rva_and_sizes: bytes_to_int(reader.take_bytes(4)?) as u32,
        }
    };

    let data_directories = {
        DataDirectories {
            export_table_offset: bytes_to_int(reader.take_bytes(4)?) as u32,
            export_table_length: bytes_to_int(reader.take_bytes(4)?) as u32,

            import_table_offset: bytes_to_int(reader.take_bytes(4)?) as u32,
            import_table_length: bytes_to_int(reader.take_bytes(4)?) as u32,

            resource_table_offset: bytes_to_int(reader.take_bytes(4)?) as u32,
            resource_table_length: bytes_to_int(reader.take_bytes(4)?) as u32,

            exception_table_offset: bytes_to_int(reader.take_bytes(4)?) as u32,
            exception_table_length: bytes_to_int(reader.take_bytes(4)?) as u32,

            certificate_table_offset: bytes_to_int(reader.take_bytes(4)?) as u32,
            certificate_table_length: bytes_to_int(reader.take_bytes(4)?) as u32,

            base_reloc_table_offset: bytes_to_int(reader.take_bytes(4)?) as u32,
            base_reloc_table_length: bytes_to_int(reader.take_bytes(4)?) as u32,

            debug_table_offset: bytes_to_int(reader.take_bytes(4)?) as u32,
            debug_table_length: bytes_to_int(reader.take_bytes(4)?) as u32,

            arch: bytes_to_int(reader.take_bytes(8)?) as u64,

            global_ptr_table_offset: bytes_to_int(reader.take_bytes(4)?) as u32,
            global_ptr_table_length: bytes_to_int(reader.take_bytes(4)?) as u32,

            tls_table_offset: bytes_to_int(reader.take_bytes(4)?) as u32,
            tls_table_length: bytes_to_int(reader.take_bytes(4)?) as u32,

            load_config_table_offset: bytes_to_int(reader.take_bytes(4)?) as u32,
            load_config_table_length: bytes_to_int(reader.take_bytes(4)?) as u32,

            bound_import_table_offset: bytes_to_int(reader.take_bytes(4)?) as u32,
            bound_import_table_length: bytes_to_int(reader.take_bytes(4)?) as u32,

            iat_table_offset: bytes_to_int(reader.take_bytes(4)?) as u32,
            iat_table_length: bytes_to_int(reader.take_bytes(4)?) as u32,

            delay_import_offset: bytes_to_int(reader.take_bytes(4)?) as u32,
            delay_import_length: bytes_to_int(reader.take_bytes(4)?) as u32,

            clr_import_offset: bytes_to_int(reader.take_bytes(4)?) as u32,
            clr_import_length: bytes_to_int(reader.take_bytes(4)?) as u32,

            reserved: bytes_to_int(reader.take_bytes(8)?) as u64,
        }
    };

    let section_headers = {
        let mut section_headers = HashMap::new();
        for _ in 0..coff.num_sections {
            let name = std::str::from_utf8(reader.take_bytes(8)?)?.trim_end_matches('\0').to_string();
            section_headers.insert(name.clone(), SectionHeader {
                name,
                length: bytes_to_int(reader.take_bytes(4)?) as u32,
                offset: bytes_to_int(reader.take_bytes(4)?) as u32,
                data_length: bytes_to_int(reader.take_bytes(4)?) as u32,
                data_offset: bytes_to_int(reader.take_bytes(4)?) as u32,
                reloc_offset: bytes_to_int(reader.take_bytes(4)?) as u32,
                line_numbers_offset: bytes_to_int(reader.take_bytes(4)?) as u32,
                reloc_count: bytes_to_int(reader.take_bytes(2)?) as u16,
                line_numbers_count: bytes_to_int(reader.take_bytes(2)?) as u16,
                characteristics: parse_section_characteristic(bytes_to_int(reader.take_bytes(4)?) as u32)
            });
        }

        section_headers
    };

    println!("{:#x?}", opt_header);
    println!("{:#x?}", win_fields);
    println!("{:#x?}", data_directories);
    println!("{:#x?}", section_headers);

    Ok((WindowsEXE {
        optional_header: opt_header,
        win_fields,
        data_directories,
        section_headers,
    }, reader))
}