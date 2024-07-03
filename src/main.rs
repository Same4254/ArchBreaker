//  Prefix::LOCK          => 0xF0,
//  Prefix::REPNE         => 0xF2,
//  Prefix::REPE          => 0xF3,
//  Prefix::BND           => 0xF2,
//
//  Prefix::CS_SEG        => 0x2E,
//  Prefix::SS_SEG        => 0x36,
//  Prefix::DS_SEG        => 0x3E,
//  Prefix::ES_SEG        => 0x26,
//  Prefix::FS_SEG        => 0x64,
//  Prefix::GS_SEG        => 0x65,
//
//  Prefix::BR_TAKEN      => 0x2E,
//  Prefix::BR_NOT_TAKEN  => 0x3E,
//
//  Prefix::OP_SIZE       => 0x66,
//  Prefix::AD_SIZE       => 0x67

use std::{cmp, fs::File, io::Read};

mod registers;
use registers::*;

mod one_byte_opcode;
use one_byte_opcode::*;

use std::io::{BufReader, Cursor};

const PREFIX_VALS: &[u8] = &[ 0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26 ,0x64, 0x65, 0x66, 0x67 ];

fn is_prefix_byte (byte: u8) -> bool 
{
    for val in PREFIX_VALS
    {
        if *val == byte
        {
            return true;
        }
    }

    return false;
}

const REX_LOWER: u8 = 0x40;
const REX_UPPER: u8 = 0x4F;

#[derive(Debug)]
struct Rex_Prefix
{
    w: bool,
    r: bool,
    x: bool,
    b: bool,
}

fn parse_rex_prefix (byte: u8) -> Option<Rex_Prefix> 
{
    if REX_LOWER <= byte && byte <= REX_UPPER
    {
        return Some(Rex_Prefix { 
            w: ((1 << 3) & byte) > 0,
            r: ((1 << 2) & byte) > 0,
            x: ((1 << 1) & byte) > 0,
            b: ((1 << 0) & byte) > 0,
        });
    }

    return None;
}

enum Prefix_Group1
{
    LOCK_F0,
    REPNZ_BND_F2,
    REPZ_F3,
}

enum Prefix_Group2
{
    CS_2E,
    SS_36,
    DS_3E,
    ES_26,
    FS_64,
    GS_65,

    BR_NOT_TAKEN_2E,
    BR_TAKEN_3E,
}

enum Prefix_Group3
{
    Operand_Override_66,
}

enum Prefix_Group4
{
    Address_Override_67,
}

enum Prefix
{
    Prefix_Group1(Prefix_Group1),
    Prefix_Group2(Prefix_Group2),
    Prefix_Group3(Prefix_Group3),
    Prefix_Group4(Prefix_Group4),
}

enum Prefix_Addition_Result
{
    NOT_A_PREFIX,
    GROUP_USED,
}

struct Prefix_Acc
{
    group1: Option<Prefix_Group1>,
    group2: Option<Prefix_Group2>,
    group3: Option<Prefix_Group3>,
    group4: Option<Prefix_Group4>,
}

impl Prefix_Acc
{
    fn add_prefix (&mut self, byte: u8) -> Result<(), Prefix_Addition_Result>
    {
        if !PREFIX_VALS.contains(&byte)
        {
            return Err(Prefix_Addition_Result::NOT_A_PREFIX);
        }

        match (byte, &mut *self)
        {
            (0xf0, Prefix_Acc{group1: None, group2: _,    group3: _,    group4: _})    => self.group1 = Some(Prefix_Group1::LOCK_F0),
            (0xf2, Prefix_Acc{group1: None, group2: _,    group3: _,    group4: _})    => self.group1 = Some(Prefix_Group1::REPNZ_BND_F2),
            (0xf3, Prefix_Acc{group1: None, group2: _,    group3: _,    group4: _})    => self.group1 = Some(Prefix_Group1::REPZ_F3),

            (0x2e, Prefix_Acc{group1: _,    group2: None, group3: _,    group4: _})    => self.group2 = Some(Prefix_Group2::CS_2E),
            (0x36, Prefix_Acc{group1: _,    group2: None, group3: _,    group4: _})    => self.group2 = Some(Prefix_Group2::SS_36),
            (0x3e, Prefix_Acc{group1: _,    group2: None, group3: _,    group4: _})    => self.group2 = Some(Prefix_Group2::DS_3E),
            (0x26, Prefix_Acc{group1: _,    group2: None, group3: _,    group4: _})    => self.group2 = Some(Prefix_Group2::ES_26),
            (0x64, Prefix_Acc{group1: _,    group2: None, group3: _,    group4: _})    => self.group2 = Some(Prefix_Group2::FS_64),
            (0x65, Prefix_Acc{group1: _,    group2: None, group3: _,    group4: _})    => self.group2 = Some(Prefix_Group2::GS_65),
            (0x2e, Prefix_Acc{group1: _,    group2: None, group3: _,    group4: _})    => self.group2 = Some(Prefix_Group2::BR_NOT_TAKEN_2E),
            (0x3e, Prefix_Acc{group1: _,    group2: None, group3: _,    group4: _})    => self.group2 = Some(Prefix_Group2::BR_TAKEN_3E),

            (0x66, Prefix_Acc{group1: _,    group2: _,    group3: None, group4: _})    => self.group3 = Some(Prefix_Group3::Operand_Override_66),
            (0x67, Prefix_Acc{group1: _,    group2: _,    group3: _,    group4: None}) => self.group4 = Some(Prefix_Group4::Address_Override_67),
            _ => return Err(Prefix_Addition_Result::GROUP_USED) 
        }
        
        Ok(())
    }

}

struct ModRMByte
{
    md: u8,
    rm : u8,
    reg_op: u8
}

impl ModRMByte
{
    pub fn new(byte: u8) -> ModRMByte
    {
        ModRMByte {
            md     : (0b11000000 & byte) >> 6,
            rm     : (0b00000111 & byte) >> 0,
            reg_op : (0b00111000 & byte) >> 3,
        }
    }
}

#[derive(Debug, Copy, Clone)]
struct Dref
{
    base: Option<Register>,
    index: Option<Register>,
    scale: u64,
    disp: i64,
    res_size: Register_Size,
}

#[derive(Debug, Copy, Clone)]
enum Instruction_Operand
{
    REGISTER(Register),
    IMM(i64),
    DREF(Dref), 
}

#[derive(Debug, Copy, Clone)]
struct Instruction
{
    name: Instruction_Name,
    operands: [Option<Instruction_Operand>; 4]
}

struct MyReader<'a, R: Read, const Capacity: usize>
{
    buff: [u8; Capacity],
    length: usize,
    cursor: usize,

    source: &'a mut R,
}

impl <'a, R: Read, const Len: usize> MyReader<'a, R, Len>
{
    fn new(read: &'a mut R) -> MyReader<'a, R, Len>
    {
        let mut reader = MyReader {
            buff: [0; Len],
            length: 0,
            cursor: 0,
            source: read,
        };

        // attempt to fill the buffer
        reader.refill();

        return reader;
    }

    fn has_next_byte(&self) -> bool
    {
        return self.length > 0 && self.cursor < self.length;
    }

    fn refill(&mut self) -> std::io::Result<usize>
    {
        // shift the elements to the start
        for i in self.cursor..self.length
        {
            self.buff[i - self.cursor] = self.buff[i];
        }

        match self.source.read(&mut self.buff[(self.length - self.cursor)..])
        {
            Ok(num_bytes) => {
                self.length = (self.length - self.cursor) + num_bytes;
                self.cursor = 0;
                Ok(num_bytes)
            },

            Err(E) => Err(E)
        }
    }

    fn peek_byte(&mut self) -> std::io::Result<u8>
    {
        if self.cursor >= self.length
        {
            self.cursor = self.length;
            match self.refill()
            {
                Err (E) => return Err(E),
                _ => ()
            }
        }

        match self.cursor < self.length
        {
            true  => Ok(self.buff[self.cursor]),
            false => Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
        }
    }

    fn take_byte(&mut self) -> std::io::Result<u8>
    {
        match self.peek_byte()
        {
            Ok (v) => {
                self.cursor += 1;
                if self.cursor >= self.length
                {
                    // Ok for this to fail, we have the byte we wanted
                    self.refill();
                }

                Ok (v)
            }

            Err(E) => Err(E)
        }
    }

    fn take_bytes<const num: usize>(&mut self) -> std::io::Result<[u8; num]>
    {
        let mut bytes = [0u8; num];

        for i in 0..num
        {
            match self.take_byte()
            {
                Ok (v) => bytes[i] = v,
                Err(E) => return Err(E)
            }
        }

        return Ok(bytes);
    }
}

fn bytes_to_int (bytes: &[u8]) -> i64
{
    let mut ret: u64 = 0;
    for i in bytes.iter().rev()
    {
        ret <<= 8;
        ret |= *i as u64;
    }

    return ret as i64;
}

fn parse_sib_byte<A, const B: usize>(reader: &mut MyReader::<A, B>, modrm: &ModRMByte, add_size: Register_Size, op_size: Register_Size, rex: &Option<Rex_Prefix>) -> std::io::Result<Instruction_Operand>
where A: std::io::Read
{
    let sib: u8 = reader.take_byte()?;
    let scale: u8 = u8::pow(2, ((sib & 0b11000000) >> 6) as u32);
    let index: u8 =             (sib & 0b00111000) >> 3;
    let base : u8 =             (sib & 0b00000111) >> 0;

    let index_reg = match index
    {
        0b100 => None,
        _     => search_register(index, Register_Type::GP, add_size, match rex.as_ref() {
                 Some (r) => Some(r.x),
                 _ => None
        })
    };

    let base_reg = match base
    {
        0b101 => match modrm.md
        {
            0b01 | 0b10 => match add_size
            {
                Register_Size::_64 => Some(RBP),
                Register_Size::_32 => Some(EBP),
                _ => panic!("idk"),
            }
            
            _ => None
        }

        _ => search_register(base, Register_Type::GP, add_size, match rex {
            Some(r) => Some(r.b),
            _ => None
        })
    };

    let disp = match (modrm.md, base)
    {
        (0b01, _)     => bytes_to_int(&reader.take_bytes::<1>()?),
        (0b10, _)     => bytes_to_int(&reader.take_bytes::<4>()?),
        (0b00, 0b101) => bytes_to_int(&reader.take_bytes::<4>()?),
        _             => 0
    };

    return Ok(Instruction_Operand::DREF(Dref {
        base: base_reg,
        index: index_reg,
        scale: match index_reg {
            None => 0,
            _ => scale as u64,
        },

        disp,
        res_size: op_size,
    }));
}

fn lookup_32_effective_address<A, const B: usize>(reader: &mut MyReader::<A, B>, modrm: &ModRMByte, add_size: Register_Size, op_size: Register_Size, rex: &Option<Rex_Prefix>) -> std::io::Result<Instruction_Operand>
where A: std::io::Read
{
    let add_reg = search_register(modrm.rm, Register_Type::GP, add_size, match rex {
        Some (r) => Some(r.b),
        _        => None
    }).unwrap();

    let op_reg = search_register(modrm.rm, Register_Type::GP, op_size, match rex {
        Some (r) => Some(r.b),
        _        => None
    }).unwrap();

    match add_size {
        Register_Size::_16 => match modrm
        {
            // TODO: this needs to be replaced with 2 bit struct fields so that this can be exhaustive. Need to return something more meaningful
            ModRMByte { md: 0b00, rm: 0b00, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(BX), index: Some(SI), scale: 1, disp: 0, res_size: op_size })),
            ModRMByte { md: 0b00, rm: 0b01, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(BX), index: Some(SI), scale: 1, disp: bytes_to_int(&reader.take_bytes::<1>()?), res_size: op_size })),
            ModRMByte { md: 0b00, rm: 0b10, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(BX), index: Some(SI), scale: 1, disp: bytes_to_int(&reader.take_bytes::<2>()?), res_size: op_size })),

            ModRMByte { md: 0b00, rm: 0b00, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(BX), index: Some(DI), scale: 1, disp: 0, res_size: op_size })),
            ModRMByte { md: 0b00, rm: 0b01, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(BX), index: Some(DI), scale: 1, disp: bytes_to_int(&reader.take_bytes::<1>()?), res_size: op_size })),
            ModRMByte { md: 0b00, rm: 0b10, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(BX), index: Some(DI), scale: 1, disp: bytes_to_int(&reader.take_bytes::<2>()?), res_size: op_size })),

            ModRMByte { md: 0b00, rm: 0b00, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(BP), index: Some(SI), scale: 1, disp: 0, res_size: op_size })),
            ModRMByte { md: 0b00, rm: 0b01, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(BP), index: Some(SI), scale: 1, disp: bytes_to_int(&reader.take_bytes::<1>()?), res_size: op_size })),
            ModRMByte { md: 0b00, rm: 0b10, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(BP), index: Some(SI), scale: 1, disp: bytes_to_int(&reader.take_bytes::<2>()?), res_size: op_size })),

            ModRMByte { md: 0b00, rm: 0b00, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(BP), index: Some(DI), scale: 1, disp: 0, res_size: op_size })),
            ModRMByte { md: 0b00, rm: 0b01, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(BP), index: Some(DI), scale: 1, disp: bytes_to_int(&reader.take_bytes::<1>()?), res_size: op_size })),
            ModRMByte { md: 0b00, rm: 0b10, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(BP), index: Some(DI), scale: 1, disp: bytes_to_int(&reader.take_bytes::<2>()?), res_size: op_size })),

            ModRMByte { md: 0b00, rm: 0b00, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(SI), index: None, scale: 1, disp: 0, res_size: op_size })),
            ModRMByte { md: 0b00, rm: 0b01, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(SI), index: None, scale: 1, disp: bytes_to_int(&reader.take_bytes::<1>()?), res_size: op_size })),
            ModRMByte { md: 0b00, rm: 0b10, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(SI), index: None, scale: 1, disp: bytes_to_int(&reader.take_bytes::<2>()?), res_size: op_size })),

            ModRMByte { md: 0b00, rm: 0b00, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(DI), index: None, scale: 1, disp: 0, res_size: op_size })),
            ModRMByte { md: 0b00, rm: 0b01, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(DI), index: None, scale: 1, disp: bytes_to_int(&reader.take_bytes::<1>()?), res_size: op_size })),
            ModRMByte { md: 0b00, rm: 0b10, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(DI), index: None, scale: 1, disp: bytes_to_int(&reader.take_bytes::<2>()?), res_size: op_size })),

            ModRMByte { md: 0b00, rm: 0b00, .. } => Ok(Instruction_Operand::DREF(Dref { base: None, index: None, scale: 1, disp: bytes_to_int(&reader.take_bytes::<2>()?), res_size: op_size })),
            ModRMByte { md: 0b00, rm: 0b01, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(BP), index: None, scale: 1, disp: bytes_to_int(&reader.take_bytes::<1>()?), res_size: op_size })),
            ModRMByte { md: 0b00, rm: 0b10, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(BP), index: None, scale: 1, disp: bytes_to_int(&reader.take_bytes::<2>()?), res_size: op_size })),

            ModRMByte { md: 0b00, rm: 0b00, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(BX), index: None, scale: 1, disp: 0, res_size: op_size })),
            ModRMByte { md: 0b00, rm: 0b01, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(BX), index: None, scale: 1, disp: bytes_to_int(&reader.take_bytes::<1>()?), res_size: op_size })),
            ModRMByte { md: 0b00, rm: 0b10, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(BX), index: None, scale: 1, disp: bytes_to_int(&reader.take_bytes::<2>()?), res_size: op_size })),

            ModRMByte { md: 0b11, .. } => Ok(Instruction_Operand::REGISTER(op_reg)),
            _ => Err(std::io::Error::from(std::io::ErrorKind::NotFound))
        },

        _ => match modrm
        {
            // Not supported
            ModRMByte { md: 0b00, rm: 0b100, .. } => parse_sib_byte(reader, modrm, add_size, op_size, rex),
            ModRMByte { md: 0b01, rm: 0b100, .. } => parse_sib_byte(reader, modrm, add_size, op_size, rex),
            ModRMByte { md: 0b10, rm: 0b100, .. } => parse_sib_byte(reader, modrm, add_size, op_size, rex),

            ModRMByte { md: 0b00, rm: 0b101, .. } => Ok(Instruction_Operand::DREF(Dref { base: None, index: None, scale: 0, disp: bytes_to_int(&reader.take_bytes::<4>()?), res_size: op_size })),
            ModRMByte { md: 0b00, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(add_reg), index: None, scale: 0, disp: 0, res_size: op_size })),

            ModRMByte { md: 0b01, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(add_reg), index: None, scale: 0, disp: bytes_to_int(&reader.take_bytes::<1>()?), res_size: op_size })),
            ModRMByte { md: 0b10, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(add_reg), index: None, scale: 0, disp: bytes_to_int(&reader.take_bytes::<4>()?), res_size: op_size })),

            ModRMByte { md: 0b11, .. } => Ok(Instruction_Operand::REGISTER(op_reg)),


            _ => Err(std::io::Error::from(std::io::ErrorKind::NotFound))
        }
    }
}

fn handle_modrm_operand<A, const B: usize>(reader: &mut MyReader::<A, B>, mode: InstMode, op: Opcode_Operand_ModRM, modrm: &ModRMByte, opcode: u8, operand_override: bool, address_override: bool, rex: &Option<Rex_Prefix>) -> std::io::Result<Instruction_Operand>
where A: std::io::Read
{
    let add_size = match (mode, address_override, rex) 
    {
        (InstMode::x64, true,  Some(Rex_Prefix { w: true, .. })) => Register_Size::_32,
        (InstMode::x64, false, Some(Rex_Prefix { w: true, .. })) => Register_Size::_64,

        (InstMode::x64, true,  Some(Rex_Prefix { w: false, .. })) | (InstMode::x64, true, None)  => Register_Size::_32,
        (InstMode::x64, false, Some(Rex_Prefix { w: false, .. })) | (InstMode::x64, false, None) => Register_Size::_64,

        (InstMode::x32, false, _) => Register_Size::_32,
        (InstMode::x32, true,  _) => Register_Size::_16,
    };

    let v_op_size = match (mode, operand_override, rex) 
    {
        (_, _, Some(Rex_Prefix { .. })) => Register_Size::_64,
        (_, false, None) => Register_Size::_32,
        (_, true, None) => Register_Size::_16,
    };

    let z_size = match (v_op_size)
    {
        Register_Size::_16 => Register_Size::_16,
        Register_Size::_32 | Register_Size::_64 => Register_Size::_32,
        _ => panic!("Invalid register operand size!"),
    };

    let d64_size = match (mode, operand_override, &rex)
    {
        (InstMode::x32, _, _) => v_op_size,
        (InstMode::x64, true, _) => Register_Size::_16,
        (InstMode::x64, false, _) => Register_Size::_64,
    };

    match op
    {
        Opcode_Operand_ModRM::Eb => lookup_32_effective_address(reader, modrm, add_size, Register_Size::_8, &rex),
        Opcode_Operand_ModRM::Ev => lookup_32_effective_address(reader, modrm, add_size, v_op_size, &rex),
        Opcode_Operand_ModRM::Ev_d64 => lookup_32_effective_address(reader, modrm, add_size, d64_size, &rex),
        Opcode_Operand_ModRM::Ew => lookup_32_effective_address(reader, modrm, add_size, Register_Size::_16, &rex),

        Opcode_Operand_ModRM::M  => lookup_32_effective_address(reader, modrm, add_size, v_op_size, &rex),
        Opcode_Operand_ModRM::Ma => lookup_32_effective_address(reader, modrm, add_size, v_op_size, &rex),
        Opcode_Operand_ModRM::Mp => lookup_32_effective_address(reader, modrm, add_size, v_op_size, &rex),

        Opcode_Operand_ModRM::Sw => Ok(Instruction_Operand::REGISTER(search_register(modrm.reg_op, Register_Type::SEG, Register_Size::_16, match rex {
            Some (r) => Some(r.r),
            _ => None
        }).unwrap())),

        Opcode_Operand_ModRM::Gb => Ok(Instruction_Operand::REGISTER(search_register(modrm.reg_op, Register_Type::GP, Register_Size::_8, match rex {
            Some (r) => Some(r.r),
            _ => None
        }).unwrap())),

        Opcode_Operand_ModRM::Gv => Ok(Instruction_Operand::REGISTER(search_register(modrm.reg_op, Register_Type::GP, v_op_size, match rex {
            Some (r) => Some(r.r),
            _ => None
        }).unwrap())),

        Opcode_Operand_ModRM::Gw => Ok(Instruction_Operand::REGISTER(search_register(modrm.reg_op, Register_Type::GP, Register_Size::_16, match rex {
            Some (r) => Some(r.r),
            _ => None
        }).unwrap())),

        Opcode_Operand_ModRM::Gz => Ok(Instruction_Operand::REGISTER(search_register(modrm.reg_op, Register_Type::GP, z_size, match rex {
            Some (r) => Some(r.r),
            _ => None
        }).unwrap())),

        Opcode_Operand_ModRM::Gw => Ok(Instruction_Operand::REGISTER(search_register(modrm.reg_op, Register_Type::SEG, Register_Size::_16, match rex {
            Some (r) => Some(r.r),
            _ => None
        }).unwrap())),
    }
}

fn read_inst<A, const B: usize>(mode: InstMode, reader: &mut MyReader::<A, B>) -> std::io::Result<Instruction>
where A: std::io::Read
{
    let mut prefix = Prefix_Acc {
        group1: None,
        group2: None,
        group3: None,
        group4: None,
    };

    // TODO account for multiple prefix error here
    // Collect the prefix bytes
    while prefix.add_prefix(reader.peek_byte()?).is_ok() {
        reader.take_byte();
    };

    // Read the (possible) rex prefix
    let rex = match parse_rex_prefix(reader.peek_byte()?)
    {
        Some (rex) => {
            reader.take_byte();
            Some(rex)
        },

        None  => None
    };

    let opcode: u8 = reader.take_byte()?;

    let operand_override = match prefix.group3
    {
        Some (Prefix_Group3::Operand_Override_66) => true,
        _ => false,
    };

    let address_override = match prefix.group4
    {
        Some (Prefix_Group4::Address_Override_67) => true,
        _ => false,
    };

    let rex_w = match rex.as_ref()
    {
        Some (r) => r.w,
        _ =>          false
    };

    let mut mod_rm_byte: Option<ModRMByte> = None;
    let res: Opcode_Table_Result = match search_opcode_one_byte(opcode, mode, operand_override, address_override, rex_w)
    {
        None =>
        {
            mod_rm_byte = Some(ModRMByte::new(reader.take_byte()?));
            match search_opcode_one_byte_extention(mode, opcode, mod_rm_byte.as_ref().unwrap())
            {
                Some (ins) => ins,
                None => panic!("no instruction found!"),
            }
        }

        Some(res) => res,
    };

    let mut operands: [Option<Instruction_Operand>; 4] = [None, None, None, None];

    // parse the MODRM byte operands first
    for i in 0..4
    {
        match res.operands[i]
        {
            Some(Opcode_Operand::MODRM_BYTE(op)) => 
            {
                if (mod_rm_byte.is_none())
                {
                    mod_rm_byte = Some(ModRMByte::new(reader.take_byte()?));
                }

                operands[i] = Some(handle_modrm_operand(reader, mode, op, mod_rm_byte.as_ref().unwrap(), opcode, operand_override, address_override, &rex)?) 
            }
            
            _ => ()
        }
    }

    for i in 0..4
    {
        match res.operands[i]
        {
            Some(Opcode_Operand::DIS_BYTES(op)) => 
            {
                let op_size = match (mode, operand_override, &rex) 
                {
                    (_, _, Some(Rex_Prefix { .. })) => Register_Size::_64,
                    (_, false, None) => Register_Size::_32,
                    (_, true, None) => Register_Size::_16,
                };

                let add_size = match (mode, address_override, &rex) 
                {
                    (InstMode::x64, true,  Some(Rex_Prefix { w: true, .. })) => Register_Size::_32,
                    (InstMode::x64, false, Some(Rex_Prefix { w: true, .. })) => Register_Size::_64,

                    (InstMode::x64, true,  Some(Rex_Prefix { w: false, .. })) | (InstMode::x64, true, None)  => Register_Size::_32,
                    (InstMode::x64, false, Some(Rex_Prefix { w: false, .. })) | (InstMode::x64, false, None) => Register_Size::_64,

                    (InstMode::x32, false, _) => Register_Size::_32,
                    (InstMode::x32, true,  _) => Register_Size::_16,
                };

                match op
                {
                    Opcode_Operand_Dis::Jb => operands[i] = Some(Instruction_Operand::IMM(bytes_to_int(&reader.take_bytes::<1>()?))),
                    Opcode_Operand_Dis::Jz => operands[i] = Some(Instruction_Operand::IMM(
                    match op_size
                    {
                        Register_Size::_64 => bytes_to_int(&reader.take_bytes::<4>()?),
                        Register_Size::_32 => bytes_to_int(&reader.take_bytes::<4>()?),
                        Register_Size::_16 => bytes_to_int(&reader.take_bytes::<2>()?),
                        _ => panic!("Unexpected immediate size!"),
                    })),

                    Opcode_Operand_Dis::Ob => operands[i] = Some(Instruction_Operand::DREF(Dref { base: None, index: None, scale: 0, disp: bytes_to_int(&reader.take_bytes::<1>()?), res_size: op_size })),
                    Opcode_Operand_Dis::Ov => operands[i] = Some(Instruction_Operand::DREF(Dref { base: None, index: None, scale: 0, disp: 
                        match op_size
                        {
                            Register_Size::_64 => bytes_to_int(&reader.take_bytes::<4>()?),
                            Register_Size::_32 => bytes_to_int(&reader.take_bytes::<4>()?),
                            Register_Size::_16 => bytes_to_int(&reader.take_bytes::<2>()?),
                            _ => panic!("Unexpected immediate size!"),
                        }, res_size: op_size })),

                    _ => ()
                }
            }
            
            _ => ()
        }
    }

    for i in 0..4
    {
        match res.operands[i]
        {
            Some(Opcode_Operand::IMM_BYTES(imm)) => 
            {
                let op_size = match (mode, operand_override, &rex) 
                {
                    (_, _, Some(Rex_Prefix { .. })) => Register_Size::_64,
                    (_, false, None) => Register_Size::_32,
                    (_, true, None) => Register_Size::_16,
                };

                operands[i] = Some(Instruction_Operand::IMM(match imm 
                {
                    Opcode_Operand_Imm::Ib => bytes_to_int(&reader.take_bytes::<1>()?),
                    Opcode_Operand_Imm::Iw => bytes_to_int(&reader.take_bytes::<2>()?),

                    Opcode_Operand_Imm::Iv => {
                        match op_size
                        {
                            Register_Size::_64 => bytes_to_int(&reader.take_bytes::<8>()?),
                            Register_Size::_32 => bytes_to_int(&reader.take_bytes::<4>()?),
                            Register_Size::_16 => bytes_to_int(&reader.take_bytes::<2>()?),
                            _ => panic!("Unexpected immediate size!"),
                        }
                    },

                    Opcode_Operand_Imm::Iz => 
                    {
                        match op_size
                        {
                            Register_Size::_64 => bytes_to_int(&reader.take_bytes::<4>()?),
                            Register_Size::_32 => bytes_to_int(&reader.take_bytes::<4>()?),
                            Register_Size::_16 => bytes_to_int(&reader.take_bytes::<2>()?),
                            _ => panic!("Unexpected immediate size!"),
                        }
                    },
                }));
            }
            
            _ => ()
        }
    }

    for i in 0..4
    {
        let op_size = match (mode, operand_override, &rex) 
        {
            (_, _, Some(Rex_Prefix { .. })) => Register_Size::_64,
            (_, false, None) => Register_Size::_32,
            (_, true, None) => Register_Size::_16,
        };

        let d64_size = match (mode, operand_override, &rex)
        {
            (InstMode::x32, _, _) => op_size,
            (InstMode::x64, true, _) => Register_Size::_16,
            (InstMode::x64, false, _) => Register_Size::_64,
        };

        match res.operands[i]
        {
            Some(Opcode_Operand::REGISTER(r)) => operands[i] = Some(Instruction_Operand::REGISTER(r)),
            Some(Opcode_Operand::REGISTER_UNSIZED(reg)) => operands[i] = Some(Instruction_Operand::REGISTER(size_register(reg, op_size).unwrap())),
            Some(Opcode_Operand::REGISTER_REX_PAIR((r1, r2))) =>
            {
                let r = match rex.as_ref()
                {
                    Some (Rex_Prefix { b: true, .. }) => r2,
                    _ => r1,
                };

                match r
                {
                    Register_Known_Or_Unsized::KNOWN(reg) => operands[i] = Some(Instruction_Operand::REGISTER(reg)),
                    Register_Known_Or_Unsized::UNSIZED(reg) => operands[i] = Some(Instruction_Operand::REGISTER(size_register(reg, op_size).unwrap())),
                    Register_Known_Or_Unsized::UNSIZED_d64(reg) => operands[i] = Some(Instruction_Operand::REGISTER(size_register(reg, d64_size).unwrap())),
                };
            }

            Some(Opcode_Operand::imm_one) => operands[i] = Some(Instruction_Operand::IMM(1)),

            Some(Opcode_Operand::IMM_BYTES(..)) => (),
            Some(Opcode_Operand::MODRM_BYTE(..)) => (),
            Some(Opcode_Operand::DIS_BYTES(..)) => (),
            None => (),

            _ => (),
        }
    }

    return Ok(Instruction { name: res.instruction, operands });
}

fn main() 
{
    println!("------------------------------");
    println!("------ Welcome to DASM! ------");
    println!("");

    //     src   dst
    // add rax, r12
    // let bytes = [0x49u8, 0x01, 0xc4];
    // let mut index = 0;

    // let rex = parse_rex_prefix(bytes[index]);
    // match rex {
    //     Some (val) => {
    //         index += 1;
    //         println!("{:?}", val);
    //     },

    //     None       => println!("Not an REX PREFIX"),
    // }

    // let reg = search_register(0b1101, Register_Type::SEG, Register_Size::_16, false);
    // match reg
    // {
    //     Some(reg) => println!("{:?}", reg.name),
    //     _ => println!("Could not find register!")
    // }

    // let inst = search_opcode_one_byte(0x5a, InstMode::x64, Some(false), Some(false), Some(false));
    // println!("{:x?}", inst);


    // Read in the bytes from a stream
    let bytes = [0x49u8, 0x01, 0xc4, 0x20, 0xd8, 0x41, 0x30, 0xdc, 0x04, 0x0c, 0x48, 0x05, 0xb0, 0x04, 0x00, 0x00, 0x48, 0x89, 0xd8, 0x39, 0xc8, 0x48, 0x01, 0x18, 0x44, 0x00, 0x00, 0xe9, 0x01, 0x00, 000, 0x00, 0xb0, 0x01, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x48, 0xd1, 0xe8, 0xd1, 0xe8, 0x90, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb0, 0x01, 0xb0, 0x01, 0xc6, 0x03, 0x05, 0x48, 0xff, 0xc3, 0xff, 0xc3, 0xa8, 0x02, 0xd0, 0xe9, 0x49, 0xd1, 0xec, 0x48, 0xc7, 0x00, 0x05, 0x00, 0x00, 0x00, 0xc6, 0x00, 0x05, 0xc6, 0x40, 0x0c, 0x05, 0xc6, 0x04, 0xc0, 0x05, 0xc6, 0x04, 0xc5, 0x04, 0x00, 0x00, 0x00, 0x05, 0x67, 0xc6, 0x45, 0x00, 0x05, 0xff, 0x20, 0xff, 0x24, 0x25, 0x11, 0x11, 0x00, 0x00, 0x67, 0x48, 0xff, 0x28, 0x75, 0x00, 0x75, 0xfe, 0x68, 0x11, 0x11, 0x00, 0x00, 0x66, 0x41, 0x50, 0x41, 0x50, 0x50, 0x66, 0x50, 0x8f, 0x00, 0x66, 0x8f, 0x00];
    let mut cursor = Cursor::new(bytes);
    let mut reader = MyReader::<_, 1024>::new(&mut cursor);

    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));
    println!("{:?}", read_inst(InstMode::x64, &mut reader));

    // let inst_mode = InstMode::x64;

    // match reader.take_byte()
    // {
    //     Some(v) => println!("{:x?}", v),
    //     None    => println!("Failed!")
    // }

    // match reader.take_byte()
    // {
    //     Some(v) => println!("{:x?}", v),
    //     None    => println!("Failed!")
    // }

    // let bytes = [0x49u8, 0x01, 0xc4];
    // let b: &[u8] = &bytes;

    // let mut reader = BufReader::new(b);
    // {
    //     let mut byte_buff: [u8; 1] = [0];
    //     while 
    //         match reader.read(&mut byte_buff)
    //         {
    //               Ok(1)  => true,
    //               Ok(_)  => false,
    //               Err(_) => false
    //         }
    //     {
    //         let mut vec = Vec::new();

    //     }
    // }
}
