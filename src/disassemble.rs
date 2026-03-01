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

use crate::registers::*;
use crate::util::*;
use crate::one_byte_opcode::*;

// mod util;
// use util::*;


const PREFIX_VALS: &[u8] = &[ 0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26 ,0x64, 0x65, 0x66, 0x67 ];

const REX_LOWER: u8 = 0x40;
const REX_UPPER: u8 = 0x4F;

#[derive(Debug, Clone, Copy)]
pub struct Rex_Prefix
{
    pub w: bool,
    pub r: bool,
    pub x: bool,
    pub b: bool,
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

pub enum Prefix_Group1
{
    LOCK_F0,
    REPNZ_BND_F2,
    REPZ_F3,
}

pub enum Prefix_Group2
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

pub enum Prefix_Group3
{
    Operand_Override_66,
}

pub enum Prefix_Group4
{
    Address_Override_67,
}

pub enum Prefix
{
    Prefix_Group1(Prefix_Group1),
    Prefix_Group2(Prefix_Group2),
    Prefix_Group3(Prefix_Group3),
    Prefix_Group4(Prefix_Group4),
}

#[derive(Debug)]
enum Prefix_Addition_Result
{
    NOT_A_PREFIX,
    GROUP_USED,
}

pub struct Prefix_Acc
{
    pub group1: Option<Prefix_Group1>,
    pub group2: Option<Prefix_Group2>,
    pub group3: Option<Prefix_Group3>,
    pub group4: Option<Prefix_Group4>,
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
            // (0x2e, Prefix_Acc{group1: _,    group2: None, group3: _,    group4: _})    => self.group2 = Some(Prefix_Group2::BR_NOT_TAKEN_2E),
            // (0x3e, Prefix_Acc{group1: _,    group2: None, group3: _,    group4: _})    => self.group2 = Some(Prefix_Group2::BR_TAKEN_3E),

            (0x66, Prefix_Acc{group1: _,    group2: _,    group3: None, group4: _})    => self.group3 = Some(Prefix_Group3::Operand_Override_66),
            (0x67, Prefix_Acc{group1: _,    group2: _,    group3: _,    group4: None}) => self.group4 = Some(Prefix_Group4::Address_Override_67),
            _ => () // return Err(Prefix_Addition_Result::GROUP_USED) 
        }
        
        Ok(())
    }
}

pub enum Vector_Length
{
    _128,
    _256
}

pub enum Opcode_Map
{
    ONE_BYTE,
    TWO_BYTE,
    THREE_BYTE_38,
    THREE_BYTE_3A,
}

pub struct Vex_Prefix
{
    pub vector_length: Vector_Length,
    pub v_reg        : u8,
}

pub struct Inst_Prefix
{
    pub prefixes: Prefix_Acc,
    pub rex: Option<Rex_Prefix>,
    pub vex: Option<Vex_Prefix>,
    pub opcode_map: Opcode_Map,
}

fn parse_vex_prefix_two_byte(byte_one: u8, mut prefix: Prefix_Acc) -> std::io::Result<Inst_Prefix>
{
    // TODO: bit field pattern match?
    match byte_one & 0b11
    {
        0b00 => {},
        0b01 => prefix.add_prefix(0x66).unwrap(),
        0b10 => prefix.add_prefix(0xf3).unwrap(),
        0b11 => prefix.add_prefix(0xf2).unwrap(),
        _ => { return Err(std::io::Error::from(std::io::ErrorKind::NotFound)); }
    };

    let rex = Rex_Prefix {
        w: false,
        x: true,
        b: true,
        r: (byte_one & 0b10000000) == 0
    };

    let vex = Vex_Prefix {
        vector_length: match (byte_one & 0b100) == 0
        {
            true  => Vector_Length::_128,
            false => Vector_Length::_256,
        },

        v_reg: ((byte_one & 0b01111000) >> 3),
    };

    return Ok(Inst_Prefix {
        prefixes: prefix,
        rex: Some(rex),
        vex: Some(vex),
        opcode_map: Opcode_Map::TWO_BYTE
    });
}

fn parse_vex_prefix_three_byte(byte_one: u8, byte_two: u8, mut prefix: Prefix_Acc) -> std::io::Result<Inst_Prefix>
{
    // TODO: bit field pattern match?
    match byte_two & 0b11
    {
        0b00 => {},
        0b01 => prefix.add_prefix(0x66).unwrap(),
        0b10 => prefix.add_prefix(0xf3).unwrap(),
        0b11 => prefix.add_prefix(0xf2).unwrap(),
        _    => { return Err(std::io::Error::from(std::io::ErrorKind::NotFound)); }
    }

    let rex = Rex_Prefix {
        w: (byte_two & 0b10000000) == 0,
        x: (byte_one & 0b01000000) == 0,
        b: (byte_one & 0b00100000) == 0,
        r: (byte_one & 0b10000000) == 0,
    };

    let opcode_map = match byte_one & 0b00011111
    {
        0b00001 => Opcode_Map::TWO_BYTE,
        0b00010 => Opcode_Map::THREE_BYTE_38,
        0b00011 => Opcode_Map::THREE_BYTE_3A,
        _       => { return Err(std::io::Error::from(std::io::ErrorKind::NotFound)); }
    };

    let vex = Vex_Prefix {
        vector_length: match (byte_two & 0b100) == 0
        {
            true  => Vector_Length::_128,
            false => Vector_Length::_256,
        },

        v_reg: ((byte_two & 0b01111000) >> 3),
    };

    return Ok(Inst_Prefix {
        prefixes: prefix,
        rex: Some(rex),
        vex: Some(vex),
        opcode_map: opcode_map,
    });
}

pub struct ModRMByte
{
    pub byte: u8,
    pub md: u8,
    pub rm : u8,
    pub reg_op: u8
}

impl ModRMByte
{
    pub fn new(byte: u8) -> ModRMByte
    {
        ModRMByte {
            byte,
            md     : (0b11000000 & byte) >> 6,
            rm     : (0b00000111 & byte) >> 0,
            reg_op : (0b00111000 & byte) >> 3,
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Dref
{
    pub base: Option<Register>,
    pub index: Option<Register>,
    pub scale: u64,
    pub disp: i64,
    pub res_size: Register_Size,
}

#[derive(Debug, Copy, Clone)]
pub enum Instruction_Operand
{
    REGISTER(Register),
    IMM_64(i64),
    IMM_32(i32),
    IMM_16(i16),
    IMM_8(i8),
    DREF(Dref), 
}

impl std::fmt::Display for Instruction_Operand {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Instruction_Operand::REGISTER(reg) => {
                write!(f, " {}", reg)?;
            },

            Instruction_Operand::IMM_64(imm) => {
                write!(f, " {:#x}", imm)?;
            }

            Instruction_Operand::IMM_32(imm) => {
                write!(f, " {:#x}", imm)?;
            }

            Instruction_Operand::IMM_16(imm) => {
                write!(f, " {:#x}", imm)?;
            }

            Instruction_Operand::IMM_8(imm) => {
                write!(f, " {:#x}", imm)?;
            }

            Instruction_Operand::DREF(dref) => {
                write!(f, " [")?;
                if dref.base.is_some() {
                    write!(f, "{} ", dref.base.unwrap())?;
                }

                if dref.index.is_some() {
                    write!(f, "+ {} ", dref.index.unwrap())?;
                }

                if dref.scale != 0 && dref.scale != 1 {
                    write!(f, "* {:#x} ", dref.scale)?;
                }

                if dref.disp != 0 {
                    write!(f, "+ {:#x}", dref.disp)?;
                }

                write!(f, "]")?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Instruction
{
    pub name: Instruction_Name,
    pub byte_len: u32,
    pub operands: [Option<Instruction_Operand>; 4]
}

impl std::fmt::Display for Instruction {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.name)?;
        for operand in self.operands {
            match operand {
                Some(op) => write!(f, "{}", op)?,
                _ => (),
            };
        }

        Ok(())
    }
}

impl Instruction {
    pub fn get_first_val(&self) -> Option<i64> {
        match self.operands[0] {
            Some(Instruction_Operand::IMM_64(val)) => Some(val as i64),
            Some(Instruction_Operand::IMM_32(val)) => Some(val as i64),
            Some(Instruction_Operand::IMM_16(val)) => Some(val as i64),
            Some(Instruction_Operand::IMM_8(val)) => Some(val as i64),
            _ => None
        }
    }

    pub fn is_offset_jmp(&self) -> Option<i64> {
        match self.name {
            Instruction_Name::near_Jmp |
            Instruction_Name::short_Jmp |
            Instruction_Name::J_O |
            Instruction_Name::J_NO |
            Instruction_Name::J_B_NAE_C |
            Instruction_Name::J_NB_AE_NC |
            Instruction_Name::J_Z_E |
            Instruction_Name::J_NZ_NE |
            Instruction_Name::J_BE_NA |
            Instruction_Name::J_NBE_A |
            Instruction_Name::J_S |
            Instruction_Name::J_NS |
            Instruction_Name::J_P_PE |
            Instruction_Name::J_NP_PO |
            Instruction_Name::J_L_NGE |
            Instruction_Name::J_NL_GE |
            Instruction_Name::J_LE_NG |
            Instruction_Name::J_NLE_G |
            Instruction_Name::J_CC_O |
            Instruction_Name::J_CC_NO |
            Instruction_Name::J_CC_B_CNAE |
            Instruction_Name::J_CC_AE_NB_NC |
            Instruction_Name::J_CC_E_Z |
            Instruction_Name::J_CC_NE_NZ |
            Instruction_Name::J_CC_BE_NA |
            Instruction_Name::J_CC_A_NBE |
            Instruction_Name::J_CC_S |
            Instruction_Name::J_CC_NS |
            Instruction_Name::J_CC_P_PE |
            Instruction_Name::J_CC_NP_PO |
            Instruction_Name::J_CC_L_NGE |
            Instruction_Name::J_CC_NL_GE |
            Instruction_Name::J_CC_LE_NA |
            Instruction_Name::J_CC_NLE_G => {
                match self.operands[0] {
                    Some(Instruction_Operand::IMM_64(val)) => Some(val),
                    Some(Instruction_Operand::IMM_32(val)) => Some(val as i64),
                    Some(Instruction_Operand::IMM_16(val)) => Some(val as i64),
                    Some(Instruction_Operand::IMM_8(val)) => Some(val as i64),
                    _ => panic!("JMP instruction expected to have immediate offset "),
                }
            },

            _ => None
        }
    }
}

fn parse_sib_byte(reader: &mut MyReader, modrm: &ModRMByte, add_size: Register_Size, op_size: Register_Size, rex: &Option<Rex_Prefix>) -> std::io::Result<Instruction_Operand>
{
    let sib: u8 = reader.take_byte()?;
    let scale: u8 = u8::pow(2, ((sib & 0b11000000) >> 6) as u32);
    let index: u8 =             (sib & 0b00111000) >> 3;
    let base : u8 =             (sib & 0b00000111) >> 0;

    let index_reg = match index
    {
        0b100 => None,
        _     => Some(search_register(index, Register_Type::GP, add_size, match rex.as_ref() {
                 Some (r) => Some(r.x),
                 _ => None
        })?)
    };

    let base_reg = match base
    {
        0b101 => match modrm.md
        {
            0b01 | 0b10 => match add_size
            {
                Register_Size::_64 => Some(RBP),
                Register_Size::_32 => Some(EBP),
                _ => { return Err(std::io::Error::from(std::io::ErrorKind::NotFound)); }
            }
            
            _ => None
        }

        _ => Some(search_register(base, Register_Type::GP, add_size, match rex {
            Some(r) => Some(r.b),
            _ => None
        })?)
    };

    let disp = match (modrm.md, base)
    {
        (0b01, _)     => bytes_to_int(reader.take_bytes(1)?),
        (0b10, _)     => bytes_to_int(reader.take_bytes(4)?),
        (0b00, 0b101) => bytes_to_int(reader.take_bytes(4)?),
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

fn lookup_32_effective_address(reader: &mut MyReader, modrm: &ModRMByte, add_size: Register_Size, op_size: Register_Size, op_type: Register_Type, rex: &Option<Rex_Prefix>) -> std::io::Result<Instruction_Operand>
{
    let add_reg = search_register(modrm.rm, Register_Type::GP, add_size, match rex {
        Some (r) => Some(r.b),
        _        => None
    }).unwrap();

    let op_reg = search_register(modrm.rm, op_type, op_size, match rex {
        Some (r) => Some(r.b),
        _        => None
    }).unwrap();

    match add_size {
        Register_Size::_16 => match modrm
        {
            // TODO: this needs to be replaced with 2 bit struct fields so that this can be exhaustive. Need to return something more meaningful
            ModRMByte { md: 0b00, rm: 0b000, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(BX), index: Some(SI), scale: 1, disp: 0, res_size: op_size })),
            ModRMByte { md: 0b00, rm: 0b001, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(BX), index: Some(DI), scale: 1, disp: 0, res_size: op_size })),
            ModRMByte { md: 0b00, rm: 0b010, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(BP), index: Some(SI), scale: 1, disp: 0, res_size: op_size })),
            ModRMByte { md: 0b00, rm: 0b011, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(BP), index: Some(DI), scale: 1, disp: 0, res_size: op_size })),
            ModRMByte { md: 0b00, rm: 0b100, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(SI), index: None, scale: 1, disp: 0, res_size: op_size })),
            ModRMByte { md: 0b00, rm: 0b101, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(DI), index: None, scale: 1, disp: 0, res_size: op_size })),
            ModRMByte { md: 0b00, rm: 0b110, .. } => Ok(Instruction_Operand::DREF(Dref { base: None,     index: None, scale: 1, disp: bytes_to_int(reader.take_bytes(2)?), res_size: op_size })),
            ModRMByte { md: 0b00, rm: 0b111, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(BX), index: None, scale: 1, disp: 0, res_size: op_size })),

            ModRMByte { md: 0b01, rm: 0b000, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(BX), index: Some(SI), scale: 1, disp: bytes_to_int(reader.take_bytes(1)?), res_size: op_size })),
            ModRMByte { md: 0b01, rm: 0b001, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(BX), index: Some(DI), scale: 1, disp: bytes_to_int(reader.take_bytes(1)?), res_size: op_size })),
            ModRMByte { md: 0b01, rm: 0b010, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(BP), index: Some(SI), scale: 1, disp: bytes_to_int(reader.take_bytes(1)?), res_size: op_size })),
            ModRMByte { md: 0b01, rm: 0b011, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(BP), index: Some(DI), scale: 1, disp: bytes_to_int(reader.take_bytes(1)?), res_size: op_size })),
            ModRMByte { md: 0b01, rm: 0b100, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(SI), index: None, scale: 1, disp: bytes_to_int(reader.take_bytes(1)?), res_size: op_size })),
            ModRMByte { md: 0b01, rm: 0b101, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(DI), index: None, scale: 1, disp: bytes_to_int(reader.take_bytes(1)?), res_size: op_size })),
            ModRMByte { md: 0b01, rm: 0b110, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(BP), index: None, scale: 1, disp: bytes_to_int(reader.take_bytes(1)?), res_size: op_size })),
            ModRMByte { md: 0b01, rm: 0b111, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(BX), index: None, scale: 1, disp: bytes_to_int(reader.take_bytes(1)?), res_size: op_size })),

            ModRMByte { md: 0b10, rm: 0b000, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(BX), index: Some(SI), scale: 1, disp: bytes_to_int(reader.take_bytes(2)?), res_size: op_size })),
            ModRMByte { md: 0b10, rm: 0b001, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(BX), index: Some(DI), scale: 1, disp: bytes_to_int(reader.take_bytes(2)?), res_size: op_size })),
            ModRMByte { md: 0b10, rm: 0b010, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(BP), index: Some(SI), scale: 1, disp: bytes_to_int(reader.take_bytes(2)?), res_size: op_size })),
            ModRMByte { md: 0b10, rm: 0b011, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(BP), index: Some(DI), scale: 1, disp: bytes_to_int(reader.take_bytes(2)?), res_size: op_size })),
            ModRMByte { md: 0b10, rm: 0b100, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(SI), index: None, scale: 1, disp: bytes_to_int(reader.take_bytes(2)?), res_size: op_size })),
            ModRMByte { md: 0b10, rm: 0b101, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(DI), index: None, scale: 1, disp: bytes_to_int(reader.take_bytes(2)?), res_size: op_size })),
            ModRMByte { md: 0b10, rm: 0b110, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(BP), index: None, scale: 1, disp: bytes_to_int(reader.take_bytes(2)?), res_size: op_size })),
            ModRMByte { md: 0b10, rm: 0b111, .. } => Ok(Instruction_Operand::DREF(Dref { base: Some(BX), index: None, scale: 1, disp: bytes_to_int(reader.take_bytes(2)?), res_size: op_size })),

            ModRMByte { md: 0b11, .. } => Ok(Instruction_Operand::REGISTER(op_reg)),
            _ => Err(std::io::Error::from(std::io::ErrorKind::NotFound))
        },

        _ => match modrm
        {
            // Not supported
            ModRMByte { md: 0b00, rm: 0b100, .. } => parse_sib_byte(reader, modrm, add_size, op_size, rex),
            ModRMByte { md: 0b01, rm: 0b100, .. } => parse_sib_byte(reader, modrm, add_size, op_size, rex),
            ModRMByte { md: 0b10, rm: 0b100, .. } => parse_sib_byte(reader, modrm, add_size, op_size, rex),

            ModRMByte { md: 0b00, rm: 0b101, .. } => Ok(Instruction_Operand::DREF(Dref { base: None,          index: None, scale: 0, disp: bytes_to_int(reader.take_bytes(4)?), res_size: op_size })),
            ModRMByte { md: 0b00, .. }            => Ok(Instruction_Operand::DREF(Dref { base: Some(add_reg), index: None, scale: 0, disp: 0,                                   res_size: op_size })),

            ModRMByte { md: 0b01, .. }            => Ok(Instruction_Operand::DREF(Dref { base: Some(add_reg), index: None, scale: 0, disp: bytes_to_int(reader.take_bytes(1)?), res_size: op_size })),
            ModRMByte { md: 0b10, .. }            => Ok(Instruction_Operand::DREF(Dref { base: Some(add_reg), index: None, scale: 0, disp: bytes_to_int(reader.take_bytes(4)?), res_size: op_size })),

            ModRMByte { md: 0b11, .. }            => Ok(Instruction_Operand::REGISTER(op_reg)),


            _ => Err(std::io::Error::from(std::io::ErrorKind::NotFound))
        }
    }
}

fn handle_modrm_operand(reader: &mut MyReader, mode: InstMode, op: Opcode_Operand_ModRM, modrm: &ModRMByte, operand_override: bool, address_override: bool, rex: &Option<Rex_Prefix>, vex: &Option<Vex_Prefix>) -> std::io::Result<Option<Instruction_Operand>>
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

    let z_size = match v_op_size
    {
        Register_Size::_16 => Register_Size::_16,
        Register_Size::_32 | Register_Size::_64 => Register_Size::_32,
        _ => { return Err(std::io::Error::from(std::io::ErrorKind::NotFound)); }
    };

    let d64_size = match (mode, operand_override, &rex)
    {
        (InstMode::x32, _, _) => v_op_size,
        (InstMode::x64, true, _) => Register_Size::_16,
        (InstMode::x64, false, _) => Register_Size::_64,
    };

    let y_size = match (mode, operand_override)
    {
        (InstMode::x32, _) => Register_Size::_32,
        (InstMode::x64, true) => Register_Size::_32,
        (InstMode::x64, false) => Register_Size::_64,
    };

    match op
    {
        Opcode_Operand_ModRM::Cd => Ok(Some(Instruction_Operand::REGISTER(search_register(modrm.reg_op, Register_Type::CON, Register_Size::_32, None)?))),
        Opcode_Operand_ModRM::Dd => Ok(Some(Instruction_Operand::REGISTER(search_register(modrm.reg_op, Register_Type::DEB, Register_Size::_32, None)?))),
        Opcode_Operand_ModRM::Rd => Ok(Some(Instruction_Operand::REGISTER(search_register(modrm.rm, Register_Type::GP,  Register_Size::_32, None)?))),

        Opcode_Operand_ModRM::Ppi => Ok(Some(Instruction_Operand::REGISTER(search_register(modrm.reg_op, Register_Type::MMX,  Register_Size::_64, None)?))),
        Opcode_Operand_ModRM::Pq  => Ok(Some(Instruction_Operand::REGISTER(search_register(modrm.reg_op, Register_Type::MMX,  Register_Size::_64, None)?))),
        Opcode_Operand_ModRM::Pd  => Ok(Some(Instruction_Operand::REGISTER(search_register(modrm.reg_op, Register_Type::MMX,  Register_Size::_64, None)?))),
        
        Opcode_Operand_ModRM::Nq => Ok(Some(Instruction_Operand::REGISTER(search_register(modrm.rm, Register_Type::MMX,  Register_Size::_64, None)?))),

        Opcode_Operand_ModRM::Qpi => Ok(Some(lookup_32_effective_address(reader, modrm, add_size, Register_Size::_64, Register_Type::MMX, &None)?)),
        Opcode_Operand_ModRM::Qd => Ok(Some(lookup_32_effective_address(reader, modrm, add_size, Register_Size::_64, Register_Type::MMX, &None)?)),
        Opcode_Operand_ModRM::Qq => Ok(Some(lookup_32_effective_address(reader, modrm, add_size, Register_Size::_64, Register_Type::MMX, &None)?)),

        Opcode_Operand_ModRM::Eb =>     Ok(Some(lookup_32_effective_address(reader, modrm, add_size, Register_Size::_8, Register_Type::GP, &rex)?)),
        Opcode_Operand_ModRM::Ev =>     Ok(Some(lookup_32_effective_address(reader, modrm, add_size, v_op_size, Register_Type::GP, &rex)?)),
        Opcode_Operand_ModRM::Ev_d64 => Ok(Some(lookup_32_effective_address(reader, modrm, add_size, d64_size, Register_Type::GP, &rex)?)),
        Opcode_Operand_ModRM::Ew =>     Ok(Some(lookup_32_effective_address(reader, modrm, add_size, Register_Size::_16, Register_Type::GP, &rex)?)),
        Opcode_Operand_ModRM::Ey =>     Ok(Some(lookup_32_effective_address(reader, modrm, add_size, y_size, Register_Type::GP, &rex)?)),

        Opcode_Operand_ModRM::M  =>     Ok(Some(lookup_32_effective_address(reader, modrm, add_size, v_op_size, Register_Type::GP, &rex)?)),
        Opcode_Operand_ModRM::Ma =>     Ok(Some(lookup_32_effective_address(reader, modrm, add_size, v_op_size, Register_Type::GP, &rex)?)),
        Opcode_Operand_ModRM::Mp =>     Ok(Some(lookup_32_effective_address(reader, modrm, add_size, v_op_size, Register_Type::GP, &rex)?)),
        Opcode_Operand_ModRM::Mq =>     Ok(Some(lookup_32_effective_address(reader, modrm, add_size, v_op_size, Register_Type::GP, &rex)?)),
        Opcode_Operand_ModRM::Mx =>     Ok(Some(lookup_32_effective_address(reader, modrm, add_size, 
            Register_Size::_128,
            Register_Type::XMM,
            &None).unwrap()
        )),

        Opcode_Operand_ModRM::My =>    Ok(Some(lookup_32_effective_address(reader, modrm, add_size, 
            match operand_override {
                true => Register_Size::_128,
                false => Register_Size::_256,
            }, 
            match operand_override {
                true => Register_Type::XMM,
                false => Register_Type::YMM,
            },
            &None).unwrap()
        )),

        Opcode_Operand_ModRM::Mps =>    Ok(Some(lookup_32_effective_address(reader, modrm, add_size, 
            match operand_override {
                true => Register_Size::_128,
                false => Register_Size::_256,
            }, 
            match operand_override {
                true => Register_Type::XMM,
                false => Register_Type::YMM,
            },
            &None).unwrap()
        )),

        Opcode_Operand_ModRM::Mpd =>     Ok(Some(lookup_32_effective_address(reader, modrm, add_size, 
            match operand_override {
                true => Register_Size::_128,
                false => Register_Size::_256,
            }, 
            match operand_override {
                true => Register_Type::XMM,
                false => Register_Type::YMM,
            },
            &None).unwrap()
        )),

        Opcode_Operand_ModRM::Sw => Ok(Some(Instruction_Operand::REGISTER(search_register(modrm.reg_op, Register_Type::SEG, Register_Size::_16, match rex {
            Some (r) => Some(r.r),
            _ => None
        })?))),

        Opcode_Operand_ModRM::Gb => Ok(Some(Instruction_Operand::REGISTER(search_register(modrm.reg_op, Register_Type::GP, Register_Size::_8, match rex {
            Some (r) => Some(r.r),
            _ => None
        })?))),

        Opcode_Operand_ModRM::Gv => Ok(Some(Instruction_Operand::REGISTER(search_register(modrm.reg_op, Register_Type::GP, v_op_size, match rex {
            Some (r) => Some(r.r),
            _ => None
        })?))),

        Opcode_Operand_ModRM::Gw => Ok(Some(Instruction_Operand::REGISTER(search_register(modrm.reg_op, Register_Type::GP, Register_Size::_16, match rex {
            Some (r) => Some(r.r),
            _ => None
        })?))),

        Opcode_Operand_ModRM::Gz => Ok(Some(Instruction_Operand::REGISTER(search_register(modrm.reg_op, Register_Type::GP, z_size, match rex {
            Some (r) => Some(r.r),
            _ => None
        })?))),

        Opcode_Operand_ModRM::Gy => Ok(Some(Instruction_Operand::REGISTER(search_register(modrm.reg_op, Register_Type::GP, y_size, match rex {
            Some (r) => Some(r.r),
            _ => None
        })?))),

        Opcode_Operand_ModRM::Gd => Ok(Some(Instruction_Operand::REGISTER(search_register(modrm.reg_op, Register_Type::GP, Register_Size::_32, match rex {
            Some (r) => Some(r.r),
            _ => None
        })?))),

        Opcode_Operand_ModRM::FLOAT_Single_Real => Ok(Some(lookup_32_effective_address(reader, modrm, add_size, Register_Size::_32, Register_Type::GP, &None)?)),

        // 16 means 14 and 32 means 28 FPU environment
        Opcode_Operand_ModRM::FLOAT_14_28_byte => Ok(Some(lookup_32_effective_address(reader, modrm, add_size, v_op_size, Register_Type::GP, &None)?)),

        Opcode_Operand_ModRM::FLOAT_2_byte => Ok(Some(lookup_32_effective_address(reader, modrm, add_size, Register_Size::_16, Register_Type::GP, &None)?)),

        Opcode_Operand_ModRM::FLOAT_DWORD_INTEGER => Ok(Some(lookup_32_effective_address(reader, modrm, add_size, Register_Size::_32, Register_Type::GP, &None)?)),
        Opcode_Operand_ModRM::FLOAT_DOUBLE_REAL =>   Ok(Some(lookup_32_effective_address(reader, modrm, add_size, Register_Size::_64, Register_Type::GP, &None)?)),
        Opcode_Operand_ModRM::FLOAT_98_108_byte =>   Ok(Some(lookup_32_effective_address(reader, modrm, add_size, v_op_size, Register_Type::GP, &None)?)),
        Opcode_Operand_ModRM::FLOAT_WORD_INTEGER =>  Ok(Some(lookup_32_effective_address(reader, modrm, add_size, Register_Size::_16, Register_Type::GP, &None)?)),
        Opcode_Operand_ModRM::FLOAT_PACKED_BCD =>    Ok(Some(lookup_32_effective_address(reader, modrm, add_size, Register_Size::_32, Register_Type::GP, &None)?)),
        Opcode_Operand_ModRM::FLOAT_QUAD_INTEGER =>  Ok(Some(lookup_32_effective_address(reader, modrm, add_size, Register_Size::_64, Register_Type::GP, &None)?)),

        Opcode_Operand_ModRM::Hx => Ok(
        match vex {
            Some(vex) => Some(Instruction_Operand::REGISTER(search_register(vex.v_reg, match vex.vector_length {
                Vector_Length::_128 => Register_Type::XMM,
                Vector_Length::_256 => Register_Type::YMM,
            }, match vex.vector_length {
                Vector_Length::_128 => Register_Size::_128,
                Vector_Length::_256 => Register_Size::_256,
            }, None).unwrap())),

            None => None,
        }),

        Opcode_Operand_ModRM::Hss => Ok(
            match vex {
                Some(vex) => Some(Instruction_Operand::REGISTER(search_register(vex.v_reg, Register_Type::XMM, Register_Size::_128, None).unwrap())),
                None => None
            }
        ),

        Opcode_Operand_ModRM::Hsd => Ok(
            match vex {
                Some(vex) => Some(Instruction_Operand::REGISTER(search_register(vex.v_reg, Register_Type::XMM, Register_Size::_128, None).unwrap())),
                None => None
            }
        ),

        Opcode_Operand_ModRM::Hq => Ok(
            match vex {
                Some(vex) => Some(Instruction_Operand::REGISTER(search_register(vex.v_reg, Register_Type::XMM, Register_Size::_128, None).unwrap())),
                None => None
            }
        ),

        Opcode_Operand_ModRM::Hps => Ok(
        match vex {
            Some(vex) => Some(Instruction_Operand::REGISTER(search_register(vex.v_reg, match vex.vector_length {
                Vector_Length::_128 => Register_Type::XMM,
                Vector_Length::_256 => Register_Type::YMM,
            }, match vex.vector_length {
                Vector_Length::_128 => Register_Size::_128,
                Vector_Length::_256 => Register_Size::_256,
            }, None).unwrap())),

            None => None,
        }),

        Opcode_Operand_ModRM::Hpd => Ok(
        match vex {
            Some(vex) => Some(Instruction_Operand::REGISTER(search_register(vex.v_reg, match vex.vector_length {
                Vector_Length::_128 => Register_Type::XMM,
                Vector_Length::_256 => Register_Type::YMM,
            }, match vex.vector_length {
                Vector_Length::_128 => Register_Size::_128,
                Vector_Length::_256 => Register_Size::_256,
            }, None).unwrap())),

            None => None,
        }),

        Opcode_Operand_ModRM::Vx => Ok(
            Some(Instruction_Operand::REGISTER(search_register(modrm.reg_op,
                match operand_override {
                true => Register_Type::XMM,
                false => Register_Type::YMM,
            }, match operand_override {
                true => Register_Size::_128,
                false => Register_Size::_256,
            }, None).unwrap()))
        ),

        Opcode_Operand_ModRM::Vss => Ok(
            Some(Instruction_Operand::REGISTER(search_register(modrm.reg_op, Register_Type::XMM, Register_Size::_128, None).unwrap())),
        ),

        Opcode_Operand_ModRM::Vsd => Ok(
            Some(Instruction_Operand::REGISTER(search_register(modrm.reg_op, Register_Type::XMM, Register_Size::_128, None).unwrap())),
        ),

        Opcode_Operand_ModRM::Vq => Ok(
            Some(Instruction_Operand::REGISTER(search_register(modrm.reg_op, Register_Type::XMM, Register_Size::_128, None).unwrap())),
        ),

        Opcode_Operand_ModRM::Vps => Ok(
            Some(Instruction_Operand::REGISTER(search_register(modrm.reg_op, 
                match operand_override {
                true => Register_Type::XMM,
                false => Register_Type::YMM,
            }, match operand_override {
                true => Register_Size::_128,
                false => Register_Size::_256,
            }, None).unwrap()))
        ),

        Opcode_Operand_ModRM::Vpd => Ok(
            Some(Instruction_Operand::REGISTER(search_register(modrm.reg_op, 
                match operand_override {
                true => Register_Type::XMM,
                false => Register_Type::YMM,
            }, match operand_override {
                true => Register_Size::_128,
                false => Register_Size::_256,
            },

            None
        ).unwrap()))),

        Opcode_Operand_ModRM::Vdq => Ok(
            Some(Instruction_Operand::REGISTER(search_register(modrm.reg_op, Register_Type::XMM, Register_Size::_128, None).unwrap())),
        ),

        Opcode_Operand_ModRM::Vy => Ok(
            Some(Instruction_Operand::REGISTER(search_register(modrm.reg_op, 
            match operand_override {
                true => Register_Type::XMM,
                false => Register_Type::YMM,
            }, match operand_override {
                true => Register_Size::_128,
                false => Register_Size::_256,
            },

            None
        ).unwrap()))),

        Opcode_Operand_ModRM::Wx => Ok(Some(lookup_32_effective_address(reader, modrm, add_size, 
    match operand_override {
                true => Register_Size::_128,
                false => Register_Size::_256,
            },
            match operand_override {
                true => Register_Type::XMM,
                false => Register_Type::YMM,
            }, 
            &None)?
        )),

        Opcode_Operand_ModRM::Wps => Ok(Some(lookup_32_effective_address(reader, modrm, add_size, 
    match operand_override {
                true => Register_Size::_128,
                false => Register_Size::_256,
            },
            match operand_override {
                true => Register_Type::XMM,
                false => Register_Type::YMM,
            }, 
            &None)?
        )),

        Opcode_Operand_ModRM::Wss => Ok(Some(lookup_32_effective_address(reader, modrm, add_size, 
            Register_Size::_128,
            Register_Type::XMM,
            &None)?
        )),

        Opcode_Operand_ModRM::Wsd => Ok(Some(lookup_32_effective_address(reader, modrm, add_size, 
            Register_Size::_128,
            Register_Type::XMM,
            &None)?
        )),

        Opcode_Operand_ModRM::Wpd => Ok(Some(lookup_32_effective_address(reader, modrm, add_size, 
    match operand_override {
                true => Register_Size::_128,
                false => Register_Size::_256,
            },
            match operand_override {
                true => Register_Type::XMM,
                false => Register_Type::YMM,
            }, 
            &None)?
        )),

        Opcode_Operand_ModRM::Wq => Ok(Some(lookup_32_effective_address(reader, modrm, add_size, 
            Register_Size::_128,
            Register_Type::XMM,
            &None)?
        )),

        Opcode_Operand_ModRM::Wdq => Ok(Some(lookup_32_effective_address(reader, modrm, add_size, 
            Register_Size::_128,
            Register_Type::XMM,
            &None)?
        )),

        Opcode_Operand_ModRM::Ux => Ok(
            Some(Instruction_Operand::REGISTER(search_register(modrm.rm,
                match operand_override {
                true => Register_Type::XMM,
                false => Register_Type::YMM,
            }, match operand_override {
                true => Register_Size::_128,
                false => Register_Size::_256,
            }, None).unwrap()))
        ),

        Opcode_Operand_ModRM::Ups => Ok(
            Some(Instruction_Operand::REGISTER(search_register(modrm.rm, 
                match operand_override {
                true => Register_Type::XMM,
                false => Register_Type::YMM,
            }, match operand_override {
                true => Register_Size::_128,
                false => Register_Size::_256,
            }, None).unwrap()))
        ),

        Opcode_Operand_ModRM::Upd => Ok(
            Some(Instruction_Operand::REGISTER(search_register(modrm.rm, 
                match operand_override {
                true => Register_Type::XMM,
                false => Register_Type::YMM,
            }, match operand_override {
                true => Register_Size::_128,
                false => Register_Size::_256,
            }, None).unwrap()))
        ),

        Opcode_Operand_ModRM::Uq => Ok(
            Some(Instruction_Operand::REGISTER(search_register(modrm.rm, Register_Type::XMM, Register_Size::_128, None).unwrap())),
        ),

        Opcode_Operand_ModRM::Udq => Ok(
            Some(Instruction_Operand::REGISTER(search_register(modrm.rm, Register_Type::XMM, Register_Size::_128, None).unwrap())),
        ),
    }
}

pub fn read_inst(mode: InstMode, reader: &mut MyReader) -> std::io::Result<Instruction>
{
    let start_pos = reader.cursor;

    let inst_prefix: Inst_Prefix = {
        let mut prefix = Prefix_Acc {
            group1: None,
            group2: None,
            group3: None,
            group4: None,
        };

        // TODO account for multiple prefix error here
        // Collect the prefix bytes
        while prefix.add_prefix(reader.peek_byte()?).is_ok() {
            reader.take_byte()?;
        };

        match reader.peek_byte()?
        {
            0xc4 => {
                reader.take_byte()?;
                parse_vex_prefix_two_byte(reader.take_byte()?, prefix)?
            }

            0xc5 => {
                reader.take_byte()?;
                parse_vex_prefix_three_byte(reader.take_byte()?, reader.take_byte()?, prefix)?
            }

            _ => {
                // Read the (possible) rex prefix
                let rex = match (parse_rex_prefix(reader.peek_byte()?), mode)
                {
                    (Some (rex), InstMode::x64) => {
                        reader.take_byte()?;
                        Some(rex)
                    },

                    _ => None
                };

                let opcode_map = match reader.peek_byte()?
                {
                    0x0F => {
                        reader.take_byte()?;
                        match reader.peek_byte()?
                        {
                            0x38 => {
                                reader.take_byte()?;
                                Opcode_Map::THREE_BYTE_38
                            },

                            0x3A => {
                                reader.take_byte()?;
                                Opcode_Map::THREE_BYTE_3A
                            },

                            _    => Opcode_Map::TWO_BYTE
                        }
                    },

                    _ => Opcode_Map::ONE_BYTE,
                };

                Inst_Prefix {
                    prefixes: prefix,
                    rex: rex,
                    vex: None,
                    opcode_map: opcode_map,
                }
            }
        }
    };

    let opcode: u8 = reader.take_byte()?;
    let operand_override = match inst_prefix.prefixes.group3 {
        Some(Prefix_Group3::Operand_Override_66) => true,
        _ => false,
    };
    let address_override = match inst_prefix.prefixes.group4 {
        Some(Prefix_Group4::Address_Override_67) => true,
        _ => false,
    };

    let (res, mut mod_rm_byte) : (Opcode_Table_Result, Option<ModRMByte>) = {
        // hypothetical ModRMByte. Needed for AVX instruction to check if using register or memory
        // operation. (0x02: vmovlps and vmovhlps, cause this)
        let test_mod_rm_byte: Option<ModRMByte> = match reader.peek_byte()
        {
            Ok(val) => Some(ModRMByte::new(val)),
            Err(..) => None
        };

        let rex_w = match inst_prefix.rex {
            Some(rex) => rex.w,
            _ => false,
        };

        match inst_prefix.opcode_map {
            Opcode_Map::ONE_BYTE => {
                if let Some(inst) = search_opcode_one_byte(opcode, mode, operand_override, address_override, rex_w) {
                    // take the modrm byte if it was used
                    (inst, 
                        match inst.operands.iter().any(|&x| match x { Some(Opcode_Operand::MODRM_BYTE(..)) => true, _ => false })
                        {
                            true  => { reader.take_byte()?; test_mod_rm_byte },
                            false => None,
                        })
                } else if let Some(inst) = search_opcode_one_byte_extention(mode, opcode, test_mod_rm_byte.as_ref().unwrap()) {
                    // take the modrm byte since it is required
                    reader.take_byte()?;
                    (inst, test_mod_rm_byte)
                } else if let Some(inst) = search_opcode_one_byte_float(opcode, test_mod_rm_byte.as_ref().unwrap()) {
                    // take the modrm byte since it is required
                    reader.take_byte()?;
                    (inst, test_mod_rm_byte)
                } else {
                    return Err(std::io::Error::from(std::io::ErrorKind::NotFound));
                }
            }

            Opcode_Map::TWO_BYTE => {
                if let Some(inst) = search_opcode_two_byte(opcode, mode, &inst_prefix, test_mod_rm_byte.as_ref().unwrap(), rex_w) {
                    (inst, 
                        match inst.operands.iter().any(|&x| match x { Some(Opcode_Operand::MODRM_BYTE(..)) => true, _ => false })
                        {
                            true  => { reader.take_byte()?; test_mod_rm_byte },
                            false => None,
                        })
                } else {
                    return Err(std::io::Error::from(std::io::ErrorKind::NotFound));
                }
            },

            _ => { return Err(std::io::Error::from(std::io::ErrorKind::NotFound)); }
        }

        // match search_opcode_one_byte(opcode, mode, operand_override, address_override, rex_w)
        // {
        //     None =>
        //     {
        //         match search_opcode_one_byte_extention(mode, opcode, test_mod_rm_byte.as_ref().unwrap())
        //         {
        //             // Here, the ModRM byte is required, thus it must exist and the byte is claimed
        //             Some (ins) => {reader.take_byte()?; (ins, test_mod_rm_byte)},
        //             None => match search_opcode_one_byte_float(mode, opcode, test_mod_rm_byte.as_ref().unwrap())
        //             {
        //                 // these floating point instructions all have a modrm byte
        //                 Some (ins) => {reader.take_byte()?; (ins, test_mod_rm_byte)},
        //                 None => { return Err(std::io::Error::from(std::io::ErrorKind::NotFound)); }
        //             }
        //         }
        //     }

        //     // finalize the modrm optional by checking if any operand ended up needing it. If not, make it None.
        //     // If any operand ended up needing the ModRM, claim the byte in the byte stream
        //     Some(res) => (res, 
        //         match res.operands.iter().any(|&x| match x { Some(Opcode_Operand::MODRM_BYTE(..)) => true, _ => false })
        //         {
        //             true  => { reader.take_byte()?; test_mod_rm_byte },
        //             false => None,
        //         }
        //     ),
        // }
    };

    let mut operands: [Option<Instruction_Operand>; 4] = [None, None, None, None];

    // parse the MODRM byte operands first
    for i in 0..4
    {
        match res.operands[i]
        {
            Some(Opcode_Operand::MODRM_BYTE(op)) => 
            {
                if mod_rm_byte.is_none()
                {
                    mod_rm_byte = Some(ModRMByte::new(reader.take_byte()?));
                }

                operands[i] = handle_modrm_operand(reader, mode, op, mod_rm_byte.as_ref().unwrap(), operand_override, address_override, &inst_prefix.rex, &inst_prefix.vex)?
            },

            Some(Opcode_Operand::imm_one) =>
            {
                operands[i] = Some(Instruction_Operand::IMM_8(1));
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
                let op_size = match (mode, operand_override, &inst_prefix.rex) 
                {
                    (_, _, Some(Rex_Prefix { .. })) => Register_Size::_64,
                    (_, false, None) => Register_Size::_32,
                    (_, true, None) => Register_Size::_16,
                };

                // let add_size = match (mode, address_override, &inst_prefix.rex) 
                // {
                //     (InstMode::x64, true,  Some(Rex_Prefix { w: true, .. })) => Register_Size::_32,
                //     (InstMode::x64, false, Some(Rex_Prefix { w: true, .. })) => Register_Size::_64,

                //     (InstMode::x64, true,  Some(Rex_Prefix { w: false, .. })) | (InstMode::x64, true, None)  => Register_Size::_32,
                //     (InstMode::x64, false, Some(Rex_Prefix { w: false, .. })) | (InstMode::x64, false, None) => Register_Size::_64,

                //     (InstMode::x32, false, _) => Register_Size::_32,
                //     (InstMode::x32, true,  _) => Register_Size::_16,
                // };

                match op
                {
                    Opcode_Operand_Dis::Jb => operands[i] = Some(Instruction_Operand::IMM_8(bytes_to_int(reader.take_bytes(1)?) as i8)),
                    Opcode_Operand_Dis::Jz => operands[i] = Some(
                    match op_size
                    {
                        Register_Size::_64 => Instruction_Operand::IMM_32(bytes_to_int(reader.take_bytes(4)?) as i32),
                        Register_Size::_32 => Instruction_Operand::IMM_32(bytes_to_int(reader.take_bytes(4)?) as i32),
                        Register_Size::_16 => Instruction_Operand::IMM_16(bytes_to_int(reader.take_bytes(2)?) as i16),
                        _ => { return Err(std::io::Error::from(std::io::ErrorKind::NotFound)); }
                    }),

                    Opcode_Operand_Dis::Ob => operands[i] = Some(Instruction_Operand::DREF(Dref { base: None, index: None, scale: 0, disp: bytes_to_int(reader.take_bytes(1)?), res_size: op_size })),
                    Opcode_Operand_Dis::Ov => operands[i] = Some(Instruction_Operand::DREF(Dref { base: None, index: None, scale: 0, disp: 
                        match op_size
                        {
                            Register_Size::_64 => bytes_to_int(reader.take_bytes(8)?),
                            Register_Size::_32 => bytes_to_int(reader.take_bytes(4)?),
                            Register_Size::_16 => bytes_to_int(reader.take_bytes(2)?),
                            _ => { return Err(std::io::Error::from(std::io::ErrorKind::NotFound)); }
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
                let op_size = match (mode, operand_override, &inst_prefix.rex) 
                {
                    (_, _, Some(Rex_Prefix { .. })) => Register_Size::_64,
                    (_, false, None) => Register_Size::_32,
                    (_, true, None) => Register_Size::_16,
                };

                operands[i] = Some(match imm 
                {
                    Opcode_Operand_Imm::Ib => Instruction_Operand::IMM_8(bytes_to_int(reader.take_bytes(1)?) as i8),
                    Opcode_Operand_Imm::Iw => Instruction_Operand::IMM_16(bytes_to_int(reader.take_bytes(2)?) as i16),

                    Opcode_Operand_Imm::Iv => {
                        match op_size
                        {
                            Register_Size::_64 => Instruction_Operand::IMM_64(bytes_to_int(reader.take_bytes(8)?) as i64),
                            Register_Size::_32 => Instruction_Operand::IMM_32(bytes_to_int(reader.take_bytes(4)?) as i32),
                            Register_Size::_16 => Instruction_Operand::IMM_16(bytes_to_int(reader.take_bytes(2)?) as i16),
                            _ => { return Err(std::io::Error::from(std::io::ErrorKind::NotFound)); }
                        }
                    },

                    Opcode_Operand_Imm::Iz => 
                    {
                        match op_size
                        {
                            Register_Size::_64 => Instruction_Operand::IMM_32(bytes_to_int(reader.take_bytes(4)?) as i32),
                            Register_Size::_32 => Instruction_Operand::IMM_32(bytes_to_int(reader.take_bytes(4)?) as i32),
                            Register_Size::_16 => Instruction_Operand::IMM_16(bytes_to_int(reader.take_bytes(2)?) as i16),
                            _ => { return Err(std::io::Error::from(std::io::ErrorKind::NotFound)); }
                        }
                    },
                });
            }
            
            _ => ()
        }
    }

    for i in 0..4
    {
        let op_size = match (mode, operand_override, &inst_prefix.rex) 
        {
            (_, _, Some(Rex_Prefix { .. })) => Register_Size::_64,
            (_, false, None) => Register_Size::_32,
            (_, true, None) => Register_Size::_16,
        };

        let d64_size = match (mode, operand_override, &inst_prefix.rex)
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
                let r = match inst_prefix.rex.as_ref()
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

            Some(Opcode_Operand::Yv) => operands[i] = Some(Instruction_Operand::DREF(Dref { 
                base: Some(size_register(Register_Unsized::eDI, op_size)?), 
                index: None, 
                scale: 1, 
                disp: 0, 
                res_size: op_size,
            })),

            Some(Opcode_Operand::Yb) => operands[i] = Some(Instruction_Operand::DREF(Dref { 
                base: Some(size_register(Register_Unsized::eDI, op_size)?), 
                index: None, 
                scale: 1, 
                disp: 0, 
                res_size: Register_Size::_8,
            })),

            Some(Opcode_Operand::IMM_BYTES(..)) => (),
            Some(Opcode_Operand::MODRM_BYTE(..)) => (),
            Some(Opcode_Operand::DIS_BYTES(..)) => (),
            None => (),

            _ => (),
        }
    }

    let mut write_index = 0;
    for read_index in 0..operands.len() {
        if let Some(val) = operands[read_index] {
            operands[write_index] = Some(val);
            if write_index != read_index {
                operands[read_index] = None;
            }
            write_index += 1;
        }
    }

    return Ok(Instruction { name: res.instruction, byte_len: (reader.cursor - start_pos) as u32, operands });
}