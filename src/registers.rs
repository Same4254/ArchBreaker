#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum Register_Size
{
    _8, _16, _32, _64, _80, _128, _256
}

#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum Register_Type
{
    GP, x87, MMX, XMM, YMM, 
    SEG, CON, DEB
}

#[derive(Debug, Copy, Clone)]
pub struct Register
{
    pub name: &'static str,
    pub ty:   Register_Type,
    pub size: Register_Size,
}

impl std::fmt::Display for Register {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

macro_rules! declare_regs 
{
    (
        $(($code1:expr, $code2:expr, $reg_name:ident, $size:ident, $type:ident)),+
        $(,)?
    ) => {
        $(
            pub const $reg_name: Register = Register {
                name: stringify!($reg_name),
                ty:   Register_Type::$type,
                size: Register_Size::$size,
            };
        )+

        pub fn search_register(byte: u8, ty: Register_Type, size: Register_Size, rex_override: Option<bool>) -> Option<Register>
        {
            let mod_byte = match rex_override
            {
                Some (true) => byte | (1 << 3),
                _ => byte
            };

            let x = (mod_byte, ty, size, rex_override);

            match x 
            {
                // hardcoded cases based on the presence of REX prefix
                (0b0100, Register_Type::GP, Register_Size::_8, Some(..))  => return Ok(SPL),
                (0b0100, Register_Type::GP, Register_Size::_8, None) => return Ok(AH),
                (0b0101, Register_Type::GP, Register_Size::_8, Some(..))  => return Ok(BPL),
                (0b0101, Register_Type::GP, Register_Size::_8, None) => return Ok(CH),
                (0b0110, Register_Type::GP, Register_Size::_8, Some(..))  => return Ok(SIL),
                (0b0110, Register_Type::GP, Register_Size::_8, None) => return Ok(DH),
                (0b0111, Register_Type::GP, Register_Size::_8, Some(..))  => return Ok(DIL),
                (0b0111, Register_Type::GP, Register_Size::_8, None) => return Ok(BH),
                _ =>
                    match x
                    {
                        $(
                            ($code1 | $code2, Register_Type::$type, Register_Size::$size, _) => Ok($reg_name),
                        )+

                        _ => None
                    }
            }
        }
    };
}

// declare_regs!(
//     // 8 bit GP
//     (0b0000, 0b0000, AL, _8, GP),
//     (0b0001, 0b0001, CL, _8, GP),
//     (0b0010, 0b0010, DL, _8, GP),
//     (0b0011, 0b0011, BL, _8, GP),
// 
//     (0b0100, 0b0100, AH, _8, GP),
//     (0b0101, 0b0101, CH, _8, GP),
//     (0b0110, 0b0110, DH, _8, GP),
//     (0b0111, 0b0111, BH, _8, GP),
// 
//     (0b0100, 0b0100, SPL, _8, GP),
//     (0b0101, 0b0101, BPL, _8, GP),
//     (0b0110, 0b0110, SIL, _8, GP),
//     (0b0111, 0b0111, DIL, _8, GP),
// 
//     (0b1000, 0b1000, R8L , _8, GP),
//     (0b1001, 0b1001, R9L , _8, GP),
//     (0b1010, 0b1010, R10L, _8, GP),
//     (0b1011, 0b1011, R11L, _8, GP),
//     (0b1100, 0b1100, R12L, _8, GP),
//     (0b1101, 0b1101, R13L, _8, GP),
//     (0b1110, 0b1110, R14L, _8, GP),
//     (0b1111, 0b1111, R15L, _8, GP),
// 
//     // 16 bit GP
//     (0b0000, 0b0000, AX  , _16, GP),
//     (0b0001, 0b0001, CX  , _16, GP),
//     (0b0010, 0b0010, DX  , _16, GP),
//     (0b0011, 0b0011, BX  , _16, GP),
//     (0b0100, 0b0100, SP  , _16, GP),
//     (0b0101, 0b0101, BP  , _16, GP),
//     (0b0110, 0b0110, SI  , _16, GP),
//     (0b0111, 0b0111, DI  , _16, GP),
//     (0b1000, 0b1000, R8W , _16, GP),
//     (0b1001, 0b1001, R9W , _16, GP),
//     (0b1010, 0b1010, R10W, _16, GP),
//     (0b1011, 0b1011, R11W, _16, GP),
//     (0b1100, 0b1100, R12W, _16, GP),
//     (0b1101, 0b1101, R13W, _16, GP),
//     (0b1110, 0b1110, R14W, _16, GP),
//     (0b1111, 0b1111, R15W, _16, GP),
// 
//     // 32 bit GP
//     (0b0000, 0b0000, EAX , _32, GP),
//     (0b0001, 0b0001, ECX , _32, GP),
//     (0b0010, 0b0010, EDX , _32, GP),
//     (0b0011, 0b0011, EBX , _32, GP),
//     (0b0100, 0b0100, ESP , _32, GP),
//     (0b0101, 0b0101, EBP , _32, GP),
//     (0b0110, 0b0110, ESI , _32, GP),
//     (0b0111, 0b0111, EDI , _32, GP),
//     (0b1000, 0b1000, R8D , _32, GP),
//     (0b1001, 0b1001, R9D , _32, GP),
//     (0b1010, 0b1010, R10D, _32, GP),
//     (0b1011, 0b1011, R11D, _32, GP),
//     (0b1100, 0b1100, R12D, _32, GP),
//     (0b1101, 0b1101, R13D, _32, GP),
//     (0b1110, 0b1110, R14D, _32, GP),
//     (0b1111, 0b1111, R15D, _32, GP),
// 
//     // 64 bit GP
//     (0b0000, 0b0000, RAX, _64, GP),
//     (0b0001, 0b0001, RCX, _64, GP),
//     (0b0010, 0b0010, RDX, _64, GP),
//     (0b0011, 0b0011, RBX, _64, GP),
//     (0b0100, 0b0100, RSP, _64, GP),
//     (0b0101, 0b0101, RBP, _64, GP),
//     (0b0110, 0b0110, RSI, _64, GP),
//     (0b0111, 0b0111, RDI, _64, GP),
//     (0b1000, 0b1000, R8 , _64, GP),
//     (0b1001, 0b1001, R9 , _64, GP),
//     (0b1010, 0b1010, R10, _64, GP),
//     (0b1011, 0b1011, R11, _64, GP),
//     (0b1100, 0b1100, R12, _64, GP),
//     (0b1101, 0b1101, R13, _64, GP),
//     (0b1110, 0b1110, R14, _64, GP),
//     (0b1111, 0b1111, R15, _64, GP),
// 
//     // 80 bit x87
//     (0b0000, 0b0000, ST0, _80, x87),
//     (0b0001, 0b0001, ST1, _80, x87),
//     (0b0010, 0b0010, ST2, _80, x87),
//     (0b0011, 0b0011, ST3, _80, x87),
//     (0b0100, 0b0100, ST4, _80, x87),
//     (0b0101, 0b0101, ST5, _80, x87),
//     (0b0110, 0b0110, ST6, _80, x87),
//     (0b0111, 0b0111, ST7, _80, x87),
// 
//     // 64 bit MMX
//     (0b0000, 0b1000, MMX0, _64, MMX),
//     (0b0001, 0b1001, MMX1, _64, MMX),
//     (0b0010, 0b1010, MMX2, _64, MMX),
//     (0b0011, 0b1011, MMX3, _64, MMX),
//     (0b0100, 0b1100, MMX4, _64, MMX),
//     (0b0101, 0b1101, MMX5, _64, MMX),
//     (0b0110, 0b1110, MMX6, _64, MMX),
//     (0b0111, 0b1111, MMX7, _64, MMX),
//     // (0b1000, MMX0, _64, MMX),
//     // (0b1001, MMX1, _64, MMX),
//     // (0b1010, MMX2, _64, MMX),
//     // (0b1011, MMX3, _64, MMX),
//     // (0b1100, MMX4, _64, MMX),
//     // (0b1101, MMX5, _64, MMX),
//     // (0b1110, MMX6, _64, MMX),
//     // (0b1111, MMX7, _64, MMX),
// 
//     // 128 bit XMM
//     (0b0000, 0b0000, XMM0,  _128, XMM),
//     (0b0001, 0b0001, XMM1,  _128, XMM),
//     (0b0010, 0b0010, XMM2,  _128, XMM),
//     (0b0011, 0b0011, XMM3,  _128, XMM),
//     (0b0100, 0b0100, XMM4,  _128, XMM),
//     (0b0101, 0b0101, XMM5,  _128, XMM),
//     (0b0110, 0b0110, XMM6,  _128, XMM),
//     (0b0111, 0b0111, XMM7,  _128, XMM),
//     (0b1000, 0b1000, XMM8,  _128, XMM),
//     (0b1001, 0b1001, XMM9,  _128, XMM),
//     (0b1010, 0b1010, XMM10, _128, XMM),
//     (0b1011, 0b1011, XMM11, _128, XMM),
//     (0b1100, 0b1100, XMM12, _128, XMM),
//     (0b1101, 0b1101, XMM13, _128, XMM),
//     (0b1110, 0b1110, XMM14, _128, XMM),
//     (0b1111, 0b1111, XMM15, _128, XMM),
// 
//     // 256 bit YMM
//     (0b0000, 0b0000, YMM0,  _256, YMM),
//     (0b0001, 0b0001, YMM1,  _256, YMM),
//     (0b0010, 0b0010, YMM2,  _256, YMM),
//     (0b0011, 0b0011, YMM3,  _256, YMM),
//     (0b0100, 0b0100, YMM4,  _256, YMM),
//     (0b0101, 0b0101, YMM5,  _256, YMM),
//     (0b0110, 0b0110, YMM6,  _256, YMM),
//     (0b0111, 0b0111, YMM7,  _256, YMM),
//     (0b1000, 0b1000, YMM8,  _256, YMM),
//     (0b1001, 0b1001, YMM9,  _256, YMM),
//     (0b1010, 0b1010, YMM10, _256, YMM),
//     (0b1011, 0b1011, YMM11, _256, YMM),
//     (0b1100, 0b1100, YMM12, _256, YMM),
//     (0b1101, 0b1101, YMM13, _256, YMM),
//     (0b1110, 0b1110, YMM14, _256, YMM),
//     (0b1111, 0b1111, YMM15, _256, YMM),
// 
//     // 16 bit Segment
//     (0b0000, 0b1000, ES,  _16, SEG),
//     (0b0001, 0b1001, CS,  _16, SEG),
//     (0b0010, 0b1010, SS,  _16, SEG),
//     (0b0011, 0b1011, DS,  _16, SEG),
//     (0b0100, 0b1100, FS,  _16, SEG),
//     (0b0101, 0b1101, GS,  _16, SEG),
// 
//     // 32 bit Control
//     (0b0000, 0b0000, CR0 , _32, CON),
//     (0b0001, 0b0001, CR1 , _32, CON),
//     (0b0010, 0b0010, CR2 , _32, CON),
//     (0b0011, 0b0011, CR3 , _32, CON),
//     (0b0100, 0b0100, CR4 , _32, CON),
//     (0b0101, 0b0101, CR5 , _32, CON),
//     (0b0110, 0b0110, CR6 , _32, CON),
//     (0b0111, 0b0111, CR7 , _32, CON),
//     (0b1000, 0b1000, CR8 , _32, CON),
//     (0b1001, 0b1001, CR9 , _32, CON),
//     (0b1010, 0b1010, CR10, _32, CON),
//     (0b1011, 0b1011, CR11, _32, CON),
//     (0b1100, 0b1100, CR12, _32, CON),
//     (0b1101, 0b1101, CR13, _32, CON),
//     (0b1110, 0b1110, CR14, _32, CON),
//     (0b1111, 0b1111, CR15, _32, CON),
// 
//     // 32 bit Debug
//     (0b0000, 0b0000, DR0 , _32, DEB),
//     (0b0001, 0b0001, DR1 , _32, DEB),
//     (0b0010, 0b0010, DR2 , _32, DEB),
//     (0b0011, 0b0011, DR3 , _32, DEB),
//     (0b0100, 0b0100, DR4 , _32, DEB),
//     (0b0101, 0b0101, DR5 , _32, DEB),
//     (0b0110, 0b0110, DR6 , _32, DEB),
//     (0b0111, 0b0111, DR7 , _32, DEB),
//     (0b1000, 0b1000, DR8 , _32, DEB),
//     (0b1001, 0b1001, DR9 , _32, DEB),
//     (0b1010, 0b1010, DR10, _32, DEB),
//     (0b1011, 0b1011, DR11, _32, DEB),
//     (0b1100, 0b1100, DR12, _32, DEB),
//     (0b1101, 0b1101, DR13, _32, DEB),
//     (0b1110, 0b1110, DR14, _32, DEB)
// );
pub const AL: Register = Register {
    name: "AL",
    ty: Register_Type::GP,
    size: Register_Size::_8,
};
pub const CL: Register = Register {
    name: "CL",
    ty: Register_Type::GP,
    size: Register_Size::_8,
};
pub const DL: Register = Register {
    name: "DL",
    ty: Register_Type::GP,
    size: Register_Size::_8,
};
pub const BL: Register = Register {
    name: "BL",
    ty: Register_Type::GP,
    size: Register_Size::_8,
};
pub const AH: Register = Register {
    name: "AH",
    ty: Register_Type::GP,
    size: Register_Size::_8,
};
pub const CH: Register = Register {
    name: "CH",
    ty: Register_Type::GP,
    size: Register_Size::_8,
};
pub const DH: Register = Register {
    name: "DH",
    ty: Register_Type::GP,
    size: Register_Size::_8,
};
pub const BH: Register = Register {
    name: "BH",
    ty: Register_Type::GP,
    size: Register_Size::_8,
};
pub const SPL: Register = Register {
    name: "SPL",
    ty: Register_Type::GP,
    size: Register_Size::_8,
};
pub const BPL: Register = Register {
    name: "BPL",
    ty: Register_Type::GP,
    size: Register_Size::_8,
};
pub const SIL: Register = Register {
    name: "SIL",
    ty: Register_Type::GP,
    size: Register_Size::_8,
};
pub const DIL: Register = Register {
    name: "DIL",
    ty: Register_Type::GP,
    size: Register_Size::_8,
};
pub const R8L: Register = Register {
    name: "R8L",
    ty: Register_Type::GP,
    size: Register_Size::_8,
};
pub const R9L: Register = Register {
    name: "R9L",
    ty: Register_Type::GP,
    size: Register_Size::_8,
};
pub const R10L: Register = Register {
    name: "R10L",
    ty: Register_Type::GP,
    size: Register_Size::_8,
};
pub const R11L: Register = Register {
    name: "R11L",
    ty: Register_Type::GP,
    size: Register_Size::_8,
};
pub const R12L: Register = Register {
    name: "R12L",
    ty: Register_Type::GP,
    size: Register_Size::_8,
};
pub const R13L: Register = Register {
    name: "R13L",
    ty: Register_Type::GP,
    size: Register_Size::_8,
};
pub const R14L: Register = Register {
    name: "R14L",
    ty: Register_Type::GP,
    size: Register_Size::_8,
};
pub const R15L: Register = Register {
    name: "R15L",
    ty: Register_Type::GP,
    size: Register_Size::_8,
};
pub const AX: Register = Register {
    name: "AX",
    ty: Register_Type::GP,
    size: Register_Size::_16,
};
pub const CX: Register = Register {
    name: "CX",
    ty: Register_Type::GP,
    size: Register_Size::_16,
};
pub const DX: Register = Register {
    name: "DX",
    ty: Register_Type::GP,
    size: Register_Size::_16,
};
pub const BX: Register = Register {
    name: "BX",
    ty: Register_Type::GP,
    size: Register_Size::_16,
};
pub const SP: Register = Register {
    name: "SP",
    ty: Register_Type::GP,
    size: Register_Size::_16,
};
pub const BP: Register = Register {
    name: "BP",
    ty: Register_Type::GP,
    size: Register_Size::_16,
};
pub const SI: Register = Register {
    name: "SI",
    ty: Register_Type::GP,
    size: Register_Size::_16,
};
pub const DI: Register = Register {
    name: "DI",
    ty: Register_Type::GP,
    size: Register_Size::_16,
};
pub const R8W: Register = Register {
    name: "R8W",
    ty: Register_Type::GP,
    size: Register_Size::_16,
};
pub const R9W: Register = Register {
    name: "R9W",
    ty: Register_Type::GP,
    size: Register_Size::_16,
};
pub const R10W: Register = Register {
    name: "R10W",
    ty: Register_Type::GP,
    size: Register_Size::_16,
};
pub const R11W: Register = Register {
    name: "R11W",
    ty: Register_Type::GP,
    size: Register_Size::_16,
};
pub const R12W: Register = Register {
    name: "R12W",
    ty: Register_Type::GP,
    size: Register_Size::_16,
};
pub const R13W: Register = Register {
    name: "R13W",
    ty: Register_Type::GP,
    size: Register_Size::_16,
};
pub const R14W: Register = Register {
    name: "R14W",
    ty: Register_Type::GP,
    size: Register_Size::_16,
};
pub const R15W: Register = Register {
    name: "R15W",
    ty: Register_Type::GP,
    size: Register_Size::_16,
};
pub const EAX: Register = Register {
    name: "EAX",
    ty: Register_Type::GP,
    size: Register_Size::_32,
};
pub const ECX: Register = Register {
    name: "ECX",
    ty: Register_Type::GP,
    size: Register_Size::_32,
};
pub const EDX: Register = Register {
    name: "EDX",
    ty: Register_Type::GP,
    size: Register_Size::_32,
};
pub const EBX: Register = Register {
    name: "EBX",
    ty: Register_Type::GP,
    size: Register_Size::_32,
};
pub const ESP: Register = Register {
    name: "ESP",
    ty: Register_Type::GP,
    size: Register_Size::_32,
};
pub const EBP: Register = Register {
    name: "EBP",
    ty: Register_Type::GP,
    size: Register_Size::_32,
};
pub const ESI: Register = Register {
    name: "ESI",
    ty: Register_Type::GP,
    size: Register_Size::_32,
};
pub const EDI: Register = Register {
    name: "EDI",
    ty: Register_Type::GP,
    size: Register_Size::_32,
};
pub const R8D: Register = Register {
    name: "R8D",
    ty: Register_Type::GP,
    size: Register_Size::_32,
};
pub const R9D: Register = Register {
    name: "R9D",
    ty: Register_Type::GP,
    size: Register_Size::_32,
};
pub const R10D: Register = Register {
    name: "R10D",
    ty: Register_Type::GP,
    size: Register_Size::_32,
};
pub const R11D: Register = Register {
    name: "R11D",
    ty: Register_Type::GP,
    size: Register_Size::_32,
};
pub const R12D: Register = Register {
    name: "R12D",
    ty: Register_Type::GP,
    size: Register_Size::_32,
};
pub const R13D: Register = Register {
    name: "R13D",
    ty: Register_Type::GP,
    size: Register_Size::_32,
};
pub const R14D: Register = Register {
    name: "R14D",
    ty: Register_Type::GP,
    size: Register_Size::_32,
};
pub const R15D: Register = Register {
    name: "R15D",
    ty: Register_Type::GP,
    size: Register_Size::_32,
};
pub const RAX: Register = Register {
    name: "RAX",
    ty: Register_Type::GP,
    size: Register_Size::_64,
};
pub const RCX: Register = Register {
    name: "RCX",
    ty: Register_Type::GP,
    size: Register_Size::_64,
};
pub const RDX: Register = Register {
    name: "RDX",
    ty: Register_Type::GP,
    size: Register_Size::_64,
};
pub const RBX: Register = Register {
    name: "RBX",
    ty: Register_Type::GP,
    size: Register_Size::_64,
};
pub const RSP: Register = Register {
    name: "RSP",
    ty: Register_Type::GP,
    size: Register_Size::_64,
};
pub const RBP: Register = Register {
    name: "RBP",
    ty: Register_Type::GP,
    size: Register_Size::_64,
};
pub const RSI: Register = Register {
    name: "RSI",
    ty: Register_Type::GP,
    size: Register_Size::_64,
};
pub const RDI: Register = Register {
    name: "RDI",
    ty: Register_Type::GP,
    size: Register_Size::_64,
};
pub const R8: Register = Register {
    name: "R8",
    ty: Register_Type::GP,
    size: Register_Size::_64,
};
pub const R9: Register = Register {
    name: "R9",
    ty: Register_Type::GP,
    size: Register_Size::_64,
};
pub const R10: Register = Register {
    name: "R10",
    ty: Register_Type::GP,
    size: Register_Size::_64,
};
pub const R11: Register = Register {
    name: "R11",
    ty: Register_Type::GP,
    size: Register_Size::_64,
};
pub const R12: Register = Register {
    name: "R12",
    ty: Register_Type::GP,
    size: Register_Size::_64,
};
pub const R13: Register = Register {
    name: "R13",
    ty: Register_Type::GP,
    size: Register_Size::_64,
};
pub const R14: Register = Register {
    name: "R14",
    ty: Register_Type::GP,
    size: Register_Size::_64,
};
pub const R15: Register = Register {
    name: "R15",
    ty: Register_Type::GP,
    size: Register_Size::_64,
};
pub const ST0: Register = Register {
    name: "ST0",
    ty: Register_Type::x87,
    size: Register_Size::_80,
};
pub const ST1: Register = Register {
    name: "ST1",
    ty: Register_Type::x87,
    size: Register_Size::_80,
};
pub const ST2: Register = Register {
    name: "ST2",
    ty: Register_Type::x87,
    size: Register_Size::_80,
};
pub const ST3: Register = Register {
    name: "ST3",
    ty: Register_Type::x87,
    size: Register_Size::_80,
};
pub const ST4: Register = Register {
    name: "ST4",
    ty: Register_Type::x87,
    size: Register_Size::_80,
};
pub const ST5: Register = Register {
    name: "ST5",
    ty: Register_Type::x87,
    size: Register_Size::_80,
};
pub const ST6: Register = Register {
    name: "ST6",
    ty: Register_Type::x87,
    size: Register_Size::_80,
};
pub const ST7: Register = Register {
    name: "ST7",
    ty: Register_Type::x87,
    size: Register_Size::_80,
};
pub const MMX0: Register = Register {
    name: "MMX0",
    ty: Register_Type::MMX,
    size: Register_Size::_64,
};
pub const MMX1: Register = Register {
    name: "MMX1",
    ty: Register_Type::MMX,
    size: Register_Size::_64,
};
pub const MMX2: Register = Register {
    name: "MMX2",
    ty: Register_Type::MMX,
    size: Register_Size::_64,
};
pub const MMX3: Register = Register {
    name: "MMX3",
    ty: Register_Type::MMX,
    size: Register_Size::_64,
};
pub const MMX4: Register = Register {
    name: "MMX4",
    ty: Register_Type::MMX,
    size: Register_Size::_64,
};
pub const MMX5: Register = Register {
    name: "MMX5",
    ty: Register_Type::MMX,
    size: Register_Size::_64,
};
pub const MMX6: Register = Register {
    name: "MMX6",
    ty: Register_Type::MMX,
    size: Register_Size::_64,
};
pub const MMX7: Register = Register {
    name: "MMX7",
    ty: Register_Type::MMX,
    size: Register_Size::_64,
};
pub const XMM0: Register = Register {
    name: "XMM0",
    ty: Register_Type::XMM,
    size: Register_Size::_128,
};
pub const XMM1: Register = Register {
    name: "XMM1",
    ty: Register_Type::XMM,
    size: Register_Size::_128,
};
pub const XMM2: Register = Register {
    name: "XMM2",
    ty: Register_Type::XMM,
    size: Register_Size::_128,
};
pub const XMM3: Register = Register {
    name: "XMM3",
    ty: Register_Type::XMM,
    size: Register_Size::_128,
};
pub const XMM4: Register = Register {
    name: "XMM4",
    ty: Register_Type::XMM,
    size: Register_Size::_128,
};
pub const XMM5: Register = Register {
    name: "XMM5",
    ty: Register_Type::XMM,
    size: Register_Size::_128,
};
pub const XMM6: Register = Register {
    name: "XMM6",
    ty: Register_Type::XMM,
    size: Register_Size::_128,
};
pub const XMM7: Register = Register {
    name: "XMM7",
    ty: Register_Type::XMM,
    size: Register_Size::_128,
};
pub const XMM8: Register = Register {
    name: "XMM8",
    ty: Register_Type::XMM,
    size: Register_Size::_128,
};
pub const XMM9: Register = Register {
    name: "XMM9",
    ty: Register_Type::XMM,
    size: Register_Size::_128,
};
pub const XMM10: Register = Register {
    name: "XMM10",
    ty: Register_Type::XMM,
    size: Register_Size::_128,
};
pub const XMM11: Register = Register {
    name: "XMM11",
    ty: Register_Type::XMM,
    size: Register_Size::_128,
};
pub const XMM12: Register = Register {
    name: "XMM12",
    ty: Register_Type::XMM,
    size: Register_Size::_128,
};
pub const XMM13: Register = Register {
    name: "XMM13",
    ty: Register_Type::XMM,
    size: Register_Size::_128,
};
pub const XMM14: Register = Register {
    name: "XMM14",
    ty: Register_Type::XMM,
    size: Register_Size::_128,
};
pub const XMM15: Register = Register {
    name: "XMM15",
    ty: Register_Type::XMM,
    size: Register_Size::_128,
};
pub const YMM0: Register = Register {
    name: "YMM0",
    ty: Register_Type::YMM,
    size: Register_Size::_256,
};
pub const YMM1: Register = Register {
    name: "YMM1",
    ty: Register_Type::YMM,
    size: Register_Size::_256,
};
pub const YMM2: Register = Register {
    name: "YMM2",
    ty: Register_Type::YMM,
    size: Register_Size::_256,
};
pub const YMM3: Register = Register {
    name: "YMM3",
    ty: Register_Type::YMM,
    size: Register_Size::_256,
};
pub const YMM4: Register = Register {
    name: "YMM4",
    ty: Register_Type::YMM,
    size: Register_Size::_256,
};
pub const YMM5: Register = Register {
    name: "YMM5",
    ty: Register_Type::YMM,
    size: Register_Size::_256,
};
pub const YMM6: Register = Register {
    name: "YMM6",
    ty: Register_Type::YMM,
    size: Register_Size::_256,
};
pub const YMM7: Register = Register {
    name: "YMM7",
    ty: Register_Type::YMM,
    size: Register_Size::_256,
};
pub const YMM8: Register = Register {
    name: "YMM8",
    ty: Register_Type::YMM,
    size: Register_Size::_256,
};
pub const YMM9: Register = Register {
    name: "YMM9",
    ty: Register_Type::YMM,
    size: Register_Size::_256,
};
pub const YMM10: Register = Register {
    name: "YMM10",
    ty: Register_Type::YMM,
    size: Register_Size::_256,
};
pub const YMM11: Register = Register {
    name: "YMM11",
    ty: Register_Type::YMM,
    size: Register_Size::_256,
};
pub const YMM12: Register = Register {
    name: "YMM12",
    ty: Register_Type::YMM,
    size: Register_Size::_256,
};
pub const YMM13: Register = Register {
    name: "YMM13",
    ty: Register_Type::YMM,
    size: Register_Size::_256,
};
pub const YMM14: Register = Register {
    name: "YMM14",
    ty: Register_Type::YMM,
    size: Register_Size::_256,
};
pub const YMM15: Register = Register {
    name: "YMM15",
    ty: Register_Type::YMM,
    size: Register_Size::_256,
};
pub const ES: Register = Register {
    name: "ES",
    ty: Register_Type::SEG,
    size: Register_Size::_16,
};
pub const CS: Register = Register {
    name: "CS",
    ty: Register_Type::SEG,
    size: Register_Size::_16,
};
pub const SS: Register = Register {
    name: "SS",
    ty: Register_Type::SEG,
    size: Register_Size::_16,
};
pub const DS: Register = Register {
    name: "DS",
    ty: Register_Type::SEG,
    size: Register_Size::_16,
};
pub const FS: Register = Register {
    name: "FS",
    ty: Register_Type::SEG,
    size: Register_Size::_16,
};
pub const GS: Register = Register {
    name: "GS",
    ty: Register_Type::SEG,
    size: Register_Size::_16,
};
pub const CR0: Register = Register {
    name: "CR0",
    ty: Register_Type::CON,
    size: Register_Size::_32,
};
pub const CR1: Register = Register {
    name: "CR1",
    ty: Register_Type::CON,
    size: Register_Size::_32,
};
pub const CR2: Register = Register {
    name: "CR2",
    ty: Register_Type::CON,
    size: Register_Size::_32,
};
pub const CR3: Register = Register {
    name: "CR3",
    ty: Register_Type::CON,
    size: Register_Size::_32,
};
pub const CR4: Register = Register {
    name: "CR4",
    ty: Register_Type::CON,
    size: Register_Size::_32,
};
pub const CR5: Register = Register {
    name: "CR5",
    ty: Register_Type::CON,
    size: Register_Size::_32,
};
pub const CR6: Register = Register {
    name: "CR6",
    ty: Register_Type::CON,
    size: Register_Size::_32,
};
pub const CR7: Register = Register {
    name: "CR7",
    ty: Register_Type::CON,
    size: Register_Size::_32,
};
pub const CR8: Register = Register {
    name: "CR8",
    ty: Register_Type::CON,
    size: Register_Size::_32,
};
pub const CR9: Register = Register {
    name: "CR9",
    ty: Register_Type::CON,
    size: Register_Size::_32,
};
pub const CR10: Register = Register {
    name: "CR10",
    ty: Register_Type::CON,
    size: Register_Size::_32,
};
pub const CR11: Register = Register {
    name: "CR11",
    ty: Register_Type::CON,
    size: Register_Size::_32,
};
pub const CR12: Register = Register {
    name: "CR12",
    ty: Register_Type::CON,
    size: Register_Size::_32,
};
pub const CR13: Register = Register {
    name: "CR13",
    ty: Register_Type::CON,
    size: Register_Size::_32,
};
pub const CR14: Register = Register {
    name: "CR14",
    ty: Register_Type::CON,
    size: Register_Size::_32,
};
pub const CR15: Register = Register {
    name: "CR15",
    ty: Register_Type::CON,
    size: Register_Size::_32,
};
pub const DR0: Register = Register {
    name: "DR0",
    ty: Register_Type::DEB,
    size: Register_Size::_32,
};
pub const DR1: Register = Register {
    name: "DR1",
    ty: Register_Type::DEB,
    size: Register_Size::_32,
};
pub const DR2: Register = Register {
    name: "DR2",
    ty: Register_Type::DEB,
    size: Register_Size::_32,
};
pub const DR3: Register = Register {
    name: "DR3",
    ty: Register_Type::DEB,
    size: Register_Size::_32,
};
pub const DR4: Register = Register {
    name: "DR4",
    ty: Register_Type::DEB,
    size: Register_Size::_32,
};
pub const DR5: Register = Register {
    name: "DR5",
    ty: Register_Type::DEB,
    size: Register_Size::_32,
};
pub const DR6: Register = Register {
    name: "DR6",
    ty: Register_Type::DEB,
    size: Register_Size::_32,
};
pub const DR7: Register = Register {
    name: "DR7",
    ty: Register_Type::DEB,
    size: Register_Size::_32,
};
pub const DR8: Register = Register {
    name: "DR8",
    ty: Register_Type::DEB,
    size: Register_Size::_32,
};
pub const DR9: Register = Register {
    name: "DR9",
    ty: Register_Type::DEB,
    size: Register_Size::_32,
};
pub const DR10: Register = Register {
    name: "DR10",
    ty: Register_Type::DEB,
    size: Register_Size::_32,
};
pub const DR11: Register = Register {
    name: "DR11",
    ty: Register_Type::DEB,
    size: Register_Size::_32,
};
pub const DR12: Register = Register {
    name: "DR12",
    ty: Register_Type::DEB,
    size: Register_Size::_32,
};
pub const DR13: Register = Register {
    name: "DR13",
    ty: Register_Type::DEB,
    size: Register_Size::_32,
};
pub const DR14: Register = Register {
    name: "DR14",
    ty: Register_Type::DEB,
    size: Register_Size::_32,
};
pub fn search_register(
    byte: u8,
    ty: Register_Type,
    size: Register_Size,
    rex_override: Option<bool>,
) -> std::io::Result<Register> {
    let mod_byte = match rex_override {
        Some(true) => byte | (1 << 3),
        _ => byte,
    };
    let x = (mod_byte, ty, size, rex_override);
    match x {
        (0b0100, Register_Type::GP, Register_Size::_8, Some(..)) => return Ok(SPL),
        (0b0100, Register_Type::GP, Register_Size::_8, None) => return Ok(AH),
        (0b0101, Register_Type::GP, Register_Size::_8, Some(..)) => return Ok(BPL),
        (0b0101, Register_Type::GP, Register_Size::_8, None) => return Ok(CH),
        (0b0110, Register_Type::GP, Register_Size::_8, Some(..)) => return Ok(SIL),
        (0b0110, Register_Type::GP, Register_Size::_8, None) => return Ok(DH),
        (0b0111, Register_Type::GP, Register_Size::_8, Some(..)) => return Ok(DIL),
        (0b0111, Register_Type::GP, Register_Size::_8, None) => return Ok(BH),
        _ => match x {
            (0b0000 /* | 0b0000 */, Register_Type::GP, Register_Size::_8, _) => Ok(AL),
            (0b0001 /* | 0b0001 */, Register_Type::GP, Register_Size::_8, _) => Ok(CL),
            (0b0010 /* | 0b0010 */, Register_Type::GP, Register_Size::_8, _) => Ok(DL),
            (0b0011 /* | 0b0011 */, Register_Type::GP, Register_Size::_8, _) => Ok(BL),
            (0b0100 /* | 0b0100 */, Register_Type::GP, Register_Size::_8, _) => Ok(AH),
            (0b0101 /* | 0b0101 */, Register_Type::GP, Register_Size::_8, _) => Ok(CH),
            (0b0110 /* | 0b0110 */, Register_Type::GP, Register_Size::_8, _) => Ok(DH),
            (0b0111 /* | 0b0111 */, Register_Type::GP, Register_Size::_8, _) => Ok(BH),
            // (0b0100 | 0b0100, Register_Type::GP, Register_Size::_8, _) => Some(SPL),
            // (0b0101 | 0b0101, Register_Type::GP, Register_Size::_8, _) => Some(BPL),
            // (0b0110 | 0b0110, Register_Type::GP, Register_Size::_8, _) => Some(SIL),
            // (0b0111 | 0b0111, Register_Type::GP, Register_Size::_8, _) => Some(DIL),
            (0b1000 /* | 0b1000 */, Register_Type::GP, Register_Size::_8, _) => Ok(R8L),
            (0b1001 /* | 0b1001 */, Register_Type::GP, Register_Size::_8, _) => Ok(R9L),
            (0b1010 /* | 0b1010 */, Register_Type::GP, Register_Size::_8, _) => Ok(R10L),
            (0b1011 /* | 0b1011 */, Register_Type::GP, Register_Size::_8, _) => Ok(R11L),
            (0b1100 /* | 0b1100 */, Register_Type::GP, Register_Size::_8, _) => Ok(R12L),
            (0b1101 /* | 0b1101 */, Register_Type::GP, Register_Size::_8, _) => Ok(R13L),
            (0b1110 /* | 0b1110 */, Register_Type::GP, Register_Size::_8, _) => Ok(R14L),
            (0b1111 /* | 0b1111 */, Register_Type::GP, Register_Size::_8, _) => Ok(R15L),
            (0b0000 /* | 0b0000 */, Register_Type::GP, Register_Size::_16, _) => Ok(AX),
            (0b0001 /* | 0b0001 */, Register_Type::GP, Register_Size::_16, _) => Ok(CX),
            (0b0010 /* | 0b0010 */, Register_Type::GP, Register_Size::_16, _) => Ok(DX),
            (0b0011 /* | 0b0011 */, Register_Type::GP, Register_Size::_16, _) => Ok(BX),
            (0b0100 /* | 0b0100 */, Register_Type::GP, Register_Size::_16, _) => Ok(SP),
            (0b0101 /* | 0b0101 */, Register_Type::GP, Register_Size::_16, _) => Ok(BP),
            (0b0110 /* | 0b0110 */, Register_Type::GP, Register_Size::_16, _) => Ok(SI),
            (0b0111 /* | 0b0111 */, Register_Type::GP, Register_Size::_16, _) => Ok(DI),
            (0b1000 /* | 0b1000 */, Register_Type::GP, Register_Size::_16, _) => Ok(R8W),
            (0b1001 /* | 0b1001 */, Register_Type::GP, Register_Size::_16, _) => Ok(R9W),
            (0b1010 /* | 0b1010 */, Register_Type::GP, Register_Size::_16, _) => Ok(R10W),
            (0b1011 /* | 0b1011 */, Register_Type::GP, Register_Size::_16, _) => Ok(R11W),
            (0b1100 /* | 0b1100 */, Register_Type::GP, Register_Size::_16, _) => Ok(R12W),
            (0b1101 /* | 0b1101 */, Register_Type::GP, Register_Size::_16, _) => Ok(R13W),
            (0b1110 /* | 0b1110 */, Register_Type::GP, Register_Size::_16, _) => Ok(R14W),
            (0b1111 /* | 0b1111 */, Register_Type::GP, Register_Size::_16, _) => Ok(R15W),
            (0b0000 /* | 0b0000 */, Register_Type::GP, Register_Size::_32, _) => Ok(EAX),
            (0b0001 /* | 0b0001 */, Register_Type::GP, Register_Size::_32, _) => Ok(ECX),
            (0b0010 /* | 0b0010 */, Register_Type::GP, Register_Size::_32, _) => Ok(EDX),
            (0b0011 /* | 0b0011 */, Register_Type::GP, Register_Size::_32, _) => Ok(EBX),
            (0b0100 /* | 0b0100 */, Register_Type::GP, Register_Size::_32, _) => Ok(ESP),
            (0b0101 /* | 0b0101 */, Register_Type::GP, Register_Size::_32, _) => Ok(EBP),
            (0b0110 /* | 0b0110 */, Register_Type::GP, Register_Size::_32, _) => Ok(ESI),
            (0b0111 /* | 0b0111 */, Register_Type::GP, Register_Size::_32, _) => Ok(EDI),
            (0b1000 /* | 0b1000 */, Register_Type::GP, Register_Size::_32, _) => Ok(R8D),
            (0b1001 /* | 0b1001 */, Register_Type::GP, Register_Size::_32, _) => Ok(R9D),
            (0b1010 /* | 0b1010 */, Register_Type::GP, Register_Size::_32, _) => Ok(R10D),
            (0b1011 /* | 0b1011 */, Register_Type::GP, Register_Size::_32, _) => Ok(R11D),
            (0b1100 /* | 0b1100 */, Register_Type::GP, Register_Size::_32, _) => Ok(R12D),
            (0b1101 /* | 0b1101 */, Register_Type::GP, Register_Size::_32, _) => Ok(R13D),
            (0b1110 /* | 0b1110 */, Register_Type::GP, Register_Size::_32, _) => Ok(R14D),
            (0b1111 /* | 0b1111 */, Register_Type::GP, Register_Size::_32, _) => Ok(R15D),
            (0b0000 /* | 0b0000 */, Register_Type::GP, Register_Size::_64, _) => Ok(RAX),
            (0b0001 /* | 0b0001 */, Register_Type::GP, Register_Size::_64, _) => Ok(RCX),
            (0b0010 /* | 0b0010 */, Register_Type::GP, Register_Size::_64, _) => Ok(RDX),
            (0b0011 /* | 0b0011 */, Register_Type::GP, Register_Size::_64, _) => Ok(RBX),
            (0b0100 /* | 0b0100 */, Register_Type::GP, Register_Size::_64, _) => Ok(RSP),
            (0b0101 /* | 0b0101 */, Register_Type::GP, Register_Size::_64, _) => Ok(RBP),
            (0b0110 /* | 0b0110 */, Register_Type::GP, Register_Size::_64, _) => Ok(RSI),
            (0b0111 /* | 0b0111 */, Register_Type::GP, Register_Size::_64, _) => Ok(RDI),
            (0b1000 /* | 0b1000 */, Register_Type::GP, Register_Size::_64, _) => Ok(R8),
            (0b1001 /* | 0b1001 */, Register_Type::GP, Register_Size::_64, _) => Ok(R9),
            (0b1010 /* | 0b1010 */, Register_Type::GP, Register_Size::_64, _) => Ok(R10),
            (0b1011 /* | 0b1011 */, Register_Type::GP, Register_Size::_64, _) => Ok(R11),
            (0b1100 /* | 0b1100 */, Register_Type::GP, Register_Size::_64, _) => Ok(R12),
            (0b1101 /* | 0b1101 */, Register_Type::GP, Register_Size::_64, _) => Ok(R13),
            (0b1110 /* | 0b1110 */, Register_Type::GP, Register_Size::_64, _) => Ok(R14),
            (0b1111 /* | 0b1111 */, Register_Type::GP, Register_Size::_64, _) => Ok(R15),
            (0b0000 /* | 0b0000 */, Register_Type::x87, Register_Size::_80, _) => Ok(ST0),
            (0b0001 /* | 0b0001 */, Register_Type::x87, Register_Size::_80, _) => Ok(ST1),
            (0b0010 /* | 0b0010 */, Register_Type::x87, Register_Size::_80, _) => Ok(ST2),
            (0b0011 /* | 0b0011 */, Register_Type::x87, Register_Size::_80, _) => Ok(ST3),
            (0b0100 /* | 0b0100 */, Register_Type::x87, Register_Size::_80, _) => Ok(ST4),
            (0b0101 /* | 0b0101 */, Register_Type::x87, Register_Size::_80, _) => Ok(ST5),
            (0b0110 /* | 0b0110 */, Register_Type::x87, Register_Size::_80, _) => Ok(ST6),
            (0b0111 /* | 0b0111 */, Register_Type::x87, Register_Size::_80, _) => Ok(ST7),
            (0b0000 /* | 0b1000 */, Register_Type::MMX, Register_Size::_64, _) => Ok(MMX0),
            (0b0001 /* | 0b1001 */, Register_Type::MMX, Register_Size::_64, _) => Ok(MMX1),
            (0b0010 /* | 0b1010 */, Register_Type::MMX, Register_Size::_64, _) => Ok(MMX2),
            (0b0011 /* | 0b1011 */, Register_Type::MMX, Register_Size::_64, _) => Ok(MMX3),
            (0b0100 /* | 0b1100 */, Register_Type::MMX, Register_Size::_64, _) => Ok(MMX4),
            (0b0101 /* | 0b1101 */, Register_Type::MMX, Register_Size::_64, _) => Ok(MMX5),
            (0b0110 /* | 0b1110 */, Register_Type::MMX, Register_Size::_64, _) => Ok(MMX6),
            (0b0111 /* | 0b1111 */, Register_Type::MMX, Register_Size::_64, _) => Ok(MMX7),
            (0b0000 /* | 0b0000 */, Register_Type::XMM, Register_Size::_128, _) => Ok(XMM0),
            (0b0001 /* | 0b0001 */, Register_Type::XMM, Register_Size::_128, _) => Ok(XMM1),
            (0b0010 /* | 0b0010 */, Register_Type::XMM, Register_Size::_128, _) => Ok(XMM2),
            (0b0011 /* | 0b0011 */, Register_Type::XMM, Register_Size::_128, _) => Ok(XMM3),
            (0b0100 /* | 0b0100 */, Register_Type::XMM, Register_Size::_128, _) => Ok(XMM4),
            (0b0101 /* | 0b0101 */, Register_Type::XMM, Register_Size::_128, _) => Ok(XMM5),
            (0b0110 /* | 0b0110 */, Register_Type::XMM, Register_Size::_128, _) => Ok(XMM6),
            (0b0111 /* | 0b0111 */, Register_Type::XMM, Register_Size::_128, _) => Ok(XMM7),
            (0b1000 /* | 0b1000 */, Register_Type::XMM, Register_Size::_128, _) => Ok(XMM8),
            (0b1001 /* | 0b1001 */, Register_Type::XMM, Register_Size::_128, _) => Ok(XMM9),
            (0b1010 /* | 0b1010 */, Register_Type::XMM, Register_Size::_128, _) => Ok(XMM10),
            (0b1011 /* | 0b1011 */, Register_Type::XMM, Register_Size::_128, _) => Ok(XMM11),
            (0b1100 /* | 0b1100 */, Register_Type::XMM, Register_Size::_128, _) => Ok(XMM12),
            (0b1101 /* | 0b1101 */, Register_Type::XMM, Register_Size::_128, _) => Ok(XMM13),
            (0b1110 /* | 0b1110 */, Register_Type::XMM, Register_Size::_128, _) => Ok(XMM14),
            (0b1111 /* | 0b1111 */, Register_Type::XMM, Register_Size::_128, _) => Ok(XMM15),
            (0b0000 /* | 0b0000 */, Register_Type::YMM, Register_Size::_256, _) => Ok(YMM0),
            (0b0001 /* | 0b0001 */, Register_Type::YMM, Register_Size::_256, _) => Ok(YMM1),
            (0b0010 /* | 0b0010 */, Register_Type::YMM, Register_Size::_256, _) => Ok(YMM2),
            (0b0011 /* | 0b0011 */, Register_Type::YMM, Register_Size::_256, _) => Ok(YMM3),
            (0b0100 /* | 0b0100 */, Register_Type::YMM, Register_Size::_256, _) => Ok(YMM4),
            (0b0101 /* | 0b0101 */, Register_Type::YMM, Register_Size::_256, _) => Ok(YMM5),
            (0b0110 /* | 0b0110 */, Register_Type::YMM, Register_Size::_256, _) => Ok(YMM6),
            (0b0111 /* | 0b0111 */, Register_Type::YMM, Register_Size::_256, _) => Ok(YMM7),
            (0b1000 /* | 0b1000 */, Register_Type::YMM, Register_Size::_256, _) => Ok(YMM8),
            (0b1001 /* | 0b1001 */, Register_Type::YMM, Register_Size::_256, _) => Ok(YMM9),
            (0b1010 /* | 0b1010 */, Register_Type::YMM, Register_Size::_256, _) => Ok(YMM10),
            (0b1011 /* | 0b1011 */, Register_Type::YMM, Register_Size::_256, _) => Ok(YMM11),
            (0b1100 /* | 0b1100 */, Register_Type::YMM, Register_Size::_256, _) => Ok(YMM12),
            (0b1101 /* | 0b1101 */, Register_Type::YMM, Register_Size::_256, _) => Ok(YMM13),
            (0b1110 /* | 0b1110 */, Register_Type::YMM, Register_Size::_256, _) => Ok(YMM14),
            (0b1111 /* | 0b1111 */, Register_Type::YMM, Register_Size::_256, _) => Ok(YMM15),
            (0b0000 /* | 0b1000 */, Register_Type::SEG, Register_Size::_16, _) => Ok(ES),
            (0b0001 /* | 0b1001 */, Register_Type::SEG, Register_Size::_16, _) => Ok(CS),
            (0b0010 /* | 0b1010 */, Register_Type::SEG, Register_Size::_16, _) => Ok(SS),
            (0b0011 /* | 0b1011 */, Register_Type::SEG, Register_Size::_16, _) => Ok(DS),
            (0b0100 /* | 0b1100 */, Register_Type::SEG, Register_Size::_16, _) => Ok(FS),
            (0b0101 /* | 0b1101 */, Register_Type::SEG, Register_Size::_16, _) => Ok(GS),
            (0b0000 /* | 0b0000 */, Register_Type::CON, Register_Size::_32, _) => Ok(CR0),
            (0b0001 /* | 0b0001 */, Register_Type::CON, Register_Size::_32, _) => Ok(CR1),
            (0b0010 /* | 0b0010 */, Register_Type::CON, Register_Size::_32, _) => Ok(CR2),
            (0b0011 /* | 0b0011 */, Register_Type::CON, Register_Size::_32, _) => Ok(CR3),
            (0b0100 /* | 0b0100 */, Register_Type::CON, Register_Size::_32, _) => Ok(CR4),
            (0b0101 /* | 0b0101 */, Register_Type::CON, Register_Size::_32, _) => Ok(CR5),
            (0b0110 /* | 0b0110 */, Register_Type::CON, Register_Size::_32, _) => Ok(CR6),
            (0b0111 /* | 0b0111 */, Register_Type::CON, Register_Size::_32, _) => Ok(CR7),
            (0b1000 /* | 0b1000 */, Register_Type::CON, Register_Size::_32, _) => Ok(CR8),
            (0b1001 /* | 0b1001 */, Register_Type::CON, Register_Size::_32, _) => Ok(CR9),
            (0b1010 /* | 0b1010 */, Register_Type::CON, Register_Size::_32, _) => Ok(CR10),
            (0b1011 /* | 0b1011 */, Register_Type::CON, Register_Size::_32, _) => Ok(CR11),
            (0b1100 /* | 0b1100 */, Register_Type::CON, Register_Size::_32, _) => Ok(CR12),
            (0b1101 /* | 0b1101 */, Register_Type::CON, Register_Size::_32, _) => Ok(CR13),
            (0b1110 /* | 0b1110 */, Register_Type::CON, Register_Size::_32, _) => Ok(CR14),
            (0b1111 /* | 0b1111 */, Register_Type::CON, Register_Size::_32, _) => Ok(CR15),
            (0b0000 /* | 0b0000 */, Register_Type::DEB, Register_Size::_32, _) => Ok(DR0),
            (0b0001 /* | 0b0001 */, Register_Type::DEB, Register_Size::_32, _) => Ok(DR1),
            (0b0010 /* | 0b0010 */, Register_Type::DEB, Register_Size::_32, _) => Ok(DR2),
            (0b0011 /* | 0b0011 */, Register_Type::DEB, Register_Size::_32, _) => Ok(DR3),
            (0b0100 /* | 0b0100 */, Register_Type::DEB, Register_Size::_32, _) => Ok(DR4),
            (0b0101 /* | 0b0101 */, Register_Type::DEB, Register_Size::_32, _) => Ok(DR5),
            (0b0110 /* | 0b0110 */, Register_Type::DEB, Register_Size::_32, _) => Ok(DR6),
            (0b0111 /* | 0b0111 */, Register_Type::DEB, Register_Size::_32, _) => Ok(DR7),
            (0b1000 /* | 0b1000 */, Register_Type::DEB, Register_Size::_32, _) => Ok(DR8),
            (0b1001 /* | 0b1001 */, Register_Type::DEB, Register_Size::_32, _) => Ok(DR9),
            (0b1010 /* | 0b1010 */, Register_Type::DEB, Register_Size::_32, _) => Ok(DR10),
            (0b1011 /* | 0b1011 */, Register_Type::DEB, Register_Size::_32, _) => Ok(DR11),
            (0b1100 /* | 0b1100 */, Register_Type::DEB, Register_Size::_32, _) => Ok(DR12),
            (0b1101 /* | 0b1101 */, Register_Type::DEB, Register_Size::_32, _) => Ok(DR13),
            (0b1110 /* | 0b1110 */, Register_Type::DEB, Register_Size::_32, _) => Ok(DR14),
            _ => Err(std::io::Error::from(std::io::ErrorKind::NotFound)),
        },
    }
}