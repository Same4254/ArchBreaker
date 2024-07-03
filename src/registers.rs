#[derive(Debug, Copy, Clone)]
pub enum Register_Size
{
    _8, _16, _32, _64, _80, _128, _256
}

#[derive(Debug, Copy, Clone)]
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
                (0b0100, Register_Type::GP, Register_Size::_8, Some(..))  => return Some(SPL),
                (0b0100, Register_Type::GP, Register_Size::_8, None) => return Some(AH),
                (0b0101, Register_Type::GP, Register_Size::_8, Some(..))  => return Some(BPL),
                (0b0101, Register_Type::GP, Register_Size::_8, None) => return Some(CH),
                (0b0110, Register_Type::GP, Register_Size::_8, Some(..))  => return Some(SIL),
                (0b0110, Register_Type::GP, Register_Size::_8, None) => return Some(DH),
                (0b0111, Register_Type::GP, Register_Size::_8, Some(..))  => return Some(DIL),
                (0b0111, Register_Type::GP, Register_Size::_8, None) => return Some(BH),
                _ =>
                    match x
                    {
                        $(
                            ($code1 | $code2, Register_Type::$type, Register_Size::$size, _) => Some($reg_name),
                        )+

                        _ => None
                    }
            }
        }
    };
}

declare_regs!(
    // 8 bit GP
    (0b0000, 0b0000, AL, _8, GP),
    (0b0001, 0b0001, CL, _8, GP),
    (0b0010, 0b0010, DL, _8, GP),
    (0b0011, 0b0011, BL, _8, GP),

    (0b0100, 0b0100, AH, _8, GP),
    (0b0101, 0b0101, CH, _8, GP),
    (0b0110, 0b0110, DH, _8, GP),
    (0b0111, 0b0111, BH, _8, GP),

    (0b0100, 0b0100, SPL, _8, GP),
    (0b0101, 0b0101, BPL, _8, GP),
    (0b0110, 0b0110, SIL, _8, GP),
    (0b0111, 0b0111, DIL, _8, GP),

    (0b1000, 0b1000, R8L , _8, GP),
    (0b1001, 0b1001, R9L , _8, GP),
    (0b1010, 0b1010, R10L, _8, GP),
    (0b1011, 0b1011, R11L, _8, GP),
    (0b1100, 0b1100, R12L, _8, GP),
    (0b1101, 0b1101, R13L, _8, GP),
    (0b1110, 0b1110, R14L, _8, GP),
    (0b1111, 0b1111, R15L, _8, GP),

    // 16 bit GP
    (0b0000, 0b0000, AX  , _16, GP),
    (0b0001, 0b0001, CX  , _16, GP),
    (0b0010, 0b0010, DX  , _16, GP),
    (0b0011, 0b0011, BX  , _16, GP),
    (0b0100, 0b0100, SP  , _16, GP),
    (0b0101, 0b0101, BP  , _16, GP),
    (0b0110, 0b0110, SI  , _16, GP),
    (0b0111, 0b0111, DI  , _16, GP),
    (0b1000, 0b1000, R8W , _16, GP),
    (0b1001, 0b1001, R9W , _16, GP),
    (0b1010, 0b1010, R10W, _16, GP),
    (0b1011, 0b1011, R11W, _16, GP),
    (0b1100, 0b1100, R12W, _16, GP),
    (0b1101, 0b1101, R13W, _16, GP),
    (0b1110, 0b1110, R14W, _16, GP),
    (0b1111, 0b1111, R15W, _16, GP),

    // 32 bit GP
    (0b0000, 0b0000, EAX , _32, GP),
    (0b0001, 0b0001, ECX , _32, GP),
    (0b0010, 0b0010, EDX , _32, GP),
    (0b0011, 0b0011, EBX , _32, GP),
    (0b0100, 0b0100, ESP , _32, GP),
    (0b0101, 0b0101, EBP , _32, GP),
    (0b0110, 0b0110, ESI , _32, GP),
    (0b0111, 0b0111, EDI , _32, GP),
    (0b1000, 0b1000, R8D , _32, GP),
    (0b1001, 0b1001, R9D , _32, GP),
    (0b1010, 0b1010, R10D, _32, GP),
    (0b1011, 0b1011, R11D, _32, GP),
    (0b1100, 0b1100, R12D, _32, GP),
    (0b1101, 0b1101, R13D, _32, GP),
    (0b1110, 0b1110, R14D, _32, GP),
    (0b1111, 0b1111, R15D, _32, GP),

    // 64 bit GP
    (0b0000, 0b0000, RAX, _64, GP),
    (0b0001, 0b0001, RCX, _64, GP),
    (0b0010, 0b0010, RDX, _64, GP),
    (0b0011, 0b0011, RBX, _64, GP),
    (0b0100, 0b0100, RSP, _64, GP),
    (0b0101, 0b0101, RBP, _64, GP),
    (0b0110, 0b0110, RSI, _64, GP),
    (0b0111, 0b0111, RDI, _64, GP),
    (0b1000, 0b1000, R8 , _64, GP),
    (0b1001, 0b1001, R9 , _64, GP),
    (0b1010, 0b1010, R10, _64, GP),
    (0b1011, 0b1011, R11, _64, GP),
    (0b1100, 0b1100, R12, _64, GP),
    (0b1101, 0b1101, R13, _64, GP),
    (0b1110, 0b1110, R14, _64, GP),
    (0b1111, 0b1111, R15, _64, GP),

    // 80 bit x87
    (0b0000, 0b0000, ST0, _80, x87),
    (0b0001, 0b0001, ST1, _80, x87),
    (0b0010, 0b0010, ST2, _80, x87),
    (0b0011, 0b0011, ST3, _80, x87),
    (0b0100, 0b0100, ST4, _80, x87),
    (0b0101, 0b0101, ST5, _80, x87),
    (0b0110, 0b0110, ST6, _80, x87),
    (0b0111, 0b0111, ST7, _80, x87),

    // 64 bit MMX
    (0b0000, 0b1000, MMX0, _64, MMX),
    (0b0001, 0b1001, MMX1, _64, MMX),
    (0b0010, 0b1010, MMX2, _64, MMX),
    (0b0011, 0b1011, MMX3, _64, MMX),
    (0b0100, 0b1100, MMX4, _64, MMX),
    (0b0101, 0b1101, MMX5, _64, MMX),
    (0b0110, 0b1110, MMX6, _64, MMX),
    (0b0111, 0b1111, MMX7, _64, MMX),
    // (0b1000, MMX0, _64, MMX),
    // (0b1001, MMX1, _64, MMX),
    // (0b1010, MMX2, _64, MMX),
    // (0b1011, MMX3, _64, MMX),
    // (0b1100, MMX4, _64, MMX),
    // (0b1101, MMX5, _64, MMX),
    // (0b1110, MMX6, _64, MMX),
    // (0b1111, MMX7, _64, MMX),

    // 128 bit XMM
    (0b0000, 0b0000, XMM0,  _128, XMM),
    (0b0001, 0b0001, XMM1,  _128, XMM),
    (0b0010, 0b0010, XMM2,  _128, XMM),
    (0b0011, 0b0011, XMM3,  _128, XMM),
    (0b0100, 0b0100, XMM4,  _128, XMM),
    (0b0101, 0b0101, XMM5,  _128, XMM),
    (0b0110, 0b0110, XMM6,  _128, XMM),
    (0b0111, 0b0111, XMM7,  _128, XMM),
    (0b1000, 0b1000, XMM8,  _128, XMM),
    (0b1001, 0b1001, XMM9,  _128, XMM),
    (0b1010, 0b1010, XMM10, _128, XMM),
    (0b1011, 0b1011, XMM11, _128, XMM),
    (0b1100, 0b1100, XMM12, _128, XMM),
    (0b1101, 0b1101, XMM13, _128, XMM),
    (0b1110, 0b1110, XMM14, _128, XMM),
    (0b1111, 0b1111, XMM15, _128, XMM),

    // 256 bit YMM
    (0b0000, 0b0000, YMM0,  _256, YMM),
    (0b0001, 0b0001, YMM1,  _256, YMM),
    (0b0010, 0b0010, YMM2,  _256, YMM),
    (0b0011, 0b0011, YMM3,  _256, YMM),
    (0b0100, 0b0100, YMM4,  _256, YMM),
    (0b0101, 0b0101, YMM5,  _256, YMM),
    (0b0110, 0b0110, YMM6,  _256, YMM),
    (0b0111, 0b0111, YMM7,  _256, YMM),
    (0b1000, 0b1000, YMM8,  _256, YMM),
    (0b1001, 0b1001, YMM9,  _256, YMM),
    (0b1010, 0b1010, YMM10, _256, YMM),
    (0b1011, 0b1011, YMM11, _256, YMM),
    (0b1100, 0b1100, YMM12, _256, YMM),
    (0b1101, 0b1101, YMM13, _256, YMM),
    (0b1110, 0b1110, YMM14, _256, YMM),
    (0b1111, 0b1111, YMM15, _256, YMM),

    // 16 bit Segment
    (0b0000, 0b1000, ES,  _16, SEG),
    (0b0001, 0b1001, CS,  _16, SEG),
    (0b0010, 0b1010, SS,  _16, SEG),
    (0b0011, 0b1011, DS,  _16, SEG),
    (0b0100, 0b1100, FS,  _16, SEG),
    (0b0101, 0b1101, GS,  _16, SEG),

    // 32 bit Control
    (0b0000, 0b0000, CR0 , _32, CON),
    (0b0001, 0b0001, CR1 , _32, CON),
    (0b0010, 0b0010, CR2 , _32, CON),
    (0b0011, 0b0011, CR3 , _32, CON),
    (0b0100, 0b0100, CR4 , _32, CON),
    (0b0101, 0b0101, CR5 , _32, CON),
    (0b0110, 0b0110, CR6 , _32, CON),
    (0b0111, 0b0111, CR7 , _32, CON),
    (0b1000, 0b1000, CR8 , _32, CON),
    (0b1001, 0b1001, CR9 , _32, CON),
    (0b1010, 0b1010, CR10, _32, CON),
    (0b1011, 0b1011, CR11, _32, CON),
    (0b1100, 0b1100, CR12, _32, CON),
    (0b1101, 0b1101, CR13, _32, CON),
    (0b1110, 0b1110, CR14, _32, CON),
    (0b1111, 0b1111, CR15, _32, CON),

    // 32 bit Debug
    (0b0000, 0b0000, DR0 , _32, DEB),
    (0b0001, 0b0001, DR1 , _32, DEB),
    (0b0010, 0b0010, DR2 , _32, DEB),
    (0b0011, 0b0011, DR3 , _32, DEB),
    (0b0100, 0b0100, DR4 , _32, DEB),
    (0b0101, 0b0101, DR5 , _32, DEB),
    (0b0110, 0b0110, DR6 , _32, DEB),
    (0b0111, 0b0111, DR7 , _32, DEB),
    (0b1000, 0b1000, DR8 , _32, DEB),
    (0b1001, 0b1001, DR9 , _32, DEB),
    (0b1010, 0b1010, DR10, _32, DEB),
    (0b1011, 0b1011, DR11, _32, DEB),
    (0b1100, 0b1100, DR12, _32, DEB),
    (0b1101, 0b1101, DR13, _32, DEB),
    (0b1110, 0b1110, DR14, _32, DEB)
);
