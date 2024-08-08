use crate::{registers::*, Inst_Prefix, Instruction_Operand, ModRMByte, Prefix_Acc, Prefix_Group1, Prefix_Group3};

#[derive(Debug, Copy, Clone)]
pub enum InstMode
{
    x64,
    x32,
}

#[derive(Debug, Copy, Clone)]
pub enum Instruction_Name
{
    PUSH,
    POP,
    DAA,
    AAA,
    DAS,
    AAS,

    ADD,
    OR,
    ADC,
    SBB,
    AND,
    SUB,
    XOR,
    CMP,
    NOT,
    TEST,
    INC,
    NEG,
    DEC,
    IMUL,
    MUL,
    DIV,
    IDIV,

    PUSHA,
    PUSHAD,
    POPA,
    POPAD,
    BOUND,
    ARPL,
    MOVSXD,
    INSB,
    INSW,
    INSD,
    OUTSB,
    OUTSW,
    OUTSD,

    J_O,
    J_NO,
    J_B_NAE_C,
    J_NB_AE_NC,
    J_Z_E,
    J_NZ_NE,
    J_BE_NA,
    J_NBE_A,

    J_S,
    J_NS,
    J_P_PE,
    J_NP_PO,
    J_L_NGE,
    J_NL_GE,
    J_LE_NG,
    J_NLE_G,

    XCHG,
    MOV,
    LEA,

    CBW, CWDE, CDQE,
    CWD, CDQ, CQO,

    far_Call,
    near_Call,
    near_Ret,
    far_Ret,

    near_Jmp,
    short_Jmp,
    far_Jmp,

    PUSHF, PUSHFD, PUSHFQ,
    POPF, POPFD, POPFQ,
    WAIT,

    SAHF, LAHF,

    MOVSW, MOVSD, MOVSB, MOVSQ,
    CMPSB, CMPSW, CMPSD, CMPSQ,

    STOSB, STOSW, STOSD, STOSQ,
    LODSB, LODSW, LODSD, LODSQ,
    SCASB, SCASW, SCASD, SCASQ,

    LES, LDS,

    ENTER, READ, LEAVE,
    INT, INT1, INT3,
    INTO,

    IRET, IRETD, IRETQ,
    AAM, AAD,
    XLATB,

    LOOPNZ, LOOPZ, LOOP,
    JrCXZ, IN, OUT,

    HLT, CMC,

    CLC, STC, CLI, STI, CLD, STD,

    ROL, ROR, RCL, RCR, SHL, SHR, SAR,
    XABORT, XBEGIN,

    LAR, LSL,
    SYSCALL, SYSRET,
    CLTS, 

    INVD, WBINVD, PRE_FETCH_W,

    V_MOV_UPS, V_MOV_UPD, V_MOV_SS, V_MOV_SD,
    V_MOV_DDUP, V_MOV_SLDUP, V_MOV_LPD, V_MOV_LPS,
}

// Some opcodes tell you the register, but not the exact size. The size is determined by other factors
#[derive(Debug, Copy, Clone)]
pub enum Register_Unsized
{
    eAX,
    eCX,
    eDX,
    eBX,
    eSP,
    eBP,
    eSI,
    eDI,

    rAX,
    rCX,
    rDX,
    rBX,
    rSP,
    rBP,
    rSI,
    rDI,

    r8,
    r9,
    r10,
    r11,
    r12,
    r13,
    r14,
    r15,
}

pub fn size_register(reg: Register_Unsized, size: Register_Size) -> Option<Register>
{
    match reg
    {
        Register_Unsized::eAX => search_register(0b000, Register_Type::GP, size, None),
        Register_Unsized::eCX => search_register(0b001, Register_Type::GP, size, None),
        Register_Unsized::eDX => search_register(0b010, Register_Type::GP, size, None),
        Register_Unsized::eBX => search_register(0b011, Register_Type::GP, size, None),
        Register_Unsized::eSP => search_register(0b100, Register_Type::GP, size, None),
        Register_Unsized::eBP => search_register(0b101, Register_Type::GP, size, None),
        Register_Unsized::eSI => search_register(0b110, Register_Type::GP, size, None),
        Register_Unsized::eDI => search_register(0b111, Register_Type::GP, size, None),

        Register_Unsized::rAX => search_register(0b000, Register_Type::GP, size, Some(false)),
        Register_Unsized::rCX => search_register(0b001, Register_Type::GP, size, Some(false)),
        Register_Unsized::rDX => search_register(0b010, Register_Type::GP, size, Some(false)),
        Register_Unsized::rBX => search_register(0b011, Register_Type::GP, size, Some(false)),
        Register_Unsized::rSP => search_register(0b100, Register_Type::GP, size, Some(false)),
        Register_Unsized::rBP => search_register(0b101, Register_Type::GP, size, Some(false)),
        Register_Unsized::rSI => search_register(0b110, Register_Type::GP, size, Some(false)),
        Register_Unsized::rDI => search_register(0b111, Register_Type::GP, size, Some(false)),

        Register_Unsized::r8  => search_register(0b000, Register_Type::GP, size, Some(true)),
        Register_Unsized::r9  => search_register(0b001, Register_Type::GP, size, Some(true)),
        Register_Unsized::r10 => search_register(0b010, Register_Type::GP, size, Some(true)),
        Register_Unsized::r11 => search_register(0b011, Register_Type::GP, size, Some(true)),
        Register_Unsized::r12 => search_register(0b100, Register_Type::GP, size, Some(true)),
        Register_Unsized::r13 => search_register(0b101, Register_Type::GP, size, Some(true)),
        Register_Unsized::r14 => search_register(0b110, Register_Type::GP, size, Some(true)),
        Register_Unsized::r15 => search_register(0b111, Register_Type::GP, size, Some(true)),
    }
}

#[derive(Debug, Copy, Clone)]
pub enum Register_Known_Or_Unsized
{
    UNSIZED(Register_Unsized),
    UNSIZED_d64(Register_Unsized),
    KNOWN(Register)
}

#[derive(Debug, Copy, Clone)]
pub enum Opcode_Operand_ModRM
{
    Eb, Ev, Ev_d64, Ew,
    Gb, Gv, Gw, Gz,
    M, Ma, Mp,
    Sw,

    Vps, Vx, Vpd, Vss, Vsd,
    Wps, Wss, Wsd, Wpd,
}

#[derive(Debug, Copy, Clone)]
pub enum Opcode_Operand_Dis
{
    Jb, Jz,
    Ap,
    Ob, Ov,
}

#[derive(Debug, Copy, Clone)]
pub enum Opcode_Operand_Imm
{
    Ib, Iw, Iv, Iz,
}

#[derive(Debug, Copy, Clone)]
pub enum Opcode_Operand
{
    Yb, Yv, Yz,
    Xb, Xv, Xz,
    Hx,

    imm_one,

    MODRM_BYTE(Opcode_Operand_ModRM),
    DIS_BYTES(Opcode_Operand_Dis),
    IMM_BYTES(Opcode_Operand_Imm),

    REGISTER(Register),
    REGISTER_UNSIZED(Register_Unsized),
    REGISTER_REX_PAIR((Register_Known_Or_Unsized,
                       Register_Known_Or_Unsized)),
}

#[derive(Debug, Copy, Clone)]
pub struct Opcode_Table_Result
{
    pub instruction:Instruction_Name,
    pub operands: [Option<Opcode_Operand>; 4]
}

macro_rules! declare_table {
    ($table_name:ident,
        $(($op:expr, $inst_mode:pat, $operand_override:pat, $address_override:pat, $rex_w:pat, $instruction:expr, $operand1:expr, $operand2:expr, $operand3:expr, $operand4:expr)),+
        $(,)?
    ) => {
        pub fn $table_name(opcode: u8, mode: InstMode, operand_override: bool, address_override: bool, rex_w: bool) -> Option<Opcode_Table_Result>
        {
            let x = (opcode, mode, operand_override, address_override, rex_w);
            match x
            {
                $(
                    ($op, $inst_mode, $operand_override, $address_override, $rex_w) => 
                    Some(Opcode_Table_Result {
                        instruction: $instruction,
                        operands: [ $operand1,
                                    $operand2,
                                    $operand3,
                                    $operand4]
                    }),
                )+

                _ => None
            }
        }
    };
}

pub fn search_opcode_one_byte_extention (inst_mode: InstMode, opcode: u8, modrm: &ModRMByte) -> Option<Opcode_Table_Result>
{
    match (inst_mode, opcode, modrm)
    {
        (_, 0x80, ModRMByte { reg_op: 0b000, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::ADD, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (_, 0x80, ModRMByte { reg_op: 0b001, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::OR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (_, 0x80, ModRMByte { reg_op: 0b010, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::ADC, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (_, 0x80, ModRMByte { reg_op: 0b011, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::SBB, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (_, 0x80, ModRMByte { reg_op: 0b100, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::AND, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (_, 0x80, ModRMByte { reg_op: 0b101, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::SUB, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (_, 0x80, ModRMByte { reg_op: 0b110, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::XOR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (_, 0x80, ModRMByte { reg_op: 0b111, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::CMP, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),



        (_, 0x80, ModRMByte { reg_op: 0b000, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::ADD, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)), None, None]}),

        (_, 0x80, ModRMByte { reg_op: 0b001, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::OR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)), None, None]}),

        (_, 0x80, ModRMByte { reg_op: 0b010, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::ADC, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)), None, None]}),

        (_, 0x80, ModRMByte { reg_op: 0b011, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::SBB, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)), None, None]}),

        (_, 0x80, ModRMByte { reg_op: 0b100, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::AND, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)), None, None]}),

        (_, 0x80, ModRMByte { reg_op: 0b101, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::SUB, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)), None, None]}),

        (_, 0x80, ModRMByte { reg_op: 0b110, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::XOR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)), None, None]}),

        (_, 0x80, ModRMByte { reg_op: 0b111, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::CMP, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)), None, None]}),


        (InstMode::x32, 0x80, ModRMByte { reg_op: 0b000, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::ADD, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (InstMode::x32, 0x80, ModRMByte { reg_op: 0b001, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::OR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (InstMode::x32, 0x80, ModRMByte { reg_op: 0b010, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::ADC, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (InstMode::x32, 0x80, ModRMByte { reg_op: 0b011, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::SBB, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (InstMode::x32, 0x80, ModRMByte { reg_op: 0b100, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::AND, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (InstMode::x32, 0x80, ModRMByte { reg_op: 0b101, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::SUB, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (InstMode::x32, 0x80, ModRMByte { reg_op: 0b110, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::XOR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (InstMode::x32, 0x80, ModRMByte { reg_op: 0b111, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::CMP, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),


        (_, 0x80, ModRMByte { reg_op: 0b000, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::ADD, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (_, 0x80, ModRMByte { reg_op: 0b001, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::OR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (_, 0x80, ModRMByte { reg_op: 0b010, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::ADC, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (_, 0x80, ModRMByte { reg_op: 0b011, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::SBB, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (_, 0x80, ModRMByte { reg_op: 0b100, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::AND, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (_, 0x80, ModRMByte { reg_op: 0b101, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::SUB, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (_, 0x80, ModRMByte { reg_op: 0b110, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::XOR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (_, 0x80, ModRMByte { reg_op: 0b111, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::CMP, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),



        (InstMode::x64, 0x8F, ModRMByte { reg_op: 0b000, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::POP, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev_d64)), None, None, None]}),

        (_, 0x8F, ModRMByte { reg_op: 0b000, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::POP, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None, None]}),



        (_, 0xC0, ModRMByte { reg_op: 0b000, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::ROL, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (_, 0xC0, ModRMByte { reg_op: 0b001, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::ROR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (_, 0xC0, ModRMByte { reg_op: 0b010, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::RCL, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (_, 0xC0, ModRMByte { reg_op: 0b011, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::RCR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (_, 0xC0, ModRMByte { reg_op: 0b100, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::SHL, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (_, 0xC0, ModRMByte { reg_op: 0b101, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::SHR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (_, 0xC0, ModRMByte { reg_op: 0b111, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::SAR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),


        (_, 0xC1, ModRMByte { reg_op: 0b000, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::ROL, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (_, 0xC1, ModRMByte { reg_op: 0b001, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::ROR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (_, 0xC1, ModRMByte { reg_op: 0b010, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::RCL, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (_, 0xC1, ModRMByte { reg_op: 0b011, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::RCR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (_, 0xC1, ModRMByte { reg_op: 0b100, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::SHL, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (_, 0xC1, ModRMByte { reg_op: 0b101, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::SHR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (_, 0xC1, ModRMByte { reg_op: 0b111, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::SAR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),


        (_, 0xD0, ModRMByte { reg_op: 0b000, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::ROL, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::imm_one), None, None]}),

        (_, 0xD0, ModRMByte { reg_op: 0b001, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::ROR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::imm_one), None, None]}),

        (_, 0xD0, ModRMByte { reg_op: 0b010, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::RCL, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::imm_one), None, None]}),

        (_, 0xD0, ModRMByte { reg_op: 0b011, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::RCR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::imm_one), None, None]}),

        (_, 0xD0, ModRMByte { reg_op: 0b100, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::SHL, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::imm_one), None, None]}),

        (_, 0xD0, ModRMByte { reg_op: 0b101, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::SHR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::imm_one), None, None]}),

        (_, 0xD0, ModRMByte { reg_op: 0b111, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::SAR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::imm_one), None, None]}),


        (_, 0xD1, ModRMByte { reg_op: 0b000, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::ROL, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::imm_one), None, None]}),

        (_, 0xD1, ModRMByte { reg_op: 0b001, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::ROR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::imm_one), None, None]}),

        (_, 0xD1, ModRMByte { reg_op: 0b010, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::RCL, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::imm_one), None, None]}),

        (_, 0xD1, ModRMByte { reg_op: 0b011, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::RCR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::imm_one), None, None]}),

        (_, 0xD1, ModRMByte { reg_op: 0b100, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::SHL, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::imm_one), None, None]}),

        (_, 0xD1, ModRMByte { reg_op: 0b101, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::SHR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::imm_one), None, None]}),

        (_, 0xD1, ModRMByte { reg_op: 0b111, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::SAR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::imm_one), None, None]}),


        (_, 0xD2, ModRMByte { reg_op: 0b000, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::ROL, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::REGISTER(CL)), None, None]}),

        (_, 0xD2, ModRMByte { reg_op: 0b001, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::ROR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::REGISTER(CL)), None, None]}),

        (_, 0xD2, ModRMByte { reg_op: 0b010, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::RCL, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::REGISTER(CL)), None, None]}),

        (_, 0xD2, ModRMByte { reg_op: 0b011, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::RCR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::REGISTER(CL)), None, None]}),

        (_, 0xD2, ModRMByte { reg_op: 0b100, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::SHL, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::REGISTER(CL)), None, None]}),

        (_, 0xD2, ModRMByte { reg_op: 0b101, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::SHR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::REGISTER(CL)), None, None]}),

        (_, 0xD2, ModRMByte { reg_op: 0b111, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::SAR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::REGISTER(CL)), None, None]}),


        (_, 0xD3, ModRMByte { reg_op: 0b000, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::ROL, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::REGISTER(CL)), None, None]}),

        (_, 0xD3, ModRMByte { reg_op: 0b001, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::ROR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::REGISTER(CL)), None, None]}),

        (_, 0xD3, ModRMByte { reg_op: 0b010, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::RCL, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::REGISTER(CL)), None, None]}),

        (_, 0xD3, ModRMByte { reg_op: 0b011, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::RCR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::REGISTER(CL)), None, None]}),

        (_, 0xD3, ModRMByte { reg_op: 0b100, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::SHL, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::REGISTER(CL)), None, None]}),

        (_, 0xD3, ModRMByte { reg_op: 0b101, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::SHR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::REGISTER(CL)), None, None]}),

        (_, 0xD3, ModRMByte { reg_op: 0b111, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::SAR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::REGISTER(CL)), None, None]}),



        (_, 0xF6, ModRMByte { reg_op: 0b000, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::TEST, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (_, 0xF6, ModRMByte { reg_op: 0b010, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::NOT, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         None, None, None]}),

        (_, 0xF6, ModRMByte { reg_op: 0b011, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::NEG, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         None, None, None]}),

        (_, 0xF6, ModRMByte { reg_op: 0b100, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::MUL, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::REGISTER(AL)), None, None]}),

        (_, 0xF6, ModRMByte { reg_op: 0b101, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::IMUL, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::REGISTER(AL)), None, None]}),

        (_, 0xF6, ModRMByte { reg_op: 0b110, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::DIV, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::REGISTER(AL)), None, None]}),

        (_, 0xF6, ModRMByte { reg_op: 0b111, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::IDIV, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::REGISTER(AL)), None, None]}),




        (_, 0xF7, ModRMByte { reg_op: 0b000, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::TEST, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (_, 0xF7, ModRMByte { reg_op: 0b010, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::NOT, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         None, None, None]}),

        (_, 0xF7, ModRMByte { reg_op: 0b011, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::NEG, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         None, None, None]}),


        (InstMode::x64, 0xF7, ModRMByte { reg_op: 0b100, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::MUL, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None]}),

        (InstMode::x64, 0xF7, ModRMByte { reg_op: 0b101, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::IMUL, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None]}),

        (InstMode::x64, 0xF7, ModRMByte { reg_op: 0b110, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::DIV, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None]}),

        (InstMode::x64, 0xF7, ModRMByte { reg_op: 0b111, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::IDIV, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None]}),


        (InstMode::x32, 0xF7, ModRMByte { reg_op: 0b100, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::MUL, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eAX)), None, None]}),

        (InstMode::x32, 0xF7, ModRMByte { reg_op: 0b101, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::IMUL, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eAX)), None, None]}),

        (InstMode::x32, 0xF7, ModRMByte { reg_op: 0b110, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::DIV, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eAX)), None, None]}),

        (InstMode::x32, 0xF7, ModRMByte { reg_op: 0b111, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::IDIV, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eAX)), None, None]}),


        (_, 0xFE, ModRMByte { reg_op: 0b000, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::INC, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         None, None, None]}),

        (_, 0xFE, ModRMByte { reg_op: 0b010, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::DEC, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         None, None, None]}),


        (_, 0xFF, ModRMByte { reg_op: 0b000, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::INC, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         None, None, None]}),

        (_, 0xFF, ModRMByte { reg_op: 0b001, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::DEC, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         None, None, None]}),

        (_, 0xFF, ModRMByte { reg_op: 0b010, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::near_Call, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         None, None, None]}),

        (_, 0xFF, ModRMByte { reg_op: 0b011, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::far_Call, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         None, None, None]}),

        (_, 0xFF, ModRMByte { reg_op: 0b100, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::near_Jmp, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         None, None, None]}),

        (_, 0xFF, ModRMByte { reg_op: 0b101, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::far_Jmp, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Mp)), 
                                                                                         None, None, None]}),

        (InstMode::x64, 0xFF, ModRMByte { reg_op: 0b110, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::PUSH, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev_d64)), 
                                                                                         None, None, None]}),

        (_, 0xFF, ModRMByte { reg_op: 0b110, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::PUSH, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         None, None, None]}),

        (_, 0xC6, ModRMByte { reg_op: 0b000, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::MOV, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (_, 0xC7, ModRMByte { reg_op: 0b000, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::MOV, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)), None, None]}),


        // (_, 0xC6, ModRMByte { reg_op: 0b111, md: 0x00 | 0x01 | 0x10, rm: 0x000 }) => Some(Opcode_Table_Result { instruction: Instruction_Name::XABORT, 
        //                                                                       operands: [Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None, None]}),

        // (_, 0xC7, ModRMByte { reg_op: 0b111, md: 0x00 | 0x01 | 0x10, rm: 0x000 }) => Some(Opcode_Table_Result { instruction: Instruction_Name::XBEGIN, 
        //                                                                       operands: [Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Imm::Jz)), None, None, None]}),

        _ => None
    }
}

// TODO: the modrm byte might be needed to force operations which "can only operate on memory".
// Anything with an M operand can only operate on memory
declare_table!(search_opcode_one_byte,
    (0x00, _,             _, _, _,     Instruction_Name::ADD,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)), None, None),
    (0x01, _,             _, _, _,     Instruction_Name::ADD,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), None, None),
    (0x02, _,             _, _, _,     Instruction_Name::ADD,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), None, None),
    (0x03, _,             _, _, _,     Instruction_Name::ADD,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None),
    (0x04, _,             _, _, _,     Instruction_Name::ADD,  Some(Opcode_Operand::REGISTER(AL)),                            Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)),    None, None),
    (0x05, _,             _, _, _,     Instruction_Name::ADD,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)),    None, None),
    (0x06, InstMode::x32, _, _, false, Instruction_Name::PUSH, Some(Opcode_Operand::REGISTER(ES)),                            None,                                                       None, None),
    (0x07, InstMode::x32, _, _, false, Instruction_Name::POP,  Some(Opcode_Operand::REGISTER(ES)),                            None,                                                       None, None),

    (0x08, _,             _, _, _,     Instruction_Name::OR,   Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)), None, None),
    (0x09, _,             _, _, _,     Instruction_Name::OR,   Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), None, None),
    (0x0a, _,             _, _, _,     Instruction_Name::OR,   Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), None, None),
    (0x0b, _,             _, _, _,     Instruction_Name::OR,   Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None),
    (0x0c, _,             _, _, _,     Instruction_Name::OR,   Some(Opcode_Operand::REGISTER(AL)),                            Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)),    None, None),
    (0x0d, _,             _, _, _,     Instruction_Name::OR,   Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)),    None, None),
    (0x0e, InstMode::x32, _, _, false, Instruction_Name::PUSH, Some(Opcode_Operand::REGISTER(ES)),                            None,                                                       None, None),


    (0x10, _,             _, _, _,     Instruction_Name::ADC,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)), None, None),
    (0x11, _,             _, _, _,     Instruction_Name::ADC,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), None, None),
    (0x12, _,             _, _, _,     Instruction_Name::ADC,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), None, None),
    (0x13, _,             _, _, _,     Instruction_Name::ADC,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None),
    (0x14, _,             _, _, _,     Instruction_Name::ADC,  Some(Opcode_Operand::REGISTER(AL)),                            Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)),    None, None),
    (0x15, _,             _, _, _,     Instruction_Name::ADC,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)),    None, None),
    (0x16, InstMode::x32, _, _, false, Instruction_Name::PUSH, Some(Opcode_Operand::REGISTER(SS)),                            None,                                                       None, None),
    (0x17, InstMode::x32, _, _, false, Instruction_Name::POP,  Some(Opcode_Operand::REGISTER(SS)),                            None,                                                       None, None),

    (0x18, _,             _, _, _,     Instruction_Name::SBB,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)), None, None),
    (0x19, _,             _, _, _,     Instruction_Name::SBB,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), None, None),
    (0x1a, _,             _, _, _,     Instruction_Name::SBB,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), None, None),
    (0x1b, _,             _, _, _,     Instruction_Name::SBB,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None),
    (0x1c, _,             _, _, _,     Instruction_Name::SBB,  Some(Opcode_Operand::REGISTER(AL)),                            Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)),    None, None),
    (0x1d, _,             _, _, _,     Instruction_Name::SBB,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)),    None, None),
    (0x1e, InstMode::x32, _, _, _,     Instruction_Name::PUSH, Some(Opcode_Operand::REGISTER(DS)),                            None,                                                       None, None),
    (0x1f, InstMode::x32, _, _, false, Instruction_Name::POP,  Some(Opcode_Operand::REGISTER(DS)),                            None,                                                       None, None),


    (0x20, _,             _, _, _,     Instruction_Name::AND,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)), None, None),
    (0x21, _,             _, _, _,     Instruction_Name::AND,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), None, None),
    (0x22, _,             _, _, _,     Instruction_Name::AND,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), None, None),
    (0x23, _,             _, _, _,     Instruction_Name::AND,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None),
    (0x24, _,             _, _, _,     Instruction_Name::AND,  Some(Opcode_Operand::REGISTER(AL)),                            Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)),    None, None),
    (0x25, _,             _, _, _,     Instruction_Name::AND,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)),    None, None),
    (0x27, InstMode::x32, _, _, false, Instruction_Name::DAA,  None,                                                          None,                                                       None, None),

    (0x28, _,             _, _, _,     Instruction_Name::SUB,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)), None, None),
    (0x29, _,             _, _, _,     Instruction_Name::SUB,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), None, None),
    (0x2a, _,             _, _, _,     Instruction_Name::SUB,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), None, None),
    (0x2b, _,             _, _, _,     Instruction_Name::SUB,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None),
    (0x2c, _,             _, _, _,     Instruction_Name::SUB,  Some(Opcode_Operand::REGISTER(AL)),                            Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)),    None, None),
    (0x2d, _,             _, _, _,     Instruction_Name::SUB,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)),    None, None),
    (0x2f, InstMode::x32, _, _, false, Instruction_Name::DAS,  None,                                                          None,                                                       None, None),


    (0x30, _,             _, _, _,     Instruction_Name::XOR,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)), None, None),
    (0x31, _,             _, _, _,     Instruction_Name::XOR,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), None, None),
    (0x32, _,             _, _, _,     Instruction_Name::XOR,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), None, None),
    (0x33, _,             _, _, _,     Instruction_Name::XOR,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None),
    (0x34, _,             _, _, _,     Instruction_Name::XOR,  Some(Opcode_Operand::REGISTER(AL)),                            Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)),    None, None),
    (0x35, _,             _, _, _,     Instruction_Name::XOR,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)),    None, None),
    (0x37, InstMode::x32, _, _, false, Instruction_Name::AAA,  None,                                                          None,                                                       None, None),

    (0x38, _,             _, _, _,     Instruction_Name::CMP,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)), None, None),
    (0x39, _,             _, _, _,     Instruction_Name::CMP,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), None, None),
    (0x3a, _,             _, _, _,     Instruction_Name::CMP,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), None, None),
    (0x3b, _,             _, _, _,     Instruction_Name::CMP,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None),
    (0x3c, _,             _, _, _,     Instruction_Name::CMP,  Some(Opcode_Operand::REGISTER(AL)),                            Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)),    None, None),
    (0x3d, _,             _, _, _,     Instruction_Name::CMP,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)),    None, None),
    (0x3f, InstMode::x32, _, _, false, Instruction_Name::AAS,  None,                                                          None,                                                       None, None),


    (0x40, InstMode::x32, _, _, false, Instruction_Name::INC,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eAX)), None, None, None),
    (0x41, InstMode::x32, _, _, false, Instruction_Name::INC,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eCX)), None, None, None),
    (0x42, InstMode::x32, _, _, false, Instruction_Name::INC,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eDX)), None, None, None),
    (0x43, InstMode::x32, _, _, false, Instruction_Name::INC,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eBX)), None, None, None),
    (0x44, InstMode::x32, _, _, false, Instruction_Name::INC,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eSP)), None, None, None),
    (0x45, InstMode::x32, _, _, false, Instruction_Name::INC,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eBP)), None, None, None),
    (0x46, InstMode::x32, _, _, false, Instruction_Name::INC,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eSI)), None, None, None),
    (0x47, InstMode::x32, _, _, false, Instruction_Name::INC,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eDI)), None, None, None),

    (0x48, InstMode::x32, _, _, false, Instruction_Name::DEC,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eAX)), None, None, None),
    (0x49, InstMode::x32, _, _, false, Instruction_Name::DEC,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eCX)), None, None, None),
    (0x4a, InstMode::x32, _, _, false, Instruction_Name::DEC,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eDX)), None, None, None),
    (0x4b, InstMode::x32, _, _, false, Instruction_Name::DEC,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eBX)), None, None, None),
    (0x4c, InstMode::x32, _, _, false, Instruction_Name::DEC,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eSP)), None, None, None),
    (0x4d, InstMode::x32, _, _, false, Instruction_Name::DEC,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eBP)), None, None, None),
    (0x4e, InstMode::x32, _, _, false, Instruction_Name::DEC,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eSI)), None, None, None),
    (0x4f, InstMode::x32, _, _, false, Instruction_Name::DEC,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eDI)), None, None, None),


    (0x50, InstMode::x64, _, _, _, Instruction_Name::PUSH, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rAX), 
                                                                                                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r8)))), 
                                                            None, None, None),

    (0x51, InstMode::x64, _, _, _, Instruction_Name::PUSH, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rCX), 
                                                                                                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r9)))),
                                                            None, None, None),

    (0x52, InstMode::x64, _, _, _, Instruction_Name::PUSH, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rDX), 
                                                                                                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r10)))),
                                                            None, None, None),

    (0x53, InstMode::x64, _, _, _, Instruction_Name::PUSH, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rBX), 
                                                                                                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r11)))),
                                                            None, None, None),

    (0x54, InstMode::x64, _, _, _, Instruction_Name::PUSH, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rSP), 
                                                                                                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r12)))),
                                                            None, None, None),

    (0x55, InstMode::x64, _, _, _, Instruction_Name::PUSH, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rBP), 
                                                                                                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r13)))),
                                                            None, None, None),

    (0x56, InstMode::x64, _, _, _, Instruction_Name::PUSH, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rSI), 
                                                                                                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r14)))),
                                                            None, None, None),

    (0x57, InstMode::x64, _, _, _, Instruction_Name::PUSH, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rDI), 
                                                                                                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r15)))),
                                                            None, None, None),


    (0x58, InstMode::x64, _, _, _, Instruction_Name::POP,  Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rAX), 
                                                                                                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r8)))),
                                                            None, None, None),

    (0x59, InstMode::x64, _, _, _, Instruction_Name::POP,  Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rCX), 
                                                                                                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r9)))),
                                                            None, None, None),

    (0x5a, InstMode::x64, _, _, _, Instruction_Name::POP,  Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rDX), 
                                                                                                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r10)))),
                                                            None, None, None),

    (0x5b, InstMode::x64, _, _, _, Instruction_Name::POP,  Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rBX), 
                                                                                                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r11)))),
                                                            None, None, None),

    (0x5c, InstMode::x64, _, _, _, Instruction_Name::POP,  Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rSP), 
                                                                                                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r12)))),
                                                            None, None, None),

    (0x5d, InstMode::x64, _, _, _, Instruction_Name::POP,  Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rBP), 
                                                                                                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r13)))),
                                                            None, None, None),

    (0x5e, InstMode::x64, _, _, _, Instruction_Name::POP,  Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rSI), 
                                                                                                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r14)))),
                                                            None, None, None),

    (0x5f, InstMode::x64, _, _, _, Instruction_Name::POP,  Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rDI), 
                                                                                                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r15)))),
                                                            None, None, None),


    (0x50, InstMode::x32, _, _, false, Instruction_Name::PUSH,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eAX)),  None,  None, None),
    (0x51, InstMode::x32, _, _, false, Instruction_Name::PUSH,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eCX)),  None,  None, None),
    (0x52, InstMode::x32, _, _, false, Instruction_Name::PUSH,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eDX)),  None,  None, None),
    (0x53, InstMode::x32, _, _, false, Instruction_Name::PUSH,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eBX)),  None,  None, None),
    (0x54, InstMode::x32, _, _, false, Instruction_Name::PUSH,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eSP)),  None,  None, None),
    (0x55, InstMode::x32, _, _, false, Instruction_Name::PUSH,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eBP)),  None,  None, None),
    (0x56, InstMode::x32, _, _, false, Instruction_Name::PUSH,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eSI)),  None,  None, None),
    (0x57, InstMode::x32, _, _, false, Instruction_Name::PUSH,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eDI)),  None,  None, None),

    (0x58, InstMode::x32, _, _, false, Instruction_Name::POP,   Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eAX)),  None,  None, None),
    (0x59, InstMode::x32, _, _, false, Instruction_Name::POP,   Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eCX)),  None,  None, None),
    (0x5a, InstMode::x32, _, _, false, Instruction_Name::POP,   Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eDX)),  None,  None, None),
    (0x5b, InstMode::x32, _, _, false, Instruction_Name::POP,   Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eBX)),  None,  None, None),
    (0x5c, InstMode::x32, _, _, false, Instruction_Name::POP,   Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eSP)),  None,  None, None),
    (0x5d, InstMode::x32, _, _, false, Instruction_Name::POP,   Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eBP)),  None,  None, None),
    (0x5e, InstMode::x32, _, _, false, Instruction_Name::POP,   Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eSI)),  None,  None, None),
    (0x5f, InstMode::x32, _, _, false, Instruction_Name::POP,   Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eDI)),  None,  None, None),


    (0x60, InstMode::x32, true,  _, false, Instruction_Name::PUSHA,  None,                                                        None,                                                       None, None),
    (0x60, InstMode::x32, false, _, false, Instruction_Name::PUSHAD, None,                                                        None,                                                       None, None),
    (0x61, InstMode::x32, true,  _, false, Instruction_Name::POPA,   None,                                                        None,                                                       None, None),
    (0x61, InstMode::x32, false, _, false, Instruction_Name::POPAD,  None,                                                        None,                                                       None, None),
    (0x62, InstMode::x32, _,     _, false, Instruction_Name::BOUND,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)),  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ma)), None, None),
    (0x63, InstMode::x32, _,     _, false, Instruction_Name::ARPL,   Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ew)),  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gw)), None, None),
    (0x63, InstMode::x64, _,     _, _,     Instruction_Name::MOVSXD, Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)),  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None),

    (0x68, _, _, _, _, Instruction_Name::PUSH, Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)),    None,                                                       None,                                                    None),
    (0x69, _, _, _, _, Instruction_Name::IMUL, Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)), None),
    (0x6a, _, _, _, _, Instruction_Name::PUSH, Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)),    None,                                                       None,                                                    None),
    (0x6b, _, _, _, _, Instruction_Name::IMUL, Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None),

    (0x6c, _, _, _,     _, Instruction_Name::INSB,  Some(Opcode_Operand::Yb), Some(Opcode_Operand::REGISTER(DX)), None, None),
    (0x6d, _, _, true,  _, Instruction_Name::INSW,  Some(Opcode_Operand::Yz), Some(Opcode_Operand::REGISTER(DX)), None, None),
    (0x6d, _, _, false, _, Instruction_Name::INSD,  Some(Opcode_Operand::Yz), Some(Opcode_Operand::REGISTER(DX)), None, None),

    (0x6e, _, _, _,     _, Instruction_Name::OUTSB, Some(Opcode_Operand::REGISTER(DX)), Some(Opcode_Operand::Xb), None, None),
    (0x6f, _, _, true,  _, Instruction_Name::OUTSW, Some(Opcode_Operand::REGISTER(DX)), Some(Opcode_Operand::Xz), None, None),
    (0x6f, _, _, false, _, Instruction_Name::OUTSD, Some(Opcode_Operand::REGISTER(DX)), Some(Opcode_Operand::Xz), None, None),


    (0x70, _, _, _, _, Instruction_Name::J_O,        Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),  None,  None, None),
    (0x71, _, _, _, _, Instruction_Name::J_NO,       Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),  None,  None, None),
    (0x72, _, _, _, _, Instruction_Name::J_B_NAE_C,  Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),  None,  None, None),
    (0x73, _, _, _, _, Instruction_Name::J_NB_AE_NC, Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),  None,  None, None),
    (0x74, _, _, _, _, Instruction_Name::J_Z_E,      Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),  None,  None, None),
    (0x75, _, _, _, _, Instruction_Name::J_NZ_NE,    Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),  None,  None, None),
    (0x76, _, _, _, _, Instruction_Name::J_BE_NA,    Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),  None,  None, None),
    (0x77, _, _, _, _, Instruction_Name::J_NBE_A,    Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),  None,  None, None),

    (0x78, _, _, _, _, Instruction_Name::J_S,        Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),  None,  None, None),
    (0x79, _, _, _, _, Instruction_Name::J_NS,       Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),  None,  None, None),
    (0x7a, _, _, _, _, Instruction_Name::J_P_PE,     Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),  None,  None, None),
    (0x7b, _, _, _, _, Instruction_Name::J_NP_PO,    Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),  None,  None, None),
    (0x7c, _, _, _, _, Instruction_Name::J_L_NGE,    Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),  None,  None, None),
    (0x7d, _, _, _, _, Instruction_Name::J_NL_GE,    Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),  None,  None, None),
    (0x7e, _, _, _, _, Instruction_Name::J_LE_NG,    Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),  None,  None, None),
    (0x7f, _, _, _, _, Instruction_Name::J_NLE_G,    Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),  None,  None, None),


    (0x84, _, _, _, _, Instruction_Name::TEST, Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)),  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)),  None, None),
    (0x85, _, _, _, _, Instruction_Name::TEST, Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)),  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)),  None, None),
    (0x86, _, _, _, _, Instruction_Name::XCHG, Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)),  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)),  None, None),
    (0x87, _, _, _, _, Instruction_Name::XCHG, Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)),  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)),  None, None),

    (0x88, _, _, _, _, Instruction_Name::MOV,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)),  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)),  None, None),
    (0x89, _, _, _, _, Instruction_Name::MOV,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)),  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)),  None, None),
    (0x8a, _, _, _, _, Instruction_Name::MOV,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)),  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)),  None, None),
    (0x8b, _, _, _, _, Instruction_Name::MOV,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)),  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)),  None, None),
    (0x8c, _, _, _, _, Instruction_Name::MOV,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)),  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Sw)),  None, None),
    (0x8d, _, _, _, _, Instruction_Name::LEA,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)),  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::M)) ,  None, None),
    (0x8e, _, _, _, _, Instruction_Name::MOV,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Sw)),  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ew)),  None, None),


    (0x90, InstMode::x64, _, _, _, Instruction_Name::XCHG, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rAX), 
                                                                                                    Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r8)))),
                                                            Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),

    (0x91, InstMode::x64, _, _, _, Instruction_Name::XCHG, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rCX), 
                                                                                                     Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r9)))),
                                                            Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),

    (0x92, InstMode::x64, _, _, _, Instruction_Name::XCHG, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rDX), 
                                                                                                     Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r10)))),
                                                            Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),

    (0x93, InstMode::x64, _, _, _, Instruction_Name::XCHG, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rBX), 
                                                                                                     Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r11)))),
                                                            Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),

    (0x94, InstMode::x64, _, _, _, Instruction_Name::XCHG, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rSP), 
                                                                                                     Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r12)))),
                                                            Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),

    (0x95, InstMode::x64, _, _, _, Instruction_Name::XCHG, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rBP), 
                                                                                                     Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r13)))),
                                                            Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),

    (0x96, InstMode::x64, _, _, _, Instruction_Name::XCHG, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rSI), 
                                                                                                     Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r14)))),
                                                            Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),

    (0x97, InstMode::x64, _, _, _, Instruction_Name::XCHG, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rDI), 
                                                                                                     Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r15)))),
                                                            Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),

    (0x90, InstMode::x32, _, _, false, Instruction_Name::XCHG, Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eAX)), Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),
    (0x91, InstMode::x32, _, _, false, Instruction_Name::XCHG, Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eCX)), Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),
    (0x92, InstMode::x32, _, _, false, Instruction_Name::XCHG, Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eDX)), Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),
    (0x93, InstMode::x32, _, _, false, Instruction_Name::XCHG, Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eBX)), Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),
    (0x94, InstMode::x32, _, _, false, Instruction_Name::XCHG, Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eSP)), Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),
    (0x95, InstMode::x32, _, _, false, Instruction_Name::XCHG, Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eBP)), Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),
    (0x96, InstMode::x32, _, _, false, Instruction_Name::XCHG, Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eSI)), Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),
    (0x97, InstMode::x32, _, _, false, Instruction_Name::XCHG, Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eDI)), Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),

    (0x98, _,             true,  _,    _,    Instruction_Name::CBW,      None, None, None, None),
    (0x98, _,             false, _,    _,    Instruction_Name::CWDE,     None, None, None, None),
    (0x98, InstMode::x64, _,     _,    true, Instruction_Name::CDQE,     None, None, None, None),

    (0x99, _,             true,  _,    _,    Instruction_Name::CWD,      None, None, None, None),
    (0x99, _,             false, _,    _,    Instruction_Name::CDQ,      None, None, None, None),
    (0x99, InstMode::x64, _,     _,    true, Instruction_Name::CQO,      None, None, None, None),

    (0x9a, InstMode::x32, _,     _,    _,    Instruction_Name::far_Call, Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Ap)),  None, None, None),
    (0x9b, _,             _,     _,    _,    Instruction_Name::WAIT,     None,                                                     None, None, None),

    (0x9c, _,             true, _,     _,    Instruction_Name::PUSHF,    None,  None,  None, None),
    (0x9c, InstMode::x32, _,    _,     _,    Instruction_Name::PUSHFD,   None,  None,  None, None),
    (0x9c, InstMode::x64, _,    _,     _,    Instruction_Name::PUSHFQ,   None,  None,  None, None),

    (0x9d, _,             true, _,     _,    Instruction_Name::POPF,     None,  None,  None, None),
    (0x9d, InstMode::x32, _,    _,     _,    Instruction_Name::POPFD,    None,  None,  None, None),
    (0x9d, InstMode::x64, _,    _,     _,    Instruction_Name::POPFQ,    None,  None,  None, None),

    (0x9e, _,             _,    _,     _,    Instruction_Name::SAHF,     None,  None,  None, None),
    (0x9f, _,             _,    _,     _,    Instruction_Name::LAHF,     None,  None,  None, None),

    (0xa0, _,             _,    _,     _,    Instruction_Name::MOV,      Some(Opcode_Operand::REGISTER(AL)),                            Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Ob)),       None, None),
    (0xa1, _,             _,    _,     _,    Instruction_Name::MOV,      Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Ov)),       None, None),
    (0xa2, _,             _,    _,     _,    Instruction_Name::MOV,      Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Ob)),       Some(Opcode_Operand::REGISTER(AL)),                            None, None),
    (0xa3, _,             _,    _,     _,    Instruction_Name::MOV,      Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Ov)),       Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),
    (0xa4, _,             _,    _,     _,    Instruction_Name::MOVSB,    Some(Opcode_Operand::Yb),                                      Some(Opcode_Operand::Xb),                                      None, None),
    (0xa5, _,             _,    false, true, Instruction_Name::MOVSQ,    Some(Opcode_Operand::Yv),                                      Some(Opcode_Operand::Xv),                                      None, None),
    (0xa5, _,             _,    true,  _,    Instruction_Name::MOVSW,    Some(Opcode_Operand::Yv),                                      Some(Opcode_Operand::Xv),                                      None, None),
    (0xa5, _,             _,    false, _,    Instruction_Name::MOVSD,    Some(Opcode_Operand::Yv),                                      Some(Opcode_Operand::Xv),                                      None, None),

    (0xa6, _,             _,    _,     _,    Instruction_Name::CMPSB,    Some(Opcode_Operand::Xb), Some(Opcode_Operand::Yb), None, None),
    (0xa7, _,             _,    _,     _,    Instruction_Name::CMPSW,    Some(Opcode_Operand::Xv), Some(Opcode_Operand::Yv), None, None),
    (0xa7, _,             _,    _,     _,    Instruction_Name::CMPSD,    Some(Opcode_Operand::Xv), Some(Opcode_Operand::Yv), None, None),
    (0xa7, InstMode::x64, _,    _,     true, Instruction_Name::CMPSQ,    Some(Opcode_Operand::Xv), Some(Opcode_Operand::Yv), None, None),

    (0xa8, _,             _,    _,     _,    Instruction_Name::TEST,     Some(Opcode_Operand::REGISTER(AL)),                            Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None),
    (0xa9, _,             _,    _,     _,    Instruction_Name::TEST,     Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)), None, None),

    (0xaa, _,             _,     _, _,       Instruction_Name::STOSB,    Some(Opcode_Operand::Yb),                                Some(Opcode_Operand::REGISTER(AL)),                            None, None),
    (0xab, _,             true,  _, _,       Instruction_Name::STOSW,    Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)), Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),
    (0xab, _,             false, _, _,       Instruction_Name::STOSD,    Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)), Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),
    (0xab, InstMode::x64, _,     _, true,    Instruction_Name::STOSQ,    Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)), Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),

    (0xac, _,              _,     _, _,      Instruction_Name::LODSB,    Some(Opcode_Operand::REGISTER(AL)),                            Some(Opcode_Operand::Xb), None, None),
    (0xad, _,              true,  _, _,      Instruction_Name::LODSW,    Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), Some(Opcode_Operand::Xv), None, None),
    (0xad, _,              false, _, _,      Instruction_Name::LODSD,    Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), Some(Opcode_Operand::Xv), None, None),
    (0xad, InstMode::x64,  _,     _, true,   Instruction_Name::LODSQ,    Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),       None,                     None, None),

    (0xae, _,            _,       _, _,      Instruction_Name::SCASB,    Some(Opcode_Operand::REGISTER(AL)),                             Some(Opcode_Operand::Yb), None, None),
    (0xaf, _,            true,    _, _,      Instruction_Name::SCASW,    Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)),  Some(Opcode_Operand::Yv), None, None),
    (0xaf, _,            false,   _, _,      Instruction_Name::SCASD,    Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)),  Some(Opcode_Operand::Yv), None, None),
    (0xaf, InstMode::x64, _,      _, true,   Instruction_Name::SCASQ,    Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)),  Some(Opcode_Operand::Yv), None, None),


    (0xb0, InstMode::x64, _, _, _, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::KNOWN(AL), 
                                                                                                        Register_Known_Or_Unsized::KNOWN(R8L)))),
                                                                Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None),

    (0xb1, InstMode::x64, _, _, _, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::KNOWN(CL), 
                                                                                                        Register_Known_Or_Unsized::KNOWN(R9L)))),
                                                                Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None),

    (0xb2, InstMode::x64, _, _, _, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::KNOWN(DL), 
                                                                                                        Register_Known_Or_Unsized::KNOWN(R10L)))),
                                                                Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None),

    (0xb3, InstMode::x64, _, _, _, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::KNOWN(BL), 
                                                                                                        Register_Known_Or_Unsized::KNOWN(R11L)))),
                                                                Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None),

    (0xb4, InstMode::x64, _, _, _, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::KNOWN(AH), 
                                                                                                        Register_Known_Or_Unsized::KNOWN(R12L)))),
                                                                Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None),

    (0xb5, InstMode::x64, _, _, _, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::KNOWN(CH), 
                                                                                                        Register_Known_Or_Unsized::KNOWN(R13L)))),
                                                                Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None),

    (0xb6, InstMode::x64, _, _, _, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::KNOWN(DH), 
                                                                                                        Register_Known_Or_Unsized::KNOWN(R14L)))),
                                                                Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None),

    (0xb7, InstMode::x64, _, _, _, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::KNOWN(BH), 
                                                                                                        Register_Known_Or_Unsized::KNOWN(R15L)))),
                                                                Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None),

    (0xb0, InstMode::x32, _, _, false, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER(AL)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None),
    (0xb1, InstMode::x32, _, _, false, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER(CL)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None),
    (0xb2, InstMode::x32, _, _, false, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER(DL)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None),
    (0xb3, InstMode::x32, _, _, false, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER(BL)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None),
    (0xb4, InstMode::x32, _, _, false, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER(AH)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None),
    (0xb5, InstMode::x32, _, _, false, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER(CH)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None),
    (0xb6, InstMode::x32, _, _, false, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER(DH)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None),
    (0xb7, InstMode::x32, _, _, false, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER(BH)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None),

    (0xb8, InstMode::x64, _, _, _, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rAX), 
                                                                                                    Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r8)))),
                                                           Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv)), None, None),

    (0xb9, InstMode::x64, _, _, _, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rCX), 
                                                                                                     Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r9)))),
                                                           Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv)), None, None),

    (0xba, InstMode::x64, _, _, _, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rDX), 
                                                                                                     Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r10)))),
                                                           Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv)), None, None),

    (0xbb, InstMode::x64, _, _, _, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rBX), 
                                                                                                     Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r11)))),
                                                           Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv)), None, None),

    (0xbc, InstMode::x64, _, _, _, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rSP), 
                                                                                                     Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r12)))),
                                                           Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv)), None, None),

    (0xbd, InstMode::x64, _, _, _, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rBP), 
                                                                                                     Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r13)))),
                                                           Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv)), None, None),

    (0xbe, InstMode::x64, _, _, _, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rSI), 
                                                                                                     Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r14)))),
                                                           Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv)), None, None),

    (0xbf, InstMode::x64, _, _, _, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rDI), 
                                                                                                     Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r15)))),
                                                           Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv)), None, None),

    (0xb8, InstMode::x32, _, _, false, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eAX)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv)), None, None),
    (0xb9, InstMode::x32, _, _, false, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eCX)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv)), None, None),
    (0xba, InstMode::x32, _, _, false, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eDX)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv)), None, None),
    (0xbb, InstMode::x32, _, _, false, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eBX)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv)), None, None),
    (0xbc, InstMode::x32, _, _, false, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eSP)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv)), None, None),
    (0xbd, InstMode::x32, _, _, false, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eBP)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv)), None, None),
    (0xbe, InstMode::x32, _, _, false, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eSI)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv)), None, None),
    (0xbf, InstMode::x32, _, _, false, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eDI)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv)), None, None),

    // TODO: VEX prefix for LES and LDS
    (0xc2, _,             _,     _, _,    Instruction_Name::near_Ret, Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iw)),    None,                                                       None, None),
    (0xc3, _,             _,     _, _,    Instruction_Name::near_Ret, None,                                                       None,                                                       None, None),
    (0xc4, InstMode::x32, _,     _, _,    Instruction_Name::LES,      Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gz)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Mp)), None, None),
    (0xc5, InstMode::x32, _,     _, _,    Instruction_Name::LDS,      Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gz)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Mp)), None, None),

    (0xc8, _,             _,     _, _,    Instruction_Name::ENTER,    Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iw)),    Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)),    None, None),
    (0xc9, _,             _,     _, _,    Instruction_Name::LEAVE,    None,                                                       None,                                                       None, None),
    (0xca, _,             _,     _, _,    Instruction_Name::far_Ret,  Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iw)),    None,                                                       None, None),
    (0xcb, _,             _,     _, _,    Instruction_Name::far_Ret,  None,                                                       None,                                                       None, None),
    (0xcc, _,             _,     _, _,    Instruction_Name::INT3,     None,                                                       None,                                                       None, None),
    (0xcd, _,             _,     _, _,    Instruction_Name::INT,      Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)),    None,                                                       None, None),
    (0xce, InstMode::x32, _,     _, _,    Instruction_Name::INTO,     None,                                                       None,                                                       None, None),
    (0xcf, _,             true,  _, _,    Instruction_Name::IRET,     None,                                                       None,                                                       None, None),
    (0xcf, _,             false, _, _,    Instruction_Name::IRETD,    None,                                                       None,                                                       None, None),
    (0xcf, InstMode::x64, _,     _, true, Instruction_Name::IRETQ,    None,                                                       None,                                                       None, None),

    (0xd4, InstMode::x32, _,     _, _,    Instruction_Name::AAM,      Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)),     None,                               None, None),
    (0xd5, InstMode::x32, _,     _, _,    Instruction_Name::AAD,      Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)),     None,                               None, None),
    (0xd7, _,             _,     _, _,    Instruction_Name::XLATB,    None,                                                        None,                               None, None),
    // XLAT has parameters?

    (0xe0, _,             _, _, _, Instruction_Name::LOOPNZ,    Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),       None,                                                          None, None),
    (0xe1, _,             _, _, _, Instruction_Name::LOOPZ,     Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),       None,                                                          None, None),
    (0xe2, _,             _, _, _, Instruction_Name::LOOP,      Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),       None,                                                          None, None),
    (0xe3, _,             _, _, _, Instruction_Name::JrCXZ,     Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),       None,                                                          None, None),
    (0xe4, _,             _, _, _, Instruction_Name::IN,        Some(Opcode_Operand::REGISTER(AL)),                            Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)),       None, None),
    (0xe5, _,             _, _, _, Instruction_Name::IN,        Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eAX)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)),       None, None),
    (0xe6, _,             _, _, _, Instruction_Name::OUT,       Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)),       Some(Opcode_Operand::REGISTER(AL)),                            None, None),
    (0xe7, _,             _, _, _, Instruction_Name::OUT,       Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)),       Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eAX)), None, None),

    (0xe8, _,             _, _, _, Instruction_Name::near_Call, Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jz)),       None,                                                          None, None),
    (0xe9, _,             _, _, _, Instruction_Name::near_Jmp,  Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jz)),       None,                                                          None, None),
    (0xea, InstMode::x32, _, _, _, Instruction_Name::far_Jmp,   Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Ap)),       None,                                                          None, None),
    (0xeb, _,             _, _, _, Instruction_Name::short_Jmp, Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),       None,                                                          None, None),
    (0xec, _,             _, _, _, Instruction_Name::IN,        Some(Opcode_Operand::REGISTER(AL)),                            Some(Opcode_Operand::REGISTER(DX)),                            None, None),
    (0xed, _,             _, _, _, Instruction_Name::IN,        Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eAX)), Some(Opcode_Operand::REGISTER(DX)),                            None, None),
    (0xee, _,             _, _, _, Instruction_Name::OUT,       Some(Opcode_Operand::REGISTER(DX)),                            Some(Opcode_Operand::REGISTER(AL)),                            None, None),
    (0xef, _,             _, _, _, Instruction_Name::OUT,       Some(Opcode_Operand::REGISTER(DX)),                            Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eAX)), None, None),


    (0xf1, _,             _, _, _, Instruction_Name::INT1,      Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),       None,                                                          None, None),
    (0xf4, _,             _, _, _, Instruction_Name::HLT,       Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),       None,                                                          None, None),
    (0xf5, _,             _, _, _, Instruction_Name::CMC,       Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),       None,                                                          None, None),

    (0xf8, _,             _, _, _, Instruction_Name::CLC,       None,                                                          None,                                                          None, None),
    (0xf9, _,             _, _, _, Instruction_Name::STC,       None,                                                          None,                                                          None, None),
    (0xfa, _,             _, _, _, Instruction_Name::CLI,       None,                                                          None,                                                          None, None),
    (0xfb, _,             _, _, _, Instruction_Name::STI,       None,                                                          None,                                                          None, None),
    (0xfc, _,             _, _, _, Instruction_Name::CLD,       None,                                                          None,                                                          None, None),
    (0xfd, _,             _, _, _, Instruction_Name::STD,       None,                                                          None,                                                          None, None),
);

pub fn search_opcode_two_byte(opcode: u8, mode: InstMode, prefix: Inst_Prefix, modrm: Option<ModRMByte>) -> Option<Opcode_Table_Result>
{
    let x = (opcode, mode, prefix, modrm);
    match x
    {
        (0x02, _, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::LAR, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ew)), None, None]}),
        (0x03, _, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::LSL, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ew)), None, None]}),
        (0x05, InstMode::x64, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::SYSCALL, operands: [None, None, None, None]}),
        (0x06, _, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::CLTS, operands: [None, None, None, None]}),
        (0x07, InstMode::x64, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::SYSRET, operands: [None, None, None, None]}),

        (0x08, _, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::INVD, operands: [None, None, None, None]}),
        (0x09, _, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::WBINVD, operands: [None, None, None, None]}),
        (0x09, _, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::PRE_FETCH_W, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None, None]}),


        (0x10, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPNZ_BND_F2), .. }, .. }, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_SD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::Hx), 
                                                                                           Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wsd)), None]}),
        (0x10, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPZ_F3), .. }, .. }, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_SS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::Hx), 
                                                                                           Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wss)), None]}),
        (0x10, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_UPD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wpd)), 
                                                                                            None, None]}),
        (0x10, _, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_UPS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wps)), 
                                                                                            None, None]}),


        (0x11, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPNZ_BND_F2), .. }, .. }, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_SD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wsd)), Some(Opcode_Operand::Hx), 
                                                                                           Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vsd)), None]}),
        (0x11, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPZ_F3), .. }, .. }, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_SS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wss)), Some(Opcode_Operand::Hx), 
                                                                                           Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vss)), None]}),
        (0x11, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_UPD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vpd)), 
                                                                                            None, None]}),
        (0x11, _, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_UPS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vps)), 
                                                                                            None, None]}),

        // TODO: 0x12

        (0x13, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPNZ_BND_F2), .. }, .. }, _) => 
            None,

        (0x13, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPZ_F3), .. }, .. }, _) => 
            None,

        (0x13, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_UPD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Mq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vq)), 
                                                                                            None, None]}),
        (0x13, _, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_LPS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Mq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vq)), 
                                                                                            None, None]}),


        (0x14, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPNZ_BND_F2), .. }, .. }, _) => 
            None,

        (0x14, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPZ_F3), .. }, .. }, _) => 
            None,

        (0x14, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_UNPACK_LPD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), 
                                                                                               Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0x14, _, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_UNPACK_LPS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::Hx), 
                                                                                               Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),


        (0x15, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPNZ_BND_F2), .. }, .. }, _) => 
            None,

        (0x15, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPZ_F3), .. }, .. }, _) => 
            None,

        (0x15, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_UNPACK_HPD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), 
                                                                                               Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0x15, _, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_UNPACK_HPS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::Hx), 
                                                                                               Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
         // TODO: 0x16

        (0x17, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPNZ_BND_F2), .. }, .. }, _) => 
            None,

        (0x17, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPZ_F3), .. }, .. }, _) => 
            None,

        (0x17, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_HPD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Mq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vq)), 
                                                                                            None, None]}),
        (0x17, _, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_HPS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Mq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vq)), 
                                                                                            None, None]}),

        _ => None
    }
}
