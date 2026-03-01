use crate::{registers::*, Inst_Prefix, ModRMByte, Prefix_Acc, Prefix_Group1, Prefix_Group3};

#[derive(Debug, Copy, Clone)]
pub enum InstMode
{
    x64,
    x32,
}

#[derive(Debug, Copy, Clone, PartialEq)]
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
    J_CC_O,
    J_CC_NO,
    J_CC_B_CNAE,
    J_CC_AE_NB_NC,
    J_CC_E_Z,
    J_CC_NE_NZ,
    J_CC_BE_NA,
    J_CC_A_NBE,
    J_CC_S,
    J_CC_NS,
    J_CC_P_PE,
    J_CC_NP_PO,
    J_CC_L_NGE,
    J_CC_NL_GE,
    J_CC_LE_NA,
    J_CC_NLE_G,
    JMPE,

    SET_CC_O,
    SET_CC_NO,
    SET_CC_B_CNAE,
    SET_CC_AE_NB_NC,
    SET_CC_E_Z,
    SET_CC_NE_NZ,
    SET_CC_BE_NA,
    SET_CC_A_NBE,
    SET_CC_S,
    SET_CC_NS,
    SET_CC_P_PE,
    SET_CC_NP_PO,
    SET_CC_L_NGE,
    SET_CC_NL_GE,
    SET_CC_LE_NA,
    SET_CC_NLE_G,

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
    
    POPCNT, TZCNT, LZCNT,

    SAHF, LAHF,

    MOVSW, MOVSD, MOVSB, MOVSQ, MOV_DQ, MOV_Q, MOVDQ, MOVQ, MOVZX, MOVSX, MOV_NTL,
    CMPSB, CMPSW, CMPSD, CMPSQ,

    STOS, STOSB, STOSW, STOSD, STOSQ,
    LODSB, LODSW, LODSD, LODSQ,
    SCASB, SCASW, SCASD, SCASQ,

    LES, LDS, LAR, LSL,
    CMPXCHG, LSS, BTR, LFS, LGS,

    ENTER, READ, LEAVE,
    INT, INT1, INT3,
    INTO,

    IRET, IRETD, IRETQ,
    AAM, AAD,
    XLATB,

    LOOPNZ, LOOPZ, LOOP,
    JrCXZ, IN, OUT,

    HLT, CMC,

    CLC, STC, CLI, STI, CLD, STD, CLTS,

    ROL, ROR, RCL, RCR, SHL, SHR, SAR,
    // XABORT, XBEGIN,

    SYSCALL, SYSRET, CPUID,

    BT, SHLD, RSM, BTS, SHRD, BTC, BSF, BSR,

    INVD, WBINVD, PRE_FETCH_W,

    V_MOV_UPS, V_MOV_UPD, V_MOV_SS, V_MOV_SD,
    V_MOV_DDUP, V_MOV_SLDUP, V_MOV_LPD, V_MOV_LPS,
    V_MOV_HPS, V_MOV_HPD, V_MOV_APD, V_MOV_APS, V_MOV_NT_PS, V_MOV_NT_PD,
    V_MOV_MSK_PS, V_MOV_MSK_PD, V_MOV_DQ, V_MOV_DQA, V_MOV_DQU, VMOVDQ, VMOVQ,
    VMOVDQA, VMOVDQU, V_MOV_SHDUP, MOVQ2DQ, MOVDQ2Q, PMOVMSKB, VPMOVMSKB,

    V_UNPACK_HPD, V_UNPACK_HPS,
    V_UNPACK_LPD, V_UNPACK_LPS,

    V_SQRT_PS, V_SQRT_PD, V_SQRT_SS, V_SQRT_SD, V_RSQRT_PS, V_RSQRT_SS, 

    V_RCP_PS, V_RCP_SS,

    V_AND_PS, V_AND_PD, V_ANDN_PS, V_ANDN_PD, V_OR_PS, V_OR_PD, V_XOR_PS, V_XOR_PD, 
    V_ADD_PS, V_ADD_PD, V_ADD_SS, V_ADD_SD, V_MUL_PS, V_MUL_PD, V_MUL_SS, V_MUL_SD,
    VHADDPD, VHSUBPD, VHSUBPS,
    PADDQ, VPADDQ, PMULLW, VPMULLW, 

    V_SUB_PS, V_SUB_PD, V_SUB_SS, V_SUB_SD, 
    V_MIN_PS, V_MIN_PD, V_MIN_SS, V_MIN_SD,
    V_DIV_PS, V_DIV_PD, V_DIV_SS, V_DIV_SD,
    V_MAX_PS, V_MAX_PD, V_MAX_SS, V_MAX_SD,
    VADDSUBPD, VADDSUBPS, PSUBUSB, VPSUBUSB, PSUBUSW, VPSUBUSW,

    V_CVT_PS2_PD, V_CVT_PD2_PS, V_CVT_SS2_SD, V_CVT_SD2_SS,
    V_CVT_DQ2_PS, V_CVT_PS2_DQ, V_CVT_TPS2_DQ,

    V_CMP_PS, V_CMP_PD, V_CMP_SS, V_CMP_SD,

    PMINUB, VPMINUB, PAND, VPAND, PADDUSB, VPADDUSB, PADDUSW, VPADDUSW, PMAXUB, VPMAXUB, PANDN, VPANDN, PAVGB, VPAVGB,
    PSRAW, VPSRAW, PSRAD, VPSRAD, PMULHUW, VPMULHUW, PMULHW, VPMULHW,
    VCTTPD2DQ, VCVTDQ2PD, VCVTPD2DQ, MOVNTDQ, VMOVNTDQ, PSUBSB, PMINSW, VPMINSW, POR, VPOR, PADDSB, VPADDSB, PADDSW, VPADDSW,
    PMAXSW, VPMAXSW, PXOR, VPXOR, VLDDQU, PSLLW, VPSLLW, PSLLD, VPSLLD, PSLLQ, VPSLLQ, PMULUDQ, VPMULUDQ, PMADDWD, VPMADDWD, PSADBW,
    VPSADBW, MASKMOVQ, VMASKMOVDQU, PSUBB, VPSUBB, PSUBW, VPSUBW, PSUBD, VPSUBD, PSUBQ, VPSUBQ, PADDB, VPADDB, PADDW, VPADDW, PADDD, VPADDD,

    PSHUFW, PSHUFD, VPSHUFHW, VPSSHUFLW, VSHUFPS, VSHUFPD,
    PEXTRW, VPEXTRW,

    BSWAP, 
    
    PSRLW, VPSRLW, PSRLD, 

    PUNPCK_LBW, VPUNPCK_LBW, PUNPCK_LWD, VPUNPCK_LWD,
    PUNPCK_LDQ, VPUNPCK_LDQ, PUNPCK_SWB, VPUNPCK_SWB,
    PACKUSWB, VPACKUSWB, PUNPCKHBW, VPUNPCKHBW,
    PUNPCKHWD, VPUNPCKHWD, PUNPCKHDQ, VPUNPCKHDQ,
    PACKSSDW, VPACKSSDW, VPUNPCKLQDQ, VPUNPCKHQDQ,

    PCMP_GTB, VPCMP_GTB, PCMP_GTW, VPCMP_GTW, PCMP_GTD, VPCMP_GTD,
    PCMPEQB, PCMPEQW, PCMPEQD, 

    VPCMPEQB, VPCMPEQW, VPCMPEQD,

    VMREAD, VMWRITE,

    XADD,

    FADD, FMUL, FCOM, FCOMP, FSUB, FSUBR, FDIV, FDIVR,
    FLD, FST, FSTP, FLDENV, FLDCW, FSTENV, FSTCW,
    FXCH, FNOP, FCHS, FABS, FTST, FXAM, F2XM1,
    FYL2X, FPTAN, FPATAN, FXTRACT, FPREM1,
    FDECSTP, FINCSTP,
    FLD1, FLDL2T, FLDL2E, FLDPI, FLDLG2, FLDLN2,
    FLDZ, FPREM, FYL2XP1, FSQRT, FSINCOS, FRNDINT,
    FSCALE, FSIN, FCOS,
    FUCOMPP, FCMOVB, FCMOVBE, FCMOV, FCMOVU,
    FIADD, FIMUL, FICOM, FICOMP, FISUB, FISUBR, FIDIV, FIDIVR,
    FILD, FISTTP, FIST, FISTP, FCMOVNB, FCMOVNBE, FCOMI,
    FCMOVNE, FCMOVNU, FUCOMI, FCLEX, FINIT,
    FSAVE, FSTSW, FRSTOR, FFREE, FUCOM, FUCOMP,
    FADDP, FSUBRP, FDIVRP, FMULP, FSUBP, FDIVP,
    FCOMPP, FBSTP, FBLD, FCOMIP, FUCOMIP, FCMOVE,

    CVTPI2_PS, CVTPI2_PD, V_CTSI2_SS, V_CTSI2_SD,
    CVTT_PS_2PI, CVTT_PD_2PI, V_CVTT_SS_2SI, CVT_PS_2PI, CVT_PD_2PI, V_CVT_SS_2SI, VUCOMI_SS, VUCOMI_SD, VCOMI_SS, VCOMI_SD, 
    WRMSR, RDTSC, RDMSR, RDPMC, SYSENTER, SYSEXIT, GETSEC,

    CMOV_O, CMOV_NO, CMOV_B_C_NAE, CMOV_AE_NB_NC, CMOV_E_Z, CMOV_NE_NZ, CMOV_BE_NA, CMOV_A_NBE, CMOV_S, CMOV_NS, CMOV_P_PE, CMOV_NP_PO, CMOV_L_NGE, CMOV_NL_HE, CMOV_LE_NG, CMOV_NLE_G, 

    NOP,
    BNDLDX, BNDMOV, BNDCL, BNDCU, BNDSTX, BNDMK, BNDCN,

    VPSRLD, VSRLQ, VPSRLQ,
    PSRLQ,
}

impl std::fmt::Display for Instruction_Name {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
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

pub fn size_register(reg: Register_Unsized, size: Register_Size) -> std::io::Result<Register>
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
    Eb, Ev, Ev_d64, Ew, Ey,
    Gb, Gv, Gw, Gz, Gy, Gd,
    M, Ma, Mp, Mq, Mps, Mpd, Mx, My,
    Nq, 
    Sw,
    Cd,
    Dd,
    Rd,

    FLOAT_Single_Real,
    FLOAT_14_28_byte,
    FLOAT_2_byte,
    FLOAT_DWORD_INTEGER,
    FLOAT_DOUBLE_REAL,
    FLOAT_98_108_byte,
    FLOAT_WORD_INTEGER,
    FLOAT_PACKED_BCD,
    FLOAT_QUAD_INTEGER,

    Wx, Wps, Wss, Wsd, Wpd, Wq, Wdq,
    Vx, Vss, Vsd, Vq, Vps, Vpd, Vdq, Vy,
    Hx, Hss, Hsd, Hq, Hps, Hpd,
    Ppi, Pq, Pd,
    Qpi, Qd, Qq,
    Ux, Uq, Ups, Upd, Udq,
}

#[derive(Debug, Copy, Clone)]
pub enum Opcode_Operand_Dis
{
    Jb, Jz, Jq,
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

    FLOAT_AX,
}

#[derive(Debug, Copy, Clone)]
pub struct Opcode_Table_Result
{
    pub instruction: Instruction_Name,
    pub operands: [Option<Opcode_Operand>; 4]
}

// macro_rules! declare_table {
//     ($table_name:ident,
//         $(($op:expr, $inst_mode:pat, $operand_override:pat, $address_override:pat, $rex_w:pat, $instruction:expr, $operand1:expr, $operand2:expr, $operand3:expr, $operand4:expr)),+
//         $(,)?
//     ) => {
//         pub fn $table_name(opcode: u8, mode: InstMode, operand_override: bool, address_override: bool, rex_w: bool) -> Option<Opcode_Table_Result>
//         {
//             let x = (opcode, mode, operand_override, address_override, rex_w);
//             match x
//             {
//                 $(
//                     ($op, $inst_mode, $operand_override, $address_override, $rex_w) => 
//                     Some(Opcode_Table_Result {
//                         instruction: $instruction,
//                         operands: [ $operand1,
//                                     $operand2,
//                                     $operand3,
//                                     $operand4]
//                     }),
//                 )+
// 
//                 _ => None
//             }
//         }
//     };
// }

// Some(Opcode_Operand::REGISTER(search_register(modrm.rm, Register_Type::x87, Register_Size::_80, None).unwrap())),

fn d8_lookup(modrm: &ModRMByte) -> Option<Opcode_Table_Result>
{
    let d8_row = (modrm.byte & 0xF0) >> 4;
    let d8_col = (modrm.byte & 0x0F) >> 0;
    let d8_lookup = [
        [
            Some(Opcode_Operand::REGISTER(ST0)),
            Some(Opcode_Operand::REGISTER(ST0)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST0)),
            Some(Opcode_Operand::REGISTER(ST1)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST0)),
            Some(Opcode_Operand::REGISTER(ST2)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST0)),
            Some(Opcode_Operand::REGISTER(ST3)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST0)),
            Some(Opcode_Operand::REGISTER(ST4)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST0)),
            Some(Opcode_Operand::REGISTER(ST5)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST0)),
            Some(Opcode_Operand::REGISTER(ST6)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST0)),
            Some(Opcode_Operand::REGISTER(ST7)),
            None,
            None,
        ],
    ];

    match (d8_row, d8_col > 0x7) {
        (0xc, false) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FADD,
            operands: d8_lookup[(d8_col % 8) as usize],
        }),
        (0xd, false) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FCOM,
            operands: d8_lookup[(d8_col % 8) as usize],
        }),
        (0xe, false) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FSUB,
            operands: d8_lookup[(d8_col % 8) as usize],
        }),
        (0xf, false) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FDIV,
            operands: d8_lookup[(d8_col % 8) as usize],
        }),
        (0xc, true) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FMUL,
            operands: d8_lookup[(d8_col % 8) as usize],
        }),
        (0xd, true) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FCOMP,
            operands: d8_lookup[(d8_col % 8) as usize],
        }),
        (0xe, true) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FSUBR,
            operands: d8_lookup[(d8_col % 8) as usize],
        }),
        (0xf, true) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FDIVR,
            operands: d8_lookup[(d8_col % 8) as usize],
        }),
        _ => None,
    }
}

fn d9_lookup(modrm: &ModRMByte) -> Option<Opcode_Table_Result>
{
    match modrm.byte {
        0xc0 => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FLD,
            operands: [
                Some(Opcode_Operand::REGISTER(ST0)),
                Some(Opcode_Operand::REGISTER(ST0)),
                None,
                None,
            ],
        }),

        0xc1 => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FLD,
            operands: [
                Some(Opcode_Operand::REGISTER(ST0)),
                Some(Opcode_Operand::REGISTER(ST1)),
                None,
                None,
            ],
        }),
        0xc2 => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FLD,
            operands: [
                Some(Opcode_Operand::REGISTER(ST0)),
                Some(Opcode_Operand::REGISTER(ST2)),
                None,
                None,
            ],
        }),
        0xc3 => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FLD,
            operands: [
                Some(Opcode_Operand::REGISTER(ST0)),
                Some(Opcode_Operand::REGISTER(ST3)),
                None,
                None,
            ],
        }),
        0xc4 => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FLD,
            operands: [
                Some(Opcode_Operand::REGISTER(ST0)),
                Some(Opcode_Operand::REGISTER(ST4)),
                None,
                None,
            ],
        }),
        0xc5 => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FLD,
            operands: [
                Some(Opcode_Operand::REGISTER(ST0)),
                Some(Opcode_Operand::REGISTER(ST5)),
                None,
                None,
            ],
        }),
        0xc6 => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FLD,
            operands: [
                Some(Opcode_Operand::REGISTER(ST0)),
                Some(Opcode_Operand::REGISTER(ST6)),
                None,
                None,
            ],
        }),
        0xc7 => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FLD,
            operands: [
                Some(Opcode_Operand::REGISTER(ST0)),
                Some(Opcode_Operand::REGISTER(ST7)),
                None,
                None,
            ],
        }),

        0xD0 => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FNOP,
            operands: [
                None,
                None,
                None,
                None,
            ],
        }),

        0xE0 => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FCHS,
            operands: [
                None,
                None,
                None,
                None,
            ],
        }),

        0xE1 => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FABS,
            operands: [
                None,
                None,
                None,
                None,
            ],
        }),

        0xE4 => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FTST,
            operands: [
                None,
                None,
                None,
                None,
            ],
        }),

        0xE5 => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FXAM,
            operands: [
                None,
                None,
                None,
                None,
            ],
        }),

        0xF0 => Some(Opcode_Table_Result {
            instruction: Instruction_Name::F2XM1,
            operands: [
                None,
                None,
                None,
                None,
            ],
        }),

        0xF1 => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FYL2X,
            operands: [
                None,
                None,
                None,
                None,
            ],
        }),

        0xF2 => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FPTAN,
            operands: [
                None,
                None,
                None,
                None,
            ],
        }),

        0xF3 => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FPATAN,
            operands: [
                None,
                None,
                None,
                None,
            ],
        }),

        0xF4 => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FXTRACT,
            operands: [
                None,
                None,
                None,
                None,
            ],
        }),

        0xF5 => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FPREM1,
            operands: [
                None,
                None,
                None,
                None,
            ],
        }),

        0xF6 => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FDECSTP,
            operands: [
                None,
                None,
                None,
                None,
            ],
        }),

        0xF7 => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FINCSTP,
            operands: [
                None,
                None,
                None,
                None,
            ],
        }),

        0xc8 => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FXCH,
            operands: [
                Some(Opcode_Operand::REGISTER(ST0)),
                Some(Opcode_Operand::REGISTER(ST0)),
                None,
                None,
            ],
        }),

        0xc9 => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FXCH,
            operands: [
                Some(Opcode_Operand::REGISTER(ST0)),
                Some(Opcode_Operand::REGISTER(ST1)),
                None,
                None,
            ],
        }),
        0xca => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FXCH,
            operands: [
                Some(Opcode_Operand::REGISTER(ST0)),
                Some(Opcode_Operand::REGISTER(ST2)),
                None,
                None,
            ],
        }),
        0xcb => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FXCH,
            operands: [
                Some(Opcode_Operand::REGISTER(ST0)),
                Some(Opcode_Operand::REGISTER(ST3)),
                None,
                None,
            ],
        }),
        0xcc => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FXCH,
            operands: [
                Some(Opcode_Operand::REGISTER(ST0)),
                Some(Opcode_Operand::REGISTER(ST4)),
                None,
                None,
            ],
        }),
        0xcd => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FXCH,
            operands: [
                Some(Opcode_Operand::REGISTER(ST0)),
                Some(Opcode_Operand::REGISTER(ST5)),
                None,
                None,
            ],
        }),
        0xce => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FXCH,
            operands: [
                Some(Opcode_Operand::REGISTER(ST0)),
                Some(Opcode_Operand::REGISTER(ST6)),
                None,
                None,
            ],
        }),
        0xcf => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FXCH,
            operands: [
                Some(Opcode_Operand::REGISTER(ST0)),
                Some(Opcode_Operand::REGISTER(ST7)),
                None,
                None,
            ],
        }),



        0xE8 => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FLD1,
            operands: [
                None,
                None,
                None,
                None,
            ],
        }),

        0xE9 => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FLDL2T,
            operands: [
                None,
                None,
                None,
                None,
            ],
        }),

        0xEA => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FLDL2E,
            operands: [
                None,
                None,
                None,
                None,
            ],
        }),

        0xEB => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FLDPI,
            operands: [
                None,
                None,
                None,
                None,
            ],
        }),

        0xEC => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FLDLG2,
            operands: [
                None,
                None,
                None,
                None,
            ],
        }),

        0xED => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FLDLN2,
            operands: [
                None,
                None,
                None,
                None,
            ],
        }),

        0xEE => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FLDZ,
            operands: [
                None,
                None,
                None,
                None,
            ],
        }),

        0xF8 => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FPREM,
            operands: [
                None,
                None,
                None,
                None,
            ],
        }),

        0xF9 => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FYL2XP1,
            operands: [
                None,
                None,
                None,
                None,
            ],
        }),

        0xFA => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FSQRT,
            operands: [
                None,
                None,
                None,
                None,
            ],
        }),

        0xFB => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FSINCOS,
            operands: [
                None,
                None,
                None,
                None,
            ],
        }),

        0xFC => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FRNDINT,
            operands: [
                None,
                None,
                None,
                None,
            ],
        }),

        0xFD => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FSCALE,
            operands: [
                None,
                None,
                None,
                None,
            ],
        }),

        0xFE => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FSIN,
            operands: [
                None,
                None,
                None,
                None,
            ],
        }),

        0xFF => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FCOS,
            operands: [
                None,
                None,
                None,
                None,
            ],
        }),

        _ => None,
    }
}

fn da_lookup(modrm: &ModRMByte) -> Option<Opcode_Table_Result>
{
    let da_row = (modrm.byte & 0xF0) >> 4;
    let da_col = (modrm.byte & 0x0F) >> 0;
    let da_lookup = [
        [
            Some(Opcode_Operand::REGISTER(ST0)),
            Some(Opcode_Operand::REGISTER(ST0)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST0)),
            Some(Opcode_Operand::REGISTER(ST1)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST0)),
            Some(Opcode_Operand::REGISTER(ST2)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST0)),
            Some(Opcode_Operand::REGISTER(ST3)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST0)),
            Some(Opcode_Operand::REGISTER(ST4)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST0)),
            Some(Opcode_Operand::REGISTER(ST5)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST0)),
            Some(Opcode_Operand::REGISTER(ST6)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST0)),
            Some(Opcode_Operand::REGISTER(ST7)),
            None,
            None,
        ],
    ];

    if modrm.byte == 0xE9 {
        return Some(Opcode_Table_Result {
            instruction: Instruction_Name::FUCOMPP,
            operands: [
                None,
                None,
                None,
                None,
            ],
        })
    }

    match (da_row, da_col > 0x7) {
        (0xc, false) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FCMOVB,
            operands: da_lookup[(da_col % 8) as usize],
        }),
        (0xd, false) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FCMOVBE,
            operands: da_lookup[(da_col % 8) as usize],
        }),

        (0xc, true) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FCMOVE,
            operands: da_lookup[(da_col % 8) as usize],
        }),
        (0xd, true) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FCMOVU,
            operands: da_lookup[(da_col % 8) as usize],
        }),
        _ => None,
    }
}

fn db_lookup(modrm: &ModRMByte) -> Option<Opcode_Table_Result>
{
    let db_row = (modrm.byte & 0xF0) >> 4;
    let db_col = (modrm.byte & 0x0F) >> 0;
    let db_lookup = [
        [
            Some(Opcode_Operand::REGISTER(ST0)),
            Some(Opcode_Operand::REGISTER(ST0)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST0)),
            Some(Opcode_Operand::REGISTER(ST1)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST0)),
            Some(Opcode_Operand::REGISTER(ST2)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST0)),
            Some(Opcode_Operand::REGISTER(ST3)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST0)),
            Some(Opcode_Operand::REGISTER(ST4)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST0)),
            Some(Opcode_Operand::REGISTER(ST5)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST0)),
            Some(Opcode_Operand::REGISTER(ST6)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST0)),
            Some(Opcode_Operand::REGISTER(ST7)),
            None,
            None,
        ],
    ];

    if modrm.byte == 0xe2 {
        return Some(Opcode_Table_Result {
            instruction: Instruction_Name::FCLEX,
            operands: [
                None,
                None,
                None,
                None,
            ]
        });
    }

    if modrm.byte == 0xe3 {
        return Some(Opcode_Table_Result {
            instruction: Instruction_Name::FINIT,
            operands: [
                None,
                None,
                None,
                None,
            ]
        });
    }

    match (db_row, db_col > 0x7) {
        (0xc, false) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FCMOVNB,
            operands: db_lookup[(db_col % 8) as usize],
        }),
        (0xd, false) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FCMOVNBE,
            operands: db_lookup[(db_col % 8) as usize],
        }),
        // (0xe, false) => Some(Opcode_Table_Result {
        //     instruction: Instruction_Name::FSUB,
        //     operands: d8_lookup[(d8_col % 8) as usize],
        // }),
        (0xf, false) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FCOMI,
            operands: db_lookup[(db_col % 8) as usize],
        }),
        (0xc, true) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FCMOVNE,
            operands: db_lookup[(db_col % 8) as usize],
        }),
        (0xd, true) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FCMOVNU,
            operands: db_lookup[(db_col % 8) as usize],
        }),
        (0xe, true) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FUCOMI,
            operands: db_lookup[(db_col % 8) as usize],
        }),
        // (0xf, true) => Some(Opcode_Table_Result {
        //     instruction: Instruction_Name::FDIVR,
        //     operands: d8_lookup[(d8_col % 8) as usize],
        // }),
        _ => None,
    }
}

fn dc_lookup(modrm: &ModRMByte) -> Option<Opcode_Table_Result>
{
    let dc_row = (modrm.byte & 0xF0) >> 4;
    let dc_col = (modrm.byte & 0x0F) >> 0;
    let dc_lookup = [
        [
            Some(Opcode_Operand::REGISTER(ST0)),
            Some(Opcode_Operand::REGISTER(ST0)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST1)),
            Some(Opcode_Operand::REGISTER(ST0)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST2)),
            Some(Opcode_Operand::REGISTER(ST0)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST3)),
            Some(Opcode_Operand::REGISTER(ST0)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST4)),
            Some(Opcode_Operand::REGISTER(ST0)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST5)),
            Some(Opcode_Operand::REGISTER(ST0)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST6)),
            Some(Opcode_Operand::REGISTER(ST0)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST7)),
            Some(Opcode_Operand::REGISTER(ST0)),
            None,
            None,
        ],
    ];

    match (dc_row, dc_col > 0x7) {
        (0xc, false) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FADD,
            operands: dc_lookup[(dc_col % 8) as usize],
        }),
        (0xe, false) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FSUBR,
            operands: dc_lookup[(dc_col % 8) as usize],
        }),
        (0xf, false) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FDIVR,
            operands: dc_lookup[(dc_col % 8) as usize],
        }),
        (0xc, true) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FMUL,
            operands: dc_lookup[(dc_col % 8) as usize],
        }),
        // (0xd, true) => Some(Opcode_Table_Result {
        //     instruction: Instruction_Name::FCMOVNU,
        //     operands: db_lookup[(db_col % 8) as usize],
        // }),
        (0xe, true) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FSUB,
            operands: dc_lookup[(dc_col % 8) as usize],
        }),
        (0xf, true) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FDIV,
            operands: dc_lookup[(dc_col % 8) as usize],
        }),
        _ => None,
    }
}

fn dd_lookup(modrm: &ModRMByte) -> Option<Opcode_Table_Result>
{
    let dd_row = (modrm.byte & 0xF0) >> 4;
    let dd_col = (modrm.byte & 0x0F) >> 0;
    let dd_lookup_fucom = [
        [
            Some(Opcode_Operand::REGISTER(ST0)),
            Some(Opcode_Operand::REGISTER(ST0)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST1)),
            Some(Opcode_Operand::REGISTER(ST0)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST2)),
            Some(Opcode_Operand::REGISTER(ST0)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST3)),
            Some(Opcode_Operand::REGISTER(ST0)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST4)),
            Some(Opcode_Operand::REGISTER(ST0)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST5)),
            Some(Opcode_Operand::REGISTER(ST0)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST6)),
            Some(Opcode_Operand::REGISTER(ST0)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST7)),
            Some(Opcode_Operand::REGISTER(ST0)),
            None,
            None,
        ],
    ];

    let dd_lookup = [
        [
            Some(Opcode_Operand::REGISTER(ST0)),
            None,
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST1)),
            None,
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST2)),
            None,
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST3)),
            None,
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST4)),
            None,
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST5)),
            None,
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST6)),
            None,
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST7)),
            None,
            None,
            None,
        ],
    ];
    match (dd_row, dd_col > 0x7) {
        (0xc, false) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FFREE,
            operands: dd_lookup[(dd_col % 8) as usize],
        }),
        (0xd, false) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FST,
            operands: dd_lookup[(dd_col % 8) as usize],
        }),
        (0xe, false) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FUCOM,
            operands: dd_lookup_fucom[(dd_col % 8) as usize],
        }),
        // (0xc, true) => Some(Opcode_Table_Result {
        //     instruction: Instruction_Name::FMUL,
        //     operands: dd_lookup[(dd_col % 8) as usize],
        // }),
        (0xd, true) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FSTP,
            operands: dd_lookup[(dd_col % 8) as usize],
        }),
        (0xe, true) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FUCOMP,
            operands: dd_lookup[(dd_col % 8) as usize],
        }),
        // (0xf, true) => Some(Opcode_Table_Result {
        //     instruction: Instruction_Name::FDIV,
        //     operands: dd_lookup[(dd_col % 8) as usize],
        // }),
        _ => None,
    }
}

fn de_lookup(modrm: &ModRMByte) -> Option<Opcode_Table_Result>
{
    let de_row = (modrm.byte & 0xF0) >> 4;
    let de_col = (modrm.byte & 0x0F) >> 0;
    let de_lookup = [
        [
            Some(Opcode_Operand::REGISTER(ST0)),
            Some(Opcode_Operand::REGISTER(ST0)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST1)),
            Some(Opcode_Operand::REGISTER(ST0)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST2)),
            Some(Opcode_Operand::REGISTER(ST0)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST3)),
            Some(Opcode_Operand::REGISTER(ST0)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST4)),
            Some(Opcode_Operand::REGISTER(ST0)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST5)),
            Some(Opcode_Operand::REGISTER(ST0)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST6)),
            Some(Opcode_Operand::REGISTER(ST0)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST7)),
            Some(Opcode_Operand::REGISTER(ST0)),
            None,
            None,
        ],
    ];

    if modrm.byte == 0xd9 {
        return Some(Opcode_Table_Result { 
            instruction: Instruction_Name::FCOMPP, 
            operands: [
                None,
                None,
                None,
                None,
            ],
        })
    }

    match (de_row, de_col > 0x7) {
        (0xc, false) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FADDP,
            operands: de_lookup[(de_col % 8) as usize],
        }),
        // (0xd, false) => Some(Opcode_Table_Result {
        //     instruction: Instruction_Name::FST,
        //     operands: de_lookup[(de_col % 8) as usize],
        // }),
        (0xe, false) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FSUBRP,
            operands: de_lookup[(de_col % 8) as usize],
        }),
        (0xf, false) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FDIVRP,
            operands: de_lookup[(de_col % 8) as usize],
        }),
        (0xc, true) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FMULP,
            operands: de_lookup[(de_col % 8) as usize],
        }),
        (0xe, true) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FSUBP,
            operands: de_lookup[(de_col % 8) as usize],
        }),
        (0xf, true) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FDIVP,
            operands: de_lookup[(de_col % 8) as usize],
        }),
        _ => None,
    }
}

fn df_lookup(modrm: &ModRMByte) -> Option<Opcode_Table_Result>
{
    let df_row = (modrm.byte & 0xF0) >> 4;
    let df_col = (modrm.byte & 0x0F) >> 0;
    let df_lookup = [
        [
            Some(Opcode_Operand::REGISTER(ST0)),
            Some(Opcode_Operand::REGISTER(ST0)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST0)),
            Some(Opcode_Operand::REGISTER(ST1)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST0)),
            Some(Opcode_Operand::REGISTER(ST2)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST0)),
            Some(Opcode_Operand::REGISTER(ST3)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST0)),
            Some(Opcode_Operand::REGISTER(ST4)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST0)),
            Some(Opcode_Operand::REGISTER(ST5)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST0)),
            Some(Opcode_Operand::REGISTER(ST6)),
            None,
            None,
        ],
        [
            Some(Opcode_Operand::REGISTER(ST0)),
            Some(Opcode_Operand::REGISTER(ST7)),
            None,
            None,
        ],
    ];

    if modrm.byte == 0xE0 {
        return Some(Opcode_Table_Result {
            instruction: Instruction_Name::FSTSW,
            operands: [
                Some(Opcode_Operand::FLOAT_AX),
                None,
                None,
                None,
            ]
        })
    }

    match (df_row, df_col > 0x7) {
        (0xf, false) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FCOMIP,
            operands: df_lookup[(df_col % 8) as usize],
        }),
        (0xe, true) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FUCOMIP,
            operands: df_lookup[(df_col % 8) as usize],
        }),
        _ => None,
    }
}

pub fn search_opcode_one_byte_float(opcode: u8, modrm: &ModRMByte) -> Option<Opcode_Table_Result>
{
    let in_bf_range = modrm.byte <= 0xBF;

    match (opcode, in_bf_range, modrm)
    {
        (0xd8, true, ModRMByte { reg_op: 0b000, ..}) => Some(Opcode_Table_Result { 
            instruction: Instruction_Name::FADD, 
            operands: [
                Some(Opcode_Operand::REGISTER(ST0)),
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_Single_Real)),
                None,
                None,
            ]}),

        (0xd8, true, ModRMByte { reg_op: 0b001, ..}) => Some(Opcode_Table_Result { 
            instruction: Instruction_Name::FMUL, 
            operands: [
                Some(Opcode_Operand::REGISTER(ST0)),
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_Single_Real)),
                None,
                None,
            ]}),

        (0xd8, true, ModRMByte { reg_op: 0b010, ..}) => Some(Opcode_Table_Result { 
            instruction: Instruction_Name::FCOM, 
            operands: [
                Some(Opcode_Operand::REGISTER(ST0)),
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_Single_Real)),
                None,
                None,
            ]}),

        (0xd8, true, ModRMByte { reg_op: 0b011, ..}) => Some(Opcode_Table_Result { 
            instruction: Instruction_Name::FCOMP, 
            operands: [
                Some(Opcode_Operand::REGISTER(ST0)),
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_Single_Real)),
                None,
                None,
            ]}),

        (0xd8, true, ModRMByte { reg_op: 0b100, ..}) => Some(Opcode_Table_Result { 
            instruction: Instruction_Name::FSUB, 
            operands: [
                Some(Opcode_Operand::REGISTER(ST0)),
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_Single_Real)),
                None,
                None,
            ]}),

        (0xd8, true, ModRMByte { reg_op: 0b101, ..}) => Some(Opcode_Table_Result { 
            instruction: Instruction_Name::FSUBR, 
            operands: [
                Some(Opcode_Operand::REGISTER(ST0)),
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_Single_Real)),
                None,
                None,
            ]}),

        (0xd8, true, ModRMByte { reg_op: 0b110, ..}) => Some(Opcode_Table_Result { 
            instruction: Instruction_Name::FDIV, 
            operands: [
                Some(Opcode_Operand::REGISTER(ST0)),
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_Single_Real)),
                None,
                None,
            ]}),

        (0xd8, true, ModRMByte { reg_op: 0b111, ..}) => Some(Opcode_Table_Result { 
            instruction: Instruction_Name::FDIVR, 
            operands: [
                Some(Opcode_Operand::REGISTER(ST0)),
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_Single_Real)),
                None,
                None,
            ]}),

        (0xd8, false, modrm) => d8_lookup(modrm),

        (0xd9, true, ModRMByte { reg_op: 0b000, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FLD,
            operands: [
                Some(Opcode_Operand::REGISTER(ST0)),
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_Single_Real)),
                None,
                None,
            ]
        }),

        // 0x001 is blank

        (0xd9, true, ModRMByte { reg_op: 0b010, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FST,
            operands: [
                Some(Opcode_Operand::REGISTER(ST0)),
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_Single_Real)),
                None,
                None,
            ]
        }),

        (0xd9, true, ModRMByte { reg_op: 0b011, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FSTP,
            operands: [
                Some(Opcode_Operand::REGISTER(ST0)),
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_Single_Real)),
                None,
                None,
            ]
        }),

        (0xd9, true, ModRMByte { reg_op: 0b100, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FLDENV,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_14_28_byte)),
                None,
                None,
                None,
            ]
        }),

        (0xd9, true, ModRMByte { reg_op: 0b101, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FLDCW,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_2_byte)),
                None,
                None,
                None,
            ]
        }),

        (0xd9, true, ModRMByte { reg_op: 0b110, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FSTENV,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_14_28_byte)),
                None,
                None,
                None,
            ]
        }),

        (0xd9, true, ModRMByte { reg_op: 0b111, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FSTCW,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_2_byte)),
                None,
                None,
                None,
            ]
        }),

        (0xda, true, ModRMByte { reg_op: 0b000, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FIADD,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_DWORD_INTEGER)),
                None,
                None,
                None,
            ]
        }),

        (0xd9, false, modrm) => d9_lookup(modrm),

        (0xda, true, ModRMByte { reg_op: 0b001, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FIMUL,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_DWORD_INTEGER)),
                None,
                None,
                None,
            ]
        }),

        (0xda, true, ModRMByte { reg_op: 0b010, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FICOM,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_DWORD_INTEGER)),
                None,
                None,
                None,
            ]
        }),

        (0xda, true, ModRMByte { reg_op: 0b011, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FICOMP,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_DWORD_INTEGER)),
                None,
                None,
                None,
            ]
        }),

        (0xda, true, ModRMByte { reg_op: 0b100, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FISUB,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_DWORD_INTEGER)),
                None,
                None,
                None,
            ]
        }),

        (0xda, true, ModRMByte { reg_op: 0b101, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FISUBR,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_DWORD_INTEGER)),
                None,
                None,
                None,
            ]
        }),

        (0xda, true, ModRMByte { reg_op: 0b110, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FIDIV,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_DWORD_INTEGER)),
                None,
                None,
                None,
            ]
        }),

        (0xda, true, ModRMByte { reg_op: 0b111, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FIDIVR,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_DWORD_INTEGER)),
                None,
                None,
                None,
            ]
        }),

        (0xda, false, modrm) => da_lookup(modrm),

        (0xdb, true, ModRMByte { reg_op: 0b000, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FILD,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_DWORD_INTEGER)),
                None,
                None,
                None,
            ]
        }),

        (0xdb, true, ModRMByte { reg_op: 0b001, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FISTTP,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_DWORD_INTEGER)),
                None,
                None,
                None,
            ]
        }),

        (0xdb, true, ModRMByte { reg_op: 0b010, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FIST,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_DWORD_INTEGER)),
                None,
                None,
                None,
            ]
        }),

        (0xdb, true, ModRMByte { reg_op: 0b011, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FISTP,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_DWORD_INTEGER)),
                None,
                None,
                None,
            ]
        }),

        (0xdb, true, ModRMByte { reg_op: 0b101, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FLD,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_DWORD_INTEGER)),
                None,
                None,
                None,
            ]
        }),

        (0xdb, true, ModRMByte { reg_op: 0b111, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FSTP,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_DWORD_INTEGER)),
                None,
                None,
                None,
            ]
        }),

        (0xdb, true, modrm) => db_lookup(modrm),

        (0xdc, true, ModRMByte { reg_op: 0b000, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FADD,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_DOUBLE_REAL)),
                None,
                None,
                None,
            ]
        }),

        (0xdc, true, ModRMByte { reg_op: 0b001, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FMUL,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_DOUBLE_REAL)),
                None,
                None,
                None,
            ]
        }),

        (0xdc, true, ModRMByte { reg_op: 0b010, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FCOM,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_DOUBLE_REAL)),
                None,
                None,
                None,
            ]
        }),

        (0xdc, true, ModRMByte { reg_op: 0b011, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FCOMP,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_DOUBLE_REAL)),
                None,
                None,
                None,
            ]
        }),

        (0xdc, true, ModRMByte { reg_op: 0b100, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FSUB,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_DOUBLE_REAL)),
                None,
                None,
                None,
            ]
        }),

        (0xdc, true, ModRMByte { reg_op: 0b101, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FSUBR,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_DOUBLE_REAL)),
                None,
                None,
                None,
            ]
        }),

        (0xdc, true, ModRMByte { reg_op: 0b110, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FDIV,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_DOUBLE_REAL)),
                None,
                None,
                None,
            ]
        }),

        (0xdc, true, ModRMByte { reg_op: 0b111, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FDIVR,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_DOUBLE_REAL)),
                None,
                None,
                None,
            ]
        }),

        (0xdc, false, modrm) => dc_lookup(modrm),

        (0xdd, true, ModRMByte { reg_op: 0b000, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FLD,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_DOUBLE_REAL)),
                None,
                None,
                None,
            ]
        }),

        (0xdd, true, ModRMByte { reg_op: 0b001, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FISTTP,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_DOUBLE_REAL)),
                None,
                None,
                None,
            ]
        }),

        (0xdd, true, ModRMByte { reg_op: 0b010, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FST,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_DOUBLE_REAL)),
                None,
                None,
                None,
            ]
        }),

        (0xdd, true, ModRMByte { reg_op: 0b011, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FSTP,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_DOUBLE_REAL)),
                None,
                None,
                None,
            ]
        }),

        (0xdd, true, ModRMByte { reg_op: 0b100, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FRSTOR,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_98_108_byte)),
                None,
                None,
                None,
            ]
        }),

        (0xdd, true, ModRMByte { reg_op: 0b110, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FSAVE,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_98_108_byte)),
                None,
                None,
                None,
            ]
        }),

        (0xdd, true, ModRMByte { reg_op: 0b111, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FSTSW,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_2_byte)),
                None,
                None,
                None,
            ]
        }),

        (0xdd, true, modrm) => dd_lookup(modrm),

        (0xde, true, ModRMByte { reg_op: 0b000, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FIADD,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_WORD_INTEGER)),
                None,
                None,
                None,
            ]
        }),

        (0xde, true, ModRMByte { reg_op: 0b001, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FIMUL,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_WORD_INTEGER)),
                None,
                None,
                None,
            ]
        }),

        (0xde, true, ModRMByte { reg_op: 0b010, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FICOM,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_WORD_INTEGER)),
                None,
                None,
                None,
            ]
        }),

        (0xde, true, ModRMByte { reg_op: 0b011, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FICOMP,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_WORD_INTEGER)),
                None,
                None,
                None,
            ]
        }),

        (0xde, true, ModRMByte { reg_op: 0b100, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FISUB,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_WORD_INTEGER)),
                None,
                None,
                None,
            ]
        }),

        (0xde, true, ModRMByte { reg_op: 0b101, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FISUBR,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_WORD_INTEGER)),
                None,
                None,
                None,
            ]
        }),

        (0xde, true, ModRMByte { reg_op: 0b110, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FIDIV,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_WORD_INTEGER)),
                None,
                None,
                None,
            ]
        }),

        (0xde, true, ModRMByte { reg_op: 0b111, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FIDIVR,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_WORD_INTEGER)),
                None,
                None,
                None,
            ]
        }),

        (0xde, true, modrm) => de_lookup(modrm),

        (0xdf, true, ModRMByte { reg_op: 0b000, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FILD,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_WORD_INTEGER)),
                None,
                None,
                None,
            ]
        }),

        (0xdf, true, ModRMByte { reg_op: 0b001, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FISTTP,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_WORD_INTEGER)),
                None,
                None,
                None,
            ]
        }),

        (0xdf, true, ModRMByte { reg_op: 0b010, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FIST,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_WORD_INTEGER)),
                None,
                None,
                None,
            ]
        }),

        (0xdf, true, ModRMByte { reg_op: 0b011, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FISTP,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_WORD_INTEGER)),
                None,
                None,
                None,
            ]
        }),

        (0xdf, true, ModRMByte { reg_op: 0b100, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FBLD,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_PACKED_BCD)),
                None,
                None,
                None,
            ]
        }),

        (0xdf, true, ModRMByte { reg_op: 0b101, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FILD,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_QUAD_INTEGER)),
                None,
                None,
                None,
            ]
        }),

        (0xdf, true, ModRMByte { reg_op: 0b110, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FBSTP,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_PACKED_BCD)),
                None,
                None,
                None,
            ]
        }),

        (0xdf, true, ModRMByte { reg_op: 0b111, ..}) => Some(Opcode_Table_Result {
            instruction: Instruction_Name::FISTP,
            operands: [
                Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::FLOAT_QUAD_INTEGER)),
                None,
                None,
                None,
            ]
        }),

        (0xdf, false, modrm) => df_lookup(modrm),

        _ => None,
    }
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



        (_, 0x81, ModRMByte { reg_op: 0b000, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::ADD, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)), None, None]}),

        (_, 0x81, ModRMByte { reg_op: 0b001, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::OR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)), None, None]}),

        (_, 0x81, ModRMByte { reg_op: 0b010, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::ADC, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)), None, None]}),

        (_, 0x81, ModRMByte { reg_op: 0b011, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::SBB, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)), None, None]}),

        (_, 0x81, ModRMByte { reg_op: 0b100, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::AND, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)), None, None]}),

        (_, 0x81, ModRMByte { reg_op: 0b101, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::SUB, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)), None, None]}),

        (_, 0x81, ModRMByte { reg_op: 0b110, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::XOR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)), None, None]}),

        (_, 0x81, ModRMByte { reg_op: 0b111, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::CMP, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)), None, None]}),



        
        (InstMode::x32, 0x82, ModRMByte { reg_op: 0b000, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::ADD, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (InstMode::x32, 0x82, ModRMByte { reg_op: 0b001, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::OR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (InstMode::x32, 0x82, ModRMByte { reg_op: 0b010, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::ADC, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (InstMode::x32, 0x82, ModRMByte { reg_op: 0b011, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::SBB, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (InstMode::x32, 0x82, ModRMByte { reg_op: 0b100, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::AND, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (InstMode::x32, 0x82, ModRMByte { reg_op: 0b101, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::SUB, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (InstMode::x32, 0x82, ModRMByte { reg_op: 0b110, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::XOR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (InstMode::x32, 0x82, ModRMByte { reg_op: 0b111, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::CMP, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),



        (_, 0x83, ModRMByte { reg_op: 0b000, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::ADD, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (_, 0x83, ModRMByte { reg_op: 0b001, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::OR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (_, 0x83, ModRMByte { reg_op: 0b010, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::ADC, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (_, 0x83, ModRMByte { reg_op: 0b011, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::SBB, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (_, 0x83, ModRMByte { reg_op: 0b100, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::AND, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (_, 0x83, ModRMByte { reg_op: 0b101, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::SUB, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (_, 0x83, ModRMByte { reg_op: 0b110, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::XOR, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        (_, 0x83, ModRMByte { reg_op: 0b111, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::CMP, 
                                                                              operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
                                                                                         Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),
        
        // (InstMode::x32, 0x80, ModRMByte { reg_op: 0b000, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::ADD, 
        //                                                                       operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
        //                                                                                  Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        // (InstMode::x32, 0x80, ModRMByte { reg_op: 0b001, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::OR, 
        //                                                                       operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
        //                                                                                  Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        // (InstMode::x32, 0x80, ModRMByte { reg_op: 0b010, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::ADC, 
        //                                                                       operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
        //                                                                                  Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        // (InstMode::x32, 0x80, ModRMByte { reg_op: 0b011, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::SBB, 
        //                                                                       operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
        //                                                                                  Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        // (InstMode::x32, 0x80, ModRMByte { reg_op: 0b100, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::AND, 
        //                                                                       operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
        //                                                                                  Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        // (InstMode::x32, 0x80, ModRMByte { reg_op: 0b101, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::SUB, 
        //                                                                       operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
        //                                                                                  Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        // (InstMode::x32, 0x80, ModRMByte { reg_op: 0b110, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::XOR, 
        //                                                                       operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
        //                                                                                  Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        // (InstMode::x32, 0x80, ModRMByte { reg_op: 0b111, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::CMP, 
        //                                                                       operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), 
        //                                                                                  Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),


        // (_, 0x80, ModRMByte { reg_op: 0b000, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::ADD, 
        //                                                                       operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
        //                                                                                  Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        // (_, 0x80, ModRMByte { reg_op: 0b001, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::OR, 
        //                                                                       operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
        //                                                                                  Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        // (_, 0x80, ModRMByte { reg_op: 0b010, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::ADC, 
        //                                                                       operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
        //                                                                                  Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        // (_, 0x80, ModRMByte { reg_op: 0b011, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::SBB, 
        //                                                                       operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
        //                                                                                  Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        // (_, 0x80, ModRMByte { reg_op: 0b100, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::AND, 
        //                                                                       operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
        //                                                                                  Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        // (_, 0x80, ModRMByte { reg_op: 0b101, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::SUB, 
        //                                                                       operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
        //                                                                                  Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        // (_, 0x80, ModRMByte { reg_op: 0b110, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::XOR, 
        //                                                                       operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
        //                                                                                  Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),

        // (_, 0x80, ModRMByte { reg_op: 0b111, .. }) => Some(Opcode_Table_Result { instruction: Instruction_Name::CMP, 
        //                                                                       operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), 
        //                                                                                  Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None]}),



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

pub fn search_opcode_one_byte(
    opcode: u8,
    mode: InstMode,
    operand_override: bool,
    address_override: bool,
    rex_w: bool,
) -> Option<Opcode_Table_Result> {
    let x = (opcode, mode, operand_override, address_override, rex_w);
    match x {
        (0x00, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::ADD),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb))),
                None,
                None,
            ],
        }),
        (0x01, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::ADD),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv))),
                None,
                None,
            ],
        }),
        (0x02, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::ADD),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb))),
                None,
                None,
            ],
        }),
        (0x03, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::ADD),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev))),
                None,
                None,
            ],
        }),
        (0x04, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::ADD),
            operands: [
                (Some(Opcode_Operand::REGISTER(AL))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))),
                None,
                None,
            ],
        }),
        (0x05, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::ADD),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz))),
                None,
                None,
            ],
        }),
        (0x06, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::PUSH),
            operands: [(Some(Opcode_Operand::REGISTER(ES))), None, None, None],
        }),
        (0x07, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::POP),
            operands: [(Some(Opcode_Operand::REGISTER(ES))), None, None, None],
        }),
        (0x08, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::OR),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb))),
                None,
                None,
            ],
        }),
        (0x09, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::OR),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv))),
                None,
                None,
            ],
        }),
        (0x0a, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::OR),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb))),
                None,
                None,
            ],
        }),
        (0x0b, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::OR),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev))),
                None,
                None,
            ],
        }),
        (0x0c, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::OR),
            operands: [
                (Some(Opcode_Operand::REGISTER(AL))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))),
                None,
                None,
            ],
        }),
        (0x0d, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::OR),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz))),
                None,
                None,
            ],
        }),
        (0x0e, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::PUSH),
            operands: [(Some(Opcode_Operand::REGISTER(ES))), None, None, None],
        }),
        (0x10, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::ADC),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb))),
                None,
                None,
            ],
        }),
        (0x11, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::ADC),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv))),
                None,
                None,
            ],
        }),
        (0x12, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::ADC),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb))),
                None,
                None,
            ],
        }),
        (0x13, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::ADC),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev))),
                None,
                None,
            ],
        }),
        (0x14, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::ADC),
            operands: [
                (Some(Opcode_Operand::REGISTER(AL))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))),
                None,
                None,
            ],
        }),
        (0x15, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::ADC),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz))),
                None,
                None,
            ],
        }),
        (0x16, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::PUSH),
            operands: [(Some(Opcode_Operand::REGISTER(SS))), None, None, None],
        }),
        (0x17, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::POP),
            operands: [(Some(Opcode_Operand::REGISTER(SS))), None, None, None],
        }),
        (0x18, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::SBB),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb))),
                None,
                None,
            ],
        }),
        (0x19, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::SBB),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv))),
                None,
                None,
            ],
        }),
        (0x1a, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::SBB),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb))),
                None,
                None,
            ],
        }),
        (0x1b, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::SBB),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev))),
                None,
                None,
            ],
        }),
        (0x1c, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::SBB),
            operands: [
                (Some(Opcode_Operand::REGISTER(AL))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))),
                None,
                None,
            ],
        }),
        (0x1d, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::SBB),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz))),
                None,
                None,
            ],
        }),
        (0x1e, InstMode::x32, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::PUSH),
            operands: [(Some(Opcode_Operand::REGISTER(DS))), None, None, None],
        }),
        (0x1f, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::POP),
            operands: [(Some(Opcode_Operand::REGISTER(DS))), None, None, None],
        }),
        (0x20, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::AND),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb))),
                None,
                None,
            ],
        }),
        (0x21, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::AND),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv))),
                None,
                None,
            ],
        }),
        (0x22, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::AND),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb))),
                None,
                None,
            ],
        }),
        (0x23, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::AND),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev))),
                None,
                None,
            ],
        }),
        (0x24, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::AND),
            operands: [
                (Some(Opcode_Operand::REGISTER(AL))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))),
                None,
                None,
            ],
        }),
        (0x25, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::AND),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz))),
                None,
                None,
            ],
        }),
        (0x27, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::DAA),
            operands: [None, None, None, None],
        }),
        (0x28, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::SUB),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb))),
                None,
                None,
            ],
        }),
        (0x29, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::SUB),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv))),
                None,
                None,
            ],
        }),
        (0x2a, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::SUB),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb))),
                None,
                None,
            ],
        }),
        (0x2b, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::SUB),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev))),
                None,
                None,
            ],
        }),
        (0x2c, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::SUB),
            operands: [
                (Some(Opcode_Operand::REGISTER(AL))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))),
                None,
                None,
            ],
        }),
        (0x2d, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::SUB),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz))),
                None,
                None,
            ],
        }),
        (0x2f, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::DAS),
            operands: [None, None, None, None],
        }),
        (0x30, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::XOR),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb))),
                None,
                None,
            ],
        }),
        (0x31, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::XOR),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv))),
                None,
                None,
            ],
        }),
        (0x32, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::XOR),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb))),
                None,
                None,
            ],
        }),
        (0x33, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::XOR),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev))),
                None,
                None,
            ],
        }),
        (0x34, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::XOR),
            operands: [
                (Some(Opcode_Operand::REGISTER(AL))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))),
                None,
                None,
            ],
        }),
        (0x35, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::XOR),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz))),
                None,
                None,
            ],
        }),
        (0x37, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::AAA),
            operands: [None, None, None, None],
        }),
        (0x38, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::CMP),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb))),
                None,
                None,
            ],
        }),
        (0x39, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::CMP),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv))),
                None,
                None,
            ],
        }),
        (0x3a, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::CMP),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb))),
                None,
                None,
            ],
        }),
        (0x3b, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::CMP),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev))),
                None,
                None,
            ],
        }),
        (0x3c, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::CMP),
            operands: [
                (Some(Opcode_Operand::REGISTER(AL))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))),
                None,
                None,
            ],
        }),
        (0x3d, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::CMP),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz))),
                None,
                None,
            ],
        }),
        (0x3f, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::AAS),
            operands: [None, None, None, None],
        }),
        (0x40, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::INC),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eAX))),
                None,
                None,
                None,
            ],
        }),
        (0x41, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::INC),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eCX))),
                None,
                None,
                None,
            ],
        }),
        (0x42, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::INC),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eDX))),
                None,
                None,
                None,
            ],
        }),
        (0x43, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::INC),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eBX))),
                None,
                None,
                None,
            ],
        }),
        (0x44, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::INC),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eSP))),
                None,
                None,
                None,
            ],
        }),
        (0x45, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::INC),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eBP))),
                None,
                None,
                None,
            ],
        }),
        (0x46, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::INC),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eSI))),
                None,
                None,
                None,
            ],
        }),
        (0x47, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::INC),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eDI))),
                None,
                None,
                None,
            ],
        }),
        (0x48, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::DEC),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eAX))),
                None,
                None,
                None,
            ],
        }),
        (0x49, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::DEC),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eCX))),
                None,
                None,
                None,
            ],
        }),
        (0x4a, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::DEC),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eDX))),
                None,
                None,
                None,
            ],
        }),
        (0x4b, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::DEC),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eBX))),
                None,
                None,
                None,
            ],
        }),
        (0x4c, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::DEC),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eSP))),
                None,
                None,
                None,
            ],
        }),
        (0x4d, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::DEC),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eBP))),
                None,
                None,
                None,
            ],
        }),
        (0x4e, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::DEC),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eSI))),
                None,
                None,
                None,
            ],
        }),
        (0x4f, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::DEC),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eDI))),
                None,
                None,
                None,
            ],
        }),
        (0x50, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::PUSH),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rAX),
                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r8),
                )))),
                None,
                None,
                None,
            ],
        }),
        (0x51, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::PUSH),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rCX),
                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r9),
                )))),
                None,
                None,
                None,
            ],
        }),
        (0x52, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::PUSH),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rDX),
                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r10),
                )))),
                None,
                None,
                None,
            ],
        }),
        (0x53, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::PUSH),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rBX),
                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r11),
                )))),
                None,
                None,
                None,
            ],
        }),
        (0x54, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::PUSH),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rSP),
                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r12),
                )))),
                None,
                None,
                None,
            ],
        }),
        (0x55, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::PUSH),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rBP),
                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r13),
                )))),
                None,
                None,
                None,
            ],
        }),
        (0x56, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::PUSH),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rSI),
                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r14),
                )))),
                None,
                None,
                None,
            ],
        }),
        (0x57, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::PUSH),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rDI),
                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r15),
                )))),
                None,
                None,
                None,
            ],
        }),
        (0x58, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::POP),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rAX),
                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r8),
                )))),
                None,
                None,
                None,
            ],
        }),
        (0x59, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::POP),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rCX),
                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r9),
                )))),
                None,
                None,
                None,
            ],
        }),
        (0x5a, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::POP),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rDX),
                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r10),
                )))),
                None,
                None,
                None,
            ],
        }),
        (0x5b, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::POP),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rBX),
                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r11),
                )))),
                None,
                None,
                None,
            ],
        }),
        (0x5c, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::POP),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rSP),
                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r12),
                )))),
                None,
                None,
                None,
            ],
        }),
        (0x5d, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::POP),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rBP),
                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r13),
                )))),
                None,
                None,
                None,
            ],
        }),
        (0x5e, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::POP),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rSI),
                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r14),
                )))),
                None,
                None,
                None,
            ],
        }),
        (0x5f, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::POP),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rDI),
                    Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r15),
                )))),
                None,
                None,
                None,
            ],
        }),
        (0x50, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::PUSH),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eAX))),
                None,
                None,
                None,
            ],
        }),
        (0x51, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::PUSH),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eCX))),
                None,
                None,
                None,
            ],
        }),
        (0x52, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::PUSH),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eDX))),
                None,
                None,
                None,
            ],
        }),
        (0x53, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::PUSH),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eBX))),
                None,
                None,
                None,
            ],
        }),
        (0x54, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::PUSH),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eSP))),
                None,
                None,
                None,
            ],
        }),
        (0x55, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::PUSH),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eBP))),
                None,
                None,
                None,
            ],
        }),
        (0x56, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::PUSH),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eSI))),
                None,
                None,
                None,
            ],
        }),
        (0x57, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::PUSH),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eDI))),
                None,
                None,
                None,
            ],
        }),
        (0x58, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::POP),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eAX))),
                None,
                None,
                None,
            ],
        }),
        (0x59, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::POP),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eCX))),
                None,
                None,
                None,
            ],
        }),
        (0x5a, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::POP),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eDX))),
                None,
                None,
                None,
            ],
        }),
        (0x5b, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::POP),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eBX))),
                None,
                None,
                None,
            ],
        }),
        (0x5c, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::POP),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eSP))),
                None,
                None,
                None,
            ],
        }),
        (0x5d, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::POP),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eBP))),
                None,
                None,
                None,
            ],
        }),
        (0x5e, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::POP),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eSI))),
                None,
                None,
                None,
            ],
        }),
        (0x5f, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::POP),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eDI))),
                None,
                None,
                None,
            ],
        }),
        (0x60, InstMode::x32, true, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::PUSHA),
            operands: [None, None, None, None],
        }),
        (0x60, InstMode::x32, false, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::PUSHAD),
            operands: [None, None, None, None],
        }),
        (0x61, InstMode::x32, true, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::POPA),
            operands: [None, None, None, None],
        }),
        (0x61, InstMode::x32, false, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::POPAD),
            operands: [None, None, None, None],
        }),
        (0x62, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::BOUND),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ma))),
                None,
                None,
            ],
        }),
        (0x63, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::ARPL),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ew))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gw))),
                None,
                None,
            ],
        }),
        (0x63, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOVSXD),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev))),
                None,
                None,
            ],
        }),
        (0x68, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::PUSH),
            operands: [
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz))),
                None,
                None,
                None,
            ],
        }),
        (0x69, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::IMUL),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz))),
                None,
            ],
        }),
        (0x6a, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::PUSH),
            operands: [
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))),
                None,
                None,
                None,
            ],
        }),
        (0x6b, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::IMUL),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))),
                None,
            ],
        }),
        (0x6c, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::INSB),
            operands: [
                (Some(Opcode_Operand::Yb)),
                (Some(Opcode_Operand::REGISTER(DX))),
                None,
                None,
            ],
        }),
        (0x6d, _, _, true, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::INSW),
            operands: [
                (Some(Opcode_Operand::Yz)),
                (Some(Opcode_Operand::REGISTER(DX))),
                None,
                None,
            ],
        }),
        (0x6d, _, _, false, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::INSD),
            operands: [
                (Some(Opcode_Operand::Yz)),
                (Some(Opcode_Operand::REGISTER(DX))),
                None,
                None,
            ],
        }),
        (0x6e, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::OUTSB),
            operands: [
                (Some(Opcode_Operand::REGISTER(DX))),
                (Some(Opcode_Operand::Xb)),
                None,
                None,
            ],
        }),
        (0x6f, _, _, true, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::OUTSW),
            operands: [
                (Some(Opcode_Operand::REGISTER(DX))),
                (Some(Opcode_Operand::Xz)),
                None,
                None,
            ],
        }),
        (0x6f, _, _, false, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::OUTSD),
            operands: [
                (Some(Opcode_Operand::REGISTER(DX))),
                (Some(Opcode_Operand::Xz)),
                None,
                None,
            ],
        }),
        (0x70, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::J_O),
            operands: [
                (Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb))),
                None,
                None,
                None,
            ],
        }),
        (0x71, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::J_NO),
            operands: [
                (Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb))),
                None,
                None,
                None,
            ],
        }),
        (0x72, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::J_B_NAE_C),
            operands: [
                (Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb))),
                None,
                None,
                None,
            ],
        }),
        (0x73, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::J_NB_AE_NC),
            operands: [
                (Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb))),
                None,
                None,
                None,
            ],
        }),
        (0x74, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::J_Z_E),
            operands: [
                (Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb))),
                None,
                None,
                None,
            ],
        }),
        (0x75, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::J_NZ_NE),
            operands: [
                (Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb))),
                None,
                None,
                None,
            ],
        }),
        (0x76, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::J_BE_NA),
            operands: [
                (Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb))),
                None,
                None,
                None,
            ],
        }),
        (0x77, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::J_NBE_A),
            operands: [
                (Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb))),
                None,
                None,
                None,
            ],
        }),
        (0x78, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::J_S),
            operands: [
                (Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb))),
                None,
                None,
                None,
            ],
        }),
        (0x79, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::J_NS),
            operands: [
                (Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb))),
                None,
                None,
                None,
            ],
        }),
        (0x7a, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::J_P_PE),
            operands: [
                (Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb))),
                None,
                None,
                None,
            ],
        }),
        (0x7b, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::J_NP_PO),
            operands: [
                (Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb))),
                None,
                None,
                None,
            ],
        }),
        (0x7c, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::J_L_NGE),
            operands: [
                (Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb))),
                None,
                None,
                None,
            ],
        }),
        (0x7d, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::J_NL_GE),
            operands: [
                (Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb))),
                None,
                None,
                None,
            ],
        }),
        (0x7e, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::J_LE_NG),
            operands: [
                (Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb))),
                None,
                None,
                None,
            ],
        }),
        (0x7f, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::J_NLE_G),
            operands: [
                (Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb))),
                None,
                None,
                None,
            ],
        }),
        (0x84, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::TEST),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb))),
                None,
                None,
            ],
        }),
        (0x85, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::TEST),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv))),
                None,
                None,
            ],
        }),
        (0x86, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::XCHG),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb))),
                None,
                None,
            ],
        }),
        (0x87, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::XCHG),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv))),
                None,
                None,
            ],
        }),
        (0x88, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb))),
                None,
                None,
            ],
        }),
        (0x89, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv))),
                None,
                None,
            ],
        }),
        (0x8a, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb))),
                None,
                None,
            ],
        }),
        (0x8b, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev))),
                None,
                None,
            ],
        }),
        (0x8c, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Sw))),
                None,
                None,
            ],
        }),
        (0x8d, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::LEA),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::M))),
                None,
                None,
            ],
        }),
        (0x8e, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Sw))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ew))),
                None,
                None,
            ],
        }),
        (0x90, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::XCHG),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rAX),
                    Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r8),
                )))),
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX))),
                None,
                None,
            ],
        }),
        (0x91, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::XCHG),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rCX),
                    Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r9),
                )))),
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX))),
                None,
                None,
            ],
        }),
        (0x92, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::XCHG),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rDX),
                    Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r10),
                )))),
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX))),
                None,
                None,
            ],
        }),
        (0x93, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::XCHG),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rBX),
                    Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r11),
                )))),
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX))),
                None,
                None,
            ],
        }),
        (0x94, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::XCHG),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rSP),
                    Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r12),
                )))),
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX))),
                None,
                None,
            ],
        }),
        (0x95, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::XCHG),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rBP),
                    Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r13),
                )))),
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX))),
                None,
                None,
            ],
        }),
        (0x96, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::XCHG),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rSI),
                    Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r14),
                )))),
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX))),
                None,
                None,
            ],
        }),
        (0x97, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::XCHG),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rDI),
                    Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r15),
                )))),
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX))),
                None,
                None,
            ],
        }),
        (0x90, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::XCHG),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eAX))),
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX))),
                None,
                None,
            ],
        }),
        (0x91, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::XCHG),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eCX))),
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX))),
                None,
                None,
            ],
        }),
        (0x92, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::XCHG),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eDX))),
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX))),
                None,
                None,
            ],
        }),
        (0x93, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::XCHG),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eBX))),
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX))),
                None,
                None,
            ],
        }),
        (0x94, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::XCHG),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eSP))),
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX))),
                None,
                None,
            ],
        }),
        (0x95, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::XCHG),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eBP))),
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX))),
                None,
                None,
            ],
        }),
        (0x96, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::XCHG),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eSI))),
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX))),
                None,
                None,
            ],
        }),
        (0x97, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::XCHG),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eDI))),
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX))),
                None,
                None,
            ],
        }),
        (0x98, _, true, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::CBW),
            operands: [None, None, None, None],
        }),
        (0x98, InstMode::x64, _, _, true) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::CDQE),
            operands: [None, None, None, None],
        }),
        (0x98, _, false, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::CWDE),
            operands: [None, None, None, None],
        }),
        (0x99, _, true, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::CWD),
            operands: [None, None, None, None],
        }),
        (0x99, InstMode::x64, _, _, true) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::CQO),
            operands: [None, None, None, None],
        }),
        (0x99, _, false, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::CDQ),
            operands: [None, None, None, None],
        }),
        (0x9a, InstMode::x32, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::far_Call),
            operands: [
                (Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Ap))),
                None,
                None,
                None,
            ],
        }),
        (0x9b, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::WAIT),
            operands: [None, None, None, None],
        }),
        (0x9c, _, true, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::PUSHF),
            operands: [None, None, None, None],
        }),
        (0x9c, InstMode::x32, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::PUSHFD),
            operands: [None, None, None, None],
        }),
        (0x9c, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::PUSHFQ),
            operands: [None, None, None, None],
        }),
        (0x9d, _, true, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::POPF),
            operands: [None, None, None, None],
        }),
        (0x9d, InstMode::x32, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::POPFD),
            operands: [None, None, None, None],
        }),
        (0x9d, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::POPFQ),
            operands: [None, None, None, None],
        }),
        (0x9e, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::SAHF),
            operands: [None, None, None, None],
        }),
        (0x9f, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::LAHF),
            operands: [None, None, None, None],
        }),
        (0xa0, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::REGISTER(AL))),
                (Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Ob))),
                None,
                None,
            ],
        }),
        (0xa1, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX))),
                (Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Ov))),
                None,
                None,
            ],
        }),
        (0xa2, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Ob))),
                (Some(Opcode_Operand::REGISTER(AL))),
                None,
                None,
            ],
        }),
        (0xa3, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Ov))),
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX))),
                None,
                None,
            ],
        }),
        (0xa4, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOVSB),
            operands: [
                (Some(Opcode_Operand::Yb)),
                (Some(Opcode_Operand::Xb)),
                None,
                None,
            ],
        }),
        (0xa5, _, _, false, true) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOVSQ),
            operands: [
                (Some(Opcode_Operand::Yv)),
                (Some(Opcode_Operand::Xv)),
                None,
                None,
            ],
        }),
        (0xa5, _, _, true, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOVSW),
            operands: [
                (Some(Opcode_Operand::Yv)),
                (Some(Opcode_Operand::Xv)),
                None,
                None,
            ],
        }),
        (0xa5, _, _, false, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOVSD),
            operands: [
                (Some(Opcode_Operand::Yv)),
                (Some(Opcode_Operand::Xv)),
                None,
                None,
            ],
        }),
        (0xa6, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::CMPSB),
            operands: [
                (Some(Opcode_Operand::Xb)),
                (Some(Opcode_Operand::Yb)),
                None,
                None,
            ],
        }),
        (0xa7, InstMode::x64, _, _, true) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::CMPSQ),
            operands: [
                (Some(Opcode_Operand::Xv)),
                (Some(Opcode_Operand::Yv)),
                None,
                None,
            ],
        }),
        (0xa7, _, true, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::CMPSD),
            operands: [
                (Some(Opcode_Operand::Xv)),
                (Some(Opcode_Operand::Yv)),
                None,
                None,
            ],
        }),
        (0xa7, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::CMPSW),
            operands: [
                (Some(Opcode_Operand::Xv)),
                (Some(Opcode_Operand::Yv)),
                None,
                None,
            ],
        }),
        (0xa8, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::TEST),
            operands: [
                (Some(Opcode_Operand::REGISTER(AL))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))),
                None,
                None,
            ],
        }),
        (0xa9, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::TEST),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz))),
                None,
                None,
            ],
        }),
        (0xaa, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::STOSB),
            operands: [
                (Some(Opcode_Operand::Yb)),
                (Some(Opcode_Operand::REGISTER(AL))),
                None,
                None,
            ],
        }),

        (0xab, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::STOS),
            operands: [
                (Some(Opcode_Operand::Yv)),
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX))),
                None,
                None,
            ],
        }),
        (0xac, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::LODSB),
            operands: [
                (Some(Opcode_Operand::REGISTER(AL))),
                (Some(Opcode_Operand::Xb)),
                None,
                None,
            ],
        }),
        (0xad, InstMode::x64, _, _, true) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::LODSQ),
            operands: [
                (Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb))),
                None,
                None,
                None,
            ],
        }),
        (0xad, _, true, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::LODSW),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX))),
                (Some(Opcode_Operand::Xv)),
                None,
                None,
            ],
        }),
        (0xad, _, false, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::LODSD),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX))),
                (Some(Opcode_Operand::Xv)),
                None,
                None,
            ],
        }),
        (0xae, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::SCASB),
            operands: [
                (Some(Opcode_Operand::REGISTER(AL))),
                (Some(Opcode_Operand::Yb)),
                None,
                None,
            ],
        }),
        (0xaf, InstMode::x64, _, _, true) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::SCASQ),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX))),
                (Some(Opcode_Operand::Yv)),
                None,
                None,
            ],
        }),
        (0xaf, _, true, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::SCASW),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX))),
                (Some(Opcode_Operand::Yv)),
                None,
                None,
            ],
        }),
        (0xaf, _, false, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::SCASD),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX))),
                (Some(Opcode_Operand::Yv)),
                None,
                None,
            ],
        }),
        (0xb0, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::KNOWN(AL),
                    Register_Known_Or_Unsized::KNOWN(R8L),
                )))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))),
                None,
                None,
            ],
        }),
        (0xb1, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::KNOWN(CL),
                    Register_Known_Or_Unsized::KNOWN(R9L),
                )))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))),
                None,
                None,
            ],
        }),
        (0xb2, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::KNOWN(DL),
                    Register_Known_Or_Unsized::KNOWN(R10L),
                )))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))),
                None,
                None,
            ],
        }),
        (0xb3, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::KNOWN(BL),
                    Register_Known_Or_Unsized::KNOWN(R11L),
                )))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))),
                None,
                None,
            ],
        }),
        (0xb4, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::KNOWN(AH),
                    Register_Known_Or_Unsized::KNOWN(R12L),
                )))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))),
                None,
                None,
            ],
        }),
        (0xb5, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::KNOWN(CH),
                    Register_Known_Or_Unsized::KNOWN(R13L),
                )))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))),
                None,
                None,
            ],
        }),
        (0xb6, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::KNOWN(DH),
                    Register_Known_Or_Unsized::KNOWN(R14L),
                )))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))),
                None,
                None,
            ],
        }),
        (0xb7, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::KNOWN(BH),
                    Register_Known_Or_Unsized::KNOWN(R15L),
                )))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))),
                None,
                None,
            ],
        }),
        (0xb0, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::REGISTER(AL))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))),
                None,
                None,
            ],
        }),
        (0xb1, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::REGISTER(CL))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))),
                None,
                None,
            ],
        }),
        (0xb2, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::REGISTER(DL))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))),
                None,
                None,
            ],
        }),
        (0xb3, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::REGISTER(BL))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))),
                None,
                None,
            ],
        }),
        (0xb4, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::REGISTER(AH))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))),
                None,
                None,
            ],
        }),
        (0xb5, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::REGISTER(CH))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))),
                None,
                None,
            ],
        }),
        (0xb6, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::REGISTER(DH))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))),
                None,
                None,
            ],
        }),
        (0xb7, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::REGISTER(BH))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))),
                None,
                None,
            ],
        }),
        (0xb8, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rAX),
                    Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r8),
                )))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv))),
                None,
                None,
            ],
        }),
        (0xb9, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rCX),
                    Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r9),
                )))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv))),
                None,
                None,
            ],
        }),
        (0xba, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rDX),
                    Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r10),
                )))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv))),
                None,
                None,
            ],
        }),
        (0xbb, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rBX),
                    Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r11),
                )))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv))),
                None,
                None,
            ],
        }),
        (0xbc, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rSP),
                    Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r12),
                )))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv))),
                None,
                None,
            ],
        }),
        (0xbd, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rBP),
                    Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r13),
                )))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv))),
                None,
                None,
            ],
        }),
        (0xbe, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rSI),
                    Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r14),
                )))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv))),
                None,
                None,
            ],
        }),
        (0xbf, InstMode::x64, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::REGISTER_REX_PAIR((
                    Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rDI),
                    Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r15),
                )))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv))),
                None,
                None,
            ],
        }),
        (0xb8, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eAX))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv))),
                None,
                None,
            ],
        }),
        (0xb9, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eCX))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv))),
                None,
                None,
            ],
        }),
        (0xba, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eDX))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv))),
                None,
                None,
            ],
        }),
        (0xbb, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eBX))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv))),
                None,
                None,
            ],
        }),
        (0xbc, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eSP))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv))),
                None,
                None,
            ],
        }),
        (0xbd, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eBP))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv))),
                None,
                None,
            ],
        }),
        (0xbe, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eSI))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv))),
                None,
                None,
            ],
        }),
        (0xbf, InstMode::x32, _, _, false) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::MOV),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eDI))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv))),
                None,
                None,
            ],
        }),
        (0xc2, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::near_Ret),
            operands: [
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iw))),
                None,
                None,
                None,
            ],
        }),
        (0xc3, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::near_Ret),
            operands: [None, None, None, None],
        }),
        (0xc4, InstMode::x32, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::LES),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gz))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Mp))),
                None,
                None,
            ],
        }),
        (0xc5, InstMode::x32, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::LDS),
            operands: [
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gz))),
                (Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Mp))),
                None,
                None,
            ],
        }),
        (0xc8, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::ENTER),
            operands: [
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iw))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))),
                None,
                None,
            ],
        }),
        (0xc9, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::LEAVE),
            operands: [None, None, None, None],
        }),
        (0xca, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::far_Ret),
            operands: [
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iw))),
                None,
                None,
                None,
            ],
        }),
        (0xcb, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::far_Ret),
            operands: [None, None, None, None],
        }),
        (0xcc, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::INT3),
            operands: [None, None, None, None],
        }),
        (0xcd, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::INT),
            operands: [
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))),
                None,
                None,
                None,
            ],
        }),
        (0xce, InstMode::x32, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::INTO),
            operands: [None, None, None, None],
        }),
        (0xcf, InstMode::x64, _, _, true) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::IRETQ),
            operands: [None, None, None, None],
        }),
        (0xcf, _, true, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::IRET),
            operands: [None, None, None, None],
        }),
        (0xcf, _, false, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::IRETD),
            operands: [None, None, None, None],
        }),
        (0xd4, InstMode::x32, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::AAM),
            operands: [
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))),
                None,
                None,
                None,
            ],
        }),
        (0xd5, InstMode::x32, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::AAD),
            operands: [
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))),
                None,
                None,
                None,
            ],
        }),
        (0xd7, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::XLATB),
            operands: [None, None, None, None],
        }),
        (0xe0, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::LOOPNZ),
            operands: [
                (Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb))),
                None,
                None,
                None,
            ],
        }),
        (0xe1, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::LOOPZ),
            operands: [
                (Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb))),
                None,
                None,
                None,
            ],
        }),
        (0xe2, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::LOOP),
            operands: [
                (Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb))),
                None,
                None,
                None,
            ],
        }),
        (0xe3, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::JrCXZ),
            operands: [
                (Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb))),
                None,
                None,
                None,
            ],
        }),
        (0xe4, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::IN),
            operands: [
                (Some(Opcode_Operand::REGISTER(AL))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))),
                None,
                None,
            ],
        }),
        (0xe5, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::IN),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eAX))),
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))),
                None,
                None,
            ],
        }),
        (0xe6, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::OUT),
            operands: [
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))),
                (Some(Opcode_Operand::REGISTER(AL))),
                None,
                None,
            ],
        }),
        (0xe7, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::OUT),
            operands: [
                (Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))),
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eAX))),
                None,
                None,
            ],
        }),
        (0xe8, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::near_Call),
            operands: [
                (Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jz))),
                None,
                None,
                None,
            ],
        }),
        (0xe9, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::near_Jmp),
            operands: [
                (Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jz))),
                None,
                None,
                None,
            ],
        }),
        (0xea, InstMode::x32, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::far_Jmp),
            operands: [
                (Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Ap))),
                None,
                None,
                None,
            ],
        }),
        (0xeb, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::short_Jmp),
            operands: [
                (Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb))),
                None,
                None,
                None,
            ],
        }),
        (0xec, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::IN),
            operands: [
                (Some(Opcode_Operand::REGISTER(AL))),
                (Some(Opcode_Operand::REGISTER(DX))),
                None,
                None,
            ],
        }),
        (0xed, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::IN),
            operands: [
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eAX))),
                (Some(Opcode_Operand::REGISTER(DX))),
                None,
                None,
            ],
        }),
        (0xee, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::OUT),
            operands: [
                (Some(Opcode_Operand::REGISTER(DX))),
                (Some(Opcode_Operand::REGISTER(AL))),
                None,
                None,
            ],
        }),
        (0xef, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::OUT),
            operands: [
                (Some(Opcode_Operand::REGISTER(DX))),
                (Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eAX))),
                None,
                None,
            ],
        }),
        (0xf1, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::INT1),
            operands: [
                (Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb))),
                None,
                None,
                None,
            ],
        }),
        (0xf4, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::HLT),
            operands: [
                (Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb))),
                None,
                None,
                None,
            ],
        }),
        (0xf5, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::CMC),
            operands: [
                (Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb))),
                None,
                None,
                None,
            ],
        }),
        (0xf8, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::CLC),
            operands: [None, None, None, None],
        }),
        (0xf9, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::STC),
            operands: [None, None, None, None],
        }),
        (0xfa, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::CLI),
            operands: [None, None, None, None],
        }),
        (0xfb, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::STI),
            operands: [None, None, None, None],
        }),
        (0xfc, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::CLD),
            operands: [None, None, None, None],
        }),
        (0xfd, _, _, _, _) => Some(Opcode_Table_Result {
            instruction: (Instruction_Name::STD),
            operands: [None, None, None, None],
        }),
        _ => None,
    }
}

// // TODO: the modrm byte might be needed to force operations which "can only operate on memory".
// // Anything with an M operand can only operate on memory
// declare_table!(search_opcode_one_byte,
//     (0x00, _,             _, _, _,     Instruction_Name::ADD,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)), None, None),
//     (0x01, _,             _, _, _,     Instruction_Name::ADD,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), None, None),
//     (0x02, _,             _, _, _,     Instruction_Name::ADD,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), None, None),
//     (0x03, _,             _, _, _,     Instruction_Name::ADD,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None),
//     (0x04, _,             _, _, _,     Instruction_Name::ADD,  Some(Opcode_Operand::REGISTER(AL)),                            Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)),    None, None),
//     (0x05, _,             _, _, _,     Instruction_Name::ADD,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)),    None, None),
//     (0x06, InstMode::x32, _, _, false, Instruction_Name::PUSH, Some(Opcode_Operand::REGISTER(ES)),                            None,                                                       None, None),
//     (0x07, InstMode::x32, _, _, false, Instruction_Name::POP,  Some(Opcode_Operand::REGISTER(ES)),                            None,                                                       None, None),
// 
//     (0x08, _,             _, _, _,     Instruction_Name::OR,   Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)), None, None),
//     (0x09, _,             _, _, _,     Instruction_Name::OR,   Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), None, None),
//     (0x0a, _,             _, _, _,     Instruction_Name::OR,   Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), None, None),
//     (0x0b, _,             _, _, _,     Instruction_Name::OR,   Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None),
//     (0x0c, _,             _, _, _,     Instruction_Name::OR,   Some(Opcode_Operand::REGISTER(AL)),                            Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)),    None, None),
//     (0x0d, _,             _, _, _,     Instruction_Name::OR,   Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)),    None, None),
//     (0x0e, InstMode::x32, _, _, false, Instruction_Name::PUSH, Some(Opcode_Operand::REGISTER(ES)),                            None,                                                       None, None),
// 
// 
//     (0x10, _,             _, _, _,     Instruction_Name::ADC,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)), None, None),
//     (0x11, _,             _, _, _,     Instruction_Name::ADC,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), None, None),
//     (0x12, _,             _, _, _,     Instruction_Name::ADC,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), None, None),
//     (0x13, _,             _, _, _,     Instruction_Name::ADC,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None),
//     (0x14, _,             _, _, _,     Instruction_Name::ADC,  Some(Opcode_Operand::REGISTER(AL)),                            Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)),    None, None),
//     (0x15, _,             _, _, _,     Instruction_Name::ADC,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)),    None, None),
//     (0x16, InstMode::x32, _, _, false, Instruction_Name::PUSH, Some(Opcode_Operand::REGISTER(SS)),                            None,                                                       None, None),
//     (0x17, InstMode::x32, _, _, false, Instruction_Name::POP,  Some(Opcode_Operand::REGISTER(SS)),                            None,                                                       None, None),
// 
//     (0x18, _,             _, _, _,     Instruction_Name::SBB,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)), None, None),
//     (0x19, _,             _, _, _,     Instruction_Name::SBB,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), None, None),
//     (0x1a, _,             _, _, _,     Instruction_Name::SBB,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), None, None),
//     (0x1b, _,             _, _, _,     Instruction_Name::SBB,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None),
//     (0x1c, _,             _, _, _,     Instruction_Name::SBB,  Some(Opcode_Operand::REGISTER(AL)),                            Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)),    None, None),
//     (0x1d, _,             _, _, _,     Instruction_Name::SBB,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)),    None, None),
//     (0x1e, InstMode::x32, _, _, _,     Instruction_Name::PUSH, Some(Opcode_Operand::REGISTER(DS)),                            None,                                                       None, None),
//     (0x1f, InstMode::x32, _, _, false, Instruction_Name::POP,  Some(Opcode_Operand::REGISTER(DS)),                            None,                                                       None, None),
// 
// 
//     (0x20, _,             _, _, _,     Instruction_Name::AND,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)), None, None),
//     (0x21, _,             _, _, _,     Instruction_Name::AND,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), None, None),
//     (0x22, _,             _, _, _,     Instruction_Name::AND,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), None, None),
//     (0x23, _,             _, _, _,     Instruction_Name::AND,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None),
//     (0x24, _,             _, _, _,     Instruction_Name::AND,  Some(Opcode_Operand::REGISTER(AL)),                            Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)),    None, None),
//     (0x25, _,             _, _, _,     Instruction_Name::AND,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)),    None, None),
//     (0x27, InstMode::x32, _, _, false, Instruction_Name::DAA,  None,                                                          None,                                                       None, None),
// 
//     (0x28, _,             _, _, _,     Instruction_Name::SUB,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)), None, None),
//     (0x29, _,             _, _, _,     Instruction_Name::SUB,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), None, None),
//     (0x2a, _,             _, _, _,     Instruction_Name::SUB,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), None, None),
//     (0x2b, _,             _, _, _,     Instruction_Name::SUB,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None),
//     (0x2c, _,             _, _, _,     Instruction_Name::SUB,  Some(Opcode_Operand::REGISTER(AL)),                            Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)),    None, None),
//     (0x2d, _,             _, _, _,     Instruction_Name::SUB,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)),    None, None),
//     (0x2f, InstMode::x32, _, _, false, Instruction_Name::DAS,  None,                                                          None,                                                       None, None),
// 
// 
//     (0x30, _,             _, _, _,     Instruction_Name::XOR,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)), None, None),
//     (0x31, _,             _, _, _,     Instruction_Name::XOR,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), None, None),
//     (0x32, _,             _, _, _,     Instruction_Name::XOR,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), None, None),
//     (0x33, _,             _, _, _,     Instruction_Name::XOR,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None),
//     (0x34, _,             _, _, _,     Instruction_Name::XOR,  Some(Opcode_Operand::REGISTER(AL)),                            Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)),    None, None),
//     (0x35, _,             _, _, _,     Instruction_Name::XOR,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)),    None, None),
//     (0x37, InstMode::x32, _, _, false, Instruction_Name::AAA,  None,                                                          None,                                                       None, None),
// 
//     (0x38, _,             _, _, _,     Instruction_Name::CMP,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)), None, None),
//     (0x39, _,             _, _, _,     Instruction_Name::CMP,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), None, None),
//     (0x3a, _,             _, _, _,     Instruction_Name::CMP,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), None, None),
//     (0x3b, _,             _, _, _,     Instruction_Name::CMP,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)),    Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None),
//     (0x3c, _,             _, _, _,     Instruction_Name::CMP,  Some(Opcode_Operand::REGISTER(AL)),                            Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)),    None, None),
//     (0x3d, _,             _, _, _,     Instruction_Name::CMP,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)),    None, None),
//     (0x3f, InstMode::x32, _, _, false, Instruction_Name::AAS,  None,                                                          None,                                                       None, None),
// 
// 
//     (0x40, InstMode::x32, _, _, false, Instruction_Name::INC,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eAX)), None, None, None),
//     (0x41, InstMode::x32, _, _, false, Instruction_Name::INC,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eCX)), None, None, None),
//     (0x42, InstMode::x32, _, _, false, Instruction_Name::INC,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eDX)), None, None, None),
//     (0x43, InstMode::x32, _, _, false, Instruction_Name::INC,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eBX)), None, None, None),
//     (0x44, InstMode::x32, _, _, false, Instruction_Name::INC,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eSP)), None, None, None),
//     (0x45, InstMode::x32, _, _, false, Instruction_Name::INC,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eBP)), None, None, None),
//     (0x46, InstMode::x32, _, _, false, Instruction_Name::INC,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eSI)), None, None, None),
//     (0x47, InstMode::x32, _, _, false, Instruction_Name::INC,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eDI)), None, None, None),
// 
//     (0x48, InstMode::x32, _, _, false, Instruction_Name::DEC,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eAX)), None, None, None),
//     (0x49, InstMode::x32, _, _, false, Instruction_Name::DEC,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eCX)), None, None, None),
//     (0x4a, InstMode::x32, _, _, false, Instruction_Name::DEC,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eDX)), None, None, None),
//     (0x4b, InstMode::x32, _, _, false, Instruction_Name::DEC,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eBX)), None, None, None),
//     (0x4c, InstMode::x32, _, _, false, Instruction_Name::DEC,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eSP)), None, None, None),
//     (0x4d, InstMode::x32, _, _, false, Instruction_Name::DEC,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eBP)), None, None, None),
//     (0x4e, InstMode::x32, _, _, false, Instruction_Name::DEC,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eSI)), None, None, None),
//     (0x4f, InstMode::x32, _, _, false, Instruction_Name::DEC,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eDI)), None, None, None),
// 
// 
//     (0x50, InstMode::x64, _, _, _, Instruction_Name::PUSH, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rAX), 
//                                                                                                     Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r8)))), 
//                                                             None, None, None),
// 
//     (0x51, InstMode::x64, _, _, _, Instruction_Name::PUSH, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rCX), 
//                                                                                                     Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r9)))),
//                                                             None, None, None),
// 
//     (0x52, InstMode::x64, _, _, _, Instruction_Name::PUSH, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rDX), 
//                                                                                                     Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r10)))),
//                                                             None, None, None),
// 
//     (0x53, InstMode::x64, _, _, _, Instruction_Name::PUSH, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rBX), 
//                                                                                                     Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r11)))),
//                                                             None, None, None),
// 
//     (0x54, InstMode::x64, _, _, _, Instruction_Name::PUSH, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rSP), 
//                                                                                                     Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r12)))),
//                                                             None, None, None),
// 
//     (0x55, InstMode::x64, _, _, _, Instruction_Name::PUSH, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rBP), 
//                                                                                                     Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r13)))),
//                                                             None, None, None),
// 
//     (0x56, InstMode::x64, _, _, _, Instruction_Name::PUSH, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rSI), 
//                                                                                                     Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r14)))),
//                                                             None, None, None),
// 
//     (0x57, InstMode::x64, _, _, _, Instruction_Name::PUSH, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rDI), 
//                                                                                                     Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r15)))),
//                                                             None, None, None),
// 
// 
//     (0x58, InstMode::x64, _, _, _, Instruction_Name::POP,  Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rAX), 
//                                                                                                     Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r8)))),
//                                                             None, None, None),
// 
//     (0x59, InstMode::x64, _, _, _, Instruction_Name::POP,  Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rCX), 
//                                                                                                     Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r9)))),
//                                                             None, None, None),
// 
//     (0x5a, InstMode::x64, _, _, _, Instruction_Name::POP,  Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rDX), 
//                                                                                                     Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r10)))),
//                                                             None, None, None),
// 
//     (0x5b, InstMode::x64, _, _, _, Instruction_Name::POP,  Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rBX), 
//                                                                                                     Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r11)))),
//                                                             None, None, None),
// 
//     (0x5c, InstMode::x64, _, _, _, Instruction_Name::POP,  Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rSP), 
//                                                                                                     Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r12)))),
//                                                             None, None, None),
// 
//     (0x5d, InstMode::x64, _, _, _, Instruction_Name::POP,  Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rBP), 
//                                                                                                     Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r13)))),
//                                                             None, None, None),
// 
//     (0x5e, InstMode::x64, _, _, _, Instruction_Name::POP,  Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rSI), 
//                                                                                                     Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r14)))),
//                                                             None, None, None),
// 
//     (0x5f, InstMode::x64, _, _, _, Instruction_Name::POP,  Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::rDI), 
//                                                                                                     Register_Known_Or_Unsized::UNSIZED_d64(Register_Unsized::r15)))),
//                                                             None, None, None),
// 
// 
//     (0x50, InstMode::x32, _, _, false, Instruction_Name::PUSH,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eAX)),  None,  None, None),
//     (0x51, InstMode::x32, _, _, false, Instruction_Name::PUSH,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eCX)),  None,  None, None),
//     (0x52, InstMode::x32, _, _, false, Instruction_Name::PUSH,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eDX)),  None,  None, None),
//     (0x53, InstMode::x32, _, _, false, Instruction_Name::PUSH,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eBX)),  None,  None, None),
//     (0x54, InstMode::x32, _, _, false, Instruction_Name::PUSH,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eSP)),  None,  None, None),
//     (0x55, InstMode::x32, _, _, false, Instruction_Name::PUSH,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eBP)),  None,  None, None),
//     (0x56, InstMode::x32, _, _, false, Instruction_Name::PUSH,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eSI)),  None,  None, None),
//     (0x57, InstMode::x32, _, _, false, Instruction_Name::PUSH,  Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eDI)),  None,  None, None),
// 
//     (0x58, InstMode::x32, _, _, false, Instruction_Name::POP,   Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eAX)),  None,  None, None),
//     (0x59, InstMode::x32, _, _, false, Instruction_Name::POP,   Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eCX)),  None,  None, None),
//     (0x5a, InstMode::x32, _, _, false, Instruction_Name::POP,   Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eDX)),  None,  None, None),
//     (0x5b, InstMode::x32, _, _, false, Instruction_Name::POP,   Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eBX)),  None,  None, None),
//     (0x5c, InstMode::x32, _, _, false, Instruction_Name::POP,   Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eSP)),  None,  None, None),
//     (0x5d, InstMode::x32, _, _, false, Instruction_Name::POP,   Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eBP)),  None,  None, None),
//     (0x5e, InstMode::x32, _, _, false, Instruction_Name::POP,   Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eSI)),  None,  None, None),
//     (0x5f, InstMode::x32, _, _, false, Instruction_Name::POP,   Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eDI)),  None,  None, None),
// 
// 
//     (0x60, InstMode::x32, true,  _, false, Instruction_Name::PUSHA,  None,                                                        None,                                                       None, None),
//     (0x60, InstMode::x32, false, _, false, Instruction_Name::PUSHAD, None,                                                        None,                                                       None, None),
//     (0x61, InstMode::x32, true,  _, false, Instruction_Name::POPA,   None,                                                        None,                                                       None, None),
//     (0x61, InstMode::x32, false, _, false, Instruction_Name::POPAD,  None,                                                        None,                                                       None, None),
//     (0x62, InstMode::x32, _,     _, false, Instruction_Name::BOUND,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)),  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ma)), None, None),
//     (0x63, InstMode::x32, _,     _, false, Instruction_Name::ARPL,   Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ew)),  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gw)), None, None),
//     (0x63, InstMode::x64, _,     _, _,     Instruction_Name::MOVSXD, Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)),  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None),
// 
//     (0x68, _, _, _, _, Instruction_Name::PUSH, Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)),    None,                                                       None,                                                    None),
//     (0x69, _, _, _, _, Instruction_Name::IMUL, Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)), None),
//     (0x6a, _, _, _, _, Instruction_Name::PUSH, Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)),    None,                                                       None,                                                    None),
//     (0x6b, _, _, _, _, Instruction_Name::IMUL, Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None),
// 
//     (0x6c, _, _, _,     _, Instruction_Name::INSB,  Some(Opcode_Operand::Yb), Some(Opcode_Operand::REGISTER(DX)), None, None),
//     (0x6d, _, _, true,  _, Instruction_Name::INSW,  Some(Opcode_Operand::Yz), Some(Opcode_Operand::REGISTER(DX)), None, None),
//     (0x6d, _, _, false, _, Instruction_Name::INSD,  Some(Opcode_Operand::Yz), Some(Opcode_Operand::REGISTER(DX)), None, None),
// 
//     (0x6e, _, _, _,     _, Instruction_Name::OUTSB, Some(Opcode_Operand::REGISTER(DX)), Some(Opcode_Operand::Xb), None, None),
//     (0x6f, _, _, true,  _, Instruction_Name::OUTSW, Some(Opcode_Operand::REGISTER(DX)), Some(Opcode_Operand::Xz), None, None),
//     (0x6f, _, _, false, _, Instruction_Name::OUTSD, Some(Opcode_Operand::REGISTER(DX)), Some(Opcode_Operand::Xz), None, None),
// 
// 
//     (0x70, _, _, _, _, Instruction_Name::J_O,        Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),  None,  None, None),
//     (0x71, _, _, _, _, Instruction_Name::J_NO,       Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),  None,  None, None),
//     (0x72, _, _, _, _, Instruction_Name::J_B_NAE_C,  Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),  None,  None, None),
//     (0x73, _, _, _, _, Instruction_Name::J_NB_AE_NC, Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),  None,  None, None),
//     (0x74, _, _, _, _, Instruction_Name::J_Z_E,      Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),  None,  None, None),
//     (0x75, _, _, _, _, Instruction_Name::J_NZ_NE,    Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),  None,  None, None),
//     (0x76, _, _, _, _, Instruction_Name::J_BE_NA,    Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),  None,  None, None),
//     (0x77, _, _, _, _, Instruction_Name::J_NBE_A,    Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),  None,  None, None),
// 
//     (0x78, _, _, _, _, Instruction_Name::J_S,        Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),  None,  None, None),
//     (0x79, _, _, _, _, Instruction_Name::J_NS,       Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),  None,  None, None),
//     (0x7a, _, _, _, _, Instruction_Name::J_P_PE,     Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),  None,  None, None),
//     (0x7b, _, _, _, _, Instruction_Name::J_NP_PO,    Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),  None,  None, None),
//     (0x7c, _, _, _, _, Instruction_Name::J_L_NGE,    Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),  None,  None, None),
//     (0x7d, _, _, _, _, Instruction_Name::J_NL_GE,    Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),  None,  None, None),
//     (0x7e, _, _, _, _, Instruction_Name::J_LE_NG,    Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),  None,  None, None),
//     (0x7f, _, _, _, _, Instruction_Name::J_NLE_G,    Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),  None,  None, None),
// 
// 
//     (0x84, _, _, _, _, Instruction_Name::TEST, Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)),  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)),  None, None),
//     (0x85, _, _, _, _, Instruction_Name::TEST, Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)),  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)),  None, None),
//     (0x86, _, _, _, _, Instruction_Name::XCHG, Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)),  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)),  None, None),
//     (0x87, _, _, _, _, Instruction_Name::XCHG, Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)),  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)),  None, None),
// 
//     (0x88, _, _, _, _, Instruction_Name::MOV,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)),  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)),  None, None),
//     (0x89, _, _, _, _, Instruction_Name::MOV,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)),  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)),  None, None),
//     (0x8a, _, _, _, _, Instruction_Name::MOV,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)),  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)),  None, None),
//     (0x8b, _, _, _, _, Instruction_Name::MOV,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)),  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)),  None, None),
//     (0x8c, _, _, _, _, Instruction_Name::MOV,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)),  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Sw)),  None, None),
//     (0x8d, _, _, _, _, Instruction_Name::LEA,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)),  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::M)) ,  None, None),
//     (0x8e, _, _, _, _, Instruction_Name::MOV,  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Sw)),  Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ew)),  None, None),
// 
// 
//     (0x90, InstMode::x64, _, _, _, Instruction_Name::XCHG, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rAX), 
//                                                                                                     Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r8)))),
//                                                             Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),
// 
//     (0x91, InstMode::x64, _, _, _, Instruction_Name::XCHG, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rCX), 
//                                                                                                      Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r9)))),
//                                                             Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),
// 
//     (0x92, InstMode::x64, _, _, _, Instruction_Name::XCHG, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rDX), 
//                                                                                                      Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r10)))),
//                                                             Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),
// 
//     (0x93, InstMode::x64, _, _, _, Instruction_Name::XCHG, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rBX), 
//                                                                                                      Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r11)))),
//                                                             Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),
// 
//     (0x94, InstMode::x64, _, _, _, Instruction_Name::XCHG, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rSP), 
//                                                                                                      Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r12)))),
//                                                             Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),
// 
//     (0x95, InstMode::x64, _, _, _, Instruction_Name::XCHG, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rBP), 
//                                                                                                      Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r13)))),
//                                                             Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),
// 
//     (0x96, InstMode::x64, _, _, _, Instruction_Name::XCHG, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rSI), 
//                                                                                                      Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r14)))),
//                                                             Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),
// 
//     (0x97, InstMode::x64, _, _, _, Instruction_Name::XCHG, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rDI), 
//                                                                                                      Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r15)))),
//                                                             Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),
// 
//     (0x90, InstMode::x32, _, _, false, Instruction_Name::XCHG, Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eAX)), Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),
//     (0x91, InstMode::x32, _, _, false, Instruction_Name::XCHG, Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eCX)), Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),
//     (0x92, InstMode::x32, _, _, false, Instruction_Name::XCHG, Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eDX)), Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),
//     (0x93, InstMode::x32, _, _, false, Instruction_Name::XCHG, Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eBX)), Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),
//     (0x94, InstMode::x32, _, _, false, Instruction_Name::XCHG, Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eSP)), Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),
//     (0x95, InstMode::x32, _, _, false, Instruction_Name::XCHG, Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eBP)), Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),
//     (0x96, InstMode::x32, _, _, false, Instruction_Name::XCHG, Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eSI)), Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),
//     (0x97, InstMode::x32, _, _, false, Instruction_Name::XCHG, Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eDI)), Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),
// 
//     (0x98, _,             true,  _,    _,    Instruction_Name::CBW,      None, None, None, None),
//     (0x98, _,             false, _,    _,    Instruction_Name::CWDE,     None, None, None, None),
//     (0x98, InstMode::x64, _,     _,    true, Instruction_Name::CDQE,     None, None, None, None),
// 
//     (0x99, _,             true,  _,    _,    Instruction_Name::CWD,      None, None, None, None),
//     (0x99, _,             false, _,    _,    Instruction_Name::CDQ,      None, None, None, None),
//     (0x99, InstMode::x64, _,     _,    true, Instruction_Name::CQO,      None, None, None, None),
// 
//     (0x9a, InstMode::x32, _,     _,    _,    Instruction_Name::far_Call, Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Ap)),  None, None, None),
//     (0x9b, _,             _,     _,    _,    Instruction_Name::WAIT,     None,                                                     None, None, None),
// 
//     (0x9c, _,             true, _,     _,    Instruction_Name::PUSHF,    None,  None,  None, None),
//     (0x9c, InstMode::x32, _,    _,     _,    Instruction_Name::PUSHFD,   None,  None,  None, None),
//     (0x9c, InstMode::x64, _,    _,     _,    Instruction_Name::PUSHFQ,   None,  None,  None, None),
// 
//     (0x9d, _,             true, _,     _,    Instruction_Name::POPF,     None,  None,  None, None),
//     (0x9d, InstMode::x32, _,    _,     _,    Instruction_Name::POPFD,    None,  None,  None, None),
//     (0x9d, InstMode::x64, _,    _,     _,    Instruction_Name::POPFQ,    None,  None,  None, None),
// 
//     (0x9e, _,             _,    _,     _,    Instruction_Name::SAHF,     None,  None,  None, None),
//     (0x9f, _,             _,    _,     _,    Instruction_Name::LAHF,     None,  None,  None, None),
// 
//     (0xa0, _,             _,    _,     _,    Instruction_Name::MOV,      Some(Opcode_Operand::REGISTER(AL)),                            Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Ob)),       None, None),
//     (0xa1, _,             _,    _,     _,    Instruction_Name::MOV,      Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Ov)),       None, None),
//     (0xa2, _,             _,    _,     _,    Instruction_Name::MOV,      Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Ob)),       Some(Opcode_Operand::REGISTER(AL)),                            None, None),
//     (0xa3, _,             _,    _,     _,    Instruction_Name::MOV,      Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Ov)),       Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),
//     (0xa4, _,             _,    _,     _,    Instruction_Name::MOVSB,    Some(Opcode_Operand::Yb),                                      Some(Opcode_Operand::Xb),                                      None, None),
//     (0xa5, _,             _,    false, true, Instruction_Name::MOVSQ,    Some(Opcode_Operand::Yv),                                      Some(Opcode_Operand::Xv),                                      None, None),
//     (0xa5, _,             _,    true,  _,    Instruction_Name::MOVSW,    Some(Opcode_Operand::Yv),                                      Some(Opcode_Operand::Xv),                                      None, None),
//     (0xa5, _,             _,    false, _,    Instruction_Name::MOVSD,    Some(Opcode_Operand::Yv),                                      Some(Opcode_Operand::Xv),                                      None, None),
// 
//     (0xa6, _,             _,    _,     _,    Instruction_Name::CMPSB,    Some(Opcode_Operand::Xb), Some(Opcode_Operand::Yb), None, None),
//     (0xa7, _,             _,    _,     _,    Instruction_Name::CMPSW,    Some(Opcode_Operand::Xv), Some(Opcode_Operand::Yv), None, None),
//     (0xa7, _,             _,    _,     _,    Instruction_Name::CMPSD,    Some(Opcode_Operand::Xv), Some(Opcode_Operand::Yv), None, None),
//     (0xa7, InstMode::x64, _,    _,     true, Instruction_Name::CMPSQ,    Some(Opcode_Operand::Xv), Some(Opcode_Operand::Yv), None, None),
// 
//     (0xa8, _,             _,    _,     _,    Instruction_Name::TEST,     Some(Opcode_Operand::REGISTER(AL)),                            Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None),
//     (0xa9, _,             _,    _,     _,    Instruction_Name::TEST,     Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iz)), None, None),
// 
//     (0xaa, _,             _,     _, _,       Instruction_Name::STOSB,    Some(Opcode_Operand::Yb),                                Some(Opcode_Operand::REGISTER(AL)),                            None, None),
//     (0xab, _,             true,  _, _,       Instruction_Name::STOSW,    Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)), Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),
//     (0xab, _,             false, _, _,       Instruction_Name::STOSD,    Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)), Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),
//     (0xab, InstMode::x64, _,     _, true,    Instruction_Name::STOSQ,    Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)), Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), None, None),
// 
//     (0xac, _,              _,     _, _,      Instruction_Name::LODSB,    Some(Opcode_Operand::REGISTER(AL)),                            Some(Opcode_Operand::Xb), None, None),
//     (0xad, _,              true,  _, _,      Instruction_Name::LODSW,    Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), Some(Opcode_Operand::Xv), None, None),
//     (0xad, _,              false, _, _,      Instruction_Name::LODSD,    Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)), Some(Opcode_Operand::Xv), None, None),
//     (0xad, InstMode::x64,  _,     _, true,   Instruction_Name::LODSQ,    Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),       None,                     None, None),
// 
//     (0xae, _,            _,       _, _,      Instruction_Name::SCASB,    Some(Opcode_Operand::REGISTER(AL)),                             Some(Opcode_Operand::Yb), None, None),
//     (0xaf, _,            true,    _, _,      Instruction_Name::SCASW,    Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)),  Some(Opcode_Operand::Yv), None, None),
//     (0xaf, _,            false,   _, _,      Instruction_Name::SCASD,    Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)),  Some(Opcode_Operand::Yv), None, None),
//     (0xaf, InstMode::x64, _,      _, true,   Instruction_Name::SCASQ,    Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::rAX)),  Some(Opcode_Operand::Yv), None, None),
// 
// 
//     (0xb0, InstMode::x64, _, _, _, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::KNOWN(AL), 
//                                                                                                         Register_Known_Or_Unsized::KNOWN(R8L)))),
//                                                                 Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None),
// 
//     (0xb1, InstMode::x64, _, _, _, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::KNOWN(CL), 
//                                                                                                         Register_Known_Or_Unsized::KNOWN(R9L)))),
//                                                                 Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None),
// 
//     (0xb2, InstMode::x64, _, _, _, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::KNOWN(DL), 
//                                                                                                         Register_Known_Or_Unsized::KNOWN(R10L)))),
//                                                                 Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None),
// 
//     (0xb3, InstMode::x64, _, _, _, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::KNOWN(BL), 
//                                                                                                         Register_Known_Or_Unsized::KNOWN(R11L)))),
//                                                                 Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None),
// 
//     (0xb4, InstMode::x64, _, _, _, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::KNOWN(AH), 
//                                                                                                         Register_Known_Or_Unsized::KNOWN(R12L)))),
//                                                                 Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None),
// 
//     (0xb5, InstMode::x64, _, _, _, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::KNOWN(CH), 
//                                                                                                         Register_Known_Or_Unsized::KNOWN(R13L)))),
//                                                                 Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None),
// 
//     (0xb6, InstMode::x64, _, _, _, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::KNOWN(DH), 
//                                                                                                         Register_Known_Or_Unsized::KNOWN(R14L)))),
//                                                                 Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None),
// 
//     (0xb7, InstMode::x64, _, _, _, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::KNOWN(BH), 
//                                                                                                         Register_Known_Or_Unsized::KNOWN(R15L)))),
//                                                                 Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None),
// 
//     (0xb0, InstMode::x32, _, _, false, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER(AL)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None),
//     (0xb1, InstMode::x32, _, _, false, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER(CL)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None),
//     (0xb2, InstMode::x32, _, _, false, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER(DL)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None),
//     (0xb3, InstMode::x32, _, _, false, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER(BL)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None),
//     (0xb4, InstMode::x32, _, _, false, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER(AH)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None),
//     (0xb5, InstMode::x32, _, _, false, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER(CH)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None),
//     (0xb6, InstMode::x32, _, _, false, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER(DH)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None),
//     (0xb7, InstMode::x32, _, _, false, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER(BH)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None, None),
// 
//     (0xb8, InstMode::x64, _, _, _, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rAX), 
//                                                                                                     Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r8)))),
//                                                            Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv)), None, None),
// 
//     (0xb9, InstMode::x64, _, _, _, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rCX), 
//                                                                                                      Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r9)))),
//                                                            Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv)), None, None),
// 
//     (0xba, InstMode::x64, _, _, _, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rDX), 
//                                                                                                      Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r10)))),
//                                                            Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv)), None, None),
// 
//     (0xbb, InstMode::x64, _, _, _, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rBX), 
//                                                                                                      Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r11)))),
//                                                            Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv)), None, None),
// 
//     (0xbc, InstMode::x64, _, _, _, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rSP), 
//                                                                                                      Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r12)))),
//                                                            Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv)), None, None),
// 
//     (0xbd, InstMode::x64, _, _, _, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rBP), 
//                                                                                                      Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r13)))),
//                                                            Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv)), None, None),
// 
//     (0xbe, InstMode::x64, _, _, _, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rSI), 
//                                                                                                      Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r14)))),
//                                                            Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv)), None, None),
// 
//     (0xbf, InstMode::x64, _, _, _, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_REX_PAIR((Register_Known_Or_Unsized::UNSIZED(Register_Unsized::rDI), 
//                                                                                                      Register_Known_Or_Unsized::UNSIZED(Register_Unsized::r15)))),
//                                                            Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv)), None, None),
// 
//     (0xb8, InstMode::x32, _, _, false, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eAX)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv)), None, None),
//     (0xb9, InstMode::x32, _, _, false, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eCX)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv)), None, None),
//     (0xba, InstMode::x32, _, _, false, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eDX)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv)), None, None),
//     (0xbb, InstMode::x32, _, _, false, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eBX)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv)), None, None),
//     (0xbc, InstMode::x32, _, _, false, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eSP)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv)), None, None),
//     (0xbd, InstMode::x32, _, _, false, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eBP)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv)), None, None),
//     (0xbe, InstMode::x32, _, _, false, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eSI)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv)), None, None),
//     (0xbf, InstMode::x32, _, _, false, Instruction_Name::MOV, Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eDI)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iv)), None, None),
// 
//     // TODO: VEX prefix for LES and LDS
//     (0xc2, _,             _,     _, _,    Instruction_Name::near_Ret, Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iw)),    None,                                                       None, None),
//     (0xc3, _,             _,     _, _,    Instruction_Name::near_Ret, None,                                                       None,                                                       None, None),
//     (0xc4, InstMode::x32, _,     _, _,    Instruction_Name::LES,      Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gz)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Mp)), None, None),
//     (0xc5, InstMode::x32, _,     _, _,    Instruction_Name::LDS,      Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gz)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Mp)), None, None),
// 
//     (0xc8, _,             _,     _, _,    Instruction_Name::ENTER,    Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iw)),    Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)),    None, None),
//     (0xc9, _,             _,     _, _,    Instruction_Name::LEAVE,    None,                                                       None,                                                       None, None),
//     (0xca, _,             _,     _, _,    Instruction_Name::far_Ret,  Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Iw)),    None,                                                       None, None),
//     (0xcb, _,             _,     _, _,    Instruction_Name::far_Ret,  None,                                                       None,                                                       None, None),
//     (0xcc, _,             _,     _, _,    Instruction_Name::INT3,     None,                                                       None,                                                       None, None),
//     (0xcd, _,             _,     _, _,    Instruction_Name::INT,      Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)),    None,                                                       None, None),
//     (0xce, InstMode::x32, _,     _, _,    Instruction_Name::INTO,     None,                                                       None,                                                       None, None),
//     (0xcf, _,             true,  _, _,    Instruction_Name::IRET,     None,                                                       None,                                                       None, None),
//     (0xcf, _,             false, _, _,    Instruction_Name::IRETD,    None,                                                       None,                                                       None, None),
//     (0xcf, InstMode::x64, _,     _, true, Instruction_Name::IRETQ,    None,                                                       None,                                                       None, None),
// 
//     (0xd4, InstMode::x32, _,     _, _,    Instruction_Name::AAM,      Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)),     None,                               None, None),
//     (0xd5, InstMode::x32, _,     _, _,    Instruction_Name::AAD,      Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)),     None,                               None, None),
//     (0xd7, _,             _,     _, _,    Instruction_Name::XLATB,    None,                                                        None,                               None, None),
//     // XLAT has parameters?
// 
//     (0xe0, _,             _, _, _, Instruction_Name::LOOPNZ,    Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),       None,                                                          None, None),
//     (0xe1, _,             _, _, _, Instruction_Name::LOOPZ,     Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),       None,                                                          None, None),
//     (0xe2, _,             _, _, _, Instruction_Name::LOOP,      Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),       None,                                                          None, None),
//     (0xe3, _,             _, _, _, Instruction_Name::JrCXZ,     Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),       None,                                                          None, None),
//     (0xe4, _,             _, _, _, Instruction_Name::IN,        Some(Opcode_Operand::REGISTER(AL)),                            Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)),       None, None),
//     (0xe5, _,             _, _, _, Instruction_Name::IN,        Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eAX)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)),       None, None),
//     (0xe6, _,             _, _, _, Instruction_Name::OUT,       Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)),       Some(Opcode_Operand::REGISTER(AL)),                            None, None),
//     (0xe7, _,             _, _, _, Instruction_Name::OUT,       Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)),       Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eAX)), None, None),
// 
//     (0xe8, _,             _, _, _, Instruction_Name::near_Call, Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jz)),       None,                                                          None, None),
//     (0xe9, _,             _, _, _, Instruction_Name::near_Jmp,  Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jz)),       None,                                                          None, None),
//     (0xea, InstMode::x32, _, _, _, Instruction_Name::far_Jmp,   Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Ap)),       None,                                                          None, None),
//     (0xeb, _,             _, _, _, Instruction_Name::short_Jmp, Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),       None,                                                          None, None),
//     (0xec, _,             _, _, _, Instruction_Name::IN,        Some(Opcode_Operand::REGISTER(AL)),                            Some(Opcode_Operand::REGISTER(DX)),                            None, None),
//     (0xed, _,             _, _, _, Instruction_Name::IN,        Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eAX)), Some(Opcode_Operand::REGISTER(DX)),                            None, None),
//     (0xee, _,             _, _, _, Instruction_Name::OUT,       Some(Opcode_Operand::REGISTER(DX)),                            Some(Opcode_Operand::REGISTER(AL)),                            None, None),
//     (0xef, _,             _, _, _, Instruction_Name::OUT,       Some(Opcode_Operand::REGISTER(DX)),                            Some(Opcode_Operand::REGISTER_UNSIZED(Register_Unsized::eAX)), None, None),
// 
// 
//     (0xf1, _,             _, _, _, Instruction_Name::INT1,      Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),       None,                                                          None, None),
//     (0xf4, _,             _, _, _, Instruction_Name::HLT,       Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),       None,                                                          None, None),
//     (0xf5, _,             _, _, _, Instruction_Name::CMC,       Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jb)),       None,                                                          None, None),
// 
//     (0xf8, _,             _, _, _, Instruction_Name::CLC,       None,                                                          None,                                                          None, None),
//     (0xf9, _,             _, _, _, Instruction_Name::STC,       None,                                                          None,                                                          None, None),
//     (0xfa, _,             _, _, _, Instruction_Name::CLI,       None,                                                          None,                                                          None, None),
//     (0xfb, _,             _, _, _, Instruction_Name::STI,       None,                                                          None,                                                          None, None),
//     (0xfc, _,             _, _, _, Instruction_Name::CLD,       None,                                                          None,                                                          None, None),
//     (0xfd, _,             _, _, _, Instruction_Name::STD,       None,                                                          None,                                                          None, None),
// );

pub fn search_opcode_two_byte(opcode: u8, mode: InstMode, prefix: &Inst_Prefix, modrm: &ModRMByte, rex_w: bool) -> Option<Opcode_Table_Result>
{
    let x = (opcode, mode, prefix);
    match x
    {
        (0x02, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::LAR, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ew)), None, None]}),
        (0x03, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::LSL, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ew)), None, None]}),
        (0x05, InstMode::x64, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::SYSCALL, operands: [None, None, None, None]}),
        (0x06, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::CLTS, operands: [None, None, None, None]}),
        (0x07, InstMode::x64, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::SYSRET, operands: [None, None, None, None]}),

        (0x08, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::INVD, operands: [None, None, None, None]}),
        (0x09, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::WBINVD, operands: [None, None, None, None]}),
        (0x0D, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::PRE_FETCH_W, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None, None]}),

        (0x10, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_UPD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wpd)), 
                                                                                            None, None]}),
        (0x10, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPZ_F3), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_SS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::Hx), 
                                                                                           Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wss)), None]}),
        (0x10, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPNZ_BND_F2), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_SD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::Hx), 
                                                                                           Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wsd)), None]}),
        (0x10, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_UPS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wps)), 
                                                                                            None, None]}),

        (0x11, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_UPD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vpd)), 
                                                                                            None, None]}),
        (0x11, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPZ_F3), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_SS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wss)), Some(Opcode_Operand::Hx), 
                                                                                           Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vss)), None]}),
        (0x11, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPNZ_BND_F2), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_SD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wsd)), Some(Opcode_Operand::Hx), 
                                                                                           Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vsd)), None]}),
        (0x11, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_UPS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vps)), 
                                                                                            None, None]}),

        // TODO: 0x12. What is vmovhlps
        (0x12, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_LPD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hq)), 
                                                                                            Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Mq)), None]}),
        (0x12, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPZ_F3), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_SLDUP, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), 
                                                                                              None, None]}),
        (0x12, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPNZ_BND_F2), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_DDUP, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), 
                                                                                             None, None]}),
        (0x12, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_LPS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hq)), 
                                                                                            Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Mq)), None]}),


        (0x13, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_LPD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Mq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vq)), 
                                                                                            None, None]}),
        (0x13, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_LPS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Mq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vq)), 
                                                                                            None, None]}),


        (0x14, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_UNPACK_LPD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), 
                                                                                               Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0x14, _, _,) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_UNPACK_LPS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::Hx), 
                                                                                               Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),


        (0x15, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_UNPACK_HPD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), 
                                                                                               Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0x15, _, _,) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_UNPACK_HPS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::Hx), 
                                                                                               Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),

        // TODO: 0x16, What is vmovhlps?
        (0x16, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_HPD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vdq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hq)), 
                                                                                            Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Mq)), None]}),
        (0x16, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPZ_F3), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_SHDUP, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), 
                                                                                              None, None]}),
        (0x16, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_HPS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vdq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hq)), 
                                                                                            Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Mq)), None]}),


        (0x17, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_HPD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Mq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vq)), 
                                                                                            None, None]}),
        (0x17, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_HPS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Mq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vq)), 
                                                                                            None, None]}),


        (0x19, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::NOP, operands: [None, None, None, None] }),


        (0x1A, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::BNDMOV, operands: [None, None, None, None]}),
        (0x1A, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPZ_F3), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::BNDCL, operands: [None, None, None, None]}),
        (0x1A, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPNZ_BND_F2), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::BNDCU, operands: [None, None, None, None]}),
        (0x1A, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::BNDLDX, operands: [None, None, None, None]}),

        (0x1B, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::BNDMOV, operands: [None, None, None, None]}),
        (0x1B, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPZ_F3), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::BNDMK, operands: [None, None, None, None]}),
        (0x1B, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPNZ_BND_F2), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::BNDCN, operands: [None, None, None, None]}),
        (0x1B, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::BNDSTX, operands: [None, None, None, None]}),
        

        (0x1C, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::NOP, operands: [None, None, None, None] }),
        (0x1D, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::NOP, operands: [None, None, None, None] }),
        (0x1E, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::NOP, operands: [None, None, None, None] }),
        (0x1F, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::NOP, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None, None] }),

        (0x20, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::MOV, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Rd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Cd)), None, None]}),
        (0x21, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::MOV, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Rd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Dd)), None, None]}),
        (0x22, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::MOV, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Cd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Rd)), None, None]}),
        (0x23, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::MOV, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Dd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Rd)), None, None]}),


        (0x28, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_APD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wpd)), None, None]}),
        (0x28, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_APS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wps)), None, None]}),


        (0x29, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_APD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vpd)), None, None]}),
        (0x29, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_APS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vps)), None, None]}),


        (0x2A, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::CVTPI2_PD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qpi)), None, None]}),
        (0x2A, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPZ_F3), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_CTSI2_SS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vss)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hss)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ey)), None]}),
        (0x2A, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPNZ_BND_F2), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_CTSI2_SD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vsd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hsd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ey)), None]}),
        (0x2A, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::CVTPI2_PS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qpi)), None, None]}),

        (0x2B, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_NT_PD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Mpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vpd)), None, None]}),
        (0x2B, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_NT_PS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Mps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vps)), None, None]}),


        (0x2C, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::CVTT_PD_2PI, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ppi)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wpd)), None, None]}),
        (0x2C, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPZ_F3), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_CVTT_SS_2SI, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gy)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wss)), None, None]}),
        (0x2C, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPNZ_BND_F2), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_CVTT_SS_2SI, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gy)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wsd)), None, None]}),
        (0x2C, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::CVTT_PS_2PI, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ppi)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wps)), None, None]}),

        (0x2D, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::CVT_PD_2PI, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qpi)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wpd)), None, None]}),
        (0x2D, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPZ_F3), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_CVT_SS_2SI, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gy)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wss)), None, None]}),
        (0x2D, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPNZ_BND_F2), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_CVT_SS_2SI, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gy)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wsd)), None, None]}),
        (0x2D, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::CVT_PS_2PI, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ppi)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wps)), None, None]}),

        (0x2E, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VUCOMI_SD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vsd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wsd)), None, None]}),
        (0x2E, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VUCOMI_SS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vss)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wss)), None, None]}),

        (0x2F, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VCOMI_SD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vsd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wsd)), None, None]}),
        (0x2F, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VCOMI_SS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vss)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wss)), None, None]}),

        (0x30, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::WRMSR,    operands: [None, None, None, None] }),
        (0x31, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::RDTSC,    operands: [None, None, None, None] }),
        (0x32, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::RDMSR,    operands: [None, None, None, None] }),
        (0x33, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::RDPMC,    operands: [None, None, None, None] }),
        (0x34, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::SYSENTER, operands: [None, None, None, None] }),
        (0x35, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::SYSEXIT,  operands: [None, None, None, None] }),
        (0x37, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::GETSEC,   operands: [None, None, None, None] }),

        (0x40, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::CMOV_O,        operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None] }),
        (0x41, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::CMOV_NO,       operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None] }),
        (0x42, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::CMOV_B_C_NAE,  operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None] }),
        (0x43, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::CMOV_AE_NB_NC, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None] }),
        (0x44, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::CMOV_E_Z,      operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None] }),
        (0x45, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::CMOV_NE_NZ,    operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None] }),
        (0x46, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::CMOV_BE_NA,    operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None] }),
        (0x47, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::CMOV_A_NBE,    operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None] }),
        (0x48, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::CMOV_S,        operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None] }),
        (0x49, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::CMOV_NS,       operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None] }),
        (0x4A, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::CMOV_P_PE,     operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None] }),
        (0x4B, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::CMOV_NP_PO,    operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None] }),
        (0x4C, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::CMOV_L_NGE,    operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None] }),
        (0x4D, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::CMOV_NL_HE,    operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None] }),
        (0x4E, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::CMOV_LE_NG,    operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None] }),
        (0x4F, _, _) => Some(Opcode_Table_Result { instruction: Instruction_Name::CMOV_NLE_G,    operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None] }),

        (0x50, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_MSK_PD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gy)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Upd)), None, None]}),
        (0x50, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_MSK_PS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gy)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ups)), None, None]}),

        (0x51, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_SQRT_PD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wpd)), None, None]}),
        (0x51, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPZ_F3), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_SQRT_SS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vss)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hss)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wss)), None]}),
        (0x51, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPNZ_BND_F2), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_SQRT_SD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hsd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wsd)), None]}),
        (0x51, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_SQRT_PS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wps)), None, None]}),

        (0x52, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPZ_F3), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_RSQRT_SS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vss)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hss)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wss)), None]}),
        (0x52, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_RSQRT_PS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wps)), None, None]}),

        (0x53, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPZ_F3), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_RCP_SS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vss)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hss)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wss)), None]}),
        (0x53, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_RCP_PS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wps)), None, None]}),

        (0x54, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_AND_PD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wpd)), None]}),
        (0x54, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_AND_PS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wps)), None]}),

        (0x55, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_ANDN_PD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wpd)), None]}),
        (0x55, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_ANDN_PS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wps)), None]}),

        (0x56, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_OR_PD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wpd)), None]}),
        (0x56, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_OR_PS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wps)), None]}),

        (0x57, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_XOR_PD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wpd)), None]}),
        (0x57, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_XOR_PS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wps)), None]}),

        (0x58, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_ADD_PD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wpd)), None]}),
        (0x58, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPZ_F3), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_ADD_SS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vss)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hss)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wss)), None]}),
        (0x58, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPNZ_BND_F2), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_ADD_SD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vsd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hsd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wsd)), None]}),
        (0x58, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_ADD_PS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wps)), None]}),

        (0x59, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MUL_PD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wpd)), None]}),
        (0x59, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPZ_F3), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MUL_SS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vss)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hss)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wss)), None]}),
        (0x59, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPNZ_BND_F2), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MUL_SD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vsd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hsd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wsd)), None]}),
        (0x59, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MUL_PS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wps)), None]}),

        (0x5A, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_CVT_PD2_PS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wpd)), None, None]}),
        (0x5A, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPZ_F3), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_CVT_SS2_SD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vsd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wss)), None]}),
        (0x5A, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPNZ_BND_F2), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_CVT_SD2_SS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vss)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wsd)), None]}),
        (0x5A, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_CVT_PS2_PD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wps)), None, None]}),

        (0x5B, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_CVT_PS2_DQ, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vdq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wps)), None, None]}),
        (0x5B, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPZ_F3), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_CVT_TPS2_DQ, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vdq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wps)), None, None]}),
        (0x5B, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_CVT_DQ2_PS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wdq)), None, None]}),

        (0x5C, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_SUB_PD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wpd)), None]}),
        (0x5C, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPZ_F3), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_SUB_SS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vss)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hss)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wss)), None]}),
        (0x5C, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPNZ_BND_F2), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_SUB_SD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vsd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hsd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wsd)), None]}),
        (0x5C, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_SUB_PS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wps)), None]}),

        (0x5D, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MIN_PD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wpd)), None]}),
        (0x5D, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPZ_F3), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MIN_SS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vss)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hss)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wss)), None]}),
        (0x5D, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPNZ_BND_F2), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MIN_SD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vsd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hsd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wsd)), None]}),
        (0x5D, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MIN_PS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wps)), None]}),

        (0x5E, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_DIV_PD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wpd)), None]}),
        (0x5E, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPZ_F3), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_DIV_SS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vss)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hss)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wss)), None]}),
        (0x5E, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPNZ_BND_F2), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_DIV_SD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vsd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hsd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wsd)), None]}),
        (0x5E, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_DIV_PS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wps)), None]}),

        (0x5F, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MAX_PD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wpd)), None]}),
        (0x5F, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPZ_F3), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MAX_SS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vss)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hss)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wss)), None]}),
        (0x5F, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPNZ_BND_F2), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MAX_SD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vsd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hsd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wsd)), None]}),
        (0x5F, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MAX_PS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wps)), None]}),

        (0x60, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPUNPCK_LBW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0x60, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PUNPCK_LBW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qd)), None, None]}),

        (0x61, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPUNPCK_LWD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0x61, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PUNPCK_LWD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qd)), None, None]}),

        (0x62, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPUNPCK_LDQ, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0x62, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PUNPCK_LDQ, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qd)), None, None]}),

        (0x63, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPUNPCK_SWB, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0x63, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PUNPCK_SWB, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qd)), None, None]}),

        (0x64, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPCMP_GTB, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0x64, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PCMP_GTB, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qd)), None, None]}),

        (0x65, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPCMP_GTW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0x65, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PCMP_GTW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qd)), None, None]}),

        (0x66, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPCMP_GTD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0x66, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PCMP_GTD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qd)), None, None]}),

        (0x67, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPACKUSWB, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0x67, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PACKUSWB, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qd)), None, None]}),

        (0x68, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPUNPCKHBW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0x68, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PUNPCKHBW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qd)), None, None]}),

        (0x69, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPUNPCKHWD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0x69, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PUNPCKHWD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qd)), None, None]}),

        (0x6A, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPUNPCKHDQ, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0x6A, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PUNPCKHDQ, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qd)), None, None]}),

        (0x6B, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPACKSSDW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0x6B, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PACKSSDW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qd)), None, None]}),

        (0x6C, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPUNPCKLQDQ, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),

        (0x6D, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPUNPCKHQDQ, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),

        (0x6E, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_DQ, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vy)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ey)), None, None]}),
        (0x6E, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::MOV_DQ, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ey)), None, None]}),

        (0x6F, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_DQA, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None, None]}),
        (0x6F, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPZ_F3), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_MOV_DQU, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None, None]}),
        (0x6F, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::MOV_Q, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0x70, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PSHUFD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None]}),
        (0x70, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPZ_F3), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPSHUFHW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None]}),
        (0x70, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPNZ_BND_F2), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPSSHUFLW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None]}),
        (0x70, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PSHUFW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None]}),

        (0x74, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPCMPEQB, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0x74, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PCMPEQB, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0x75, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPCMPEQW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0x75, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PCMPEQW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0x76, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPCMPEQD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0x76, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PCMPEQD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        // TODO: wtf is 0x77?

        (0x78, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VMREAD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ey)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gy)), None, None]}),
        (0x79, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VMWRITE, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ey)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gy)), None, None]}),

        (0x7C, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VHADDPD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wpd)), None]}),
        (0x7C, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPNZ_BND_F2), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VHADDPD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wps)), None]}),

        (0x7D, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VHSUBPD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wpd)), None]}),
        (0x7D, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPNZ_BND_F2), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VHSUBPS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wps)), None]}),

        (0x7E, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VMOVDQ, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ey)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vy)), None, None]}),
        (0x7E, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPZ_F3), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VMOVQ, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wq)), None, None]}),
        (0x7E, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::MOVDQ, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ey)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pd)), None, None]}),

        (0x7F, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VMOVDQA, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), None, None]}),
        (0x7F, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPZ_F3), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VMOVDQU, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), None, None]}),
        (0x7F, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::MOVQ, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), None, None]}),

        (0x80, InstMode::x64, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::J_CC_O, operands: [Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jq)), None, None, None]}),
        (0x81, InstMode::x64, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::J_CC_NO, operands: [Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jq)), None, None, None]}),
        (0x82, InstMode::x64, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::J_CC_B_CNAE, operands: [Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jq)), None, None, None]}),
        (0x83, InstMode::x64, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::J_CC_AE_NB_NC, operands: [Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jq)), None, None, None]}),
        (0x84, InstMode::x64, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::J_CC_E_Z, operands: [Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jq)), None, None, None]}),
        (0x85, InstMode::x64, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::J_CC_NE_NZ, operands: [Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jq)), None, None, None]}),
        (0x86, InstMode::x64, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::J_CC_BE_NA, operands: [Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jq)), None, None, None]}),
        (0x87, InstMode::x64, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::J_CC_A_NBE, operands: [Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jq)), None, None, None]}),
        (0x88, InstMode::x64, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::J_CC_S, operands: [Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jq)), None, None, None]}),
        (0x89, InstMode::x64, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::J_CC_NS, operands: [Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jq)), None, None, None]}),
        (0x8A, InstMode::x64, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::J_CC_P_PE, operands: [Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jq)), None, None, None]}),
        (0x8B, InstMode::x64, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::J_CC_NP_PO, operands: [Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jq)), None, None, None]}),
        (0x8C, InstMode::x64, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::J_CC_L_NGE, operands: [Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jq)), None, None, None]}),
        (0x8D, InstMode::x64, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::J_CC_NL_GE, operands: [Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jq)), None, None, None]}),
        (0x8E, InstMode::x64, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::J_CC_LE_NA, operands: [Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jq)), None, None, None]}),
        (0x8F, InstMode::x64, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::J_CC_NLE_G, operands: [Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jq)), None, None, None]}),

        (0x80, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::J_CC_O, operands: [Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jz)), None, None, None]}),
        (0x81, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::J_CC_NO, operands: [Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jz)), None, None, None]}),
        (0x82, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::J_CC_B_CNAE, operands: [Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jz)), None, None, None]}),
        (0x83, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::J_CC_AE_NB_NC, operands: [Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jz)), None, None, None]}),
        (0x84, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::J_CC_E_Z, operands: [Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jz)), None, None, None]}),
        (0x85, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::J_CC_NE_NZ, operands: [Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jz)), None, None, None]}),
        (0x86, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::J_CC_BE_NA, operands: [Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jz)), None, None, None]}),
        (0x87, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::J_CC_A_NBE, operands: [Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jz)), None, None, None]}),
        (0x88, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::J_CC_S, operands: [Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jz)), None, None, None]}),
        (0x89, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::J_CC_NS, operands: [Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jz)), None, None, None]}),
        (0x8A, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::J_CC_P_PE, operands: [Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jz)), None, None, None]}),
        (0x8B, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::J_CC_NP_PO, operands: [Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jz)), None, None, None]}),
        (0x8C, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::J_CC_L_NGE, operands: [Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jz)), None, None, None]}),
        (0x8D, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::J_CC_NL_GE, operands: [Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jz)), None, None, None]}),
        (0x8E, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::J_CC_LE_NA, operands: [Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jz)), None, None, None]}),
        (0x8F, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::J_CC_NLE_G, operands: [Some(Opcode_Operand::DIS_BYTES(Opcode_Operand_Dis::Jz)), None, None, None]}),

        (0x90, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::SET_CC_O, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), None, None, None]}),
        (0x91, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::SET_CC_NO, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), None, None, None]}),
        (0x92, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::SET_CC_B_CNAE, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), None, None, None]}),
        (0x93, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::SET_CC_AE_NB_NC, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), None, None, None]}),
        (0x94, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::SET_CC_E_Z, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), None, None, None]}),
        (0x95, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::SET_CC_NE_NZ, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), None, None, None]}),
        (0x96, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::SET_CC_BE_NA, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), None, None, None]}),
        (0x97, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::SET_CC_A_NBE, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), None, None, None]}),
        (0x98, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::SET_CC_S, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), None, None, None]}),
        (0x99, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::SET_CC_NS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), None, None, None]}),
        (0x9A, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::SET_CC_P_PE, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), None, None, None]}),
        (0x9B, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::SET_CC_NP_PO, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), None, None, None]}),
        (0x9C, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::SET_CC_L_NGE, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), None, None, None]}),
        (0x9D, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::SET_CC_NL_GE, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), None, None, None]}),
        (0x9E, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::SET_CC_LE_NA, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), None, None, None]}),
        (0x9F, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::SET_CC_NLE_G, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), None, None, None]}),

        (0xA0, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PUSH, operands: [Some(Opcode_Operand::REGISTER(FS)), None, None, None]}),
        (0xA1, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::POP, operands: [Some(Opcode_Operand::REGISTER(FS)), None, None, None]}),
        (0xA2, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::CPUID, operands: [None, None, None, None]}),
        (0xA3, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::BT, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), None, None]}),
        (0xA4, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::SHLD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None]}),
        (0xA5, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::SHLD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::REGISTER(CL)), None]}),

        (0xA8, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PUSH, operands: [Some(Opcode_Operand::REGISTER(GS)), None, None, None]}),
        (0xA9, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::POP, operands: [Some(Opcode_Operand::REGISTER(GS)), None, None, None]}),
        (0xAA, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::RSM, operands: [None, None, None, None]}),
        (0xAB, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::BTS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), None, None]}),
        (0xAC, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::SHRD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None]}),
        (0xAD, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::SHRD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::REGISTER(CL)), None]}),
        (0xAF, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::IMUL, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None]}),

        (0xB0, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::CMPXCHG, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)), None, None]}),
        (0xB1, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::CMPXCHG, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), None, None]}),
        (0xB2, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::LSS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Mp)), None, None]}),
        (0xB3, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::BTR, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), None, None]}),
        (0xB4, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::LFS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Mp)), None, None]}),
        (0xB5, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::LGS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Mp)), None, None]}),
        (0xB6, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::MOVZX, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), None, None]}),
        (0xB7, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::MOVZX, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ew)), None, None]}),

        (0xB8, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPZ_F3), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::POPCNT, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None]}),
        // (0xB8, _, _) => 
        //     Some(Opcode_Table_Result { instruction: Instruction_Name::JMPE, operands: [None, None, None, None]}),

        (0xBB, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::BTC, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), None, None]}),

        (0xBC, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPZ_F3), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::TZCNT, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None]}),
        (0xBC, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::BSF, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None]}),

        (0xBD, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPZ_F3), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::LZCNT, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None]}),
        (0xBD, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::BSR, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), None, None]}),

        (0xBE, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::MOVSX, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), None, None]}),
        (0xBF, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::MOVSX, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ew)), None, None]}),

        (0xC0, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::XADD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Eb)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gb)), None, None]}),

        (0xC1, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::XADD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ev)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gv)), None, None]}),

        (0xC2, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_CMP_PD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wpd)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))]}),
        (0xC2, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPZ_F3), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_CMP_SS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vss)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hss)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wss)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))]}),
        (0xC2, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPNZ_BND_F2), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_CMP_SD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vsd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hsd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wsd)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))]}),
        (0xC2, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::V_CMP_PS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wps)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))]}),

        (0xC3, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::MOV_NTL, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::My)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gy)), None, None]}),

        //TODO: idk what the operands of this are supposed to be...?
        // (0xC4, _, _) => 
        //     Some(Opcode_Table_Result { instruction: Instruction_Name::PINSRW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wps)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))]}),
        // (0xC4, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
        //     Some(Opcode_Table_Result { instruction: Instruction_Name::VPINSRW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wpd)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))]}),

        (0xC5, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPEXTRW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Udq)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None]}),
        (0xC5, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PEXTRW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Nq)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib)), None]}),

        (0xC6, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VSHUFPD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wpd)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))]}),
        (0xC6, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VSHUFPS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wps)), Some(Opcode_Operand::IMM_BYTES(Opcode_Operand_Imm::Ib))]}),

        (0xC8..=0xCF, InstMode::x32, _) =>
            Some(Opcode_Table_Result { instruction: Instruction_Name::BSWAP, operands: [Some(Opcode_Operand::REGISTER(
                match rex_w {
                    false => search_register(modrm.reg_op, Register_Type::GP, Register_Size::_32, None).unwrap(),
                    true => search_register(modrm.reg_op, Register_Type::GP, Register_Size::_64, Some(rex_w)).unwrap(),
                })),
            None, None, None] }),
        
        (0xD0, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VADDSUBPD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hpd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wpd)), None]}),
        (0xD0, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPNZ_BND_F2), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VADDSUBPS, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hps)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wps)), None]}),

        (0xD1, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPSRLW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xD1, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PSRLW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0xD2, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPSRLD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xD2, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PSRLD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0xD3, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPSRLQ, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xD3, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PSRLQ, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0xD4, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPADDQ, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xD4, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PADDQ, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0xD5, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPMULLW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xD5, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PMULLW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0xD6, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VMOVQ, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vq)), None, None]}),
        (0xD6, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPZ_F3), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::MOVQ2DQ, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vdq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Nq)), None, None]}),
        (0xD6, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPNZ_BND_F2), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::MOVDQ2Q, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Uq)), None, None]}),

        (0xD7, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPMOVMSKB, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Ux)), None, None]}),
        (0xD7, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PMOVMSKB, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Gd)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Nq)), None, None]}),

        (0xD8, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPSUBUSB, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xD8, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PSUBUSB, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0xD9, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPSUBUSW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xD9, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PSUBUSW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0xDA, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPMINUB, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xDA, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PMINUB, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0xDB, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPAND, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xDB, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PAND, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0xDC, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPADDUSB, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xDC, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PADDUSB, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0xDD, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPADDUSW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xDD, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PADDUSW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0xDE, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPMAXUB, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xDE, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PMAXUB, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0xDF, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPANDN, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xDF, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PANDN, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),


        (0xE0, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPAVGB, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xE0, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PAVGB, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0xE1, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPSRLW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xE1, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PSRLW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0xE2, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPSRAW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xE2, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PSRAW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0xE3, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPSRAD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xE3, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PSRAD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0xE4, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPMULHUW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xE4, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PMULHUW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0xE5, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPMULHW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xE5, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PMULHW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0xE6, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VCTTPD2DQ, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wpd)), None, None]}),
        (0xE6, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPZ_F3), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VCVTDQ2PD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wpd)), None, None]}),
        (0xE6, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPNZ_BND_F2), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VCVTPD2DQ, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wpd)), None, None]}),

        (0xE7, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VMOVNTDQ, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Mx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), None, None]}),
        (0xE7, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::MOVNTDQ, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Mq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), None, None]}),

        (0xE8, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPSUBUSB, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xE8, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PSUBSB, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0xE9, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPSUBUSW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xE9, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PSUBUSW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0xEA, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPMINSW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xEA, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PMINSW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0xEB, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPOR, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xEB, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::POR, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0xEC, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPADDSB, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xEC, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PADDSB, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0xED, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPADDSW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xED, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PADDSW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0xEE, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPMAXSW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xEE, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PMAXSW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0xEF, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPXOR, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xEF, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PXOR, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),



        (0xF0, _, Inst_Prefix { prefixes: Prefix_Acc { group1: Some(Prefix_Group1::REPNZ_BND_F2), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VLDDQU, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Mx)), None, None]}),

        (0xF1, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPSLLW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xF1, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PSLLW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0xF2, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPSLLD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xF2, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PSLLD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0xF3, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPSLLQ, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xF3, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PSLLQ, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0xF4, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPMULUDQ, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xF4, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PMULUDQ, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0xF5, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPMADDWD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xF5, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PMADDWD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0xF6, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPSADBW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xF6, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PSADBW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0xF7, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VMASKMOVDQU, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vdq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Udq)), None, None]}),
        (0xF7, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::MASKMOVQ, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Nq)), None, None]}),


        (0xF8, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPSUBB, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xF8, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PSUBB, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0xF9, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPSUBW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xF9, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PSUBW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0xFA, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPSUBD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xFA, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PSUBD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0xFB, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPSUBQ, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xFB, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PSUBQ, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0xFC, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPADDB, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xFC, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PADDB, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0xFD, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPADDW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xFD, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PADDW, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        (0xFE, _, Inst_Prefix { prefixes: Prefix_Acc { group3: Some(Prefix_Group3::Operand_Override_66), .. }, .. }) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::VPADDD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Vx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Hx)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Wx)), None]}),
        (0xFE, _, _) => 
            Some(Opcode_Table_Result { instruction: Instruction_Name::PADDD, operands: [Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Pq)), Some(Opcode_Operand::MODRM_BYTE(Opcode_Operand_ModRM::Qq)), None, None]}),

        _ => None
    }
}
