use std::{cell::RefCell, collections::{BTreeMap, HashMap, HashSet}, env::var, fmt, hash::{DefaultHasher, Hash, Hasher}, rc::Rc, sync::WaitTimeoutResult};
use std::ops::Bound::{ Included, Excluded };

use crate::{
    disassemble::{self, *}, one_byte_opcode::Instruction_Name, registers::*
};

#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum RegisterSlot
{
    AX,
    BX,
    CX,
    DX,

    SI,
    DI,

    SP,
    BP,

    Flag_Carry,
    Flag_Parity,
    Flag_Aux,
    Flag_Zero,
    Flag_Sign,
    Flag_Trap,
    Flag_Interrupt,
    Flag_Direction,
    Flag_Overflow,
}

fn reg_to_slot(
    reg: &Register
) -> RegisterSlot {
    match *reg {
        AL  => RegisterSlot::AX,
        AH  => RegisterSlot::AX,
        AX  => RegisterSlot::AX,
        EAX => RegisterSlot::AX,
        RAX => RegisterSlot::AX,

        BL  => RegisterSlot::BX,
        BH  => RegisterSlot::BX,
        BX  => RegisterSlot::BX,
        EBX => RegisterSlot::BX,
        RBX => RegisterSlot::BX,

        CL  => RegisterSlot::CX,
        CH  => RegisterSlot::BX,
        CX  => RegisterSlot::CX,
        ECX => RegisterSlot::CX,
        RCX => RegisterSlot::CX,

        DL  => RegisterSlot::DX,
        DH  => RegisterSlot::BX,
        DX  => RegisterSlot::DX,
        EDX => RegisterSlot::DX,
        RDX => RegisterSlot::DX,

        SIL => RegisterSlot::SI,
        SI  => RegisterSlot::SI,
        ESI => RegisterSlot::SI,
        RSI => RegisterSlot::SI,

        DIL => RegisterSlot::DI,
        DI  => RegisterSlot::DI,
        EDI => RegisterSlot::DI,
        RDI => RegisterSlot::DI,

        SPL => RegisterSlot::SP,
        SP  => RegisterSlot::SP,
        ESP => RegisterSlot::SP,
        RSP => RegisterSlot::SP,

        BPL => RegisterSlot::BP,
        BP  => RegisterSlot::BP,
        EBP => RegisterSlot::BP,
        RBP => RegisterSlot::BP,
        
        _ => panic!("Could not convert register {:?} to a slot", reg)
    }
}


// #[derive(Debug, Clone)]
// pub enum Type {
//     I64,
//     I32,
//     I16,
//     I8,
// 
//     PTR(Box<Type>), // When a ptr is represented by a pointer to the type of the pointer...
// }
// 
// fn get_type_size(ty: &Type) -> u32 {
//     match ty {
//         Type::I64 => 8,
//         Type::I32 => 4,
//         Type::I16 => 2,
//         Type::I8  => 1,
//         Type::PTR(_)  => 4, // assuming 32 bit for now
//     }
// }
// 
// fn get_reg_type(reg: &Register) -> Type {
//     get_reg_size_type(&reg.size)
// }
// 
// fn get_reg_size_type(size: &Register_Size) -> Type {
//     match size {
//         Register_Size::_8 => Type::I8,
//         Register_Size::_16 => Type::I16,
//         Register_Size::_32 => Type::I32,
//         _ => panic!("Handle non GP register types"),
//     }
// }
// 
// #[derive(Debug, Clone)]
// pub struct Variable {
//     pub local_func: FuncID,
//     pub id: VarID,
//     pub ty: Type,
//     pub size_bytes: u32,
// 
//     // To tell whether this is merely preserved
//     pub locally_used: bool,
//     pub input_reg_variable: bool,
// }
// 
// impl fmt::Display for Variable {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         write!(f, "var_{}_{}", self.local_func, self.id)
//     }
// }
// 
// pub type VarID = u32;
// 
// #[derive(Debug)]
// pub struct VariableRegistry {
//     pub vars: Vec<Variable>,
// 
//     // Represents variables that are merely aliases of each other in different scopes
//     pub var_alias: HashMap<(FuncID, FuncID, VarID), VarID>,
// }
// 
// pub type VariableRegistry_Ptr = Rc<RefCell<VariableRegistry>>;
// 
// impl VariableRegistry {
//     fn new_var(&mut self, local_func: FuncID, ty: Type) -> VarID
//     {
//         let size = get_type_size(&ty);
// 
//         let id = self.vars.len() as u32;
//         self.vars.push(Variable { id, ty, size_bytes: size, local_func, locally_used: false, input_reg_variable: false});
// 
//         return id;
//     }
// 
//     fn get_var_mut(&mut self, var_id: VarID) -> &mut Variable {
//         &mut self.vars[var_id as usize]
//     }
// 
//     pub fn get_var(&self, var_id: VarID) -> &Variable {
//         &self.vars[var_id as usize]
//     }
// }
// 
// pub type FuncID = u32;
// 
// #[derive(Debug)]
// pub struct FunctionRegistry {
//     pub funcs: BTreeMap<FuncID, Pass1_Func>,
//     pub next_func_id: FuncID,
// }
// 
// pub type FunctionRegistry_Ptr = Rc<RefCell<FunctionRegistry>>;
// 
// impl FunctionRegistry {
//     // fn new_func(self: &Rc<RefCell<Self>>, entry: u32, var_registry: VariableRegistry_Ptr) -> (FuncID, &mut Pass1_Func) {
//     //     let func_id = self.funcs.len() as u32;
//     //     self.funcs.push(Pass1_Func { entry: entry, env: VirtualEnv::new(func_id, Rc::clone(&self), var_registry) });
// 
//     //     (func_id, self.funcs.last_mut().unwrap())
//     // }
// 
//     // fn new_func(self: &Rc<RefCell<Self>>) {
// 
//     // }
// 
//     fn get_func(&mut self, func_id: FuncID) -> &mut Pass1_Func {
//         self.funcs.get_mut(&func_id).unwrap()
//     }
// 
//     fn get_next_func_id(&mut self) -> FuncID {
//         let tmp = self.next_func_id;
//         self.next_func_id += 1;
// 
//         tmp
//     }
// }
// 
// // fn new_func(entry: u32, function_regitry: FunctionRegistry_Ptr, variable_registry: VariableRegistry_Ptr) -> FuncID {
// //     let func_id = function_regitry.borrow_mut().funcs.len() as u32;
// //     let env = VirtualEnv::new(
// //         func_id,
// //         function_regitry.clone(),
// //         variable_registry.clone(),
// //     );
// // 
// //     function_regitry.borrow_mut().funcs.push(Pass1_Func { entry, env, returned_vars: Vec::new()});
// // 
// //     func_id
// // }
// 
// #[derive(Debug, Clone)]
// pub struct VirtualEnv {
//     pub func_registry: FunctionRegistry_Ptr,
//     pub var_registry: VariableRegistry_Ptr,
// 
//     pub func_id: FuncID,
//     pub block_id: BasicBlockID,
// 
//     // The stack representing the offsets into the stack
//     //   and the known variable at each part of the stack
//     pub stack: BTreeMap<u32, VarID>,
// 
//     pub regs: HashMap<RegisterSlot, VarID>,
// 
//     pub input_regs: HashMap<RegisterSlot, VarID>,
// 
//     // Any time we pop off the stack and there's nothing there, 
//     //   this must represent a parameter passed by the stack
//     pub input_stack: BTreeMap<u32, VarID>,
// 
//     pub byte_len: u32,
// }
// 
// impl VirtualEnv {
//     fn new(func_id: FuncID, block_id: BasicBlockID, func_registry: FunctionRegistry_Ptr, var_registry: VariableRegistry_Ptr) -> Self {
//         Self {
//             func_registry,
//             var_registry,
//             func_id,
//             block_id,
//             stack: BTreeMap::new(),
//             regs: HashMap::new(),
//             input_regs: HashMap::new(),
//             input_stack: BTreeMap::new(),
//             byte_len: 0, 
//         }
//     }
// 
//     fn new_var(&mut self, ty: Type) -> VarID {
//         self.var_registry.borrow_mut().new_var(self.func_id, ty)
//     }
// 
//     fn push_new_var(&mut self, ty: Type) -> VarID {
//         let var_id = self.new_var(ty);
//         self.push_var(var_id);
// 
//         return var_id;
//     }
// 
//     fn push_var(&mut self, var_id: u32) {
//         self.set_stack_var(self.byte_len, var_id);
//         self.byte_len += self.var_registry.borrow_mut().get_var_mut(var_id).size_bytes;
//     }
// 
//     fn get_stack_var(&mut self, stack_offset: u32, ty: Type) -> VarID {
//         match self.stack.get(&stack_offset) {
//             // TODO: deal with conflicts and when vars overlap
//             Some(var_id) => {
//                 self.var_registry.borrow_mut().get_var_mut(*var_id).locally_used = true;
//                 *var_id
//             },
//             _ => {
//                 let var_id = self.var_registry.borrow_mut().new_var(self.func_id, ty); 
//                 self.stack.insert(stack_offset, var_id);
// 
//                 var_id
//             }
//         }
//     }
// 
//     fn set_stack_var(&mut self, stack_offset: u32, var_id: VarID) {
//         // TODO: deal with conflicts and when vars overlap
//         self.stack.insert(stack_offset, var_id);
//     }
// 
//     fn get_input_stack_var(&mut self, stack_offset: u32, ty: Type) -> VarID {
//         match self.input_stack.get(&stack_offset) {
//             // TODO: deal with conflicts and when vars overlap
//             Some(var_id) => {
//                 self.var_registry.borrow_mut().get_var_mut(*var_id).locally_used = true;
//                 *var_id
//             },
//             _ => {
//                 let var_id = self.var_registry.borrow_mut().new_var(self.func_id, ty);
//                 self.input_stack.insert(stack_offset, var_id);
// 
//                 var_id
//             }
//         }
//     }
// 
//     fn get_reg_var(&mut self, register: RegisterSlot, ty: Type) -> VarID {
//         // TODO: deal with conflicts and when vars overlap
//         match self.regs.get(&register) {
//             Some(var_id) => {
//                 let mut var_id = *var_id;
//                 let var_func_id = self.var_registry.borrow_mut().get_var_mut(var_id).local_func;
// 
//                 self.var_registry.borrow_mut().get_var_mut(var_id).locally_used = true;
//                 if var_func_id != self.func_id {
//                     let current_ty = self.var_registry.borrow_mut().get_var_mut(var_id).ty.clone();
//                     let local_var = self.var_registry.borrow_mut().new_var(self.func_id, current_ty);
// 
//                     // self.var_registry.borrow_mut().var_alias.entry((var_func_id, var_id)).or_insert(Vec::new()).push((self.func_id, local_var));
//                     // self.var_registry.borrow_mut().var_alias.entry((self.func_id, local_var)).or_insert(Vec::new()).push((var_func_id, var_id));
//                     self.var_registry.borrow_mut().var_alias.insert((self.func_id, var_func_id, var_id), local_var);
//                     self.var_registry.borrow_mut().var_alias.insert((var_func_id, self.func_id, local_var), var_id);
// 
//                     self.var_registry.borrow_mut().get_var_mut(local_var).locally_used = true;
// 
//                     self.func_registry.borrow_mut().get_func(self.var_registry.borrow_mut().get_var_mut(var_id).local_func).returned_vars.push(var_id);
// 
//                     var_id = local_var;
//                 }
// 
//                 var_id
//             },
// 
//             None => {
//                 let var_id = self.var_registry.borrow_mut().new_var(self.func_id, ty);
//                 self.var_registry.borrow_mut().get_var_mut(var_id).input_reg_variable = true;
//                 self.regs.insert(register, var_id);
//                 var_id
//             }
//         }
//     }
//     
//     fn set_reg_var(&mut self, register: RegisterSlot, var_id: VarID) {
//         // TODO: deal with conflicts and when vars overlap
//         self.regs.insert(register, var_id);
//     }
// 
//     fn pop_var(&mut self, ty: Type) -> VarID {
//         // TODO: deal with conflicts and when vars overlap
//         let var_size = get_type_size(&ty);
//         let var_id = self.get_stack_var(self.byte_len - var_size, ty);
// 
//         self.byte_len -= var_size;
// 
//         return var_id;
//     }
// 
//     fn shrink_stack(&mut self, num_bytes: u32) {
//         // TODO: handle when the stack partially shrinks into a variable
//         self.byte_len -= num_bytes;
//         self.stack.retain(| k, _ | *k < self.byte_len);
//     }
// }
// 
pub struct Program {
    pub insts: BTreeMap<i64, Instruction>,
    pub text_offset: i64,
}
// 
// struct Dref
// {
//     base: Option<Variable>,
//     index: Option<Variable>,
//     scale: u64,
//     disp: i64,
//     res_size: Register_Size,
// }
// 
// /**
//  * SSA Bytecode where the first parameter is the dst variable
//  */
// #[derive(Debug)]
// pub enum Statement {
//     ADD(VarID, VarID, VarID),
//     MUL(VarID, VarID, VarID),
//     MOV(VarID, VarID),
//     SET(VarID, i64),
//     SHL(VarID, VarID, i64),
// 
//     DREF(VarID, VarID),
//     CALL(FuncID),
//     RET,
// }
// 
// type BasicBlockID = u32;
// 
// pub struct BasicBlock {
//     pub func_id: FuncID,
//     pub block_id: BasicBlockID,
// 
//     pub env: VirtualEnv,
//     pub bytecode: Vec<Statement>,
// }
// 
// pub struct BasicBlockRegistry {
//     basic_blocks: Vec<BasicBlock>,
// }
// 
// pub type BasicBlockRegistry_Ptr = Rc<RefCell<BasicBlockRegistry>>;
// 
// // Pass 1
// // 1. Identify variables
// // 2. Describe net effect on stack and registers
// 
// #[derive(Debug)]
// pub struct Pass1_Func {
//     pub id: FuncID,
//     pub entry: u32,
//     pub env: VirtualEnv,
// 
//     // TODO: TECHNICALLU, the entirety of the stack upon
//     // return of a function is subject to be considered a
//     // return variable. The issue may be that allocated, 
//     // but not variable declared, sections of that stack
//     // May later prove to contain variables.
//     // However, we currentlly are only considering variables
//     // on the called upon stack, and merely extending the byte range
//     // of the host stack. In reality, some of these extended bytes, 
//     // which do not have any variables, could later be considered
//     // variables. But this will create new variables in the host stack,
//     // rather than the called upon stack, since the byte range was only
//     // allocated for.
//     pub passed_in_vars: Vec<VarID>,
//     pub returned_vars: Vec<VarID>,
// 
//     // The creme de le creme
//     pub bytecode: Vec<Statement>,
// }
// 
// pub fn decompile(program: &Program, entry: u32, function_registry: FunctionRegistry_Ptr, variable_registry: VariableRegistry_Ptr) -> FuncID
// {
//     // let func_id = new_func(entry, function_registry.clone(), variable_registry.clone());
//     // let mut binding = function_registry.borrow_mut();
//     // let Pass1_Func { 
//     //     env, 
//     //     ..
//     // } = binding.get_func(func_id);
// 
//     let func_id = function_registry.borrow_mut().get_next_func_id();
//     let mut env = VirtualEnv::new(func_id, function_registry.clone(), variable_registry.clone());
//     let mut bytecode = Vec::new();
// 
//     let mut last_cmp: Option<(VarID, VarID)> = None;
// 
//     for (pc, inst) in program.insts.range((Included(&entry), std::ops::Bound::Unbounded)) {
//         match inst {
//             Instruction {
//                 name: Instruction_Name::near_Ret,
//                 operands: [
//                     None,
//                     None,
//                     None,
//                     None,
//                 ],
//                 ..
//             } => {
//                 bytecode.push(Statement::RET);
//                 break;
//             },
// 
//             // =================== Function Entry and Exit ignore
//             Instruction {
//                 name: Instruction_Name::PUSH,
//                 operands: [
//                     Some(Instruction_Operand::REGISTER(EBP)),
//                     None,
//                     None,
//                     None,
//                 ],
//                 ..
//             } => {
//             },
// 
//             Instruction {
//                 name: Instruction_Name::MOV,
//                 operands: [
//                     Some(Instruction_Operand::REGISTER(EBP)),
//                     Some(Instruction_Operand::REGISTER(ESP)),
//                     None,
//                     None,
//                 ],
//                 ..
//             } => {
//             },
// 
//             Instruction {
//                 name: Instruction_Name::POP,
//                 operands: [
//                     Some(Instruction_Operand::REGISTER(EBP)),
//                     None,
//                     None,
//                     None,
//                 ],
//                 ..
//             } => {
//             },
//             // =================== 
// 
//             Instruction {
//                 name: Instruction_Name::PUSH,
//                 operands: [
//                     Some(Instruction_Operand::IMM_32(val)),
//                     None,
//                     None,
//                     None,
//                 ],
//                 ..
//             } => {
//                 let var = env.push_new_var(Type::I32);
//                 bytecode.push(Statement::SET(var, *val as i64));
//             },
//             
//             Instruction {
//                 name: Instruction_Name::PUSH,
//                 operands: [
//                     Some(Instruction_Operand::REGISTER(reg)),
//                     None,
//                     None,
//                     None,
//                 ],
//                 ..
//             } => {
//                 let var_id = env.get_reg_var(reg_to_slot(reg), get_reg_type(reg));
//                 env.push_var(var_id);
//             },
// 
//             Instruction {
//                 name: Instruction_Name::ADD,
//                 operands: [
//                     Some(Instruction_Operand::REGISTER(ESP)),
//                     Some(Instruction_Operand::IMM_8(val)),
//                     None,
//                     None,
//                 ],
//                 ..
//             } => {
//                 env.shrink_stack(*val as u32);
//             },
// 
//             Instruction {
//                 name: Instruction_Name::SHL,
//                 operands: [
//                     Some(Instruction_Operand::REGISTER(reg)),
//                     Some(Instruction_Operand::IMM_8(val)),
//                     None,
//                     None,
//                 ],
//                 ..
//             } => {
//                 let var = env.get_reg_var(reg_to_slot(reg), get_reg_type(reg));
//                 let new_var = env.new_var(get_reg_type(reg));
//                 env.set_reg_var(reg_to_slot(reg), new_var);
// 
//                 bytecode.push(Statement::SHL(new_var, var, *val as i64));
//             },
// 
//             Instruction {
//                 name: Instruction_Name::MOV,
//                 operands: [
//                     Some(Instruction_Operand::REGISTER(reg)),
//                     Some(Instruction_Operand::DREF(disassemble::Dref { base: Some(EBP), index: None, scale: 0, disp: offset, .. })),
//                     None,
//                     None,
//                 ],
//                 ..
//             } => {
//                 let var = env.get_input_stack_var((*offset) as u32, get_reg_type(reg));
//                 env.set_reg_var(reg_to_slot(reg), var);
//             },
// 
//             Instruction {
//                 name: Instruction_Name::MOV,
//                 operands: [
//                     Some(Instruction_Operand::REGISTER(reg_dst)),
//                     Some(Instruction_Operand::REGISTER(reg_src)),
//                     None,
//                     None,
//                 ],
//                 ..
//             } => {
//                 let var_src = env.get_reg_var(reg_to_slot(reg_src), get_reg_type(reg_src));
//                 env.set_reg_var(reg_to_slot(reg_dst), var_src);
//             },
// 
//             Instruction {
//                 name: Instruction_Name::MOV,
//                 operands: [
//                     Some(Instruction_Operand::REGISTER(reg_dst)),
//                     Some(Instruction_Operand::IMM_8(val)),
//                     None,
//                     None,
//                 ],
//                 ..
//             } => {
//                 let var_id = env.new_var(get_reg_type(reg_dst));
//                 env.set_reg_var(reg_to_slot(reg_dst), var_id);
// 
//                 bytecode.push(Statement::SET(var_id, *val as i64));
//             },
// 
//             Instruction {
//                 name: Instruction_Name::MOV,
//                 operands: [
//                     Some(Instruction_Operand::REGISTER(reg_dst)),
//                     Some(Instruction_Operand::IMM_32(val)),
//                     None,
//                     None,
//                 ],
//                 ..
//             } => {
//                 let var_id = env.new_var(get_reg_type(reg_dst));
//                 env.set_reg_var(reg_to_slot(reg_dst), var_id);
// 
//                 bytecode.push(Statement::SET(var_id, *val as i64));
//             },
// 
//             Instruction {
//                 name: Instruction_Name::near_Call,
//                 byte_len: inst_len,
//                 operands: [
//                     Some(Instruction_Operand::IMM_32(val)),
//                     None,
//                     None,
//                     None,
//                 ],
//             } => {
//                 let called_entry = ((pc + inst_len) as i32) + val;
// 
//                 let called_id = decompile(program, called_entry as u32, function_registry.clone(), variable_registry.clone());
//     
//                 let mut binding = function_registry.borrow_mut();
//                 let called_func = binding.get_func(called_id);
// 
//                 // ******* Alias
//                 // Alias the inputs to the local input variables of the function
//                 for (slot, var_id) in &called_func.env.input_regs {
//                     let mut binding = variable_registry.borrow_mut();
//                     let var = binding.get_var_mut(*var_id);
//                     if var.locally_used {
//                         let ty = var.ty.clone();
//                         binding.var_alias.insert((func_id, called_id, *var_id), env.get_reg_var(*slot, ty.clone()));
//                         binding.var_alias.insert((called_id, func_id, env.get_reg_var(*slot, ty)), *var_id);
//                     }
//                 }
//             
//                 for (stack_offset, var_id) in &called_func.env.input_stack {
//                     let ty = variable_registry.borrow_mut().get_var(*var_id).ty.clone();
//                     let local_var = env.get_stack_var(env.byte_len - *stack_offset + 4, ty);
//                     let mut binding = variable_registry.borrow_mut();
// 
//                     binding.var_alias.insert((func_id, called_id, *var_id), local_var);
//                     binding.var_alias.insert((called_id, func_id, local_var), *var_id);
//                 }
//                 // ******* 
// 
//                 // ******* Merge stack and registers
//                 // extend the called stack onto our stack
//                 for (offset, var) in &called_func.env.stack {
//                     env.stack.insert(offset + env.byte_len, *var);
//                 }
// 
//                 env.byte_len += called_func.env.byte_len;
// 
//                 // Set registers
//                 for (reg_slot, var_id) in &called_func.env.regs {
//                     if !variable_registry.borrow_mut().get_var_mut(*var_id).input_reg_variable {
//                         env.regs.insert(*reg_slot, *var_id);
//                     }
//                 }
// 
//                 bytecode.push(Statement::CALL(called_id));
//             }
// 
//             Instruction {
//                 name: Instruction_Name::XOR,
//                 operands: [
//                     Some(Instruction_Operand::REGISTER(reg_a)),
//                     Some(Instruction_Operand::REGISTER(reg_b)),
//                     None,
//                     None,
//                 ],
//                 ..
//             } if reg_a == reg_b => {
//                 let var = env.new_var(Type::I32);
//                 env.regs.insert(reg_to_slot(reg_a), var);
// 
//                 bytecode.push(Statement::SET(var, 0));
//             }
//             
//             Instruction {
//                 name: Instruction_Name::ADD,
//                 operands: [
//                     Some(Instruction_Operand::REGISTER(reg_a)),
//                     Some(Instruction_Operand::REGISTER(reg_b)),
//                     None,
//                     None,
//                 ],
//                 ..
//             } => {
//                 let dst_var = env.new_var(get_reg_type(reg_a));
//                 let var_a = env.get_reg_var(reg_to_slot(reg_a), get_reg_type(reg_a));
//                 let var_b = env.get_reg_var(reg_to_slot(reg_b), get_reg_type(reg_b));
// 
//                 env.set_reg_var(reg_to_slot(reg_a), dst_var);
// 
//                 bytecode.push(Statement::ADD(dst_var, var_a, var_b));
//             }
// 
//             Instruction {
//                 name: Instruction_Name::IMUL,
//                 operands: [
//                     Some(Instruction_Operand::REGISTER(reg_a)),
//                     Some(Instruction_Operand::DREF(disassemble::Dref { base: Some(EBP), index: None, scale: 0, disp: offset, .. })),
//                     None,
//                     None,
//                 ],
//                 ..
//             } => {
//                 let dst_var = env.new_var(get_reg_type(reg_a));
//                 let var_a = env.get_reg_var(reg_to_slot(reg_a), get_reg_type(reg_a));
//                 let var_b = env.get_input_stack_var((*offset) as u32, get_reg_type(reg_a));
// 
//                 env.set_reg_var(reg_to_slot(reg_a), dst_var);
//                 bytecode.push(Statement::MUL(dst_var, var_a, var_b));
//             },
// 
//             Instruction {
//                 name: Instruction_Name::CMP,
//                 operands: [
//                     Some(Instruction_Operand::DREF(disassemble::Dref { base: Some(EBP), index: None, scale: 0, disp: offset, res_size })),
//                     Some(Instruction_Operand::IMM_8(val)),
//                     None,
//                     None,
//                 ],
//                 ..
// 
//             } => {
//                 let var_a = env.get_input_stack_var((*offset) as u32, get_reg_size_type(res_size));
//                 let var_b = env.new_var(get_reg_size_type(res_size));
// 
//                 bytecode.push(Statement::SET(var_b, *val as i64));
// 
//                 last_cmp = Some((var_a, var_b));
//             }
// 
//             _ => ()
//         }
//     }
// 
//     // Determine what inputs were truly used in this function
//     let mut passed_in_vars = Vec::new();
//     for (_, var_id) in &env.input_regs {
//         let binding = variable_registry.borrow_mut();
//         let var = binding.get_var(*var_id);
//         if var.locally_used {
//             passed_in_vars.push(*var_id);
//         }
//     }
// 
//     for (_, var_id) in &env.input_stack {
//         passed_in_vars.push(*var_id);
//     }
// 
//     function_registry.borrow_mut().funcs.insert(env.func_id, Pass1_Func { id: func_id, entry, env, passed_in_vars, returned_vars: Vec::new(), bytecode });
//     func_id
// }

pub type BlockID = i64;

#[derive(Debug)]
pub struct Pass1_Block {
    // pc of the first instruction of the block
    pub entry: i64,

    // pc of the instruction after this block
    pub end: i64,

    pub id: BlockID,
}

#[derive(Default, Debug)]
pub struct Pass1_BlockRegistry {
    pub blocks: BTreeMap<i64, Pass1_Block>,
}

pub fn pass_1_identify_blocks(
    program: &Program,
    entry: i64,
) -> Pass1_BlockRegistry {
    let mut block_registry = Pass1_BlockRegistry::default();
    let mut to_eval = Vec::new();
    to_eval.push(entry);

    while !to_eval.is_empty() {
        let entry = to_eval.pop().unwrap();
        if block_registry.blocks.contains_key(&entry) {
            continue;
        }

        for (pc, inst) in program.insts.range((Included(&entry), std::ops::Bound::Unbounded)) {
            if inst.name == Instruction_Name::far_Ret || 
                inst.name == Instruction_Name::near_Ret
            {
                // End of block
                block_registry.blocks.insert(entry, Pass1_Block { entry, end: *pc + inst.byte_len as i64, id: entry});
                break;
            } else if inst.name == Instruction_Name::far_Call ||
                inst.name == Instruction_Name::near_Call
            {
                to_eval.push(pc + (inst.byte_len as i64));
                block_registry.blocks.insert(entry, Pass1_Block { entry, end: *pc + inst.byte_len as i64, id: entry});
                break;
            } else if let Some(offset) = inst.is_offset_jmp() {
                to_eval.push(pc + offset + inst.byte_len as i64);
                if inst.name != Instruction_Name::far_Jmp &&
                    inst.name != Instruction_Name::near_Jmp &&
                    inst.name != Instruction_Name::short_Jmp
                {
                    // Conditional Jump
                    to_eval.push(pc + (inst.byte_len as i64));
                }

                block_registry.blocks.insert(entry, Pass1_Block { entry, end: *pc + inst.byte_len as i64, id: entry});
                break;
            }
        }
    }

    // Do another pass and clean up blocks that have another block starting in the middle of it
    let mut iter = block_registry.blocks.iter_mut();
    if let Some(mut prev) = iter.next() {
        for curr in iter {
            println!("Pair: ({:x?}, {:x?})", prev, curr);
            if curr.1.entry < prev.1.end {
                prev.1.end = curr.1.entry;
            }
            prev = curr;
        }
    }

    return block_registry;
}

pub fn pass_2_identify_function_calls(
    pass1_blocks: &Pass1_BlockRegistry,
    program: &Program
) -> Vec<i64> {
    let mut entries = Vec::new();
    if pass1_blocks.blocks.len() == 0 {
        return entries;
    }

    for (pc, inst) in program.insts.range((
        Included(*pass1_blocks.blocks.first_key_value().unwrap().0), 
        Excluded(pass1_blocks.blocks.iter().rev().next().unwrap().1.end))
    ) {
        if inst.name == Instruction_Name::near_Call || 
            inst.name == Instruction_Name::far_Call 
        {
            entries.push(*pc + (inst.byte_len as i64) + inst.get_first_val().expect("Expected call instruction to have and immediate value for the offset"));
        }
    }

    return entries;
}

#[derive(Debug)]
pub enum VirtualEnvCmd {

}

pub type VarID = u32;
pub type FuncID = u32;

#[derive(Debug)]
pub struct Flags_JLE {
    zero_flag: VarID,
    sign_flag: VarID,
    overflow_flag: VarID,
}

#[derive(Debug)]
pub struct Flags_JL {
    sign_flag: VarID,
    overflow_flag: VarID,
}

#[derive(Debug)]
pub struct Flags_JZ {
    zero_flag: VarID,
}

#[derive(Debug)]
pub struct Flags_JNZ {
    zero_flag: VarID,
}

/**
 * SSA Bytecode where the first parameter is the dst variable
 */
#[derive(Debug)]
pub enum Statement {
    ADD(VarID, VarID, VarID),
    INC(VarID, VarID),
    SUB(VarID, VarID, VarID),
    MUL(VarID, VarID, VarID),
    MUL_HI_LOW(VarID, VarID, VarID, VarID),
    // SHL(VarID, VarID, i64),
    SHR(VarID, VarID, VarID),
    XOR(VarID, VarID, VarID),

    // SET(VarID, i64),

    // Placeholder during translation to hold auto-generated varaibles that don't go into an instruction
    NOP_1(VarID),
    NOP_2(VarID, VarID),

    MOV(VarID, VarID),
    DREF(VarID, VarID),

    CMP(VarID, VarID),
    TEST(VarID, VarID),

    JLE(Flags_JLE, BlockID, BlockID),
    JL(Flags_JL, BlockID, BlockID),
    JZ(Flags_JZ, BlockID, BlockID),
    JNZ(Flags_JNZ, BlockID, BlockID),

    CALL(FuncID),
    RET,
}

#[derive(Debug, Clone)]
pub enum Type {
    I64,
    I32,
    I16,
    I8,

    PTR(Box<Type>), // When a ptr is represented by a pointer to the type of the pointer...
}

fn get_type_size(ty: &Type) -> u32 {
    match ty {
        Type::I64 => 8,
        Type::I32 => 4,
        Type::I16 => 2,
        Type::I8  => 1,
        Type::PTR(_)  => 4, // assuming 32 bit for now
    }
}

fn get_reg_type(reg: &Register) -> Type {
    get_reg_size_type(&reg.size)
}

fn get_reg_size_type(size: &Register_Size) -> Type {
    match size {
        Register_Size::_8 => Type::I8,
        Register_Size::_16 => Type::I16,
        Register_Size::_32 => Type::I32,
        _ => panic!("Handle non GP register types"),
    }
}

#[derive(Debug)]
pub struct Pass3_Var {
    pub ty: Type,
    pub size_bytes: u32,

    pub block_id: i64,

    pub phi: HashSet<VarID>,
    pub val: Option<i64>,

    // What instruction produced this variable
    pub inst_addr: Option<i64>
}

#[derive(Default, Debug)]
pub struct Pass3_Func {
    id: FuncID,
    net_env: Vec<Vec<VirtualEnvCmd>>,
    pub bytecode: BTreeMap<i64, Statement>,
}

#[derive(Default, Debug)]
pub struct Pass3_VariableRegistry {
    vars: Vec<Pass3_Var>,
    pub block_vars: HashMap<BlockID, Vec<VarID>>,

    variable_block_alias: HashMap<(BlockID, VarID), VarID>,
}

impl Pass3_VariableRegistry {
    fn new_var(&mut self, ty: Type, local_func: FuncID, block: BlockID, val: Option<i64>, inst_addr: Option<i64>) -> VarID
    {
        let size = get_type_size(&ty);

        let id = self.vars.len() as u32;
        // self.vars.push(Pass { id, ty, size_bytes: size, local_func, locally_used: false, input_reg_variable: false});
        self.vars.push(
            Pass3_Var { 
                ty: ty, 
                size_bytes: size,
                phi: HashSet::new(),
                block_id: block,
                val,
                inst_addr,
            }
        );

        self.block_vars.entry(block).or_insert_with(Vec::new).push(id);

        return id;
    }

    pub fn get_var(&self, var_id: VarID) -> &Pass3_Var {
        &self.vars[var_id as usize]
    }

    fn get_var_mut(&mut self, var_id: VarID) -> &mut Pass3_Var {
        &mut self.vars[var_id as usize]
    }

}

// TODO: tag space on the stack with what function allocated that stack space
// a variable could allocated on the stack, but unused and unlabled
// until someone in a different function sees it.
// since the space is empty, they will create a variable owned by their
// function, rather than the function that allocated space for it

#[derive(Default, Debug, Clone, Hash)]
pub struct Pass3_VirtualEnv {
    // The stack representing the offsets into the stack
    //   and the known variable at each part of the stack
    pub stack: BTreeMap<i64, VarID>,

    pub regs: BTreeMap<RegisterSlot, VarID>,

    pub byte_len: u32,

    pub stack_base_stack: Vec<i64>,
    pub current_base_offset: i64,

    // last_cmp: Option<(VarID, VarID)>,
}

impl Pass3_VirtualEnv {
    fn new_var(&self, ty: Type, function: FuncID, block: BlockID, inst_addr: Option<i64>, var_registry: &mut Pass3_VariableRegistry) -> VarID {
        // self.var_registry.borrow_mut().new_var(self.func_id, ty)
        var_registry.new_var(ty, function, block, None, inst_addr)
    }

    fn new_var_val(&self, ty: Type, function: FuncID, block: BlockID, inst_addr: Option<i64>, val: i64, var_registry: &mut Pass3_VariableRegistry) -> VarID {
        // self.var_registry.borrow_mut().new_var(self.func_id, ty)
        var_registry.new_var(ty, function, block, inst_addr, Some(val))
    }

    fn set_stack_var(&mut self, stack_offset: i64, var_id: VarID) {
        // TODO: deal with conflicts and when vars overlap
        self.stack.insert(stack_offset, var_id);
    }

    fn push_var(&mut self, var_registry: &mut Pass3_VariableRegistry,var_id: u32) {
        self.set_stack_var(self.byte_len as i64, var_id);
        self.byte_len += var_registry.get_var(var_id).size_bytes;
    }

    fn push_new_var(&mut self, ty: Type, function: FuncID, block: BlockID, inst_addr: Option<i64>, var_registry: &mut Pass3_VariableRegistry) -> VarID {
        let var_id = self.new_var(ty, function, block, inst_addr, var_registry);
        self.push_var(var_registry, var_id);

        return var_id;
    }

    fn push_new_var_val(&mut self, ty: Type, function: FuncID, block: BlockID, inst_addr: Option<i64>, val: i64, var_registry: &mut Pass3_VariableRegistry) -> VarID {
        let var_id = self.new_var(ty, function, block, inst_addr, var_registry);
        self.push_var(var_registry, var_id);

        return var_id;
    }

    fn get_reg_var(&mut self, register: RegisterSlot, ty: Type, function: FuncID, block: BlockID, new_block_var: bool, var_registry: &mut Pass3_VariableRegistry) -> VarID {
        // TODO: deal with conflicts and when vars overlap
        match self.regs.get(&register) {
            Some(var_id) => {
                let mut var_id = *var_id;

                let var = var_registry.get_var(var_id);
                if var.block_id != block && new_block_var {
                    // Create a new variable with a single phi-node entry
                    // This is so that phi nodes are handled consistently in all lines of execution
                    // if we don't place them in advance, we would have to stomp over variables
                    // after discovering a phi-node was needed.
                    // Should that happen, we would need to replace later references of this variable with a new variable
                    // but this is terribly complicated, and might work if you always evaluate the earliest line
                    // of execution. BUT does not work with loops where the program will backtrack and arbitrarily
                    // require a new varaible for a phi node at any time.
                    // A new variable with a phi node is needed because variables are immutable in SSA

                    if let Some(registered_var) = var_registry.variable_block_alias.get(&(block, var_id)) {
                        var_id = *registered_var;
                    } else {
                        let new_var_id = var_registry.new_var(var.ty.clone(), function, block, None, None);
                        let var = var_registry.get_var_mut(new_var_id);
                        var.phi.insert(var_id);

                        var_registry.variable_block_alias.insert((block, var_id), new_var_id);
                        var_id = new_var_id;
                    }
                }

                // let var_func_id = self.var_registry.borrow_mut().get_var_mut(var_id).local_func;

                // self.var_registry.borrow_mut().get_var_mut(var_id).locally_used = true;
                // if var_func_id != self.func_id {
                //     let current_ty = self.var_registry.borrow_mut().get_var_mut(var_id).ty.clone();
                //     let local_var = self.var_registry.borrow_mut().new_var(self.func_id, current_ty);

                //     // self.var_registry.borrow_mut().var_alias.entry((var_func_id, var_id)).or_insert(Vec::new()).push((self.func_id, local_var));
                //     // self.var_registry.borrow_mut().var_alias.entry((self.func_id, local_var)).or_insert(Vec::new()).push((var_func_id, var_id));
                //     self.var_registry.borrow_mut().var_alias.insert((self.func_id, var_func_id, var_id), local_var);
                //     self.var_registry.borrow_mut().var_alias.insert((var_func_id, self.func_id, local_var), var_id);

                //     self.var_registry.borrow_mut().get_var_mut(local_var).locally_used = true;

                //     self.func_registry.borrow_mut().get_func(self.var_registry.borrow_mut().get_var_mut(var_id).local_func).returned_vars.push(var_id);

                //     var_id = local_var;
                // }

                var_id
            },

            None => {
                let var_id = var_registry.new_var(ty, function, block, None, None);
                // self.var_registry.borrow_mut().get_var_mut(var_id).input_reg_variable = true;
                self.regs.insert(register, var_id);
                var_id
            }
        }
    }

    fn set_reg_var(&mut self, register: RegisterSlot, var_id: VarID) {
        // TODO: deal with conflicts and when vars overlap
        self.regs.insert(register, var_id);
    }

    fn shrink_stack(&mut self, num_bytes: u32) {
        // TODO: handle when the stack partially shrinks into a variable
        self.byte_len -= num_bytes;
        self.stack.retain(| k, _ | *k < self.byte_len as i64);
    }

    fn get_stack_var(&mut self, stack_offset: i64, ty: &Type, function: FuncID, block: BlockID, new_block_var: bool, var_registry: &mut Pass3_VariableRegistry) -> VarID {
        if let Some(&var_id) = self.stack.get(&stack_offset) {
            let var = var_registry.get_var(var_id);
            if var.block_id != block && new_block_var {
                if let Some(registerd_var_id) = var_registry.variable_block_alias.get(&(block, var_id)) {
                    return *registerd_var_id;
                }

                let new_var_id = var_registry.new_var(var.ty.clone(), function, block, None, None);
                let var = var_registry.get_var_mut(new_var_id);
                var.phi.insert(var_id);

                var_registry.variable_block_alias.insert((block, var_id), new_var_id);

                return new_var_id;
            } else {
                return var_id;
            }
        } else {
            let var_id = var_registry.new_var(ty.clone(), function, block, None, None);
            self.stack.insert(stack_offset, var_id);

            return var_id;
        }
    }
}


// Calculates the net effect of the function that can be applied to an input environment in the next pass
//   - Outputs more than one if there are multiple branches
// Generates the bytecode for the function
// Puts variables to the data in the function
// Variables may also be made by a phi node, 
//   - meaning that their value depends on what block the program just came from
pub fn pass_3_generate_virtual_env_cmds(
    program: &Program,
    blocks: &Pass1_BlockRegistry,

    variables: &mut Pass3_VariableRegistry,
) ->  Pass3_Func {
    let mut func = Pass3_Func::default();
    func.id = 0;

    let mut to_eval : BTreeMap<i64, (Pass3_VirtualEnv, Vec<VirtualEnvCmd>)> = BTreeMap::new();
    to_eval.insert(*blocks.blocks.first_key_value().unwrap().0, (Pass3_VirtualEnv::default(), Vec::new()));

    let mut termination_state = HashSet::new();

    while !to_eval.is_empty() {
        let (start_pc , (mut env, mut cmds)) = to_eval.pop_first().unwrap();
        let block = blocks.blocks.get(&start_pc).unwrap();

        let mut hasher = DefaultHasher::new();
        env.hash(&mut hasher);
        let hash_val = hasher.finish();

        if termination_state.get(&(block.id, hash_val)).is_some() {
            continue;
        } else {
            termination_state.insert((block.id, hash_val));
        }

        let mut next_block_set = false;

        'inst_loop: 
        for (pc, inst) in program.insts.range((
            Included(block.entry), 
            Excluded(block.end))
        ) {
            match inst {
                Instruction {
                    name: Instruction_Name::near_Ret,
                    ..
                } => {
                    match func.bytecode.get(pc) {
                        None => { func.bytecode.insert(*pc, Statement::RET); },
                        _ => {}
                    };

                    next_block_set = true;
                    break 'inst_loop;
                }

                // =================== Function Entry and Exit, ignore
                Instruction {
                    name: Instruction_Name::PUSH,
                    operands: [
                        Some(Instruction_Operand::REGISTER(EBP)),
                        None,
                        None,
                        None,
                    ],
                    ..
                } => {
                    env.stack_base_stack.push(env.current_base_offset);
                },

                Instruction {
                    name: Instruction_Name::MOV,
                    operands: [
                        Some(Instruction_Operand::REGISTER(EBP)),
                        Some(Instruction_Operand::REGISTER(ESP)),
                        None,
                        None,
                    ],
                    ..
                } => {
                    env.current_base_offset = env.byte_len as i64;
                },

                Instruction {
                    name: Instruction_Name::POP,
                    operands: [
                        Some(Instruction_Operand::REGISTER(EBP)),
                        None,
                        None,
                        None,
                    ],
                    ..
                } => {
                    env.current_base_offset = env.stack_base_stack.pop().unwrap();
                },
                // =================== 

                Instruction {
                    name: Instruction_Name::PUSH,
                    operands: [
                        Some(Instruction_Operand::IMM_32(val)),
                        None,
                        None,
                        None,
                    ],
                    ..
                } => {
                    if func.bytecode.get(pc).is_none() {
                        let var = env.push_new_var_val(Type::I32, func.id, block.id, None, *val as i64, variables);
                        // func.bytecode.insert(*pc, Statement::SET(var, *val as i64));
                    }
                },

                Instruction {
                    name: Instruction_Name::PUSH,
                    operands: [
                        Some(Instruction_Operand::REGISTER(reg)),
                        None,
                        None,
                        None,
                    ],
                    ..
                } => {
                    let var_id = env.get_reg_var(reg_to_slot(reg), get_reg_type(reg), func.id, block.id, true, variables);
                    env.push_var(variables, var_id);
                },

                Instruction {
                    name: Instruction_Name::ADD,
                    operands: [
                        Some(Instruction_Operand::REGISTER(ESP)),
                        Some(Instruction_Operand::IMM_8(val)),
                        None,
                        None,
                    ],
                    ..
                } => {
                    env.shrink_stack(*val as u32);
                },

                Instruction {
                    name: Instruction_Name::IMUL,
                    operands: [
                        Some(Instruction_Operand::REGISTER(reg_a)),
                        Some(Instruction_Operand::DREF(disassemble::Dref { base: Some(EBP), index: None, scale: 0, disp: offset, .. })),
                        None,
                        None,
                    ],
                    ..
                } => {
                    let new_var_a = env.get_reg_var(reg_to_slot(reg_a), get_reg_type(reg_a), func.id, block.id, !func.bytecode.contains_key(pc), variables);
                    let new_var_b = env.get_stack_var(env.current_base_offset - *offset, &get_reg_type(reg_a), func.id, block.id, !func.bytecode.contains_key(pc), variables);
                    if let Some(Statement::MUL(dst_var_id, var_a_id, var_b_id)) = func.bytecode.get(pc) {
                        let var_a = variables.get_var_mut(*var_a_id);
                        if new_var_a != *var_a_id {
                            var_a.phi.insert(new_var_a);
                        }

                        let var_b = variables.get_var_mut(*var_b_id);
                        if new_var_b != *var_b_id {
                            var_b.phi.insert(new_var_b);
                        }

                        env.set_reg_var(reg_to_slot(reg_a), *dst_var_id);
                    } else {
                        let dst_var = env.new_var(get_reg_type(reg_a), func.id, block.id, None, variables);
                        env.set_reg_var(reg_to_slot(reg_a), dst_var);
                        func.bytecode.insert(*pc, Statement::MUL(dst_var, new_var_a, new_var_b));
                    }
                },

                Instruction {
                    name: Instruction_Name::ADD,
                    operands: [
                        Some(Instruction_Operand::REGISTER(reg_a)),
                        Some(Instruction_Operand::REGISTER(reg_b)),
                        None,
                        None,
                    ],
                    ..
                } => {
                    let new_var_a = env.get_reg_var(reg_to_slot(reg_a), get_reg_type(reg_a), func.id, block.id, !func.bytecode.contains_key(pc), variables);
                    let new_var_b = env.get_reg_var(reg_to_slot(reg_b), get_reg_type(reg_b), func.id, block.id, !func.bytecode.contains_key(pc), variables);
                    if let Some(Statement::ADD(dst_var_id, var_a_id, var_b_id)) = func.bytecode.get(pc) {
                        let var_a = variables.get_var_mut(*var_a_id);
                        if new_var_a != *var_a_id {
                            var_a.phi.insert(new_var_a);
                        }

                        let var_b = variables.get_var_mut(*var_b_id);
                        if new_var_b != *var_b_id {
                            var_b.phi.insert(new_var_b);
                        }

                        env.set_reg_var(reg_to_slot(reg_a), *dst_var_id);
                    } else {
                        let dst_var = env.new_var(get_reg_type(reg_a), func.id, block.id, None, variables);
                        env.set_reg_var(reg_to_slot(reg_a), dst_var);
                        func.bytecode.insert(*pc, Statement::ADD(dst_var, new_var_a, new_var_b));
                    }
                }

                Instruction {
                    name: Instruction_Name::SUB,
                    operands: [
                        Some(Instruction_Operand::REGISTER(reg_a)),
                        Some(Instruction_Operand::REGISTER(reg_b)),
                        None,
                        None,
                    ],
                    ..
                } => {
                    let new_var_a = env.get_reg_var(reg_to_slot(reg_a), get_reg_type(reg_a), func.id, block.id, !func.bytecode.contains_key(pc), variables);
                    let new_var_b = env.get_reg_var(reg_to_slot(reg_b), get_reg_type(reg_b), func.id, block.id, !func.bytecode.contains_key(pc), variables);
                    if let Some(Statement::SUB(dst_var_id, var_a_id, var_b_id)) = func.bytecode.get(pc) {
                        let var_a = variables.get_var_mut(*var_a_id);
                        if new_var_a != *var_a_id {
                            var_a.phi.insert(new_var_a);
                        }

                        let var_b = variables.get_var_mut(*var_b_id);
                        if new_var_b != *var_b_id {
                            var_b.phi.insert(new_var_b);
                        }

                        env.set_reg_var(reg_to_slot(reg_a), *dst_var_id);
                    } else {
                        let dst_var = env.new_var(get_reg_type(reg_a), func.id, block.id, None, variables);
                        env.set_reg_var(reg_to_slot(reg_a), dst_var);
                        func.bytecode.insert(*pc, Statement::SUB(dst_var, new_var_a, new_var_b));
                    }
                }

                Instruction {
                    name: Instruction_Name::IMUL,
                    operands: [
                        Some(Instruction_Operand::REGISTER(reg_a)),
                        Some(Instruction_Operand::REGISTER(reg_b)),
                        None,
                        None,
                    ],
                    ..
                } => {
                    let new_var_a = env.get_reg_var(reg_to_slot(reg_a), get_reg_type(reg_a), func.id, block.id, !func.bytecode.contains_key(pc), variables);
                    let new_var_b = env.get_reg_var(reg_to_slot(reg_b), get_reg_type(reg_b), func.id, block.id, !func.bytecode.contains_key(pc), variables);
                    if let Some(Statement::MUL(dst_var_id, var_a_id, var_b_id)) = func.bytecode.get(pc) {
                        let var_a = variables.get_var_mut(*var_a_id);
                        if new_var_a != *var_a_id {
                            var_a.phi.insert(new_var_a);
                        }

                        let var_b = variables.get_var_mut(*var_b_id);
                        if new_var_b != *var_b_id {
                            var_b.phi.insert(new_var_b);
                        }

                        env.set_reg_var(reg_to_slot(reg_a), *dst_var_id);
                    } else {
                        let dst_var = env.new_var(get_reg_type(reg_a), func.id, block.id, None, variables);
                        env.set_reg_var(reg_to_slot(reg_a), dst_var);
                        func.bytecode.insert(*pc, Statement::MUL(dst_var, new_var_a, new_var_b));
                    }
                }

                Instruction {
                    name: Instruction_Name::SHR,
                    operands: [
                        Some(Instruction_Operand::REGISTER(reg_a)),
                        Some(Instruction_Operand::IMM_8(val)),
                        None,
                        None,
                    ],
                    ..
                } => {
                    let new_var_a = env.get_reg_var(reg_to_slot(reg_a), get_reg_type(reg_a), func.id, block.id, !func.bytecode.contains_key(pc), variables);
                    if let Some(Statement::SHR(dst_var_id, var_a_id, var_b_id)) = func.bytecode.get(pc) {
                        let var_a = variables.get_var_mut(*var_a_id);
                        if new_var_a != *var_a_id {
                            var_a.phi.insert(new_var_a);
                        }

                        env.set_reg_var(reg_to_slot(reg_a), *dst_var_id);
                    } else {
                        let dst_var = env.new_var(get_reg_type(reg_a), func.id, block.id, None, variables);
                        let new_var_b = env.new_var_val(Type::I8, func.id, block.id, None, *val as i64, variables);

                        env.set_reg_var(reg_to_slot(reg_a), dst_var);
                        func.bytecode.insert(*pc, Statement::SHR(dst_var, new_var_a, new_var_b));
                    }
                }

                Instruction {
                    name: Instruction_Name::CMP,
                    operands: [
                        Some(Instruction_Operand::DREF(disassemble::Dref { base: Some(EBP), index: None, scale: 0, disp: offset, res_size })),
                        Some(Instruction_Operand::IMM_8(val)),
                        None,
                        None,
                    ],
                    ..

                } => {
                    let new_var_a = env.get_stack_var(env.current_base_offset - *offset, &get_reg_size_type(res_size), func.id, block.id, !func.bytecode.contains_key(pc), variables);
                    if let Some(Statement::CMP(var_a_id, var_b_id)) = func.bytecode.get(pc) {
                        let var_a = variables.get_var_mut(*var_a_id);
                        if new_var_a != *var_a_id {
                            var_a.phi.insert(new_var_a);
                        }

                        // env.last_cmp = Some((*var_a_id, *var_b_id));
                    } else {
                        let new_var_b = env.new_var_val(Type::I8, func.id, block.id, None, *val as i64, variables);

                        // env.last_cmp = Some((new_var_a, new_var_b));
                        func.bytecode.insert(*pc, Statement::CMP(new_var_a, new_var_b));
                    }
                }

                Instruction {
                    name: Instruction_Name::CMP,
                    operands: [
                        Some(Instruction_Operand::REGISTER(reg_a)),
                        Some(Instruction_Operand::IMM_8(val)),
                        None,
                        None,
                    ],
                    ..

                } => {
                    let new_var_a = env.get_reg_var(reg_to_slot(reg_a), get_reg_type(reg_a), func.id, block.id, !func.bytecode.contains_key(pc), variables);
                    if let Some(Statement::CMP(var_a_id, var_b_id)) = func.bytecode.get(pc) {
                        let var_a = variables.get_var_mut(*var_a_id);
                        if new_var_a != *var_a_id {
                            var_a.phi.insert(new_var_a);
                        }

                        // env.last_cmp = Some((*var_a_id, *var_b_id));
                    } else {
                        let new_var_b = env.new_var_val(Type::I8, func.id, block.id, None, *val as i64, variables);

                        // env.last_cmp = Some((new_var_a, new_var_b));
                        func.bytecode.insert(*pc, Statement::CMP(new_var_a, new_var_b));
                    }
                }

                Instruction {
                    name: Instruction_Name::CMP,
                    operands: [
                        Some(Instruction_Operand::REGISTER(reg_a)),
                        Some(Instruction_Operand::REGISTER(reg_b)),
                        None,
                        None,
                    ],
                    ..

                } => {
                    let new_var_a = env.get_reg_var(reg_to_slot(reg_a), get_reg_type(reg_a), func.id, block.id, !func.bytecode.contains_key(pc), variables);
                    let new_var_b = env.get_reg_var(reg_to_slot(reg_b), get_reg_type(reg_b), func.id, block.id, !func.bytecode.contains_key(pc), variables);
                    if let Some(Statement::CMP(var_a_id, var_b_id)) = func.bytecode.get(pc) {
                        let var_a = variables.get_var_mut(*var_a_id);
                        if new_var_a != *var_a_id {
                            var_a.phi.insert(new_var_a);
                        }

                        let var_b = variables.get_var_mut(*var_b_id);
                        if new_var_b != *var_b_id {
                            var_b.phi.insert(new_var_b);
                        }
                        // env.last_cmp = Some((*var_a_id, *var_b_id));
                    } else {
                        // env.last_cmp = Some((new_var_a, new_var_b));
                        func.bytecode.insert(*pc, Statement::CMP(new_var_a, new_var_b));
                    }
                }

                Instruction {
                    name: Instruction_Name::XOR,
                    operands: [
                        Some(Instruction_Operand::REGISTER(reg_a)),
                        Some(Instruction_Operand::REGISTER(reg_b)),
                        None,
                        None,
                    ],
                    ..
                } if reg_a == reg_b => {
                    let var_id = 
                    {
                        if let Some(Statement::NOP_1(var_id)) = func.bytecode.get(pc) {
                            *var_id
                        } else {
                            let var = env.new_var_val(Type::I32, func.id, block.id, None, 0, variables);

                            func.bytecode.insert(*pc, Statement::NOP_1(var));
                            var
                        }
                    };

                    env.regs.insert(reg_to_slot(reg_a), var_id);
                }

                Instruction {
                    name: Instruction_Name::XOR,
                    operands: [
                        Some(Instruction_Operand::REGISTER(reg_a)),
                        Some(Instruction_Operand::REGISTER(reg_b)),
                        None,
                        None,
                    ],
                    ..
                } => {
                    let new_var_a = env.get_reg_var(reg_to_slot(reg_a), get_reg_type(reg_a), func.id, block.id, !func.bytecode.contains_key(pc), variables);
                    let new_var_b = env.get_reg_var(reg_to_slot(reg_b), get_reg_type(reg_b), func.id, block.id, !func.bytecode.contains_key(pc), variables);
                    if let Some(Statement::XOR(dst_var_id, var_a_id, var_b_id)) = func.bytecode.get(pc) {
                        let var_a = variables.get_var_mut(*var_a_id);
                        if new_var_a != *var_a_id {
                            var_a.phi.insert(new_var_a);
                        }

                        let var_b = variables.get_var_mut(*var_b_id);
                        if new_var_b != *var_b_id {
                            var_b.phi.insert(new_var_b);
                        }

                        env.set_reg_var(reg_to_slot(reg_a), *dst_var_id);
                    } else {
                        let dst_var = env.new_var(get_reg_type(reg_a), func.id, block.id, None, variables);
                        env.set_reg_var(reg_to_slot(reg_a), dst_var);
                        func.bytecode.insert(*pc, Statement::XOR(dst_var, new_var_a, new_var_b));
                    }
                }

                Instruction {
                    name: Instruction_Name::TEST,
                    operands: [
                        Some(Instruction_Operand::REGISTER(reg_a)),
                        Some(Instruction_Operand::REGISTER(reg_b)),
                        None,
                        None,
                    ],
                    ..
                } => {
                    let new_var_a = env.get_reg_var(reg_to_slot(reg_a), get_reg_type(reg_a), func.id, block.id, !func.bytecode.contains_key(pc), variables);
                    let new_var_b = env.get_reg_var(reg_to_slot(reg_b), get_reg_type(reg_b), func.id, block.id, !func.bytecode.contains_key(pc), variables);
                    if let Some(Statement::TEST(var_a_id, var_b_id)) = func.bytecode.get(pc) {
                        let var_a = variables.get_var_mut(*var_a_id);
                        if new_var_a != *var_a_id {
                            var_a.phi.insert(new_var_a);
                        }

                        let var_b = variables.get_var_mut(*var_b_id);
                        if new_var_b != *var_b_id {
                            var_b.phi.insert(new_var_b);
                        }

                        // env.last_cmp = Some((*var_a_id, *var_b_id));
                    } else {
                        // let new_var_b = env.new_var(Type::I8, func.id, block.id, variables);

                        // env.last_cmp = Some((new_var_a, new_var_b));
                        func.bytecode.insert(*pc, Statement::TEST(new_var_a, new_var_b));
                    }
                }

                Instruction {
                    name: Instruction_Name::TEST,
                    operands: [
                        Some(Instruction_Operand::REGISTER(reg_a)),
                        Some(Instruction_Operand::IMM_8(val)),
                        None,
                        None,
                    ],
                    ..
                } => {
                    let new_var_a = env.get_reg_var(reg_to_slot(reg_a), get_reg_type(reg_a), func.id, block.id, !func.bytecode.contains_key(pc), variables);
                    if let Some(Statement::TEST(var_a_id, var_b_id)) = func.bytecode.get(pc) {
                        let var_a = variables.get_var_mut(*var_a_id);
                        if new_var_a != *var_a_id {
                            var_a.phi.insert(new_var_a);
                        }

                        // env.last_cmp = Some((*var_a_id, *var_b_id));
                    } else {
                        let new_var_b = env.new_var_val(Type::I8, func.id, block.id, None, *val as i64, variables);

                        // env.last_cmp = Some((new_var_a, new_var_b));
                        func.bytecode.insert(*pc, Statement::TEST(new_var_a, new_var_b));
                    }
                }

                Instruction {
                    name: Instruction_Name::INC,
                    operands: [
                        Some(Instruction_Operand::REGISTER(reg_a)),
                        None,
                        None,
                        None,
                    ],
                    ..
                } => {
                    let new_var_a = env.get_reg_var(reg_to_slot(reg_a), get_reg_type(reg_a), func.id, block.id, !func.bytecode.contains_key(pc), variables);
                    if let Some(Statement::INC(dst_var_id, var_a_id)) = func.bytecode.get(pc) {
                        let var_a = variables.get_var_mut(*var_a_id);
                        if new_var_a != *var_a_id {
                            var_a.phi.insert(new_var_a);
                        }

                        env.set_reg_var(reg_to_slot(reg_a), *dst_var_id);
                    } else {
                        let dst_var = env.new_var(get_reg_type(reg_a), func.id, block.id, None, variables);
                        env.set_reg_var(reg_to_slot(reg_a), dst_var);
                        func.bytecode.insert(*pc, Statement::INC(dst_var, new_var_a));
                    }
                }

                Instruction {
                    name: Instruction_Name::MOV,
                    operands: [
                        Some(Instruction_Operand::REGISTER(reg_a)),
                        Some(Instruction_Operand::IMM_32(val)),
                        None,
                        None,
                    ],
                    ..
                } => {
                    if let Some(Statement::NOP_1(dst_var_id)) = func.bytecode.get(pc) {
                        env.set_reg_var(reg_to_slot(reg_a), *dst_var_id);
                    } else {
                        let dst_var = env.new_var_val(get_reg_type(reg_a), func.id, block.id, None, *val as i64, variables);
                        env.set_reg_var(reg_to_slot(reg_a), dst_var);
                        func.bytecode.insert(*pc, Statement::NOP_1(dst_var));
                    }
                }

                Instruction {
                    name: Instruction_Name::MOV,
                    operands: [
                        Some(Instruction_Operand::REGISTER(reg_a)),
                        Some(Instruction_Operand::REGISTER(reg_b)),
                        None,
                        None,
                    ],
                    ..
                } => {
                    let new_var_b = env.get_reg_var(reg_to_slot(reg_b), get_reg_type(reg_b), func.id, block.id, !func.bytecode.contains_key(pc), variables);
                    if let Some(Statement::NOP_1(src_var_id)) = func.bytecode.get(pc) {
                        let var_a = variables.get_var_mut(*src_var_id);
                        if new_var_b != *src_var_id {
                            var_a.phi.insert(new_var_b);
                        }

                        env.set_reg_var(reg_to_slot(reg_a), *src_var_id);
                    } else {
                        env.set_reg_var(reg_to_slot(reg_a), new_var_b);
                        func.bytecode.insert(*pc, Statement::NOP_1(new_var_b));
                    }
                }

                Instruction {
                    name: Instruction_Name::J_LE_NG,
                    operands: [
                        Some(Instruction_Operand::IMM_8(offset)),
                        None,
                        None,
                        None,
                    ],
                    ..
                } => {
                    let true_pc = *pc + (*offset as i64) + (inst.byte_len as i64);
                    let false_pc = *pc + (inst.byte_len as i64);

                    to_eval.insert(true_pc, (env.clone(), Vec::new()));
                    to_eval.insert(false_pc, (env.clone(), Vec::new()));

                    let true_block = blocks.blocks.get(&true_pc).unwrap().id;
                    let false_block = blocks.blocks.get(&false_pc).unwrap().id;

                    if func.bytecode.get(pc).is_none() {
                        func.bytecode.insert(*pc, 
                            Statement::JLE(Flags_JLE { 
                                zero_flag: env.get_reg_var(RegisterSlot::Flag_Zero, Type::I32, func.id, block.id, !func.bytecode.contains_key(pc), variables), 
                                sign_flag: env.get_reg_var(RegisterSlot::Flag_Sign, Type::I32, func.id, block.id, !func.bytecode.contains_key(pc), variables), 
                                overflow_flag: env.get_reg_var(RegisterSlot::Flag_Overflow, Type::I32, func.id, block.id, !func.bytecode.contains_key(pc), variables), 
                            }, true_block, false_block));
                    }

                    next_block_set = true;
                    break;
                }

                Instruction {
                    name: Instruction_Name::J_Z_E,
                    operands: [
                        Some(Instruction_Operand::IMM_8(offset)),
                        None,
                        None,
                        None,
                    ],
                    ..
                } => {
                    let true_pc = *pc + (*offset as i64) + (inst.byte_len as i64);
                    let false_pc = *pc + (inst.byte_len as i64);

                    to_eval.insert(true_pc, (env.clone(), Vec::new()));
                    to_eval.insert(false_pc, (env.clone(), Vec::new()));

                    let true_block = blocks.blocks.get(&true_pc).unwrap().id;
                    let false_block = blocks.blocks.get(&false_pc).unwrap().id;

                    if func.bytecode.get(pc).is_none() {
                        func.bytecode.insert(*pc, 
                            Statement::JZ(Flags_JZ { 
                                zero_flag: env.get_reg_var(RegisterSlot::Flag_Zero, Type::I32, func.id, block.id, !func.bytecode.contains_key(pc), variables), 
                            }, true_block, false_block));
                    }

                    next_block_set = true;
                    break;
                }

                Instruction {
                    name: Instruction_Name::J_NZ_NE,
                    operands: [
                        Some(Instruction_Operand::IMM_8(offset)),
                        None,
                        None,
                        None,
                    ],
                    ..
                } => {
                    let true_pc = *pc + (*offset as i64) + (inst.byte_len as i64);
                    let false_pc = *pc + (inst.byte_len as i64);

                    to_eval.insert(true_pc, (env.clone(), Vec::new()));
                    to_eval.insert(false_pc, (env.clone(), Vec::new()));

                    let true_block = blocks.blocks.get(&true_pc).unwrap().id;
                    let false_block = blocks.blocks.get(&false_pc).unwrap().id;

                    if func.bytecode.get(pc).is_none() {
                        func.bytecode.insert(*pc, 
                            Statement::JNZ(Flags_JNZ { 
                                zero_flag: env.get_reg_var(RegisterSlot::Flag_Zero, Type::I32, func.id, block.id, !func.bytecode.contains_key(pc), variables), 
                            }, true_block, false_block));
                    }

                    next_block_set = true;
                    break;
                }

                Instruction {
                    name: Instruction_Name::J_L_NGE,
                    operands: [
                        Some(Instruction_Operand::IMM_8(offset)),
                        None,
                        None,
                        None,
                    ],
                    ..
                } => {
                    let true_pc = *pc + (*offset as i64) + (inst.byte_len as i64);
                    let false_pc = *pc + (inst.byte_len as i64);

                    to_eval.insert(true_pc, (env.clone(), Vec::new()));
                    to_eval.insert(false_pc, (env.clone(), Vec::new()));

                    let true_block = blocks.blocks.get(&true_pc).unwrap().id;
                    let false_block = blocks.blocks.get(&false_pc).unwrap().id;

                    if func.bytecode.get(pc).is_none() {
                        func.bytecode.insert(*pc, Statement::JL(Flags_JL { 
                            sign_flag: env.get_reg_var(RegisterSlot::Flag_Sign, Type::I32, func.id, block.id, !func.bytecode.contains_key(pc), variables), 
                            overflow_flag: env.get_reg_var(RegisterSlot::Flag_Overflow, Type::I32, func.id, block.id, !func.bytecode.contains_key(pc), variables), 
                        }, true_block, false_block));
                    }

                    next_block_set = true;
                    break;
                }

                _ => {}
            }
        }

        if !next_block_set {
            to_eval.insert(block.end, (env.clone(), Vec::new()));
        }
    }

    return func;
}