#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(unused_imports)]

mod windows_exe;
use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;
use std::cell::RefCell;

use windows_exe::*;

mod disassemble;
use disassemble::*;

mod decompile;
use decompile::*;

mod registers;
use registers::*;

mod util;
use util::*;

mod one_byte_opcode;
use one_byte_opcode::*;


fn main() -> std::io::Result<()>
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


    //*********** LINUX ELF FILE ***********//
    // let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // d.push("res/test_source");

    // let file_data = fs::read(d).unwrap();
    // let mut file_reader = MyReader 
    // {
    //     buff: &file_data,
    //     cursor: 0,
    // };

    // assert_eq!(file_reader.take_bytes(4).unwrap(), [0x7F, 0x45, 0x4c, 0x46]);

    // let meta = parse_elf_header(&mut file_reader).unwrap();
    // println!("{:?}", meta);

    // let mut section_headers = Vec::<SectionHeader>::new();
    // for i in 0..meta.section_header_table_entry_count
    // {
    //     section_headers.push(parse_elf_section_header(&mut file_reader, meta.section_header_table_off + (i * meta.section_header_table_entry_len), meta.inst_mode).unwrap());
    //     println!("{:?}", section_headers[section_headers.len() - 1]);
    // }

    // let mut segment_headers = Vec::<SegmentHeader>::new();
    // for i in 0..meta.segment_header_table_entry_count
    // {
    //     segment_headers.push(parse_elf_segment_header(&mut file_reader, meta.segment_header_table_off + (i * meta.segment_header_table_entry_len), meta.inst_mode).unwrap());
    //     println!("{:?}", segment_headers[segment_headers.len() - 1]);
    // }

    // let str_table = &section_headers[meta.section_header_table_name_idx];
    // for section_idx in 0..meta.section_header_table_entry_count
    // {
    //     if section_idx == meta.section_header_table_name_idx
    //     {
    //         continue;
    //     }

    //     let name = read_string_from_table(&mut file_reader, str_table.section_off, section_headers[section_idx].name_off);
    //     println!("Name: {}", name);

    //     if name == ".text"
    //     {
    //         let mut inst_reader = MyReader
    //         {
    //             buff: &file_data[section_headers[section_idx].section_off..section_headers[section_idx].section_off + section_headers[section_idx].section_size],
    //             cursor: 0,
    //         };

    //         loop
    //         {
    //             let inst = read_inst(meta.inst_mode, &mut inst_reader);
    //             if inst.is_ok()
    //             {
    //                 println!("{} {:?}", inst_reader.cursor, inst);
    //             } else {
    //                 break;
    //             }
    //         }
    //     }
    // }

    //*********** WINDOWS PE FILE ***********//
    // let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // d.push("res/test.exe");

    // let (exe, mut reader) = parse_windows_exe("C:\\Users\\samse\\source\\repos\\TestBinary\\Release\\TestBinary.exe".into()).unwrap();
    let (exe, mut reader) = parse_windows_exe("C:\\Users\\samse\\source\\repos\\TestBinary3\\Release\\TestBinary3.exe".into()).unwrap();

    let text_section = exe.section_headers.get(TEXT_SECTION).unwrap();

    println!("{:#x?}", exe.optional_header.entry_point_offset);

    // TODO: actually get the entry point by analyzing scrt_common_main
    reader.seek((text_section.data_offset) as usize)?;
    let mut insts =  BTreeMap::new();
    while reader.cursor < (text_section.data_offset + text_section.data_length) as usize {
        let pos = reader.cursor;
        let inst = read_inst(InstMode::x32, &mut reader);
        if let Ok(inst) = inst {
            // if inst.name == Instruction_Name::far_Ret || inst.name == Instruction_Name::near_Ret {
                insts.insert(pos as i64, inst);
            //     break;
            // } else {
            //     insts.insert(pos as u32, inst);
            // }
        } else {
            reader.seek(pos)?;
            reader.take_byte()?;
        }
    }

    // for (pc, inst) in insts.iter() {
    //     println!("{:?}", inst);
    // }


    let program = 
        Program {
            insts,
            text_offset: text_section.data_offset as i64,
        };

    let pass1_blocks = pass_1_identify_blocks(
        &program,
        text_section.data_offset as i64 + 0x40,
        // text_section.data_offset as i64 + 0x30,
        // &mut pass1_funcs,
    );

    println!("{:x?}", pass1_blocks);
    use std::ops::Bound::Included;
    use std::ops::Bound::Excluded;
    for (pc, inst) in program.insts.range((Included((text_section.data_offset as i64 + 0x40)), Excluded(pass1_blocks.blocks.iter().rev().next().unwrap().1.end))) {
        println!("{:x?}", inst);
    }

    let mut pass_3_vars = Pass3_VariableRegistry::default();
    let func = pass_3_generate_virtual_env_cmds(&program, &pass1_blocks, &mut pass_3_vars);

    for (_, block) in &pass1_blocks.blocks {
        println!("-------------------");
        println!("Block_{:x}:", block.id);
        println!("Variables:");

        if let Some(vars) = pass_3_vars.block_vars.get(&block.id) {
            for var_id in vars {
                println!("ID: {:x}", var_id);
                println!("{:#x?}", pass_3_vars.get_var(*var_id));
                println!();
            }
        }

        println!("Code:");
        for (pc, statement) in func.bytecode.range((
            Included(block.entry), 
            Excluded(block.end))
        ) {
            println!("{:#x?}", statement);
        }
        
        println!();
    }
    
    println!("------------------------------------------------");
    for (_, block) in &pass1_blocks.blocks {
        println!("-------------------");
        println!("Block_{:x}:", block.id);

        if let Some(vars) = pass_3_vars.block_vars.get(&block.id) {
            let mut any_phi = false;
            for var_id in vars {
                let var = pass_3_vars.get_var(*var_id);
                if var.phi.len() > 0 {
                    any_phi = true;

                    print!("\tint var_{:x} = phi(", var_id);
                    let mut count = 0;
                    for phi_var_id in &var.phi {
                        if count == var.phi.len() - 1 {
                            println!("var_{:x});", phi_var_id);
                        } else {
                            print!("var_{:x}, ", phi_var_id);
                        }

                        count += 1;
                    }
                }
            }

            if any_phi {
                println!();
            }
        }

        if let Some(vars) = pass_3_vars.block_vars.get(&block.id) {
            let mut any_vals = false;
            for var_id in vars {
                let var = pass_3_vars.get_var(*var_id);
                if var.val.is_some() {
                    any_vals = true;

                    println!("\tint var_{:x} = {};", var_id, var.val.unwrap());
                }
            }

            if any_vals {
                println!();
            }
        }

        // println!("Code:");
        for (pc, statement) in func.bytecode.range((
            Included(block.entry), 
            Excluded(block.end))
        ) {
            match statement {
                // Statement::SET(var_id, value) => {
                //     println!("\tint var_{} = {};", var_id, value);
                // }
                Statement::ADD(dst_var_id, var_a_id, var_b_id) => {
                    println!("\tint var_{:x} = var_{:x} + var_{:x};", dst_var_id, var_a_id, var_b_id);
                }
                Statement::MUL(dst_var_id, var_a_id, var_b_id) => {
                    println!("\tint var_{:x} = var_{:x} * var_{:x};", dst_var_id, var_a_id, var_b_id);
                }
                Statement::SUB(dst_var_id, var_a_id, var_b_id) => {
                    println!("\tint var_{:x} = var_{:x} - var_{:x};", dst_var_id, var_a_id, var_b_id);
                }
                Statement::SHR(dst_var_id, var_a_id, var_b_id) => {
                    println!("\tint var_{:x} = var_{:x} >> var_{:x};", dst_var_id, var_a_id, var_b_id);
                }
                Statement::INC(dst_var_id, var_a_id) => {
                    println!("\tint var_{:x} = var_{:x} + 1;", dst_var_id, var_a_id);
                }
                Statement::RET => {
                    println!("\treturn;")
                }

                Statement::CMP(var_a_id, var_b_id) => {
                    println!("\tcmp(var_{:x}, var_{:x});", var_a_id, var_b_id);
                }

                Statement::TEST(var_a_id, var_b_id) => {
                    println!("\ttest(var_{:x}, var_{:x});", var_a_id, var_b_id);
                }

                Statement::JLE(block_true_id, block_false_id) => {
                    println!("\tjle(block_{:x}, block_{:x});", block_true_id, block_false_id);
                }

                Statement::JL(block_true_id, block_false_id) => {
                    println!("\tjl(block_{:x}, block_{:x});", block_true_id, block_false_id);
                }

                Statement::JZ(block_true_id, block_false_id) => {
                    println!("\tjz(block_{:x}, block_{:x});", block_true_id, block_false_id);
                }

                Statement::JNZ(block_true_id, block_false_id) => {
                    println!("\tjnz(block_{:x}, block_{:x});", block_true_id, block_false_id);
                }
                _ => {}
            }
        }
        
        println!();
    }


    // let mut function_registry = FunctionRegistry {
    //     funcs: BTreeMap::new(),
    //     next_func_id: 0,
    // };

    // let mut variable_registry = VariableRegistry {
    //     vars: Vec::new(),
    //     var_alias: HashMap::new(),
    // };

    // let function_registry_ptr = Rc::new(RefCell::new(function_registry));
    // let variable_registry_ptr = Rc::new(RefCell::new(variable_registry));
    
    // println!("-----------");
    // decompile(
    //     &Program {
    //         insts,
    //         text_offset: text_section.data_offset,
    //     }, 
    //     text_section.data_offset + 0x30,
    //     function_registry_ptr.clone(),
    //     variable_registry_ptr.clone(),
    // );

    // let variable_registry = variable_registry_ptr.borrow();
    // let function_registry = function_registry_ptr.borrow();

    // for (entry, func) in function_registry.funcs.iter().rev() {
    //     if func.returned_vars.len() == 0 {
    //         print!("void ");
    //     } else if func.returned_vars.len() == 1 {
    //         let var_id = func.returned_vars[0];
    //         let var = variable_registry.get_var(var_id);
    //         print!("int{}_t ", var.size_bytes * 8);
    //     } else {
    //         todo!("Handle multiple return values");
    //     }

    //     print!("func_{} (", func.id);
    //         for (ix, var_id) in func.passed_in_vars.iter().enumerate() {
    //             if ix != func.passed_in_vars.len() - 1 {
    //                 print!("int{}_t {}, ", 
    //                 variable_registry.get_var(*var_id).size_bytes * 8,
    //                 variable_registry.get_var(*var_id));
    //             } else {
    //                 print!("int{}_t {}", 
    //                 variable_registry.get_var(*var_id).size_bytes * 8,
    //                 variable_registry.get_var(*var_id));
    //             }
    //         }
    //     println!(") {{");

    //         for stmt in &func.bytecode {
    //             match stmt {
    //                 Statement::ADD(dst_var, var_a, var_b) => {
    //                     print!("\t");
    //                     println!("int{}_t {} = {} + {};",
    //                         variable_registry.get_var(*dst_var).size_bytes * 8,
    //                         variable_registry.get_var(*dst_var),
    //                         variable_registry.get_var(*var_a),
    //                         variable_registry.get_var(*var_b),
    //                     );
    //                 },

    //                 Statement::MUL(dst_var, var_a, var_b) => {
    //                     print!("\t");
    //                     println!("int{}_t {} = {} * {};",
    //                         variable_registry.get_var(*dst_var).size_bytes * 8,
    //                         variable_registry.get_var(*dst_var),
    //                         variable_registry.get_var(*var_a),
    //                         variable_registry.get_var(*var_b),
    //                     );
    //                 },

    //                 Statement::MOV(dst_var, _) => todo!(),

    //                 Statement::SET(dst_var, val) => {
    //                     print!("\t");
    //                     println!("int{}_t {} = {};",
    //                         variable_registry.get_var(*dst_var).size_bytes * 8,
    //                         variable_registry.get_var(*dst_var),
    //                         val
    //                     );
    //                 },

    //                 Statement::SHL(dst_var, src_var, val) => {
    //                     print!("\t");
    //                     println!("int{}_t {} = {} << {};",
    //                         variable_registry.get_var(*dst_var).size_bytes * 8,
    //                         variable_registry.get_var(*dst_var),
    //                         variable_registry.get_var(*src_var),
    //                         val,
    //                     );
    //                 },

    //                 Statement::DREF(dst_var, _) => todo!(),

    //                 Statement::CALL(func_id) => {
    //                     print!("\t");
    //                     let ret_vars = &function_registry.funcs.get(func_id).unwrap().returned_vars;
    //                     if ret_vars.len() == 1 {
    //                         let local_var = variable_registry.var_alias.get(&(func.id, *func_id, ret_vars[0])).unwrap();
    //                         print!("int{}_t {} = ",
    //                             variable_registry.get_var(ret_vars[0]).size_bytes * 8,
    //                             variable_registry.get_var(*local_var),
    //                         );
    //                     } else {
    //                         todo!("Handle multiple return values");
    //                     }

    //                     print!("func_{}(", func_id);
    //                     for (ix, called_input_var) in function_registry.funcs.get(func_id).unwrap().passed_in_vars.iter().enumerate() {
    //                         if ix != function_registry.funcs.get(func_id).unwrap().passed_in_vars.len() - 1 {
    //                             print!("{}, ", variable_registry.get_var(*variable_registry.var_alias.get(&(func.id, *func_id, *called_input_var)).unwrap()));
    //                         } else {
    //                             print!("{}", variable_registry.get_var(*variable_registry.var_alias.get(&(func.id, *func_id, *called_input_var)).unwrap()));
    //                         }
    //                     }
    //                     println!(");")
    //                 },

    //                 Statement::RET => {
    //                     print!("\treturn");
    //                         if func.returned_vars.len() == 0 {
    //                         } else if func.returned_vars.len() == 1 {
    //                             print!(" {}", variable_registry.get_var(func.returned_vars[0]));
    //                         } else {
    //                             todo!("Handle multiple return values");
    //                         }
    //                     println!(";")
    //                 }
    //             }
    //         }
    //     println!("}}\n");
    // }





    // while reader.cursor < (text_section.data_offset + text_section.data_length) as usize
    // {
    //     let pos = reader.cursor;
    //     let inst = read_inst(InstMode::x32, &mut reader);
    //     if inst.is_ok()
    //     {
    //         let end_pos = reader.cursor;
    //         print!("({:#x}): ", pos);

    //         reader.seek(pos)?;
    //         while reader.cursor != end_pos {
    //             print!("{:#x} ", reader.take_byte()?);
    //         }

    //         println!("");
    //         println!(" {} ", inst?);
    //         println!("");

    //         reader.seek(end_pos)?;
    //     } else {
    //         reader.seek(pos)?;
    //         println!("({:#x}): {:#x} (bad) -----------------------------------------------", pos, reader.take_byte()?);
    //         println!("");
    //     }
    // }

    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // Read in the bytes from a stream
    // let bytes = [0x49u8, 0x01, 0xc4, 0x20, 0xd8, 0x41, 0x30, 0xdc, 0x04, 0x0c, 0x48, 0x05, 0xb0, 0x04, 0x00, 0x00, 0x48, 0x89, 0xd8, 0x39, 0xc8, 0x48, 0x01, 0x18, 0x44, 0x00, 0x00, 0xe9, 0x01, 0x00, 000, 0x00, 0xb0, 0x01, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x48, 0xd1, 0xe8, 0xd1, 0xe8, 0x90, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb0, 0x01, 0xb0, 0x01, 0xc6, 0x03, 0x05, 0x48, 0xff, 0xc3, 0xff, 0xc3, 0xa8, 0x02, 0xd0, 0xe9, 0x49, 0xd1, 0xec, 0x48, 0xc7, 0x00, 0x05, 0x00, 0x00, 0x00, 0xc6, 0x00, 0x05, 0xc6, 0x40, 0x0c, 0x05, 0xc6, 0x04, 0xc0, 0x05, 0xc6, 0x04, 0xc5, 0x04, 0x00, 0x00, 0x00, 0x05, 0x67, 0xc6, 0x45, 0x00, 0x05, 0xff, 0x20, 0xff, 0x24, 0x25, 0x11, 0x11, 0x00, 0x00, 0x67, 0x48, 0xff, 0x28, 0x75, 0x00, 0x75, 0xfe, 0x68, 0x11, 0x11, 0x00, 0x00, 0x66, 0x41, 0x50, 0x41, 0x50, 0x50, 0x66, 0x50, 0x8f, 0x00, 0x66, 0x8f, 0x00];
    // let mut cursor = Cursor::new(bytes);
    // let mut reader = MyReader {
    //     buff: &bytes.to_vec(),
    //     cursor: 0,
    // };

    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));
    // println!("{:?}", read_inst(InstMode::x64, &mut reader));

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

    Ok(())
}
