# ArchBreaker

The goal for this project is to write my own x86 disassembler and decompiler. The long term goal is to make a decompiler that is more capable of propagating information across function boundaries. This is aimed to be achieved with an SSA bytecode that expresses the mutability of variables with new aliases. The next long term goal is to support runtime debugging. I have found that the debuggers in IDA and Ghidra are severely lacking when trying to debug a large reverse engineered project.

## What I have accomplished so far

This project is immense in scope and actively being worked on in my non-existent free time. It is nowhere near complete.
- I have written a complete x86 disassembler which supports AVX instructions and floating point instructions.
- I have parsed a Windows executable to parse out the segments.
- Converted the instructions into an SSA bytecode which uses phi nodes to handle mutability and variable scope across simple blocks of code. 

## What I am working on now
- Recovering control flow. Essentially, I need to identify the conditionals and loops of the program.
- Propagate varaible aliases to the phi nodes based on the control flow.
- This will be done by creating a virtual environment (a virtual representation of the stack and registers) for every branch of the code. Yes, this will be computationally intensive. But I believe this is possible on modern hardware. Moreover, I do think this would be possible to achieve in mass-parallel on a GPU one day

## Privacy / Legal Note

For now, I am only leaving the disassembler in the public repo. 
