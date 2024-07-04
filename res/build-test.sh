#!/bin/bash

# nasm -g -f elf32 test.asm -o test.o
# ld -m elf_i386 test.o -o test

nasm -g -f elf64 test.asm -o test.o
ld test.o -o test
