section .bss
    buff resb 1024

section .data
section .text
    global _start

_start:
    pushf

exit:
     ;;; exit
    mov eax, 60
    ; code
    mov edi, 0
    syscall
