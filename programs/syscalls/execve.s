.section .text
.global execve
execve:
    addi    a7, zero, 28
    ecall
    ret
