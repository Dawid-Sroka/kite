.section .text
.global execve
execve:
    addi    a7, zero, 59
    ecall
    ret
