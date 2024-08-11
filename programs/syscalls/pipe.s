.section .text
.global pipe
pipe:
    addi    a7, zero, 22
    ecall
    ret
