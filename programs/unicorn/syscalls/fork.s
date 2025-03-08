.section .text
.global fork
fork:
    addi    a7, zero, 57
    ecall
    ret
