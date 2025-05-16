.section .text
.global fork
fork:
    addi    a7, zero, 2
    ecall
    ret
