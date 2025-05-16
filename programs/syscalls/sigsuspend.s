.section .text
.global sigsuspend
sigsuspend:
    addi    a7, zero, 55
    ecall
    ret
