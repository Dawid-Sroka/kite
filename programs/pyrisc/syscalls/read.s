.section .text
.global read
read:
    addi    a7, zero, 3
    ecall
    ret
