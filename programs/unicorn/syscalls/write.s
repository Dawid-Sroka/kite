.section .text
.global write
write:
    addi    a7, zero, 4
    ecall
    ret
