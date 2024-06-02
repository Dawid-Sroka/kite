.section .text
.global write
write:
    addi    a7, zero, 1
    ecall
    ret
