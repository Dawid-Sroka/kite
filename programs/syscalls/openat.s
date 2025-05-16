.section .text
.global openat
openat:
    addi    a7, zero, 5
    ecall
    ret
