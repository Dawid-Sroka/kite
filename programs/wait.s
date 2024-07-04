.section .text
.global wait
wait:
    addi    a7, zero, 247
    ecall
    ret
