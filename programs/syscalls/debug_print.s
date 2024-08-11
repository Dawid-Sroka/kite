.section .text
.global debug_print
debug_print:
    addi    a7, zero, 100
    ecall
    ret
