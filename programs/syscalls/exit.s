.section .text
.global _exit
_exit:
    addi    a7, zero, 1
    ecall
