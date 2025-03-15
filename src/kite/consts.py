#==========================================================================
#
#   The kite Project
#
#   Constant definitions
#
#==========================================================================


import numpy as np
from abc import ABC

# --------------------------------------------------------------------------
#   Program: loads an ELF file into memory and supports disassembling
# --------------------------------------------------------------------------

ELF_OK              = 0
ELF_ERR_OPEN        = 1
ELF_ERR_CLASS       = 2
ELF_ERR_DATA        = 3
ELF_ERR_TYPE        = 4
ELF_ERR_MACH        = 5

ELF_ERR_MSG = {
    ELF_ERR_OPEN    : 'File %s not found',
    ELF_ERR_CLASS   : 'File %s is not a 32-bit ELF file',
    ELF_ERR_DATA    : 'File %s is not a little-endian ELF file',
    ELF_ERR_TYPE    : 'File %s is not an executable file',
    ELF_ERR_MACH    : 'File %s is not an RISC-V executable file',
}

# Register aliases:

# The order of registers is based on mcontext_t from ucontext_t,
# Changing these values will break setcontext/getcontext syscall
REG_RA = 0
REG_SP = 1
REG_GP = 2
REG_TP = 3
REG_T0 = 4
REG_T1 = 5
REG_T2 = 6
REG_S0 = 7
REG_S1 = 8
REG_A0 = 9
REG_A1 = 10
REG_A2 = 11
REG_A3 = 12
REG_A4 = 13
REG_A5 = 14
REG_A6 = 15
REG_A7 = 16
REG_S2 = 17
REG_S3 = 18
REG_S4 = 19
REG_S5 = 20
REG_S6 = 21
REG_S7 = 22
REG_S8 = 23
REG_S9 = 24
REG_S10 = 25
REG_S11 = 26
REG_T3 = 27
REG_T4 = 28
REG_T5 = 29
REG_T6 = 30

REG_PC = 31
REG_SR = 32
REG_TVAL = 33
REG_CAUSE = 34

REG_RV = REG_A0

RA                      = REG_RA
SP                      = REG_SP

REG_SYSCALL_ARG0        = REG_A0
REG_SYSCALL_ARG1        = REG_A1
REG_SYSCALL_ARG2        = REG_A2
REG_SYSCALL_ARG3        = REG_A3
REG_SYSCALL_ARG4        = REG_A4
REG_SYSCALL_ARG5        = REG_A5

REG_SYSCALL_NUMBER      = REG_A7

REG_RET_VAL1            = REG_A0
REG_RET_VAL2            = REG_A1

# signal handlers will jump to this address when returning
SIGNAL_RETURN_ADDRESS = 0x100

#--------------------------------------------------------------------------
#   Data types
#--------------------------------------------------------------------------

WORD                = np.uint32
SWORD               = np.int32

INT_SIZE = 4

INT = np.int32
LONG = lambda x: np.int64(np.uint64(x))
USHORT = np.uint16

#--------------------------------------------------------------------------
#   RISC-V constants
#--------------------------------------------------------------------------

WORD_SIZE           = 4
NUM_REGS            = 32

BUBBLE              = WORD(0x00004033)      # Machine-generated NOP:  xor x0, x0, x0
NOP                 = WORD(0x00000013)      # Software-generated NOP: addi zero, zero, 0
ILLEGAL             = WORD(0xffffffff)

OP_MASK             = WORD(0x0000007f)
OP_SHIFT            = 0
RD_MASK             = WORD(0x00000f80)
RD_SHIFT            = 7
FUNCT3_MASK         = WORD(0x00007000)
FUNCT3_SHIFT        = 12
RS1_MASK            = WORD(0x000f8000)
RS1_SHIFT           = 15
RS2_MASK            = WORD(0x01f00000)
RS2_SHIFT           = 20
FUNCT7_MASK         = WORD(0xfe000000)
FUNCT7_SHIFT        = 25


#--------------------------------------------------------------------------
#   Memory control signals
#--------------------------------------------------------------------------

M_XRD               = 0
M_XWR               = 1


#--------------------------------------------------------------------------
#   ISA table index
#--------------------------------------------------------------------------

IN_NAME             = 0
IN_MASK             = 1
IN_TYPE             = 2
IN_CLASS            = 3
IN_ALU1             = 4
IN_ALU2             = 5
IN_OP               = 6
IN_MT               = 7


#--------------------------------------------------------------------------
#   ISA table[IN_TYPE]: Instruction types for disassembling
#--------------------------------------------------------------------------

R_TYPE              = 0
I_TYPE              = 1
IL_TYPE             = 2     # I_TYPE, but load instruction
IJ_TYPE             = 3     # I_TYPE, but jalr instruction
IS_TYPE             = 4     # I_TYPE, but shift instructions
U_TYPE              = 5
S_TYPE              = 6
B_TYPE              = 7
J_TYPE              = 8
X_TYPE              = 9


#--------------------------------------------------------------------------
#   ISA table[IN_CLASS]: Instruction classes for collecting stats
#--------------------------------------------------------------------------

CL_ALU              = 0
CL_MEM              = 1
CL_CTRL             = 2


#--------------------------------------------------------------------------
#   ISA table[IN_ALU1]: ALU operand select 1
#--------------------------------------------------------------------------

OP1_X               = 0
OP1_RS1             = 1
OP1_PC              = 2


#--------------------------------------------------------------------------
#   ISA table[IN_ALU2]: ALU operand select 2
#--------------------------------------------------------------------------

OP2_X               = 0
OP2_RS2             = 1
OP2_IMI             = 2
OP2_IMS             = 3
OP2_IMU             = 4
OP2_IMJ             = 5
OP2_IMB             = 6


#--------------------------------------------------------------------------
#   ISA table[IN_OP]: ALU and memory operation control
#--------------------------------------------------------------------------

ALU_X               = 0
ALU_ADD             = 1
ALU_SUB             = 2
ALU_SLL             = 3
ALU_SRL             = 4
ALU_SRA             = 5
ALU_AND             = 6
ALU_OR              = 7
ALU_XOR             = 8
ALU_SLT             = 9
ALU_SLTU            = 10
MEM_LD              = 11
MEM_ST              = 12


#--------------------------------------------------------------------------
#   ISA table[IN_MT]: Memory operation type
#--------------------------------------------------------------------------

MT_X                = 0
MT_B                = 1
MT_H                = 2
MT_W                = 3
MT_D                = 4
MT_BU               = 5
MT_HU               = 6
MT_WU               = 7


#--------------------------------------------------------------------------
#   Exceptions
#--------------------------------------------------------------------------

EXC_NONE            = 0         # EXC_NONE should be zero
EXC_PAGE_FAULT_MISS = 1
EXC_PAGE_FAULT_PERMS= 2
EXC_ILLEGAL_INST    = 4
EXC_EBREAK          = 8
EXC_ECALL           = 16        ## ? takie są exception codes na riscv?
EXC_CLOCK           = 32        ## przerwanie zegarowe

EXC_MSG = {
                    EXC_PAGE_FAULT_MISS: "page fault - page not present",
                    EXC_PAGE_FAULT_PERMS: "page fault - permissions error",
                    EXC_ILLEGAL_INST:   "illegal instruction",
                    EXC_EBREAK:         "ebreak",
                    EXC_ECALL:          "syscall",
                    EXC_CLOCK:          "clock interrupt",
}

#--------------------------------------------------------------------------
#   ABI
#--------------------------------------------------------------------------

syscall_names = {
                1: "exit",
                2:  "open",
                3:  "read",
                4:  "write",
                5:  "openat",
                6:  "close",
                11: "fstat",
                12: "sbrk",
                13: "mmap",
                18: "sigaction",
                22: "pipe",
                26: "clock_gettime",
                37: "sigaltstack",
                38: "sigprocmask",
                39: "setcontext",
                40: "ioctl",
                45: "issetugid",
                49: "readlinkat",
                57: "fork",
                59: "execve",
                100: "debug print",
                247: "wait"
                }

class Event(ABC):
    def __init__(self, exception_type: int):
        self.type = exception_type

class MemEvent(Event):
    def __init__(self, exception_type: int, fault_addr: int, fault_pc: int):
        super().__init__(exception_type)
        self.fault_addr = fault_addr
        self.fault_pc = fault_pc

VPO_LENTGH = 12
PAGE_SIZE = 2 ** VPO_LENTGH
VPO_MASK = 2**VPO_LENTGH - 1
VPN_MASK = 2**32 - 1 - VPO_MASK

MMAP_SEGMENTS_RANGE_START = 0x300000000000
MMAP_SEGMENTS_RANGE_END = 0x400000000000
