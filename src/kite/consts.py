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

INT_SIZE = 4

ULONG = np.uint64
LONG = lambda x: np.int64(np.uint64(x))

UINT = lambda x: np.uint32(x & 0xffffffff)
INT = lambda x: np.int32(np.uint32(x & 0xffffffff))

USHORT = lambda x: np.uint16(x & 0xffff)
SHORT = lambda x: np.int16(x & 0xffff)

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
                2:  "fork",
                3:  "read",
                4:  "write",
                5:  "openat",
                6:  "close",
                7:  "lseek",
                9:  "getpid",
                10: "kill",
                11: "fstat",
                12: "sbrk",
                13: "mmap",
                15: "getdents",
                16: "dup",
                17: "dup2",
                18: "sigaction",
                20: "wait4",
                23: "faccessat",
                24: "fstatat",
                25: "pipe2",
                26: "clock_gettime",
                28: "execve",
                29: "getppid",
                30: "setpgid",
                31: "getpgid",
                32: "umask",
                35: "chdir",
                36: "getcwd",
                37: "sigaltstack",
                38: "sigprocmask",
                39: "setcontext",
                40: "ioctl",
                41: "getresuid",
                42: "getresgid",
                45: "issetugid",
                46: "fcntl",
                49: "readlinkat",
                55: "sigsuspend",
                59: "setgroups",
                60: "setsid",
                64: "setuid",
                67: "setgid",
                81: "setitimer",
                86: "sigtimedwait",
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

STACK_32_BIT_TOP = 0xffff0000
STACK_32_BIT_SIZE = 64*1024

STACK_64_BIT_TOP = 0x7fffff7ff000
STACK_64_BIT_SIZE = 8*1024*1024

# openat
AT_FDCWD = -100
O_CREAT = 0x200

# wait4
WNOHANG = 1
WUNTRACED = 2

# fcntl
F_DUPFD = 0
F_GETFL = 3
F_SETFD = 2

# ioctl
TIOCGPGRP = 0x40047477
TIOCSPGRP = 0x80047476
TIOCGETA = 0x402c7413
TIOCSETAW = 0x802c7415
TIOCSETAF = 0x802c7416
