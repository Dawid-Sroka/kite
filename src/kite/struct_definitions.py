import struct
import termios
from kite.consts import USHORT
import os

class UContext:
    FORMAT = "Q Q I 24s 35Q 33Q 64s"
    SIZE = 656

    @staticmethod
    def pack(gregs, fregs):
        return struct.pack(
            UContext.FORMAT,
            0,
            0,
            0,
            bytes(24),
            *gregs,
            *fregs,
            bytes(64)
        )

    @staticmethod
    def unpack(binary_data):
        unpacked_data = struct.unpack(UContext.FORMAT, binary_data)
        return {
            "gregs": unpacked_data[4:39],
            "fregs": unpacked_data[39:72],
        }

class Sigaction:
    FORMAT = "Q I I"
    SIZE = 16

    @staticmethod
    def pack(handler, mask, flags):
        return struct.pack(
            Sigaction.FORMAT,
            handler,
            mask,
            flags
        )

    @staticmethod
    def unpack(binary_data):
        unpacked_data = struct.unpack(Sigaction.FORMAT, binary_data)
        return {
            "handler": unpacked_data[0],
            "mask": unpacked_data[1],
            "flags": unpacked_data[2],
        }

class Stat:
    FORMAT = 'HHIHIIHI16s16s16s4sII'
    SIZE = 88

    @staticmethod
    def pack(stat_info):
        return struct.pack(
            Stat.FORMAT,
            USHORT(stat_info.st_dev),
            0,
            stat_info.st_mode,
            USHORT(stat_info.st_nlink),
            stat_info.st_uid,
            stat_info.st_gid,
            USHORT(stat_info.st_rdev),
            stat_info.st_size,
            bytes(16),
            bytes(16),
            bytes(20),
            bytes(4), # padding
            stat_info.st_blksize,
            stat_info.st_blocks
        )

    @staticmethod
    def unpack(binary_data):
        raise NotImplementedError("unpacking struct stract is not supported")

class Termios:
    FORMAT = "I I I I 20s I I"
    SIZE = 44

    @staticmethod
    def pack(icanon, isig, echo):
        lflags = 0
        if icanon:
            lflags |= 0x100
        if isig:
            lflags |= 0x80
        if echo:
            lflags |= 0x8
        return struct.pack(
            Termios.FORMAT,
            25862,
            5,
            191,
            lflags,
            b'\x04\x00\x00\x7f\x17\x15\x00\x00\x03\x1c\x1a\x00\x11\x13\x16\x0f\x01\x00\x12\x00',
            15,
            15
        )

    @staticmethod
    def unpack(binary_data):
        unpacked_data = struct.unpack(Termios.FORMAT, binary_data)
        lflags = unpacked_data[3]
        icanon = lflags & 0x100 != 0
        isig = lflags & 0x80 != 0
        echo = lflags & 0x8 != 0
        return icanon, isig, echo

NETBSD_TO_LINUX_O_FLAGS = {
    0x00000000: os.O_RDONLY,
    0x00000001: os.O_WRONLY,
    0x00000002: os.O_RDWR,

    0x00000004: os.O_NONBLOCK,
    0x00000008: os.O_APPEND,
    0x00000040: os.O_ASYNC,
    0x00000080: os.O_SYNC,
    0x00000100: os.O_NOFOLLOW,
    0x00000200: os.O_CREAT,
    0x00000400: os.O_TRUNC,
    0x00000800: os.O_EXCL,
    0x00001000: os.O_DIRECTORY,
    0x00002000: os.O_CLOEXEC,
    0x00008000: os.O_DIRECT,
    0x00010000: os.O_DSYNC,
    0x00020000: os.O_RSYNC,
    0x00040000: os.O_NOCTTY,
}

# Reverse map for Linux -> NetBSD
LINUX_TO_NETBSD_O_FLAGS = {v: k for k, v in NETBSD_TO_LINUX_O_FLAGS.items()}

def convert_o_flags_netbsd_to_linux(netbsd_flags: int) -> int:
    linux_flags = 0
    for netbsd_val, linux_val in NETBSD_TO_LINUX_O_FLAGS.items():
        if (netbsd_flags & netbsd_val) == netbsd_val:
            linux_flags |= linux_val
    return linux_flags

def convert_o_flags_linux_to_netbsd(linux_flags: int) -> int:
    netbsd_flags = 0
    for linux_val, netbsd_val in LINUX_TO_NETBSD_O_FLAGS.items():
        if (linux_flags & linux_val) == linux_val:
            netbsd_flags |= netbsd_val
    return netbsd_flags
