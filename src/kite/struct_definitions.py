import struct

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
