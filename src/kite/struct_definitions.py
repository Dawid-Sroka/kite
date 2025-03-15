import struct

class UContext:
    UCONTEXT_FORMAT = "Q Q I 24s 35Q 33Q 64s"
    SIZE = 656

    @staticmethod
    def pack(gregs, fregs):
        return struct.pack(
            UContext.UCONTEXT_FORMAT,
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
        """Unpack binary data into the ucontext_t structure."""
        unpacked_data = struct.unpack(UContext.UCONTEXT_FORMAT, binary_data)
        return {
            "gregs": unpacked_data[4:39],
            "fregs": unpacked_data[39:72],
        }
