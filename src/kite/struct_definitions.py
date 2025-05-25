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

class Dirent:
    @staticmethod
    def pack(inode, type, name):
        name = bytes(name, 'utf-8') + b'\x00'
        if len(name) % 2 == 0:
            name += b'\x00'
        res = (inode & 0xffff).to_bytes(2, 'little')
        reclen = 2 + 2 + 2 + 1 + len(name)
        res += reclen.to_bytes(2, 'little')
        res += len(name).to_bytes(2, 'little')
        res += type.to_bytes(1, 'little')
        res += name
        return res
