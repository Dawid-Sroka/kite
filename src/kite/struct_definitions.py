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
