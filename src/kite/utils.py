from kite.consts import PAGE_SIZE

def round_up_to_2(n):
    if n & 1 == 1:
        return n + 1
    return 1

def round_down_to_page_size(size):
    return size & ~(PAGE_SIZE - 1)

def round_up_to_page_size(size):
    return (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
