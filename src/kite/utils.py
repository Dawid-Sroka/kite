from kite.consts import PAGE_SIZE

def round_up_to_page_size(size):
    return (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
