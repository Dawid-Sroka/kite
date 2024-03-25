from kite.kernel import Kernel

# parse filename
# return init_program

kernel = Kernel.create()

kernel.start("../../tests/prog")
