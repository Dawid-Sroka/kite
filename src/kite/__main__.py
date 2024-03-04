from kite.kernel import Kernel
from kite.simulator import Simulator

# parse filename
# return init_program

kernel = Kernel.create()

entry_point = kernel.load_process_from_file("../../../lib/prog")
print(entry_point)
