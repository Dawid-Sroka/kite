from kite.kernel import Kernel
from pathlib import Path

# parse filename
# return init_program

kernel = Kernel.create()

kernel.start(Path(__file__).parents[2] / "binaries" / "simply_execve")
