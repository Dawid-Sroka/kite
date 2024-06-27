from kite.kernel import Kernel
from pathlib import Path

from sys import argv

kernel = Kernel.create()

if len(argv) > 1:
    program_name = argv[1]
else:
    program_name = "simply_exit"

kernel.start(Path(__file__).parents[2] / "binaries" / program_name)
