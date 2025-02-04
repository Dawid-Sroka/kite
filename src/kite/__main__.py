from kite.kernel import Kernel
from pathlib import Path
from sys import stderr
import logging
import typer

from kite.simulators.pyrisc import PyRISCSimulator
from kite.simulators.unicorn import UnicornSimulator

from kite.consts import REG_PC
from unicorn.riscv_const import *

app = typer.Typer(pretty_exceptions_enable=False)

@app.command()
def main(path_to_binary: Path, debug: bool = False, simulator: str = "unicorn"):
    if simulator == "pyrisc":
        simulator_obj = PyRISCSimulator()
    elif simulator == "unicorn":
        simulator_obj = UnicornSimulator()
    else:
        raise NotImplementedError(f"{simulator}: simulator not supported")
    kernel = Kernel.create(simulator_obj)

    class ContextFilter(logging.Filter):
        """
        This filter injects cpu simulator's cycle count into the log.
        """
        def filter(self, record):
            pc = kernel.simulator.reg_read(REG_PC)
            record.pc = hex(pc) if pc > 0 else "before run"
            return True

    handlers = [logging.FileHandler('kernel.log', mode='w')]
    if debug:
        handlers.append(logging.StreamHandler(stderr))
    logging.basicConfig(
        level=logging.INFO,
        format='%(pc)s - %(message)s',
        handlers=handlers
    )

    logging.getLogger().addFilter(ContextFilter())

    kernel.start(path_to_binary)

app()
