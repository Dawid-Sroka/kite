from kite.kernel import Kernel
from pathlib import Path
from sys import stderr
import logging
import typer
from typing import List

from kite.simulators.pyrisc import PyRISCSimulator
from kite.simulators.unicorn import UnicornSimulator

from kite.consts import REG_PC
from unicorn.riscv_const import *

app = typer.Typer(pretty_exceptions_enable=False)

@app.command()
def main(path_to_binary: List[str], log_to_stdout: bool = False, simulator: str = "unicorn", debug: bool = False):
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
            process = kernel.current_process
            pc = process.cpu_context.reg_read(REG_PC) if process else -1
            record.pc = hex(pc) if pc > 0 else "before run"
            record.pid = process.pid if process else "-"
            return True

    handlers = [logging.FileHandler('kernel.log', mode='w')]
    if log_to_stdout:
        handlers.append(logging.StreamHandler(stderr))
    logging.basicConfig(
        level=logging.INFO,
        format='[%(pid)s] %(pc)s - %(message)s',
        handlers=handlers
    )

    logging.getLogger().addFilter(ContextFilter())

    if debug:
        if simulator != "unicorn":
            raise NotImplementedError("Launching GDB server is only supported for unicorn")
        simulator_obj.launch_gdb_server()

    kernel.start(path_to_binary)

app()
