from kite.kernel import Kernel
from pathlib import Path
import logging
import typer

app = typer.Typer(pretty_exceptions_enable=False)

@app.command()
def main(path_to_binary: Path, debug: bool = False):
    kernel = Kernel.create()

    class ContextFilter(logging.Filter):
        """
        This filter injects cpu simulator's cycle count into the log.
        """
        def filter(self, record):
            record.cycles_count = kernel.simulator.cpu.clock.cycles
            pc = kernel.simulator.cpu.pc.r
            record.pc = hex(pc) if pc > 0 else "before run"
            return True

    handlers = [logging.FileHandler('kernel.log', mode='w')]
    if debug:
        handlers.append(logging.StreamHandler(sys.stderr))
    logging.basicConfig(
        level=logging.INFO,
        format='%(pc)s - %(cycles_count)s - %(message)s',
        handlers=handlers
    )

    logging.getLogger().addFilter(ContextFilter())

    kernel.start(path_to_binary)

app()
