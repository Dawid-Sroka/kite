from kite.kernel import Kernel
from pathlib import Path
import logging
import typer

app = typer.Typer(pretty_exceptions_enable=False)

@app.command()
def main(path_to_binary: Path, debug: bool = False):
    handlers = [logging.FileHandler('logfile.log', mode='w')]
    if debug:
        handlers.append(logging.StreamHandler())
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=handlers
    )

    kernel = Kernel.create()
    kernel.start(path_to_binary)

app()
