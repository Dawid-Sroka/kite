from kite.kernel import Kernel
from pathlib import Path
import logging
from sys import argv

logging.basicConfig(
    level=logging.INFO,  # Set the logging level
    format='%(asctime)s - %(levelname)s - %(message)s',  # Log message format
    handlers=[
        logging.StreamHandler(),  # Log to stdout
        logging.FileHandler('logfile.log', mode='w')  # Log to file
    ]
)

kernel = Kernel.create()

if len(argv) > 1:
    program_name = argv[1]
else:
    program_name = "simply_exit"

kernel.start(Path(__file__).parents[2] / "binaries" / program_name)
