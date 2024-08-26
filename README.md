# Welcome to Kite - a floating kernel

Kite is a Python program that implements the functionality of a unix kernel. It manages the userspace processes, which are binary programs executed on a CPU simulator.

The purpose of this project is for education and research.

The motivation for this project is to give us a high-level, conceptual look at what OS kernel actually does. It allows us to forget that the kernel is also a binary program, that must somehow take care of itself. We can instead focus on how the control flow in the operating system looks like. What happens when the userspace process calls the kernel? How the control is given back to the process?

# Installation

`kite` project consists of kite source code and a `pyrisc` submodule - a RISC-V cpu simulator. Clone the repo recursively:
```
git clone --recursive git@github.com:Dawid-Sroka/kite.git
```
`kite` and `pyrisc` are imported as python packages. To use them easily, create a virtual environment (venv) and enter it by sourcing.
```
python -m venv .venv
source YOUR_KITE_REPO_PATH/.venv/bin/activate
```
Then install the dependecies by running:
```
pip install -r requirements.txt
```

# Running Kite

Kite can run binary user programs compiled for RISC-V, by executing them on the [`pyrisc`](https://github.com/snu-csl/pyrisc) simulator. The `programs` directory contains example programs written in C and a minimal library. The `binaries` directory contains versions of these examples, already compiled for `pyrisc`. To run one of them on kite execute:

```
python -u -m kite path/to/example_program
```
This launches Kite operating system and passes `example_program` as the first userspace program.

The Kite kernel produes logs which are by default saved in file `kernel.log` (by overwriting the content, not appending). If you add the `--debug` option then Kite logs will be printed to `stderr` as well.
```
python -u -m kite path/to/example_program --debug
```

# Compiling userspace programs

Compiling userspace programs with the use of `riscv64-linux-gnu-gcc` package was tested on Arch linux. Download the compiler.
```
pacman -S riscv64-linux-gnu-gcc
```
Then you should be able to compile your own userspace programs using the Makefile provided in the project. Place your program in `programs` directory and specify its name (without the extension) as `PROG` variable. For example:
```
make PROG=simply_exit
```
This will compile file `simply_exit.c`, link it with the library provided in the project and produce an executable file named `simply_exit` in the `binaries` directory.

Alternatively, you can follow the compilation guide described in the `pyrisc` documentation. However, this requires building the compiler from sources.
