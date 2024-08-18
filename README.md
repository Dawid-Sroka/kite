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

Kite can run binary user programs compiled for RISC-V. The `programs` directory contains example programs written in C and a minimal library. The `binaries` directory contains already compiled versions of these examples. To run one of them on kite execute:

```
python -u -m kite example_program
```
This launches Kite operating system and passes `example_program` as the first userspace program. The kernel logs are printed beginning with a `#`.
