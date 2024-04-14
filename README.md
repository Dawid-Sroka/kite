# Welcome to Kite - a floating kernel

Kite is a Python program that implements the functionality of a unix kernel. It manages the userspace processes, which are binary programs executed on a CPU simulator.

The purpose of this project is for education and research.

The motivation for this project is to give us a high-level, conceptual look at what OS kernel actually does. It allows us to forget that the kernel is also a binary program, that must somehow take care of itself. We can instead focus on how the control flow in the operating system looks like. What happens when the userspace process calls the kernel? How the control is given back to the process?

# Installation

`kite` project consists of kite source code and a `pyrisc` submodule - a cpu simulator source code. Clone the repo recursively:
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
Now you are ready to run the kernel:
```
cd src/kite
python __main__.py
```
or:
```
cd src/kite
python -m kite
```
This runs the kernel which loads the program specified in `__main__.py` and executes it as the first userspace program.
