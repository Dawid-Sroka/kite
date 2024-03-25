# Welcome to Kite - a floating kernel

Kite is a Python program that implements the functionality of a unix kernel. It manages the userspace processes, which are binary programs executed on a CPU simulator.

The purpose of this project is for education and research.

The motivation for this project is to give us a high-level, conceptual look at what OS kernel actually does. It allows us to forget that the kernel is also a binary program, that must somehow take care of itself. We can instead focus on how the control flow in the operating system looks like. What happens when the userspace process calls the kernel? How the control is given back to the process?
