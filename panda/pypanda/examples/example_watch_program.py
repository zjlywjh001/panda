#!/usr/bin/env python3
'''
example_watch_program.py

This example allows us to debug a specific program by name.

Run with: python3 example_watch_program.py

'''
from pypanda import *
from time import sleep
from sys import argv

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

@panda.cb_before_block_exec(procname="wget")
def before_block_execute(cpustate,transblock):
	progress("Called before block exec")	
	return 0

panda.run()
