#!/usr/bin/env python3
'''
example_multiple_callbacks.py

This example registers the before_block_exec and after_block_exec callbacks and
prints a message and sleeps each time the callback is hit.

Run with: python3 example_multiple_callbacks.py
'''
from pypanda import *
from time import sleep
from sys import argv

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

@panda.cb_before_block_exec
def my_before_block_execute(cpustate,transblock):
	progress("before block in python")
	sleep(sleeptime)
	return 0

@panda.cb_after_block_exec
def my_after_block_execute(cpustate,transblock):
	progress("after block in python")
	sleep(sleeptime)
	return 0

sleeptime = 1
panda.run()
