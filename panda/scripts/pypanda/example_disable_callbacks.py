from pypanda import *
from time import sleep
from sys import argv

panda = Panda(qcow=argv[1])

@panda.callback.init
def init(handle):
	progress("init in python. handle="+str(handle))
	panda.register_callback(handle, panda.callback.before_block_exec, before_block_execute)
	panda.register_callback(handle, panda.callback.after_block_exec, after_block_execute)
	return True

count = 0

@panda.callback.before_block_exec
def before_block_execute(cpustate,transblock):
	global count
	if count < 9:
		progress("before block in python %d" %count)
	if count == 2:
		panda.disable_callback(panda.callback.after_block_exec)
	if count == 4:
		panda.enable_callback(panda.callback.after_block_exec)
	count+=1
	return 0

@panda.callback.after_block_exec
def after_block_execute(cpustate,transblock):
	global count
	if count < 9:
		progress("after block in python %d" % count)
	return 0

panda.load_python_plugin(init,"Disable Callbacks")
panda.run()
