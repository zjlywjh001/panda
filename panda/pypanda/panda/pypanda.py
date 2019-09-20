import sys

if sys.version_info[0] < 3:
    print("Please run with Python 3!")
    sys.exit(0)

import socket
import threading

from os.path import join as pjoin
from os.path import realpath, exists, abspath, isfile

from os import dup, getenv, devnull, environ
from enum import Enum
from random import randint
from inspect import signature
from tempfile import NamedTemporaryFile

from .taint import TaintQuery

from .autogen.panda_datatypes import * # ffi comes from here
from .panda_expect import Expect
from .asyncthread import AsyncThread
from .images import qcows
from .plog import PLogReader
from .utils import progress, make_iso, debug

# Mixins to extend Panda class functionality
from .libpanda_mixins   import libpanda_mixins
from .blocking_mixins   import blocking_mixins
from .osi_mixins        import osi_mixins
from .hooking_mixins    import hooking_mixins
from .callback_mixins   import callback_mixins
from .taint_mixins      import taint_mixins

import pdb

# location of panda build dir
panda_build = realpath(pjoin(abspath(__file__), "../../../../build"))


# XXX REFACTOR MAIN LOOP WAIT STUFF

# main_loop_wait_cb is called at the start of the main cpu loop in qemu.
# This is a fairly safe place to call into qemu internals but watch out for deadlocks caused
# by your request blocking on the guest's execution

# Functions+args to call when we're next at the main loop. Callbacks to call when they're done
main_loop_wait_fnargs = []
main_loop_wait_cbargs = []


# At the start of the main cpu loop: run async_callbacks and main_loop_wait_fns
@pcb.main_loop_wait
def main_loop_wait_cb():
    # Then run any and all requested commands
    global main_loop_wait_fnargs
    global main_loop_wait_cbargs
    if len(main_loop_wait_fnargs) == 0: return
#    progress("Entering main_loop_wait_cb")
    for fnargs, cbargs in zip(main_loop_wait_fnargs, main_loop_wait_cbargs):
        (fn, args) = fnargs
        (cb, cb_args) = cbargs
        fnargs = (fn, args)
        #progress("main_loop_wait_stuff running : " + (str(fnargs)))
        ret = fn(*args)
        if cb:
            progress("running callback : " + (str(cbargs)))
            try:
                if len(cb_args): # Must take result when cb_args provided
                    cb(ret, *cb_args) # callback(result, cb_arg0, cb_arg1...). Note results may be None
                else:
                    if len(signature(cb).parameters) > 0:
                        f(ret)
                    else:
                        f()
            except Exception as e: # Catch it so we can keep going?
                print("CALLBACK {} RAISED EXCEPTION: {}".format(cb, e))
                raise e
    main_loop_wait_fnargs = []
    main_loop_wait_cbargs = []


class Panda(libpanda_mixins, blocking_mixins, osi_mixins, hooking_mixins, callback_mixins, taint_mixins):
    def __init__(self, arch="i386", mem="128M",
            expect_prompt = None, os_version="debian:3.2.0-4-686-pae",
            qcow="default", extra_args = "", os="linux", generic=None):
        self.arch = arch
        self.mem = mem
        self.os = os_version
        self.static_var = 0
        self.qcow = qcow

        if extra_args:
            extra_args = extra_args.split()
        else:
            extra_args = []

        # If specified use a generic (x86_64, i386, arm, ppc) qcow from moyix and ignore
        # other args. See details in qcows.py
        if generic:
            q = qcows.get_qcow_info(generic)
            self.arch     = q.arch
            self.os       = q.os
            self.qcow     = qcows.get_qcow(generic)
            expect_prompt = q.prompt
            if q.extra_args:
                extra_args.extend(q.extra_args.split(" "))

        if self.qcow is None:
            # this means we wont be using a qcow -- replay only presumably
            pass
        else:
            if self.qcow is "default":
                # this means we'll use arch / mem / os to find a qcow
                self.qcow = pjoin(getenv("HOME"), ".panda", "%s-%s-%s.qcow" % (self.os, self.arch, mem))
            if not (exists(self.qcow)):
                print("Missing qcow -- %s" % self.qcow)
                print("Please go create that qcow and give it to moyix!")


        self.bindir = pjoin(panda_build, "%s-softmmu" % self.arch)
        environ["PANDA_PLUGIN_DIR"] = self.bindir+"/panda/plugins"
        self.panda = pjoin(self.bindir, "qemu-system-%s" % self.arch)

        self.libpanda_path = pjoin(self.bindir,"libpanda-%s.so" % self.arch)
        self.libpanda = ffi.dlopen(self.libpanda_path)

        self.loaded_python = False

        if self.os:
            self.set_os_name(self.os)

        biospath = realpath(pjoin(self.panda,"..", "..",  "pc-bios"))
        bits = None
        endianness = None # String 'little' or 'big'
        if self.arch == "i386":
            bits = 32
            endianness = 'little'
        elif self.arch == "x86_64":
            bits = 64
            endianness = 'little'
        elif self.arch == "arm":
            bits = 32
        elif self.arch == "aarch64":
            bit = 64
        elif self.arch == "ppc":
            bits = 32

        assert (bits is not None), "For arch %s: I need logic to figure out num bits" % self.arch
        assert (endianness is not None), "For arch %s: I need logic to figure out endianness" % self.arch

        # set os string in line with osi plugin requirements e.g. "linux[-_]64[-_].+"
        self.os_string = "%s-%d-%s" % (os,bits,os_version)
        self.bits = bits
        self.endianness = endianness
        self.register_size = int(bits / 8)

        # note: weird that we need panda as 1st arg to lib fn to init?
        self.panda_args = [self.panda, "-m", self.mem, "-display", "none", "-L", biospath, "-os", self.os_string, self.qcow]
        self.panda_args.extend(extra_args)

        # The "athread" thread manages actions that need to occur outside qemu's CPU loop
        # e.g., interacting with monitor/serial and waiting for results

        # Configure serial - Always enabled for now
        self.serial_prompt = expect_prompt
        self.serial_console = None
        self.serial_file = NamedTemporaryFile(prefix="pypanda_s").name
        self.serial_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.panda_args.extend(['-serial', 'unix:{},server,nowait'.format(self.serial_file)])

        # Configure monitor - Always enabled for now
        self.monitor_prompt = "(qemu)"
        self.monitor_console = None
        self.monitor_file = NamedTemporaryFile(prefix="pypanda_m").name
        self.monitor_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.panda_args.extend(['-monitor', 'unix:{},server,nowait'.format(self.monitor_file)])

        self.running = threading.Event()
        self.started = threading.Event()
        self.athread = AsyncThread(self.started)

        self.panda_args_ffi = [ffi.new("char[]", bytes(str(i),"utf-8")) for i in self.panda_args]
        cargs = ffi.new("char **")

        nulls = ffi.new("char[]", b"")
        cenvp = ffi.new("char **",nulls)
        len_cargs = ffi.cast("int", len(self.panda_args))

        progress ("Panda args: [" + (" ".join(self.panda_args)) + "]")

        self.len_cargs = len_cargs
        self.cenvp = cenvp
        self.taint_enabled = False
        self.hook_list = []

        self.current_asid_name = None
        self.asid_mapping = {}

        self.callback = pcb
        self.register_cb_decorators()

        self.registered_callbacks = {} # name -> {procname: "bash", enabled: False, callback: None}

        self.handle = ffi.cast('void *', 0xdeadbeef)
        self._initialized_panda = False
        self.disabled_tb_chaining = False

        # Register asid_changed CB if and only if a callback requires procname
        self._registered_asid_changed_internal_cb = False
    # /__init__

    def _initialize_panda(self):
        '''
        After initializing the class, the user has a chance to do something (TODO: what? register callbacks?) before we finish initializing
        '''
        self.libpanda.panda_set_library_mode(True)
        self.libpanda.panda_init(self.len_cargs, self.panda_args_ffi, self.cenvp)

        # Connect to serial socket and setup serial_console if necessary
        if not self.serial_console:
            self.serial_socket.connect(self.serial_file)
            self.serial_console = Expect(self.serial_socket, expectation=self.serial_prompt, quiet=True,
                                        consume_first=False)

        # Connect to monitor socket and setup monitor_console if necessary
        if not self.monitor_console:
            self.monitor_socket.connect(self.monitor_file)
            self.monitor_console = Expect(self.monitor_socket, expectation=self.monitor_prompt, quiet=True,
                                        consume_first=True)
        # Register main_loop_wait_callback
        self.register_callback(self.callback.main_loop_wait, main_loop_wait_cb, 'main_loop_wait') # XXX WIP
    # /__init__



    # fnargs is a pair (fn, args)
    # fn is a function we want to run
    # args is args (an array)
    def queue_main_loop_wait_fn(self, fn, args=[], callback=None, cb_args=[]):
        #progress("queued up a fnargs")
        fnargs = (fn, args)
        main_loop_wait_fnargs.append(fnargs)
        cbargs = (callback, cb_args)
        main_loop_wait_cbargs.append(cbargs)

    def exit_cpu_loop(self):
        self.libpanda.panda_break_cpu_loop_req = True

    def revert(self, snapshot_name, now=False, finished_cb=None): # In the next main loop, revert
        # XXX: now=True might be unsafe. Causes weird 30s hangs sometimes
        if debug:
            progress ("Loading snapshot " + snapshot_name)
        if now:
            charptr = ffi.new("char[]", bytes(snapshot_name, "utf-8"))
            self.libpanda.panda_revert(charptr)
        else:
            self.vm_stop()

            # queue up revert then continue
            charptr = ffi.new("char[]", bytes(snapshot_name, "utf-8"))
            self.queue_main_loop_wait_fn(self.libpanda.panda_revert, [charptr])
            # if specified, finished_cb will run after we revert and have started to continue
            # but before guest has a chance to execute anything
            self.queue_main_loop_wait_fn(self.libpanda.panda_cont, [], callback=finished_cb)

    def cont(self): # Call after self.stop()
#        print ("executing panda_start (vm_start)\n");
        self.libpanda.panda_cont()
        self.running.set()

    def vm_stop(self, code=4): # default code of 4 = RUN_STATE_PAUSED
        self.libpanda.panda_stop(code)

    def snap(self, snapshot_name, cont=True):

        if debug:
            progress ("Creating snapshot " + snapshot_name)
        self.vm_stop()

        # queue up snapshot for when monitor gets a turn
        charptr = ffi.new("char[]", bytes(snapshot_name, "utf-8"))
        self.queue_main_loop_wait_fn(self.libpanda.panda_snap, [charptr])
        # and right after that we will do a vm_start
        if cont:
            self.queue_main_loop_wait_fn(self.libpanda.panda_cont, []) # so this 


    def delvm(self, snapshot_name, now):
        if debug:
            progress ("Deleting snapshot " + snapshot_name)
        if now:
            charptr = ffi.new("char[]", bytes(snapshot_name, "utf-8"))
            self.libpanda.panda_delvm(charptr)
        else:
            self.exit_cpu_loop()
            charptr = ffi.new("char[]", bytes(snapshot_name, "utf-8"))
            self.queue_main_loop_wait_fn(self.libpanda.panda_delvm, [charptr])


    def enable_tb_chaining(self):
        if debug:
            progress("Enabling TB chaining")
        self.libpanda.panda_enable_tb_chaining()

    def disable_tb_chaining(self):
        if not self.disabled_tb_chaining:
            self.disabled_tb_chaining = True
            if debug:
                progress("Disabling TB chaining")
            self.libpanda.panda_disable_tb_chaining()

    def run(self):
        if debug:
            progress ("Running")

        if not self._initialized_panda:
            self._initialize_panda()
            self._initialized_panda = True

        if not self.started.is_set():
            self.started.set()

        self.running.set()
        self.libpanda.panda_run()
        self.running.clear()

    def end_analysis(self):
        '''
        Call from any thread to unload all plugins. If called from async thread, it will also stop execution and unblock panda.run()
        '''
        self.unload_plugins()
        if self.running:
            self.queue_async(self.stop_run)

    def finish(self):
        if debug:
            progress ("Finishing qemu execution")
        self.running.clear()
        self.started.clear()
        self.libpanda.panda_finish()

    def run_replay(self, replaypfx):
        '''
        Load a replay and run it
        '''
        from os import path as os_path
        if not os_path.isfile(replaypfx+"-rr-snp") or not os_path.isfile(replaypfx+"-rr-nondet.log"):
            raise ValueError("Replay files not present to run replay of {}".format(replaypfx))
        
        if debug:
            progress ("Replaying %s" % replaypfx)

        charptr = ffi.new("char[]",bytes(replaypfx,"utf-8"))
        self.libpanda.panda_replay(charptr)
        self.run()

    def require(self, name):
        '''
        Load a C plugin with no arguments
        '''
        self.load_plugin(name, args={})

    def load_plugin(self, name, args={}):
        '''
        Load a C plugin, optionally with arguments
        '''
        if debug:
            progress ("Loading plugin %s" % name),
#            print("plugin args: [" + (" ".join(args)) + "]")

        argstrs_ffi = []
        if isinstance(args, dict):
            for k,v in args.items():
                this_arg_s = "{}={}".format(k,v)
                this_arg = ffi.new("char[]", bytes(this_arg_s, "utf-8"))
                argstrs_ffi.append(this_arg)

            n = len(args.keys())
        elif isinstance(args, list):
            for arg in args:
                this_arg = ffi.new("char[]", bytes(arg, "utf-8"))
                argstrs_ffi.append(this_arg)
            n = len(args)

        else:
            raise ValueError("Arguments to load plugin must be a list or dict of key/value pairs")


        # First set qemu_path so plugins can load (may be unnecessary after the first time)
        panda_name_ffi = ffi.new("char[]", bytes(self.panda,"utf-8"))
        self.libpanda.panda_set_qemu_path(panda_name_ffi)

        charptr = pyp.new("char[]", bytes(name,"utf-8"))
        self.libpanda.panda_require_from_library(charptr)
        self.load_plugin_library(name)

    def load_python_plugin(self, init_function, name):
        if not self.loaded_python: # Only cdef this once
            ffi.cdef("""
            extern "Python" bool init(void*);
            """)
            self.loaded_python = True
        init_ffi = init_function
        name_ffi = ffi.new("char[]", bytes(name, "utf-8"))
        filename_ffi = ffi.new("char[]", bytes(name, "utf-8"))
        uid_ffi = ffi.cast("void*",randint(0,0xffffffff)) # XXX: Unlikely but possible for collisions here
        self.libpanda.panda_load_external_plugin(filename_ffi, name_ffi, uid_ffi, init_ffi)


    def procname_changed(self, name):
        for cb_name, cb in self.registered_callbacks.items():
            if not cb["procname"]:
                continue
            if name == cb["procname"] and not cb['enabled']:
                self.enable_callback(cb_name)
            if name != cb["procname"] and cb['enabled']:
                self.disable_callback(cb_name)

            self.update_hooks_new_procname(name)

    def unload_plugin(self, name):
        if debug:
            progress ("Unloading plugin %s" % name),
        name_ffi = ffi.new("char[]", bytes(name,"utf-8"))
        self.libpanda.panda_unload_plugin_by_name(name_ffi)

    def unload_plugins(self):
        if debug:
            progress ("Unloading all panda plugins")

        # First unload python plugins, should be safe to do anytime
        for name in self.registered_callbacks.keys():
            self.disable_callback(name)

        # Then unload C plugins. May be unsafe to do except from the top of the main loop (taint segfaults otherwise)
        self.queue_main_loop_wait_fn(self.libpanda.panda_unload_plugins)

    def rr_get_guest_instr_count(self):
        return self.libpanda.rr_get_guest_instr_count_external()

    def memsavep(self, file_out):
        newfd = dup(f_out.fileno())
        self.libpanda.panda_memsavep(newfd)
        self.libpanda.fclose(newfd)

    def current_sp(self, cpustate): # under construction
        if self.arch == "i386":
            from x86.helper import R_ESP
            return cpustate.env_ptr.regs[R_ESP]
        else:
            raise NotImplemented("current_sp doesn't yet support arch {}".format(self.arch))

    def disas(self, fout, code, size):
        newfd = dup(fout.fileno())
        return self.libpanda.panda_disas(newfd, code, size)

    def set_os_name(self, os_name):
        os_name_new = ffi.new("char[]", bytes(os_name, "utf-8"))
        self.libpanda.panda_set_os_name(os_name_new)

    def virtual_memory_read(self, env, addr, length, fmt='bytearray'):
        '''
        Read but with an autogen'd buffer. Returns a bytearray
        '''
        if not hasattr(self, "_memcb"):
            self.enable_memcb()
        buf = ffi.new("char[]", length)

        buf_a = ffi.cast("char*", buf)
        length_a = ffi.cast("int", length)
        self.libpanda.panda_virtual_memory_read_external(env, addr, buf_a, length_a)

        r = ffi.unpack(buf, length)
        if fmt == 'bytearray':
            return r
        elif fmt=='int':
            return int.from_bytes(r, byteorder=self.endianness)  # XXX size better be small enough to pack into an int!
        elif fmt=='str':
            return ffi.string(buf, length)
        else:
            raise ValueError("fmt={} unsupported".format(fmt))


    def virtual_memory_write(self, env, addr, buf, length):
        if not hasattr(self, "_memcb"):
            self.enable_memcb()
        return self.libpanda.panda_virtual_memory_write_external(env, addr, buf, length)

    def virt_to_phys(self, env, addr):
        return self.libpanda.panda_virt_to_phys_external(env, addr)


# uint32_t get_callers(target_ulong *callers, uint32_t n, CPUState *cpu);

    def callstack_callers(self, lim, cpu):
        if not hasattr(self, "libpanda_callstack_instr"):
            progress("enabling callstack_instr plugin")
            self.require("callstack_instr")
        
        callers = ffi.new("uint32_t[%d]" % lim)
        n = self.libpanda_callstack_instr.get_callers(callers, lim, cpu)
        c = []
        for pc in callers:
            c.append(pc)
        return c


    def send_monitor_async(self, cmd, finished_cb=None, finished_cb_args=[]):
        if debug:
            progress ("Sending monitor command async: %s" % cmd),

        buf = ffi.new("char[]", bytes(cmd,"UTF-8"))
        n = len(cmd)

        self.queue_main_loop_wait_fn(self.libpanda.panda_monitor_run,
                [buf], self.monitor_command_cb, [finished_cb, finished_cb_args])

    def monitor_command_cb(self, result, finished_cb=None, finished_cb_args=[]):
        if result == ffi.NULL:
            r = None
        else:
            r = ffi.string(result).decode("utf-8", "ignore")
        if finished_cb:
            if len(finished_cb_args):
                finished_cb(r, *finished_cb_args)
            else:
                finished_cb(r)
        elif debug and r:
            print("(Debug) Monitor command result: {}".format(r))


    def load_plugin_library(self, name):
        if hasattr(self,"__did_load_libpanda"):
            libpanda_path_chr = ffi.new("char[]",bytes(self.libpanda_path,"UTF-8"))
            self.__did_load_libpanda = self.libpanda.panda_load_libpanda(libpanda_path_chr)
        libname = "libpanda_%s" % name
        if not hasattr(self, libname):
            assert(isfile(pjoin(self.bindir, "panda/plugins/panda_%s.so"% name)))
            library = ffi.dlopen(pjoin(self.bindir, "panda/plugins/panda_%s.so"% name))
            self.__setattr__(libname, library)

    def ppp_reg_cb(self):
        pass

    def get_cpu(self,cpustate):
        if self.arch == "arm":
            return self.get_cpu_arm(cpustate)
        elif self.arch == "x86":
            return self.get_cpu_x86(cpustate)
        elif self.arch == "x64" or self.arch == "x86_64":
            return self.get_cpu_x64(cpustate)
        elif self.arch == "ppc":
            return self.get_cpu_ppc(cpustate)
        else:
            return self.get_cpu_x86(cpustate)

    # note: should add something to check arch in self.arch
    def get_cpu_x86(self,cpustate):
        # we dont do this because x86 is the assumed arch
        # ffi.cdef(open("./include/panda_x86_support.h")) 
        return ffi.cast("CPUX86State*", cpustate.env_ptr)

    def get_cpu_x64(self,cpustate):
        # we dont do this because x86 is the assumed arch
        if not hasattr(self, "x64_support"):
            self.x64_support = ffi.cdef(open("./include/panda_x64_support.h").read()) 
        return ffi.cast("CPUX64State*", cpustate.env_ptr)

    def get_cpu_arm(self,cpustate):
        if not hasattr(self, "arm_support"):
            self.arm_support = ffi.cdef(open("./include/panda_arm_support.h").read())
        return ffi.cast("CPUARMState*", cpustate.env_ptr)

    def get_cpu_ppc(self,cpustate):
        if not hasattr(self, "ppc_support"):
            self.ppc_support = ffi.cdef(open("./include/panda_ppc_support.h").read())
        return ffi.cast("CPUPPCState*", cpustate.env_ptr)

    def queue_async(self, f):
        self.athread.queue(f)

# vim: expandtab:tabstop=4:
