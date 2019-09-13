#ifndef __CALLSTACK_INSTR_INT_FNS_H__
#define __CALLSTACK_INSTR_INT_FNS_H__

//#include "prog_point.h"

// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

// Public interface

// Get up to n callers from the given address space at this moment
// Callers are returned in callers[], most recent first
uint32_t get_callers(target_ulong *callers, uint32_t n, CPUState *cpu);

// Get up to n functions from the given address space at this moment
// Functions are returned in functions[], most recent first
uint32_t get_functions(target_ulong *functions, uint32_t n, CPUState *cpu);


// END_PYPANDA_NEEDS_THIS -- do not delete this comment!



// create pandalog message for callstack info
Panda__CallStack *pandalog_callstack_create(void);

// free that data structure
void pandalog_callstack_free(Panda__CallStack *cs);


// NB: prog_point is c++, so beware

// Get the current program point: (Caller, PC, ASID)
// This isn't quite the right place for it, but since it's awkward
// right now to have a "utilities" library, this will have to do
void get_prog_point(CPUState *cpu, prog_point *p);


#endif
