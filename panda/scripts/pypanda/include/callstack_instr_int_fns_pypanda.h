
// Public interface

// Get up to n callers from the given address space at this moment
// Callers are returned in callers[], most recent first
uint32_t get_callers(target_ulong *callers, uint32_t n, CPUState *cpu);

// Get up to n functions from the given address space at this moment
// Functions are returned in functions[], most recent first
uint32_t get_functions(target_ulong *functions, uint32_t n, CPUState *cpu);


