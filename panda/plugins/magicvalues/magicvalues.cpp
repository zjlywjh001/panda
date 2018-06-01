/* PANDABEGINCOMMENT
 *
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */
#define __STDC_FORMAT_MACROS

#include <cstdio>
#include <cstdlib>

#include <map>
#include <set>
#include <vector>
#include <algorithm>

#include <capstone/capstone.h>
#if defined(TARGET_I386)
#include <capstone/x86.h>
#elif defined(TARGET_ARM)
#include <capstone/arm.h>
#elif defined(TARGET_PPC)
#include <capstone/ppc.h>
#endif

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "magicvalues.h"

extern "C" {
#include "panda/plog.h"

int exec_callback(CPUState* cpu, target_ulong pc);
int before_block_exec(CPUState* cpu, TranslationBlock *tb);
int after_block_exec(CPUState* cpu, TranslationBlock *tb);
int after_block_translate(CPUState* cpu, TranslationBlock *tb);

bool init_plugin(void *);
void uninit_plugin(void *);

PPP_PROT_REG_CB(on_call);
PPP_PROT_REG_CB(on_ret);
}

PPP_CB_BOILERPLATE(on_call);
PPP_CB_BOILERPLATE(on_ret);

enum instr_type {
  INSTR_UNKNOWN = 0,
  INSTR_CALL,
  INSTR_RET,
  INSTR_SYSCALL,
  INSTR_SYSRET,
  INSTR_SYSENTER,
  INSTR_SYSEXIT,
  INSTR_INT,
  INSTR_IRET,
};

struct stack_entry {
    target_ulong pc;
    instr_type kind;
};

csh cs_handle_32;
csh cs_handle_64;

typedef target_ulong Asid;
typedef target_ulong Pc;

typedef std::set<Pc, std::vector<target_ulong>> pc_to_ulong_vec;

typedef std::map<Pc, std::vector<int> > pc_to_vec;
std::map<Asid, pc_to_vec > compare_immediates;

//map<Asid, Pc> last_pc;

// multiple ASIDs -> multiple pc  -> vector of constants
//compare_immediates[asid][pc].push_back(val)
//std::set<Asid, std::vector<pc_to_ulong_vec>> compare_immediates;
//std::map<pc, target_ulong> compare_immediates;

// PC -> register id used for compare
std::map<Pc, std::vector<unsigned short>> compare_registers;
std::map<Pc, std::vector<target_ulong>> register_values;

// PC -> mem address  used in compare
#if defined(TARGET_I386)
std::map<target_ulong, std::vector<cs_x86_op>> compare_memory;
#endif

std::map<target_ulong, instr_type> insn_cache;

// Translate capstone x86 register identifier to panda x86 register (Note PANDA's overlap? is there another way?)
short cs_reg_to_panda(short cs) {
    switch(cs) {
        case X86_REG_EAX: return R_EAX; break;
        case X86_REG_EBX: return R_EBX; break;
        case X86_REG_ECX: return R_ECX; break;
        case X86_REG_EDX: return R_EDX; break;
        case X86_REG_ESP: return R_ESP; break;
        case X86_REG_EBP: return R_EBP; break;
        case X86_REG_ESI: return R_ESI; break;
        case X86_REG_EDI: return R_EDI; break;

        case X86_REG_AL: return R_AL; break;
        case X86_REG_CL: return R_CL; break;
        case X86_REG_DL: return R_DL; break;
        case X86_REG_BL: return R_BL; break;
        case X86_REG_AH: return R_AH; break;
        case X86_REG_CH: return R_CH; break;
        case X86_REG_DH: return R_DH; break;
        case X86_REG_BH: return R_BH; break;

        case X86_REG_ES: return R_ES; break;
        case X86_REG_CS: return R_CS; break;
        case X86_REG_SS: return R_SS; break;


        default: return 0; break;
    }
}


// Given a basic block, find all comparisions and:
// 1) Save immediates comapred against
// 2) Save register/PC pairs to use later to get register values
// 3) Save memory/PC pairs to use later to get memory values

instr_type block_to_constants(CPUArchState* env, target_ulong pc, int size) {
    unsigned char *buf = (unsigned char *) malloc(size);
    int err = panda_virtual_memory_rw(ENV_GET_CPU(env), pc, buf, size, 0);
    if (err == -1) printf("Couldn't read TB memory!\n");
    instr_type res = INSTR_UNKNOWN;

#if defined(TARGET_I386)
    csh handle = (env->hflags & HF_LMA_MASK) ? cs_handle_64 : cs_handle_32;
#endif

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_insn *insn;
    //cs_insn *end;
    size_t count = cs_disasm(handle, buf, size, pc, 0, &insn);
    target_ulong asid = panda_current_asid(ENV_GET_CPU(env)); // TODO something with ASID
   
#if defined(TARGET_I386)
    size_t i;

    cs_x86 *x86;

    for (i = 0; i < count; i++) { // For each instruction
      // TODO add support for TEST and any other common comparison operands?
      if (strncmp(insn[i].mnemonic, "cmp\0", 4) == 0) {
        // cmp will have two arguments, we currently support: cmp reg, reg; cmp reg, const

        //printf(TARGET_FMT_lx "\t0x%lu:\t%s\t\t%s\n", asid, insn[i].address, insn[i].mnemonic, insn[i].op_str);

        x86 = &(insn[i].detail->x86);
        assert(x86->op_count == 2); // What else could it be for cmp
        cs_x86_op op1 = x86->operands[0];
        cs_x86_op op2 = x86->operands[1];

        // Extract immediates
        if (op1.type == X86_OP_IMM && op2.type == X86_OP_IMM) // comparing two imms is meaningless
          continue;

        // Only push back unique values
        if (op1.type == X86_OP_IMM) {
          compare_immediates.insert(std::make_pair(asid, pc_to_vec())); // Initialize if necessary

          if (std::find(compare_immediates[asid][pc].begin(), compare_immediates[asid][pc].end(), op1.imm) == compare_immediates[asid][pc].end())
            compare_immediates[asid][pc].push_back(op1.imm);
          
        }else if (op2.type == X86_OP_IMM) {
          compare_immediates.insert(std::make_pair(asid, pc_to_vec())); // Initialize if necessary
          if (std::find(compare_immediates[asid][pc].begin(), compare_immediates[asid][pc].end(), op1.imm) == compare_immediates[asid][pc].end())
            compare_immediates[asid][pc].push_back(op1.imm);
        }

        // Extract registers
        if (op1.type == X86_OP_REG) {
             compare_registers[insn[i].address].push_back(op1.reg);
        }
        if (op2.type == X86_OP_REG) {
             compare_registers[insn[i].address].push_back(op2.reg);
        }

        // Extract memory - Save whole operand object?
        if (op1.type == X86_OP_MEM) {
             compare_memory[insn[i].address].push_back(op1);
        }
        if (op2.type == X86_OP_MEM) {
             compare_memory[insn[i].address].push_back(op2);
        }
      }
    }

#endif
    // TODO x86_64 support

    if (insn != NULL) cs_free(insn, count);
    free(buf);
    return res;
}

// After we translate a block store its constants in the cache
int after_block_translate(CPUState *cpu, TranslationBlock *tb) {
    CPUArchState* env = (CPUArchState*)cpu->env_ptr;
    insn_cache[tb->pc] = block_to_constants(env, tb->pc, tb->size);

    return 1;
}

bool translate_callback(CPUState* cpu, target_ulong pc){
    // Return true if current instruction is in our mem map that triggers our exec_callback
    return compare_registers.count(pc) > 0;
}

int exec_callback(CPUState* cpu, target_ulong pc){
#if defined(TARGET_I386)
  // There was a register compare
  for (auto & element : compare_registers[pc]) {
    CPUArchState* env = (CPUArchState*)cpu->env_ptr;
    ulong val = env->regs[cs_reg_to_panda(element)];
    //printf("0x%x Read register %d => 0x%x\n", pc, cs_reg_to_panda(element), val);
    // Only add unique values at this address
    if (std::find(register_values[pc].begin(), register_values[pc].end(), val) == register_values[pc].end()) {
      // TODO: store in compare_immediates with a type=mem or at least something better than this
      register_values[pc].push_back(val);
    }
  }
#endif
  return 1;
}



bool init_plugin(void *self) {
#if defined(TARGET_I386)
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle_32) != CS_ERR_OK)
        return false;
#if defined(TARGET_X86_64)
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs_handle_64) != CS_ERR_OK)
        return false;
#endif
#elif defined(TARGET_ARM)
    if (cs_open(CS_ARCH_ARM, CS_MODE_ARM, &cs_handle_32) != CS_ERR_OK)
        return false;
#elif defined(TARGET_PPC)
    if (cs_open(CS_ARCH_PPC, CS_MODE_32, &cs_handle_32) != CS_ERR_OK)
        return false;
#endif

    // Need details in capstone to have instruction groupings
#if defined(TARGET_X86_64)
    cs_option(cs_handle_64, CS_OPT_DETAIL, CS_OPT_ON);
#else
    cs_option(cs_handle_32, CS_OPT_DETAIL, CS_OPT_ON);
#endif

    panda_cb pcb;

    panda_enable_memcb();
    panda_enable_precise_pc();

    pcb.after_block_translate = after_block_translate;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_TRANSLATE, pcb);

    pcb.insn_translate = translate_callback;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);

    pcb.insn_exec = exec_callback;
    panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);


    return true;
}

void uninit_plugin(void *self) {
  // At end - do something with all our saved data

  // Print all immediates we saw
  // Asid
  for (auto asids : compare_immediates) {
    printf("ASID=0x%x\n",  asids.first);
    for (auto pcs : asids.second) {
      printf("\tPC=0x%x\n\t",  pcs.first);
      for (auto vals : pcs.second) {
        printf("\t0x%x",  vals);
      }
        printf("\n");
    }
  }
  /*
  for (std::map<target_ulong, target_ulong>::iterator it = compare_immediates.begin(); it != compare_immediates.end(); ++it) {
        printf("At 0x%x compare with \t0x%x\n", it->first, it->second);
  }*/

  // Print all memory comparisons we saw
  /*
  for (std::map<target_ulong, std::vector<target_ulong>>::iterator it = register_values.begin(); it != register_values.end(); ++it) {
      printf("At 0x%x compare with memory:", it->first);
      for (auto & element : it->second) {
        printf("\t0x%x", element);
      }
  }
  */

}

/* vim: set tabstop=4 softtabstop=4 expandtab ft=cpp: */
