// Generate a drcov trace file from a panda recording
// TODO: the output isn't quite right, Lighthouse shows no coverage

// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include <cstdio>

#include "panda/plugin.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

#include <stdint.h>

#include "panda/plog.h"
#include "osi/osi_types.h"
#include "osi/osi_ext.h"

}

#include<fstream>
#include<map>
#include<set>
#include <iomanip>


#ifdef CONFIG_SOFTMMU

#endif

using namespace std;

typedef target_ulong Asid;
typedef target_ulong Pc;
typedef pair<Pc, Pc> Edge; 
typedef pair<Pc, unsigned int> Block; 

map<Asid, set<Block>> blocks;
map<Asid, set<Edge>> asid_edges;
map<Asid, Pc> last_pc;


struct ProcessData {
    const char* name;
    target_ulong pid;
    target_ulong load_address;
    target_ulong size;
};

map<Asid, ProcessData> process_datas;

target_ulong MY_TARGET_ASID = 0; // Set to 0 to collect everything
//target_ulong MY_TARGET_ASID = 0x05b7f000; // cat

// Called before each block, we have PC and ASID
int collect_edges(CPUState *env, TranslationBlock *tb) {
    // First figure out if we have info for this ASID's process
    target_ulong asid = panda_current_asid(env);
    target_ulong pc = panda_current_pc(env);

    if (MY_TARGET_ASID != 0 && asid != MY_TARGET_ASID) return 0; // Only trace our asid


	if (process_datas.find(asid) == process_datas.end()){
        target_ulong load_addr = 0;
        target_ulong size = 0;

		OsiProc *current = get_current_process(env);
        if(current) {
            OsiModules *libraries = get_libraries(env, current);

            if (libraries && libraries->num > 0)  {
                OsiModule *self = &libraries->module[0];

                /*
                for (int i=0; i < libraries->num; i++) {
                    OsiModule *mod = &libraries->module[i];
                    if (mod ->file == NULL) break;
                    printf("%s base=0x" TARGET_FMT_lx ", size=0x" TARGET_FMT_lx "\n", self->file, self->base, mod->size);
                }
                */

                load_addr = self->base;
                size = self->size;
                if (self->file != NULL) {

                    printf("LOADED %s asid=0x" TARGET_FMT_lx " at PC 0x" TARGET_FMT_lx ": low = " TARGET_FMT_lx ", relative= 0x" TARGET_FMT_lx "\n", self->file, asid, pc, load_addr, pc-load_addr);

                    ProcessData p;
                    p.name = current->name;
                    p.pid = current->pid;
                    p.load_address = load_addr;
                    p.size = size;
                    process_datas.insert(make_pair(asid, p));
                }
            }
        }
        /*
	}else if (asid == 0x7a4d000) { // DEBUG - print every basic block's PC for whoami
		OsiProc *current = get_current_process(env);
        if(current) {
            OsiModules *libraries = get_libraries(env, current);

            if (libraries && libraries->num > 0)  {
                OsiModule *self = &libraries->module[0];

                if (libraries->num >0  && strcmp(libraries->module[0].file, "whoami")) {
                    printf("%s RELPC=0x" TARGET_FMT_lx " , PC=0x" TARGET_FMT_lx " base=0x" TARGET_FMT_lx ", size=0x" TARGET_FMT_lx "\n", self->file, pc-self->base, pc, self->base, self->size);
                }
            }
        }
        */
    }

    // Actually store the PC, in both blocks and edges for now
    if (last_pc.count(asid) != 0) {               
        unsigned int block_size = tb->size;
        Block b = make_pair(pc, block_size);
        Edge e = make_pair(last_pc[asid], pc);
        asid_edges[asid].insert(e);
        //printf("At bb: 0x" TARGET_FMT_lx "\n", pc);
        blocks[asid].insert(b);
    }
    last_pc[asid] = pc;
    return 0;
}

bool init_plugin(void *self) {
    panda_require("osi");
    // this sets up OS introspection API
    assert(init_osi_api());

    panda_cb pcb;
    pcb.before_block_exec = collect_edges;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    printf("Initialized coverage plugin\n");
    return true;
}


void uninit_plugin(void *) {
    char fname[32];
    snprintf(fname, 32, "trace.log");
    ofstream outfile(fname); //, ofstream::binary);
    outfile << "DRCOV VERSION: 2\n";
    outfile << "DRCOV FLAVOR: panda\n";
    outfile << "Module Table: version 2, count " << asid_edges.size() << "\n";
    outfile << "Columns: id, base, end, entry, checksum, timestamp, path\n";

    // First, for each asid, print basic info
    int idx = 0;
    for (auto kvp : asid_edges) {
        auto asid = kvp.first;
        if (MY_TARGET_ASID != 0 && asid != MY_TARGET_ASID) continue; // Only trace our asid
        // We don't supply entry, checksum and, timestamp.
	    auto p = process_datas.find(asid);
        string image_name = "unknown";
        target_ulong image_low = 0;
        target_ulong image_high = 0;
        if (p != process_datas.end()){
            image_name = p->second.name;

            image_low = p->second.load_address;
            image_low -= 0x8000000;
            image_high = image_low + p->second.size;
        }
        outfile << setbase(10) << setprecision(2) << ++idx << ", ";
        outfile << setbase(16) << setprecision(8) <<  "0x" << image_low << ", 0x" << image_high << ", 0x0000000000000000, 0x00000000, 0x00000000, " << image_name << "\n";
    }

    outfile << setbase(10) << setprecision(0);

    idx = 0;
    unsigned int bb_size = 0;
    for (auto kvp : asid_edges) {
        auto asid = kvp.first;
        if (MY_TARGET_ASID != 0 && asid != MY_TARGET_ASID) continue; // Only trace our asid
        printf("id = %d count = %lu asid=" TARGET_FMT_lx "\n", ++idx, kvp.second.size(), kvp.first);
        bb_size += kvp.second.size();
    }

    outfile << "BB Table: " << bb_size << " bbs\n";
    outfile.close();

    // Reopen logfile so we can use fwrite instead of << for the binary data
    auto outfile2 = fopen(fname, "a");

    struct __attribute__((packed)) drcov_bb {
        uint32_t start;
        uint16_t size;
        uint16_t id;
    };

    drcov_bb tmp;

    idx = 0;
    for (auto block : blocks) {
        auto asid = block.first;
        auto blocks = block.second;

        if (MY_TARGET_ASID != 0 && asid != MY_TARGET_ASID) continue; // Only trace our asid

	    auto p = process_datas.find(asid);
        if (p == process_datas.end()){ // This is bad
            continue;
        }

        //auto image_name = p->second.name;
        auto image_low = p->second.load_address;
        //auto image_high = image_low + p->second.size;

        tmp.id = ++idx;

        for (auto b : blocks) {
            auto curr_pc = b.first;
            auto block_size = b.second;

            /*
            printf("BLOCK: curr_pc = 0x" TARGET_FMT_lx " size= %u img_low=0x" TARGET_FMT_lx "\n", curr_pc, block_size, image_low);

            printf("Relative PC=" TARGET_FMT_lx "\n", curr_pc-image_low);
            printf("Relative PCshifted=" TARGET_FMT_lx "\n", curr_pc-image_low+0x400000);
            */

            curr_pc -= image_low; // We want to have the pc relative to the process
            //printf("Saw bb: 0x" TARGET_FMT_lx "\n", curr_pc);

            tmp.size = block_size;
            tmp.start = curr_pc;
            fwrite(&tmp, sizeof(tmp), 1, outfile2);
        }
    }
    printf("Unload coverage plugin\n");
}

