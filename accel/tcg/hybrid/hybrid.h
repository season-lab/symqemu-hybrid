#ifndef HYBRID_H
#define HYBRID_H

#include <stdint.h>

#include "qemu/osdep.h"
#include "cpu.h"

#include "linux-user/qemu.h"
#include "linux-user/x86_64/syscall_nr.h"

extern abi_ulong start_addr;
extern uint64_t  plt_jump_table_addr;
extern uint64_t  nb_plt_entries;

typedef enum {
    INITIAL_JUMP_INTO_NATIVE,
    RETURN_FROM_EMULATION,
    EMULATION_TO_NATIVE,
    FORKED_TASK,
} switch_mode_t;

#define MAX_DEPTH 256
struct CpuContext_t;
typedef struct {
    uint64_t             tid;
    struct CpuContext_t* native_context;
    struct CpuContext_t* emulated_context;
    struct CpuContext_t* qemu_context;
    CPUX86State*         emulated_state;
    int64_t              depth;
    uint64_t             return_addrs[MAX_DEPTH];
    //
    int64_t              long_jumps_used;
    uint64_t             longjmp[MAX_DEPTH];
    uint64_t             longjmp_arg[MAX_DEPTH];
    uint64_t             longjmp_depth[MAX_DEPTH];
    uint64_t             longjmp_callsite[MAX_DEPTH];
    //
    uint64_t             concretized_rsp_point;
    //
    bool                 is_native;
    bool                 must_exit;
} task_t;

int  is_hooked_plt_entry(uint64_t target);
void switch_to_emulated(int plt_entry);
void switch_to_native(uint64_t target, CPUX86State* env, switch_mode_t mode);
void switch_back_to_native(uint64_t target, CPUX86State* env);
void concretize_args(uint64_t target, CPUX86State* env, task_t* task);
extern void save_native_context(void);
extern void return_handler_from_emulation(void);
void        hybrid_init(CPUState *cpu);
void hybrid_syscall(uint64_t retval, uint64_t num, uint64_t arg1, uint64_t arg2,
                    uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6,
                    uint64_t arg7, uint64_t arg8);
void hybrid_new_thread(uint64_t tid, CPUX86State* state);
void hybrid_set_sigill_handler(void);
int  hybrid_is_task_native(void);
void hybrid_debug(void);

void forkserver(void);

extern uint64_t libc_concrete_funcs[256];

task_t* get_task(void);
void    hybrid_stub(task_t* task);

extern int       reached_start;
extern abi_ulong hybrid_start_code, hybrid_end_code;
extern abi_ulong hybrid_start_lib_1, hybrid_end_lib_1;
extern abi_ulong hybrid_start_lib_2, hybrid_end_lib_2;

#define RETURN_FROM_EMULATION_SENTINEL 0xDEADBEEF

// } else if (hybrid_is_task_native()) {                                  
//     switch_to_native(target, state, FORKED_TASK);                      
//     *flag = 1;                                                         

#define SWITCH_TO_NATIVE(target, state, flag)                                  \
    do {                                                                       \
        if (target == start_addr) {                                            \
            switch_to_native(target, state, INITIAL_JUMP_INTO_NATIVE);         \
            *flag = 1;                                                         \
        } else if (target == (target_ulong)RETURN_FROM_EMULATION_SENTINEL) {   \
            switch_to_native(target, state, RETURN_FROM_EMULATION);            \
            *flag = 1;                                                         \
        } else if (reached_start && ((target >= hybrid_start_code &&           \
                                      target <= hybrid_end_code) ||            \
                                     (target >= hybrid_start_lib_1 &&          \
                                      target <= hybrid_end_lib_1) ||           \
                                     (target >= hybrid_start_lib_2 &&          \
                                      target <= hybrid_end_lib_2) ||           \
                                      is_hooked_plt_entry(target))) {          \
            switch_to_native(target, state, EMULATION_TO_NATIVE);              \
            *flag = 1;                                                         \
        }                                                                      \
    } while (0)

//        } else if (hybrid_is_task_native()) {
//            switch_to_native(target, state, FORKED_TASK);
//            *flag = 1;

#define LIBC_CONCRETIZE_ARGS(target, state) concretize_args(target, state, NULL)

#endif // HYBRID_H