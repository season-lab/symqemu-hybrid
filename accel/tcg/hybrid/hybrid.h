#ifndef HYBRID_H
#define HYBRID_H

#include <stdint.h>

#include "qemu/osdep.h"
#include "cpu.h"

#include "linux-user/qemu.h"
#include "linux-user/x86_64/syscall_nr.h"

extern abi_ulong start_addr;
extern uint64_t plt_jump_table_addr;
extern uint64_t nb_plt_entries;

int is_hooked_plt_entry(uint64_t target);
void switch_to_emulated(int plt_entry);
void switch_to_native(uint64_t target, CPUX86State *env);
void switch_back_to_native(uint64_t target, CPUX86State *env);
extern void save_native_context(void);
extern void return_handler_from_emulation(void);
void hybrid_init(void);
void hybrid_syscall(uint64_t retval,
                    uint64_t num, uint64_t arg1, uint64_t arg2,
                    uint64_t arg3, uint64_t arg4, uint64_t arg5,
                    uint64_t arg6, uint64_t arg7, uint64_t arg8);
void hybrid_new_thread(uint64_t tid, CPUX86State *state);
void hybrid_set_sigill_handler(void);
int hybrid_is_task_native(void);

struct CpuContext_t;
typedef struct
{
    uint64_t tid;
    struct CpuContext_t *native_context;
    struct CpuContext_t *emulated_context;
    struct CpuContext_t *qemu_context;
    CPUX86State *emulated_state;
    bool is_native;
    bool must_exit;
} task_t;

task_t *get_task(void);
void hybrid_stub(task_t* task);

#define SWITCH_TO_NATIVE(target, state, flag)                           \
    do                                                                  \
    {                                                                   \
        if (target == start_addr)                                       \
        {                                                               \
            switch_to_native(target, state);                            \
            *flag = 1;                                                  \
        }                                                               \
        else if (target == (target_ulong)return_handler_from_emulation) \
        {                                                               \
            switch_to_native(target, state);                            \
            *flag = 1;                                                  \
        }                                                               \
        else if (hybrid_is_task_native())                               \
        {                                                               \
            switch_to_native(target, state);                            \
            *flag = 1;                                                  \
        }                                                               \
    } while (0)

#endif // HYBRID_H