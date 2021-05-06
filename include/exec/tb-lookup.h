/*
 * Copyright (C) 2017, Emilio G. Cota <cota@braap.org>
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */
#ifndef EXEC_TB_LOOKUP_H
#define EXEC_TB_LOOKUP_H

#ifdef NEED_CPU_H
#include "cpu.h"
#else
#include "exec/poison.h"
#endif

#include "exec/exec-all.h"
#include "exec/tb-hash.h"

#include "accel/tcg/hybrid/hybrid.h"

/* Might cause an exception, so have a longjmp destination ready */
static inline TranslationBlock *
tb_lookup__cpu_state(CPUState *cpu, target_ulong *pc, target_ulong *cs_base,
                     uint32_t *flags, uint32_t cf_mask, TranslationBlock **last_tb)
{
    CPUArchState *env = (CPUArchState *)cpu->env_ptr;
    TranslationBlock *tb;
    uint32_t hash;

    cpu_get_tb_cpu_state(env, pc, cs_base, flags);
    
    /* HYBRID */
    // printf("EIP: %lx\n", pc);
    int fetch_again_cpu_state = 0;
    SWITCH_TO_NATIVE(*pc, env, &fetch_again_cpu_state);
    // THIS IS IMPORTANT: compiler may reorder some assignments!
    __asm__ __volatile__("":::"memory");
    //
    if (fetch_again_cpu_state) {
        // printf("Refetching cpu state as native execution has terminated\n");

        task_t* task = get_task();
        if (task->must_exit) {
            do_syscall(task->emulated_state,
                        task->emulated_state->regs[R_EAX],
                        task->emulated_state->regs[R_EDI],
                        task->emulated_state->regs[R_ESI],
                        task->emulated_state->regs[R_EDX],
                        task->emulated_state->regs[10],
                        task->emulated_state->regs[8],
                        task->emulated_state->regs[9],
                        0, 0);
            tcg_abort();
        }

        cpu_get_tb_cpu_state(env, pc, cs_base, flags);
        printf("Resuming emulation from %lx\n", *pc);
        // printf("RSP: %lx\n", task->emulated_state->regs[R_ESP]);
        hybrid_stub();
        if (last_tb)
            *last_tb = NULL;
    }
    /* HYBRID */

    hash = tb_jmp_cache_hash_func(*pc);
    tb = atomic_rcu_read(&cpu->tb_jmp_cache[hash]);

    cf_mask &= ~CF_CLUSTER_MASK;
    cf_mask |= cpu->cluster_index << CF_CLUSTER_SHIFT;

    if (likely(tb &&
               tb->pc == *pc &&
               tb->cs_base == *cs_base &&
               tb->flags == *flags &&
               tb->trace_vcpu_dstate == *cpu->trace_dstate &&
               (tb_cflags(tb) & (CF_HASH_MASK | CF_INVALID)) == cf_mask)) {
        return tb;
    }
    tb = tb_htable_lookup(cpu, *pc, *cs_base, *flags, cf_mask);
    if (tb == NULL) {
        return NULL;
    }
    atomic_set(&cpu->tb_jmp_cache[hash], tb);
    return tb;
}

#endif /* EXEC_TB_LOOKUP_H */
