#include <stdio.h>
#include "hybrid.h"

#include <stdio.h>
#include <asm/prctl.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <glib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "qemu/osdep.h"
#include "cpu.h"
#include "trace.h"
#include "disas/disas.h"
#include "exec/exec-all.h"
#include "tcg.h"
#include "qemu/atomic.h"
#include "sysemu/qtest.h"
#include "qemu/timer.h"
#include "exec/address-spaces.h"
#include "qemu/rcu.h"
#include "exec/tb-hash.h"
#include "exec/log.h"
#include "qemu/main-loop.h"
#include "sysemu/cpus.h"
#include "sysemu/replay.h"

#include <immintrin.h>

#define SymExpr void *
#include "RuntimeCommon.h"
#undef SymExpr

#define SAVE_GPR(reg, slot)                            \
    "movq $" str(slot) ", %rcx"                        \
                       "\n\t"                          \
                       "movq " reg ", (%rax, %rcx, 8)" \
                       "\n\t"
#define RESTORE_GPR(reg, slot)  \
    "movq $" str(slot) ", %rcx" \
                       "\n\t"   \
                       "movq (%rax, %rcx, 8), " reg "\n\t"
#define SAVE_SEGR(reg, slot)                           \
    "movq $" str(slot) ", %rcx"                        \
                       "\n\t"                          \
                       "movw " reg ", (%rax, %rcx, 2)" \
                       "\n\t"
#define RESTORE_SEGR(reg, slot)                       \
    "movq $" str(slot) ", %rcx"                       \
                       "\n\t"                         \
                       "movzwl (%rax, %rcx, 2), %rcx" \
                       "\n\t"                         \
                       "push %rcx"                    \
                       "\n\t"                         \
                       "pop " reg "\n\t"

#define xstr(ss) str(ss)
#define str(s) #s

#include "accel/tcg/hybrid/hybrid_cpu.h"

#define SLOT_RAX R_EAX
#define SLOT_RBX R_EBX
#define SLOT_RCX R_ECX
#define SLOT_RDX R_EDX
#define SLOT_RSI R_ESI
#define SLOT_RDI R_EDI
#define SLOT_RBP R_EBP
#define SLOT_RSP R_ESP
#define SLOT_R8 R_R8
#define SLOT_R9 R_R9
#define SLOT_R10 R_R10
#define SLOT_R11 R_R11
#define SLOT_R12 R_R12
#define SLOT_R13 R_R13
#define SLOT_R14 R_R14
#define SLOT_R15 R_R15
#define SLOT_GPR_END (R_R15 + 1)

#define SLOT_ES R_ES
#define SLOT_CS R_CS
#define SLOT_SS R_SS
#define SLOT_DS R_DS
#define SLOT_FS R_FS
#define SLOT_GS 5 // weird link error: clash of names?
#define SLOT_SEGR_END (R_GS + 1)

typedef struct CpuContext_t
{
    uint64_t gpr[SLOT_GPR_END];
    uint64_t flags;
    uint16_t seg[SLOT_SEGR_END];
    uint64_t fs_base;
    uint64_t valid;
    uint64_t pc;
    struct sigaction sigill_handler;
} CpuContext;

#define MAX_TASKS 64
static task_t tasks[MAX_TASKS] = {0};

#define MAX_PLT_ENTRIES 256
uint64_t shadow_plt[MAX_PLT_ENTRIES] = {0};

uint64_t start_addr = 0;
static GSList *plt_patches = NULL;
static GSList *syscall_patches = NULL;
static GSList *runtime_patches = NULL;
static GSList *plt_aliases = NULL;

typedef struct
{
    char *name;
    GSList *offsets;
} plt_patch_t;

typedef struct
{
    char *name;
    GSList *offsets;
} syscall_patch_t;

typedef struct
{
    char *name;
    uint64_t offset;
} runtime_plt_patch_t;

typedef struct
{
    char *name;
    GSList *patches;
} runtime_patch_t;

typedef struct
{
    char *from_obj;
    char *to_obj;
    uint64_t from_got_entry;
    uint64_t to_got_entry;
    uint64_t to_plt_entry;
} plt_alias_t;

static int plt_stubs_count = 0;

typedef enum
{
    FILE_STATE_INVALID,
    FILE_STATE_OPEN
} file_state_t;

typedef struct
{
    int state;
    char *name;
} open_file_t;

typedef struct
{
    char *name;
    uint64_t addr;
} mmap_file_t;

#define MAX_MMAP_FILES 64
open_file_t open_files[MAX_MMAP_FILES] = {0};
GSList *mmaped_files = NULL;

int arch_prctl(int code, unsigned long addr);

static int parse_config_file(char *file)
{
    // printf("Reading config file: %s\n", file);

    GKeyFile *gkf = g_key_file_new();
    if (!g_key_file_load_from_file(gkf, file, G_KEY_FILE_NONE, NULL))
    {
        fprintf(stderr, "Could not read config file %s\n", file);
        return -1;
    }

    char *res = g_key_file_get_value(gkf, "start_addr", "addr", NULL);
    if (res)
    {
        // printf("ADDR: %s\n", res);
        start_addr = (target_ulong)strtoull(res, NULL, 16);
    }

    char **groups = g_key_file_get_groups(gkf, NULL);
    char **groups_original = groups;
    while (*groups != NULL)
    {
        // printf("group %s\n", *groups);
        if (strcmp(*groups, "start_addr") != 0)
        {
            GSList *offsets = NULL;
            // int is_main_image = strcmp(*groups, "main_image") == 0;
            char **addrs = g_key_file_get_string_list(gkf, *groups, "patch_plt", NULL, NULL);
            if (addrs)
            {
                char **addrs_original = addrs;
                while (*addrs != NULL)
                {
                    uint64_t offset = (target_ulong)strtoull(*addrs, NULL, 16);
                    // printf("[%s] offset: 0x%lx\n", *groups, offset);
                    offsets = g_slist_append(offsets, (gpointer)offset);
                    addrs++;
                }
                plt_patch_t *patch = g_malloc0(sizeof(plt_patch_t));
                patch->name = strdup(*groups);
                patch->offsets = offsets;
                plt_patches = g_slist_append(plt_patches, (gpointer)patch);
                g_strfreev(addrs_original);
            }

            // GSList *syscall_offsets = NULL;
            addrs = g_key_file_get_string_list(gkf, *groups, "patch_syscall", NULL, NULL);
            if (addrs)
            {
                char **addrs_original = addrs;
#if 0
                while (*addrs != NULL)
                {
                    uint64_t offset = (target_ulong)strtoull(*addrs, NULL, 16);
                    // printf("[%s] offset: 0x%lx\n", *groups, offset);
                    syscall_offsets = g_slist_append(syscall_offsets, (gpointer)offset);
                    addrs++;
                }
                syscall_patch_t *patch = g_malloc0(sizeof(syscall_patch_t));
                patch->name = strdup(*groups);
                patch->offsets = syscall_offsets;
                syscall_patches = g_slist_append(syscall_patches, (gpointer)patch);
#endif
                g_strfreev(addrs_original);
            }

            char **keys = g_key_file_get_keys(gkf, *groups, NULL, NULL);
            char **keys_original = keys;
            runtime_patch_t *runtime_patch = NULL;
            while (*keys != NULL)
            {
                if (strncmp(*keys, "RUNTIME_", 8) == 0)
                {
                    if (runtime_patch == NULL)
                    {
                        runtime_patch = g_malloc0(sizeof(runtime_patch_t));
                        runtime_patch->name = strdup(*groups);
                        runtime_patch->patches = NULL;
                    }

                    char *name = strdup(*keys + 8);
                    char *offset = g_key_file_get_value(gkf, *groups, *keys, NULL);
                    if (offset)
                    {
                        // printf("ADDR: %s\n", res);
                        uint64_t off = (target_ulong)strtoull(offset, NULL, 16);
                        // printf("name: %s value: %lx\n", name, off);

                        runtime_plt_patch_t *patch = g_malloc0(sizeof(runtime_plt_patch_t));
                        patch->name = name;
                        patch->offset = off;
                        runtime_patch->patches = g_slist_append(runtime_patch->patches, (gpointer)patch);
                    }
                }
                else if (strncmp(*keys, "0x_", 2) == 0)
                {
                    printf("V=%s\n", *keys);
                    char **addrs = g_key_file_get_string_list(gkf, *groups, *keys, NULL, NULL);
                    if (addrs)
                    {
                        plt_alias_t *plt_alias = g_malloc0(sizeof(plt_alias_t));
                        plt_alias->from_obj = strdup(*groups);
                        plt_alias->from_got_entry = (target_ulong)strtoull(*keys, NULL, 16);
                        char **addrs_original = addrs;
                        int index = 0;
                        while (*addrs != NULL)
                        {
                            printf("VV=%s\n", *addrs);
                            if (index == 0)
                                plt_alias->to_obj = strdup(*addrs);
                            else if (index == 1)
                                plt_alias->to_got_entry = (target_ulong)strtoull(*addrs, NULL, 16);
                            else if (index == 2)
                                plt_alias->to_plt_entry = (target_ulong)strtoull(*addrs, NULL, 16);
                            else
                                tcg_abort();
                            addrs++;
                            index += 1;
                        }
                        plt_aliases = g_slist_append(plt_aliases, (gpointer)plt_alias);
                        g_strfreev(addrs_original);
                    }
                }

                keys++;
            }
            g_strfreev(keys_original);
            if (runtime_patch)
            {
                runtime_patches = g_slist_append(runtime_patches, (gpointer)runtime_patch);
            }
        }
        groups++;
    }
    g_strfreev(groups_original);

    g_key_file_free(gkf);
    return 0;
}

task_t *get_task(void)
{
    pid_t tid = syscall(__NR_gettid);
    task_t *task = NULL;

    // FIXME: we should protect this with a lock
    for (int i = 0; i < MAX_TASKS; i++)
    {
        if (tasks[i].tid == tid)
        {
            task = &tasks[i];
            break;
        }
    }

    if (task == NULL)
        tcg_abort();

    return task;
}

void hybrid_syscall_handler(int mysignal, siginfo_t *si, void *arg);
extern void restore_qemu_context(CpuContext *context);

void save_native_context_clobber_syscall(uint64_t rsp, uint64_t *save_area);
void save_native_context_clobber_syscall(uint64_t rsp, uint64_t *save_area)
{
    task_t *task = get_task();

    uint64_t fs_base;
    arch_prctl(ARCH_GET_FS, (uint64_t)&fs_base);

    arch_prctl(ARCH_SET_FS, task->qemu_context->fs_base);

#if 0
    printf("Handler #2: fs_base=%lx fs_base_qemu=%lx\n", fs_base, task->qemu_context->fs_base);
    printf("*(rsp) = %lx\n", *((uint64_t*) rsp));
    printf("*(rsp - 8) = %lx\n", *((uint64_t*) (rsp - 8)));
#endif

    CpuContext *context = task->native_context;
    *((uint64_t *)(rsp - 8)) = (uint64_t)context;

    // general purpose registers
    context->gpr[SLOT_RAX] = save_area[0];
    context->gpr[SLOT_RBX] = save_area[-1];
    context->gpr[SLOT_RCX] = save_area[-2];
    context->gpr[SLOT_RDX] = save_area[-3];
    context->gpr[SLOT_RSI] = save_area[-4];
    context->gpr[SLOT_RDI] = save_area[-5];
    context->gpr[SLOT_RBP] = save_area[-6];
    context->gpr[SLOT_R8] = save_area[-7];
    context->gpr[SLOT_R9] = save_area[-8];
    context->gpr[SLOT_R10] = save_area[-9];
    context->gpr[SLOT_R11] = save_area[-10];
    context->gpr[SLOT_R12] = save_area[-11];
    context->gpr[SLOT_R13] = save_area[-12];
    context->gpr[SLOT_R14] = save_area[-13];
    context->gpr[SLOT_R15] = save_area[-14];
    context->gpr[SLOT_RSP] = rsp;

    // flags
    context->flags = save_area[-15];

    // fs base
    context->fs_base = fs_base;

    // program counter: return address
    context->pc = *(((uint64_t *)rsp));

    // valid flag
    context->valid = 1;

    {
// CPUState *cpu = ENV_GET_CPU(task->emulated_state);
// TaskState *ts = cpu->opaque;
// atomic_xchg(&((TaskState *)thread_cpu->opaque)->signal_pending, 0);
// process_pending_signals(task->emulated_state);
#if 0
        TaskState * ts1 = (TaskState *)thread_cpu->opaque;

        CPUState *cpu = ENV_GET_CPU(task->emulated_state);
        TaskState *ts2 = cpu->opaque;

        if (ts1 != ts2) {
            printf("INCONSISTENT: [%lx] T1=%x T2=%x [state=%p]\n", task->tid, ts1->ts_tid, ts2->ts_tid, task->emulated_state);
            tcg_abort();
        } else {
            // printf("CONSISTENT: [%lx] T1=%x T2=%x [state=%p]\n", task->tid, ts1->ts_tid, ts2->ts_tid, task->emulated_state);
        }
#endif
    }

    switch (save_area[0])
    {
    case TARGET_NR_clone:
    {
        // printf("clone()\n");
        // we have to update the emulated state because
        // it will be copied into the cloned cpu
        task->emulated_state->eip = context->pc;
        task->emulated_state->regs[SLOT_RAX] = context->gpr[SLOT_RAX];
        task->emulated_state->regs[SLOT_RBX] = context->gpr[SLOT_RBX];
        task->emulated_state->regs[SLOT_RCX] = context->gpr[SLOT_RCX];
        task->emulated_state->regs[SLOT_RDX] = context->gpr[SLOT_RDX];
        task->emulated_state->regs[SLOT_RDI] = context->gpr[SLOT_RDI];
        task->emulated_state->regs[SLOT_RSI] = context->gpr[SLOT_RSI];
        task->emulated_state->regs[SLOT_RSP] = context->gpr[SLOT_RSP];
        task->emulated_state->regs[SLOT_RBP] = context->gpr[SLOT_RBP];
        task->emulated_state->regs[SLOT_R9] = context->gpr[SLOT_R9];
        task->emulated_state->regs[SLOT_R10] = context->gpr[SLOT_R10];
        task->emulated_state->regs[SLOT_R11] = context->gpr[SLOT_R11];
        task->emulated_state->regs[SLOT_R12] = context->gpr[SLOT_R12];
        task->emulated_state->regs[SLOT_R13] = context->gpr[SLOT_R13];
        task->emulated_state->regs[SLOT_R14] = context->gpr[SLOT_R14];
        task->emulated_state->regs[SLOT_R15] = context->gpr[SLOT_R15];
        task->emulated_state->eflags = context->flags;
        break;
    }

    case TARGET_NR_exit:
    {
        // printf("EXITING...\n");

        // we cannot execute the exit from the native context
        // because QEMU may call pthread_exit that will
        // try to unwind the stack, failing because
        // we are not working on the stack built
        // by pthread_create. We need to switch back
        // to the qemu context and then we can
        // execute the exit.

        task->emulated_state->eip = context->pc;
        task->emulated_state->regs[SLOT_RAX] = context->gpr[SLOT_RAX];
        task->emulated_state->regs[SLOT_RBX] = context->gpr[SLOT_RBX];
        task->emulated_state->regs[SLOT_RCX] = context->gpr[SLOT_RCX];
        task->emulated_state->regs[SLOT_RDX] = context->gpr[SLOT_RDX];
        task->emulated_state->regs[SLOT_RDI] = context->gpr[SLOT_RDI];
        task->emulated_state->regs[SLOT_RSI] = context->gpr[SLOT_RSI];
        task->emulated_state->regs[SLOT_RSP] = context->gpr[SLOT_RSP];
        task->emulated_state->regs[SLOT_RBP] = context->gpr[SLOT_RBP];
        task->emulated_state->regs[SLOT_R9] = context->gpr[SLOT_R9];
        task->emulated_state->regs[SLOT_R10] = context->gpr[SLOT_R10];
        task->emulated_state->regs[SLOT_R11] = context->gpr[SLOT_R11];
        task->emulated_state->regs[SLOT_R12] = context->gpr[SLOT_R12];
        task->emulated_state->regs[SLOT_R13] = context->gpr[SLOT_R13];
        task->emulated_state->regs[SLOT_R14] = context->gpr[SLOT_R14];
        task->emulated_state->regs[SLOT_R15] = context->gpr[SLOT_R15];
        task->emulated_state->eflags = context->flags;

        task->must_exit = 1;
        restore_qemu_context(task->qemu_context);
        break;
    }

    default:
        break;
    }

    for (int i = 0; i < 10; i++)
    {
        task->is_native = 1;
        // printf("[%lx] DO_SYSCALL: %ld\n", task->tid, save_area[0]);
        uint64_t ret = do_syscall(task->emulated_state,
                                  save_area[0],  // env->regs[R_EAX],
                                  save_area[-5], // env->regs[R_EDI],
                                  save_area[-4], // env->regs[R_ESI],
                                  save_area[-3], // env->regs[R_EDX],
                                  save_area[-9], // env->regs[10],
                                  save_area[-7], // env->regs[8],
                                  save_area[-8], // env->regs[9],
                                  0, 0);
        task->is_native = 0;
        context->gpr[SLOT_RAX] = ret;

        if (TARGET_NR_write == save_area[0] && ret == -512)
        {
            // const char* str = "test\n";
            // write(2, str, sizeof(str));
            continue;
        }
        else
            break;

        break;
    }

    switch (save_area[0])
    {
    case TARGET_NR_rt_sigaction:
    {
#if 1
        // printf("\n[%lx] ENABLING SIGNALS AFTER SIGACTION\n\n", task->tid);
        // CPUState *cpu = ENV_GET_CPU(task->emulated_state);
        // TaskState *ts = cpu->opaque;
        // atomic_xchg(&ts->signal_pending, 1);
        process_pending_signals(task->emulated_state);
// atomic_xchg(&ts->signal_pending, 0);
#endif
        break;
    }

    default:
        break;
    }

    struct sigaction action;
    action.sa_sigaction = &hybrid_syscall_handler;
    action.sa_flags = SA_SIGINFO | SA_RESTART;
    sigaction(SIGILL, &action, &task->qemu_context->sigill_handler);

    // restore fsbase to avoid canary check failure...
    arch_prctl(ARCH_SET_FS, fs_base);
}

void save_native_context_safe_syscall(void);
void hybrid_syscall_handler(int mysignal, siginfo_t *si, void *arg)
{
    ucontext_t *context = (ucontext_t *)arg;
    context->uc_mcontext.gregs[REG_RSP] = context->uc_mcontext.gregs[REG_RSP] - 8;
    *((uint64_t *)context->uc_mcontext.gregs[REG_RSP]) = context->uc_mcontext.gregs[REG_RIP] + 0x2;
    context->uc_mcontext.gregs[REG_RIP] = (uint64_t)&save_native_context_safe_syscall;

    return;
#if 0
    task_t *task = get_task();

    uint64_t fs_base;
    arch_prctl(ARCH_GET_FS, (uint64_t)&fs_base);

    arch_prctl(ARCH_SET_FS, task->qemu_context->fs_base);
    printf("Handler\n");

    ucontext_t *context = (ucontext_t *)arg;
    printf("[%lx] Address from where crash happen is %llx\n", task->tid, context->uc_mcontext.gregs[REG_RIP]);

    uint8_t *bytes = (uint8_t *)(context->uc_mcontext.gregs[REG_RIP]);
    if (!(bytes[0] == 0x0f && bytes[1] == 0x0b))
        tcg_abort();

    if (context->uc_mcontext.gregs[REG_RIP] != (uint64_t)si->si_addr)
        tcg_abort();

    if (si->si_code != ILL_ILLOPC && si->si_code != ILL_ILLOPN)
        tcg_abort();

    context->uc_mcontext.gregs[REG_RIP] = context->uc_mcontext.gregs[REG_RIP] + 0x02;

    uint64_t syscall_no = context->uc_mcontext.gregs[REG_RAX];
    switch (syscall_no)
    {
    case TARGET_NR_clone:
    {
        // we have to update the emulated state because
        // it will be copied into the cloned cpu
        task->emulated_state->eip = context->uc_mcontext.gregs[REG_RIP];
        task->emulated_state->regs[SLOT_RAX] = context->uc_mcontext.gregs[REG_RAX];
        task->emulated_state->regs[SLOT_RBX] = context->uc_mcontext.gregs[REG_RBX];
        task->emulated_state->regs[SLOT_RCX] = context->uc_mcontext.gregs[REG_RCX];
        task->emulated_state->regs[SLOT_RDX] = context->uc_mcontext.gregs[REG_RDX];
        task->emulated_state->regs[SLOT_RDI] = context->uc_mcontext.gregs[REG_RDI];
        task->emulated_state->regs[SLOT_RSI] = context->uc_mcontext.gregs[REG_RSI];
        task->emulated_state->regs[SLOT_RSP] = context->uc_mcontext.gregs[REG_RSP];
        task->emulated_state->regs[SLOT_RBP] = context->uc_mcontext.gregs[REG_RBP];
        task->emulated_state->regs[SLOT_R9] = context->uc_mcontext.gregs[REG_R9];
        task->emulated_state->regs[SLOT_R10] = context->uc_mcontext.gregs[REG_R10];
        task->emulated_state->regs[SLOT_R11] = context->uc_mcontext.gregs[REG_R11];
        task->emulated_state->regs[SLOT_R12] = context->uc_mcontext.gregs[REG_R12];
        task->emulated_state->regs[SLOT_R13] = context->uc_mcontext.gregs[REG_R13];
        task->emulated_state->regs[SLOT_R14] = context->uc_mcontext.gregs[REG_R14];
        task->emulated_state->regs[SLOT_R15] = context->uc_mcontext.gregs[REG_R15];
        task->emulated_state->eflags = context->uc_mcontext.gregs[REG_EFL];
        break;
    }
    default:
        break;
    }

    task->is_native = 1;
    uint64_t ret = do_syscall(task->emulated_state,
                              context->uc_mcontext.gregs[REG_RAX], // env->regs[R_EAX],
                              context->uc_mcontext.gregs[REG_RDI], // env->regs[R_EDI],
                              context->uc_mcontext.gregs[REG_RSI], // env->regs[R_ESI],
                              context->uc_mcontext.gregs[REG_RDX], // env->regs[R_EDX],
                              context->uc_mcontext.gregs[REG_R10], // env->regs[10],
                              context->uc_mcontext.gregs[REG_R8],  // env->regs[8],
                              context->uc_mcontext.gregs[REG_R9],  // env->regs[9],
                              0, 0);
    task->is_native = 0;

    printf("SYSCALL %lx DONE: %lx\n", syscall_no, ret);
    printf("NATIVE PC: %llx\n", context->uc_mcontext.gregs[REG_RIP]);

    context->uc_mcontext.gregs[REG_RAX] = ret;

    arch_prctl(ARCH_SET_FS, fs_base);
#endif
}

static task_t *hybrid_new_task(uint64_t tid)
{
    CpuContext *native_context = g_malloc0(sizeof(CpuContext));
    CpuContext *emulated_context = g_malloc0(sizeof(CpuContext));
    CpuContext *qemu_context = g_malloc0(sizeof(CpuContext));

    // FIXME: we should protect this with a lock
    for (int i = 0; i < MAX_TASKS; i++)
    {
        if (tasks[i].tid == 0)
        {
            tasks[i].tid = tid;
            tasks[i].native_context = native_context;
            tasks[i].emulated_context = emulated_context;
            tasks[i].qemu_context = qemu_context;
            return &tasks[i];
        }
    }

    tcg_abort();
    return NULL;
}

void hybrid_new_thread(uint64_t tid, CPUX86State *state)
{
    task_t *task = get_task();
    assert(task->is_native); // ToDo

    task_t *new_task = hybrid_new_task(tid);
    new_task->is_native = 1;
    new_task->emulated_state = state;

    // printf("THREAD EIP: %lx\n", state->eip);

    uint64_t fs_base;
    arch_prctl(ARCH_GET_FS, (uint64_t)&fs_base);
    // printf("PARENT QEMU FSBASE: %lx\n", fs_base);
}

void hybrid_set_sigill_handler(void)
{
    task_t *task = get_task();
    struct sigaction action;
    action.sa_sigaction = &hybrid_syscall_handler;
    action.sa_flags = SA_SIGINFO | SA_RESTART;
    sigaction(SIGILL, &action, &task->qemu_context->sigill_handler);

    uint64_t fs_base;
    arch_prctl(ARCH_GET_FS, (uint64_t)&fs_base);
    // printf("CHILD QEMU FSBASE: %lx\n", fs_base);
}

int hybrid_is_task_native(void)
{
    task_t *task = get_task();
    if (task)
    {
        int is_native = task->is_native;
        task->is_native = 0;
        return is_native;
    }
    return 0;
}

#if 0

extern void save_qemu_context_safe(CpuContext* qemu_context);
__asm__(
    ".globl save_qemu_context_safe\n\t"
    //
    ".type func, @function\n\t"
    "save_qemu_context_safe:\n\t"
    ".cfi_startproc\n\t"
    //
    "leaq -8(%rsp), %rsp"
    "\n\t"
// #define CONTEXT qemu_cpu_context
#include "save_context.h"
// #undef CONTEXT
    //
    "leaq 8(%rsp), %rsp"
    "\n\t"
    "ret\n\t"
    //
    ".cfi_endproc");

#else

void save_qemu_context_clobber(uint64_t rsp, uint64_t *save_area);
void save_qemu_context_clobber(uint64_t rsp, uint64_t *save_area)
{
    task_t *task = get_task();
    CpuContext *context = task->qemu_context;

    // general purpose registers
    context->gpr[SLOT_RAX] = save_area[0];
    context->gpr[SLOT_RBX] = save_area[-1];
    context->gpr[SLOT_RCX] = save_area[-2];
    context->gpr[SLOT_RDX] = save_area[-3];
    context->gpr[SLOT_RSI] = save_area[-4];
    context->gpr[SLOT_RDI] = save_area[-5];
    context->gpr[SLOT_RBP] = save_area[-6];
    context->gpr[SLOT_R8] = save_area[-7];
    context->gpr[SLOT_R9] = save_area[-8];
    context->gpr[SLOT_R10] = save_area[-9];
    context->gpr[SLOT_R11] = save_area[-10];
    context->gpr[SLOT_R12] = save_area[-11];
    context->gpr[SLOT_R13] = save_area[-12];
    context->gpr[SLOT_R14] = save_area[-13];
    context->gpr[SLOT_R15] = save_area[-14];
    context->gpr[SLOT_RSP] = rsp;

    // flags
    context->flags = save_area[-15];

    // fs base
    arch_prctl(ARCH_GET_FS, (uint64_t)&context->fs_base);

    // program counter: return address
    context->pc = *(((uint64_t *)rsp));

    // valid flag
    context->valid = 1;
}

void save_qemu_context_safe(void);
__asm__(
    ".globl save_qemu_context_safe\n"
    //
    ".type func, @function\n"
    "save_qemu_context_safe:\n"
    ".cfi_startproc\n\t"
    "leaq -8(%rsp), %rsp\n"
#define SAVE_ROUTINE save_qemu_context_clobber
#include "save_context_safe.h"
#undef SAVE_ROUTINE
    //
    "leaq 8(%rsp), %rsp\n"
    "ret\n"
    //
    ".cfi_endproc");
#endif

#if 0
__asm__(
    ".globl save_native_context_safe2\n\t"
    //
    ".type func, @function\n\t"
    "save_native_context_safe2:\n\t"
    ".cfi_startproc\n\t"
//
#define CONTEXT native_cpu_context
#include "save_context.h"
#undef CONTEXT
    //
    "popq %rdi"
    "\n\t" // plt entry index
    "call switch_to_emulated\n\t"
    //
    ".cfi_endproc");
#endif

void save_native_context_clobber(uint64_t rsp, uint64_t *save_area);
void save_native_context_clobber(uint64_t rsp, uint64_t *save_area)
{
    task_t *task = get_task();
    CpuContext *context = task->native_context;

    // general purpose registers
    context->gpr[SLOT_RAX] = save_area[0];
    context->gpr[SLOT_RBX] = save_area[-1];
    context->gpr[SLOT_RCX] = save_area[-2];
    context->gpr[SLOT_RDX] = save_area[-3];
    context->gpr[SLOT_RSI] = save_area[-4];
    context->gpr[SLOT_RDI] = save_area[-5];
    context->gpr[SLOT_RBP] = save_area[-6];
    context->gpr[SLOT_R8] = save_area[-7];
    context->gpr[SLOT_R9] = save_area[-8];
    context->gpr[SLOT_R10] = save_area[-9];
    context->gpr[SLOT_R11] = save_area[-10];
    context->gpr[SLOT_R12] = save_area[-11];
    context->gpr[SLOT_R13] = save_area[-12];
    context->gpr[SLOT_R14] = save_area[-13];
    context->gpr[SLOT_R15] = save_area[-14];
    context->gpr[SLOT_RSP] = rsp;

    // flags
    context->flags = save_area[-15];

    // fs base
    arch_prctl(ARCH_GET_FS, (uint64_t)&context->fs_base);

    // program counter: return address
    context->pc = *(((uint64_t *)rsp));

    // valid flag
    context->valid = 1;

    // arch_prctl(ARCH_SET_FS, (uint64_t) task->qemu_context->fs_base);
    for (int i = 0; i < 8; i++)
    {
        task->emulated_state->xmm_regs[i]._q_ZMMReg[0] = save_area[-17 - (2 * i)];
        task->emulated_state->xmm_regs[i]._q_ZMMReg[1] = save_area[-18 - (2 * i)];
    }
    // arch_prctl(ARCH_SET_FS, (uint64_t) context->fs_base);
}

void save_native_context_safe(void);
__asm__(
    ".globl save_native_context_safe\n"
    //
    ".type func, @function\n"
    "save_native_context_safe:\n"
    ".cfi_startproc\n\t"
#define PRESERVE_XMM
#define SAVE_ROUTINE save_native_context_clobber
#include "save_context_safe.h"
#undef SAVE_ROUTINE
#undef PRESERVE_XMM
    //
    "popq %rdi\n" // plt entry index
    "call switch_to_emulated\n"
    //
    ".cfi_endproc");

__asm__(
    ".globl save_native_context_safe_syscall\n"
    //
    ".type func, @function\n"
    "save_native_context_safe_syscall:\n"
    ".cfi_startproc\n\t"
    "pushq $0\n" // native context
// #define PRESERVE_XMM
// #define RESTORE_XMM
#define SAVE_ROUTINE save_native_context_clobber_syscall
#include "save_context_safe.h"
#undef SAVE_ROUTINE
    // #undef PRESERVE_XMM
    // #undef RESTORE_XMM
    //
    "popq %rdi\n"
//
#include "restore_context.h"
    //
    "ret\n\t"
    //
    ".cfi_endproc");

static void save_emulated_context(CPUX86State *state, int skip_eip)
{
    int i;

    task_t *task = get_task();
    CpuContext *emulated_cpu_context = task->emulated_context;

    // general purpose registers
    assert(CPU_NB_REGS == SLOT_GPR_END);
    for (i = 0; i < SLOT_GPR_END; i++)
        emulated_cpu_context->gpr[i] = state->regs[i];

    // flags
    emulated_cpu_context->flags = state->eflags;

    // segment registers
    assert(SLOT_SEGR_END == 6);
    for (i = 0; i < SLOT_SEGR_END; i++)
        emulated_cpu_context->seg[i] = state->segs[i].selector;

    // fs base
    emulated_cpu_context->fs_base = state->segs[R_FS].base;

    // pc
    if (!skip_eip)
        emulated_cpu_context->pc = state->eip;
}

static void restore_emulated_context(CpuContext *context, CPUX86State *state)
{
    int i;

    // general purpose registers
    assert(CPU_NB_REGS == SLOT_GPR_END);
    for (i = 0; i < SLOT_GPR_END; i++)
        state->regs[i] = context->gpr[i];

    // flags
    state->eflags = context->flags;

    // segment registers
    assert(SLOT_SEGR_END == 6);
    for (i = 0; i < SLOT_SEGR_END; i++)
        state->segs[i].selector = context->seg[i];

    // fs base
    state->segs[R_FS].base = context->fs_base;
}

extern void restore_native_context(CpuContext *context, uint64_t target);
__asm__(
    ".globl restore_native_context\n\t"
    //
    ".type func, @function\n\t"
    "restore_native_context:\n\t"
    ".cfi_startproc\n\t"
//
#define RESTORE_ADD_SLOT_STACK
#include "restore_context.h"
#undef RESTORE_ADD_SLOT_STACK
    //
    "ret\n\t"
    //
    ".cfi_endproc");

__asm__(
    ".globl restore_qemu_context\n\t"
    //
    ".type func, @function\n\t"
    "restore_qemu_context:\n\t"
    ".cfi_startproc\n\t"
//
//
#include "restore_context.h"
    //
    "ret\n\t"
    //
    ".cfi_endproc");

extern void dummy_plt_stub(void);
__asm__(
    ".globl dummy_plt_stub\n\t"
    //
    // ".type func, @function\n\t"
    "dummy_plt_stub:\n\t"
    // ".cfi_startproc\n\t"
    //
    "pushq $0xCAFE"
    "\n\t"
    "jmp save_native_context_safe"
    "\n\t"
    //
    // ".cfi_endproc"
);

typedef struct
{
    uint64_t addr;
    uint64_t arg6;
    uint64_t arg5;
    uint64_t arg4;
    uint64_t arg3;
    uint64_t arg2;
    uint64_t arg1;
} runtime_stub_args_t;

extern void dummy_runtime_plt_stub(void);
__asm__(
    ".globl dummy_runtime_plt_stub\n\t"
    //
    // ".type func, @function\n\t"
    "dummy_runtime_plt_stub:\n\t"
    // ".cfi_startproc\n\t"
    //
    "pushq %rdi\n\t"
    "pushq %rsi\n\t"
    "pushq %rdx\n\t"
    "pushq %rcx\n\t"
    "pushq %r8\n\t"
    "pushq %r9\n\t"
    "movabsq $0xCAFECAFECAFECAFE, %rdi\n"
    "pushq %rdi\n"
    "movq %rsp, %rdi\n\t"
    "call save_native_context_safe\n\t"
    "leaq 56(%rsp), %rsp\n\t"
    "ret"
    //
    // ".cfi_endproc"
);

void return_handler_from_emulation(void)
{
    assert(0 && "Thos should never be executed since QEMU should intercept it.");
}

void switch_to_emulated(int plt_entry)
{
    // printf("Switching to emulated\n...");

    task_t *task = get_task();
    restore_emulated_context(task->native_context, task->emulated_state);

    // swap return address
    uint64_t *ret_addr = (uint64_t *)task->emulated_state->regs[SLOT_RSP];
    task->native_context->pc = *(ret_addr);
    *(ret_addr) = (uint64_t)return_handler_from_emulation;
    assert(plt_entry >= 0 && plt_entry < plt_stubs_count);
    task->emulated_state->eip = shadow_plt[plt_entry];

    uint64_t base;
    arch_prctl(ARCH_GET_FS, (uint64_t)&base);
    arch_prctl(ARCH_SET_FS, (uint64_t)task->qemu_context->fs_base);
    _sym_notify_call((uint64_t)return_handler_from_emulation);
    arch_prctl(ARCH_SET_FS, base);

    // return into QEMU
#if 0
    // we cannot restore handler from QEMU
    // since handlers are per process and not per thread
    // hence we may need our handler for a parallel
    // thread in native mode
    //
    // sigaction(SIGILL, &task->qemu_context->sigill_handler, NULL);
#endif
    restore_qemu_context(task->qemu_context);
}

#define PAGE_ALIGNED(addr)            \
    ((void *)((unsigned long)(addr) - \
              ((unsigned long)(addr) & (getpagesize() - 1UL))))
#define PAGE_ALIGNED_SIZE(addr, size)                            \
    (((size + ((unsigned long)(addr) & (getpagesize() - 1UL))) / \
          getpagesize() +                                        \
      1) *                                                       \
     (getpagesize()))

#define PLT_STUBS_SIZE 1024 * 1024 // 1 MiB
static uint8_t plt_stubs[PLT_STUBS_SIZE];
static uint8_t runtime_plt_stubs[PLT_STUBS_SIZE];

//__thread
int hybrid_init_done = 0;
void hybrid_init(void)
{
    if (hybrid_init_done)
        return;

    printf("DOING INIT\n");

    char *res = getenv("HYBRID_CONF_FILE");
    if (res)
        parse_config_file(res);

    pid_t tid = syscall(__NR_gettid);

    hybrid_new_task(tid);

    assert(start_addr);
    hybrid_init_done = 1;
}

#define SymExpr void *
#include "RuntimeCommon.h"

#define RUNTIME_FN_PTR(name, f)                       \
    if (strcmp(name, #f) == 0)                        \
    {                                                 \
        printf("Runtime function %s: %p\n", name, f); \
        return (uint64_t)&f;                          \
    }

int memcmp_symbolized(const void *a, const void *b, size_t n);
char *strncpy_symbolized(char *dest, const char *src, size_t n);
const char *strchr_symbolized(const char *s, int c);

static uint64_t get_runtime_function_addr(char *name)
{
    if (strcmp(name, "fread_symbolized") == 0)
    {
        tcg_abort();
    }
    if (strcmp(name, "fopen_symbolized") == 0)
    {
        tcg_abort();
    }

    RUNTIME_FN_PTR(name, _sym_notify_basic_block);
    RUNTIME_FN_PTR(name, _sym_build_equal);
    RUNTIME_FN_PTR(name, _sym_build_mul);
    RUNTIME_FN_PTR(name, _sym_build_integer);
    RUNTIME_FN_PTR(name, _sym_notify_call);
    RUNTIME_FN_PTR(name, _sym_notify_ret);
    RUNTIME_FN_PTR(name, _sym_read_memory);
    RUNTIME_FN_PTR(name, _sym_write_memory);
    RUNTIME_FN_PTR(name, _sym_get_return_expression);
    RUNTIME_FN_PTR(name, _sym_set_return_expression);
    RUNTIME_FN_PTR(name, _sym_push_path_constraint);
    RUNTIME_FN_PTR(name, _sym_build_not_equal);
    RUNTIME_FN_PTR(name, _sym_build_add);
    RUNTIME_FN_PTR(name, _sym_build_null_pointer);
    RUNTIME_FN_PTR(name, _sym_build_sext);
    RUNTIME_FN_PTR(name, _sym_get_parameter_expression);
    RUNTIME_FN_PTR(name, _sym_set_parameter_expression);
    RUNTIME_FN_PTR(name, _sym_build_signed_greater_than);
    RUNTIME_FN_PTR(name, _sym_build_signed_less_than);
    RUNTIME_FN_PTR(name, _sym_build_trunc);
    RUNTIME_FN_PTR(name, _sym_build_and);
    RUNTIME_FN_PTR(name, _sym_get_return_expression_with_truncate);
    RUNTIME_FN_PTR(name, _sym_set_int_parameter_expression);
    RUNTIME_FN_PTR(name, _sym_is_int_parameter);
    RUNTIME_FN_PTR(name, _sym_set_args_count);
    RUNTIME_FN_PTR(name, _sym_build_arithmetic_shift_right);
    RUNTIME_FN_PTR(name, _sym_build_shift_left);
    RUNTIME_FN_PTR(name, _sym_build_float_to_float);
    RUNTIME_FN_PTR(name, _sym_build_unsigned_rem);
    RUNTIME_FN_PTR(name, _sym_build_signed_less_equal);
    RUNTIME_FN_PTR(name, _sym_build_signed_greater_equal);
    RUNTIME_FN_PTR(name, _sym_build_unsigned_greater_equal);
    RUNTIME_FN_PTR(name, _sym_build_bool_xor);
    RUNTIME_FN_PTR(name, _sym_build_xor);
    RUNTIME_FN_PTR(name, _sym_build_unsigned_less_than);
    RUNTIME_FN_PTR(name, _sym_build_bool);
    RUNTIME_FN_PTR(name, _sym_build_unsigned_greater_than);
    RUNTIME_FN_PTR(name, _sym_build_bool_to_bits);
    RUNTIME_FN_PTR(name, _sym_build_sub);
    RUNTIME_FN_PTR(name, _sym_build_zext);
    RUNTIME_FN_PTR(name, _sym_build_or);
    RUNTIME_FN_PTR(name, _sym_build_unsigned_div);
    RUNTIME_FN_PTR(name, _sym_build_logical_shift_right);
    RUNTIME_FN_PTR(name, _sym_memcpy);
    RUNTIME_FN_PTR(name, _sym_build_unsigned_less_equal);
    RUNTIME_FN_PTR(name, _sym_build_signed_rem);
    RUNTIME_FN_PTR(name, _sym_print_path_constraints);
    RUNTIME_FN_PTR(name, _sym_debug_function_after_return);
    RUNTIME_FN_PTR(name, _sym_build_equal);
    RUNTIME_FN_PTR(name, _sym_memmove);
    RUNTIME_FN_PTR(name, memcmp_symbolized);
    RUNTIME_FN_PTR(name, _sym_build_fp_div);
    RUNTIME_FN_PTR(name, _sym_memset);
    RUNTIME_FN_PTR(name, _sym_build_signed_div);
    RUNTIME_FN_PTR(name, _sym_build_int_to_float);
    RUNTIME_FN_PTR(name, _sym_build_float_to_bits);
    RUNTIME_FN_PTR(name, _sym_build_float_to_unsigned_integer);
    RUNTIME_FN_PTR(name, _sym_build_bool_or);
    RUNTIME_FN_PTR(name, _sym_build_extract);
    RUNTIME_FN_PTR(name, strncpy_symbolized);
    RUNTIME_FN_PTR(name, _sym_build_bswap);
    RUNTIME_FN_PTR(name, strchr_symbolized);
    RUNTIME_FN_PTR(name, _sym_build_bits_to_float);
    RUNTIME_FN_PTR(name, _sym_build_fp_mul);
    RUNTIME_FN_PTR(name, _sym_build_float);
    RUNTIME_FN_PTR(name, _sym_build_bool_and);
    RUNTIME_FN_PTR(name, _sym_libc_memmove);
    RUNTIME_FN_PTR(name, _sym_libc_memset);
    RUNTIME_FN_PTR(name, _sym_libc_memcpy);
    RUNTIME_FN_PTR(name, _sym_build_float_to_signed_integer);
    RUNTIME_FN_PTR(name, _sym_build_fp_add);
    RUNTIME_FN_PTR(name, _sym_build_float_unordered_not_equal);

    printf("%s\n", name);
    tcg_abort();
    return 0;
}

static uint64_t runtime_function_handler(runtime_stub_args_t *args)
{
    task_t *task = get_task();
    uint64_t base;
    arch_prctl(ARCH_GET_FS, (uint64_t)&base);
    arch_prctl(ARCH_SET_FS, (uint64_t)task->qemu_context->fs_base);
    // printf("FN %lx: arg1=%lx, arg2=%lx, arg3=%lx\n", args->addr, args->arg1, args->arg2, args->arg3);
    if (args->addr == 0)
        tcg_abort();
    uint64_t (*f)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t) = (uint64_t(*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t))args->addr;

    uint64_t res = f(args->arg1, args->arg2, args->arg3, args->arg4, args->arg5, args->arg6);
    arch_prctl(ARCH_SET_FS, base);
    return res;
}

static inline TCGTemp *tcg_find_temp_arch_reg(const char *reg_name)
{
    for (int i = 0; i < TCG_TARGET_NB_REGS; i++)
    {
        TCGTemp *t = &tcg_ctx->temps[i];
        if (t->fixed_reg)
            continue; // not a register
        if (strcmp(t->name, reg_name) == 0)
            return t;
    }
    // printf("Cannot find TCG for %s\n", reg_name);
    // tcg_abort();
    return NULL;
}

static int reached_start = 0;

void *get_temp_expr(const char* temp_name);
void *get_temp_expr(const char* temp_name)
{
    if (!reached_start)
        return NULL;

    task_t *task = get_task();
    TCGTemp *ret_val_ts = tcg_find_temp_arch_reg(temp_name);
    if (ret_val_ts == NULL)
        return NULL;

    assert(ret_val_ts->symbolic_expression == 1);
    assert(ret_val_ts->mem_coherent == 1);
    assert(ret_val_ts->val_type == TEMP_VAL_MEM);
    uint64_t **ret_val_expr = (uint64_t **)((uint64_t)ret_val_ts->mem_offset + (uint64_t)task->emulated_state);
    if (*ret_val_expr)
    {
        size_t current_bits = _sym_bits_helper(*ret_val_expr);
        if (current_bits < 64)
        {
            *ret_val_expr = _sym_build_zext(*ret_val_expr, 64 - current_bits);
        }
        const char *s_expr = _sym_expr_to_string(*ret_val_expr);
        printf("%s: len=%ld %s\n", temp_name, current_bits, s_expr);
    }
    return *ret_val_expr;
}

void switch_to_native(uint64_t target, CPUX86State *state)
{
    assert(hybrid_init_done);
    reached_start = 1;

    task_t *task = get_task();
    CpuContext *native_cpu_context = task->native_context;

    task->emulated_state = state;

    // uint64_t original_target = target;

    int from_emulation = 0;
    if (target == (uint64_t)return_handler_from_emulation)
    {
        target = native_cpu_context->pc;
        task->emulated_context->pc = native_cpu_context->pc;
        from_emulation = 1;
    }
    printf("Switching to native: 0x%lx...\n", target);

    // patch PLTs && syscall insns
    if (target == start_addr)
    {
        mprotect(PAGE_ALIGNED(plt_stubs), PAGE_ALIGNED_SIZE(plt_stubs, sizeof(plt_stubs)),
                 PROT_EXEC | PROT_READ | PROT_WRITE);
        mprotect(PAGE_ALIGNED(runtime_plt_stubs), PAGE_ALIGNED_SIZE(runtime_plt_stubs, sizeof(runtime_plt_stubs)),
                 PROT_EXEC | PROT_READ | PROT_WRITE);

        GSList *next = plt_aliases;
        while (next != NULL)
        {
            plt_alias_t *plt_alias = next->data;
            next = g_slist_next(next);

            uint64_t base_address = 0x0;
            GSList *next_mmaped_file = mmaped_files;
            int mmaped_file_found = 0;
            while (next_mmaped_file != NULL)
            {
                mmap_file_t *mmaped_file = (mmap_file_t *)next_mmaped_file->data;
                next_mmaped_file = g_slist_next(next_mmaped_file);

                if (strcmp(mmaped_file->name, plt_alias->from_obj) == 0)
                {
                    mmaped_file_found = 1;
                    base_address = mmaped_file->addr;
                    break;
                }
            }

            uint64_t addr = base_address + plt_alias->from_got_entry;
            printf("base address: %lx\n", base_address);
            printf("GOT entry %lx: %lx %lx %lx\n", base_address + plt_alias->from_got_entry,
                   *((uint64_t *)addr),
                   plt_alias->to_plt_entry,
                   *((uint64_t *)plt_alias->to_got_entry));

            if (*((uint64_t *)addr) == plt_alias->to_plt_entry)
            {
                uint8_t *a = PAGE_ALIGNED(addr);
                mprotect(a, getpagesize(), PROT_EXEC | PROT_READ | PROT_WRITE);
                *((uint64_t *)addr) = *((uint64_t *)plt_alias->to_got_entry);
            }
        }

        uint8_t *plt_stub = (uint8_t *)&plt_stubs;
        next = plt_patches;
        while (next != NULL)
        {
            plt_patch_t *patch = next->data;
            char *name = patch->name;
            next = g_slist_next(next);
            uint64_t base_address = 0x0;
            int is_main_image = strcmp(name, "main_image") == 0;
            if (!is_main_image)
            {
                GSList *next_mmaped_file = mmaped_files;
                int mmaped_file_found = 0;
                while (next_mmaped_file != NULL)
                {
                    mmap_file_t *mmaped_file = (mmap_file_t *)next_mmaped_file->data;
                    next_mmaped_file = g_slist_next(next_mmaped_file);

                    if (strcmp(mmaped_file->name, patch->name) == 0)
                    {
                        mmaped_file_found = 1;
                        base_address = mmaped_file->addr;
                        break;
                    }
                }
                if (!mmaped_file_found)
                {
                    printf("PLT PATCH ON %s NOT FOUND\n", patch->name);
                    tcg_abort();
                }
            }

            GSList *offsets = patch->offsets;
            while (offsets != NULL)
            {
                uint64_t offset = (uint64_t)offsets->data;
                printf("[%s] BASE=%lx OFFSET: %lx\n", name, base_address, offset);
                offsets = g_slist_next(offsets);

                void **plt = (void **)(base_address + offset);

                memcpy(plt_stub, dummy_plt_stub, 16);

                assert(plt_stub[0] == 0x68);                   // push opcode
                *((uint16_t *)&plt_stub[1]) = plt_stubs_count; // pushed constant

                assert(plt_stub[5] == 0xe9); // relative jump
                uint64_t rip = (uint64_t)&plt_stub[10];
                uint64_t delta;
                if (((uint64_t)save_native_context_safe) > rip)
                    delta = ((uint64_t)save_native_context_safe) - rip;
                else
                    delta = -(rip - ((uint64_t)save_native_context_safe));

                *((uint32_t *)&plt_stub[6]) = (uint32_t)delta; // relative offset

                printf("[%s] PLT entry %d at %p: %p => %p %p\n", name, plt_stubs_count, &plt[0], plt[0], dummy_plt_stub, plt_stub);
                shadow_plt[plt_stubs_count] = (uint64_t)plt[0];

                uint8_t *a = PAGE_ALIGNED(&plt[0]);
                mprotect(a, getpagesize(), PROT_EXEC | PROT_READ | PROT_WRITE);

                plt[0] = plt_stub;

                plt_stubs_count++;
                plt_stub += 16;
                assert(plt_stubs_count < MAX_PLT_ENTRIES);
                assert(plt_stub < plt_stubs + sizeof(plt_stubs));
            }
        }

        next = syscall_patches;
        while (next != NULL)
        {
            syscall_patch_t *patch = (syscall_patch_t *)next->data;
            next = g_slist_next(next);

            // printf("SYSCALL PATCH ON %s\n", patch->name);

            uint64_t base_address = 0x0;
            if (strcmp("main_image", patch->name) != 0)
            {
                GSList *next_mmaped_file = mmaped_files;
                int mmaped_file_found = 0;
                while (next_mmaped_file != NULL)
                {
                    mmap_file_t *mmaped_file = (mmap_file_t *)next_mmaped_file->data;
                    next_mmaped_file = g_slist_next(next_mmaped_file);

                    if (strcmp(mmaped_file->name, patch->name) == 0)
                    {
                        // printf("SYSCALL PATCH ON %s FOUND\n", patch->name);
                        mmaped_file_found = 1;
                        base_address = mmaped_file->addr;
                        break;
                    }
                }
                if (!mmaped_file_found)
                {
                    printf("SYSCALL PATCH ON %s NOT FOUND\n", patch->name);
                    tcg_abort();
                }
            }

            GSList *syscall_insns = patch->offsets;
            while (syscall_insns != 0)
            {
                uint64_t syscall_insn = (uint64_t)syscall_insns->data;
                syscall_insns = g_slist_next(syscall_insns);

                uint8_t *bytes = (uint8_t *)(base_address + syscall_insn);
                if (bytes[0] == 0x0f && bytes[1] == 0x05)
                {
                    // printf("Found syscall opcodes!\n");
                    uint8_t *a = PAGE_ALIGNED(&bytes[1]);
                    if (a > &bytes[1])
                        tcg_abort();

                    int r = mprotect(a, getpagesize(), PROT_EXEC | PROT_READ | PROT_WRITE);
                    if (r == 0)
                    {
                        // printf("Writing at %p\n", &bytes[1], a);
                        bytes[1] = 0x0b;
                        // printf("Done\n", a);
                    }
                    else
                    {
                        // printf("Failed to make code writable at %p\n", a);
                        tcg_abort();
                    }
                }
                else
                {
                    printf("Cannot find syscall opcodes at 0x%lx + 0x%lx for %s!\n", base_address, syscall_insn, patch->name);
                    printf("[%p] %x\n", &bytes[0], bytes[0]);
                    printf("[%p] %x\n", &bytes[1], bytes[1]);
                    tcg_abort();
                }
            }
        }

        int runtime_stubs_count = 0;
        uint8_t *runtime_stub = (uint8_t *)&runtime_plt_stubs;
        next = runtime_patches;
        while (next != NULL)
        {
            runtime_patch_t *patch = (runtime_patch_t *)next->data;
            next = g_slist_next(next);

            printf("RUNTIME PATCH ON %s\n", patch->name);

            uint64_t base_address = 0x0;
            if (strcmp("main_image", patch->name) != 0)
            {
                GSList *next_mmaped_file = mmaped_files;
                int mmaped_file_found = 0;
                while (next_mmaped_file != NULL)
                {
                    mmap_file_t *mmaped_file = (mmap_file_t *)next_mmaped_file->data;
                    next_mmaped_file = g_slist_next(next_mmaped_file);

                    if (strcmp(mmaped_file->name, patch->name) == 0)
                    {
                        // printf("SYSCALL PATCH ON %s FOUND\n", patch->name);
                        mmaped_file_found = 1;
                        base_address = mmaped_file->addr;
                        break;
                    }
                }
                if (!mmaped_file_found)
                {
                    printf("RUNTIME PATCH ON %s NOT FOUND\n", patch->name);
                    tcg_abort();
                }
            }

            GSList *runtime_plt = patch->patches;
            while (runtime_plt != 0)
            {
                runtime_plt_patch_t *p = (runtime_plt_patch_t *)runtime_plt->data;
                runtime_plt = g_slist_next(runtime_plt);

                if (strcmp("_sym_initialize", p->name) == 0)
                    continue;

                // printf("RUNTIME PATCH FOR FUNCTION %s\n", p->name);

                void **plt = (void **)(base_address + p->offset);

                // printf("[%s] RUNTIME PLT entry %s at %p\n", patch->name, p->name, plt);

                memcpy(runtime_stub, dummy_runtime_plt_stub, 64);

                assert(runtime_stub[8] == 0x48);                                       // movaps opcode
                *((uint64_t *)&runtime_stub[10]) = get_runtime_function_addr(p->name); // pushed constant

                assert(runtime_stub[22] == 0xe8); // relative call
                uint64_t rip = (uint64_t)&runtime_stub[27];
                uint64_t delta;
                if (((uint64_t)runtime_function_handler) > rip)
                    delta = ((uint64_t)runtime_function_handler) - rip;
                else
                    delta = -(rip - ((uint64_t)runtime_function_handler));

                *((uint32_t *)&runtime_stub[23]) = (uint32_t)delta; // relative offset

                uint8_t *a = PAGE_ALIGNED(&plt[0]);
                mprotect(a, getpagesize(), PROT_EXEC | PROT_READ | PROT_WRITE);

                // printf("OLD: %p - NEW: %p - RETURN_HANLDERL %p\n", plt[0], runtime_stub, return_handler_from_emulation);

                plt[0] = runtime_stub;

                runtime_stubs_count++;
                runtime_stub += 64;
                assert(runtime_stub < runtime_plt_stubs + sizeof(runtime_plt_stubs));
            }
        }
    }

    TCGTemp *ret_val_ts = tcg_find_temp_arch_reg("rax_expr");

    // these sanity checks make sense only
    // after jitting... should we remove them?
    assert(ret_val_ts->symbolic_expression == 1);
    assert(ret_val_ts->mem_coherent == 1);
    assert(ret_val_ts->val_type == TEMP_VAL_MEM);
    
    uint64_t **ret_val_expr = (uint64_t **)((uint64_t)ret_val_ts->mem_offset + (uint64_t)task->emulated_state);
    if (*ret_val_expr)
    {
        size_t current_bits = _sym_bits_helper(*ret_val_expr);
        if (current_bits < 64)
        {
            *ret_val_expr = _sym_build_zext(*ret_val_expr, 64 - current_bits);
        }
        // const char *s_expr = _sym_expr_to_string(*ret_val_expr);
        // printf("RETURN EXP: len=%ld %s\n", current_bits, s_expr);
        _sym_set_return_expression(*ret_val_expr);
    }
#if 0
    void* expr = _sym_get_parameter_expression(0);
    if (expr) {
        size_t current_bits = _sym_bits_helper(expr);
        if (current_bits < 64) {
            expr = _sym_build_zext(expr, 64 - current_bits);
        }
        
        assert(arg0->symbolic_expression == 1);
        assert(arg0->mem_coherent == 1);
        assert(arg0->val_type == TEMP_VAL_MEM);
        uint64_t** arg0_expr = (uint64_t**) ((uint64_t)arg0->mem_offset + (uint64_t)task->emulated_state);
        char* s_expr = _sym_expr_to_string(expr);
        printf("WRITING TO %llx EXPR %llx: %s\n", arg0_expr, expr, s_expr);

        *arg0_expr = expr;
    }
#endif

#if 0
    uint64_t base;
    arch_prctl(ARCH_GET_FS, &base);
    printf("FSBASE QEMU: %lx\n", base);
#endif
    // save_qemu_context_safe(task->qemu_context);
    save_qemu_context_safe();

    if (task->qemu_context->valid)
    {
#if 0
        for (int i = 0; i < SLOT_GPR_END; i++)
            printf("R[%d] = %lx\n", i, task->qemu_context->gpr[i]);
        printf("PC = %lx\n", task->qemu_context->pc);
#endif

        // printf("RSP QEMU: %lx\n", qemu_cpu_context.gpr[SLOT_RSP]);

        task->qemu_context->valid = 0;
        save_emulated_context(task->emulated_state, from_emulation);

        struct sigaction action;
        action.sa_sigaction = &hybrid_syscall_handler;
        action.sa_flags = SA_SIGINFO | SA_RESTART;
        sigaction(SIGILL, &action, &task->qemu_context->sigill_handler);

        // printf("\n[%lx] Resuming native to 0x%lx [0x%lx] [0x%lx]\n", task->tid, target, original_target, (uint64_t)&return_handler_from_emulation);

#if 0
        printf("FS EMULATED BASE: %lx %p\n", emulated_cpu_context.fs_base, &emulated_cpu_context.fs_base);
        uint64_t base;
        arch_prctl(ARCH_GET_FS, &base);
        printf("FS BASE: %lx\n", base);

        printf("BASE=%p SEG=%p FSBASE=%p\n", &emulated_cpu_context, &emulated_cpu_context.seg, &emulated_cpu_context.fs_base);
        printf("RIP EMULATED: %lx %p\n", emulated_cpu_context.pc, &emulated_cpu_context.pc);

        printf("STATE RSP: %lx\n", emulated_state->regs[SLOT_RSP]);
        printf("EMULATED RSP: %lx\n", emulated_cpu_context.gpr[SLOT_RSP]);
        printf("NATIVE RSP: %lx\n", native_cpu_context.gpr[SLOT_RSP]);
        if(native_cpu_context.gpr[SLOT_RSP] > 0) {
            printf("*[NATIVE RSP]: %lx\n", *((uint64_t*)native_cpu_context.gpr[SLOT_RSP]));
            printf("*[NATIVE RSP + 8]: %lx\n", *((uint64_t*)(native_cpu_context.gpr[SLOT_RSP] + 8)));
            assert(native_cpu_context.gpr[SLOT_RSP] + 8 == emulated_cpu_context.gpr[SLOT_RSP]);
        }
#endif

        __m128i xmm0 = _mm_loadu_si128((__m128i_u const *)&task->emulated_state->xmm_regs[0]);
        __m128i xmm1 = _mm_loadu_si128((__m128i_u const *)&task->emulated_state->xmm_regs[1]);
        __asm__("movups %0, %%xmm0\n"
                "movups %0, %%xmm1\n"
                :
                : "m"(xmm0), "m"(xmm1)
                : "xmm0", "xmm1");

        restore_native_context(task->emulated_context, target);
    }
    else
    {
#if 0
        arch_prctl(ARCH_GET_FS, &base);
        printf("FSBASE QEMU: %lx\n", base);
#endif
        // printf("\nResuming emulation to 0x%lx\n", task->emulated_state->eip);
#if 0
        printf("NATIVE PC: %lx\n", native_cpu_context.pc);
        printf("EMULATED PC: %lx\n", emulated_state->eip);
        printf("EMULATED RSP: %lx\n", emulated_state->regs[SLOT_RSP]);
        printf("NATIVE RSP: %lx\n", native_cpu_context.gpr[SLOT_RSP]);
        printf("*[NATIVE RSP]: %lx\n", *((uint64_t*)native_cpu_context.gpr[SLOT_RSP]));
        printf("*[NATIVE RSP + 8]: %lx\n", *((uint64_t*)(native_cpu_context.gpr[SLOT_RSP] + 8)));
        for (int i = 0; i < SLOT_GPR_END; i++)
            printf("R[%d] = %lx vs %lx vs %lx\n", i, native_cpu_context.gpr[i], emulated_cpu_context.gpr[i], emulated_state->regs[i]);
#endif

        const char *arg_regs[] = {
            "rdi_expr",
            "rsi_expr",
            "rdx_expr",
            "rcx_expr",
            "r8_expr",
            "r9_expr",
            //
            "rax_expr",
            "rbx_expr",
            "r10_expr",
            "r11_expr",
            "r12_expr",
            "r13_expr",
            "r14_expr",
            "r15_expr",
        };

        uint8_t args_count = _sym_get_args_count();
        printf("\nArgument count: %d\n", args_count);
        printf("RDI: %lx\n", task->emulated_state->regs[SLOT_RDI]);
        printf("RSI: %lx\n", task->emulated_state->regs[SLOT_RSI]);
        printf("RDX: %lx\n", task->emulated_state->regs[SLOT_RDX]);
        int int_arg_count = 0;
        for (int i = 0; i < args_count; i++)
        {
            void *expr = _sym_get_parameter_expression(i);
            uint8_t is_int = _sym_is_int_parameter(i);
            // printf("Argument %d is int: %d\n", i, is_int);

            if (is_int)
            {
                if (int_arg_count < 6)
                {
                    // printf("Setting symbolic regs: %s\n", arg_regs[int_arg_count]);
                    TCGTemp *arg = tcg_find_temp_arch_reg(arg_regs[int_arg_count]);
                    if (arg)
                    {
                        // these sanity checks make sense only
                        // after jitting... should we remove them?
                        assert(arg->symbolic_expression == 1);
                        assert(arg->mem_coherent == 1);
                        assert(arg->val_type == TEMP_VAL_MEM);
                    
                        uint64_t **arg_expr = (uint64_t **)((uint64_t)arg->mem_offset + (uint64_t)task->emulated_state);
                        if (expr)
                        {
                            size_t current_bits = _sym_bits_helper(expr);
                            if (current_bits < 64)
                            {
                                expr = _sym_build_zext(expr, 64 - current_bits);
                            }
                            const char *s_expr = _sym_expr_to_string(expr);
                            printf("%s: %s\n", arg_regs[int_arg_count], s_expr);
                        }
                        *arg_expr = expr;
                    }
                }
                else
                {
                    uint64_t arg_stack_index = int_arg_count - 6;
                    // printf("ESP: %lx\n", task->emulated_state->regs[SLOT_RSP]);
                    // printf("offset(xmm_regs): %x\n", offsetof(CPUX86State, xmm_regs));
                    // printf("NATIVE RSP: %lx\n", task->native_context->gpr[SLOT_RSP]);
                    uint64_t arg_stack_addr = task->emulated_state->regs[SLOT_RSP] + (arg_stack_index + 1) * 8;
                    if (expr)
                    {
                        size_t current_bits = _sym_bits_helper(expr);
                        if (current_bits < 64)
                        {
                            expr = _sym_build_zext(expr, 64 - current_bits);
                        }
                        // const char *s_expr = _sym_expr_to_string(expr);
                        // printf("stack_arg[%d]: %s\n", arg_stack_index, s_expr);
                    }
                    _sym_write_memory((uint8_t *)arg_stack_addr, 8, expr, 1);
                }
                int_arg_count++;
            }
        }
#if 0
        for (int i = int_arg_count; i < sizeof(arg_regs) / sizeof(char *); i++)
        {
            TCGTemp *arg = tcg_find_temp_arch_reg(arg_regs[int_arg_count]);
            assert(arg->symbolic_expression == 1);
            assert(arg->mem_coherent == 1);
            assert(arg->val_type == TEMP_VAL_MEM);
            uint64_t **arg_expr = (uint64_t **)((uint64_t)arg->mem_offset + (uint64_t)task->emulated_state);
            *arg_expr = NULL;
        }
#endif
    }
}

void switch_back_to_native(uint64_t target, CPUX86State *emulated_state)
{
    tcg_abort();
}

int is_hooked_plt_entry(uint64_t target)
{
    if (target >= (uint64_t)&plt_stubs && target <= (uint64_t)&plt_stubs[PLT_STUBS_SIZE])
    {
        return 1;
    }
    return 0;
}

void hybrid_stub(task_t *task)
{
    printf("Native return address: %lx\n", task->native_context->pc);
    return;
}

#define DEBUG_SYSCALLS 1
void hybrid_syscall(uint64_t retval,
                    uint64_t num, uint64_t arg1, uint64_t arg2,
                    uint64_t arg3, uint64_t arg4, uint64_t arg5,
                    uint64_t arg6, uint64_t arg7, uint64_t arg8)
{
#if DEBUG_SYSCALLS
    task_t *task = get_task();
#endif
    switch (num)
    {
    case TARGET_NR_openat:
    case TARGET_NR_open:
    {
        int fd = retval;
        if (fd >= 0)
        {
            char *fname = (char *)(num == TARGET_NR_open ? arg1 : arg2);
#if DEBUG_SYSCALLS
            printf("[%lu] SYSCALL: open(%s) = %d\n", task->tid, fname, fd);
#endif
            if (fd >= MAX_MMAP_FILES)
                tcg_abort();
            if (open_files[fd].state != FILE_STATE_INVALID)
                tcg_abort();
            open_files[fd].state = FILE_STATE_OPEN;
            open_files[fd].name = strdup(fname);
        }
        break;
    }

    case TARGET_NR_close:
    {
        int fd = arg1;
        if (fd >= 0)
        {
#if DEBUG_SYSCALLS
            printf("[%lu] SYSCALL: close(%d)\n", task->tid, fd);
#endif
            if (fd >= MAX_MMAP_FILES)
                tcg_abort();
            if (open_files[fd].state != FILE_STATE_OPEN)
                tcg_abort();
            open_files[fd].state = FILE_STATE_INVALID;
            open_files[fd].name = NULL;
        }
        break;
    }

    case TARGET_NR_mmap:
    {
        int fd = arg5;
        int prot = arg3;
#if DEBUG_SYSCALLS
        printf("[%lu] SYSCALL: mmap(%lx, %ld, %d, %d, %d, %lu) = 0x%lx\n",
               task->tid, arg1, (size_t)arg2, prot, (int)arg4, fd, (off_t)arg6, retval);
#endif
        if (fd >= 0 && prot & PROT_EXEC)
        {
            if (fd >= MAX_MMAP_FILES)
                tcg_abort();
            if (open_files[fd].state != FILE_STATE_OPEN)
                tcg_abort();
            mmap_file_t *mft = g_malloc0(sizeof(mmap_file_t));
            mft->name = open_files[fd].name;
            mft->addr = retval;
            mmaped_files = g_slist_append(mmaped_files, (gpointer)mft);
        }
        break;
    }

    case TARGET_NR_clone:
    {
#if DEBUG_SYSCALLS
        printf("[%lu] SYSCALL: clone() = 0x%lx\n", task->tid, retval);
#endif
        break;
    }

    case TARGET_NR_writev:
    case TARGET_NR_write:
    {
#if DEBUG_SYSCALLS
        printf("[%lu] SYSCALL: write(%ld, ..., %ld) = %ld\n", task->tid, arg1, arg3, retval);
#endif
        break;
    }

    case TARGET_NR_brk:
    {
#if DEBUG_SYSCALLS
        printf("[%lu] SYSCALL: brk(%lx) = %lx\n", task->tid, arg1, retval);
#endif
        break;
    }

    default:
#if DEBUG_SYSCALLS
        printf("[%lu] SYSCALL: %ld => 0x%lx\n", task->tid, num, retval);
#endif
        break;
    }
    return;
}