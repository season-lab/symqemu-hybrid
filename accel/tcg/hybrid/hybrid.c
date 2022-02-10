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
#include <sys/sysinfo.h>

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

#define SymExpr void*
#include "RuntimeCommon.h"
#undef SymExpr

#include "hybrid_debug.h"

#if !HYBRID_DBG_PRINT
#define printf(...)                                                            \
    {                                                                          \
    }
#endif

#define SAVE_GPR(reg, slot)                                                    \
    "movq $" str(slot) ", %rcx"                                                \
                       "\n\t"                                                  \
                       "movq " reg ", (%rax, %rcx, 8)"                         \
                       "\n\t"
#define RESTORE_GPR(reg, slot)                                                 \
    "movq $" str(slot) ", %rcx"                                                \
                       "\n\t"                                                  \
                       "movq (%rax, %rcx, 8), " reg "\n\t"
#define SAVE_SEGR(reg, slot)                                                   \
    "movq $" str(slot) ", %rcx"                                                \
                       "\n\t"                                                  \
                       "movw " reg ", (%rax, %rcx, 2)"                         \
                       "\n\t"
#define RESTORE_SEGR(reg, slot)                                                \
    "movq $" str(slot) ", %rcx"                                                \
                       "\n\t"                                                  \
                       "movzwl (%rax, %rcx, 2), %rcx"                          \
                       "\n\t"                                                  \
                       "push %rcx"                                             \
                       "\n\t"                                                  \
                       "pop " reg "\n\t"

#define xstr(ss) str(ss)
#define str(s)   #s

#include "accel/tcg/hybrid/hybrid_cpu.h"

#define SLOT_RAX     R_EAX
#define SLOT_RBX     R_EBX
#define SLOT_RCX     R_ECX
#define SLOT_RDX     R_EDX
#define SLOT_RSI     R_ESI
#define SLOT_RDI     R_EDI
#define SLOT_RBP     R_EBP
#define SLOT_RSP     R_ESP
#define SLOT_R8      R_R8
#define SLOT_R9      R_R9
#define SLOT_R10     R_R10
#define SLOT_R11     R_R11
#define SLOT_R12     R_R12
#define SLOT_R13     R_R13
#define SLOT_R14     R_R14
#define SLOT_R15     R_R15
#define SLOT_GPR_END (R_R15 + 1)

#define SLOT_ES       R_ES
#define SLOT_CS       R_CS
#define SLOT_SS       R_SS
#define SLOT_DS       R_DS
#define SLOT_FS       R_FS
#define SLOT_GS       5 // weird link error: clash of names?
#define SLOT_SEGR_END (R_GS + 1)

typedef struct CpuContext_t {
    uint64_t         gpr[SLOT_GPR_END];
    uint64_t         flags;
    uint16_t         seg[SLOT_SEGR_END];
    uint64_t         fs_base;
    uint64_t         valid;
    uint64_t         pc;
    struct sigaction sigill_handler;
} CpuContext;

abi_ulong       hybrid_entry_point, hybrid_start_code, hybrid_end_code;
abi_ulong       hybrid_start_lib_1, hybrid_end_lib_1;
abi_ulong       hybrid_start_lib_2, hybrid_end_lib_2;
extern uint64_t hybrid2_start_lib_1, hybrid2_end_lib_1;
extern uint64_t hybrid2_start_lib_2, hybrid2_end_lib_2;

#define MAX_TASKS 64
static task_t tasks[MAX_TASKS] = {0};

#define MAX_PLT_ENTRIES 1024
uint64_t shadow_plt[MAX_PLT_ENTRIES] = {0};

uint8_t        hybrid_trace_mode        = 0;
uint64_t       start_addr               = 0;
static GSList* plt_patches              = NULL;
static GSList* syscall_patches          = NULL;
static GSList* runtime_patches          = NULL;
static GSList* plt_aliases              = NULL;
static char*   libc_path                = NULL;
uint64_t       libc_concrete_funcs[256] = {0};
uint64_t       libc_models[256]         = {0};

uint64_t libc_setjmp_addr[2]  = {0};
uint64_t libc_longjmp_addr[2] = {0};

typedef struct {
    char*   name;
    GSList* offsets;
} plt_patch_t;

typedef struct {
    char*   name;
    GSList* offsets;
} syscall_patch_t;

typedef struct {
    char*    name;
    uint64_t offset;
} runtime_plt_patch_t;

typedef struct {
    char*   name;
    GSList* patches;
} runtime_patch_t;

typedef struct {
    char*    from_obj;
    char*    to_obj;
    uint64_t from_got_entry;
    uint64_t to_got_entry;
    uint64_t to_plt_entry;
} plt_alias_t;

static int plt_stubs_count = 0;

typedef enum { FILE_STATE_INVALID, FILE_STATE_OPEN } file_state_t;

typedef struct {
    int   state;
    char* name;
} open_file_t;

typedef struct {
    char*    name;
    uint64_t addr;
} mmap_file_t;

#define MAX_MMAP_FILES 64
open_file_t open_files[MAX_MMAP_FILES] = {0};
GSList*     mmaped_files               = NULL;

#if HYBRID_USE_FSBASEINSN
static inline int arch_prctl(int code, unsigned long base)
{
    if (code == ARCH_GET_FS) {
        *((unsigned long*)base) = _readfsbase_u64();
    } else {
        _writefsbase_u64(*((unsigned long*)base));
    }
    return 0;
}
#else
int arch_prctl(int code, unsigned long addr);
#endif

static int parse_config_file(char* file)
{
    // printf("Reading config file: %s\n", file);

    GKeyFile* gkf = g_key_file_new();
    if (!g_key_file_load_from_file(gkf, file, G_KEY_FILE_NONE, NULL)) {
        fprintf(stderr, "Could not read config file %s\n", file);
        return -1;
    }

    char* res = g_key_file_get_value(gkf, "start_addr", "addr", NULL);
    if (res) {
        // printf("ADDR: %s\n", res);
        start_addr = (target_ulong)strtoull(res, NULL, 16);
    }
#if 1
    // libc
    res = g_key_file_get_value(gkf, "libc", "path", NULL);
    if (res) {
        libc_path = strdup(res);
        printf("LIBC PATH: %s\n", libc_path);
    }
    const char* libc_concretize_funcs_names[] = {
        "__libc_malloc", "__libc_calloc", "__libc_realloc", "__libc_free",
        "__printf_chk",  "_IO_printf",    "__snprintf_chk", "__vsnprintf_chk",
        "__snprintf",    "__vsnprintf",   "_IO_vfprintf",   "_vfprintf_chk"};
    for (int i = 0, j = 0;
         i < sizeof(libc_concretize_funcs_names) / sizeof(char*); i++) {
        res = g_key_file_get_value(gkf, "libc", libc_concretize_funcs_names[i],
                                   NULL);
        if (res) {
            printf("LIBC %s at 0x%s\n", libc_concretize_funcs_names[i], res);
            uint64_t offset = (uint64_t)strtoull(res, NULL, 16);
            assert(j < sizeof(libc_concrete_funcs) / sizeof(uint64_t));
            libc_concrete_funcs[j++] = offset;
        }
    }
    res = g_key_file_get_value(gkf, "libc", "__sigsetjmp", NULL);
    if (res) {
        printf("__sigsetjmp at 0x%s\n", res);
        uint64_t offset     = (uint64_t)strtoull(res, NULL, 16);
        libc_setjmp_addr[0] = offset;
    }
    res = g_key_file_get_value(gkf, "libc", "_setjmp", NULL);
    if (res) {
        printf("_setjmp at 0x%s\n", res);
        uint64_t offset     = (uint64_t)strtoull(res, NULL, 16);
        libc_setjmp_addr[1] = offset;
    }
    res = g_key_file_get_value(gkf, "libc", "__libc_siglongjmp", NULL);
    if (res) {
        printf("__libc_siglongjmp at 0x%s\n", res);
        uint64_t offset      = (uint64_t)strtoull(res, NULL, 16);
        libc_longjmp_addr[0] = offset;
    }
    res = g_key_file_get_value(gkf, "libc", "__libc_longjmp", NULL);
    if (res) {
        printf("__libc_longjmp at 0x%s\n", res);
        uint64_t offset      = (uint64_t)strtoull(res, NULL, 16);
        libc_longjmp_addr[1] = offset;
    }

    {
        char** keys = g_key_file_get_keys(gkf, "libc_models", NULL, NULL);
        int    j    = 0;
        while (*keys != NULL) {
            char* res = g_key_file_get_value(gkf, "libc_models", *keys, NULL);
            if (strcmp("path", *keys) != 0) {
                printf("LIBC MODEL %s at 0x%s\n", *keys, res);
                uint64_t offset = (uint64_t)strtoull(res, NULL, 16);
                assert(j < sizeof(libc_models) / sizeof(uint64_t));
                libc_models[j++] = offset;
            }
            keys++;
        }
    }

#endif
    char** groups          = g_key_file_get_groups(gkf, NULL);
    char** groups_original = groups;
    while (*groups != NULL) {
        // printf("group %s\n", *groups);
        if (strcmp(*groups, "start_addr") != 0 &&
            strcmp(*groups, "libc") != 0) {
            GSList* offsets = NULL;
            // int is_main_image = strcmp(*groups, "main_image") == 0;
            char** addrs = g_key_file_get_string_list(gkf, *groups, "patch_plt",
                                                      NULL, NULL);
            if (addrs) {
                char** addrs_original = addrs;
                while (*addrs != NULL) {
                    uint64_t offset = (target_ulong)strtoull(*addrs, NULL, 16);
                    // printf("[%s] offset: 0x%lx\n", *groups, offset);
                    offsets = g_slist_append(offsets, (gpointer)offset);
                    addrs++;
                }
                plt_patch_t* patch = g_malloc0(sizeof(plt_patch_t));
                patch->name        = strdup(*groups);
                patch->offsets     = offsets;
                plt_patches = g_slist_append(plt_patches, (gpointer)patch);
                g_strfreev(addrs_original);
            }

            // GSList *syscall_offsets = NULL;
            addrs = g_key_file_get_string_list(gkf, *groups, "patch_syscall",
                                               NULL, NULL);
            if (addrs) {
                char** addrs_original = addrs;
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

            char** keys = g_key_file_get_keys(gkf, *groups, NULL, NULL);
            char** keys_original           = keys;
            runtime_patch_t* runtime_patch = NULL;
            while (*keys != NULL) {
                if (strncmp(*keys, "RUNTIME_", 8) == 0) {
                    if (runtime_patch == NULL) {
                        runtime_patch = g_malloc0(sizeof(runtime_patch_t));
                        runtime_patch->name    = strdup(*groups);
                        runtime_patch->patches = NULL;
                    }

                    char* name = strdup(*keys + 8);
                    char* offset =
                        g_key_file_get_value(gkf, *groups, *keys, NULL);
                    if (offset) {
                        // printf("ADDR: %s\n", res);
                        uint64_t off = (target_ulong)strtoull(offset, NULL, 16);
                        // printf("name: %s value: %lx\n", name, off);

                        runtime_plt_patch_t* patch =
                            g_malloc0(sizeof(runtime_plt_patch_t));
                        patch->name            = name;
                        patch->offset          = off;
                        runtime_patch->patches = g_slist_append(
                            runtime_patch->patches, (gpointer)patch);
                    }
                } else if (strncmp(*keys, "0x_", 2) == 0) {
                    // printf("V=%s\n", *keys);
                    char** addrs = g_key_file_get_string_list(
                        gkf, *groups, *keys, NULL, NULL);
                    if (addrs) {
                        char**       addrs_original = addrs;
                        int          index          = 0;
                        plt_alias_t* plt_alias      = NULL;
                        while (*addrs != NULL) {
                            if (index % 3 == 0) {
                                plt_alias = g_malloc0(sizeof(plt_alias_t));
                                plt_alias->from_obj = strdup(*groups);
                                plt_alias->from_got_entry =
                                    (target_ulong)strtoull(*keys, NULL, 16);
                            }

                            assert(plt_alias);

                            // printf("VV=%s\n", *addrs);
                            if (index % 3 == 0)
                                plt_alias->to_obj = strdup(*addrs);
                            else if (index % 3 == 1)
                                plt_alias->to_got_entry =
                                    (target_ulong)strtoull(*addrs, NULL, 16);
                            else if (index % 3 == 2)
                                plt_alias->to_plt_entry =
                                    (target_ulong)strtoull(*addrs, NULL, 16);

                            addrs++;
                            index += 1;

                            if (index % 3 == 0 && index > 0)
                                plt_aliases = g_slist_append(
                                    plt_aliases, (gpointer)plt_alias);
                        }
                        g_strfreev(addrs_original);
                    }
                }

                keys++;
            }
            g_strfreev(keys_original);
            if (runtime_patch) {
                runtime_patches =
                    g_slist_append(runtime_patches, (gpointer)runtime_patch);
            }
        }
        groups++;
    }
    g_strfreev(groups_original);

    g_key_file_free(gkf);
    return 0;
}

task_t* get_task(void)
{
    return &tasks[0];
#if 0 // FIXME: use it when making it thread-safe!
    pid_t tid;
    tid          = cached_pid;
    task_t* task = NULL;

    // FIXME: we should protect this with a lock
    for (int i = 0; i < MAX_TASKS; i++) {
        if (tasks[i].tid == tid) {
            task = &tasks[i];
            break;
        }
    }

    if (task == NULL)
        tcg_abort();

    return task;
#endif
}

extern void restore_qemu_context(CpuContext* context);

#if 0
void        hybrid_syscall_handler(int mysignal, siginfo_t* si, void* arg);
void save_native_context_clobber_syscall(uint64_t rsp, uint64_t* save_area);
void save_native_context_clobber_syscall(uint64_t rsp, uint64_t* save_area)
{
    abort();
    task_t* task = get_task();

    uint64_t fs_base;
    arch_prctl(ARCH_GET_FS, (uint64_t)&fs_base);
    arch_prctl(ARCH_SET_FS, task->qemu_context->fs_base);

#if 0
    printf("Handler #2: fs_base=%lx fs_base_qemu=%lx\n", fs_base, task->qemu_context->fs_base);
    printf("*(rsp) = %lx\n", *((uint64_t*) rsp));
    printf("*(rsp - 8) = %lx\n", *((uint64_t*) (rsp - 8)));
#endif

    CpuContext* context     = task->native_context;
    *((uint64_t*)(rsp - 8)) = (uint64_t)context;

    // general purpose registers
    context->gpr[SLOT_RAX] = save_area[0];
    context->gpr[SLOT_RBX] = save_area[-1];
    context->gpr[SLOT_RCX] = save_area[-2];
    context->gpr[SLOT_RDX] = save_area[-3];
    context->gpr[SLOT_RSI] = save_area[-4];
    context->gpr[SLOT_RDI] = save_area[-5];
    context->gpr[SLOT_RBP] = save_area[-6];
    context->gpr[SLOT_R8]  = save_area[-7];
    context->gpr[SLOT_R9]  = save_area[-8];
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
    context->pc = *(((uint64_t*)rsp));

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

    switch (save_area[0]) {
        case TARGET_NR_clone: {
            // printf("clone()\n");
            // we have to update the emulated state because
            // it will be copied into the cloned cpu
            task->emulated_state->eip            = context->pc;
            task->emulated_state->regs[SLOT_RAX] = context->gpr[SLOT_RAX];
            task->emulated_state->regs[SLOT_RBX] = context->gpr[SLOT_RBX];
            task->emulated_state->regs[SLOT_RCX] = context->gpr[SLOT_RCX];
            task->emulated_state->regs[SLOT_RDX] = context->gpr[SLOT_RDX];
            task->emulated_state->regs[SLOT_RDI] = context->gpr[SLOT_RDI];
            task->emulated_state->regs[SLOT_RSI] = context->gpr[SLOT_RSI];
            task->emulated_state->regs[SLOT_RSP] = context->gpr[SLOT_RSP];
            task->emulated_state->regs[SLOT_RBP] = context->gpr[SLOT_RBP];
            task->emulated_state->regs[SLOT_R9]  = context->gpr[SLOT_R9];
            task->emulated_state->regs[SLOT_R10] = context->gpr[SLOT_R10];
            task->emulated_state->regs[SLOT_R11] = context->gpr[SLOT_R11];
            task->emulated_state->regs[SLOT_R12] = context->gpr[SLOT_R12];
            task->emulated_state->regs[SLOT_R13] = context->gpr[SLOT_R13];
            task->emulated_state->regs[SLOT_R14] = context->gpr[SLOT_R14];
            task->emulated_state->regs[SLOT_R15] = context->gpr[SLOT_R15];
            task->emulated_state->eflags         = context->flags;
            break;
        }

        case TARGET_NR_exit: {
            // printf("EXITING...\n");

            // we cannot execute the exit from the native context
            // because QEMU may call pthread_exit that will
            // try to unwind the stack, failing because
            // we are not working on the stack built
            // by pthread_create. We need to switch back
            // to the qemu context and then we can
            // execute the exit.

            task->emulated_state->eip            = context->pc;
            task->emulated_state->regs[SLOT_RAX] = context->gpr[SLOT_RAX];
            task->emulated_state->regs[SLOT_RBX] = context->gpr[SLOT_RBX];
            task->emulated_state->regs[SLOT_RCX] = context->gpr[SLOT_RCX];
            task->emulated_state->regs[SLOT_RDX] = context->gpr[SLOT_RDX];
            task->emulated_state->regs[SLOT_RDI] = context->gpr[SLOT_RDI];
            task->emulated_state->regs[SLOT_RSI] = context->gpr[SLOT_RSI];
            task->emulated_state->regs[SLOT_RSP] = context->gpr[SLOT_RSP];
            task->emulated_state->regs[SLOT_RBP] = context->gpr[SLOT_RBP];
            task->emulated_state->regs[SLOT_R9]  = context->gpr[SLOT_R9];
            task->emulated_state->regs[SLOT_R10] = context->gpr[SLOT_R10];
            task->emulated_state->regs[SLOT_R11] = context->gpr[SLOT_R11];
            task->emulated_state->regs[SLOT_R12] = context->gpr[SLOT_R12];
            task->emulated_state->regs[SLOT_R13] = context->gpr[SLOT_R13];
            task->emulated_state->regs[SLOT_R14] = context->gpr[SLOT_R14];
            task->emulated_state->regs[SLOT_R15] = context->gpr[SLOT_R15];
            task->emulated_state->eflags         = context->flags;

            task->must_exit = 1;
            restore_qemu_context(task->qemu_context);
            break;
        }

        default:
            break;
    }

    for (int i = 0; i < 10; i++) {
        task->is_native = 1;
        // printf("[%lx] DO_SYSCALL: %ld\n", task->tid, save_area[0]);
        uint64_t ret           = do_syscall(task->emulated_state,
                                  save_area[0],  // env->regs[R_EAX],
                                  save_area[-5], // env->regs[R_EDI],
                                  save_area[-4], // env->regs[R_ESI],
                                  save_area[-3], // env->regs[R_EDX],
                                  save_area[-9], // env->regs[10],
                                  save_area[-7], // env->regs[8],
                                  save_area[-8], // env->regs[9],
                                  0, 0);
        task->is_native        = 0;
        context->gpr[SLOT_RAX] = ret;

        if (TARGET_NR_write == save_area[0] && ret == -512) {
            // const char* str = "test\n";
            // write(2, str, sizeof(str));
            continue;
        } else
            break;

        break;
    }

    switch (save_area[0]) {
        case TARGET_NR_rt_sigaction: {
#if 1
            // printf("\n[%lx] ENABLING SIGNALS AFTER SIGACTION\n\n",
            // task->tid); CPUState *cpu = ENV_GET_CPU(task->emulated_state);
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

#if 0
    struct sigaction action;
    action.sa_sigaction = &hybrid_syscall_handler;
    action.sa_flags     = SA_SIGINFO | SA_RESTART;
    sigaction(SIGILL, &action, &task->qemu_context->sigill_handler);
#endif

    // restore fsbase to avoid canary check failure...
    arch_prctl(ARCH_SET_FS, fs_base);
}

void save_native_context_safe_syscall(void);
void hybrid_syscall_handler(int mysignal, siginfo_t* si, void* arg)
{
    ucontext_t* context = (ucontext_t*)arg;
    context->uc_mcontext.gregs[REG_RSP] =
        context->uc_mcontext.gregs[REG_RSP] - 8;
    *((uint64_t*)context->uc_mcontext.gregs[REG_RSP]) =
        context->uc_mcontext.gregs[REG_RIP] + 0x2;
    context->uc_mcontext.gregs[REG_RIP] =
        (uint64_t)&save_native_context_safe_syscall;

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
#endif

static task_t* hybrid_new_task(uint64_t tid)
{
    CpuContext* native_context   = g_malloc0(sizeof(CpuContext));
    CpuContext* emulated_context = g_malloc0(sizeof(CpuContext));
    CpuContext* qemu_context     = g_malloc0(sizeof(CpuContext));

    // FIXME: we should protect this with a lock
    for (int i = 0; i < MAX_TASKS; i++) {
        if (tasks[i].tid == 0) {
            tasks[i].tid              = tid;
            tasks[i].native_context   = native_context;
            tasks[i].emulated_context = emulated_context;
            tasks[i].qemu_context     = qemu_context;
            tasks[i].depth            = 0;
            return &tasks[i];
        }
    }

    tcg_abort();
    return NULL;
}

void hybrid_new_thread(uint64_t tid, CPUX86State* state)
{
    task_t* task = get_task();
    assert(task->is_native); // ToDo

    task_t* new_task         = hybrid_new_task(tid);
    new_task->is_native      = 1;
    new_task->emulated_state = state;

    // printf("THREAD EIP: %lx\n", state->eip);

    // uint64_t fs_base;
    // arch_prctl(ARCH_GET_FS, (uint64_t)&fs_base);
    // printf("PARENT QEMU FSBASE: %lx\n", fs_base);
}

#if 0
void hybrid_set_sigill_handler(void)
{
#if 0
    task_t*          task = get_task();
    struct sigaction action;
    action.sa_sigaction = &hybrid_syscall_handler;
    action.sa_flags     = SA_SIGINFO | SA_RESTART;
    sigaction(SIGILL, &action, &task->qemu_context->sigill_handler);
#endif
    // uint64_t fs_base;
    // arch_prctl(ARCH_GET_FS, (uint64_t)&fs_base);
    // printf("CHILD QEMU FSBASE: %lx\n", fs_base);
}
#endif

int hybrid_is_task_native(void)
{
    task_t* task = get_task();
    if (task) {
        int is_native   = task->is_native;
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

void save_qemu_context_clobber(uint64_t rsp, uint64_t* save_area);
void save_qemu_context_clobber(uint64_t rsp, uint64_t* save_area)
{
    task_t*     task    = get_task();
    CpuContext* context = task->qemu_context;

    // general purpose registers
    context->gpr[SLOT_RAX] = save_area[0];
    context->gpr[SLOT_RBX] = save_area[-1];
    context->gpr[SLOT_RCX] = save_area[-2];
    context->gpr[SLOT_RDX] = save_area[-3];
    context->gpr[SLOT_RSI] = save_area[-4];
    context->gpr[SLOT_RDI] = save_area[-5];
    context->gpr[SLOT_RBP] = save_area[-6];
    context->gpr[SLOT_R8]  = save_area[-7];
    context->gpr[SLOT_R9]  = save_area[-8];
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
#if HYBRID_UPDATE_FSBASE_DURING_SWITCH
    arch_prctl(ARCH_GET_FS, (uint64_t)&context->fs_base);
#endif
    // program counter: return address
    context->pc = *(((uint64_t*)rsp));

    // valid flag
    context->valid = 1;
}

void save_qemu_context_safe(void);
__asm__(".globl save_qemu_context_safe\n"
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

void save_native_context_clobber(uint64_t rsp, uint64_t* save_area);
void save_native_context_clobber(uint64_t rsp, uint64_t* save_area)
{
    task_t*     task    = get_task();
    CpuContext* context = task->native_context;

    // general purpose registers
    context->gpr[SLOT_RAX] = save_area[0];
    context->gpr[SLOT_RBX] = save_area[-1];
    context->gpr[SLOT_RCX] = save_area[-2];
    context->gpr[SLOT_RDX] = save_area[-3];
    context->gpr[SLOT_RSI] = save_area[-4];
    context->gpr[SLOT_RDI] = save_area[-5];
    context->gpr[SLOT_RBP] = save_area[-6];
    context->gpr[SLOT_R8]  = save_area[-7];
    context->gpr[SLOT_R9]  = save_area[-8];
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
#if HYBRID_UPDATE_FSBASE_DURING_SWITCH
    arch_prctl(ARCH_GET_FS, (uint64_t)&context->fs_base);
#endif
    // program counter: return address
    context->pc = *(((uint64_t*)rsp));

    // valid flag
    context->valid = 1;

    // arch_prctl(ARCH_SET_FS, (uint64_t) task->qemu_context->fs_base);
    for (int i = 0; i < 8; i++) {
        task->emulated_state->xmm_regs[i]._q_ZMMReg[0] =
            save_area[-17 - (2 * i)];
        task->emulated_state->xmm_regs[i]._q_ZMMReg[1] =
            save_area[-18 - (2 * i)];
    }
    // arch_prctl(ARCH_SET_FS, (uint64_t) context->fs_base);
}

void save_native_context_safe(void);
__asm__(".globl save_native_context_safe\n"
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
        "popq %rdi\n"  // plt entry index
        "pushq %rdi\n" // alignment
        "call switch_to_emulated\n"
        //
        ".cfi_endproc");

void save_native_context_safe_back_to_emulation(void);
__asm__(".globl save_native_context_safe_back_to_emulation\n"
        //
        ".type func, @function\n"
        "save_native_context_safe_back_to_emulation:\n"
        ".cfi_startproc\n\t"
#define BACK_FROM_EMULATION
#define PRESERVE_XMM
#define SAVE_ROUTINE save_native_context_clobber
#include "save_context_safe.h"
#undef SAVE_ROUTINE
#undef PRESERVE_XMM
#undef BACK_FROM_EMULATION
        //
        "call switch_back_emulation\n"
        //
        ".cfi_endproc");

void save_native_context_indirect_call(uint64_t arg1, uint64_t arg2,
                                       uint64_t arg3, uint64_t arg4,
                                       uint64_t arg5, uint64_t arg6);
__asm__(".globl save_native_context_indirect_call\n"
        //
        ".type func, @function\n"
        "save_native_context_indirect_call:\n"
        ".cfi_startproc\n\t"
#define BACK_FROM_EMULATION
#define PRESERVE_XMM
#define SAVE_ROUTINE save_native_context_clobber
#include "save_context_safe.h"
#undef SAVE_ROUTINE
#undef PRESERVE_XMM
#undef BACK_FROM_EMULATION
        //
        "pushq $0xCAFE\n" // alignment
        "call switch_emulation_indirect_call\n"
        //
        ".cfi_endproc");

#if 0
__asm__(".globl save_native_context_safe_syscall\n"
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
#endif

static void save_emulated_context(CPUX86State* state, int skip_eip)
{
    int i;

    task_t*     task                 = get_task();
    CpuContext* emulated_cpu_context = task->emulated_context;

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
#if HYBRID_UPDATE_FSBASE_DURING_SWITCH
    emulated_cpu_context->fs_base = state->segs[R_FS].base;
#endif
    // pc
    if (!skip_eip)
        emulated_cpu_context->pc = state->eip;
    else
        printf("Skipping EIP import from emulated state\n");
}

static void restore_emulated_context(CpuContext* context, CPUX86State* state)
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
#if HYBRID_UPDATE_FSBASE_DURING_SWITCH
    state->segs[R_FS].base = context->fs_base;
#endif
}

extern void restore_native_context(CpuContext* context, uint64_t target);
__asm__(".globl restore_native_context\n\t"
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

__asm__(".globl restore_qemu_context\n\t"
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
__asm__(".globl dummy_plt_stub\n\t"
        //
        // ".type func, @function\n\t"
        "dummy_plt_stub:\n\t"
        // ".cfi_startproc\n\t"
        //
        "pushq $0xCAFE\n\t"
        "jmp save_native_context_safe"
        "\n\t"
        //
        // ".cfi_endproc"
);

typedef struct {
    uint64_t addr;
    uint64_t arg6;
    uint64_t arg5;
    uint64_t arg4;
    uint64_t arg3;
    uint64_t arg2;
    uint64_t arg1;
} runtime_stub_args_t;

extern void dummy_runtime_plt_stub(void);
__asm__(".globl dummy_runtime_plt_stub\n\t"
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
        "call save_native_context_safe\n\t" // this is replaced by runtime_function_handler
        "leaq 56(%rsp), %rsp\n\t"
        "ret"
        //
        // ".cfi_endproc"
);

#if 0
void return_handler_from_emulation(void)
{
    assert(0 &&
           "This should never be executed since QEMU should intercept it.");
}
#endif

static inline void get_time(struct timespec* tp)
{
    clock_gettime(CLOCK_MONOTONIC, tp);
}

static inline uint64_t get_diff_time_microsec(struct timespec* start,
                                              struct timespec* end)
{
    uint64_t r = (end->tv_sec - start->tv_sec) * 1000000000;
    r += (end->tv_nsec - start->tv_nsec);
    return (r / 1000);
}

uint64_t total_emulation = 0;
struct timespec t1_start;
struct timespec t_emulation_end;
struct timespec t_native_end;
void switch_to_emulated(int plt_entry)
{
    task_t* task = get_task();
    restore_emulated_context(task->native_context, task->emulated_state);

    // swap return address
    uint64_t* ret_addr       = (uint64_t*)task->emulated_state->regs[SLOT_RSP];
    task->native_context->pc = *(ret_addr);

    task->depth += 1;
    assert(task->depth >= 0 && task->depth <= MAX_DEPTH);
    task->return_addrs[task->depth - 1] = *(ret_addr);

#if HYBRID_UPDATE_FSBASE_DURING_SWITCH
    uint64_t base;
    arch_prctl(ARCH_GET_FS, (uint64_t)&base);
    arch_prctl(ARCH_SET_FS, (uint64_t)task->qemu_context->fs_base);
#endif

    *(ret_addr) = RETURN_FROM_EMULATION_SENTINEL;
    _sym_concretize_memory((uint8_t*)ret_addr, sizeof(void*));
    assert(plt_entry >= 0 && plt_entry < plt_stubs_count);
    task->emulated_state->eip = shadow_plt[plt_entry];

    printf("Switching to emulated to 0x%lx...\n", task->emulated_state->eip);
#if HYBRID_DBG_PRINT
    _sym_print_stack();
#endif
    if (libc_setjmp_addr[0] == task->emulated_state->eip ||
        libc_setjmp_addr[1] == task->emulated_state->eip) {
        assert(task->long_jumps_used < MAX_DEPTH - 1);

        int index    = 0;
        int existing = 0;
        while (index < task->long_jumps_used) {
            if (task->longjmp[index] == task->return_addrs[task->depth - 1] &&
                task->longjmp_arg[index] ==
                    task->emulated_state->regs[SLOT_RDI] &&
                task->longjmp_callsite[index] == _sym_get_call_site()) {
                existing = 1;
                break;
            }
            index += 1;
        }

        if (!existing) {
            task->longjmp[task->long_jumps_used] =
                task->return_addrs[task->depth - 1];
            task->longjmp_arg[task->long_jumps_used] =
                task->emulated_state->regs[SLOT_RDI];
            task->longjmp_depth[task->long_jumps_used] = task->depth;
            task->longjmp_callsite[task->long_jumps_used] =
                _sym_get_call_site();
            printf("[%ld] SAVING JMP TO %lx WITH ARG %lx callsite=%lx\n",
                   task->long_jumps_used, task->longjmp[task->long_jumps_used],
                   task->longjmp_arg[task->long_jumps_used],
                   _sym_get_call_site());
            task->long_jumps_used += 1;
        }
    } else if (libc_longjmp_addr[0] == task->emulated_state->eip ||
               libc_longjmp_addr[1] == task->emulated_state->eip) {
        int index = task->long_jumps_used - 1;
        while (index >= 0) {
            if (task->longjmp_arg[index] ==
                task->emulated_state->regs[SLOT_RDI])
                break;
            index -= 1;
        }
        assert(index >= 0);
        // FIXME: we should track RSP values...
        printf("ADJUSTING DEPTH FROM %ld to %ld for callsite %lx\n", task->depth,
               task->longjmp_depth[index], task->longjmp_callsite[index]);
        task->depth                         = task->longjmp_depth[index];
        task->return_addrs[task->depth - 1] = task->longjmp[index];

        _sym_notify_call(task->longjmp_callsite[index]);
        // tcg_abort();
    }

    _sym_notify_call(RETURN_FROM_EMULATION_SENTINEL);
#if HYBRID_UPDATE_FSBASE_DURING_SWITCH
    arch_prctl(ARCH_SET_FS, base);
#endif

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

void switch_back_emulation(void);
void switch_back_emulation(void)
{
    task_t* task = get_task();

    // fix pc
    assert(task->depth >= 0 && task->depth <= MAX_DEPTH);
    // FIXME: should we check rsp?
    task->native_context->pc = task->return_addrs[task->depth - 1];
    task->depth -= 1;

    restore_emulated_context(task->native_context, task->emulated_state);
    task->emulated_state->eip = task->native_context->pc;

#if HYBRID_UPDATE_FSBASE_DURING_SWITCH
    uint64_t base;
    arch_prctl(ARCH_GET_FS, (uint64_t)&base);
    arch_prctl(ARCH_SET_FS, (uint64_t)task->qemu_context->fs_base);
#endif
    printf("[depth=%ld] JUMPING BACK TO %lx rsp=%lx\n", task->depth,
           task->emulated_state->eip, task->emulated_state->regs[SLOT_RSP]);

    // FIXME: is this needed?
    // _sym_notify_ret(task->emulated_state->eip);
#if HYBRID_UPDATE_FSBASE_DURING_SWITCH
    arch_prctl(ARCH_SET_FS, base);
#endif

    restore_qemu_context(task->qemu_context);
}

void switch_emulation_indirect_call(void);
void switch_emulation_indirect_call(void)
{
    task_t* task = get_task();

    // fix pc
    assert(task->depth >= 0 && task->depth <= MAX_DEPTH);
    task->native_context->pc = task->return_addrs[task->depth - 1];
    task->depth -= 1;

    restore_emulated_context(task->native_context, task->emulated_state);
    task->emulated_state->eip = task->native_context->pc;

    // swap return address
    uint64_t* ret_addr = (uint64_t*)task->emulated_state->regs[SLOT_RSP];
    task->depth += 1;
    assert(task->depth >= 0 && task->depth <= MAX_DEPTH);
    task->return_addrs[task->depth - 1] = *(ret_addr);
    *(ret_addr)                         = RETURN_FROM_EMULATION_SENTINEL;
    _sym_concretize_memory((uint8_t*)ret_addr, sizeof(void*));

#if HYBRID_UPDATE_FSBASE_DURING_SWITCH
    uint64_t base;
    arch_prctl(ARCH_GET_FS, (uint64_t)&base);
    arch_prctl(ARCH_SET_FS, (uint64_t)task->qemu_context->fs_base);
#endif
    printf("[depth=%ld] EMULATED INDIRECT CALL %lx rsp=%lx rdi=%lx *rsp=%lx\n",
           task->depth, task->emulated_state->eip,
           task->emulated_state->regs[SLOT_RSP],
           task->emulated_state->regs[SLOT_RDI],
           task->return_addrs[task->depth - 1]);
    _sym_notify_call(RETURN_FROM_EMULATION_SENTINEL);
#if 0
    for(int i = 0; i < SLOT_GPR_END; i++)
        printf("R[%d] = %lx\n", i, task->emulated_state->regs[i]);
#endif
#if HYBRID_UPDATE_FSBASE_DURING_SWITCH
    arch_prctl(ARCH_SET_FS, base);
#endif
    restore_qemu_context(task->qemu_context);
}

#define PAGE_ALIGNED(addr)                                                     \
    ((void*)((unsigned long)(addr) -                                           \
             ((unsigned long)(addr) & (getpagesize() - 1UL))))
#define PAGE_ALIGNED_SIZE(addr, size)                                          \
    (((size + ((unsigned long)(addr) & (getpagesize() - 1UL))) /               \
          getpagesize() +                                                      \
      1) *                                                                     \
     (getpagesize()))

#define PLT_STUBS_SIZE 10 * 1024 * 1024 // 10 MiB
static uint8_t plt_stubs[PLT_STUBS_SIZE];
static uint8_t runtime_plt_stubs[PLT_STUBS_SIZE];

uint64_t check_indirect_target(uint64_t target, uint64_t* args,
                               uint64_t args_count);

struct timespec t_init;

static void switch_fs_to_native(void) {
    task_t* task = get_task();
    arch_prctl(ARCH_SET_FS, (uint64_t)task->native_context->fs_base);
}

static void switch_fs_to_emulation(void) {
    task_t* task = get_task();
    arch_prctl(ARCH_SET_FS, (uint64_t)task->qemu_context->fs_base);
}

typedef void (*switch_fs_t)(void);
extern switch_fs_t switch_fs_to_native_ptr;
extern switch_fs_t switch_fs_to_emulation_ptr;

//__thread
int  hybrid_init_done = 0;
static CPUState* hybrid_cpu;
void hybrid_init(CPUState *cpu)
{
    if (hybrid_init_done)
        return;

    printf("\nHYBRID INIT\n");

    _sym_pre_initialize_qemu();

    // get_time(&t_init);

    if (getenv("SYMFUSION_PATH_TRACER"))
        hybrid_trace_mode = 1;

    // hybrid_trace_mode = 0;

    char* res = getenv("HYBRID_CONF_FILE");
    if (res)
        parse_config_file(res);

    pid_t tid = syscall(__NR_gettid);

    hybrid_new_task(tid);

    _sym_wrap_indirect_call_set_trumpoline((uint64_t)check_indirect_target);

    switch_fs_to_native_ptr = switch_fs_to_native;
    switch_fs_to_emulation_ptr = switch_fs_to_emulation;

    assert(start_addr);
    hybrid_init_done = 1;

    hybrid_cpu = cpu;
}

#define SymExpr void*
#include "RuntimeCommon.h"

#define RUNTIME_FN_PTR(name, f)                                                \
    if (strcmp(name, #f) == 0) {                                               \
        printf("Runtime function %s: %p\n", name, f);                          \
        return (uint64_t)&f;                                                   \
    }

int         memcmp_symbolized(const void* a, const void* b, size_t n);
char*       strncpy_symbolized(char* dest, const char* src, size_t n);
const char* strchr_symbolized(const char* s, int c);
int         strncmp_symbolized(const char* s1, const char* s2, size_t n);
int         strcmp_symbolized(const char* s1, const char* s2);
int         bcmp_symbolized(const void* s1, const void* s2, size_t n);
int         strlen_symbolized(const void* s1);

static uint64_t get_runtime_function_addr(char* name)
{
    if (strcmp(name, "fread_symbolized") == 0) {
        tcg_abort();
    }
    if (strcmp(name, "fopen_symbolized") == 0) {
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
    // RUNTIME_FN_PTR(name, _sym_print_path_constraints);
    // RUNTIME_FN_PTR(name, _sym_debug_function_after_return);
    RUNTIME_FN_PTR(name, _sym_build_equal);
    RUNTIME_FN_PTR(name, _sym_memmove);
    RUNTIME_FN_PTR(name, memcmp_symbolized);
    RUNTIME_FN_PTR(name, strncmp_symbolized);
    RUNTIME_FN_PTR(name, bcmp_symbolized);
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
    RUNTIME_FN_PTR(name, strcmp_symbolized);
    RUNTIME_FN_PTR(name, strlen_symbolized);
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
    RUNTIME_FN_PTR(name, _sym_build_float_unordered_greater_than);
    RUNTIME_FN_PTR(name, _sym_build_float_ordered_greater_equal);
    RUNTIME_FN_PTR(name, _sym_build_float_unordered_less_than);
    RUNTIME_FN_PTR(name, _sym_build_float_ordered_less_equal);
    RUNTIME_FN_PTR(name, _sym_build_float_ordered_less_than);
    RUNTIME_FN_PTR(name, _sym_build_float_ordered_equal);
    RUNTIME_FN_PTR(name, _sym_build_float_ordered_greater_than);
    RUNTIME_FN_PTR(name, _sym_build_integer128);
    RUNTIME_FN_PTR(name, _sym_get_parameter_expression_with_truncate);
    RUNTIME_FN_PTR(name, _sym_wrap_indirect_call_int);
    RUNTIME_FN_PTR(name, _sym_indirect_call_set_arg_int);
    RUNTIME_FN_PTR(name, _sym_indirect_call_set_arg_count);
    RUNTIME_FN_PTR(name, _sym_check_indirect_call_target);
    RUNTIME_FN_PTR(name, _sym_build_float_unordered_greater_equal);
    RUNTIME_FN_PTR(name, _sym_build_float_unordered);
    RUNTIME_FN_PTR(name, _sym_build_float_unordered_less_equal);
    RUNTIME_FN_PTR(name, _sym_build_float_unordered_equal);
    RUNTIME_FN_PTR(name, _sym_build_fp_abs);
    RUNTIME_FN_PTR(name, _sym_build_fp_sub);
    RUNTIME_FN_PTR(name, _sym_check_consistency);
    RUNTIME_FN_PTR(name, _sym_va_list_start);
    RUNTIME_FN_PTR(name, _sym_build_bool_to_sign_bits);
    RUNTIME_FN_PTR(name, _sym_build_float_ordered_not_equal);
    RUNTIME_FN_PTR(name, _sym_build_float_ordered);
    RUNTIME_FN_PTR(name, _sym_concretize_memory);
    RUNTIME_FN_PTR(name, _sym_initialize);
    RUNTIME_FN_PTR(name, _sym_finalize);
    RUNTIME_FN_PTR(name, _sym_build_insert);
    RUNTIME_FN_PTR(name, _sym_switch_fs_to_native);
    RUNTIME_FN_PTR(name, _sym_switch_fs_to_emulation);

    printf("Add me:\n\t%s\n", name);
    tcg_abort();
    return 0;
}

#if 0
static uint64_t runtime_function_handler(runtime_stub_args_t* args)
{
#if !HYBRID_UPDATE_FSBASE_DURING_SWITCH
    // we now directly jump into the runtime function
    abort();
#else
    task_t*  task = &tasks[0]; // get_task();
    uint64_t base;
    arch_prctl(ARCH_GET_FS, (uint64_t)&base);
    arch_prctl(ARCH_SET_FS, (uint64_t)task->qemu_context->fs_base);
    // printf("FN %lx: arg1=%lx, arg2=%lx, arg3=%lx\n", args->addr, args->arg1,
    // args->arg2, args->arg3);
    // if (args->addr == 0)
    //    tcg_abort();
#endif

    uint64_t (*f)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t) =
        (uint64_t(*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                     uint64_t))args->addr;

    uint64_t res = f(args->arg1, args->arg2, args->arg3, args->arg4, args->arg5,
                     args->arg6);
#if HYBRID_UPDATE_FSBASE_DURING_SWITCH
    arch_prctl(ARCH_SET_FS, base);
#endif
    return res;
}
#endif

static inline TCGTemp* tcg_find_temp_arch_reg(const char* reg_name)
{
    for (int i = 0; i < TCG_TARGET_NB_REGS; i++) {
        TCGTemp* t = &tcg_ctx->temps[i];
        if (t->fixed_reg)
            continue; // not a register
        if (strcmp(t->name, reg_name) == 0)
            return t;
    }
    // printf("Cannot find TCG for %s\n", reg_name);
    // tcg_abort();
    return NULL;
}

int reached_start = 0;

void* get_temp_expr(const char* temp_name);
void* get_temp_expr(const char* temp_name)
{
    if (!reached_start)
        return NULL;

    task_t*  task       = get_task();
    TCGTemp* ret_val_ts = tcg_find_temp_arch_reg(temp_name);
    if (ret_val_ts == NULL)
        return NULL;

    assert(ret_val_ts->symbolic_expression == 1);
    assert(ret_val_ts->mem_coherent == 1);
    assert(ret_val_ts->val_type == TEMP_VAL_MEM);
    uint64_t** ret_val_expr = (uint64_t**)((uint64_t)ret_val_ts->mem_offset +
                                           (uint64_t)task->emulated_state);
    if (*ret_val_expr) {
        size_t current_bits = _sym_bits_helper(*ret_val_expr);
        if (current_bits < 64) {
            *ret_val_expr = _sym_build_zext(*ret_val_expr, 64 - current_bits);
        }
#if HYBRID_DBG_PRINT
        const char* s_expr = _sym_expr_to_string(*ret_val_expr);
        printf("%s: len=%ld %s\n", temp_name, current_bits, s_expr);
#endif
    }
    return *ret_val_expr;
}

static uint64_t total_pre_main = 0;
static uint64_t total_native = 0;
void finalize_execution_stats(void);
void finalize_execution_stats(void) {
    struct timespec t1;
    get_time(&t1);
    uint64_t delta = get_diff_time_microsec(&t_init, &t1);
    fprintf(stderr, "TOTAL RUNNING TIME: %lu\n", delta);
    fprintf(stderr, "A) TOTAL EMULATION: %lu\n", total_emulation);
    fprintf(stderr, "B) TOTAL NATIVE: %lu\n", total_native);
    fprintf(stderr, "C) TOTAL PRE MAIN: %lu\n", total_pre_main);
    fprintf(stderr, "SUM A + B + C: %lu\n", total_pre_main + total_native + total_emulation);
}

void finalize_execution(void);
#if 1
__asm__(
    ".globl finalize_execution\n"
    //
    ".type func, @function\n"
    //
    "finalize_execution:"
    "pushq %rax\n"
    "pushq %rax\n"
    "call finalize_execution_stats\n"
    "call _sym_finalize\n"
    "popq %rdi\n"
    "movq $231, %rax\n"
    "syscall\n"
    // "call exit\n"
    //
);
#else
void finalize_execution(void) {
    struct timespec t1;
    get_time(&t1);
    uint64_t delta = get_diff_time_microsec(&t_init, &t1);
    fprintf(stderr, "Total running time: %lu\n", delta);
    exit(0);
}
#endif

void switch_to_native(uint64_t target, CPUX86State* state, switch_mode_t mode)
{
    assert(hybrid_init_done);
    reached_start = 1;
#if 0
    if (!hybrid_trace_mode)
        exit(0);
#endif
    task_t*     task               = get_task();
    CpuContext* native_cpu_context = task->native_context;

    task->emulated_state = state;

    task->native_context->fs_base = state->segs[R_FS].base;
    arch_prctl(ARCH_GET_FS, (uint64_t)&task->qemu_context->fs_base);

    // printf("NATIVE FS: %lx\n", task->native_context->fs_base);
    // printf("EMULATION FS: %lx\n", task->qemu_context->fs_base);

    // fprintf(stderr, "LIB: START=%lx END=%lx INDIRECT=%lx\n",
    // hybrid_start_code, hybrid_end_code, check_indirect_target); tcg_abort();

    concretize_args(target, state, task);

    // uint64_t original_target = target;

    if (mode == RETURN_FROM_EMULATION) {
        assert(task->depth > 0);
        // assert(task->depth == 1); // FIXME

        native_cpu_context->pc     = task->return_addrs[task->depth - 1];
        target                     = native_cpu_context->pc;
        task->emulated_context->pc = native_cpu_context->pc;
        task->depth -= 1;

    } else if (mode == EMULATION_TO_NATIVE) {
        assert(task->depth > 0);

        // swap return address
        uint64_t* ret_addr = (uint64_t*)task->emulated_state->regs[SLOT_RSP];
        task->native_context->pc = *(ret_addr);

        printf("EMULATION_TO_NATIVE: ret_addr=%lx rsp=%p\n",
               task->native_context->pc, ret_addr);

        task->depth += 1;
        assert(task->depth >= 0 && task->depth <= MAX_DEPTH);
        task->return_addrs[task->depth - 1] = *(ret_addr);

        *(ret_addr) = (uint64_t)save_native_context_safe_back_to_emulation;

    }  else if (mode == INITIAL_JUMP_INTO_NATIVE) {

        uint64_t* ret_addr = (uint64_t*)task->emulated_state->regs[SLOT_RSP];
        task->depth += 1;
        assert(task->depth >= 0 && task->depth <= MAX_DEPTH);
        task->return_addrs[task->depth - 1] = *(ret_addr);

        *(ret_addr) = (uint64_t)finalize_execution;
    }

    _sym_set_emulation_mode(0);
    printf("Switching to native: 0x%lx...\n", target);

    // patch PLTs && syscall insns
    if (target == start_addr) {

        get_time(&t_emulation_end);
        get_time(&t_native_end);
        get_time(&t1_start);
#if 1
        struct timespec t0;
        get_time(&t0);
#endif
        assert(mode == INITIAL_JUMP_INTO_NATIVE);

        mprotect(PAGE_ALIGNED(plt_stubs),
                 PAGE_ALIGNED_SIZE(plt_stubs, sizeof(plt_stubs)),
                 PROT_EXEC | PROT_READ | PROT_WRITE);
        mprotect(
            PAGE_ALIGNED(runtime_plt_stubs),
            PAGE_ALIGNED_SIZE(runtime_plt_stubs, sizeof(runtime_plt_stubs)),
            PROT_EXEC | PROT_READ | PROT_WRITE);

        GSList* next = plt_aliases;
        while (next != NULL) {
            plt_alias_t* plt_alias = next->data;
            next                   = g_slist_next(next);

            uint64_t base_address     = 0x0;
            GSList*  next_mmaped_file = mmaped_files;
            while (next_mmaped_file != NULL) {
                mmap_file_t* mmaped_file = (mmap_file_t*)next_mmaped_file->data;
                next_mmaped_file         = g_slist_next(next_mmaped_file);

                if (strcmp(mmaped_file->name, plt_alias->from_obj) == 0) {
                    base_address = mmaped_file->addr;
                    break;
                }
            }
            assert(base_address);

            uint64_t base_address_to_obj = 0x0;
            // printf("base address of to object %s: %lx\n", plt_alias->to_obj,
            // base_address_to_obj);
            if (strcmp(plt_alias->to_obj, "main_image") != 0) {
                next_mmaped_file = mmaped_files;
                while (next_mmaped_file != NULL) {
                    mmap_file_t* mmaped_file =
                        (mmap_file_t*)next_mmaped_file->data;
                    next_mmaped_file = g_slist_next(next_mmaped_file);

                    // printf("mmaped file: %s\n", mmaped_file->name);

                    if (strcmp(basename(mmaped_file->name),
                               plt_alias->to_obj) == 0) {
                        base_address_to_obj = mmaped_file->addr;
                        break;
                    }
                }
                assert(base_address_to_obj);
            }

            uint64_t addr = base_address + plt_alias->from_got_entry;
            printf("\nbase address of from object %s: %lx\n",
                   plt_alias->from_obj, base_address);
            printf("base address of to object %s: %lx\n", plt_alias->to_obj,
                   base_address_to_obj);

            printf(
                "GOT entry at %lx [%lx]: jumping to plt %lx with got entry "
                "%lx\n",
                addr, *((uint64_t*)addr),
                base_address_to_obj + plt_alias->to_plt_entry,
                *((uint64_t*)(base_address_to_obj + plt_alias->to_got_entry)));

            if (*((uint64_t*)addr) ==
                (base_address_to_obj + plt_alias->to_plt_entry)) {
                uint8_t* a = PAGE_ALIGNED(addr);
                mprotect(a, getpagesize(), PROT_EXEC | PROT_READ | PROT_WRITE);
                *((uint64_t*)addr) = *(
                    (uint64_t*)(base_address_to_obj + plt_alias->to_got_entry));

                printf("FIXED PLT REDIRECT\n");
            } else {
                printf("SKIPPING FIX OF PLT REDIRECT\n");
            }
        }

        uint8_t* plt_stub = (uint8_t*)&plt_stubs;
        next              = plt_patches;
        while (next != NULL) {
            plt_patch_t* patch     = next->data;
            char*        name      = patch->name;
            next                   = g_slist_next(next);
            uint64_t base_address  = 0x0;
            int      is_main_image = strcmp(name, "main_image") == 0;
            if (!is_main_image) {
                GSList* next_mmaped_file  = mmaped_files;
                int     mmaped_file_found = 0;
                while (next_mmaped_file != NULL) {
                    mmap_file_t* mmaped_file =
                        (mmap_file_t*)next_mmaped_file->data;
                    next_mmaped_file = g_slist_next(next_mmaped_file);

                    if (strcmp(mmaped_file->name, patch->name) == 0) {
                        mmaped_file_found = 1;
                        base_address      = mmaped_file->addr;
                        break;
                    }
                }
                if (!mmaped_file_found) {
                    printf("PLT PATCH ON %s NOT FOUND\n", patch->name);
                    tcg_abort();
                }
            }

            GSList* offsets = patch->offsets;
            while (offsets != NULL) {
                uint64_t offset = (uint64_t)offsets->data;
                printf("[%s] BASE=%lx OFFSET: %lx\n", basename(name),
                       base_address, offset);
                offsets = g_slist_next(offsets);

                void** plt = (void**)(base_address + offset);

                memcpy(plt_stub, dummy_plt_stub, 16);

                assert(plt_stub[0] == 0x68);                  // push opcode
                *((uint16_t*)&plt_stub[1]) = plt_stubs_count; // pushed constant

                assert(plt_stub[5] == 0xe9); // relative jump
                uint64_t rip = (uint64_t)&plt_stub[10];
                uint64_t delta;
                if (((uint64_t)save_native_context_safe) > rip)
                    delta = ((uint64_t)save_native_context_safe) - rip;
                else
                    delta = -(rip - ((uint64_t)save_native_context_safe));

                *((uint32_t*)&plt_stub[6]) = (uint32_t)delta; // relative offset

                printf("[%s] PLT entry %d at %p: %p => %p %p\n", name,
                       plt_stubs_count, &plt[0], plt[0], dummy_plt_stub,
                       plt_stub);
                shadow_plt[plt_stubs_count] = (uint64_t)plt[0];

                uint8_t* a = PAGE_ALIGNED(&plt[0]);
                mprotect(a, getpagesize(), PROT_EXEC | PROT_READ | PROT_WRITE);

                plt[0] = plt_stub;

                plt_stubs_count++;
                plt_stub += 16;
                assert(plt_stubs_count < MAX_PLT_ENTRIES);
                assert(plt_stub < plt_stubs + sizeof(plt_stubs));
            }
        }

        next = syscall_patches;
        while (next != NULL) {
            syscall_patch_t* patch = (syscall_patch_t*)next->data;
            next                   = g_slist_next(next);

            // printf("SYSCALL PATCH ON %s\n", patch->name);

            uint64_t base_address = 0x0;
            if (strcmp("main_image", patch->name) != 0) {
                GSList* next_mmaped_file  = mmaped_files;
                int     mmaped_file_found = 0;
                while (next_mmaped_file != NULL) {
                    mmap_file_t* mmaped_file =
                        (mmap_file_t*)next_mmaped_file->data;
                    next_mmaped_file = g_slist_next(next_mmaped_file);

                    if (strcmp(mmaped_file->name, patch->name) == 0) {
                        // printf("SYSCALL PATCH ON %s FOUND\n", patch->name);
                        mmaped_file_found = 1;
                        base_address      = mmaped_file->addr;
                        break;
                    }
                }
                if (!mmaped_file_found) {
                    printf("SYSCALL PATCH ON %s NOT FOUND\n", patch->name);
                    tcg_abort();
                }
            }

            GSList* syscall_insns = patch->offsets;
            while (syscall_insns != 0) {
                uint64_t syscall_insn = (uint64_t)syscall_insns->data;
                syscall_insns         = g_slist_next(syscall_insns);

                uint8_t* bytes = (uint8_t*)(base_address + syscall_insn);
                if (bytes[0] == 0x0f && bytes[1] == 0x05) {
                    // printf("Found syscall opcodes!\n");
                    uint8_t* a = PAGE_ALIGNED(&bytes[1]);
                    if (a > &bytes[1])
                        tcg_abort();

                    int r = mprotect(a, getpagesize(),
                                     PROT_EXEC | PROT_READ | PROT_WRITE);
                    if (r == 0) {
                        // printf("Writing at %p\n", &bytes[1], a);
                        bytes[1] = 0x0b;
                        // printf("Done\n", a);
                    } else {
                        // printf("Failed to make code writable at %p\n", a);
                        tcg_abort();
                    }
                } else {
                    printf("Cannot find syscall opcodes at 0x%lx + 0x%lx for "
                           "%s!\n",
                           base_address, syscall_insn, patch->name);
                    printf("[%p] %x\n", &bytes[0], bytes[0]);
                    printf("[%p] %x\n", &bytes[1], bytes[1]);
                    tcg_abort();
                }
            }
        }

        int      runtime_stubs_count = 0;
        uint8_t* runtime_stub        = (uint8_t*)&runtime_plt_stubs;
        next                         = runtime_patches;
        while (next != NULL) {
            runtime_patch_t* patch = (runtime_patch_t*)next->data;
            next                   = g_slist_next(next);

            printf("RUNTIME PATCH ON %s\n", patch->name);

            uint64_t base_address = 0x0;
            if (strcmp("main_image", patch->name) != 0) {
                GSList* next_mmaped_file  = mmaped_files;
                int     mmaped_file_found = 0;
                while (next_mmaped_file != NULL) {
                    mmap_file_t* mmaped_file =
                        (mmap_file_t*)next_mmaped_file->data;
                    next_mmaped_file = g_slist_next(next_mmaped_file);

                    if (strcmp(mmaped_file->name, patch->name) == 0) {
                        // printf("SYSCALL PATCH ON %s FOUND\n", patch->name);
                        mmaped_file_found = 1;
                        base_address      = mmaped_file->addr;
                        break;
                    }
                }
                if (!mmaped_file_found) {
                    printf("RUNTIME PATCH ON %s NOT FOUND\n", patch->name);
                    tcg_abort();
                }
            }

            GSList* runtime_plt = patch->patches;
            while (runtime_plt != 0) {
                runtime_plt_patch_t* p =
                    (runtime_plt_patch_t*)runtime_plt->data;
                runtime_plt = g_slist_next(runtime_plt);
#if 0
                if (strcmp("_sym_initialize", p->name) == 0)
                    continue;
#endif
                // printf("RUNTIME PATCH FOR FUNCTION %s\n", p->name);

                void** plt = (void**)(base_address + p->offset);

                // printf("[%s] RUNTIME PLT entry %s at %p\n", patch->name,
                // p->name, plt);
#if HYBRID_UPDATE_FSBASE_DURING_SWITCH
                memcpy(runtime_stub, dummy_runtime_plt_stub, 64);

                assert(runtime_stub[8] == 0x48); // movaps opcode
                *((uint64_t*)&runtime_stub[10]) =
                    get_runtime_function_addr(p->name); // pushed constant

                assert(runtime_stub[22] == 0xe8); // relative call
                uint64_t rip = (uint64_t)&runtime_stub[27];
                uint64_t delta;
                if (((uint64_t)runtime_function_handler) > rip)
                    delta = ((uint64_t)runtime_function_handler) - rip;
                else
                    delta = -(rip - ((uint64_t)runtime_function_handler));

                *((uint32_t*)&runtime_stub[23]) =
                    (uint32_t)delta; // relative offset

                uint8_t* a = PAGE_ALIGNED(&plt[0]);
                mprotect(a, getpagesize(), PROT_EXEC | PROT_READ | PROT_WRITE);

                // printf("OLD: %p - NEW: %p - RETURN_HANLDERL %p\n", plt[0],
                // runtime_stub, return_handler_from_emulation);

                plt[0] = (void*) runtime_stub;
#else
                plt[0] = (void*) get_runtime_function_addr(p->name); // runtime_stub;
#endif
                runtime_stubs_count++;
                runtime_stub += 64;
                assert(runtime_stub <
                       runtime_plt_stubs + sizeof(runtime_plt_stubs));
            }
        }
#if 1
        // libc
        uint64_t libc_base_address = 0;
        GSList*  next_mmaped_file  = mmaped_files;
        while (next_mmaped_file != NULL) {
            mmap_file_t* mmaped_file = (mmap_file_t*)next_mmaped_file->data;
            next_mmaped_file         = g_slist_next(next_mmaped_file);

            if (strcmp(mmaped_file->name, libc_path) == 0) {
                libc_base_address = mmaped_file->addr;
                break;
            }
        }
        for (int i = 0; libc_concrete_funcs[i] > 0 &&
                        i < sizeof(libc_concrete_funcs) / sizeof(uint64_t);
             i++) {
            libc_concrete_funcs[i] += libc_base_address;
            printf("LIBC FN TO CONCRETIZE at %lx [%lx]\n",
                   libc_concrete_funcs[i], libc_base_address);
        }

        for (int i = 0;
             libc_models[i] > 0 && i < sizeof(libc_models) / sizeof(uint64_t);
             i++) {
            libc_models[i] += libc_base_address;
            printf("LIBC MODEL at %lx [%lx]\n", libc_models[i],
                   libc_base_address);
        }

        libc_setjmp_addr[0] += libc_base_address;
        libc_setjmp_addr[1] += libc_base_address;
        printf("SIGSETJMP at %lx [%lx]\n", libc_setjmp_addr[0],
               libc_base_address);
        libc_longjmp_addr[0] += libc_base_address;
        libc_longjmp_addr[1] += libc_base_address;
        printf("SIGLONGJMP at %lx [%lx]\n", libc_longjmp_addr[0],
               libc_base_address);
#endif
#if 1
        uint64_t delta;
        struct timespec t1;
        get_time(&t1);
        // delta = get_diff_time_microsec(&t0, &t1);
        // fprintf(stderr, "Setup time: %lu\n", delta);
        delta = get_diff_time_microsec(&t_init, &t1);
        total_pre_main = delta;
        // fprintf(stderr, "PRE MAIN: %lu\n", delta);
#endif
    }

    /* Initialize the symbolic backend */
    forkserver();
    _sym_initialize_qemu();

#if 0
    uint64_t base;
    arch_prctl(ARCH_GET_FS, &base);
    printf("FSBASE QEMU: %lx\n", base);
#endif
    // save_qemu_context_safe(task->qemu_context);
    save_qemu_context_safe();
#if 0
    static int count = 0;
    struct timespec t1;
    get_time(&t1);
    uint64_t delta = get_diff_time_microsec(&t_init, &t1);
    fprintf(stderr, "Time [count=%d]: %lu\n", count++, delta / 1000);
#endif
    if (task->qemu_context->valid) {
#if 0
        for (int i = 0; i < SLOT_GPR_END; i++)
            printf("R[%d] = %lx\n", i, task->qemu_context->gpr[i]);
        printf("PC = %lx\n", task->qemu_context->pc);
#endif

        // printf("RSP QEMU: %lx\n", qemu_cpu_context.gpr[SLOT_RSP]);

        task->qemu_context->valid = 0;
        save_emulated_context(task->emulated_state,
                              mode == RETURN_FROM_EMULATION);
#if 0
        struct sigaction action;
        action.sa_sigaction = &hybrid_syscall_handler;
        action.sa_flags     = SA_SIGINFO | SA_RESTART;
        sigaction(SIGILL, &action, &task->qemu_context->sigill_handler);
#endif
        // printf("\n[%lx] Resuming native to 0x%lx [0x%lx] [0x%lx]\n",
        // task->tid, target, original_target,
        // (uint64_t)&return_handler_from_emulation); printf("\n[%lx] Resuming
        // native to 0x%lx [0x%lx] [0x%lx]\n", task->tid, target,
        // task->emulated_context->pc, task->emulated_state->eip);

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
        if (mode == RETURN_FROM_EMULATION) {
            // symbolic return value

            TCGTemp* ret_val_ts = tcg_find_temp_arch_reg("rax_expr");

            // these sanity checks make sense only
            // after jitting... should we remove them?
#if 0
            assert(ret_val_ts->symbolic_expression == 1);
            assert(ret_val_ts->mem_coherent == 1);
            assert(ret_val_ts->val_type == TEMP_VAL_MEM);
#endif
            uint64_t** ret_val_expr =
                (uint64_t**)((uint64_t)ret_val_ts->mem_offset +
                             (uint64_t)task->emulated_state);

            if (hybrid_trace_mode)
                *ret_val_expr = NULL;
            
            if (*ret_val_expr) {
                size_t current_bits = _sym_bits_helper(*ret_val_expr);
                if (current_bits < 64) {
                    *ret_val_expr =
                        _sym_build_zext(*ret_val_expr, 64 - current_bits);
                }
                // const char *s_expr = _sym_expr_to_string(*ret_val_expr);
                // printf("RETURN EXP: len=%ld %s\n", current_bits, s_expr);
            }
            _sym_set_return_expression(*ret_val_expr);

            // concrete floating return value

            __m128i xmm0 = _mm_loadu_si128(
                (__m128i_u const*)&task->emulated_state->xmm_regs[0]);
            __m128i xmm1 = _mm_loadu_si128(
                (__m128i_u const*)&task->emulated_state->xmm_regs[1]);
            __asm__("movups %0, %%xmm0\n"
                    "movups %0, %%xmm1\n"
                    :
                    : "m"(xmm0), "m"(xmm1)
                    : "xmm0", "xmm1");
        } else if (mode == EMULATION_TO_NATIVE) {
            // move symbolic arguments
            // NOTE: we do not know the number of argumtents
            // NOTE: we do not know the type of the arguments
            // FIXME: we support up to 6 integer arguments

            const char* arg_regs[] = {
                "rdi_expr", "rsi_expr", "rdx_expr",
                "rcx_expr", "r8_expr",  "r9_expr",
            };

            for (int i = 0; i < sizeof(arg_regs) / sizeof(char*); i++) {
                TCGTemp*   reg_expr_tmp = tcg_find_temp_arch_reg(arg_regs[i]);
                uint64_t** reg_expr =
                    (uint64_t**)((uint64_t)reg_expr_tmp->mem_offset +
                                 (uint64_t)task->emulated_state);
                if (*reg_expr) {
                    size_t current_bits = _sym_bits_helper(*reg_expr);
                    if (current_bits < 64) {
                        // *ret_val_expr = _sym_build_zext(*ret_val_expr, 64 -
                        // current_bits);
                    }
#if HYBRID_DBG_PRINT
                    const char* s_expr = _sym_expr_to_string(*reg_expr);
                    printf("%s: len=%ld %s\n", arg_regs[i], current_bits,
                           s_expr);
#endif
                    _sym_set_parameter_expression(i, *reg_expr);
                }
            }
        }

#if 0
        struct timespec t1;
        get_time(&t1);
        fprintf(stderr, "Time: %ld\n", get_diff_time_microsec(&t_init, &t1) / 1000);
#endif
        printf("\n[depth=%ld] Resuming native to 0x%lx [0x%lx]\n", task->depth,
               target, task->emulated_context->pc);

        // printf("NATIVE FS: %lx\n", task->native_context->fs_base);
        // printf("EMULATION FS: %lx\n", task->qemu_context->fs_base);

        // uint64_t base;
        // arch_prctl(ARCH_GET_FS, &base);
        // printf("FSBASE: %lx\n", base);

        _sym_set_emulation_mode(0);
        _sym_set_concrete_mode(0);

        get_time(&t_emulation_end);
        uint64_t delta = get_diff_time_microsec(&t_native_end, &t_emulation_end);
        total_emulation += delta;
        printf("TOTAL EMULATION: %lu\n", total_emulation);

        restore_native_context(task->emulated_context, target);

    } else {

        get_time(&t_native_end);
        uint64_t delta = get_diff_time_microsec(&t_emulation_end, &t_native_end);
        total_native += delta;
        printf("TOTAL NATIVE: %lu\n", total_native);

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

        // FIXME: what to do when returning from native back into emulation?

#if HYBRID_LIB_CONCRETE_MODE
        int enable_concrete_mode = 1;
        for(int i = 0; libc_models[i] != 0; i++) {
            if (libc_models[i] == task->emulated_state->eip) {
                enable_concrete_mode = 0;
                break;
            }
        }

        if (enable_concrete_mode) {
            _sym_set_concrete_mode(1);
            printf("ENABLING CONCRETIZATION MODE AT %lx\n", task->emulated_state->eip);
        } else {
            _sym_set_concrete_mode(0);
            printf("DISABLING CONCRETIZATION MODE AT %lx\n", task->emulated_state->eip);
        }
#else
        int enable_concrete_mode = 0;
#endif
        const char* arg_regs[] = {
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
        // printf("\nArgument count: %d\n", args_count);
#if 0
        printf("RDI: %lx\n", task->emulated_state->regs[SLOT_RDI]);
        printf("RSI: %lx\n", task->emulated_state->regs[SLOT_RSI]);
        printf("RDX: %lx\n", task->emulated_state->regs[SLOT_RDX]);
#endif
        int int_arg_count = 0;
        for (int i = 0; i < args_count; i++) {
            void*   expr   = enable_concrete_mode ? NULL : _sym_get_parameter_expression(i);
            uint8_t is_int = _sym_is_int_parameter(i);
            // printf("Argument %d is int: %d\n", i, is_int);

            if (hybrid_trace_mode)
                expr = NULL;

            if (is_int) {
                if (int_arg_count < 6) {
                    // printf("Setting symbolic regs: %s\n",
                    // arg_regs[int_arg_count]);
                    TCGTemp* arg = NULL;
                    if (!hybrid_trace_mode)
                        arg = tcg_find_temp_arch_reg(arg_regs[int_arg_count]);
                    if (arg) {
                        // these sanity checks make sense only
                        // after jitting... should we remove them?
                        assert(arg->symbolic_expression == 1);
                        assert(arg->mem_coherent == 1);
                        assert(arg->val_type == TEMP_VAL_MEM);

                        uint64_t** arg_expr =
                            (uint64_t**)((uint64_t)arg->mem_offset +
                                         (uint64_t)task->emulated_state);
                        if (expr) {
                            size_t current_bits = _sym_bits_helper(expr);
                            if (current_bits < 64) {
                                expr = _sym_build_zext(expr, 64 - current_bits);
                            }
                            printf("%s: %s\n", arg_regs[int_arg_count],
                                   _sym_expr_to_string(expr));
                        }
                        *arg_expr = expr;

#if HYBRID_DBG_CONSISTENCY_CHECK
                        const int arg_regs_id[] = {SLOT_RDI, SLOT_RSI, SLOT_RDX,
                                                   SLOT_RCX, SLOT_R8,  SLOT_R9};
                        // fprintf(stderr, "Checking arg reg %s consistency\n",
                        // arg_regs[int_arg_count]);
                        _sym_check_consistency(
                            expr,
                            task->emulated_state
                                ->regs[arg_regs_id[int_arg_count]],
                            task->emulated_state->eip);
#endif
                    }
                } else {
                    uint64_t arg_stack_index = int_arg_count - 6;
                    // printf("ESP: %lx\n",
                    // task->emulated_state->regs[SLOT_RSP]);
                    // printf("offset(xmm_regs): %x\n", offsetof(CPUX86State,
                    // xmm_regs)); printf("NATIVE RSP: %lx\n",
                    // task->native_context->gpr[SLOT_RSP]);
                    uint64_t arg_stack_addr =
                        task->emulated_state->regs[SLOT_RSP] +
                        (arg_stack_index + 1) * 8;
                    if (expr) {
                        size_t current_bits = _sym_bits_helper(expr);
                        if (current_bits < 64) {
                            expr = _sym_build_zext(expr, 64 - current_bits);
                        }
                        // const char *s_expr = _sym_expr_to_string(expr);
                        // printf("stack_arg[%d]: %s\n", arg_stack_index,
                        // s_expr);
                        _sym_write_memory(NULL, (uint8_t*)arg_stack_addr, 8, expr, 1, *((uint64_t*)arg_stack_addr));
                    } else {
                        _sym_concretize_memory((uint8_t*)arg_stack_addr, 8);
                    }
                }
                int_arg_count++;
            }
        }

        // RAX is used in variadic functions for # of FP args
        TCGTemp*   arg      = tcg_find_temp_arch_reg("rax_expr");
        uint64_t** arg_expr = (uint64_t**)((uint64_t)arg->mem_offset +
                                           (uint64_t)task->emulated_state);
        *arg_expr           = NULL;

        // we reset symbolically the XMM regs...
        for (int i = 0; i < 8; i++) {
            _sym_concretize_memory((uint8_t*)&task->emulated_state->xmm_regs[i]._q_ZMMReg[0], 8);
            _sym_concretize_memory((uint8_t*)&task->emulated_state->xmm_regs[i]._q_ZMMReg[1], 8);
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
        _sym_set_emulation_mode(1);
    }
}

void switch_back_to_native(uint64_t target, CPUX86State* emulated_state)
{
    tcg_abort();
}

int is_hooked_plt_entry(uint64_t target)
{
    if (target >= (uint64_t)&plt_stubs &&
        target <= (uint64_t)&plt_stubs[PLT_STUBS_SIZE]) {
        return 1;
    }
    return 0;
}

void hybrid_stub(task_t* task)
{
    printf("Native return address: %lx\n", task->return_addrs[task->depth - 1]);
    return;
}

#define DEBUG_SYSCALLS      1
#define DEBUG_SYSCALLS_TIME 0
void hybrid_syscall(uint64_t retval, uint64_t num, uint64_t arg1, uint64_t arg2,
                    uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6,
                    uint64_t arg7, uint64_t arg8)
{
#if DEBUG_SYSCALLS_TIME
    {
        struct timespec t1;
        get_time(&t1);
        uint64_t delta = get_diff_time_microsec(&t_init, &t1);
        fprintf(stderr, "Time before syscall %ld: %lu\n", num, delta / 1000);
    }
#endif

#if DEBUG_SYSCALLS
    // task_t* task = get_task();
#endif
    switch (num) {
        case TARGET_NR_openat:
        case TARGET_NR_open: {
            int fd = retval;
            if (fd >= 0) {
                char* fname = (char*)(num == TARGET_NR_open ? arg1 : arg2);
#if DEBUG_SYSCALLS
                printf("[%lu] SYSCALL: open(%s) = %d\n", task->tid, fname, fd);
#endif
                if (fd >= MAX_MMAP_FILES)
                    tcg_abort();
                if (open_files[fd].state != FILE_STATE_INVALID)
                    tcg_abort();
                open_files[fd].state = FILE_STATE_OPEN;
                open_files[fd].name  = strdup(fname);
            }
            break;
        }
#if 1
        case TARGET_NR_stat: {
#if DEBUG_SYSCALLS
            printf("[%lu] SYSCALL: stat(%s) = %d\n", task->tid, (char*)arg1,
                   (int)retval);
#endif
            break;
        }
#endif
        case TARGET_NR_close: {
            int fd = arg1;
            if (fd >= 0) {
#if DEBUG_SYSCALLS
                printf("[%lu] SYSCALL: close(%d)\n", task->tid, fd);
#endif
                if (fd >= MAX_MMAP_FILES)
                    tcg_abort();
                if (open_files[fd].state != FILE_STATE_OPEN)
                    tcg_abort();
                open_files[fd].state = FILE_STATE_INVALID;
                open_files[fd].name  = NULL;
            }
            break;
        }

        case TARGET_NR_mmap: {
            int fd   = arg5;
            int prot = arg3;
#if DEBUG_SYSCALLS
            printf("[%lu] SYSCALL: mmap(%lx, %ld, %d, %d, %d, %lu) = 0x%lx\n",
                   task->tid, arg1, (size_t)arg2, prot, (int)arg4, fd,
                   (off_t)arg6, retval);
#endif
            if (fd >= 0 && prot & PROT_EXEC) {
                if (fd >= MAX_MMAP_FILES)
                    tcg_abort();
                if (open_files[fd].state != FILE_STATE_OPEN)
                    tcg_abort();
                mmap_file_t* mft = g_malloc0(sizeof(mmap_file_t));
                mft->name        = open_files[fd].name;
                mft->addr        = retval;
                mmaped_files     = g_slist_append(mmaped_files, (gpointer)mft);

                if (prot & PROT_EXEC) {
                    char* name = basename(mft->name);
                    // FIXME: do this for all libs that have been
                    // instrumented...

                    printf("LIB: %s,%lx,%lx\n", name, retval, retval + arg2);

                    if ((strcmp(name, "libc++.so.1") == 0 ||
                         strcmp(name, "libc++abi.so.1") == 0) &&
                        (strstr(mft->name, "libcxx_symcc") != NULL ||
                         strstr(mft->name, "libcxx_install") != NULL)) {
                        if (strcmp(name, "libc++.so.1") == 0) {
                            hybrid_start_lib_1 = retval;
                            hybrid_end_lib_1   = retval + arg2;
                            printf("Found instrumented libc++ lib!\n");
                        } else if (strcmp(name, "libc++abi.so.1") == 0) {
                            hybrid_start_lib_2 = retval;
                            hybrid_end_lib_2   = retval + arg2;
                            printf("Found instrumented libc++abi lib!\n");
                        } else
                            tcg_abort();
                    } else {
#if 0
                        printf("FILE: %s\n", mft->name);
                        printf("Mapping executable code. Removing executable "
                               "permission at %lx...\n",
                               retval);
                        mprotect((void*)retval, arg2, prot & ~PROT_EXEC);
#endif
                    }
                }
            }
            break;
        }

        case TARGET_NR_clone: {
#if DEBUG_SYSCALLS
            printf("[%lu] SYSCALL: clone() = 0x%lx\n", task->tid, retval);
#endif
            break;
        }

        case TARGET_NR_writev:
        case TARGET_NR_write: {
#if DEBUG_SYSCALLS
            printf("[%lu] SYSCALL: write(%ld, ..., %ld) = %ld\n", task->tid,
                   arg1, arg3, retval);
#endif
            break;
        }

        case TARGET_NR_brk: {
#if DEBUG_SYSCALLS
            printf("[%lu] SYSCALL: brk(%lx) = %lx\n", task->tid, arg1, retval);
#endif
            break;
        }

        case TARGET_NR_mprotect: {
#if DEBUG_SYSCALLS
            printf("[%lu] SYSCALL: mprotect(%lx, %ld, %ld) = %lx\n", task->tid,
                   arg1, arg2, arg3, retval);
#endif
            break;
        }

        case TARGET_NR_sysinfo: {
#if DEBUG_SYSCALLS
            printf("[%lu] SYSCALL: sysinfo(%lx) = %lx\n", task->tid, arg1,
                   retval);
#endif
            _sym_concretize_memory((uint8_t*)arg1, sizeof(struct sysinfo));
            break;
        }

        default:
#if DEBUG_SYSCALLS
            printf("[%lu] SYSCALL: %ld => 0x%lx\n", task->tid, num, retval);
#endif
            break;
    }

#if DEBUG_SYSCALLS_TIME
    {
        struct timespec t1;
        get_time(&t1);
        uint64_t delta = get_diff_time_microsec(&t_init, &t1);
        fprintf(stderr, "Time after syscall: %lu\n", delta / 1000);
    }
#endif

    return;
}

uint64_t check_indirect_target(uint64_t target, uint64_t* args,
                               uint64_t args_count)
{
#if 0
    uint64_t* a = (uint64_t*)0x40007fead0;
    if (*a == 0x40007feae0)
        printf("VALUE %lx AT %lx\n", 0x40007feae0, 0x40007fead0);
    // assert(*a != 0x40007feae0);
#endif
    task_t* task = get_task();
    if (reached_start &&
        ((target >= hybrid_start_code && target <= hybrid_end_code) ||
         (target >= hybrid_start_lib_1 && target <= hybrid_end_lib_1) ||
         (target >= hybrid_start_lib_2 && target <= hybrid_end_lib_2))) {

        if (args == NULL) // this was a check on the target
            return 0;

        printf("indirect call target=%lx\n", target);

#if HYBRID_UPDATE_FSBASE_DURING_SWITCH
        arch_prctl(ARCH_SET_FS, (uint64_t)task->native_context->fs_base);
#endif
        uint64_t res;
        // run in native mode
        switch (args_count) {
            case 0: {
                uint64_t (*f)(void) = (uint64_t(*)(void))target;
                res                 = f();
                break;
            }
            case 1: {
                uint64_t (*f)(uint64_t) = (uint64_t(*)(uint64_t))target;
                res                     = f(args[0]);
                break;
            }
            case 2: {
                uint64_t (*f)(uint64_t, uint64_t) =
                    (uint64_t(*)(uint64_t, uint64_t))target;
                res = f(args[0], args[1]);
                break;
            }
            case 3: {
                uint64_t (*f)(uint64_t, uint64_t, uint64_t) =
                    (uint64_t(*)(uint64_t, uint64_t, uint64_t))target;
                res = f(args[0], args[1], args[2]);
                break;
            }
            case 4: {
                uint64_t (*f)(uint64_t, uint64_t, uint64_t, uint64_t) =
                    (uint64_t(*)(uint64_t, uint64_t, uint64_t, uint64_t))target;
                res = f(args[0], args[1], args[2], args[3]);
                break;
            }
            case 5: {
                uint64_t (*f)(uint64_t, uint64_t, uint64_t, uint64_t,
                              uint64_t) =
                    (uint64_t(*)(uint64_t, uint64_t, uint64_t, uint64_t,
                                 uint64_t))target;
                res = f(args[0], args[1], args[2], args[3], args[4]);
                break;
            }
            case 6: {
                uint64_t (*f)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                              uint64_t) =
                    (uint64_t(*)(uint64_t, uint64_t, uint64_t, uint64_t,
                                 uint64_t, uint64_t))target;
                res = f(args[0], args[1], args[2], args[3], args[4], args[5]);
                break;
            }
            case 7: {
                uint64_t (*f)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                              uint64_t, uint64_t) =
                    (uint64_t(*)(uint64_t, uint64_t, uint64_t, uint64_t,
                                 uint64_t, uint64_t, uint64_t))target;
                res = f(args[0], args[1], args[2], args[3], args[4], args[5],
                        args[6]);
                break;
            }
            case 8: {
                uint64_t (*f)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                              uint64_t, uint64_t, uint64_t) =
                    (uint64_t(*)(uint64_t, uint64_t, uint64_t, uint64_t,
                                 uint64_t, uint64_t, uint64_t, uint64_t))target;
                res = f(args[0], args[1], args[2], args[3], args[4], args[5],
                        args[6], args[7]);
                break;
            }
            case 9: {
                uint64_t (*f)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                              uint64_t, uint64_t, uint64_t, uint64_t) =
                    (uint64_t(*)(uint64_t, uint64_t, uint64_t, uint64_t,
                                 uint64_t, uint64_t, uint64_t, uint64_t,
                                 uint64_t))target;
                res = f(args[0], args[1], args[2], args[3], args[4], args[5],
                        args[6], args[7], args[8]);
                break;
            }
            case 10: {
                uint64_t (*f)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                              uint64_t, uint64_t, uint64_t, uint64_t,
                              uint64_t) =
                    (uint64_t(*)(uint64_t, uint64_t, uint64_t, uint64_t,
                                 uint64_t, uint64_t, uint64_t, uint64_t,
                                 uint64_t, uint64_t))target;
                res = f(args[0], args[1], args[2], args[3], args[4], args[5],
                        args[6], args[7], args[8], args[9]);
                break;
            }
            case 11: {
                uint64_t (*f)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                              uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                              uint64_t) =
                    (uint64_t(*)(uint64_t, uint64_t, uint64_t, uint64_t,
                                 uint64_t, uint64_t, uint64_t, uint64_t,
                                 uint64_t, uint64_t, uint64_t))target;
                res = f(args[0], args[1], args[2], args[3], args[4], args[5],
                        args[6], args[7], args[8], args[9], args[10]);
                break;
            }
            case 12: {
                uint64_t (*f)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                              uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                              uint64_t, uint64_t) =
                    (uint64_t(*)(uint64_t, uint64_t, uint64_t, uint64_t,
                                 uint64_t, uint64_t, uint64_t, uint64_t,
                                 uint64_t, uint64_t, uint64_t, uint64_t))target;
                res = f(args[0], args[1], args[2], args[3], args[4], args[5],
                        args[6], args[7], args[8], args[9], args[10], args[11]);
                break;
            }
            case 13: {
                uint64_t (*f)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                              uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                              uint64_t, uint64_t, uint64_t) =
                    (uint64_t(*)(uint64_t, uint64_t, uint64_t, uint64_t,
                                 uint64_t, uint64_t, uint64_t, uint64_t,
                                 uint64_t, uint64_t, uint64_t, uint64_t,
                                 uint64_t))target;
                res = f(args[0], args[1], args[2], args[3], args[4], args[5],
                        args[6], args[7], args[8], args[9], args[10], args[11],
                        args[12]);
                break;
            }
            case 14: {
                uint64_t (*f)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                              uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                              uint64_t, uint64_t, uint64_t, uint64_t) =
                    (uint64_t(*)(uint64_t, uint64_t, uint64_t, uint64_t,
                                 uint64_t, uint64_t, uint64_t, uint64_t,
                                 uint64_t, uint64_t, uint64_t, uint64_t,
                                 uint64_t, uint64_t))target;
                res = f(args[0], args[1], args[2], args[3], args[4], args[5],
                        args[6], args[7], args[8], args[9], args[10], args[11],
                        args[12], args[13]);
                break;
            }
            case 15: {
                uint64_t (*f)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                              uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                              uint64_t, uint64_t, uint64_t, uint64_t,
                              uint64_t) =
                    (uint64_t(*)(uint64_t, uint64_t, uint64_t, uint64_t,
                                 uint64_t, uint64_t, uint64_t, uint64_t,
                                 uint64_t, uint64_t, uint64_t, uint64_t,
                                 uint64_t, uint64_t, uint64_t))target;
                res = f(args[0], args[1], args[2], args[3], args[4], args[5],
                        args[6], args[7], args[8], args[9], args[10], args[11],
                        args[12], args[13], args[14]);
                break;
            }
            default:
                assert(0 && "Indirect call with more than 15 arguments.");
        }
#if HYBRID_UPDATE_FSBASE_DURING_SWITCH
        arch_prctl(ARCH_SET_FS, (uint64_t)task->qemu_context->fs_base);
#endif
        printf("indirect call target=%lx res=%lx\n", target, res);
#if HYBRID_UPDATE_FSBASE_DURING_SWITCH
        arch_prctl(ARCH_SET_FS, (uint64_t)task->native_context->fs_base);
#endif
        return res;
    } else // run in emulation mode
    {
        if (args == NULL) // this was a check on the target
            tcg_abort();

        assert(task->depth < MAX_DEPTH);
        task->depth += 1;
        task->return_addrs[task->depth - 1] = target;
        assert(args_count <= 6);

#if HYBRID_UPDATE_FSBASE_DURING_SWITCH
        arch_prctl(ARCH_SET_FS, (uint64_t)task->native_context->fs_base);
#endif
        save_native_context_indirect_call(
            args_count >= 1 ? args[0] : 0, args_count >= 2 ? args[1] : 0,
            args_count >= 3 ? args[2] : 0, args_count >= 4 ? args[3] : 0,
            args_count >= 5 ? args[4] : 0, args_count >= 6 ? args[5] : 0);
#if HYBRID_UPDATE_FSBASE_DURING_SWITCH
        arch_prctl(ARCH_SET_FS, (uint64_t)task->qemu_context->fs_base);
#endif
        printf("RETURNED FROM EMULATION OF INDIRECT CALL: res=%lx\n",
               task->emulated_state->regs[SLOT_RAX]);
#if HYBRID_UPDATE_FSBASE_DURING_SWITCH
        arch_prctl(ARCH_SET_FS, (uint64_t)task->native_context->fs_base);
#endif
        return task->emulated_state->regs[SLOT_RAX];
    }
    tcg_abort();
}

void concretize_args(uint64_t target, CPUX86State* emulated_state, task_t* task)
{
    if (!reached_start)
        return;

#if HYBRID_DISABLED_LIBC_CONCRETIZATIONS
    return;
#endif

    int found = 0;
    for (int i = 0; i < sizeof(libc_concrete_funcs) / sizeof(uint64_t); i++) {
        if (libc_concrete_funcs[i] == 0)
            break;
        if (libc_concrete_funcs[i] == target) {
            found = 1;
            break;
        }
    }

    if (!found) {
        if (task == NULL)
            task = get_task();

        if (task->concretized_rsp_point ==
            task->emulated_state->regs[SLOT_RSP]) {
            task->concretized_rsp_point = 0;
            printf("DISABLING CONCRETIZATION: %lx\n",
                   task->concretized_rsp_point);
            _sym_set_concrete_mode(0);
        }
        return;
    }

    const char* arg_regs[] = {
        "rdi_expr", "rsi_expr", "rdx_expr", "rcx_expr", "r8_expr", "r9_expr",
    };

    for (int i = 0; i < sizeof(arg_regs) / sizeof(char*); i++) {
        TCGTemp*   reg_expr_tmp = tcg_find_temp_arch_reg(arg_regs[i]);
        uint64_t** reg_expr = (uint64_t**)((uint64_t)reg_expr_tmp->mem_offset +
                                           (uint64_t)emulated_state);
        *reg_expr           = NULL;
    }

    if (task == NULL)
        task = get_task();

    uint64_t point = task->emulated_state->regs[SLOT_RSP] + 8;
    if (task->concretized_rsp_point == point)
        return;

    if (task->concretized_rsp_point != 0) {
        printf("\nRECURSIVE CONCRETIZATION at %lx\n", point);
        return;
    }

    task->concretized_rsp_point = point;
    printf("\nENABLING CONCRETIZATION at %lx\n", task->concretized_rsp_point);
    _sym_set_concrete_mode(1);
}

void hybrid_debug(void) {
    task_t* task = get_task();
    if (task->emulated_state == NULL) return;
    for(int i = 0; i < SLOT_GPR_END; i++)
        printf("R[%d] = %lx\n", i, task->emulated_state->regs[i]);
}

struct afl_tb {
  target_ulong pc;
  target_ulong cs_base;
  uint32_t     flags;
  uint32_t     cf_mask;
};

struct afl_tsl {
  struct afl_tb tb;
  char          is_chain;
};

struct afl_chain {
  struct afl_tb last_tb;
  uint32_t      cf_mask;
  int           tb_exit;
};

#define FORKSRV_FD          198
#define TSL_FD (FORKSRV_FD - 1)

static unsigned char afl_fork_child;
unsigned int afl_forksrv_pid;
static int forkserver_running = 0;

void forkserver_request_tsl(target_ulong pc, target_ulong cb, uint32_t flags,
                            uint32_t cf_mask, TranslationBlock *last_tb,
                            int tb_exit);
void forkserver_request_tsl(target_ulong pc, target_ulong cb, uint32_t flags,
                            uint32_t cf_mask, TranslationBlock *last_tb,
                            int tb_exit) {

    if (!afl_fork_child) return;

    struct afl_tsl   t;
    struct afl_chain c;

    t.tb.pc = pc;
    t.tb.cs_base = cb;
    t.tb.flags = flags;
    t.tb.cf_mask = cf_mask;
    t.is_chain = (last_tb != NULL);

    if (write(TSL_FD, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
        return;

    if (t.is_chain) {
        c.last_tb.pc = last_tb->pc;
        c.last_tb.cs_base = last_tb->cs_base;
        c.last_tb.flags = last_tb->flags;
        c.cf_mask = cf_mask;
        c.tb_exit = tb_exit;

        if (write(TSL_FD, &c, sizeof(struct afl_chain)) != sizeof(struct afl_chain))
            return;
    }

    // printf("forkserver_request_tsl: request sent to parent for %lx cflags=%x\n", pc, cf_mask);
}

static inline int is_valid_addr(target_ulong addr) {
    int          flags;
    target_ulong page;

    page = addr & TARGET_PAGE_MASK;

    flags = page_get_flags(page);
    if (!(flags & PAGE_VALID) || !(flags & PAGE_READ)) return 0;

    return 1;
}

void tb_add_jump(TranslationBlock *tb, int n,
                               TranslationBlock *tb_next);

static void forkserver_wait_tsl(CPUState *cpu, int fd) {

    if (!forkserver_running) return;
    // printf("forkserver_wait_tsl\n");

    struct afl_tsl    t;
    struct afl_chain  c;
    TranslationBlock *tb, *last_tb;

    while (1) {

        uint8_t invalid_pc = 0;

        /* Broken pipe means it's time to return to the fork server routine. */
        if (read(fd, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl)) break;

        tb = tb_htable_lookup(cpu, t.tb.pc, t.tb.cs_base, t.tb.flags, t.tb.cf_mask);

        if (!tb) {

            /* The child may request to transate a block of memory that is not
                mapped in the parent (e.g. jitted code or dlopened code).
                This causes a SIGSEV in gen_intermediate_code() and associated
                subroutines. We simply avoid caching of such blocks. */

            if (is_valid_addr(t.tb.pc)) {
                mmap_lock();
                tb = tb_gen_code(cpu, t.tb.pc, t.tb.cs_base, t.tb.flags, t.tb.cf_mask);
                mmap_unlock();
                // printf("forkserver_wait_tsl: jitting block %lx [%lx, %x, %x]\n", t.tb.pc, t.tb.cs_base, t.tb.flags, t.tb.cf_mask);
#if 0
                if (!tb_htable_lookup(cpu, t.tb.pc, t.tb.cs_base, t.tb.flags, t.tb.cf_mask)) {
                    printf("ERROR: jitted block is not in cache!\n");
                    abort();
                }
#endif
            } else {
                invalid_pc = 1;
            }
        }

        if (t.is_chain) {

            if (read(fd, &c, sizeof(struct afl_chain)) != sizeof(struct afl_chain))
                break;

            if (!invalid_pc) {
                last_tb = tb_htable_lookup(cpu, c.last_tb.pc, c.last_tb.cs_base,
                                        c.last_tb.flags, c.cf_mask);
                if (last_tb) { 
                    tb_add_jump(last_tb, c.tb_exit, tb); 
                    // printf("forkserver_wait_tsl: chaining block %lx with %lx\n", c.last_tb.pc, t.tb.pc);
                }
            }
        }
    }
    close(fd);
}

static void forkserver_loop(CPUState *cpu) {

    char* pipe_name = getenv("SYMFUSION_TRACER_PIPE");
    if (pipe_name == NULL) return;

    printf("forkserver_loop\n");
    forkserver_running = 1;
    rcu_disable_atfork();

    printf("Opening pipe: %s\n", pipe_name);

    int fd_pipe = open(pipe_name, O_RDONLY);
    if (fd_pipe <= 0) {
        printf("Cannot open pipe: %s\n", pipe_name);
        exit(1);
    }

    char* f_done = getenv("SYMFUSION_PATH_TRACER_FILE_DONE");
    if (f_done == NULL) {
        printf("SYMFUSION_PATH_TRACER_FILE_DONE was not set\n");
        abort();
    }
        
    char buf[16];

    afl_forksrv_pid = getpid();

    /* All right, let's await orders... */

    struct timespec sleep;
    sleep.tv_nsec = 10000;
    while (1) {

        pid_t child_pid;
        int status, t_fd[2];

        int r = read(fd_pipe, buf, 1);
        if (r != 1) {
            nanosleep(&sleep, NULL);
            continue;
        }

        /* Establish a channel with child to grab translation commands. We'll
        read from t_fd[0], child will write to TSL_FD. */

        if (pipe(t_fd) || dup2(t_fd[1], TSL_FD) < 0) exit(3);
        close(t_fd[1]);

        total_native = 0;
        total_emulation = 0;
        total_pre_main = 0;
        get_time(&t_native_end);
        get_time(&t_emulation_end);
        get_time(&t_init);

        child_pid = fork();
        if (child_pid < 0) exit(4);

        if (!child_pid) {
            /* Child process. Close descriptors and run free. */
            // printf("CHILD\n");
            // exit(0);
            afl_fork_child = 1;
            close(t_fd[0]);
            return;
        }

        /* Parent. */
        // printf("PARENT\n");

        close(TSL_FD);

        /* Collect translation requests until child dies and closes the pipe. */

        forkserver_wait_tsl(cpu, t_fd[0]);

        /* Get and relay exit status to parent. */

        if (waitpid(child_pid, &status, 0) < 0) exit(6);

        FILE* fp = fopen(f_done, "w");
        status = WEXITSTATUS(status);
        fwrite(&status, sizeof(status), 1, fp);
        fclose(fp);
    }
}

void forkserver(void) {
    if (forkserver_running) return;
    forkserver_loop(hybrid_cpu);
}