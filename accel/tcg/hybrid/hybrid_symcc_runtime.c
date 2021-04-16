#include "hybrid.h"

#define SymExpr void *
#include "RuntimeCommon.h"

#include <asm/prctl.h>
#include <sys/prctl.h>

typedef struct
{
    void *open_symbolized_ptr;
    void *read_symbolized_ptr;
} symcc_runtime_t;

#define symcc_runtime_fun3(type, default_ret, name, type1, arg1, type2, arg2, type3, arg3) \
    type name(type1 arg1, type2 arg2, type3 arg3)                                          \
    {                                                                                      \
        if (!is_symcc_runtime_init_done)                                                   \
            return default_ret;                                                            \
        name (*fun_ptr)(type1, type2, type3) = symcc_runtime.##name_ptr;                   \
        return fun_ptr(arg1, arg2, arg3);                                                  \
    }

static symcc_runtime_t symcc_runtime = {0};
static int is_symcc_runtime_init_done = 0;

void set_symcc_runtime_init_done(void)
{
    is_symcc_runtime_init_done = 1;
}

#define COUNT_OFFSETS 2
void symcc_runtime_load(uint64_t addr)
{
    uint64_t base = 0x111000;
    uint8_t *bytes = (uint8_t *)addr;

    void **ptrs[COUNT_OFFSETS] = {
        &symcc_runtime.open_symbolized_ptr, 
        &symcc_runtime.read_symbolized_ptr 
    };
    uint64_t offsets[COUNT_OFFSETS] = {
        0x1a03e6,
        0x1a0549
    };

    for (int i = 0; i < COUNT_OFFSETS; i++)
    {
        uint64_t offset = offsets[i];

        // endbr64
        if (!(bytes[offset - base] == 0xf3 && bytes[offset - base + 1] == 0x0f && bytes[offset - base + 2] == 0x1e && bytes[offset - base + 3] == 0xfa))
            tcg_abort();

        *ptrs[i] = (void *)(addr + offset - base);
    }
}

int open_symbolized(const char *ptah, int oflag, mode_t mode);
int open_symbolized(const char *ptah, int oflag, mode_t mode)
{
    task_t *task = get_task();
    if (!is_symcc_runtime_init_done || !task)
        return safe_openat(AT_FDCWD, ptah, oflag, mode);

    if (task->is_inside_runtime)
    {
        uint64_t old_fs_base = switch_fsbase_to_qemu(task);
        printf("RECURSIVE OPEN. Executing QEMU\n");
        int res = safe_openat(AT_FDCWD, ptah, oflag, mode);
        printf("DONE QEMU\n");
        switch_fsbase_to(old_fs_base);
        return res;
    }

    printf("Opening file: %s\n", ptah);

    assert(task->is_inside_runtime == 0);
    task->is_inside_runtime = 1;

    uint64_t old_fs_base = switch_fsbase_to_native(task);

    assert(symcc_runtime.open_symbolized_ptr);
    ssize_t (*fun_ptr)(const char *, int, mode_t) = symcc_runtime.open_symbolized_ptr;
    int res = fun_ptr(ptah, oflag, mode);

    switch_fsbase_to(old_fs_base);

    task->is_inside_runtime = 0;
    return res;
}

ssize_t read_symbolized(int fildes, void *buf, size_t nbyte);
ssize_t read_symbolized(int fildes, void *buf, size_t nbyte)
{
    task_t *task = get_task();
    if (!is_symcc_runtime_init_done || !task)
        return safe_read(fildes, buf, nbyte);

    if (task->is_inside_runtime)
    {
        uint64_t old_fs_base = switch_fsbase_to_qemu(task);
        printf("RECURSIVE READ. Executing QEMU\n");
        int res = safe_read(fildes, buf, nbyte);
        printf("DONE QEMU\n");
        switch_fsbase_to(old_fs_base);
        return res;
    }

    printf("\nReading file %d\n\n", fildes);

    assert(task->is_inside_runtime == 0);
    task->is_inside_runtime = 1;

    uint64_t old_fs_base = switch_fsbase_to_native(task);

    assert(symcc_runtime.read_symbolized_ptr);
    ssize_t (*fun_ptr)(int, void *, size_t) = symcc_runtime.read_symbolized_ptr;
    ssize_t res = fun_ptr(fildes, buf, nbyte);

    switch_fsbase_to(old_fs_base);

    task->is_inside_runtime = 0;
    return res;
}

uint64_t lseek64_symbolized(int fd, uint64_t offset, int whence);
uint64_t lseek64_symbolized(int fd, uint64_t offset, int whence)
{
    tcg_abort();
    return -1;
}

void _sym_initialize(void)
{
    // Nothing to do?
}

void _sym_register_expression_region(SymExpr *start, size_t length)
{
    // this is needed for the garbage collector
    // for now, we do not support the GC.
}

SymExpr _sym_build_integer(uint64_t value, uint8_t bits)
{
    if (!is_symcc_runtime_init_done)
        return NULL;

    tcg_abort();
}

SymExpr _sym_build_add(SymExpr a, SymExpr b)
{
    if (!is_symcc_runtime_init_done)
        return NULL;

    tcg_abort();
}

SymExpr _sym_build_sub(SymExpr a, SymExpr b)
{
    if (!is_symcc_runtime_init_done)
        return NULL;

    tcg_abort();
}

SymExpr _sym_build_mul(SymExpr a, SymExpr b)
{
    if (!is_symcc_runtime_init_done)
        return NULL;

    tcg_abort();
}

SymExpr _sym_build_signed_div(SymExpr a, SymExpr b)
{
    if (!is_symcc_runtime_init_done)
        return NULL;

    tcg_abort();
}

SymExpr _sym_build_unsigned_div(SymExpr a, SymExpr b)
{
    if (!is_symcc_runtime_init_done)
        return NULL;

    tcg_abort();
}

SymExpr _sym_build_signed_rem(SymExpr a, SymExpr b)
{
    if (!is_symcc_runtime_init_done)
        return NULL;

    tcg_abort();
}

SymExpr _sym_build_unsigned_rem(SymExpr a, SymExpr b)
{
    if (!is_symcc_runtime_init_done)
        return NULL;

    tcg_abort();
}

SymExpr _sym_build_and(SymExpr a, SymExpr b)
{
    if (!is_symcc_runtime_init_done)
        return NULL;

    tcg_abort();
}

SymExpr _sym_build_or(SymExpr a, SymExpr b)
{
    if (!is_symcc_runtime_init_done)
        return NULL;

    tcg_abort();
}

SymExpr _sym_build_xor(SymExpr a, SymExpr b)
{
    if (!is_symcc_runtime_init_done)
        return NULL;

    tcg_abort();
}

SymExpr _sym_build_logical_shift_right(SymExpr a, SymExpr b)
{
    if (!is_symcc_runtime_init_done)
        return NULL;

    tcg_abort();
}

SymExpr _sym_build_arithmetic_shift_right(SymExpr a, SymExpr b)
{
    if (!is_symcc_runtime_init_done)
        return NULL;

    tcg_abort();
}

SymExpr _sym_build_shift_left(SymExpr a, SymExpr b)
{
    if (!is_symcc_runtime_init_done)
        return NULL;

    tcg_abort();
}

size_t _sym_bits_helper(SymExpr expr)
{
    if (!is_symcc_runtime_init_done)
        return 0;

    tcg_abort();
}

SymExpr _sym_build_neg(SymExpr expr)
{
    if (!is_symcc_runtime_init_done)
        return NULL;

    tcg_abort();
}

SymExpr _sym_build_not(SymExpr expr)
{
    if (!is_symcc_runtime_init_done)
        return NULL;

    tcg_abort();
}

SymExpr _sym_build_sext(SymExpr expr, uint8_t bits)
{
    if (!is_symcc_runtime_init_done)
        return NULL;

    tcg_abort();
}

SymExpr _sym_build_zext(SymExpr expr, uint8_t bits)
{
    if (!is_symcc_runtime_init_done)
        return NULL;

    tcg_abort();
}

SymExpr _sym_concat_helper(SymExpr a, SymExpr b)
{
    if (!is_symcc_runtime_init_done)
        return NULL;

    tcg_abort();
}

SymExpr _sym_extract_helper(SymExpr expr, size_t first_bit, size_t last_bit)
{
    if (!is_symcc_runtime_init_done)
        return NULL;

    tcg_abort();
}

SymExpr _sym_build_trunc(SymExpr expr, uint8_t bits)
{
    if (!is_symcc_runtime_init_done)
        return NULL;

    tcg_abort();
}

SymExpr _sym_build_bswap(SymExpr expr)
{
    if (!is_symcc_runtime_init_done)
        return NULL;

    tcg_abort();
}

SymExpr _sym_build_equal(SymExpr a, SymExpr b)
{
    if (!is_symcc_runtime_init_done)
        return NULL;

    tcg_abort();
}

void _sym_push_path_constraint(SymExpr constraint, int taken,
                               uintptr_t site_id)
{
    if (!is_symcc_runtime_init_done)
        return;

    tcg_abort();
}

SymExpr _sym_read_memory(uint8_t *addr, size_t length, bool little_endian)
{
    if (!is_symcc_runtime_init_done)
        return NULL;

    printf("READING %ld bytes FROM MEMORY at %p\n", length, addr);
    tcg_abort();
}

void _sym_write_memory(uint8_t *addr, size_t length, SymExpr expr,
                       bool little_endian)
{
    if (!is_symcc_runtime_init_done)
        return;

    tcg_abort();
}

SymExpr _sym_build_signed_less_than(SymExpr a, SymExpr b)
{
    if (!is_symcc_runtime_init_done)
        return NULL;

    tcg_abort();
}

SymExpr _sym_build_signed_less_equal(SymExpr a, SymExpr b)
{
    if (!is_symcc_runtime_init_done)
        return NULL;

    tcg_abort();
}

SymExpr _sym_build_signed_greater_than(SymExpr a, SymExpr b)
{
    if (!is_symcc_runtime_init_done)
        return NULL;

    tcg_abort();
}

SymExpr _sym_build_signed_greater_equal(SymExpr a, SymExpr b)
{
    if (!is_symcc_runtime_init_done)
        return NULL;

    tcg_abort();
}

SymExpr _sym_build_unsigned_less_than(SymExpr a, SymExpr b)
{
    if (!is_symcc_runtime_init_done)
        return NULL;

    tcg_abort();
}

SymExpr _sym_build_unsigned_less_equal(SymExpr a, SymExpr b)
{
    if (!is_symcc_runtime_init_done)
        return NULL;

    tcg_abort();
}

SymExpr _sym_build_unsigned_greater_than(SymExpr a, SymExpr b)
{
    if (!is_symcc_runtime_init_done)
        return NULL;

    tcg_abort();
}

SymExpr _sym_build_unsigned_greater_equal(SymExpr a, SymExpr b)
{
    if (!is_symcc_runtime_init_done)
        return NULL;

    tcg_abort();
}

SymExpr _sym_build_not_equal(SymExpr a, SymExpr b)
{
    if (!is_symcc_runtime_init_done)
        return NULL;

    tcg_abort();
}

SymExpr _sym_build_bool_to_bits(SymExpr expr, uint8_t bits)
{
    if (!is_symcc_runtime_init_done)
        return NULL;

    tcg_abort();
}

void _sym_notify_call(uintptr_t site_id)
{
    if (!is_symcc_runtime_init_done)
        return;

    tcg_abort();
}

void _sym_notify_ret(uintptr_t site_id)
{
    if (!is_symcc_runtime_init_done)
        return;

    tcg_abort();
}

void _sym_notify_basic_block(uintptr_t site_id)
{
    if (!is_symcc_runtime_init_done)
        return;

    tcg_abort();
}