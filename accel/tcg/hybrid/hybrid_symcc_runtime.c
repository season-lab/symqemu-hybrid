#include "hybrid.h"

#define SymExpr void *
#include "RuntimeCommon.h"

size_t _sym_bits_helper2(void *expr) { return 0; }

int open_symbolized(const char *ptah, int oflag, mode_t mode);
int open_symbolized(const char *ptah, int oflag, mode_t mode)
{
    tcg_abort();
    return -1;
}

ssize_t read_symbolized(int fildes, void *buf, size_t nbyte);
ssize_t read_symbolized(int fildes, void *buf, size_t nbyte)
{
    tcg_abort();
    return -1;
}

uint64_t lseek64_symbolized(int fd, uint64_t offset, int whence);
uint64_t lseek64_symbolized(int fd, uint64_t offset, int whence)
{
    tcg_abort();
    return -1;
}

void _sym_initialize(void)
{
    tcg_abort();
}

void _sym_register_expression_region(SymExpr *start, size_t length)
{
    tcg_abort();
}

SymExpr _sym_build_integer(uint64_t value, uint8_t bits)
{
    tcg_abort();
}

SymExpr _sym_build_add(SymExpr a, SymExpr b)
{
    tcg_abort();
}

SymExpr _sym_build_sub(SymExpr a, SymExpr b)
{
    tcg_abort();
}

SymExpr _sym_build_mul(SymExpr a, SymExpr b)
{
    tcg_abort();
}

SymExpr _sym_build_signed_div(SymExpr a, SymExpr b)
{
    tcg_abort();
}

SymExpr _sym_build_unsigned_div(SymExpr a, SymExpr b)
{
    tcg_abort();
}

SymExpr _sym_build_signed_rem(SymExpr a, SymExpr b)
{
    tcg_abort();
}

SymExpr _sym_build_unsigned_rem(SymExpr a, SymExpr b)
{
    tcg_abort();
}

SymExpr _sym_build_and(SymExpr a, SymExpr b)
{
    tcg_abort();
}

SymExpr _sym_build_or(SymExpr a, SymExpr b)
{
    tcg_abort();
}

SymExpr _sym_build_xor(SymExpr a, SymExpr b)
{
    tcg_abort();
}

SymExpr _sym_build_logical_shift_right(SymExpr a, SymExpr b)
{
    tcg_abort();
}

SymExpr _sym_build_arithmetic_shift_right(SymExpr a, SymExpr b)
{
    tcg_abort();
}

SymExpr _sym_build_shift_left(SymExpr a, SymExpr b)
{
    tcg_abort();
}