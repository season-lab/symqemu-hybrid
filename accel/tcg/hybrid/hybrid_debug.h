#ifndef HYBRID_DEBUG_H
#define HYBRID_DEBUG_H

#define SOLVER_Z3    1
#define SOLVER_FUZZY 2

#define HYBRID_SOLVER                        SOLVER_Z3
#define HYBRID_DISABLED_LIBC_CONCRETIZATIONS 1
#define HYBRID_DISCARD_UNSAT_CONSTRAINT      0
#define HYBRID_SKIP_LIB_QUERY                1
#define HYBRID_SKIP_LIB_CONSTRAINTS          1
#define HYBRID_DISABLE_Z3_SIMPLIFY           1
#define HYBRID_DISABLE_RANGE_CONSTRAINT      1
#define HYBRID_DBG_PRINT                     0
#define HYBRID_DBG_PRINT_QUERY_ADDR          0
#define HYBRID_DBG_DUMP_QUERY                0
#define HYBRID_DBG_CONSISTENCY_CHECK         0
#define HYBRID_DBG_CONSISTENCY_ALT           0
#define HYBRID_DBG_CHECK_PI_SAT              0
#define HYBRID_DBG_PRINT_PC                  0
#define HYBRID_DBG_SKIP_SOLVE                0
#define HYBRID_DBG_SKIP_QUERY                0
#define HYBRID_HANDLE_VAR_ARGS               0
#define HYBRID_USE_SYM_HELPERS               1
#define HYBRID_USE_FSBASEINSN                1
#define HYBRID_CACHE_CONSTANTS               1

#endif // HYBRID_DEBUG_H
