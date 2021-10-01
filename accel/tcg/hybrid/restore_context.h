#ifdef RESTORE_PUSH_RSI
"pushq %rsi" "\n\t"
#endif
//
// general-purpose register
//
"movq %rdi, %rax" "\n\t"    // CpuContext* 
//
// fs base
//
"pushq %rax" "\n\t"
"movq $" xstr(SLOT_GPR_END) ", %rcx" "\n\t"
"leaq (%rax, %rcx, 8), %rax" "\n\t"     // skip gpr
"leaq 8(%rax), %rax" "\n\t"             // skip flags
"movq $" xstr(SLOT_SEGR_END) ", %rcx" "\n\t"
"leaq (%rax, %rcx, 2), %rax" "\n\t"     
"movabsq $0xFFFFFFFFFFFFFFF8, %rcx" "\n\t"
"andq %rcx, %rax" "\n\t"
"leaq 8(%rax), %rax" "\n\t"                  // skip seg
#if HYBRID_USE_FSBASEINSN
"movq (%rax), %rsi" "\n\t"
"wrfsbase %rsi" "\n\t"
#else
"movq $" xstr(ARCH_SET_FS) ", %rdi" "\n\t"
"movq (%rax), %rsi" "\n\t"
"movq $158, %rax" "\n\t"           // arch_prctl
"syscall" "\n\t"
#endif
"popq %rax" "\n\t"
//
// we skip rax, rcx, rsp
//
RESTORE_GPR("%rbx", SLOT_RBX) "\n\t"
//
RESTORE_GPR("%rdx", SLOT_RDX) "\n\t"
RESTORE_GPR("%rsi", SLOT_RSI) "\n\t"
RESTORE_GPR("%rdi", SLOT_RDI) "\n\t"
RESTORE_GPR("%rbp", SLOT_RBP) "\n\t"
//
"movq %rsp, %r8" "\n\t"
RESTORE_GPR("%rsp", SLOT_RSP) "\n\t"
#ifdef RESTORE_ADD_SLOT_STACK
"subq $8, %rsp" "\n\t"
#endif
"subq $8, %r8" "\n\t"
"movq %rsp, (%r8)" "\n\t"
"movq %r8, %rsp" "\n\t"
//
RESTORE_GPR("%r8", SLOT_R8) "\n\t"
RESTORE_GPR("%r9", SLOT_R9) "\n\t"
RESTORE_GPR("%r10", SLOT_R10) "\n\t"
RESTORE_GPR("%r11", SLOT_R11) "\n\t"
RESTORE_GPR("%r12", SLOT_R12) "\n\t"
RESTORE_GPR("%r13", SLOT_R13) "\n\t"
RESTORE_GPR("%r14", SLOT_R14) "\n\t"
RESTORE_GPR("%r15", SLOT_R15) "\n\t"
//
"pushq %rax" "\n\t"
//
// flags
//
"movq $" xstr(SLOT_GPR_END) ", %rcx" "\n\t"
"leaq (%rax, %rcx, 8), %rax" "\n\t"
"pushq (%rax)" "\n\t"
"popfq" "\n\t"
//
// segment registers
//
"leaq 8(%rax), %rax" "\n\t"
//
#if 0
RESTORE_SEGR("%cs", SLOT_CS) "\n\t"
RESTORE_SEGR("%ds", SLOT_DS) "\n\t"
RESTORE_SEGR("%es", SLOT_ES) "\n\t"
RESTORE_SEGR("%fs", SLOT_FS) "\n\t"
RESTORE_SEGR("%gs", SLOT_GS) "\n\t"
RESTORE_SEGR("%ss", SLOT_SS) "\n\t"
#endif
//
"movq $" xstr(SLOT_SEGR_END) ", %rcx" "\n\t"
"leaq (%rax, %rcx, 2), %rax" "\n\t"
"movabsq $0xFFFFFFFFFFFFFFF8, %rcx" "\n\t"
"pushfq" "\n\t"
"andq %rcx, %rax" "\n\t" // clobbers eflags
"popfq" "\n\t"
"leaq 16(%rax), %rax" "\n\t"
//
// valid flag
//
"movq $0, (%rax)" "\n\t"
"leaq 8(%rax), %rax" "\n\t"
//
// PC
//
"movq (%rax), %rcx" "\n\t"      // PC
"movq 8(%rsp), %rax" "\n\t"     // RSP
"movq %rcx, (%rax)" "\n\t"
//
// rcx, rax, rsp
//
"popq %rax" "\n\t"
RESTORE_GPR("%rcx", SLOT_RCX) "\n\t"
"movq (%rax), %rax" "\n\t"
"movq (%rsp), %rsp" "\n\t"