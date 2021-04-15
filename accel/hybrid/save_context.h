// we will clobber rax, rcx, and rdx
"pushq %rax" "\n\t" // preserve
"pushq %rcx" "\n\t" // preserve
"pushq %rdx" "\n\t" // preserve
//
// general-purpose register
//
// "leaq " xstr(CONTEXT) "(%rip), %rax" "\n\t" 
"movq %rdi, %rax\n\t"
//
"movq 16(%rsp), %rdx" "\n\t"
SAVE_GPR("%rdx", SLOT_RAX) "\n\t"
//
SAVE_GPR("%rbx", SLOT_RBX) "\n\t"
//
"movq 8(%rsp), %rdx" "\n\t"
SAVE_GPR("%rdx", SLOT_RCX) "\n\t"
//
"movq (%rsp), %rdx" "\n\t"
SAVE_GPR("%rdx", SLOT_RDX) "\n\t"
//
SAVE_GPR("%rsi", SLOT_RSI) "\n\t"
SAVE_GPR("%rdi", SLOT_RDI) "\n\t"
SAVE_GPR("%rbp", SLOT_RBP) "\n\t"
//
"leaq 32(%rsp), %rdx" "\n\t"        // 3 push here + 1 push from the plt_stub!
SAVE_GPR("%rdx", SLOT_RSP) "\n\t"
//
SAVE_GPR("%r8", SLOT_R8) "\n\t"
SAVE_GPR("%r9", SLOT_R9) "\n\t"
SAVE_GPR("%r10", SLOT_R10) "\n\t"
SAVE_GPR("%r11", SLOT_R11) "\n\t"
SAVE_GPR("%r12", SLOT_R12) "\n\t"
SAVE_GPR("%r13", SLOT_R13) "\n\t"
SAVE_GPR("%r14", SLOT_R14) "\n\t"
SAVE_GPR("%r15", SLOT_R15) "\n\t"
//
// flags
//
"movq $" xstr(SLOT_GPR_END) ", %rcx" "\n\t"
"leaq (%rax, %rcx, 8), %rax" "\n\t"
//
"pushfq" "\n\t"
"popq (%rax)" "\n\t"
//
// segment registers
//
"addq $8, %rax" "\n\t"
//
SAVE_SEGR("%cs", SLOT_CS) "\n\t"
SAVE_SEGR("%ds", SLOT_DS) "\n\t"
SAVE_SEGR("%es", SLOT_ES) "\n\t"
SAVE_SEGR("%fs", SLOT_FS) "\n\t"
SAVE_SEGR("%gs", SLOT_GS) "\n\t"
SAVE_SEGR("%ss", SLOT_SS) "\n\t"
//
// fs base
//
"movq $" xstr(SLOT_SEGR_END) ", %rcx" "\n\t"
"leaq (%rax, %rcx, 2), %rax" "\n\t"
"movabsq $0xFFFFFFFFFFFFFFF8, %rcx" "\n\t"
"andq %rcx, %rax" "\n\t"
"addq $8, %rax" "\n\t"
"movq $" xstr(ARCH_GET_FS) ", %rdi" "\n\t"
"movq %rax, %rsi" "\n\t"
"pushq %rax" "\n\t"
"movq $158, %rax" "\n\t"           // arch_prctl
"syscall" "\n\t"
"popq %rax" "\n\t"
//
// valid flag
//
"addq $8, %rax" "\n\t"
"movq $1, (%rax)" "\n\t"
//
// PC
//
"addq $8, %rax" "\n\t"
"movq 32(%rsp), %rdx" "\n\t"
"movq %rdx, (%rax)" "\n\t"
//
"popq %rdx" "\n\t" // restore
"popq %rcx" "\n\t" // restore
"popq %rax" "\n\t" // restore
