// this is called by plt_stub
// that has pushed a constant
// into the stack before
// jumping at this code.
"pushq %rax\n"
"movq %rsp, %rax\n"          // start of the save area
"pushq %rbx\n"
"pushq %rcx\n"
"pushq %rdx\n"
"pushq %rsi\n"
"pushq %rdi\n"
"pushq %rbp\n"
"pushq %r8\n"
"pushq %r9\n"
"pushq %r10\n"
"pushq %r11\n"
"pushq %r12\n"
"pushq %r13\n"
"pushq %r14\n"
"pushq %r15\n"
"pushfq\n"
"movabsq $0xFFFFFFFFFFFFFFF0, %rdi\n"
"andq %rdi, %rsp\n"
#ifdef PRESERVE_XMM
"leaq   -16(%rsp), %rsp\n"
"movdqu  %xmm0, (%rsp)\n"
"leaq   -16(%rsp), %rsp\n"
"movdqu  %xmm1, (%rsp)\n"
"leaq   -16(%rsp), %rsp\n"
"movdqu  %xmm2, (%rsp)\n"
"leaq   -16(%rsp), %rsp\n"
"movdqu  %xmm3, (%rsp)\n"
"leaq   -16(%rsp), %rsp\n"
"movdqu  %xmm4, (%rsp)\n"
"leaq   -16(%rsp), %rsp\n"
"movdqu  %xmm5, (%rsp)\n"
"leaq   -16(%rsp), %rsp\n"
"movdqu  %xmm6, (%rsp)\n"
"leaq   -16(%rsp), %rsp\n"
"movdqu  %xmm7, (%rsp)\n"
"leaq   -16(%rsp), %rsp\n"
"movdqu  %xmm8, (%rsp)\n"
"leaq   -16(%rsp), %rsp\n"
"movdqu  %xmm9, (%rsp)\n"
"leaq   -16(%rsp), %rsp\n"
"movdqu  %xmm10, (%rsp)\n"
"leaq   -16(%rsp), %rsp\n"
"movdqu  %xmm11, (%rsp)\n"
"leaq   -16(%rsp), %rsp\n"
"movdqu  %xmm12, (%rsp)\n"
"leaq   -16(%rsp), %rsp\n"
"movdqu  %xmm13, (%rsp)\n"
"leaq   -16(%rsp), %rsp\n"
"movdqu  %xmm14, (%rsp)\n"
"leaq   -16(%rsp), %rsp\n"
"movdqu  %xmm15, (%rsp)\n"
#endif

#ifdef BACK_FROM_EMULATION
"leaq 8(%rax), %rdi\n"         // original RSP (above the pushed constant)
#else
"leaq 16(%rax), %rdi\n"         // original RSP (above the pushed constant)
#endif

"movq %rax, %rsi\n"             // save area
"leaq 8(%rax), %rbx\n"          // preserve initial RSP
"call " xstr(SAVE_ROUTINE) "\n" //
//
#ifdef RESTORE_XMM
"movdqu  -0x90(%rbx), %xmm0\n"  
"movdqu  -0xA0(%rbx), %xmm1\n"  
"movdqu  -0xB0(%rbx), %xmm2\n"  
"movdqu  -0xC0(%rbx), %xmm3\n"  
"movdqu  -0xD0(%rbx), %xmm4\n"
"movdqu  -0xE0(%rbx), %xmm5\n"
"movdqu  -0xF0(%rbx), %xmm6\n"
"movdqu  -0x100(%rbx), %xmm7\n"
"movdqu  -0x110(%rbx), %xmm8\n"
"movdqu  -0x120(%rbx), %xmm9\n"
"movdqu  -0x130(%rbx), %xmm10\n"
"movdqu  -0x140(%rbx), %xmm11\n"
"movdqu  -0x150(%rbx), %xmm12\n"
"movdqu  -0x160(%rbx), %xmm13\n"
"movdqu  -0x170(%rbx), %xmm14\n"
"movdqu  -0x180(%rbx), %xmm15\n"  
#endif
//
"movq %rbx, %rsp\n"             // restore initial RSP