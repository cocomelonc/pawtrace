/* author: cocomelonc */
.text

.globl pt_raw_syscall6
.type pt_raw_syscall6,@function
pt_raw_syscall6:
    mov %rdi, %rax
    mov %rsi, %rdi
    mov %rdx, %rsi
    mov %rcx, %rdx
    mov %r8,  %r10
    mov %r9,  %r8
    mov 8(%rsp), %r9
    syscall
    ret

.globl pt_gettid_raw
.type pt_gettid_raw,@function
pt_gettid_raw:
    mov $186, %rax
    syscall
    ret

.globl pt_rdtsc
.type pt_rdtsc,@function
pt_rdtsc:
    rdtsc
    shl $32, %rdx
    or %rdx, %rax
    ret
