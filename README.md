## TrapFlagForSyscalling: Bypass user-land hooks by syscall tampering via the Trap Flag

### Quick Links

[Maldev Academy Home](https://maldevacademy.com?ref=gh)
  
[Maldev Academy Syllabus](https://maldevacademy.com/syllabus?ref=gh)

[Maldev Academy Pricing](https://maldevacademy.com/pricing?ref=gh)

### What Is The Trap Flag

The [Trap Flag (TF)](https://en.wikipedia.org/wiki/Trap_flag) is a special bit in the CPU's EFLAGS register that forces the processor to generate a **single-step exception** after every instruction. This behavior is commonly used in debugging to trace program flow one instruction at a time.

<br>

### How Does It Work?

* Locate the address of the target syscall, for example, `NtAllocateVirtualMemory`.
* Enable the Trap Flag on the current thread using `GetThreadContext` and `SetThreadContext`.
* Invoke the `NtAllocateVirtualMemory` syscall with random dummy parameters. When execution reaches the `syscall` instruction, the VEH will capture the syscall number of `NtAllocateVirtualMemory`.
* Obtain the address of a whitelisted syscall. These are syscalls rarely monitored by security software, such as `NtDrawText`.
* Call `NtDrawText` with the original parameters intended for `NtAllocateVirtualMemory`. Here, the VEH replaces the syscall number of `NtDrawText` with that of `NtAllocateVirtualMemory` when it reaches the `syscall` instruction.

This approach bypasses user-land hooks placed on `NtAllocateVirtualMemory`, while also feeding any security software hooking it with invalid, random parameters.

<br>

### Usage

Use the [INVOKE_SYSCALL](https://github.com/Maldev-Academy/TrapFlagForSyscalling/blob/main/TrapFlagForSyscalling/Common.h#L71) macro by passing:

* `dwSyscallHash` - The [Murmur Hash](https://github.com/Maldev-Academy/TrapFlagForSyscalling/blob/main/TrapFlagForSyscalling/Utilities.c#L88) of the target syscall.
* `STATUS` - An `NTSTATUS` variable that will hold the result returned by the syscall.
* `...` - The actual parameters to be passed to the syscall identified by `dwSyscallHash`.


<br>
<br>

### Demo

The image below showcases the invocation of `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, and `NtCreateThreadEx` syscalls using the `INVOKE_SYSCALL` macro.


<img width="1272" height="882" alt="image" src="https://github.com/user-attachments/assets/8ea603c9-ef78-41ab-a56c-e6f43acac520" />
