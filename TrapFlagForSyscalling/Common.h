#pragma once



#ifndef SYSCALLS_H
#define SYSCALLS_H


#include <Windows.h>
#include <immintrin.h> 


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#define STATUS_UNSUCCESSFUL		0xC0000001

#define EXCEPTION_SINGLE_STEP	0x80000004
#define EFLAGS_TF				0x100
#define SYSCALL_OPCODE			0x050F

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#define NT_SUCCESS(STATUS) (((NTSTATUS)(STATUS)) >= 0)

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL MurmurHashStringA(IN LPCSTR pszInputString, OUT PDWORD pdwHashValue);
BOOL GetSystemCallAddress(IN DWORD dwSyscallHash, OUT PVOID* ppSyscallAddress);
BYTE GenRandomByte();
DWORD FetchRandomSyscallHash();


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL InitializeTrapVector();
BOOL DestroyTrapVector();

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

typedef NTSTATUS(WINAPI* fnSyscallFunction)();

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#define MURMUR_NTDRAWTEXT					0x6E99DC1B		// NtDrawText
#define MURMUR_NTQUERYDEFAULTUILANGUAGE		0x563529D4		// NtQueryDefaultUILanguage
#define MURMUR_NTGETCURRENTPROCESSORNUMBER	0x0415F818		// NtGetCurrentProcessorNumber
#define MURMUR_NTOPENEVENTPAIR				0xAB0A17A1		// NtOpenEventPair

/*
	These syscalls were chosen because they are unlikely to be hooked or monitored. More of these syscalls can be found in 'win32u.dll'
*/

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static __forceinline ULONG_PTR GenRandomArg()
{
    unsigned __int64 ui64RndValue = 0x00;
    for (int i = 0; i < 0x0A; i++)
    {
        if (_rdrand64_step(&ui64RndValue))
        {
            return (ULONG_PTR)ui64RndValue;
        }
        _mm_pause();
    }
    return 0x00; 
}


#define INVOKE_SYSCALL(dwSyscallHash, STATUS, ...)                                         \
do {                                                                                       \
    CONTEXT             ThreadCtx               = { 0 };                                   \
    fnSyscallFunction   pRealSyscallAddress     = NULL;                                    \
    fnSyscallFunction   pDummySyscallAddress    = NULL;                                    \
    ULONG_PTR           uArg1                   = GenRandomArg();                          \
    ULONG_PTR           uArg2                   = GenRandomArg();                          \
    ULONG_PTR           uArg3                   = GenRandomArg();                          \
    ULONG_PTR           uArg4                   = GenRandomArg();                          \
    ULONG_PTR           uArg5                   = GenRandomArg();                          \
    ULONG_PTR           uArg6                   = GenRandomArg();                          \
                                                                                           \
    ThreadCtx.ContextFlags = CONTEXT_CONTROL;                                              \
                                                                                           \
    GetSystemCallAddress(dwSyscallHash, (PVOID*)&pRealSyscallAddress);                     \
    GetSystemCallAddress(FetchRandomSyscallHash(), (PVOID*)&pDummySyscallAddress);         \
                                                                                           \
    GetThreadContext((HANDLE)-2, &ThreadCtx);                                              \
    ThreadCtx.EFlags |= EFLAGS_TF;                                                         \
    SetThreadContext((HANDLE)-2, &ThreadCtx);                                              \
                                                                                           \
    pRealSyscallAddress(uArg1, uArg2, uArg3, uArg4, uArg5, uArg6);                         \
                                                                                           \
    STATUS = pDummySyscallAddress(__VA_ARGS__);                                            \
                                                                                           \
} while(0)


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

/*
#define INVOKE_SYSCALL(dwSyscallHash, STATUS, ...)											\
do {																						\
    CONTEXT				ThreadCtx				= { 0 };									\
    fnSyscallFunction	pRealSyscallAddress		= NULL;										\
    fnSyscallFunction	pDummySyscallAddress	= NULL;										\
                                                                                            \
    ThreadCtx.ContextFlags = CONTEXT_CONTROL;												\
                                                                                            \
    GetSystemCallAddress(dwSyscallHash, (PVOID*)&pRealSyscallAddress);						\
    GetSystemCallAddress(FetchRandomSyscallHash(), (PVOID*)&pDummySyscallAddress);			\
                                                                                            \
    GetThreadContext((HANDLE)-2, &ThreadCtx);												\
    ThreadCtx.EFlags |= EFLAGS_TF ;															\
    SetThreadContext((HANDLE)-2, &ThreadCtx);												\
                                                                                            \
    pRealSyscallAddress(0x01, 0x02, 0x03, 0x04, 0x05, 0x06);								\
                                                                                            \
    STATUS = pDummySyscallAddress(__VA_ARGS__);												\
                                                                                            \
} while(0)
*/


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


#endif // !SYSCALLS_H

