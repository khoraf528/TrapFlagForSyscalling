#include <Windows.h>
#include <stdio.h>

#include "Common.h"


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
//
// Global Variables

__declspec(thread) static WORD t_wSyscallNumber = 0x00;

static PVOID g_pVectoredHandle = NULL;

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static LONG WINAPI ExceptionHandler(IN PEXCEPTION_POINTERS pExceptionInfo)
{
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
    {
        if (*(WORD*)pExceptionInfo->ExceptionRecord->ExceptionAddress != SYSCALL_OPCODE)
        {
            pExceptionInfo->ContextRecord->EFlags |= EFLAGS_TF;
        }
        else
        {
            if (!t_wSyscallNumber)
            {
                printf("[i] [TID:%lu] Setting Syscall Number To: 0x%04X\n", GetCurrentThreadId(), (WORD)pExceptionInfo->ContextRecord->Rax);

                printf("[i] Parameters:\n");
                printf("  > 1: 0x%016llX\n", pExceptionInfo->ContextRecord->Rcx);
                printf("  > 2: 0x%016llX\n", pExceptionInfo->ContextRecord->Rdx);
                printf("  > 3: 0x%016llX\n", pExceptionInfo->ContextRecord->R8);
                printf("  > 4: 0x%016llX\n", pExceptionInfo->ContextRecord->R9);
                printf("  > 5: 0x%016llX\n", *(PULONG_PTR)(pExceptionInfo->ContextRecord->Rsp + 0x28));


                t_wSyscallNumber = (WORD)pExceptionInfo->ContextRecord->Rax;
                pExceptionInfo->ContextRecord->EFlags |= EFLAGS_TF;
            }
            else
            {
                printf("[i] [TID:%lu] Updated Syscall Number From: 0x%04X To: 0x%04X\n", GetCurrentThreadId(), (WORD)pExceptionInfo->ContextRecord->Rax, t_wSyscallNumber);

                pExceptionInfo->ContextRecord->Rax = t_wSyscallNumber;
                pExceptionInfo->ContextRecord->EFlags &= ~EFLAGS_TF;
                t_wSyscallNumber = 0x00;
            }
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL InitializeTrapVector()
{
	if (g_pVectoredHandle)
		return TRUE;

	if (!(g_pVectoredHandle = AddVectoredExceptionHandler(0x01, ExceptionHandler)))
	{
		printf("[!] AddVectoredExceptionHandler[%d] Failed With Error: %lu\n", __LINE__, GetLastError());
		return FALSE;
	}

	return TRUE;
}


BOOL DestroyTrapVector()
{
	if (!g_pVectoredHandle)
		return FALSE;

	if (!RemoveVectoredExceptionHandler(g_pVectoredHandle))
	{
		printf("[!] RemoveVectoredExceptionHandler[%d] Failed With Error: %lu\n", __LINE__, GetLastError());
		return FALSE;
	}

	g_pVectoredHandle = NULL;
	return TRUE;
}


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

