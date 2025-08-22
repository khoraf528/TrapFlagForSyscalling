#include <Windows.h>
#include <immintrin.h> 
#include <stdio.h>

#include "Structs.h"
#include "Common.h"


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
//
// Constants

#define MURMUR3_SEED            0xDEADBEEF
#define MURMUR3_C1              0xCC9E2D51
#define MURMUR3_C2              0x1B873593
#define MURMUR3_R1              15
#define MURMUR3_R2              13
#define MURMUR3_M               5
#define MURMUR3_N               0xE6546B64


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// 
// Structure Definitions

typedef struct _NTDLL_CONFIG
{
    PDWORD      pdwArrayOfAddresses;   // VA of exported function addresses array [BaseAddress + AddressOfFunctions]
    PDWORD      pdwArrayOfNames;       // VA of exported function names array [BaseAddress + AddressOfNames]
    PWORD       pwArrayOfOrdinals;     // VA of exported function ordinals array [BaseAddress + AddressOfNameOrdinals]
    DWORD       dwNumberOfNames;       // Count of exported functions [NumberOfNames]
    ULONG_PTR   uModule;               // NTDLL base address for RVA calculations

} NTDLL_CONFIG, * PNTDLL_CONFIG;

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
//
// Global Variables

static NTDLL_CONFIG g_NtdllConf = { 0 };

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static DWORD ComputeMurmurHash3Raw(IN PBYTE pbData, IN DWORD dwDataSize) 
{
    DWORD   dwHash          = MURMUR3_SEED;
    DWORD   dwBlockCount    = dwDataSize >> 2;
    PDWORD  pdwBlocks       = (PDWORD)pbData;

    if (!pbData || !dwDataSize) return 0x00;

    for (DWORD i = 0; i < dwBlockCount; i++) 
    {
        DWORD dwK = pdwBlocks[i];

        dwK     *= MURMUR3_C1;
        dwK     = (dwK << MURMUR3_R1) | (dwK >> (32 - MURMUR3_R1));
        dwK     *= MURMUR3_C2;
        dwHash  ^= dwK;
        dwHash  = ((dwHash << MURMUR3_R2) | (dwHash >> (32 - MURMUR3_R2))) * MURMUR3_M + MURMUR3_N;
    }

    PBYTE pbTail    = (PBYTE)(pbData + (dwBlockCount << 2));
    DWORD dwK1      = 0x00;

    switch (dwDataSize & 3) 
    {
        case 3: dwK1 ^= pbTail[2] << 16;
        case 2: dwK1 ^= pbTail[1] << 8;
        case 1: dwK1 ^= pbTail[0];
            dwK1 *= MURMUR3_C1;
            dwK1 = (dwK1 << MURMUR3_R1) | (dwK1 >> (32 - MURMUR3_R1));
            dwK1 *= MURMUR3_C2;
            dwHash ^= dwK1;
    }

    dwHash ^= dwDataSize;
    dwHash ^= (dwHash >> 16);
    dwHash *= 0x85EBCA6B;
    dwHash ^= (dwHash >> 13);
    dwHash *= 0xC2B2AE35;
    dwHash ^= (dwHash >> 16);

    return dwHash;
}


BOOL MurmurHashStringA(IN LPCSTR pszInputString, OUT PDWORD pdwHashValue)
{
    DWORD dwStringLength = 0x00;

    if (!pszInputString || !pdwHashValue)
        return FALSE;

    dwStringLength = (DWORD)lstrlenA(pszInputString);
    if (!dwStringLength || dwStringLength > 0x10000)
        return FALSE;

    *pdwHashValue = ComputeMurmurHash3Raw((PBYTE)pszInputString, dwStringLength);

    return TRUE;
}

/*
BOOL MurmurHashStringW(IN LPCWSTR pwszInputString, OUT PDWORD pdwHashValue)
{
    DWORD dwStringLength = 0x00;

    if (!pwszInputString || !pdwHashValue)
        return FALSE;

    dwStringLength = (DWORD)lstrlenW(pwszInputString);
    if (!dwStringLength || dwStringLength > 0x8000)
        return FALSE;

    *pdwHashValue = ComputeMurmurHash3Raw((PBYTE)pwszInputString, dwStringLength * sizeof(WCHAR));

    return TRUE;
}
*/

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BYTE GenRandomByte()
{
	unsigned short usRndValue = 0x00;

	for (int i = 0; i < 0x0A; i++)
	{
		if (_rdrand16_step(&usRndValue))
		{
			return (BYTE)(usRndValue & 0xFF);
		}
		_mm_pause();
	}

    return (ULONG_PTR)((rand() << 16) | rand());
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

/*
	Assuming 'ntdll.dll' is loaded directly after our executable image (this is not always the case, as sometimes its "ntd1l.dll" for example).
*/
static BOOL InitNtdllConfigStructure()
{
    PPEB                    pPeb                = NULL;
    PLDR_DATA_TABLE_ENTRY   pNtdllEntry         = NULL;
    PIMAGE_DOS_HEADER       pDosHeader          = NULL;
    PIMAGE_NT_HEADERS       pNtHeaders          = NULL;
    PIMAGE_EXPORT_DIRECTORY pExportDir          = NULL;
    PIMAGE_DATA_DIRECTORY   pExportDataDir      = NULL;
    BOOL    			    bResult            = FALSE;


    if (g_NtdllConf.uModule) return TRUE;

#ifdef _WIN64
    pPeb = (PPEB)__readgsqword(0x60);
#else
    pPeb = NULL;
#endif

    if (!pPeb) return FALSE;

    if (pPeb->OSMajorVersion != 0xA) return FALSE;

    if (!pPeb->LoaderData || !pPeb->LoaderData->InMemoryOrderModuleList.Flink || !pPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink)
        return FALSE;

    pNtdllEntry = CONTAINING_RECORD(pPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    if (!pNtdllEntry || !pNtdllEntry->DllBase) 
        return FALSE;

    g_NtdllConf.uModule = (ULONG_PTR)pNtdllEntry->DllBase;

    pDosHeader = (PIMAGE_DOS_HEADER)g_NtdllConf.uModule;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) 
		goto _END_OF_FUNC;

    pNtHeaders = (PIMAGE_NT_HEADERS)(g_NtdllConf.uModule + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) 
        goto _END_OF_FUNC;

    pExportDataDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!pExportDataDir->VirtualAddress || !pExportDataDir->Size) 
        goto _END_OF_FUNC;

    pExportDir = (PIMAGE_EXPORT_DIRECTORY)(g_NtdllConf.uModule + pExportDataDir->VirtualAddress);

    if (!pExportDir->NumberOfNames || !pExportDir->AddressOfFunctions || !pExportDir->AddressOfNames || !pExportDir->AddressOfNameOrdinals)
        goto _END_OF_FUNC;

    g_NtdllConf.dwNumberOfNames         = pExportDir->NumberOfNames;
    g_NtdllConf.pdwArrayOfAddresses     = (PDWORD)(g_NtdllConf.uModule + pExportDir->AddressOfFunctions);
    g_NtdllConf.pdwArrayOfNames         = (PDWORD)(g_NtdllConf.uModule + pExportDir->AddressOfNames);
    g_NtdllConf.pwArrayOfOrdinals       = (PWORD)(g_NtdllConf.uModule + pExportDir->AddressOfNameOrdinals);
	bResult                             = TRUE;

_END_OF_FUNC:
    if (!bResult) 
    {
        RtlZeroMemory(&g_NtdllConf, sizeof(NTDLL_CONFIG));
	}
    return bResult;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


BOOL GetSystemCallAddress(IN DWORD dwSyscallHash, OUT PVOID* ppSyscallAddress)
{
   
    if (!dwSyscallHash || !ppSyscallAddress) return FALSE;
    
    *ppSyscallAddress = NULL;

    if (!g_NtdllConf.uModule && !InitNtdllConfigStructure()) return FALSE;
    
    for (int i = 0; i < g_NtdllConf.dwNumberOfNames; i++)
    {
        PCHAR pcFuncName    = (PCHAR)(g_NtdllConf.uModule + g_NtdllConf.pdwArrayOfNames[i]);
        DWORD dwFuncHash    = 0x00;
        
        if (MurmurHashStringA(pcFuncName, &dwFuncHash) && dwFuncHash == dwSyscallHash)
        {
            *ppSyscallAddress = (PBYTE)(g_NtdllConf.uModule + g_NtdllConf.pdwArrayOfAddresses[g_NtdllConf.pwArrayOfOrdinals[i]]);
            return TRUE;
        }
    }

    return FALSE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


static DWORD g_dwSyscallHashArray[] =
{
    MURMUR_NTDRAWTEXT,
    MURMUR_NTQUERYDEFAULTUILANGUAGE,
    MURMUR_NTGETCURRENTPROCESSORNUMBER,
    MURMUR_NTOPENEVENTPAIR
};


DWORD FetchRandomSyscallHash()
{
    BYTE bRandomByte = 0x00;
        
    bRandomByte = GenRandomByte();
    bRandomByte = bRandomByte % _countof(g_dwSyscallHashArray);

    return g_dwSyscallHashArray[bRandomByte];
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
