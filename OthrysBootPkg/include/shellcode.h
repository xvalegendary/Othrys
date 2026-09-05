#ifndef _SHELLCODE_H_
#define _SHELLCODE_H_

#include <Uefi.h>
#include "othrys_types.h"

#define SHELLCODE_MARKER_START  0xDEADBEEFCAFEBABE
#define SHELLCODE_MARKER_END    0x0BADF00DDEADC0DE

typedef struct {
    UINT64 MarkerStart;
    UINT64 DriverDataAddr;
    UINT64 DriverSize;
    UINT64 NtoskrnlBase;
    UINT64 ExAllocatePool2Addr;
    UINT64 ExAllocatePoolWithTagAddr;
    UINT64 PsLoadedModuleListAddr;
    UINT64 PatchLocation;
    UINT64 OriginalRip;
    UINT64 OriginalBytes;
    UINT64 MarkerEnd;
} SHELLCODE_HEADER;

VOID ShellcodeEntry(VOID);
UINT32 GetShellcodeSize(VOID);
UINT32 GetShellcodeOffset(VOID);

#endif