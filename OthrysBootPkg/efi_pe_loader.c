#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <IndustryStandard/PeImage.h>
#include "othrys_types.h"

#ifndef IMAGE_SCN_MEM_DISCARDABLE
#define IMAGE_SCN_MEM_DISCARDABLE 0x02000000u
#endif

typedef struct {
    UINT32 VirtualAddress;
    UINT32 SizeOfBlock;
} BASE_RELOCATION_BLOCK;

static UINT8 *
AllocateEfiCode (
    UINTN Size
)
{
    UINTN Pages = EFI_SIZE_TO_PAGES(Size);
    EFI_STATUS Status;
    EFI_PHYSICAL_ADDRESS Addr;

    Status = gBS->AllocatePages(AllocateAnyPages,
        EfiRuntimeServicesCode, Pages, &Addr);
    if (EFI_ERROR(Status)) return NULL;

    return (UINT8 *)Addr;
}

static UINT8 *
AllocateEfiData (
    UINTN Size
)
{
    UINTN Pages = EFI_SIZE_TO_PAGES(Size);
    EFI_STATUS Status;
    EFI_PHYSICAL_ADDRESS Addr;

    Status = gBS->AllocatePages(AllocateAnyPages,
        EfiRuntimeServicesData, Pages, &Addr);
    if (EFI_ERROR(Status)) return NULL;

    return (UINT8 *)Addr;
}

EFI_STATUS
EfiMapDriverSections (
    VOID *RawImage,
    UINTN RawSize,
    EFI_PE_MAPPED_IMAGE *Out
)
{
    EFI_IMAGE_DOS_HEADER *DosHdr;
    EFI_IMAGE_NT_HEADERS64 *NtHdr;
    EFI_IMAGE_SECTION_HEADER *Sec;
    UINT16 NumSections;
    UINTN CodeSize = 0;
    UINTN DataSize = 0;
    UINTN HeaderSize;

    if (!RawImage || !Out) return EFI_INVALID_PARAMETER;

    DosHdr = (EFI_IMAGE_DOS_HEADER *)RawImage;
    if (DosHdr->e_magic != EFI_IMAGE_DOS_SIGNATURE) return EFI_INVALID_PARAMETER;

    NtHdr = (EFI_IMAGE_NT_HEADERS64 *)((UINT8 *)RawImage + DosHdr->e_lfanew);
    if (NtHdr->Signature != EFI_IMAGE_NT_SIGNATURE) return EFI_INVALID_PARAMETER;
    if (NtHdr->OptionalHeader.Magic != EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC) return EFI_INVALID_PARAMETER;

    HeaderSize = NtHdr->OptionalHeader.SizeOfHeaders;
    NumSections = NtHdr->FileHeader.NumberOfSections;
    Sec = (EFI_IMAGE_SECTION_HEADER *)((UINT8 *)NtHdr + sizeof(EFI_IMAGE_NT_HEADERS64));

    for (UINT16 i = 0; i < NumSections; i++) {
        UINTN SecSize = Sec[i].Misc.VirtualSize;
        if (SecSize == 0) SecSize = Sec[i].SizeOfRawData;

        if (Sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            CodeSize += Sec[i].VirtualAddress + SecSize;
        } else {
            DataSize += Sec[i].VirtualAddress + SecSize;
        }
    }

    if (CodeSize == 0) CodeSize = NtHdr->OptionalHeader.SizeOfImage;
    if (DataSize == 0) DataSize = 0x1000;

    CodeSize = (CodeSize + 0xFFF) & ~0xFFF;
    DataSize = (DataSize + 0xFFF) & ~0xFFF;

    Out->CodeBase = AllocateEfiCode(CodeSize);
    Out->CodeSize = CodeSize;
    Out->DataBase = AllocateEfiData(DataSize);
    Out->DataSize = DataSize;

    if (!Out->CodeBase || !Out->DataBase) {
        return EFI_OUT_OF_RESOURCES;
    }

    SetMem(Out->CodeBase, CodeSize, 0);
    SetMem(Out->DataBase, DataSize, 0);

    CopyMem(Out->CodeBase, RawImage, HeaderSize);

    for (UINT16 i = 0; i < NumSections; i++) {
        UINT8 *Dest;
        UINTN SecSize = Sec[i].Misc.VirtualSize;
        if (SecSize == 0) SecSize = Sec[i].SizeOfRawData;

        if (Sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            Dest = Out->CodeBase + Sec[i].VirtualAddress;
        } else {
            Dest = Out->DataBase + Sec[i].VirtualAddress;
        }

        if (Sec[i].SizeOfRawData > 0 && Sec[i].PointerToRawData < RawSize) {
            UINTN CopySize = Sec[i].SizeOfRawData;
            if (Sec[i].PointerToRawData + CopySize > RawSize)
                CopySize = RawSize - Sec[i].PointerToRawData;
            CopyMem(Dest, (UINT8 *)RawImage + Sec[i].PointerToRawData, CopySize);
        }
    }

    Out->FullImage = Out->CodeBase;
    Out->FullSize = NtHdr->OptionalHeader.SizeOfImage;
    Out->EntryPoint = (UINT64)Out->CodeBase + NtHdr->OptionalHeader.AddressOfEntryPoint;

    return EFI_SUCCESS;
}

EFI_STATUS
EfiApplyRelocations (
    UINT8 *ImageBase,
    UINT64 OriginalBase,
    UINT64 NewBase
)
{
    EFI_IMAGE_DOS_HEADER *DosHdr = (EFI_IMAGE_DOS_HEADER *)ImageBase;
    EFI_IMAGE_NT_HEADERS64 *NtHdr = (EFI_IMAGE_NT_HEADERS64 *)(ImageBase + DosHdr->e_lfanew);
    EFI_IMAGE_DATA_DIRECTORY *RelocDir =
        &NtHdr->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (RelocDir->Size == 0) return EFI_SUCCESS;

    INT64 Delta = (INT64)(NewBase - OriginalBase);
    if (Delta == 0) return EFI_SUCCESS;

    UINT8 *RelocPtr = ImageBase + RelocDir->VirtualAddress;
    UINT8 *RelocEnd = RelocPtr + RelocDir->Size;

    while (RelocPtr < RelocEnd) {
        BASE_RELOCATION_BLOCK *Block = (BASE_RELOCATION_BLOCK *)RelocPtr;
        if (Block->SizeOfBlock == 0) break;

        UINTN EntryCount = (Block->SizeOfBlock - sizeof(BASE_RELOCATION_BLOCK))
                         / sizeof(UINT16);
        UINT16 *Entries = (UINT16 *)(Block + 1);

        for (UINTN i = 0; i < EntryCount; i++) {
            UINT16 Type = (Entries[i] >> 12) & 0xF;
            UINT16 Offset = Entries[i] & 0xFFF;
            UINT8 *PatchAddr = ImageBase + Block->VirtualAddress + Offset;

            switch (Type) {
                case EFI_IMAGE_REL_BASED_ABSOLUTE:
                    break;
                case EFI_IMAGE_REL_BASED_HIGHLOW:
                    *(UINT32 *)PatchAddr += (UINT32)Delta;
                    break;
                case EFI_IMAGE_REL_BASED_DIR64:
                    *(UINT64 *)PatchAddr += (UINT64)Delta;
                    break;
                default:
                    break;
            }
        }
        RelocPtr += Block->SizeOfBlock;
    }
    return EFI_SUCCESS;
}

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

static UINT64
FindModuleByName (
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

EFI_STATUS
EfiResolveImports (
    UINT8 *ImageBase,
    UINT64 NtoskrnlBase,
    UINT64 PsLoadedModuleList
)
{
    EFI_IMAGE_DOS_HEADER *DosHdr = (EFI_IMAGE_DOS_HEADER *)ImageBase;
    EFI_IMAGE_NT_HEADERS64 *NtHdr = (EFI_IMAGE_NT_HEADERS64 *)(ImageBase + DosHdr->e_lfanew);
    EFI_IMAGE_DATA_DIRECTORY *ImportDir =
        &NtHdr->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (ImportDir->Size == 0) return EFI_SUCCESS;

    EFI_IMAGE_IMPORT_DESCRIPTOR *ImportDesc =
        (EFI_IMAGE_IMPORT_DESCRIPTOR *)(ImageBase + ImportDir->VirtualAddress);

    while (ImportDesc->Name != 0) {
        UINT32 *ImportDescRaw = (UINT32 *)ImportDesc;
        UINT32 OriginalFirstThunk = ImportDescRaw[0];
        UINT32 NameRva = ImportDescRaw[3];
        UINT32 FirstThunk = ImportDescRaw[4];

        CHAR8 *DllName = (CHAR8 *)(ImageBase + NameRva);

        UINT64 ModuleBase = 0;

        UINTN i;
        for (i = 0; DllName[i]; i++);
        CHAR16 WideName[64];
        for (i = 0; DllName[i] && i < 63; i++)
            WideName[i] = (CHAR16)DllName[i];
        WideName[i] = 0;

        if (CompareMem(DllName, "ntoskrnl.exe", 13) == 0 ||
            CompareMem(DllName, "ntkrnlmp.exe", 13) == 0 ||
            CompareMem(DllName, "ntoskrnl", 9) == 0)
        {
            ModuleBase = NtoskrnlBase;
        } else {
            ModuleBase = FindModuleByName(PsLoadedModuleList, WideName, i);
        }

        if (!ModuleBase) {
            ImportDesc++;
            continue;
        }

        UINT64 *ThunkRef = (UINT64 *)(ImageBase + FirstThunk);
        UINT64 *FuncRef = (UINT64 *)(ImageBase + (OriginalFirstThunk ? OriginalFirstThunk : FirstThunk));

        for (; *FuncRef; FuncRef++, ThunkRef++) {
            if (*FuncRef & 0x8000000000000000ULL) {
                UINT16 Ordinal = (UINT16)(*FuncRef & 0xFFFF);
                EFI_IMAGE_DOS_HEADER *ModDos = (EFI_IMAGE_DOS_HEADER *)ModuleBase;
                EFI_IMAGE_NT_HEADERS64 *ModNt = (EFI_IMAGE_NT_HEADERS64 *)(ModuleBase + ModDos->e_lfanew);
                EFI_IMAGE_EXPORT_DIRECTORY *ModExp = (EFI_IMAGE_EXPORT_DIRECTORY *)
                    (ModuleBase + ModNt->OptionalHeader.DataDirectory[0].VirtualAddress);
                UINT32 *FuncRvas = (UINT32 *)(ModuleBase + ModExp->AddressOfFunctions);
                *ThunkRef = ModuleBase + FuncRvas[Ordinal - ModExp->Base];
            } else {
                CHAR8 *FuncName = (CHAR8 *)(ImageBase + *FuncRef + 2);

                EFI_IMAGE_DOS_HEADER *ModDos = (EFI_IMAGE_DOS_HEADER *)ModuleBase;
                EFI_IMAGE_NT_HEADERS64 *ModNt = (EFI_IMAGE_NT_HEADERS64 *)(ModuleBase + ModDos->e_lfanew);
                EFI_IMAGE_EXPORT_DIRECTORY *ModExp = (EFI_IMAGE_EXPORT_DIRECTORY *)
                    (ModuleBase + ModNt->OptionalHeader.DataDirectory[0].VirtualAddress);

                if (ModExp->NumberOfNames == 0) continue;

                UINT32 *NameRvas = (UINT32 *)(ModuleBase + ModExp->AddressOfNames);
                UINT16 *Ordinals = (UINT16 *)(ModuleBase + ModExp->AddressOfNameOrdinals);
                UINT32 *FuncRvas = (UINT32 *)(ModuleBase + ModExp->AddressOfFunctions);

                for (UINT32 j = 0; j < ModExp->NumberOfNames; j++) {
                    CHAR8 *ExpName = (CHAR8 *)(ModuleBase + NameRvas[j]);
                    UINTN k = 0;
                    while (ExpName[k] && FuncName[k] && ExpName[k] == FuncName[k]) k++;
                    if (ExpName[k] == 0 && FuncName[k] == 0) {
                        *ThunkRef = ModuleBase + FuncRvas[Ordinals[j]];
                        break;
                    }
                }
            }
        }
        ImportDesc++;
    }
    return EFI_SUCCESS;
}

EFI_STATUS
EfiLoadDriver (
    VOID *RawDriver,
    UINTN RawSize,
    UINT64 NtoskrnlBase,
    UINT64 PsLoadedModuleList,
    EFI_PE_MAPPED_IMAGE *Out
)
{
    EFI_STATUS Status;

    Status = EfiMapDriverSections(RawDriver, RawSize, Out);
    if (EFI_ERROR(Status)) return Status;

    EFI_IMAGE_DOS_HEADER *DosHdr = (EFI_IMAGE_DOS_HEADER *)RawDriver;
    EFI_IMAGE_NT_HEADERS64 *NtHdr = (EFI_IMAGE_NT_HEADERS64 *)((UINT8 *)RawDriver + DosHdr->e_lfanew);
    UINT64 OriginalBase = NtHdr->OptionalHeader.ImageBase;

    Status = EfiApplyRelocations(Out->CodeBase, OriginalBase, (UINT64)Out->CodeBase);
    if (EFI_ERROR(Status)) return Status;

    Status = EfiResolveImports(Out->CodeBase, NtoskrnlBase, PsLoadedModuleList);
    if (EFI_ERROR(Status)) return Status;

    return EFI_SUCCESS;
}