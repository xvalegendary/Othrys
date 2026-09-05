#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <IndustryStandard/PeImage.h>
#include "othrys_types.h"
#include "peimage.h"

#define IMAGE_DIRECTORY_ENTRY_BASERELOC  5
#define IMAGE_DIRECTORY_ENTRY_IMPORT     1

typedef struct {
    UINT32 VirtualAddress;
    UINT32 SizeOfBlock;
} BASE_RELOCATION_BLOCK;

typedef struct {
    UINT16 Offset:12;
    UINT16 Type:4;
} BASE_RELOCATION_ENTRY;

EFI_STATUS
PeParseHeaders (
    VOID          *ImageData,
    PE_IMAGE_INFO *Info
)
{
    EFI_IMAGE_DOS_HEADER  *DosHdr;
    EFI_IMAGE_NT_HEADERS64  *NtHdr64;
    EFI_IMAGE_NT_HEADERS32  *NtHdr32;

    DosHdr = (EFI_IMAGE_DOS_HEADER *)ImageData;
    if (DosHdr->e_magic != EFI_IMAGE_DOS_SIGNATURE) {
        return EFI_INVALID_PARAMETER;
    }

    NtHdr64 = (EFI_IMAGE_NT_HEADERS64 *)((UINT8 *)ImageData + DosHdr->e_lfanew);
    if (NtHdr64->Signature != EFI_IMAGE_NT_SIGNATURE) {
        return EFI_INVALID_PARAMETER;
    }

    Info->Is64Bit = (NtHdr64->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    if (Info->Is64Bit) {
        Info->ImageBase  = NtHdr64->OptionalHeader.ImageBase;
        Info->ImageSize  = NtHdr64->OptionalHeader.SizeOfImage;
        Info->EntryPoint = NtHdr64->OptionalHeader.AddressOfEntryPoint;
    } else {
        NtHdr32 = (EFI_IMAGE_NT_HEADERS32 *)NtHdr64;
        Info->ImageBase  = NtHdr32->OptionalHeader.ImageBase;
        Info->ImageSize  = NtHdr32->OptionalHeader.SizeOfImage;
        Info->EntryPoint = NtHdr32->OptionalHeader.AddressOfEntryPoint;
    }

    return EFI_SUCCESS;
}

EFI_STATUS
PeApplyRelocations (
    VOID   *ImageBase,
    UINT64  Delta
)
{
    EFI_IMAGE_DOS_HEADER  *DosHdr;
    EFI_IMAGE_NT_HEADERS64  *NtHdr64;
    EFI_IMAGE_NT_HEADERS32  *NtHdr32;
    EFI_IMAGE_DATA_DIRECTORY *RelocDir;
    BASE_RELOCATION_BLOCK *Block;
    BASE_RELOCATION_ENTRY *RelocEntry;
    UINT8  *RelocPtr;
    UINT8  *RelocEnd;
    UINTN   EntryCount;
    UINTN   i;

    if (Delta == 0) return EFI_SUCCESS;

    DosHdr = (EFI_IMAGE_DOS_HEADER *)ImageBase;
    NtHdr64 = (EFI_IMAGE_NT_HEADERS64 *)((UINT8 *)ImageBase + DosHdr->e_lfanew);

    if (NtHdr64->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        RelocDir = &NtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    } else {
        NtHdr32 = (EFI_IMAGE_NT_HEADERS32 *)NtHdr64;
        RelocDir = &NtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    }

    if (RelocDir->Size == 0) return EFI_SUCCESS;

    RelocPtr = (UINT8 *)ImageBase + RelocDir->VirtualAddress;
    RelocEnd = RelocPtr + RelocDir->Size;

    while (RelocPtr < RelocEnd) {
        Block = (BASE_RELOCATION_BLOCK *)RelocPtr;
        if (Block->SizeOfBlock == 0) break;

        EntryCount = (Block->SizeOfBlock - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(UINT16);
        RelocEntry = (BASE_RELOCATION_ENTRY *)(Block + 1);

        for (i = 0; i < EntryCount; i++) {
            UINT8 *PatchAddr = (UINT8 *)ImageBase + Block->VirtualAddress + RelocEntry[i].Offset;

            switch (RelocEntry[i].Type) {
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
    return EFI_SUCCESS;
}

VOID *
PeGetExportByName (
    VOID  *ImageBase,
    CHAR8 *ExportName
)
{
    EFI_IMAGE_DOS_HEADER  *DosHdr;
    EFI_IMAGE_NT_HEADERS64  *NtHdr64;
    EFI_IMAGE_NT_HEADERS32  *NtHdr32;
    EFI_IMAGE_DATA_DIRECTORY *ExportDir;
    EFI_IMAGE_EXPORT_DIRECTORY *Export;
    UINT32 *NameRvas;
    UINT32 *FuncRvas;
    UINT16 *Ordinals;
    UINTN   i;

    DosHdr = (EFI_IMAGE_DOS_HEADER *)ImageBase;
    NtHdr64 = (EFI_IMAGE_NT_HEADERS64 *)((UINT8 *)ImageBase + DosHdr->e_lfanew);

    if (NtHdr64->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        ExportDir = &NtHdr64->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_EXPORT];
    } else {
        NtHdr32 = (EFI_IMAGE_NT_HEADERS32 *)NtHdr64;
        ExportDir = &NtHdr32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_EXPORT];
    }

    if (ExportDir->Size == 0) return NULL;

    Export = (EFI_IMAGE_EXPORT_DIRECTORY *)((UINT8 *)ImageBase + ExportDir->VirtualAddress);
    NameRvas = (UINT32 *)((UINT8 *)ImageBase + Export->AddressOfNames);
    Ordinals = (UINT16 *)((UINT8 *)ImageBase + Export->AddressOfNameOrdinals);
    FuncRvas = (UINT32 *)((UINT8 *)ImageBase + Export->AddressOfFunctions);

    for (i = 0; i < Export->NumberOfNames; i++) {
        CHAR8 *Name = (CHAR8 *)ImageBase + NameRvas[i];
        UINTN j = 0;
        while (Name[j] && ExportName[j] && Name[j] == ExportName[j]) j++;
        if (Name[j] == 0 && ExportName[j] == 0) {
            UINT16 Ordinal = Ordinals[i];
            UINT32 FuncRva = FuncRvas[Ordinal];
            return (VOID *)((UINT8 *)ImageBase + FuncRva);
        }
    }
    return NULL;
}