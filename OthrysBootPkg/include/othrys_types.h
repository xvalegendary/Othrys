#ifndef _OTHYS_TYPES_H_
#define _OTHYS_TYPES_H_

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <IndustryStandard/PeImage.h>

typedef VOID *PVOID;
typedef EFI_STATUS NTSTATUS;

#define STATUS_SUCCESS                EFI_SUCCESS
#define STATUS_INVALID_PARAMETER      EFI_INVALID_PARAMETER
#define STATUS_INSUFFICIENT_RESOURCES EFI_OUT_OF_RESOURCES
#define STATUS_NOT_FOUND              EFI_NOT_FOUND
#define STATUS_BUFFER_TOO_SMALL       EFI_BUFFER_TOO_SMALL
#define STATUS_DEVICE_DATA_ERROR      EFI_DEVICE_ERROR
#define STATUS_INVALID_BUFFER_SIZE    EFI_BAD_BUFFER_SIZE
#define STATUS_NOT_SUPPORTED          EFI_UNSUPPORTED
#define STATUS_INVALID_LEVEL          EFI_NOT_READY

#ifndef IMAGE_SCN_MEM_EXECUTE
#define IMAGE_SCN_MEM_EXECUTE 0x20000000u
#endif

typedef struct {
    UINT8 *CodeBase;
    UINT64 CodeSize;
    UINT8 *DataBase;
    UINT64 DataSize;
    UINT8 *FullImage;
    UINT64 FullSize;
    UINT64 EntryPoint;
} EFI_PE_MAPPED_IMAGE;

#endif