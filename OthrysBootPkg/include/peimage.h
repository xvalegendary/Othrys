#ifndef _PEIMAGE_H_
#define _PEIMAGE_H_

#include <Uefi.h>
#include <IndustryStandard/PeImage.h>

typedef struct {
    UINT64 ImageBase;
    UINT64 ImageSize;
    UINT64 EntryPoint;
    BOOLEAN Is64Bit;
} PE_IMAGE_INFO;

EFI_STATUS PeParseHeaders(VOID *ImageData, PE_IMAGE_INFO *Info);
EFI_STATUS PeApplyRelocations(VOID *ImageBase, UINT64 Delta);
VOID *PeGetExportByName(VOID *ImageBase, CHAR8 *ExportName);

#endif