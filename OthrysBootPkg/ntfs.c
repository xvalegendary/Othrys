#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/BlockIo.h>
#include <Protocol/DiskIo.h>
#include "othrys_types.h"
#include "ntfs.h"

#define MAX_PATH_COMPONENTS  16
#define GPT_HEADER_LBA       1
#define GPT_SIGNATURE        0x5452415020494645ULL

#pragma pack(push, 1)

typedef struct {
    UINT8  BootIndicator;
    UINT8  StartHead;
    UINT8  StartSector;
    UINT8  StartCylinder;
    UINT8  SystemIndicator;
    UINT8  EndHead;
    UINT8  EndSector;
    UINT8  EndCylinder;
    UINT32 StartingLba;
    UINT32 NumSectors;
} LEGACY_MBR_PARTITION;

typedef struct {
    UINT64 Signature;
    UINT32 Revision;
    UINT32 HeaderSize;
    UINT32 HeaderCrc32;
    UINT32 Reserved;
    UINT64 MyLba;
    UINT64 AlternateLba;
    UINT64 FirstUsableLba;
    UINT64 LastUsableLba;
    UINT8  DiskGuid[16];
    UINT64 PartitionEntryLba;
    UINT32 NumPartitionEntries;
    UINT32 SizeOfPartitionEntry;
    UINT32 PartitionEntryArrayCrc32;
} GPT_HEADER;

typedef struct {
    UINT8  PartitionTypeGuid[16];
    UINT8  UniquePartitionGuid[16];
    UINT64 StartingLba;
    UINT64 EndingLba;
    UINT64 Attributes;
    UINT16 PartitionName[36];
} GPT_PARTITION_ENTRY;

#pragma pack(pop)

#define WINDOWS_NTFS_GUID  {0xE3, 0x7C, 0x49, 0x48, 0xB4, 0x62, 0x3C, 0x49, 0xAA, 0x67, 0x44, 0x1A, 0x00, 0x46, 0x56, 0x36}

INTN
StrniCmp (
    CONST CHAR16 *Str1,
    CONST CHAR16 *Str2,
    UINTN         Count
)
{
    while (Count > 0 && *Str1 && *Str2) {
        CHAR16 c1 = *Str1;
        CHAR16 c2 = *Str2;
        if (c1 >= L'A' && c1 <= L'Z') c1 += 32;
        if (c2 >= L'A' && c2 <= L'Z') c2 += 32;
        if (c1 != c2) return (INTN)c1 - (INTN)c2;
        Str1++;
        Str2++;
        Count--;
    }
    if (Count == 0) return 0;
    return (INTN)*Str1 - (INTN)*Str2;
}

static EFI_STATUS
ReadSectors (
    NTFS_CONTEXT *Ctx,
    UINT64        Lba,
    UINTN         Count,
    VOID         *Buffer
)
{
    return Ctx->BlockIo->ReadBlocks(
        Ctx->BlockIo,
        Ctx->BlockIo->Media->MediaId,
        Ctx->PartitionStartLba + Lba,
        Count * Ctx->BytesPerSector,
        Buffer
    );
}

static EFI_STATUS
ReadClusters (
    NTFS_CONTEXT *Ctx,
    UINT64        Cluster,
    UINTN         Count,
    VOID         *Buffer
)
{
    UINT64 Lba = (Cluster * Ctx->SectorsPerCluster);
    UINTN  SectorCount = Count * Ctx->SectorsPerCluster;
    return ReadSectors(Ctx, Lba, SectorCount, Buffer);
}

EFI_STATUS
FindNtfsPartition (
    EFI_BLOCK_IO_PROTOCOL *BlockIo,
    UINT32 *PartitionStartLba
)
{
    EFI_STATUS Status;
    UINT8     *SectorBuffer;
    UINTN      SectorSize;

    SectorSize = BlockIo->Media->BlockSize;
    SectorBuffer = AllocatePool(SectorSize * 2);
    if (!SectorBuffer) return EFI_OUT_OF_RESOURCES;

    Status = BlockIo->ReadBlocks(
        BlockIo,
        BlockIo->Media->MediaId,
        0,
        SectorSize,
        SectorBuffer
    );
    if (EFI_ERROR(Status)) {
        FreePool(SectorBuffer);
        return Status;
    }

    GPT_HEADER *GptHdr = (GPT_HEADER *)(SectorBuffer + SectorSize);
    if (GptHdr->Signature == GPT_SIGNATURE) {
        UINT8  *GptEntries;
        UINTN   EntriesSize = GptHdr->NumPartitionEntries * GptHdr->SizeOfPartitionEntry;
        UINTN   SectorSizeN = SectorSize;
        EntriesSize = (EntriesSize + SectorSizeN - 1) & ~(SectorSizeN - 1);
        
        GptEntries = AllocatePool(EntriesSize);
        if (!GptEntries) {
            FreePool(SectorBuffer);
            return EFI_OUT_OF_RESOURCES;
        }

        Status = BlockIo->ReadBlocks(
            BlockIo,
            BlockIo->Media->MediaId,
            GptHdr->PartitionEntryLba,
            EntriesSize,
            GptEntries
        );
        if (EFI_ERROR(Status)) {
            FreePool(GptEntries);
            FreePool(SectorBuffer);
            return Status;
        }

        UINT8 NtfsGuid[16] = WINDOWS_NTFS_GUID;
        GPT_PARTITION_ENTRY *PartEntry = (GPT_PARTITION_ENTRY *)GptEntries;
        
        for (UINTN i = 0; i < GptHdr->NumPartitionEntries; i++) {
            if (CompareMem(PartEntry[i].PartitionTypeGuid, NtfsGuid, 16) == 0) {
                *PartitionStartLba = (UINT32)PartEntry[i].StartingLba;
                FreePool(GptEntries);
                FreePool(SectorBuffer);
                return EFI_SUCCESS;
            }
        }

        for (UINTN i = 0; i < GptHdr->NumPartitionEntries; i++) {
            if (PartEntry[i].StartingLba != 0 && PartEntry[i].EndingLba != 0) {
                *PartitionStartLba = (UINT32)PartEntry[i].StartingLba;
                FreePool(GptEntries);
                FreePool(SectorBuffer);
                return EFI_SUCCESS;
            }
        }

        FreePool(GptEntries);
    } else {
        LEGACY_MBR_PARTITION *Mbr = (LEGACY_MBR_PARTITION *)SectorBuffer;
        for (UINTN i = 0; i < 4; i++) {
            if (Mbr[i].SystemIndicator == 0x07) {
                *PartitionStartLba = Mbr[i].StartingLba;
                FreePool(SectorBuffer);
                return EFI_SUCCESS;
            }
        }
    }

    FreePool(SectorBuffer);
    return EFI_NOT_FOUND;
}

static EFI_STATUS
FixupUpdateSequenceArray (
    UINT8 *Record,
    UINT32 RecordSize,
    UINT16 SectorSize
)
{
    FILE_RECORD_HEADER *Hdr = (FILE_RECORD_HEADER *)Record;
    UINT16 *Usa = (UINT16 *)(Record + Hdr->UsaOffset);
    UINT16  UsaCount = Hdr->UsaCount;
    UINT16  SavedValue = Usa[0];
    UINTN   SectorsInRecord = RecordSize / SectorSize;

    for (UINTN i = 0; i < SectorsInRecord && i < (UINTN)(UsaCount - 1); i++) {
        UINT16 *SectorUsa = (UINT16 *)(Record + (i + 1) * SectorSize - 2);
        if (*SectorUsa != SavedValue) {
            return EFI_DEVICE_ERROR;
        }
        *SectorUsa = Usa[i + 1];
    }

    return EFI_SUCCESS;
}

static EFI_STATUS
ReadMftEntry (
    NTFS_CONTEXT *Ctx,
    UINT64        EntryNumber,
    UINT8        *Buffer
)
{
    EFI_STATUS Status;
    UINT64     EntryOffset;
    UINTN      SectorsToRead;

    EntryOffset = Ctx->MftLba + (EntryNumber * Ctx->MftEntrySize / Ctx->BytesPerSector);
    SectorsToRead = Ctx->MftEntrySize / Ctx->BytesPerSector;

    Status = ReadSectors(Ctx, EntryOffset, SectorsToRead, Buffer);
    if (EFI_ERROR(Status)) return Status;

    Status = FixupUpdateSequenceArray(Buffer, Ctx->MftEntrySize, Ctx->BytesPerSector);
    return Status;
}

static ATTRIBUTE_HEADER *
FindAttribute (
    UINT8  *Record,
    UINT32  RecordSize,
    UINT32  AttrType
)
{
    FILE_RECORD_HEADER *Hdr = (FILE_RECORD_HEADER *)Record;
    UINT8  *Ptr = Record + Hdr->FirstAttributeOffset;
    UINT8  *End = Record + Hdr->UsedSize;

    while (Ptr + sizeof(ATTRIBUTE_HEADER) <= End) {
        ATTRIBUTE_HEADER *Attr = (ATTRIBUTE_HEADER *)Ptr;
        if (Attr->Type == 0xFFFFFFFF || Attr->Length == 0) break;
        if (Attr->Type == AttrType) {
            return Attr;
        }
        Ptr += Attr->Length;
    }

    return NULL;
}

typedef struct {
    UINT64 Offset;
    UINT64 Length;
} DATA_RUN;

static UINTN
ParseDataRun (
    UINT8     *RunData,
    DATA_RUN  *Runs,
    UINTN      MaxRuns
)
{
    UINTN   RunCount = 0;
    UINT8  *Ptr = RunData;
    UINT64  PrevOffset = 0;

    while (*Ptr != 0 && RunCount < MaxRuns) {
        UINT8 LenSize = *Ptr & 0x0F;
        UINT8 OffSize = (*Ptr >> 4) & 0x0F;
        Ptr++;

        if (LenSize == 0 || LenSize > 8 || OffSize > 8) break;

        UINT64 Length = 0;
        CopyMem(&Length, Ptr, LenSize);
        Ptr += LenSize;

        INT64 Offset = 0;
        if (OffSize > 0) {
            CopyMem(&Offset, Ptr, OffSize);
            Ptr += OffSize;
            if (Offset < 0) {
                Offset = -((INT64)(~Offset + 1));
            }
        }

        PrevOffset += Offset;
        Runs[RunCount].Offset = PrevOffset;
        Runs[RunCount].Length = Length;
        RunCount++;
    }

    return RunCount;
}

static EFI_STATUS
ReadNonResidentData (
    NTFS_CONTEXT *Ctx,
    NON_RESIDENT_ATTRIBUTE_HEADER *Attr,
    VOID  *Buffer,
    UINT64 MaxSize
)
{
    DATA_RUN  Runs[64];
    UINTN     RunCount;
    UINT8    *RunData;
    UINT64    BytesRead = 0;
    UINT64    BytesPerCluster = Ctx->BytesPerCluster;

    RunData = (UINT8 *)Attr + Attr->RunOffset;
    RunCount = ParseDataRun(RunData, Runs, 64);

    for (UINTN i = 0; i < RunCount && BytesRead < MaxSize; i++) {
        UINT64 ClustersToRead = Runs[i].Length;
        UINT64 BytesInRun = ClustersToRead * BytesPerCluster;
        UINT64 BytesToCopy = BytesInRun;

        if (BytesRead + BytesToCopy > MaxSize) {
            BytesToCopy = MaxSize - BytesRead;
        }

        if (Runs[i].Offset == 0) {
            SetMem((UINT8 *)Buffer + BytesRead, (UINTN)BytesToCopy, 0);
        } else {
            UINT64 SectorsPerCluster = Ctx->SectorsPerCluster;
            UINT64 TotalSectors = ClustersToRead * SectorsPerCluster;
            UINT8  *ClusterBuf = AllocatePool((UINTN)(TotalSectors * Ctx->BytesPerSector));
            if (!ClusterBuf) return EFI_OUT_OF_RESOURCES;

            EFI_STATUS Status = ReadClusters(Ctx, Runs[i].Offset, (UINTN)ClustersToRead, ClusterBuf);
            if (EFI_ERROR(Status)) {
                FreePool(ClusterBuf);
                return Status;
            }

            CopyMem((UINT8 *)Buffer + BytesRead, ClusterBuf, (UINTN)BytesToCopy);
            FreePool(ClusterBuf);
        }

        BytesRead += BytesToCopy;
    }

    return EFI_SUCCESS;
}

static UINT64
FindFileInIndex (
    NTFS_CONTEXT *Ctx,
    UINT8        *Record,
    CHAR16       *TargetName
)
{
    ATTRIBUTE_HEADER *Attr;
    FILE_NAME_ATTRIBUTE *FileName;
    INDEX_ENTRY_HEADER *IndexEntry;
    UINT8  *Ptr;
    UINT8  *End;

    Attr = FindAttribute(Record, Ctx->MftEntrySize, ATTR_TYPE_INDEX_ROOT);
    if (Attr) {
        RESIDENT_ATTRIBUTE_HEADER *ResAttr = (RESIDENT_ATTRIBUTE_HEADER *)Attr;
        Ptr = (UINT8 *)ResAttr + ResAttr->ValueOffset;
        End = Ptr + ResAttr->ValueLength;

        Ptr += 0x20;

        while (Ptr + sizeof(INDEX_ENTRY_HEADER) <= End) {
            IndexEntry = (INDEX_ENTRY_HEADER *)Ptr;
            if (IndexEntry->Flags & INDEX_ENTRY_END) break;

            FileName = (FILE_NAME_ATTRIBUTE *)((UINT8 *)IndexEntry + 0x10);
            if (StrniCmp(FileName->Name, TargetName, FileName->NameLength) == 0) {
                return IndexEntry->FileReference & 0x0000FFFFFFFFFFFFULL;
            }

            Ptr += IndexEntry->Size;
        }
    }

    Attr = FindAttribute(Record, Ctx->MftEntrySize, ATTR_TYPE_INDEX_ALLOC);
    if (Attr && Attr->NonResident) {
        NON_RESIDENT_ATTRIBUTE_HEADER *NonResAttr = (NON_RESIDENT_ATTRIBUTE_HEADER *)Attr;
        UINT64 AllocSize = NonResAttr->AllocatedSize;
        UINT8 *IndexBuf = AllocatePool((UINTN)AllocSize);
        if (!IndexBuf) return 0;

        EFI_STATUS Status = ReadNonResidentData(Ctx, NonResAttr, IndexBuf, AllocSize);
        if (EFI_ERROR(Status)) {
            FreePool(IndexBuf);
            return 0;
        }

        UINTN Offset = 0;
        while (Offset + Ctx->BytesPerCluster <= (UINTN)AllocSize) {
            UINT8 *IndexBlock = IndexBuf + Offset;

            if (*(UINT32 *)IndexBlock == 0x58444E49) {
                FixupUpdateSequenceArray(IndexBlock, Ctx->BytesPerCluster, Ctx->BytesPerSector);

                UINT8 *EntryPtr = IndexBlock + 0x18 + 0x08 + 0x18;
                UINT8 *EntryEnd = IndexBuf + Offset + Ctx->BytesPerCluster;

                while (EntryPtr + sizeof(INDEX_ENTRY_HEADER) <= EntryEnd) {
                    IndexEntry = (INDEX_ENTRY_HEADER *)EntryPtr;
                    if (IndexEntry->Flags & INDEX_ENTRY_END) break;
                    if (IndexEntry->Size == 0) break;

                    FileName = (FILE_NAME_ATTRIBUTE *)((UINT8 *)IndexEntry + 0x10);
                    if (StrniCmp(FileName->Name, TargetName, FileName->NameLength) == 0) {
                        UINT64 Ref = IndexEntry->FileReference & 0x0000FFFFFFFFFFFFULL;
                        FreePool(IndexBuf);
                        return Ref;
                    }

                    EntryPtr += IndexEntry->Size;
                }
            }

            Offset += Ctx->BytesPerCluster;
        }

        FreePool(IndexBuf);
    }

    return 0;
}

EFI_STATUS
NtfsInit (
    NTFS_CONTEXT  *Ctx,
    EFI_BLOCK_IO_PROTOCOL *BlockIo,
    UINT32 PartitionStartLba
)
{
    EFI_STATUS Status;
    NTFS_BOOT_SECTOR *BootSector;

    SetMem(Ctx, sizeof(NTFS_CONTEXT), 0);
    Ctx->BlockIo = BlockIo;
    Ctx->PartitionStartLba = PartitionStartLba;
    Ctx->BytesPerSector = (UINT32)BlockIo->Media->BlockSize;

    BootSector = AllocatePool(Ctx->BytesPerSector);
    if (!BootSector) return EFI_OUT_OF_RESOURCES;

    Status = ReadSectors(Ctx, 0, 1, BootSector);
    if (EFI_ERROR(Status)) {
        FreePool(BootSector);
        return Status;
    }

    if (*(UINT64 *)BootSector->OemId != NTFS_SIGNATURE) {
        FreePool(BootSector);
        return EFI_UNSUPPORTED;
    }

    Ctx->SectorsPerCluster = BootSector->SectorsPerCluster;
    Ctx->BytesPerCluster = Ctx->BytesPerSector * Ctx->SectorsPerCluster;

    UINT64 MftCluster = BootSector->MftLogicalCluster;
    Ctx->MftLba = MftCluster * Ctx->SectorsPerCluster;

    INT8 ClustersPerMft = BootSector->ClustersPerMftRecord;
    if (ClustersPerMft < 0) {
        Ctx->MftEntrySize = 1 << (-ClustersPerMft);
    } else {
        Ctx->MftEntrySize = ClustersPerMft * Ctx->BytesPerCluster;
    }

    FreePool(BootSector);

    Ctx->MftBuffer = AllocatePool(Ctx->MftEntrySize);
    Ctx->ScratchBuffer = AllocatePool(Ctx->MftEntrySize);
    if (!Ctx->MftBuffer || !Ctx->ScratchBuffer) {
        if (Ctx->MftBuffer) FreePool(Ctx->MftBuffer);
        if (Ctx->ScratchBuffer) FreePool(Ctx->ScratchBuffer);
        return EFI_OUT_OF_RESOURCES;
    }

    return EFI_SUCCESS;
}

EFI_STATUS
NtfsReadFile (
    NTFS_CONTEXT  *Ctx,
    CHAR16        *Path,
    VOID         **FileData,
    UINT64        *FileSize
)
{
    EFI_STATUS Status;
    CHAR16     *Components[MAX_PATH_COMPONENTS];
    UINTN       ComponentCount = 0;
    CHAR16      PathCopy[256];
    UINT64      CurrentEntry = 5;
    UINT8      *Record = Ctx->MftBuffer;

    StrCpyS(PathCopy, 256, Path);
    if (PathCopy[0] == L'\\' || PathCopy[0] == L'/') {
        PathCopy[0] = L'\0';
        Components[ComponentCount++] = PathCopy + 1;
    } else {
        Components[ComponentCount++] = PathCopy;
    }

    CHAR16 *Ptr = Components[0];
    while (*Ptr) {
        if (*Ptr == L'\\' || *Ptr == L'/') {
            *Ptr = L'\0';
            if (*(Ptr + 1)) {
                Components[ComponentCount++] = Ptr + 1;
            }
        }
        Ptr++;
    }

    for (UINTN i = 0; i < ComponentCount; i++) {
        Status = ReadMftEntry(Ctx, CurrentEntry, Record);
        if (EFI_ERROR(Status)) return Status;

        if (i == ComponentCount - 1) {
            ATTRIBUTE_HEADER *DataAttr = FindAttribute(Record, Ctx->MftEntrySize, ATTR_TYPE_DATA);
            if (!DataAttr) return EFI_NOT_FOUND;

            if (!DataAttr->NonResident) {
                RESIDENT_ATTRIBUTE_HEADER *ResAttr = (RESIDENT_ATTRIBUTE_HEADER *)DataAttr;
                *FileSize = ResAttr->ValueLength;
                *FileData = AllocatePool((UINTN)*FileSize);
                if (!*FileData) return EFI_OUT_OF_RESOURCES;
                CopyMem(*FileData, (UINT8 *)ResAttr + ResAttr->ValueOffset, (UINTN)*FileSize);
                return EFI_SUCCESS;
            } else {
                NON_RESIDENT_ATTRIBUTE_HEADER *NonResAttr = (NON_RESIDENT_ATTRIBUTE_HEADER *)DataAttr;
                *FileSize = NonResAttr->DataSize;
                *FileData = AllocatePool((UINTN)*FileSize);
                if (!*FileData) return EFI_OUT_OF_RESOURCES;
                return ReadNonResidentData(Ctx, NonResAttr, *FileData, *FileSize);
            }
        } else {
            UINT64 NextEntry = FindFileInIndex(Ctx, Record, Components[i]);
            if (NextEntry == 0) return EFI_NOT_FOUND;
            CurrentEntry = NextEntry;
        }
    }

    return EFI_NOT_FOUND;
}

VOID
NtfsCleanup (
    NTFS_CONTEXT *Ctx
)
{
    if (Ctx->MftBuffer) FreePool(Ctx->MftBuffer);
    if (Ctx->ScratchBuffer) FreePool(Ctx->ScratchBuffer);
    SetMem(Ctx, sizeof(NTFS_CONTEXT), 0);
}