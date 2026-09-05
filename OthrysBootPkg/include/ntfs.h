#ifndef _NTFS_H_
#define _NTFS_H_

#include <Uefi.h>
#include <Protocol/BlockIo.h>
#include <Protocol/DiskIo.h>

#define NTFS_SIGNATURE         0x202020205346544E
#define MFT_RECORD_SIGNATURE   0x454C4946

#define ATTR_TYPE_STANDARD_INFO  0x10
#define ATTR_TYPE_FILE_NAME      0x30
#define ATTR_TYPE_DATA           0x80
#define ATTR_TYPE_INDEX_ROOT     0x90
#define ATTR_TYPE_INDEX_ALLOC    0xA0

#define FILE_RECORD_IN_USE       0x01

#define INDEX_ENTRY_SIZE         0x10
#define INDEX_ENTRY_END          0x02

#pragma pack(push, 1)

typedef struct {
    UINT8  Jump[3];
    UINT8  OemId[8];
    UINT16 BytesPerSector;
    UINT8  SectorsPerCluster;
    UINT16 ReservedSectors;
    UINT8  AlwaysZero1[3];
    UINT16 Unused1;
    UINT8  MediaType;
    UINT8  AlwaysZero2[2];
    UINT16 SectorsPerTrack;
    UINT16 NumberOfHeads;
    UINT32 HiddenSectors;
    UINT8  AlwaysZero3[8];
    UINT64 TotalSectors;
    UINT64 MftLogicalCluster;
    UINT64 MftMirrorLogicalCluster;
    INT8   ClustersPerMftRecord;
    UINT8  Reserved1[3];
    INT8   ClustersPerIndexRecord;
    UINT8  Reserved2[3];
    UINT64 VolumeSerialNumber;
    UINT32 Checksum;
} NTFS_BOOT_SECTOR;

typedef struct {
    UINT32 Signature;
    UINT16 UsaOffset;
    UINT16 UsaCount;
    UINT64 Lsn;
    UINT16 SequenceNumber;
    UINT16 HardLinkCount;
    UINT16 FirstAttributeOffset;
    UINT16 Flags;
    UINT32 UsedSize;
    UINT32 AllocatedSize;
    UINT64 BaseRecord;
    UINT16 NextAttributeId;
} FILE_RECORD_HEADER;

typedef struct {
    UINT32 Type;
    UINT32 Length;
    UINT8  NonResident;
    UINT8  NameLength;
    UINT16 NameOffset;
    UINT16 Flags;
    UINT16 AttributeId;
} ATTRIBUTE_HEADER;

typedef struct {
    ATTRIBUTE_HEADER Header;
    UINT32 ValueLength;
    UINT16 ValueOffset;
    UINT16 Flags;
} RESIDENT_ATTRIBUTE_HEADER;

typedef struct {
    ATTRIBUTE_HEADER Header;
    UINT64 LowestVcn;
    UINT64 HighestVcn;
    UINT16 RunOffset;
    UINT16 CompressionUnit;
    UINT8  Reserved[4];
    UINT64 AllocatedSize;
    UINT64 DataSize;
    UINT64 InitializedSize;
} NON_RESIDENT_ATTRIBUTE_HEADER;

typedef struct {
    UINT64 ParentDirectory;
    UINT64 CreationTime;
    UINT64 LastModificationTime;
    UINT64 LastChangeTime;
    UINT64 LastAccessTime;
    UINT64 AllocatedSize;
    UINT64 DataSize;
    UINT32 Flags;
    UINT32 ReparseValue;
    UINT8  NameLength;
    UINT8  NameType;
    CHAR16 Name[1];
} FILE_NAME_ATTRIBUTE;

typedef struct {
    UINT64 ParentDirectory;
    UINT64 FileReference;
    UINT16 Size;
    UINT16 Flags;
} INDEX_ENTRY_HEADER;

#pragma pack(pop)

typedef struct {
    EFI_BLOCK_IO_PROTOCOL *BlockIo;
    UINT32                 PartitionStartLba;
    UINT32                 BytesPerSector;
    UINT32                 SectorsPerCluster;
    UINT32                 BytesPerCluster;
    UINT64                 MftLba;
    UINT32                 MftEntrySize;
    UINT8                 *MftBuffer;
    UINT8                 *ScratchBuffer;
} NTFS_CONTEXT;

EFI_STATUS FindNtfsPartition(EFI_BLOCK_IO_PROTOCOL *BlockIo, UINT32 *PartitionStartLba);
EFI_STATUS NtfsInit(NTFS_CONTEXT *Ctx, EFI_BLOCK_IO_PROTOCOL *BlockIo, UINT32 PartitionStartLba);
EFI_STATUS NtfsReadFile(NTFS_CONTEXT *Ctx, CHAR16 *Path, VOID **FileData, UINT64 *FileSize);
VOID NtfsCleanup(NTFS_CONTEXT *Ctx);

INTN StrniCmp(CONST CHAR16 *Str1, CONST CHAR16 *Str2, UINTN Count);

#endif