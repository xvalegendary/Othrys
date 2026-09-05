#ifndef _TCG2_HOOK_H_
#define _TCG2_HOOK_H_

#include <Uefi.h>

#define EFI_TCG2_PROTOCOL_GUID \
  { 0x607f766c, 0x7455, 0x42be, { 0x93, 0x0b, 0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f } }

typedef EFI_STATUS (EFIAPI *EFI_TCG2_SUBMIT_COMMAND)(
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

EFI_STATUS InstallTcg2Hook(VOID);

#endif