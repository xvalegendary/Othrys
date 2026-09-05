#ifndef _SB_VARIABLES_H_
#define _SB_VARIABLES_H_

#include <Uefi.h>

// !!!
//( sb variables spoofing ) but you need a real secure boot enabled system to get the real values, use sb_variables.exe to dump the real values from your system and replace the values below with the real ones
// !!!

static const UINT8 g_RealSecureBoot[] = { 0x01 };
static const UINTN g_RealSecureBootSize = 1;

static const UINT8 g_RealSetupMode[] = { 0x00 };
static const UINTN g_RealSetupModeSize = 1;

static const UINT8 g_RealAuditMode[] = { 0x00 };
static const UINTN g_RealAuditModeSize = 1;

static const UINT8 g_RealDeployedMode[] = { 0x00 };
static const UINTN g_RealDeployedModeSize = 1;

static const UINT8 g_RealCustomMode[] = { 0x00 };
static const UINTN g_RealCustomModeSize = 1;

static const UINT8 g_RealPK[] = { 0 };
static const UINTN g_RealPKSize = 0;

static const UINT8 g_RealKEK[] = { 0 };
static const UINTN g_RealKEKSize = 0;

static const UINT8 g_RealDb[] = { 0 };
static const UINTN g_RealDbSize = 0;

static const UINT8 g_RealDbx[] = { 0 };
static const UINTN g_RealDbxSize = 0;

static const UINT8 g_RealDbt[] = { 0 };
static const UINTN g_RealDbtSize = 0;

static const UINT8 g_RealDbr[] = { 0 };
static const UINTN g_RealDbrSize = 0;

static const UINT8 g_RealMokList[] = { 0 };
static const UINTN g_RealMokListSize = 0;

static const UINT8 g_RealSbatLevel[] = { 's','b','a','t',',','1',',','0','\n' };
static const UINTN g_RealSbatLevelSize = sizeof(g_RealSbatLevel);

static const UINT8 g_RealPCR7[32] = {
    0x3A, 0x1F, 0x74, 0x9F, 0x2E, 0x0D, 0x71, 0x68,
    0xEC, 0x8D, 0x69, 0x16, 0x82, 0xE1, 0x4A, 0x8B,
    0x5F, 0x54, 0xC6, 0x23, 0x6B, 0x1C, 0x30, 0xE7,
    0x4A, 0x9C, 0x61, 0x33, 0x2C, 0x98, 0xBA, 0x46
};

#endif