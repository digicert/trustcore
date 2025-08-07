/*
 * ssh_example.c
 *
 * Example code for integrating SSH Server Stack
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#if defined(__ENABLE_MOCANA_WIN_STUDIO_BUILD__)
#include <windows.h>
#endif

#include "common/moptions.h"
#if (defined( __ENABLE_MOCANA_SSH_SERVER_EXAMPLE__ ) && !defined( __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__ ) && !defined(__ENABLE_MOCANA_SSH_PORT_FORWARDING__))

/* see ssh_example_async.c for asynchronous API */
#include "common/mtypes.h"
#include "common/mocana.h"
#include "crypto/hw_accel.h"
#include "common/debug_console.h"
#include "common/mdefs.h"
#include "common/merrors.h"
#include "common/mrtos.h"
#include "common/mstdlib.h"
#include "common/mfmgmt.h"
#include "common/mtcp.h"
#include "common/int64.h"
#include "crypto/pubcrypto.h"
#include "crypto/ca_mgmt.h"
#include "common/sizedbuffer.h"
#include "crypto/cert_store.h"
#include "crypto/cert_chain.h"
#include "ssh/ssh_filesys.h"
#include "ssh/sftp.h"
#include "ssh/ssh.h"
#include "ssh/ssh_utils.h"
#ifdef __ENABLE_MOCANA_TPM__
#include "crypto/secmod/moctap.h"
#endif
#ifdef __ENABLE_MOCANA_TAP__
#include "smp/smp_cc.h"
#include "tap/tap_api.h"
#include "tap/tap_utils.h"
#include "tap/tap_smp.h"
#include "crypto/mocasym.h"
#include "crypto/mocasymkeys/tap/rsatap.h"
#include "crypto/mocasymkeys/tap/ecctap.h"
#include "crypto_interface/cryptointerface.h"
#endif

#ifdef __ENABLE_MOCANA_OCSP_CERT_VERIFY__
#include "common/memfile.h"
#include "ocsp/ocsp.h"
#include "ocsp/ocsp_context.h"
#include "ocsp/client/ocsp_client.h"
#endif

#ifdef __ENABLE_MOCANA_DATA_PROTECTION__
#include "data_protection/file_protect.h"
#endif

#ifdef __ENABLE_MOCANA_EXAMPLE_SSH_RADIUS_PASSWORD_AUTH__
#include "radius/radius.h"
#endif

#include <string.h>
#include <stdio.h>

static sbyte4 mBreak = 0;
static certStorePtr pSshCertStore;

#define SSH_EXAMPLE_banner "Mocana NanoSSH server!!\n"

/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_SSH_FTP_SERVER__
extern void SFTP_EXAMPLE_init(void);
#endif

#ifdef __ENABLE_MOCANA_EXAMPLE_SSH_RADIUS_PASSWORD_AUTH__
extern int
SSH_RADIUS_EXAMPLE_authPasswordFunction(int connectionInstance,
                                        const unsigned char *pUser,     unsigned int userLength,
                                        const unsigned char *pPassword, unsigned int passwordLength);
#endif

/* WARNING: Hardcoded credentials used below are for illustrative purposes ONLY.
   DO NOT use hardcoded credentials in production. */
#define USERNAME    "admin"
#define PASSWORD    "secure"

#ifdef __RTOS_VXWORKS__
#define PUBLIC_HOST_KEY_FILE_NAME       "NVRAM:/sshkeys.pub"
#define PRIVATE_HOST_KEY_FILE_NAME      "NVRAM:/sshkeys.prv"
#define AUTH_KEYFILE_NAME               "NVRAM:/id_dsa.pub"
#elif __RTOS_OSE__
#define PUBLIC_HOST_KEY_FILE_NAME       "/ram/sshkeys.pub"
#define PRIVATE_HOST_KEY_FILE_NAME      "/ram/sshkeys.prv"
#define AUTH_KEYFILE_NAME               "/ram/id_dsa.pub"
#else
#define PUBLIC_HOST_KEY_FILE_NAME       "sshkeys.pub"
#define PRIVATE_HOST_KEY_FILE_NAME      "sshkeys.prv"
#define AUTH_KEYFILE_NAME               "id_dsa.pub"
#endif

#if defined(__ENABLE_MOCANA_TAP__)
#include "../common/tpm2_path.h"
#if (defined(__ENABLE_MOCANA_TAP_REMOTE__))
static unsigned short  taps_ServerPort     = 0;
static char * 	       taps_ServerName     = NULL;
#endif
static char *          tap_ConfigFile      = NULL;

static TAP_Context *g_pTapContext;
static TAP_EntityCredentialList *g_pTapEntityCred = NULL;
static TAP_CredentialList       *g_pTapKeyCred    = NULL;
static TAP_ModuleList g_moduleList                = { 0 };
#endif

#ifdef __ENABLE_MOCANA_TPM__
static MOCTAP_HANDLE mh;
static void* reqKeyContext;
#endif

#ifdef __ENABLE_MOCANA_MEM_PART__
extern memPartDescr *gMemPartDescr;
#endif

#define MAX_SSH_CONNECTIONS_ALLOWED        (4)
static unsigned short  ssh_ServerPort       = SSH_DEFAULT_TCPIP_PORT;
static byteBoolean  ssh_disablePasswordExpiryTest  = FALSE;
static char *          ssh_ServerCert       = NULL;
static char *          ssh_ServerBlob       = NULL;
static char *          ssh_CACert           = NULL;
static char *          ocsp_ResponderUrl    = NULL;
static ubyte4          ocsp_Timeout         = 500000;
static char *          ssh_UserName         = NULL;
static char *          ssh_Password         = NULL;

/* for interactive-keyboard authentication */
enum exampleAuthStates
{
    EXAMPLE_PASSWORD = 0,
    EXAMPLE_CHANGE_PASSWORD = 1,
    EXAMPLE_PASSWORD_DONE = 2,
    EXAMPLE_DONE = 3
};

static sbyte *
m_exampleMessages[] =
{
    (sbyte *)"Password Authentication",
    (sbyte *)"Password Expired",
    (sbyte *)"Your password has expired.",
    (sbyte *)"Password changed",
    (sbyte *)"Password successfully changed for "
};

static keyIntPrompt
m_passwordPrompts[] =
{
    { (sbyte *)"Password: ",           10, AUTH_NO_ECHO },
    { (sbyte *)"Enter new password: ", 20, AUTH_NO_ECHO },
    { (sbyte *)"Enter it again: ",     16, AUTH_NO_ECHO }
};

#if ((defined(__ENABLE_MOCANA_SSH_X509V3_SIGN_SUPPORT__)) && (defined(__ENABLE_MOCANA_SSH_X509V3_RFC_6187_SUPPORT__)))
static ubyte cacert[] =
{
    0x30, 0x82, 0x05, 0x61, 0x30, 0x82, 0x03, 0x49, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x09, 0x00,
    0xff, 0x21, 0x1f, 0x9c, 0xdb, 0x5d, 0x5a, 0x98, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30, 0x47, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55,
    0x04, 0x06, 0x13, 0x02, 0x49, 0x4e, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c,
    0x02, 0x4d, 0x48, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x04, 0x50, 0x75,
    0x6e, 0x65, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x06, 0x4d, 0x6f, 0x63,
    0x61, 0x6e, 0x61, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x02, 0x43, 0x41,
    0x30, 0x1e, 0x17, 0x0d, 0x31, 0x33, 0x31, 0x30, 0x33, 0x31, 0x30, 0x35, 0x30, 0x30, 0x31, 0x31,
    0x5a, 0x17, 0x0d, 0x31, 0x38, 0x31, 0x30, 0x33, 0x31, 0x30, 0x35, 0x30, 0x30, 0x31, 0x31, 0x5a,
    0x30, 0x47, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x49, 0x4e, 0x31,
    0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x02, 0x4d, 0x48, 0x31, 0x0d, 0x30, 0x0b,
    0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x04, 0x50, 0x75, 0x6e, 0x65, 0x31, 0x0f, 0x30, 0x0d, 0x06,
    0x03, 0x55, 0x04, 0x0a, 0x0c, 0x06, 0x4d, 0x6f, 0x63, 0x61, 0x6e, 0x61, 0x31, 0x0b, 0x30, 0x09,
    0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x02, 0x43, 0x41, 0x30, 0x82, 0x02, 0x22, 0x30, 0x0d, 0x06,
    0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0f,
    0x00, 0x30, 0x82, 0x02, 0x0a, 0x02, 0x82, 0x02, 0x01, 0x00, 0xbf, 0x1d, 0x10, 0x39, 0x55, 0x75,
    0x71, 0x42, 0x65, 0xd1, 0x74, 0xe9, 0x64, 0x77, 0x6a, 0xf6, 0xf6, 0x49, 0xbc, 0xf3, 0xc1, 0x0f,
    0x0b, 0xdc, 0x0e, 0x07, 0x5c, 0x10, 0x2f, 0xd8, 0xd3, 0xf3, 0x9b, 0x65, 0x8a, 0xdb, 0x6a, 0xf7,
    0x49, 0x19, 0x92, 0x28, 0x7e, 0x34, 0x96, 0x1b, 0xef, 0x99, 0x3e, 0x31, 0xe0, 0x39, 0x88, 0x44,
    0x15, 0x00, 0x70, 0x22, 0x46, 0x2b, 0xf1, 0xe6, 0xc8, 0x9f, 0xa2, 0xd7, 0x5b, 0xc7, 0xe5, 0xe7,
    0xe6, 0xed, 0x1c, 0x08, 0xd2, 0x81, 0xc9, 0x15, 0x36, 0x6d, 0xba, 0xa8, 0xe7, 0xcc, 0x28, 0x28,
    0x22, 0x33, 0x3b, 0x28, 0xb9, 0x10, 0x3f, 0x0f, 0x4a, 0x13, 0x82, 0x28, 0xf6, 0x32, 0x55, 0x73,
    0x64, 0x1b, 0xaf, 0x70, 0xe6, 0xd7, 0xb9, 0x03, 0x3d, 0x7e, 0x16, 0xdd, 0xbf, 0x28, 0x35, 0x39,
    0x24, 0xb1, 0x6c, 0x4a, 0x19, 0x3a, 0xbd, 0xc7, 0x1a, 0x08, 0x88, 0x28, 0x0a, 0xd4, 0x85, 0x7d,
    0x80, 0x30, 0x1f, 0x06, 0xa7, 0x44, 0x9f, 0x2f, 0x60, 0x2a, 0x5d, 0xb8, 0x8e, 0xd9, 0x5a, 0x17,
    0xee, 0x10, 0x67, 0xdb, 0xc0, 0xc8, 0x53, 0xd8, 0x5b, 0x2c, 0x9d, 0x99, 0x4e, 0x3a, 0xcd, 0xd4,
    0xbf, 0x15, 0x3c, 0xe1, 0x31, 0xf0, 0x52, 0xbe, 0x35, 0x39, 0xfb, 0x61, 0x8e, 0xb6, 0xa1, 0x81,
    0x69, 0x9f, 0xbd, 0x8b, 0x2b, 0x06, 0xf5, 0x79, 0x55, 0x74, 0xc7, 0xb7, 0x9d, 0x1b, 0x49, 0xea,
    0x8e, 0x66, 0xe7, 0xaf, 0xb1, 0x7d, 0x11, 0x21, 0xed, 0x41, 0xaa, 0x78, 0xcd, 0x3a, 0x1c, 0xbc,
    0x10, 0x7d, 0x7a, 0x80, 0xa8, 0xd1, 0xbb, 0x64, 0x27, 0xa7, 0x7f, 0x08, 0x27, 0xd3, 0x6c, 0x86,
    0x25, 0x3d, 0x6e, 0x31, 0x86, 0xf4, 0xde, 0xef, 0xa4, 0x87, 0x9d, 0xbf, 0xd5, 0x0e, 0x81, 0x89,
    0xb4, 0xd2, 0xc8, 0x5b, 0x6a, 0x43, 0x35, 0xa2, 0x6c, 0x66, 0xdd, 0xb9, 0xd5, 0xf8, 0x98, 0x86,
    0xf9, 0xd0, 0x88, 0x84, 0xf7, 0x95, 0x58, 0xbd, 0x58, 0x26, 0x82, 0x60, 0x28, 0xad, 0x0a, 0x32,
    0xdf, 0xdd, 0x42, 0x3d, 0xcc, 0x4b, 0xac, 0x64, 0xe7, 0xe4, 0xc0, 0xcd, 0x2d, 0x2b, 0x65, 0x8f,
    0x8d, 0x98, 0x2c, 0x6e, 0xca, 0x85, 0x96, 0x8a, 0xd0, 0x26, 0x1a, 0x29, 0x05, 0x8a, 0x51, 0xeb,
    0xbe, 0xa4, 0x7e, 0xa9, 0xf9, 0x45, 0xaa, 0xa0, 0xe8, 0x95, 0x61, 0x44, 0xc0, 0xb6, 0x47, 0x2e,
    0x88, 0x7b, 0x7f, 0x0a, 0xfc, 0x14, 0xef, 0x67, 0x78, 0xb2, 0x49, 0x6c, 0x8f, 0x17, 0x2d, 0x86,
    0xb5, 0xde, 0x8f, 0xe5, 0x3f, 0x59, 0xbc, 0x6a, 0x38, 0xf5, 0x69, 0xb1, 0x95, 0x42, 0x27, 0x15,
    0xf4, 0x67, 0xbc, 0x71, 0x5c, 0x70, 0xb7, 0x58, 0x3e, 0x7f, 0x37, 0x4e, 0x28, 0xb1, 0x84, 0x24,
    0x61, 0x2d, 0x76, 0xeb, 0x65, 0x89, 0xbf, 0xf4, 0x99, 0xa9, 0xe6, 0x5f, 0x80, 0xe4, 0xeb, 0x7b,
    0x34, 0xa4, 0x1d, 0x38, 0x41, 0x14, 0x37, 0x21, 0xbe, 0x38, 0x86, 0xec, 0x40, 0x82, 0xcf, 0x36,
    0xcf, 0xb3, 0xee, 0x1b, 0x05, 0x21, 0x73, 0x43, 0x8a, 0x65, 0xa4, 0x98, 0x77, 0xbd, 0xcc, 0x6e,
    0xbb, 0x3d, 0x14, 0x86, 0x6c, 0xcf, 0x07, 0x0b, 0x2d, 0xfa, 0x9b, 0xde, 0x39, 0xd4, 0xae, 0x4a,
    0x5a, 0x52, 0x9a, 0xd2, 0x27, 0xfe, 0xd5, 0x18, 0x01, 0xb4, 0x27, 0xf1, 0xcb, 0xe1, 0x83, 0xef,
    0x68, 0x62, 0x74, 0xc2, 0x19, 0xd3, 0xcc, 0xf2, 0x94, 0xd9, 0x99, 0x60, 0x85, 0x50, 0x27, 0xe4,
    0x5b, 0x54, 0x14, 0x14, 0x72, 0xe1, 0x74, 0x11, 0x59, 0x60, 0x0b, 0x32, 0xc0, 0x48, 0x6c, 0x93,
    0x0e, 0x62, 0x9e, 0x16, 0x20, 0x3e, 0x0c, 0x54, 0x32, 0x0a, 0x4f, 0x16, 0xd6, 0x3e, 0xdb, 0x2d,
    0x28, 0x6f, 0x93, 0xea, 0x1f, 0x4f, 0x0f, 0xdb, 0x7d, 0xef, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3,
    0x50, 0x30, 0x4e, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x3e, 0x56,
    0xf7, 0xb9, 0x34, 0x1e, 0xcc, 0x2f, 0xf7, 0xc0, 0xd5, 0xab, 0x02, 0xb2, 0x03, 0xf4, 0x1e, 0xfa,
    0x7a, 0x74, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x3e,
    0x56, 0xf7, 0xb9, 0x34, 0x1e, 0xcc, 0x2f, 0xf7, 0xc0, 0xd5, 0xab, 0x02, 0xb2, 0x03, 0xf4, 0x1e,
    0xfa, 0x7a, 0x74, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01,
    0xff, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00,
    0x03, 0x82, 0x02, 0x01, 0x00, 0xa9, 0xd9, 0xe3, 0xc3, 0x43, 0xb6, 0xfd, 0x69, 0xa8, 0xe5, 0xb7,
    0x5b, 0x40, 0x0e, 0xf2, 0x42, 0x38, 0x95, 0xf6, 0xd6, 0x5e, 0xcf, 0xbf, 0xed, 0x2c, 0xa3, 0x37,
    0x2a, 0x84, 0xd2, 0x69, 0x45, 0x92, 0x24, 0x0c, 0xb0, 0xc9, 0x94, 0x9d, 0xbc, 0xf9, 0x03, 0xc6,
    0xf7, 0x08, 0x82, 0x22, 0xac, 0xe9, 0x46, 0x07, 0xb4, 0x88, 0xb3, 0xf2, 0x0f, 0x12, 0x1e, 0x97,
    0x6e, 0xd9, 0xb9, 0xf5, 0x78, 0xab, 0xe4, 0xbd, 0x29, 0xe9, 0x6d, 0x23, 0xc3, 0xcd, 0x5f, 0x63,
    0xb5, 0x10, 0x33, 0xf3, 0xb9, 0x6d, 0x07, 0x2f, 0xe1, 0x88, 0x6c, 0xb5, 0xa2, 0xf0, 0xd4, 0x53,
    0x64, 0x63, 0x8d, 0xe7, 0xc4, 0x58, 0xb5, 0x02, 0xda, 0x98, 0x39, 0xb3, 0xa6, 0xd0, 0xcb, 0xf2,
    0xe5, 0x8e, 0x71, 0xbe, 0x02, 0x07, 0x40, 0x1c, 0x72, 0x92, 0x66, 0x86, 0x4a, 0x26, 0x66, 0x5b,
    0xcc, 0x84, 0x9e, 0x42, 0x0d, 0x82, 0xb4, 0xa3, 0x53, 0xd8, 0xa9, 0x6d, 0x0e, 0xa4, 0x6a, 0x92,
    0x5b, 0x51, 0x9f, 0x16, 0x5f, 0x58, 0xcb, 0x66, 0xce, 0xe0, 0x87, 0x62, 0x5f, 0x0b, 0xf0, 0xd1,
    0x4e, 0xf8, 0x83, 0x84, 0x79, 0x45, 0xc5, 0x69, 0xa7, 0x8e, 0x42, 0x36, 0xb5, 0x10, 0x2f, 0x3f,
    0x6f, 0xa7, 0xb9, 0x1a, 0x3a, 0x9b, 0xce, 0xfb, 0x07, 0x4d, 0x68, 0x62, 0xec, 0xbb, 0xe3, 0x54,
    0x40, 0xb7, 0x18, 0xb8, 0xe6, 0xf8, 0xe4, 0xad, 0xf3, 0xdc, 0x17, 0x2b, 0x67, 0x97, 0x00, 0x78,
    0x95, 0x52, 0x2c, 0x1a, 0x06, 0x81, 0x05, 0x6a, 0x16, 0x41, 0x60, 0x51, 0xf4, 0xd1, 0xb0, 0x6a,
    0xae, 0xe2, 0xaa, 0x63, 0xc7, 0x61, 0x0b, 0x51, 0x2b, 0x1c, 0x5b, 0x1c, 0xdc, 0x48, 0x45, 0x7d,
    0x8b, 0xe3, 0x6b, 0xf6, 0x11, 0xce, 0x6b, 0x5d, 0xbb, 0x1c, 0x96, 0x26, 0x24, 0x61, 0xdf, 0x20,
    0x7c, 0xeb, 0x1e, 0x6d, 0xbb, 0x69, 0x88, 0xea, 0x36, 0xff, 0x6a, 0xbe, 0xfe, 0xd7, 0x60, 0xfb,
    0x80, 0xc7, 0x64, 0xa3, 0x7c, 0x65, 0xef, 0x9c, 0x46, 0xcf, 0xf9, 0xfe, 0x7f, 0x01, 0x93, 0x7d,
    0xd1, 0x6b, 0x9a, 0xcb, 0xc3, 0xb6, 0xaa, 0xa4, 0xd7, 0xf2, 0x1e, 0x15, 0x43, 0xf7, 0xd2, 0x7b,
    0xb3, 0xda, 0x2b, 0xe3, 0x26, 0x56, 0x46, 0x78, 0xf3, 0x59, 0x2b, 0x8f, 0x1f, 0x5c, 0x92, 0xb3,
    0x92, 0xe1, 0x38, 0x0c, 0x9a, 0x63, 0x02, 0xea, 0x07, 0x0e, 0x71, 0x95, 0x4e, 0xd4, 0x67, 0x78,
    0x9c, 0x77, 0x1a, 0xe5, 0x8c, 0x6e, 0x26, 0xe1, 0x71, 0x5d, 0xd3, 0xef, 0x7e, 0xe1, 0xa0, 0x00,
    0xe0, 0xcc, 0x59, 0x39, 0x57, 0xb2, 0xd7, 0x6a, 0x2c, 0xfd, 0x77, 0xce, 0xf6, 0xa6, 0x34, 0x41,
    0x72, 0x41, 0xd2, 0xd4, 0xbb, 0xd0, 0x79, 0xa6, 0x0e, 0x5c, 0x3c, 0xb1, 0x3f, 0xd3, 0x6c, 0xec,
    0x8e, 0x1e, 0x3f, 0xd0, 0x4a, 0xef, 0x14, 0x0a, 0x03, 0x81, 0xda, 0xab, 0xd9, 0x47, 0x1e, 0xca,
    0x59, 0x46, 0x62, 0x1f, 0x69, 0xef, 0x67, 0x2e, 0xe9, 0xef, 0xef, 0xf7, 0x0c, 0xc9, 0xce, 0xbb,
    0x36, 0x49, 0x0d, 0x7b, 0xec, 0x57, 0x15, 0x91, 0xbd, 0x15, 0x23, 0x38, 0x2d, 0x3a, 0xa5, 0x10,
    0x4b, 0x55, 0x7d, 0x4a, 0xb3, 0x4b, 0x78, 0x5b, 0x33, 0xd7, 0xf6, 0xf9, 0x96, 0x69, 0xfe, 0x9d,
    0xd3, 0x6e, 0x52, 0x71, 0x74, 0x16, 0xd6, 0x91, 0x95, 0xe8, 0xfd, 0xe3, 0xdf, 0x43, 0x7b, 0x65,
    0xc9, 0x32, 0xc6, 0x2f, 0x45, 0x97, 0x5a, 0x40, 0xac, 0x00, 0xaf, 0x70, 0x14, 0xf7, 0xeb, 0x41,
    0x2f, 0x79, 0x91, 0xf7, 0xb3, 0x96, 0xc8, 0xe2, 0x7e, 0x2c, 0x8f, 0x07, 0xcb, 0x7a, 0xf1, 0x7a,
    0x59, 0x6c, 0x0e, 0xde, 0x76, 0x68, 0x5a, 0x33, 0x8f, 0x13, 0x70, 0x50, 0x38, 0x21, 0x73, 0xcd,
    0x75, 0xa9, 0x0f, 0x48, 0xab, 0xab
};

static ubyte server_cert[] =
{
    0x30, 0x82, 0x03, 0x8b, 0x30, 0x82, 0x01, 0x73, 0x02, 0x01, 0x01, 0x30, 0x0d, 0x06, 0x09, 0x2a,
    0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30, 0x47, 0x31, 0x0b, 0x30, 0x09,
    0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x49, 0x4e, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55,
    0x04, 0x08, 0x0c, 0x02, 0x4d, 0x48, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c,
    0x04, 0x50, 0x75, 0x6e, 0x65, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x06,
    0x4d, 0x6f, 0x63, 0x61, 0x6e, 0x61, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
    0x02, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x33, 0x31, 0x30, 0x33, 0x31, 0x30, 0x37, 0x32,
    0x34, 0x30, 0x39, 0x5a, 0x17, 0x0d, 0x31, 0x35, 0x31, 0x30, 0x33, 0x31, 0x30, 0x37, 0x32, 0x34,
    0x30, 0x39, 0x5a, 0x30, 0x54, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
    0x49, 0x4e, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x02, 0x4d, 0x48, 0x31,
    0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x04, 0x50, 0x75, 0x6e, 0x65, 0x31, 0x0f,
    0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x06, 0x4d, 0x6f, 0x63, 0x61, 0x6e, 0x61, 0x31,
    0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0f, 0x53, 0x53, 0x48, 0x5f, 0x4f, 0x43,
    0x53, 0x50, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x8d, 0x00, 0x30,
    0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xc0, 0xb4, 0x55, 0x6e, 0x43, 0x83, 0x0a, 0xbd, 0x93, 0xa2,
    0xda, 0xb8, 0x80, 0xb3, 0x85, 0x85, 0x23, 0xda, 0xe3, 0x36, 0x7e, 0x5a, 0xfe, 0x58, 0x54, 0xeb,
    0xe1, 0xdc, 0x4c, 0xe5, 0x90, 0x23, 0x18, 0xc6, 0x4a, 0x60, 0xf2, 0x7e, 0xef, 0x42, 0x9f, 0x0a,
    0xe5, 0x65, 0x61, 0x63, 0x3f, 0x97, 0x76, 0x0b, 0x46, 0x58, 0x31, 0x52, 0xf2, 0x90, 0xc0, 0x50,
    0x81, 0xcb, 0x54, 0x9b, 0xb0, 0x39, 0x2a, 0xde, 0x48, 0x43, 0xee, 0x2e, 0x70, 0x49, 0xe1, 0xf3,
    0xf1, 0x30, 0x19, 0x07, 0x08, 0x15, 0x09, 0xec, 0xc9, 0x77, 0xdf, 0x3c, 0x56, 0x90, 0x09, 0x65,
    0x92, 0xad, 0xe4, 0x3f, 0x02, 0x3a, 0xa6, 0x57, 0x11, 0x38, 0xa2, 0x65, 0xbc, 0xaa, 0xab, 0xd8,
    0xcf, 0x70, 0xd5, 0x61, 0xb7, 0xac, 0xcc, 0x53, 0x2a, 0xfc, 0xf6, 0xba, 0x9c, 0xa8, 0x6a, 0xd0,
    0xaa, 0xc9, 0x64, 0x2d, 0x62, 0xf3, 0x02, 0x03, 0x01, 0x00, 0x01, 0x30, 0x0d, 0x06, 0x09, 0x2a,
    0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x03, 0x82, 0x02, 0x01, 0x00, 0xa1,
    0xb4, 0x56, 0x8f, 0x07, 0xab, 0xbc, 0xe8, 0x5f, 0x14, 0x63, 0x55, 0x66, 0x53, 0x90, 0x58, 0x0d,
    0x1e, 0xbe, 0xec, 0x43, 0x19, 0x69, 0x36, 0x71, 0x6b, 0x41, 0x29, 0x82, 0x9a, 0x2a, 0xf9, 0xe4,
    0x75, 0xe2, 0xb2, 0x1a, 0x19, 0x2a, 0x91, 0xe9, 0xc9, 0xf0, 0x84, 0x02, 0xd0, 0xa5, 0x98, 0x2f,
    0x24, 0x31, 0x96, 0x91, 0x72, 0x7a, 0x15, 0x64, 0x70, 0x16, 0x3d, 0x6b, 0xd5, 0x4a, 0xee, 0x49,
    0xd6, 0xe9, 0xae, 0xd9, 0xcb, 0x36, 0x39, 0x9b, 0xe5, 0x4c, 0x1e, 0x1c, 0x51, 0xfe, 0x63, 0x36,
    0x6c, 0x68, 0xc2, 0x59, 0xd7, 0x87, 0x5b, 0x18, 0xdc, 0xc9, 0xc7, 0xb4, 0x17, 0xfe, 0x34, 0x9f,
    0x62, 0xa1, 0x7d, 0x08, 0x77, 0x87, 0xe2, 0x4d, 0xcc, 0x92, 0x6a, 0x87, 0x20, 0x32, 0xdb, 0x1e,
    0xda, 0x18, 0x3b, 0xb1, 0x44, 0x18, 0x13, 0xb9, 0x3a, 0x43, 0xbb, 0x5f, 0x43, 0x43, 0x33, 0xe6,
    0x36, 0xc6, 0x3e, 0x6d, 0xd7, 0xe1, 0xce, 0x0b, 0x5d, 0x83, 0xd9, 0xf4, 0x77, 0x1f, 0x98, 0x05,
    0xac, 0xd0, 0x49, 0xa3, 0x50, 0x34, 0x51, 0x7d, 0x75, 0xd1, 0x68, 0x8e, 0x25, 0xbe, 0x28, 0x25,
    0xc7, 0xd6, 0xda, 0x9e, 0x1f, 0x9c, 0x5f, 0x87, 0xfa, 0xf6, 0x0a, 0xa0, 0x1d, 0xe1, 0xd5, 0x38,
    0xcf, 0x77, 0x61, 0x87, 0x1e, 0xd0, 0x2f, 0x3a, 0xbb, 0xd6, 0x71, 0xfb, 0x16, 0xc2, 0x12, 0x73,
    0x73, 0x6a, 0x68, 0x55, 0xdc, 0x58, 0x64, 0xaa, 0x55, 0xc3, 0x58, 0xaa, 0xc3, 0x1f, 0x2d, 0xf2,
    0x8c, 0xf3, 0xfc, 0xd8, 0xf9, 0x53, 0x51, 0xd1, 0x9a, 0xc3, 0x83, 0x70, 0x29, 0x7b, 0xbf, 0xdb,
    0xd6, 0x7b, 0xa2, 0x5d, 0x5a, 0x82, 0x64, 0x4c, 0xae, 0xf7, 0x99, 0x96, 0x83, 0x0f, 0x2a, 0xdd,
    0xdb, 0x3d, 0xe7, 0xb1, 0xec, 0x12, 0x9a, 0x65, 0x78, 0xbf, 0xb0, 0x1f, 0x5a, 0xe1, 0xf9, 0x68,
    0x3d, 0xb5, 0x32, 0xf4, 0xc8, 0x89, 0x43, 0x84, 0x3a, 0xed, 0x3f, 0xd4, 0xfc, 0x68, 0x54, 0x61,
    0xe6, 0xf0, 0xc1, 0xc6, 0xd1, 0x67, 0x14, 0xf8, 0x9a, 0x6f, 0x02, 0x56, 0x36, 0x14, 0x6e, 0x20,
    0x33, 0x27, 0x29, 0x2f, 0x42, 0xa9, 0xf4, 0x9c, 0xb3, 0x1b, 0xc8, 0x28, 0x49, 0xb4, 0x69, 0x05,
    0xf4, 0xfe, 0x2c, 0x05, 0xca, 0x09, 0x60, 0xf1, 0x6d, 0x27, 0xa6, 0xbb, 0xed, 0x12, 0x87, 0x9e,
    0x69, 0xce, 0x16, 0xd4, 0x29, 0x41, 0x46, 0x0f, 0x88, 0x8c, 0xd4, 0xb5, 0x5a, 0x75, 0xdf, 0x27,
    0xc1, 0x27, 0xe2, 0x26, 0xd3, 0x70, 0x3c, 0x48, 0x85, 0xa0, 0x5b, 0x39, 0x18, 0x18, 0x89, 0xc5,
    0xc9, 0x0e, 0xf4, 0xa6, 0xa4, 0x01, 0xd5, 0x7d, 0x21, 0x07, 0xb4, 0xb2, 0xa8, 0x10, 0x6c, 0xed,
    0x57, 0xc5, 0x73, 0x2a, 0x0f, 0x2b, 0x50, 0x7b, 0xde, 0x85, 0xd6, 0xbd, 0x18, 0xd3, 0xc8, 0xd6,
    0x60, 0x8a, 0x20, 0x2e, 0x58, 0xee, 0x1f, 0x64, 0x0c, 0x77, 0xf9, 0x6a, 0x11, 0x58, 0x46, 0x0f,
    0xdf, 0x8a, 0x77, 0xc6, 0xfb, 0xb2, 0x03, 0x69, 0x07, 0xed, 0x2b, 0xfa, 0x53, 0xc8, 0xae, 0x2b,
    0xf8, 0x23, 0xd9, 0x27, 0xcf, 0x44, 0x4d, 0x84, 0xb3, 0x7b, 0xa4, 0x2d, 0x81, 0x56, 0x99, 0x7d,
    0x67, 0x07, 0x2d, 0xaf, 0x74, 0xd6, 0xc5, 0xad, 0xab, 0x13, 0x00, 0x99, 0x7d, 0x0e, 0xbd, 0x58,
    0x2a, 0x28, 0xcc, 0x29, 0x05, 0xf8, 0xcb, 0x69, 0x54, 0xd1, 0x30, 0xdb, 0x48, 0x2b, 0xe8, 0x25,
    0xf6, 0x5b, 0xb7, 0x5f, 0x4c, 0x74, 0xba, 0x5d, 0x4d, 0xf7, 0xbe, 0x01, 0x33, 0x12, 0xed, 0xc2,
    0x38, 0x88, 0x81, 0xe2, 0x91, 0x7c, 0x70, 0xfc, 0x21, 0x5c, 0xd1, 0x37, 0x7b, 0x6e, 0xfb, 0xc2,
    0x70, 0x01, 0xd0, 0xbb, 0x4f, 0xed, 0x7e, 0xa4, 0xdb, 0x05, 0x95, 0x48, 0xef, 0x68, 0x3d, 0x3d
};

static ubyte privkey_pem[] =
{
    0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x52, 0x53, 0x41, 0x20, 0x50,
    0x52, 0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4b, 0x45, 0x59, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a,
    0x4d, 0x49, 0x49, 0x43, 0x58, 0x41, 0x49, 0x42, 0x41, 0x41, 0x4b, 0x42, 0x67, 0x51, 0x44, 0x41,
    0x74, 0x46, 0x56, 0x75, 0x51, 0x34, 0x4d, 0x4b, 0x76, 0x5a, 0x4f, 0x69, 0x32, 0x72, 0x69, 0x41,
    0x73, 0x34, 0x57, 0x46, 0x49, 0x39, 0x72, 0x6a, 0x4e, 0x6e, 0x35, 0x61, 0x2f, 0x6c, 0x68, 0x55,
    0x36, 0x2b, 0x48, 0x63, 0x54, 0x4f, 0x57, 0x51, 0x49, 0x78, 0x6a, 0x47, 0x53, 0x6d, 0x44, 0x79,
    0x0a, 0x66, 0x75, 0x39, 0x43, 0x6e, 0x77, 0x72, 0x6c, 0x5a, 0x57, 0x46, 0x6a, 0x50, 0x35, 0x64,
    0x32, 0x43, 0x30, 0x5a, 0x59, 0x4d, 0x56, 0x4c, 0x79, 0x6b, 0x4d, 0x42, 0x51, 0x67, 0x63, 0x74,
    0x55, 0x6d, 0x37, 0x41, 0x35, 0x4b, 0x74, 0x35, 0x49, 0x51, 0x2b, 0x34, 0x75, 0x63, 0x45, 0x6e,
    0x68, 0x38, 0x2f, 0x45, 0x77, 0x47, 0x51, 0x63, 0x49, 0x46, 0x51, 0x6e, 0x73, 0x79, 0x58, 0x66,
    0x66, 0x0a, 0x50, 0x46, 0x61, 0x51, 0x43, 0x57, 0x57, 0x53, 0x72, 0x65, 0x51, 0x2f, 0x41, 0x6a,
    0x71, 0x6d, 0x56, 0x78, 0x45, 0x34, 0x6f, 0x6d, 0x57, 0x38, 0x71, 0x71, 0x76, 0x59, 0x7a, 0x33,
    0x44, 0x56, 0x59, 0x62, 0x65, 0x73, 0x7a, 0x46, 0x4d, 0x71, 0x2f, 0x50, 0x61, 0x36, 0x6e, 0x4b,
    0x68, 0x71, 0x30, 0x4b, 0x72, 0x4a, 0x5a, 0x43, 0x31, 0x69, 0x38, 0x77, 0x49, 0x44, 0x41, 0x51,
    0x41, 0x42, 0x0a, 0x41, 0x6f, 0x47, 0x41, 0x47, 0x71, 0x6e, 0x5a, 0x47, 0x45, 0x53, 0x6e, 0x49,
    0x52, 0x6c, 0x53, 0x45, 0x44, 0x71, 0x4c, 0x52, 0x4f, 0x4f, 0x53, 0x47, 0x66, 0x58, 0x34, 0x46,
    0x33, 0x41, 0x32, 0x30, 0x34, 0x68, 0x56, 0x32, 0x49, 0x6f, 0x36, 0x32, 0x69, 0x79, 0x5a, 0x70,
    0x76, 0x50, 0x30, 0x50, 0x5a, 0x75, 0x56, 0x42, 0x6e, 0x69, 0x68, 0x79, 0x6d, 0x6f, 0x50, 0x4b,
    0x2b, 0x5a, 0x33, 0x0a, 0x4c, 0x7a, 0x42, 0x68, 0x57, 0x4b, 0x66, 0x2b, 0x74, 0x37, 0x30, 0x37,
    0x61, 0x4f, 0x79, 0x32, 0x62, 0x32, 0x31, 0x47, 0x49, 0x52, 0x4c, 0x5a, 0x73, 0x78, 0x47, 0x32,
    0x45, 0x49, 0x69, 0x35, 0x69, 0x52, 0x33, 0x58, 0x6d, 0x73, 0x41, 0x30, 0x75, 0x30, 0x42, 0x59,
    0x50, 0x54, 0x4d, 0x61, 0x44, 0x75, 0x2f, 0x6f, 0x4f, 0x44, 0x64, 0x36, 0x49, 0x52, 0x44, 0x2b,
    0x52, 0x64, 0x6d, 0x74, 0x0a, 0x4e, 0x62, 0x43, 0x2f, 0x6d, 0x47, 0x74, 0x4f, 0x58, 0x2f, 0x6e,
    0x53, 0x4c, 0x65, 0x77, 0x34, 0x57, 0x7a, 0x62, 0x36, 0x67, 0x59, 0x50, 0x36, 0x48, 0x71, 0x51,
    0x61, 0x52, 0x37, 0x59, 0x55, 0x5a, 0x6b, 0x37, 0x75, 0x30, 0x30, 0x34, 0x4f, 0x5a, 0x56, 0x38,
    0x2b, 0x36, 0x71, 0x45, 0x43, 0x51, 0x51, 0x44, 0x72, 0x56, 0x51, 0x4b, 0x34, 0x56, 0x77, 0x48,
    0x74, 0x48, 0x7a, 0x2f, 0x6f, 0x0a, 0x69, 0x62, 0x71, 0x73, 0x56, 0x53, 0x4c, 0x45, 0x79, 0x78,
    0x56, 0x63, 0x78, 0x51, 0x4b, 0x71, 0x4d, 0x6b, 0x43, 0x53, 0x59, 0x6e, 0x70, 0x66, 0x73, 0x57,
    0x44, 0x76, 0x75, 0x4f, 0x54, 0x32, 0x47, 0x38, 0x41, 0x2b, 0x73, 0x46, 0x4c, 0x49, 0x33, 0x55,
    0x68, 0x75, 0x6b, 0x55, 0x68, 0x44, 0x65, 0x7a, 0x36, 0x34, 0x30, 0x79, 0x73, 0x42, 0x54, 0x48,
    0x34, 0x77, 0x51, 0x79, 0x66, 0x62, 0x0a, 0x4b, 0x62, 0x4b, 0x32, 0x42, 0x6d, 0x6f, 0x6e, 0x41,
    0x6b, 0x45, 0x41, 0x30, 0x61, 0x44, 0x73, 0x4a, 0x4b, 0x68, 0x6d, 0x50, 0x41, 0x44, 0x79, 0x63,
    0x38, 0x4c, 0x55, 0x65, 0x67, 0x6a, 0x4e, 0x32, 0x41, 0x42, 0x7a, 0x46, 0x35, 0x50, 0x4e, 0x79,
    0x55, 0x75, 0x30, 0x71, 0x34, 0x70, 0x70, 0x52, 0x68, 0x67, 0x38, 0x4d, 0x6a, 0x50, 0x4e, 0x38,
    0x63, 0x4d, 0x67, 0x54, 0x59, 0x4f, 0x37, 0x0a, 0x36, 0x52, 0x55, 0x6f, 0x5a, 0x4d, 0x62, 0x72,
    0x63, 0x2f, 0x54, 0x44, 0x43, 0x36, 0x36, 0x6b, 0x6e, 0x65, 0x38, 0x34, 0x31, 0x43, 0x51, 0x6e,
    0x59, 0x57, 0x6d, 0x41, 0x35, 0x56, 0x30, 0x38, 0x56, 0x51, 0x4a, 0x41, 0x5a, 0x65, 0x6c, 0x4a,
    0x70, 0x55, 0x54, 0x67, 0x71, 0x36, 0x78, 0x31, 0x77, 0x36, 0x45, 0x70, 0x65, 0x77, 0x6e, 0x66,
    0x5a, 0x62, 0x50, 0x41, 0x79, 0x34, 0x7a, 0x78, 0x0a, 0x71, 0x33, 0x7a, 0x5a, 0x6f, 0x38, 0x73,
    0x4c, 0x7a, 0x62, 0x63, 0x47, 0x45, 0x4b, 0x70, 0x55, 0x56, 0x52, 0x51, 0x4e, 0x65, 0x39, 0x68,
    0x6c, 0x38, 0x57, 0x43, 0x4b, 0x78, 0x6e, 0x38, 0x5a, 0x2b, 0x55, 0x63, 0x39, 0x45, 0x56, 0x4d,
    0x35, 0x63, 0x33, 0x57, 0x4a, 0x7a, 0x43, 0x4b, 0x34, 0x39, 0x74, 0x73, 0x6d, 0x37, 0x6c, 0x62,
    0x32, 0x7a, 0x77, 0x4a, 0x42, 0x41, 0x49, 0x2f, 0x65, 0x0a, 0x4d, 0x33, 0x4d, 0x4e, 0x4a, 0x2b,
    0x7a, 0x79, 0x63, 0x58, 0x4e, 0x46, 0x4f, 0x58, 0x48, 0x76, 0x62, 0x4f, 0x5a, 0x62, 0x6d, 0x4b,
    0x47, 0x4c, 0x7a, 0x4f, 0x58, 0x6a, 0x30, 0x55, 0x45, 0x52, 0x6f, 0x79, 0x4a, 0x36, 0x4b, 0x34,
    0x59, 0x41, 0x79, 0x38, 0x79, 0x71, 0x73, 0x42, 0x62, 0x43, 0x33, 0x45, 0x6f, 0x68, 0x50, 0x54,
    0x47, 0x38, 0x32, 0x34, 0x63, 0x66, 0x61, 0x6d, 0x55, 0x77, 0x0a, 0x48, 0x4d, 0x5a, 0x50, 0x6b,
    0x64, 0x37, 0x32, 0x57, 0x52, 0x69, 0x66, 0x77, 0x64, 0x69, 0x6f, 0x58, 0x6d, 0x6b, 0x43, 0x51,
    0x47, 0x77, 0x70, 0x41, 0x44, 0x69, 0x6e, 0x4c, 0x58, 0x75, 0x79, 0x31, 0x47, 0x74, 0x44, 0x62,
    0x6b, 0x5a, 0x4a, 0x48, 0x32, 0x35, 0x67, 0x37, 0x76, 0x45, 0x32, 0x63, 0x38, 0x75, 0x30, 0x36,
    0x73, 0x76, 0x6a, 0x4e, 0x65, 0x78, 0x75, 0x31, 0x34, 0x56, 0x50, 0x0a, 0x74, 0x35, 0x71, 0x58,
    0x46, 0x75, 0x59, 0x65, 0x6e, 0x77, 0x63, 0x55, 0x6c, 0x72, 0x45, 0x5a, 0x47, 0x6b, 0x67, 0x61,
    0x74, 0x72, 0x65, 0x67, 0x30, 0x72, 0x6f, 0x33, 0x70, 0x5a, 0x49, 0x64, 0x45, 0x55, 0x6e, 0x38,
    0x53, 0x70, 0x76, 0x51, 0x44, 0x4b, 0x6b, 0x3d, 0x0a, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x45, 0x4e,
    0x44, 0x20, 0x52, 0x53, 0x41, 0x20, 0x50, 0x52, 0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4b, 0x45,
    0x59, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a, 0x0a
};
#endif

#ifdef __ENABLE_MOCANA_TAP__

static sbyte4
SSH_EXAMPLE_getTapContext(TAP_Context **ppTapContext,
                          TAP_EntityCredentialList **ppTapEntityCred,
                          TAP_CredentialList **ppTapKeyCred,
                          void *pKey, TapOperation op, ubyte getContext)
{
    MSTATUS status = OK;
    TAP_ErrorContext *pErrContext = NULL;

    if (pKey == NULL)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    if (getContext)
    {
        /* Initialize context on first module */
        status = TAP_initContext(&(g_moduleList.pModuleList[0]), g_pTapEntityCred,
                                    NULL, ppTapContext, pErrContext);
        if (OK != status)
        {
            printf("TAP_initContext : %d\n", status);
            goto exit;
        }

        *ppTapEntityCred = g_pTapEntityCred;
        *ppTapKeyCred    = g_pTapKeyCred;
    }
    else
    {
        /* Destroy the TAP context */
        if (OK > (status = TAP_uninitContext(ppTapContext, pErrContext)))
        {
            DEBUG_ERROR(DEBUG_SSH_EXAMPLE, (sbyte*)"SSL_EXAMPLE: TAP_uninitContext failed with status: ", status);
        }
    }

exit:
    return status;
}


static MSTATUS
SSH_EXAMPLE_InitializeTapContext(ubyte *pTpm2ConfigFile, TAP_Context **ppTapCtx,
                                 TAP_EntityCredentialList **ppTapEntityCred,
                                 TAP_CredentialList **ppTapKeyCred)
{
    MSTATUS status = OK;
    TAP_ConfigInfoList configInfoList = { 0, };
    TAP_ErrorContext *pErrContext = NULL;
    TAP_EntityCredentialList *pEntityCredentials = { 0 };
    TAP_CredentialList *pKeyCredentials = { 0 };
#ifdef __ENABLE_MOCANA_TAP_REMOTE__
    TAP_ConnectionInfo connInfo = { 0 };
#endif

    if (ppTapCtx == NULL)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#if (!defined(__ENABLE_MOCANA_TAP_REMOTE__))
    status = MOC_CALLOC((void **)&(configInfoList.pConfig), 1, sizeof(TAP_ConfigInfo));
    if (OK != status)
    {
        printf("Failed to allocate memory, status = %d", status);
        goto exit;
    }

    status = TAP_readConfigFile((const char *)pTpm2ConfigFile, &configInfoList.pConfig[0].configInfo, 0);
    if (OK != status)
    {
        printf("Failed to read config file, status = %d", status);
        goto exit;
    }

    configInfoList.count = 1;
    configInfoList.pConfig[0].provider = TAP_PROVIDER_TPM2;
#endif

    status = TAP_init(&configInfoList, pErrContext);
    if (OK != status)
    {
        printf("TAP_init : %d", status);
        goto exit;
    }

#if (defined(__ENABLE_MOCANA_TAP_REMOTE__))

    connInfo.serverName.bufferLen = MOC_STRLEN((char *)taps_ServerName)+1;
    status = MOC_CALLOC ((void **)&(connInfo.serverName.pBuffer), 1, connInfo.serverName.bufferLen);
    if (OK != status)
    goto exit;

    status = MOC_MEMCPY ((void *)(connInfo.serverName.pBuffer), (void *)taps_ServerName, MOC_STRLEN(taps_ServerName));
    if (OK != status)
    goto exit;

    connInfo.serverPort = taps_ServerPort;

    status = TAP_getModuleList(&connInfo, TAP_PROVIDER_TPM2, NULL,
                               &g_moduleList, pErrContext);
#else
    status = TAP_getModuleList(NULL, TAP_PROVIDER_TPM2, NULL,
                               &g_moduleList, pErrContext);
#endif
    if (OK != status)
    {
        printf("TAP_getModuleList : %d \n", status);
        goto exit;
    }
    if (0 == g_moduleList.numModules)
    {
        printf("No TPM2 modules found\n");
        goto exit;
    }

    /* For local TAP, parse the config file and get the Entity Credentials */
#if (!defined(__ENABLE_MOCANA_TAP_REMOTE__))
    status = TAP_getModuleCredentials(&(g_moduleList.pModuleList[0]),
                                      pTpm2ConfigFile, 0,
                                      &pEntityCredentials,
                                      pErrContext);

    if (OK != status)
    {
        printf("Failed to get credentials from Credential configuration file %d", status);
        goto exit;
    }
#endif

    *ppTapEntityCred = pEntityCredentials;
    *ppTapKeyCred    = pKeyCredentials;

    /* Free config info */
    if (NULL != configInfoList.pConfig)
    {
        status = TAP_UTILS_freeConfigInfoList(&configInfoList);
        if (OK != status)
            printf("TAP_UTILS_freeConfigInfoList : %d\n", status);
    }

exit:
#if (defined(__ENABLE_MOCANA_TAP_REMOTE__))
    if (connInfo.serverName.pBuffer != NULL)
    {
        MOC_FREE((void**)&connInfo.serverName.pBuffer);
    }
#endif
    return status;

}
#endif


static sbyte4
SSH_EXAMPLE_reKeyFunction(sbyte4 connectionInstance,
                                 intBoolean initiatedByRemote)
{
 printf("SSH_EXAMPLE_reKeyFunction: ... initiatedByRemote = %d\n", initiatedByRemote);
 return OK;

}  /* SSH_EXAMPLE_reKeyFunction */

/*------------------------------------------------------------------*/

static sbyte4
SSH_EXAMPLE_authPasswordFunction(sbyte4 connectionInstance,
                                 const ubyte *pUser,     ubyte4 userLength,
                                 const ubyte *pPassword, ubyte4 passwordLength)
{
    MOC_UNUSED(connectionInstance);

    /* we're going to assume everyone has a username and password */
    /* we do not force you to assume this policy */
    if ((0 == userLength) || (0 == passwordLength))
        return 0;

    /* always check the lengths first, there may not be a username or password */
    if (userLength != MOC_STRLEN(ssh_UserName))
        return 0;

    if (passwordLength != MOC_STRLEN(ssh_Password))
        return 0;

    if ((0 != memcmp(pUser,     ssh_UserName, userLength)) ||
        (0 != memcmp(pPassword, ssh_Password, passwordLength)))
    {
        return 0;
    }

#ifdef __ENABLE_MOCANA_SSH_FTP_SERVER__
    SSH_sftpSetMemberOfGroups(connectionInstance, 0);
    SSH_sftpSetHomeDirectory(connectionInstance, (sbyte *)"/");
#endif

    /* return authentication succeeded */
    return 1;

} /* SSH_EXAMPLE_authPasswordFunction */


/*------------------------------------------------------------------*/

static sbyte4
SSH_EXAMPLE_keyboardInteractiveAuth(sbyte4                  connectionInstance,
                                    const ubyte*            pUser,
                                    ubyte4                  userLength,
                                    keyIntInfoResp*         pAuthResponse,    /* if NULL, an initial request message */
                                    keyIntInfoReq*          pAuthRequest,
                                    sbyte4*                 pAuthState)
{
    sbyte4 prevState = pAuthRequest->cookie;
    sbyte4 result    = AUTH_MORE;

    if ((NULL == pAuthResponse) || (EXAMPLE_PASSWORD == pAuthRequest->cookie))
    {
        sbyte4 isAuth    = 0;

        /* you can use the connectionInstance cookie, if you prefer */
        /* use the cookie, however you please */
        pAuthRequest->cookie = EXAMPLE_PASSWORD;

        /* if pAuthResponse is null, assume inital log on state */
        if (0 != pAuthResponse)
        {
#if defined(__ENABLE_MOCANA_EXAMPLE_SSH_RADIUS_PASSWORD_AUTH__)
            isAuth = SSH_RADIUS_EXAMPLE_authPasswordFunction(connectionInstance,
#else
            isAuth = SSH_EXAMPLE_authPasswordFunction(connectionInstance,
#endif
                                                      pUser, userLength,
                                                      pAuthResponse->responses[0]->pResponse,        /* password */
                                                      pAuthResponse->responses[0]->responseLen);     /* password length */

            if (1 == isAuth)
            {
                if (TRUE == ssh_disablePasswordExpiryTest)
                {
                    pAuthRequest->cookie = EXAMPLE_PASSWORD_DONE;
                }
                else
                {
                    /* fake password expiration simulation */
                    pAuthRequest->cookie = EXAMPLE_CHANGE_PASSWORD;
                }
            }
            else
            {
                result = AUTH_FAIL_MORE;
            }
        }

        if (0 == isAuth)
        {
            /* build info request */
            pAuthRequest->pName           = m_exampleMessages[0];           /* "Password Authentication" */
            pAuthRequest->nameLen         = strlen((const char *)m_exampleMessages[0]);
            pAuthRequest->pInstruction    = 0;
            pAuthRequest->instructionLen  = 0;
            pAuthRequest->numPrompts      = 1;
            pAuthRequest->prompts[0]      = &m_passwordPrompts[0];
        }
    }

    if (EXAMPLE_CHANGE_PASSWORD == pAuthRequest->cookie)
    {
        sbyte4 isPasswordChanged = 0;

        if (EXAMPLE_CHANGE_PASSWORD == prevState)
        {
            /* before reaching this handler, the engine verifies */
            /* that we receive the expected number of responses */
            if ((0 < pAuthResponse->responses[0]->responseLen) &&
                (pAuthResponse->responses[0]->responseLen == pAuthResponse->responses[1]->responseLen) &&
                (0 == memcmp((sbyte *)pAuthResponse->responses[0]->pResponse,
                             (sbyte *)pAuthResponse->responses[1]->pResponse,
                             pAuthResponse->responses[0]->responseLen)))
            {
                /* new passwords match, fake password change completed */
                isPasswordChanged = 1;
            }
        }

        if (0 == isPasswordChanged)
        {
            /* build info request */
            pAuthRequest->pName           = m_exampleMessages[1];           /* "Password Expired" */
            pAuthRequest->nameLen         = strlen((const char *)m_exampleMessages[1]);
            pAuthRequest->pInstruction    = m_exampleMessages[2];           /* "Your password has expired." */
            pAuthRequest->instructionLen  = strlen((const char *)m_exampleMessages[2]);
            pAuthRequest->numPrompts      = 2;
            pAuthRequest->prompts[0]      = &m_passwordPrompts[1];
            pAuthRequest->prompts[1]      = &m_passwordPrompts[2];
        }
        else
        {
            /* dynamic string example */
            sbyte*           pString;
            sbyte            buf[2];
            ubyte4    index;

            /* note: see SSH_EXAMPLE_releaseKeyboardInteractiveRequest() example */
            if (0 == (pString = MALLOC(strlen((const char *)m_exampleMessages[4]) + userLength + 2)))
                return -1;  /* Note: negative returns are handled as an error by the caller */

            /* "Password successfully changed for <user>." */
            buf[1] = *pString = '\0';
            strcat((char *)pString, (const char *)m_exampleMessages[4]);

            /* Note: user string is not terminated, therefore byte copy */
            for (index = 0; index < userLength; index++)
            {
                buf[0] = pUser[index];
                strcat((char *)pString, (const char *)buf);
            }

            strcat((char *)pString, ".");

            /* build info request */
            pAuthRequest->pName           = m_exampleMessages[3];           /* "Password changed" */
            pAuthRequest->nameLen         = strlen((const char *)m_exampleMessages[3]);
            pAuthRequest->pInstruction    = pString;                        /* "Password successfully changed for user23." */
            pAuthRequest->instructionLen  = strlen((const char *)pString);
            pAuthRequest->numPrompts      = 0;

            /* Note: if we returned AUTH_PASS, there would be no message indicating password */
            /* change was successful.  */
            pAuthRequest->cookie  = EXAMPLE_DONE;
        }
    }
    else if (EXAMPLE_PASSWORD_DONE == pAuthRequest->cookie)
    {
        /* build info request */
        pAuthRequest->pName = NULL;
        pAuthRequest->nameLen = 0;
        pAuthRequest->pInstruction = NULL;
        pAuthRequest->instructionLen = 0;
        pAuthRequest->numPrompts = 0;
        pAuthRequest->cookie = EXAMPLE_DONE;
    }

    if (EXAMPLE_DONE == prevState)
    {
        /* let the server know authentication was successful */
        result = AUTH_PASS;
    }

    *pAuthState = result;
    return OK;      /* Note: negative returns are handled as an error by the caller */

} /* SSH_EXAMPLE_keyboardInteractiveAuth */


/*------------------------------------------------------------------*/

static sbyte4
SSH_EXAMPLE_releaseKeyboardInteractiveRequest(sbyte4 connectionInstance,
                                              keyIntInfoReq* pAuthRequest)
{
    MOC_UNUSED(connectionInstance);

    /*!-!-!-! if necessary, free strings here */
    if ((EXAMPLE_DONE == pAuthRequest->cookie) && (NULL != pAuthRequest->pInstruction))
    {
        FREE(pAuthRequest->pInstruction);
        pAuthRequest->pInstruction = NULL;     /* prevent a double-free */
    }

    return 0;            /* Note: negative returns are handled as an error by the caller */
}


/*------------------------------------------------------------------*/

#ifdef __DISABLE_MOCANA_FILE_SYSTEM_HELPER__
static char dsaPublicKeyPart[] =
{
    0x00, 0x00, 0x00, 0x5d, 0x00, 0xcb, 0x24, 0xb0, 0x05, 0xff, 0x77, 0xb7, 0x07, 0xff, 0xf7, 0xf7,
    0x48, 0x7f, 0xf7, 0xf7, 0x67, 0xfe, 0xff, 0xff, 0x7f, 0xde, 0xee, 0xff, 0x7f, 0xdf, 0xae, 0xfb,
    0x3d, 0xff, 0xff, 0xff, 0x1f, 0xff, 0xf7, 0xf7, 0x47, 0xfe, 0xf7, 0xf7, 0x67, 0xde, 0xee, 0xf7,
    0xff, 0xd6, 0xae, 0xf7, 0xbf, 0xdb, 0xac, 0xf4, 0xbf, 0xff, 0x77, 0xb7, 0x07, 0xfe, 0xf7, 0xf7,
    0x47, 0xde, 0xc6, 0xf7, 0x67, 0xd6, 0xae, 0xf7, 0xbf, 0x12, 0xac, 0xf4, 0xbe, 0x86, 0x82, 0xcb,
    0x83, 0x14, 0x2a, 0x03, 0x0d, 0x05, 0xd1, 0xeb, 0x72, 0xcc, 0xa4, 0x01, 0xc2, 0xa7, 0x4c, 0x95,
    0x6b, 0x00, 0x00, 0x00, 0x15, 0x00, 0xf7, 0xc3, 0x38, 0x9a, 0x21, 0xa5, 0xc8, 0xf3, 0xa7, 0x2a,
    0xef, 0x2f, 0x95, 0x53, 0xdf, 0xb1, 0x50, 0x3c, 0x42, 0xab, 0x00, 0x00, 0x00, 0x5d, 0x00, 0x8c,
    0x62, 0x7b, 0x59, 0x1f, 0xff, 0xf8, 0xcb, 0x9c, 0x5e, 0xbc, 0xe1, 0xc5, 0x06, 0x20, 0xb8, 0x7d,
    0xb8, 0x73, 0x8c, 0x30, 0x23, 0xab, 0x0f, 0xb6, 0x1a, 0x1c, 0x58, 0x5f, 0xe6, 0x00, 0x6b, 0xdc,
    0xa7, 0x50, 0xa2, 0xcd, 0xda, 0x77, 0x7b, 0x7a, 0x9e, 0xc2, 0xb6, 0xbf, 0x64, 0x65, 0xaf, 0x04,
    0x09, 0xdf, 0x26, 0x73, 0xe4, 0x6a, 0x13, 0xfb, 0x9f, 0xed, 0x32, 0x63, 0x3e, 0xd0, 0xd4, 0x72,
    0x8b, 0xd7, 0x1e, 0x3d, 0x98, 0x93, 0x2d, 0x00, 0x10, 0x81, 0xbd, 0xb3, 0xc9, 0xac, 0x95, 0xb5,
    0xd2, 0x94, 0xc2, 0x4d, 0x8b, 0xfa, 0x5d, 0xd0, 0x59, 0xb6, 0x98, 0x00, 0x00, 0x00, 0x5d, 0x00,
    0xa2, 0x55, 0x78, 0xbf, 0xd7, 0x2d, 0xd8, 0xd0, 0x9b, 0x41, 0x97, 0x2a, 0x2c, 0x7f, 0xce, 0x8d,
    0xb1, 0xac, 0xd3, 0x1c, 0x76, 0x88, 0xed, 0xa3, 0x99, 0x70, 0xa4, 0xb4, 0xe0, 0xf2, 0x48, 0xe1,
    0x5c, 0x2f, 0xc2, 0xb7, 0xb7, 0x29, 0xaf, 0x58, 0xa8, 0x48, 0x6e, 0xb2, 0x08, 0x40, 0x27, 0xb0,
    0xa4, 0x46, 0xe3, 0xb0, 0x6b, 0xd3, 0x11, 0x9c, 0x99, 0x28, 0xf1, 0x7f, 0x6b, 0xc9, 0x4f, 0xa8,
    0x93, 0xe7, 0x2c, 0x60, 0x02, 0x06, 0x11, 0xf7, 0xa3, 0xf3, 0x71, 0xab, 0xcf, 0x4a, 0xe5, 0xcd,
    0x6d, 0xe4, 0x7b, 0x5d, 0x37, 0x80, 0x00, 0x9b, 0x6a, 0xa6, 0x96, 0xa5
};

static char dsaPrivateKeyPart[] =
{
    0x00, 0x00, 0x00, 0x15, 0x00, 0xef, 0x28, 0xad, 0xcf, 0x99, 0x2f, 0xed, 0xd7, 0x5c, 0x54, 0xee,
    0x2e, 0x2f, 0x0f, 0xa7, 0x6d, 0xeb, 0xa0, 0xf9, 0x49
};

static sbyte4
SSH_EXAMPLE_sshCertStoreInitFS(certStorePtr *ppNewStore)
{
    ubyte*  pKeyBlob;
    ubyte4  keyBlobLength;
    sbyte4  index;
    sbyte4  status;

    if (OK > (status = CERT_STORE_createStore(ppNewStore)))
        goto exit;

    pKeyBlob      = NULL;
    keyBlobLength = 0;

    DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, "SSH_EXAMPLE_sshCertStoreInit: host key does not exist, computing new key...");

    /* if not, compute new host keys */
    if (0 > (status = CA_MGMT_generateNakedKey(akt_dsa, 1024, &pKeyBlob, &keyBlobLength)))
        goto exit;

    DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, "SSH_EXAMPLE_sshCertStoreInit: host key computation completed.");

    if (OK > (status = CERT_STORE_addIdentityNakedKey(*ppNewStore, pKeyBlob, keyBlobLength)))
        goto exit;

    CA_MGMT_freeNakedKey(&pKeyBlob);

exit:
    return status;
}
/*------------------------------------------------------------------*/

#if 0
static sbyte4
SSH_EXAMPLE_testHostKeys(void)
{
    /* nothing to test, since we're using a static array */
    return 0;
}
#endif

#else


/*------------------------------------------------------------------*/

#if 0
static sbyte4
SSH_EXAMPLE_testHostKeys(void)
{
    sbyte*  pRetPublicKey  = NULL;
    sbyte*  pRetPrivateKey = NULL;
    ubyte4  publicKeyLength;
    ubyte4  privateKeyLength;
    sbyte4  status;

    if (0 > (status = MOCANA_readFile(PUBLIC_HOST_KEY_FILE_NAME, (ubyte **)&pRetPublicKey, &publicKeyLength)))
        goto exit;

    status = MOCANA_readFile(PRIVATE_HOST_KEY_FILE_NAME, (ubyte **)&pRetPrivateKey, &privateKeyLength);

exit:
    MOCANA_freeReadFile((ubyte **)&pRetPublicKey);
    MOCANA_freeReadFile((ubyte **)&pRetPrivateKey);

    return status;
}
#endif


/*------------------------------------------------------------------*/

typedef struct sshExamplekeyFilesDescr
{
    ubyte*      pFilename;
    ubyte4      keyType;
    ubyte4      keySize;
#ifdef __ENABLE_MOCANA_PQC__
    ubyte4      qsAlgType;
#endif

} sshExamplekeyFilesDescr;


/*------------------------------------------------------------------*/

static sshExamplekeyFilesDescr mNakedKeyFiles[] =
{ /* HostKeys used by the example - Please ensure the keys match the negotiated algorithms and Key sizes */
#ifdef __ENABLE_MOCANA_SSH_DSA_SUPPORT__
    { (ubyte *)"ssh_dss.key", akt_dsa, 1024
#ifdef __ENABLE_MOCANA_PQC__
        , 0
#endif
     },
#endif
#ifdef __ENABLE_MOCANA_SSH_RSA_SUPPORT__
    { (ubyte *)"ssh_rsa.key", akt_rsa, 2048
#ifdef __ENABLE_MOCANA_PQC__
        , 0
#endif
    },
#endif
#ifdef __ENABLE_MOCANA_ECC__
    { (ubyte *)"ssh_ecdsa.key", akt_ecc, 256
#ifdef __ENABLE_MOCANA_PQC__
        , 0
#endif
     },
#endif
#ifdef __ENABLE_MOCANA_ECC_EDDSA_25519__
    { (ubyte *)"ssh_ed25519.key", akt_ecc_ed, 255
#ifdef __ENABLE_MOCANA_PQC__
        , 0
#endif
     },
#endif
#ifdef __ENABLE_MOCANA_PQC__
     {
        (ubyte *)"ssh_mldsa44.key", akt_qs, 0, cid_PQC_MLDSA_44
     },
#endif
#if (defined(__ENABLE_MOCANA_ECC__) && defined(__ENABLE_MOCANA_PQC__))
     {
        (ubyte *)"ssh_mldsa44_p256.key", akt_hybrid, cid_EC_P256, cid_PQC_MLDSA_44
     },
#endif
    { NULL, akt_undefined, 0 }
};

#define SSH_EXAMPLE_NUM_KEY_FILES   ((sizeof(mNakedKeyFiles) / sizeof(sshExamplekeyFilesDescr)) - 1)


/*------------------------------------------------------------------*/

static sbyte4
SSH_EXAMPLE_sshCertStoreInit(certStorePtr *ppNewStore)
{
    ubyte*  pKeyBlob = NULL;
    ubyte4  keyBlobLength;
    ubyte4  index;
    sbyte4  status;
#if (defined(__ENABLE_MOCANA_SSH_CLIENT_CERT_AUTH__))
    ubyte*      caCert = NULL;
    ubyte4      caCertLen;

#if (defined(__ENABLE_MOCANA_PEM_CONVERSION__))
    ubyte*      pTempCert = NULL;
    ubyte4      tempCertLen;
#endif
#endif
    certDescriptor certDesc = {0};
    AsymmetricKey asymKey = {0};
    hwAccelDescr    hwAccelCtx;

#if (defined(__ENABLE_MOCANA_SSH_X509V3_SIGN_SUPPORT__))
    certDescriptor tempCertificateDescr = {0};
#endif

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSH, &hwAccelCtx)))
        goto nocleanup;

    if (OK > (status = CERT_STORE_createStore(ppNewStore)))
        goto exit;

    for (index = 0; index < SSH_EXAMPLE_NUM_KEY_FILES; index++)
    {
        pKeyBlob      = NULL;
        keyBlobLength = 0;

        if (NULL == mNakedKeyFiles[index].pFilename)        /* skip past null strings; this happens if there is a dangling comma in mNakedKeyFiles[] */
            continue;

        /* check for pre-existing set of host keys */
#ifdef __ENABLE_MOCANA_DATA_PROTECTION__
        if (0 > (status = MOCANA_readFileEx((const char *)mNakedKeyFiles[index].pFilename, &pKeyBlob, &keyBlobLength, TRUE)))
#else
        if (0 > (status = MOCANA_readFile((const char *)mNakedKeyFiles[index].pFilename, &pKeyBlob, &keyBlobLength)))
#endif
        {
            /* if data protect is enabled, we do not generate keys */
#ifndef __ENABLE_MOCANA_DATA_PROTECTION__
            DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, (sbyte *)"SSH_EXAMPLE_sshCertStoreInit: host key does not exist, computing new key...");

            /* if not, compute new host keys */
#ifdef __ENABLE_MOCANA_PQC__
            if (0 > (status = CA_MGMT_generateNakedKeyPQC(mNakedKeyFiles[index].keyType, mNakedKeyFiles[index].keySize, mNakedKeyFiles[index].qsAlgType, &pKeyBlob, &keyBlobLength)))
#else
            if (0 > (status = CA_MGMT_generateNakedKey(mNakedKeyFiles[index].keyType, mNakedKeyFiles[index].keySize, &pKeyBlob, &keyBlobLength)))
#endif
                goto exit;

            if (0 > (status = MOCANA_writeFile((const char *)mNakedKeyFiles[index].pFilename, pKeyBlob, keyBlobLength)))
                goto exit;

            DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, (sbyte *)"SSH_EXAMPLE_sshCertStoreInit: host key computation completed.");

            if (OK > (status = CERT_STORE_addIdentityNakedKey(*ppNewStore, pKeyBlob, keyBlobLength)))
                goto exit;

            CA_MGMT_freeNakedKey(&pKeyBlob);
#else
            DEBUG_PRINT(DEBUG_SSH_EXAMPLE, (sbyte *)"SSH_EXAMPLE_sshCertStoreInit: Unable to load key: ");
            DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, (sbyte *)mNakedKeyFiles[index].pFilename);
            /* When data protect is enabled, if key file doesn't exist it isn't an error */
            status = OK;
#endif
        }
        else
        {
            status = CRYPTO_initAsymmetricKey(&asymKey);
            if (OK != status)
                goto exit;
            status = CRYPTO_deserializeAsymKey(MOC_ASYM(hwAccelCtx) pKeyBlob, keyBlobLength, NULL, &asymKey);
            if (OK != status)
            {
                CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
                goto exit;
            }

            status = CRYPTO_serializeAsymKey(MOC_ASYM(hwAccelCtx) &asymKey, mocanaBlobVersion2, &certDesc.pKeyBlob, &certDesc.keyBlobLength);
            if (OK != status)
            {
                CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
                goto exit;
            }

            if (OK > (status = CERT_STORE_addIdentityNakedKey(*ppNewStore, certDesc.pKeyBlob, certDesc.keyBlobLength)))
                goto exit;

            CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
            if (NULL != pKeyBlob)
            {
                MOC_FREE((void **)&pKeyBlob);
            }

            MOC_FREE((void **)&certDesc.pKeyBlob);
        }
    }

#if (defined(__ENABLE_MOCANA_SSH_CLIENT_CERT_AUTH__))
    if (ssh_CACert == NULL)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Read the issuer/CACert certificate */
#ifdef __ENABLE_MOCANA_DATA_PROTECTION__
    if (OK > (status = DPM_readSignedFile(ssh_CACert,
                                       &caCert,
                                       &caCertLen, TRUE, DPM_CA_CERTS)))
#else
    if (OK > (status = MOCANA_readFile(ssh_CACert,
                                       &caCert,
                                       &caCertLen)))
#endif
    {
        DEBUG_ERROR(DEBUG_SSH_EXAMPLE, (sbyte*)"SSH_EXAMPLE_loadCertificate: failed to read CA file with status: ", status);
        goto exit;
    }

#if (defined(__ENABLE_MOCANA_PEM_CONVERSION__))
    status = CA_MGMT_decodeCertificate(caCert, caCertLen,
        &pTempCert, &tempCertLen);
    if (OK == status)
    {
        status = MOC_FREE((void**)&caCert);
        if (OK != status)
            goto exit;

        caCert = pTempCert;
        caCertLen = tempCertLen;
        pTempCert = NULL;
        tempCertLen = 0;
    }
#endif

    if (OK > (status = CERT_STORE_addTrustPoint(*ppNewStore, caCert, caCertLen)))
    {
        DEBUG_ERROR(DEBUG_SSH_EXAMPLE, (sbyte*)"SSH_EXAMPLE_loadCertificate: CERT_STORE_addTrustPoint failed with status: ", status);
        goto exit;
    }

#endif


#ifdef __ENABLE_MOCANA_SSH_X509V3_SIGN_SUPPORT__
#ifdef __ENABLE_MOCANA_SSH_X509V3_RFC_6187_SUPPORT__

    MOC_MEMSET((ubyte *)&tempCertificateDescr, 0, sizeof (certDescriptor));
    tempCertificateDescr.pCertificate = cacert;
    tempCertificateDescr.certLength = sizeof (cacert);
    if (OK > (status = CERT_STORE_addTrustPoint(*ppNewStore,
                                                   tempCertificateDescr.pCertificate,
                                                   tempCertificateDescr.certLength)))
    {
        goto exit;
    }

    if (OK > (status = CA_MGMT_convertKeyPEM(privkey_pem, sizeof(privkey_pem),
                                             &tempCertificateDescr.pKeyBlob,
                                             &tempCertificateDescr.keyBlobLength)))
    {
        goto exit;
    }

    tempCertificateDescr.pCertificate = server_cert;
    tempCertificateDescr.certLength = sizeof (server_cert);
    status = CERT_STORE_addIdentity(*ppNewStore, tempCertificateDescr.pCertificate,
                                    tempCertificateDescr.certLength,
                                    tempCertificateDescr.pKeyBlob,
                                    tempCertificateDescr.keyBlobLength);

#else

    if ((0 > (status = MOCANA_readFile((sbyte *)"rsa.der",
                                       &tempCertificateDescr.pCertificate,
                                       &tempCertificateDescr.certLength))) ||
        (0 > (status = MOCANA_readFile((sbyte *)"rsakey.dat",
                                       &pKeyBlob,
                                       &keyBlobLength))) )
    {
        status = OK;
        goto exit;
    }

    status = CRYPTO_initAsymmetricKey(&asymKey);
    if (OK != status)
        goto exit;

    status = CRYPTO_deserializeAsymKey(MOC_ASYM(hwAccelCtx) pKeyBlob, keyBlobLength, NULL, &asymKey);
    if (OK != status)
    {
        CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
        goto exit;
    }

    status = CRYPTO_serializeAsymKey(MOC_ASYM(hwAccelCtx) &asymKey, mocanaBlobVersion2, &tempCertificateDescr.pKeyBlob, &tempCertificateDescr.keyBlobLength);
    if (OK != status)
    {
        CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
        goto exit;
    }

    status = CERT_STORE_addIdentity(*ppNewStore, tempCertificateDescr.pCertificate,
                                    tempCertificateDescr.certLength,
                                    tempCertificateDescr.pKeyBlob,
                                    tempCertificateDescr.keyBlobLength);



    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
#endif
#endif /* __ENABLE_MOCANA_SSH_X509V3_SIGN_SUPPORT__ */


exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSH, &hwAccelCtx);

    if (NULL != pKeyBlob)
    {
        MOC_FREE((void**)&pKeyBlob);
    }

#if (defined(__ENABLE_MOCANA_SSH_X509V3_SIGN_SUPPORT__))
    MOC_FREE((void**)&tempCertificateDescr.pKeyBlob);
#endif

#if (defined(__ENABLE_MOCANA_SSH_CLIENT_CERT_AUTH__))
    if(caCert)
        MOC_FREE((void**)&caCert) ;
#endif
#ifdef __ENABLE_MOCANA_SSH_X509V3_SIGN_SUPPORT__
    if(tempCertificateDescr.pKeyBlob)
        MOC_FREE((void**)&tempCertificateDescr.pKeyBlob);
#ifndef __ENABLE_MOCANA_SSH_X509V3_RFC_6187_SUPPORT__
    if(tempCertificateDescr.pCertificate)
        MOC_FREE((void**)&tempCertificateDescr.pCertificate);
#endif
#endif
    if (pKeyBlob)
    {
        MOC_FREE((void**)&pKeyBlob);
    }

nocleanup:
    return status;
}
#endif


/*------------------------------------------------------------------*/

#ifndef __DISABLE_MOCANA_FILE_SYSTEM_HELPER__
static sbyte4
SSH_EXAMPLE_pubkeyNotify(sbyte4 connectionInstance,
                         const ubyte *pUser,   ubyte4 userLength,
                         const ubyte *pPubKey, ubyte4 pubKeyLength,
                         ubyte4 keyType)
{
    ubyte *pStoredPublicKey = NULL;
    ubyte4 storedPublicKeyLength = 0;
    sbyte4 result = 0;
    MOC_UNUSED(connectionInstance);

    /* The SSH Server will only call this function, if the client's */
    /* public key matched the signature provided.  We need to now */
    /* verify that the public key is an acceptable public key (i.e. on record) */

    /* we're going to continue to assume everyone has a username */
    /* we do not force you to assume this policy */
    if (0 == userLength)
        goto exit;

    /* always check the lengths first, there may not be a username or password */
    if (userLength != MOC_STRLEN(ssh_UserName))
        goto exit;

    if (0 != memcmp(pUser, ssh_UserName, userLength))
        goto exit;

    /* make sure the client provided pubkey matches a pub key on file */
    if (0 > MOCANA_readFile(AUTH_KEYFILE_NAME,
                            &pStoredPublicKey,
                            &storedPublicKeyLength))
    {
        /* obviously, we don't want to accept *any* client's host key */
        /* without any authentication, but this simplifies the demo greatly! */
        ubyte *pRetEncodedAuthKey = NULL;
        ubyte4 pRetEncodedAuthKeyLen;
        SSH_UTILS_generateServerAuthKeyFile((ubyte*)pPubKey, pubKeyLength, &pRetEncodedAuthKey,&pRetEncodedAuthKeyLen);
        MOCANA_writeFile(AUTH_KEYFILE_NAME, pRetEncodedAuthKey, pRetEncodedAuthKeyLen);
        if (pRetEncodedAuthKey != NULL)
        {
            FREE(pRetEncodedAuthKey);
        }
        /* we accept first time client host keys */
        result = 1;
        goto exit;
    }

    /* In real life, we want to compare the received public key with the saved public key. The following call
       can be used for this.
       In this case, pStoredPublicKey is the client key file buffer, which is expected to be in the base64 encoded
       public key format.
       The corresponding Mocana ssh client code function to generate this is SSHC_UTILS_generateServerAuthKeyFile.
    */

    if (0 > SSH_compareAuthKeys(pPubKey, pubKeyLength, pStoredPublicKey, storedPublicKeyLength, &result))
        goto exit;
    /* if necessary, do additional checks here */

exit:
    if (NULL != pStoredPublicKey)
        MOCANA_freeReadFile(&pStoredPublicKey);

    return result;

} /* SSH_EXAMPLE_pubkeyNotify */
#endif



static sbyte4
SSH_EXAMPLE_certstatus(sbyte4 connectionInstance,
                         const ubyte *pUser,   ubyte4 userLength,
                         sbyte4 cert_status, ubyte *pCertificate, ubyte4 certLen,
                         certChainPtr pCertChain, const ubyte *pAnchorCert, ubyte4 anchorCertLen)
{
    MSTATUS status = OK;
    DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, (sbyte *)"SSH_EXAMPLE_certstatus:");

    if(cert_status != OK) {
        status = cert_status ;
        goto exit ;
    }

#if ((defined(__ENABLE_MOCANA_SSH_OCSP_SUPPORT__)) && (defined(__ENABLE_MOCANA_OCSP_CLIENT__)) && \
        (defined(__ENABLE_MOCANA_OCSP_CERT_VERIFY__)))
    status = OCSP_CLIENT_getCertStatus((sbyte *) ocsp_ResponderUrl, pCertificate,certLen,pCertChain, pAnchorCert, anchorCertLen  ) ;
#endif

exit:
    return status;
}



/*------------------------------------------------------------------*/

static void
SSH_EXAMPLE_postAccept(sbyte4 connectionInstance, sbyte4 clientSocket)
{
    MSTATUS status = -1;

    /* this callback occurs after the main server accept(). */
    /* for this example we will store the clientSocket in the cookie for later use */
    if (OK > (status = SSH_setCookie(connectionInstance, clientSocket)))
    {
        goto exit;
    }

#ifdef __USE_MOCANA_SSH_SERVER__
    if (OK > (status = SSH_assignCertificateStore(connectionInstance, pSshCertStore)))
    {
        DEBUG_ERROR(DEBUG_SSH_EXAMPLE, "SSH_EXAMPLE_startServer: SSH_assignCertificateStore() failed, error = ", status);
        TCP_CLOSE_SOCKET(clientSocket);
        SSH_closeConnection(connectionInstance);
    }
#endif
    /* alternatively, this code may malloc'd a structure, */
    /* storing a reference to that structure within the cookie */
exit:
    return;
}


/*------------------------------------------------------------------*/

static void
SSH_EXAMPLE_displayCommand(sbyte *pMesg, ubyte4 mesgLen)
{
    ubyte4 i;

    for (i = 0; i < mesgLen; i++)
        printf("%c", pMesg[i]);

    printf("\n");

    return;
}


/*------------------------------------------------------------------*/

static sbyte4
SSH_EXAMPLE_simpleFileTransfer(sbyte4 connInstance, sbyte4 mesgType,
                               sbyte* pInBuffer, sbyte4 numBytesReceived)
{
    sbyte4 status;

    while (1)
    {
#ifndef __ENABLE_MOCANA_SSH_STREAM_API__
        if (0 > (status = SSH_recvMessage(connInstance, &mesgType, pInBuffer,
                                &numBytesReceived, 10000)))
        {
            break;
        }
#else
        if (0 > (status = SSH_recv(connInstance, &mesgType, (ubyte *)pInBuffer,
                                    MAX_SESSION_WINDOW_SIZE, &numBytesReceived, 0)))
        {
            break;
        }
#endif

        switch (mesgType)
        {
#ifndef __ENABLE_MOCANA_SSH_SERIAL_CHANNEL__
            case SSH_SESSION_EOF:
#endif
            case SSH_SESSION_CLOSED:
                goto exit;

            default:
                break;
        }
    }
exit:
    return status;
}


/*------------------------------------------------------------------*/

static sbyte4
SSH_EXAMPLE_simpleCLI(sbyte4 connInstance, sbyte4 mesgType,
                      sbyte* pInBuffer, sbyte4 numBytesReceived)
{
    sbyte4  state = 0;
    sbyte4  i;
    sbyte4  bytesSent;
    sbyte4  status;

    /* shell: echo client input */
    while (1)
    {
#ifndef __ENABLE_MOCANA_SSH_STREAM_API__
        if (0 > (status = SSH_recvMessage(connInstance, &mesgType, pInBuffer,
                                          &numBytesReceived, 10000)))
        {
            goto exit;
        }
#else
        if (0 > (status = SSH_recv(connInstance, &mesgType, (ubyte *)pInBuffer,
                                   1, &numBytesReceived, 0)))
        {
            goto exit;
        }
#endif

        switch (mesgType)
        {
            case SSH_SESSION_NOTHING:
                DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, (sbyte *)"<idle connection>");
                break;
            case SSH_SESSION_DATA:
                if (0 < numBytesReceived)
                {
                    if (0 > (status = SSH_sendMessage(connInstance, pInBuffer, numBytesReceived, &bytesSent)))
                        goto exit;

                    /* check the input for 'bye\0x0d' */
                    for (i = 0; i < numBytesReceived; i++)
                    {
                        if ('R' == pInBuffer[i])
                        {
                            if (0 > (status = SSH_initiateReKey(connInstance, 5000)))
                            {
                                DEBUG_ERROR(DEBUG_SSH_EXAMPLE, "SSH_EXAMPLE_simpleCLI: SSH_initiateReKey() returned = ", status);
                                goto exit;
                            }
                        }

                        if ('T' == pInBuffer[i])
                        {
                            ubyte8 numBytesTransmitted;

                            if (0 > (status = SSH_numBytesTransmitted(connInstance, &numBytesTransmitted)))
                            {
                                DEBUG_ERROR(DEBUG_SSH_EXAMPLE, "SSH_EXAMPLE_simpleCLI: SSH_numBytesTransmitted() returned = ", status);
                                goto exit;
                            }

                            DEBUG_ERROR(DEBUG_SSH_EXAMPLE, "SSH_EXAMPLE_simpleCLI: bytes transmitted = ", LOW_U8(numBytesTransmitted));
                        }


                        if ('b' == pInBuffer[i])
                        {
                            sbyte4     ci = 0;
                            sbyte*   pInCipherName;
                            sbyte*   pOutCipherName;

                            while (0 != (ci = SSH_getNextConnectionInstance(ci)))
                            {
                                if (0 <= SSH_getSessionCryptoInfo(ci, &pInCipherName, NULL, &pOutCipherName, NULL))
                                {
                                    DEBUG_PRINT(DEBUG_SSH_EXAMPLE, "connectionInstance = ");
                                    DEBUG_INT(DEBUG_SSH_EXAMPLE, ci);
                                    DEBUG_PRINT(DEBUG_SSH_EXAMPLE, " in = ");
                                    DEBUG_PRINT(DEBUG_SSH_EXAMPLE, pInCipherName);
                                    DEBUG_PRINT(DEBUG_SSH_EXAMPLE, " out = ");
                                    DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, pOutCipherName);
                                }
                            }

                            state = 1;
                        }
                        else if (('y' == pInBuffer[i]) && (1 == state))
                            state = 2;
                        else if (('e' == pInBuffer[i]) && (2 == state))
                            state = 3;
                        else if (('\x0d' == pInBuffer[i]) && (3 == state))
                            goto exit;
                        else if (('!' == pInBuffer[i]) && (3 == state))
                        {
                            SSH_closeConnection(connInstance);
                            connInstance = -1;
#ifdef __USE_MOCANA_SSH_SERVER__
                            SSH_stopServer();
                            SSH_disconnectAllClients();
#else
                            mBreak = 1;
#endif
                            goto exit;
                        }
                        else state = 0;
                    }
                }
                break;
            case SSH_SESSION_STDERR:
                if (0 > (status = SSH_sendMessage(connInstance, (sbyte *)"<stderr>", 8, &bytesSent)))
                    goto exit;
                break;
            case SSH_SESSION_EOF:
                if (0 > (status = SSH_sendMessage(connInstance, (sbyte *)"<bye eof>", 9, &bytesSent)))
                    goto exit;
                break;
            case SSH_SESSION_CLOSED:
                goto exit;
            default:
                if (0 > (status = SSH_sendMessage(connInstance, (sbyte *)"<default>", 9, &bytesSent)))
                    goto exit;
                break;
        }
    }

exit:
    return status;

} /* SSH_EXAMPLE_simpleCLI */


/*------------------------------------------------------------------*/

static sbyte4
SSH_EXAMPLE_simpleExecCommands(sbyte4 connInstance, sbyte4 mesgType,
                               sbyte* pInBuffer, sbyte4 numBytesReceived)
{
    sbyte4  bytesSent;
    sbyte4  status;

    SSH_EXAMPLE_displayCommand(pInBuffer, numBytesReceived);

    /* shell: echo client input */
    while (1)
    {
        if (0 > (status = SSH_sendMessage(connInstance, (sbyte *)"hello world\n", 12, &bytesSent)))
            goto exit;

#ifndef __ENABLE_MOCANA_SSH_STREAM_API__
        if (0 > (status = SSH_recvMessage(connInstance, &mesgType, pInBuffer,
                                          &numBytesReceived, 10000)))
        {
            goto exit;
        }
#else
        if (0 > (status = SSH_recv(connInstance, &mesgType, (ubyte *)pInBuffer,
                                   1, &numBytesReceived, 0)))
        {
            goto exit;
        }
#endif

        switch (mesgType)
        {
            case SSH_SESSION_DATA:
                SSH_EXAMPLE_displayCommand(pInBuffer, numBytesReceived);
                break;
            case SSH_SESSION_NOTHING:
                DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, (sbyte *)"<idle connection>");
                break;
            case SSH_SESSION_STDERR:
                if (0 > (status = SSH_sendMessage(connInstance, (sbyte *)"<stderr>", 8, &bytesSent)))
                    goto exit;
                break;
            case SSH_SESSION_EOF:
                if (0 > (status = SSH_sendMessage(connInstance, (sbyte *)"<bye eof>", 9, &bytesSent)))
                    goto exit;
                break;
            case SSH_SESSION_CLOSED:
                goto exit;
            default:
                SSH_EXAMPLE_displayCommand(pInBuffer, numBytesReceived);
                break;
        }
    }

exit:
    return status;
}


#if (defined(__ENABLE_MOCANA_SSH_SCP_REKEY_EXAMPLE__)  && defined(__ENABLE_MOCANA_SSH_EXEC__))
static sbyte4
SSH_EXAMPLE_parseSCPCommand(sbyte *pCommand, ubyte4 commandLen, ubyte4 *pFileSize)
{
    sbyte4 status;
    ubyte4 i;
    ubyte *ptr = NULL;
    ubyte *cmd = NULL;
    ubyte4 fileSize = 0;

    ptr = pCommand;
    for (i = 0; i < commandLen; i++)
    {
        if (' ' == pCommand[i])
        {
            pCommand[i] = '\0';
        }
    }
    ptr += (MOC_STRLEN(ptr) + 1);
    fileSize = atoi(ptr);

    *pFileSize = fileSize;
    return status;
}
/*  this test mimics the server side receiving a file over scp from an OpenSSH client.
    This is not a valid SCP implementation, nor does it attempt to be. */
static sbyte4
SSH_EXAMPLE_simpleSCPReKeyExample(sbyte4 connInstance, sbyte4 mesgType,
                               sbyte* pInBuffer, sbyte4 numBytesReceived)
{
    sbyte4  bytesSent;
    sbyte4  status;
    ubyte8 totalBytesRead = 0;
    ubyte4 bytesUntilRekey = 1000000;
    ubyte4 timeToComply = 10000;
    ubyte4 timeout = 10000;
    intBoolean startRekey = FALSE;
    FileDescriptor pFileCtx = NULL;
    ubyte4 bytesWritten = 0;
    ubyte4 fileSize = 0;
    ubyte4 fileBytesRead = 0;
#ifdef __ENABLE_MOCANA_SSH_STREAM_API__
    ubyte pBuffer[SSH_SYNC_BUFFER_SIZE] = {0};
    ubyte4 bufferWritten = 0;
    intBoolean bytesPending = FALSE;
    intBoolean commandReceived = FALSE;
#endif

    SSH_EXAMPLE_displayCommand(pInBuffer, numBytesReceived);

    status = FMGMT_fopen("./testfile.txt", "wb", &pFileCtx);
    if (OK != status)
        goto exit;

    if (0 > (status = SSH_sendMessage(connInstance, (sbyte *)"\0", 1, &bytesSent)))
        goto exit;

    /* shell: echo client input */
    while (1)
    {
#ifndef __ENABLE_MOCANA_SSH_STREAM_API__
        if (0 > (status = SSH_recvMessage(connInstance, &mesgType, pInBuffer,
                                          &numBytesReceived, timeout)))
        {
            goto exit;
        }
#else
        if (0 > (status = SSH_recv(connInstance, &mesgType, (ubyte *)pInBuffer,
                                   1, &numBytesReceived, 0)))
        {
            goto exit;
        }
#endif

        switch (mesgType)
        {
            case SSH_SESSION_DATA:
#ifndef __ENABLE_MOCANA_SSH_STREAM_API__
                SSH_EXAMPLE_displayCommand(pInBuffer, numBytesReceived);
                if ('C' == pInBuffer[0]) {
                    if (0 > (status = SSH_EXAMPLE_parseSCPCommand(pInBuffer, numBytesReceived, &fileSize)))
                        goto exit;
                    if (0 > (status = SSH_sendMessage(connInstance, (sbyte *)"\0", 1, &bytesSent)))
                        goto exit;
                }
                else
                {
                    if ((numBytesReceived) >= (fileSize - fileBytesRead))
                    {
                        FMGMT_fwrite(pInBuffer, 1, (fileSize - fileBytesRead), pFileCtx, &bytesWritten);
                        fileBytesRead += (fileSize - fileBytesRead);

                        if (0 > (status = SSH_sendMessage(connInstance, (sbyte *)"\0", 1, &bytesSent)))
                            goto exit;
                    }
                    else
                    {
                        fileBytesRead += numBytesReceived;
                        FMGMT_fwrite(pInBuffer, 1, numBytesReceived, pFileCtx, &bytesWritten);
                    }
                }
                if ((OK == (status = SSH_numBytesTransmitted(connInstance, &totalBytesRead))) && (totalBytesRead > bytesUntilRekey))
                {
                    bytesUntilRekey += totalBytesRead;
                    SSH_initiateReKey(connInstance, timeToComply);
                }
#else
                printf("%c", pInBuffer[numBytesReceived - 1]);
                if (FALSE == commandReceived)
                {
                    pBuffer[bufferWritten++] = pInBuffer[numBytesReceived - 1];
                    status = SSH_recvPending (connInstance, &bytesPending);
                    if (OK != status)
                        goto exit;
                }

                if ((FALSE == commandReceived) && (FALSE == bytesPending))
                {
                    pBuffer[bufferWritten] = '\0';

                    commandReceived = TRUE;
                    if ('C' == pBuffer[0]) {
                        if (0 > (status = SSH_EXAMPLE_parseSCPCommand(pBuffer, bufferWritten, &fileSize)))
                            goto exit;
                        if (0 > (status = SSH_sendMessage(connInstance, (sbyte *)"\0", 1, &bytesSent)))
                            goto exit;
                    }
                }
                else
                {
                    if ((fileBytesRead + numBytesReceived) >= fileSize)
                    {
                        if ((fileBytesRead + numBytesReceived) == fileSize)
                        {
                            FMGMT_fwrite(pInBuffer, 1, numBytesReceived, pFileCtx, &bytesWritten);
                            fileBytesRead += numBytesReceived;

                            if (0 > (status = SSH_sendMessage(connInstance, (sbyte *)"\0", 1, &bytesSent)))
                                goto exit;
                        }
                    }
                    else
                    {
                        fileBytesRead += numBytesReceived;
                        FMGMT_fwrite(pInBuffer, 1, numBytesReceived, pFileCtx, &bytesWritten);
                        if ((OK == (status = SSH_numBytesTransmitted(connInstance, &totalBytesRead))) && (totalBytesRead > bytesUntilRekey))
                        {
                            bytesUntilRekey += totalBytesRead;
                            SSH_initiateReKey(connInstance, timeToComply);
                        }
                    }
                }
#endif

                break;
            case SSH_SESSION_NOTHING:
                DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, (sbyte *)"<idle connection>");
                break;
            case SSH_SESSION_STDERR:
                if (0 > (status = SSH_sendMessage(connInstance, (sbyte *)"<stderr>", 8, &bytesSent)))
                    goto exit;
                break;
            case SSH_SESSION_EOF:
                /* we are not expecting anymore data, we can exit */
            case SSH_SESSION_CLOSED:
                goto exit;
            default:
                SSH_EXAMPLE_displayCommand(pInBuffer, numBytesReceived);
                break;
        }
    }

exit:
    FMGMT_fclose(&pFileCtx);
    return status;
}
#endif /* (defined(__ENABLE_MOCANA_SSH_SCP_REKEY_EXAMPLE__)  && defined(__ENABLE_MOCANA_SSH_EXEC__)) */
/*------------------------------------------------------------------*/


/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_SSH_SERIAL_CHANNEL__
static void
SSH_EXAMPLE_simpleSerialChannelDemo(sbyte4 connInstance)
{
    /* incoming data */
    sbyte*     pInBuffer = NULL;
    sbyte4     numBytesReceived = 0;
    sbyte4     mesgType = 0;
    /* outgoing data */
    TCP_SOCKET socket;
    sbyte4     status;

    if (0 > SSH_getSocketId(connInstance, &socket))
        return;

#ifdef TCP_SHARE_SOCKET
    if (0 > TCP_SHARE_SOCKET(socket))
        goto exit;
#endif

    /* perform key exchange */
    if (0 > (status = SSH_negotiateConnection(connInstance)))
        goto exit;

    if (NULL == (pInBuffer = MALLOC(MAX_SESSION_WINDOW_SIZE)))
        goto exit;

    while(OK == status)
    {
        /* wait for client to open connection */
        while (((sbyte4)SSH_SESSION_OPEN_SHELL != mesgType) &&
               ((sbyte4)SSH_SESSION_OPEN_SFTP  != mesgType) &&
               ((sbyte4)SSH_SESSION_OPEN_EXEC  != mesgType))
        {
            if ((sbyte4)SSH_SESSION_CLOSED == mesgType)
            goto exit;

#ifndef __ENABLE_MOCANA_SSH_STREAM_API__
            if (0 > (status = SSH_recvMessage(connInstance, &mesgType, pInBuffer,
                                              &numBytesReceived, 0)))
            {
                goto exit;
            }
#else
            if (0 > (status = SSH_recv(connInstance, &mesgType, (ubyte *)pInBuffer,
                     MAX_SESSION_WINDOW_SIZE, &numBytesReceived, 0)))
            {
                goto exit;
            }
#endif
        }

        if ((sbyte4)SSH_SESSION_OPEN_SFTP == mesgType)
        {
            /* sftp: handle sftp messages */
            status = SSH_EXAMPLE_simpleFileTransfer(connInstance, mesgType, pInBuffer, numBytesReceived);
        }
        else
        {
            status = ERR_SSH_UNSUPPORTED_FEATURE_REQUEST;
        }
    }

    if (ERR_SSH_DISCONNECT_BY_APPLICATION == status)
    {
        status = OK;
    }

exit:
    if (NULL != pInBuffer)
        FREE(pInBuffer);

    /* free up any data stored in the cookie */
    if (0 < connInstance)
        SSH_closeConnection(connInstance);

    if (0 > status)
        DEBUG_ERROR(DEBUG_SSH_EXAMPLE, "SSH_EXAMPLE_simpleSerialChannelDemo: status = ", status);

#ifndef __USE_MOCANA_SSH_SERVER__
    TCP_CLOSE_SOCKET(socket);
#endif

    return;

} /* SSH_EXAMPLE_simpleSerialChannelDemo */
#endif


/*------------------------------------------------------------------*/

static void
SSH_EXAMPLE_simpleDemo(sbyte4 connInstance)
{
    /* incoming data */
    sbyte*     pInBuffer = NULL;
    sbyte4     numBytesReceived = 0;
    sbyte4     mesgType = 0;
    /* outgoing data */
    TCP_SOCKET socket;
    sbyte4     status;

    if (0 > SSH_getSocketId(connInstance, &socket))
        return;

#ifdef TCP_SHARE_SOCKET
    if (0 > TCP_SHARE_SOCKET(socket))
        goto exit;
#endif

    /* perform key exchange */
    if (0 > (status = SSH_negotiateConnection(connInstance)))
        goto exit;

    if (NULL == (pInBuffer = MALLOC(MAX_SESSION_WINDOW_SIZE)))
        goto exit;

    /* wait for client to open connection */
    while (((sbyte4)SSH_SESSION_OPEN_SHELL != mesgType) &&
           ((sbyte4)SSH_SESSION_OPEN_SFTP  != mesgType) &&
           ((sbyte4)SSH_SESSION_OPEN_EXEC  != mesgType))
    {
        if ((sbyte4)SSH_SESSION_CLOSED == mesgType)
	    goto exit;

#ifndef __ENABLE_MOCANA_SSH_STREAM_API__
        if (0 > (status = SSH_recvMessage(connInstance, &mesgType, pInBuffer,
                                          &numBytesReceived, 0)))
        {
            goto exit;
        }
#else
        if (0 > (status = SSH_recv(connInstance, &mesgType, (ubyte *)pInBuffer,
                 MAX_SESSION_WINDOW_SIZE, &numBytesReceived, 0)))
        {
            goto exit;
        }
#endif
    }

    if ((sbyte4)SSH_SESSION_OPEN_SFTP == mesgType)
    {
        /* sftp: handle sftp messages */
        status = SSH_EXAMPLE_simpleFileTransfer(connInstance, mesgType, pInBuffer, numBytesReceived);
    }
    else if ((sbyte4)SSH_SESSION_OPEN_EXEC == mesgType)
    {
        /* handle ssh exec open */
#if (defined(__ENABLE_MOCANA_SSH_SCP_REKEY_EXAMPLE__)  && defined(__ENABLE_MOCANA_SSH_EXEC__))
        status = SSH_EXAMPLE_simpleSCPReKeyExample(connInstance, mesgType, pInBuffer, numBytesReceived);
#else
        status = SSH_EXAMPLE_simpleExecCommands(connInstance, mesgType, pInBuffer, numBytesReceived);
#endif
    }
    else
    {
        /* handle shell, SSH_SESSION_OPEN_SHELL */
        status = SSH_EXAMPLE_simpleCLI(connInstance, mesgType, pInBuffer, numBytesReceived);
    }

exit:
    if (NULL != pInBuffer)
        FREE(pInBuffer);

    /* free up any data stored in the cookie */
    if (0 < connInstance)
        SSH_closeConnection(connInstance);

    if (0 > status)
        DEBUG_ERROR(DEBUG_SSH_EXAMPLE, "SSH_EXAMPLE_simpleDemo: status = ", status);

#ifndef __USE_MOCANA_SSH_SERVER__
    TCP_CLOSE_SOCKET(socket);
#endif

    return;

} /* SSH_EXAMPLE_simpleDemo */


/*------------------------------------------------------------------*/

static void
SSH_EXAMPLE_simpleDemoThreadEntry(void* hconnInstance)
{
    sbyte8 connInstance = (sbyte8)((uintptr)hconnInstance);
#ifdef __ENABLE_MOCANA_SSH_SERIAL_CHANNEL__
    SSH_EXAMPLE_simpleSerialChannelDemo((sbyte4)connInstance);
#else
    SSH_EXAMPLE_simpleDemo((sbyte4)connInstance);
#endif
}

/*------------------------------------------------------------------*/

#ifndef __USE_MOCANA_SSH_SERVER__
static void
SSH_EXAMPLE_startServer(void)
{
    TCP_SOCKET  listenSocket;
    sbyte4         status;

    mBreak = 0;

    if (0 > (status = TCP_LISTEN_SOCKET(&listenSocket, ((ubyte2)SSH_sshSettings()->sshListenPort))))
    {
        DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, (sbyte *)"SSH_EXAMPLE_startServer: Could not create listen socket");
        goto nocleanup;
    }


    DEBUG_PRINT(DEBUG_SSH_EXAMPLE, "SSH_EXAMPLE_startServer: SSH server listening on port ");
    DEBUG_INT(DEBUG_SSH_EXAMPLE, (sbyte4)SSH_sshSettings()->sshListenPort);
    DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, (sbyte *)"");

    MOCANA_log(MOCANA_SSH, LS_INFO, (sbyte *)"SSH EXAMPLE server listening for clients");


    while (1)
    {
        TCP_SOCKET  socketClient;
        sbyte4      ci;
        RTOS_THREAD tid;

        if (TRUE == mBreak)
            goto exit;

        if (OK > (status = TCP_ACCEPT_SOCKET(&socketClient, listenSocket, &mBreak)))
            goto exit;

        if (TRUE == mBreak)
            goto exit;

        DEBUG_PRINT(DEBUG_SSH_EXAMPLE, "SSH_EXAMPLE_startServer: Connection accepted on socket:");
        DEBUG_INT(DEBUG_SSH_EXAMPLE, (sbyte4)socketClient);
        DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, (sbyte *)"");

        if (OK > (ci = SSH_acceptConnection(socketClient)))
        {
            DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, (sbyte *)"SSH_EXAMPLE_startServer: Too many open connections.");
            TCP_CLOSE_SOCKET(socketClient);
            continue;
        }

        if (OK > (status = SSH_assignCertificateStore(ci, pSshCertStore)))
        {
            DEBUG_ERROR(DEBUG_SSH_EXAMPLE, (sbyte *)"SSH_EXAMPLE_startServer: SSH_assignCertificateStore() failed, error = ", status);
            TCP_CLOSE_SOCKET(socketClient);
            SSH_closeConnection(ci);
            continue;
        }

        if (OK > (status = RTOS_createThread(SSH_EXAMPLE_simpleDemoThreadEntry, (void *)((usize)ci), SSH_SESSION, &tid)))
        {
            DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, (sbyte *)"SSH_EXAMPLE_startServer: Too many open connections.");
            TCP_CLOSE_SOCKET(socketClient);
            goto exit;
        }

	if (tid != NULL)
	    RTOS_destroyThread(tid);
	tid = NULL;
    }

exit:
#if defined(__ENABLE_MOCANA_EXAMPLE_SSH_RADIUS_PASSWORD_AUTH__)
    RADIUS_shutdown();
#endif

    TCP_CLOSE_SOCKET(listenSocket);

nocleanup:
    return;

} /* SSH_EXAMPLE_startServer */
#endif /* __USE_MOCANA_SSH_SERVER__ */


/*------------------------------------------------------------------*/

static sbyte4
SSH_EXAMPLE_authMethod(sbyte4 connectionInstance)
{
    MOC_UNUSED(connectionInstance);

#ifndef __DISABLE_MOCANA_FILE_SYSTEM_HELPER__
    /* allows dynamic enable / disable of authentication methods */
    return (MOCANA_SSH_AUTH_PUBLIC_KEY | MOCANA_SSH_AUTH_PASSWORD
#ifdef __ENABLE_MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE__
            | MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE
#endif
            );
#else
    /* allows dynamic enable / disable of authentication methods */
    return (MOCANA_SSH_AUTH_PASSWORD
#ifdef __ENABLE_MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE__
            | MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE
#endif
            );
#endif
}

/*------------------------------------------------------------------*/
static void
setParameter(char ** param, char *value)
{
	if (OK > MOC_MALLOC((void **)param, (MOC_STRLEN((const sbyte *)value))+1))
        return;

    if (NULL == *param)
        return;

    (void) MOC_MEMCPY(*param, value, MOC_STRLEN((const sbyte *)value));
    (*param)[MOC_STRLEN((const sbyte *)value)] = '\0';
}

/*------------------------------------------------------------------*/

static void
SSH_EXAMPLE_displayHelp(char *prog)
{

    printf("  option:\n");
    printf("    -port <port>               sets listen port\n");
    printf("    -username <username>       sets username for authentication\n");
    printf("    -password <password>       sets password for authentication\n");
    printf("    -ssh_server_cert <cert>    sets the server cert path\n");
    printf("    -ssh_server_blob <key>     sets the server blob path\n");
    printf("    -ssh_ca_cert <ca_cert>     sets the CA certificate\n");
    printf("    -ocsp_responder_url <url>  sets the OCSP Responder URL\n");
    printf("    -ocsp_timeout <timeout>    sets the OCSP Wait Timeout(in ms)\n");
#if (defined(__ENABLE_MOCANA_TAP__))
#if (defined(__ENABLE_MOCANA_TAP_REMOTE__))
    printf("    -tap_server_port <tap_server_port> TAP server port\n");
    printf("    -tap_server_name <tap_server_name> TAP server name\n");
#endif
    printf("    -tap_config_file <tap_config_file> TAP config file\n");
#endif

    printf("\n");
    return;
} /*SSH_EXAMPLE_displayHelp */

/*------------------------------------------------------------------*/

extern sbyte4
SSH_EXAMPLE_getArgs(int argc, char *argv[])
{
    sbyte4 status = 0;
    int i = 0, userSet = 0, pwdSet = 0;
    char *temp;
#if (defined(__ENABLE_MOCANA_TAP__))
    int tapConfigFileSet = 0;
#if (defined(__ENABLE_MOCANA_TAP_REMOTE__))
    int tapServerNameSet = 0, tapServerPortSet = 0;
#endif
#endif

    if ((2 <= argc) && ('?' == argv[1][0]))
    {
        SSH_EXAMPLE_displayHelp(argv[0]);
        return -1;
    }

    for (i = 1; i < argc; i++) /*Skiping argv[0] which is example progam name*/
    {
		if (MOC_STRCMP((const sbyte *)argv[i], (const sbyte *)"-port") == 0)
		{
			if (++i < argc)
			{
				temp = argv[i];
				ssh_ServerPort = (unsigned short) MOC_ATOL((const sbyte *)temp,NULL);
			}
			continue;
		}
        else if (MOC_STRCMP((sbyte *)argv[i], (sbyte *) "-username") == 0)
        {
            if (++i < argc)
            {
                userSet = 1; /*username should not be set to default*/
                setParameter(&ssh_UserName, argv[i]);
            }
            continue;
        }
        else if (MOC_STRCMP((sbyte *) argv[i], (sbyte *) "-password") == 0)
        {
            if (++i < argc)
            {
                pwdSet = 1; /*password should not be set to default*/
                setParameter(&ssh_Password, argv[i]);
            }
            continue;
        }
        else if (MOC_STRCMP((const sbyte *)argv[i], (const sbyte *)"-ssh_server_cert") == 0)
		{
			if (++i < argc)
			{
				setParameter(&ssh_ServerCert, argv[i]);
			}
			continue;
		}
        else if (MOC_STRCMP((const sbyte *)argv[i], (const sbyte *)"-ssh_server_blob") == 0)
		{
			if (++i < argc)
			{
				setParameter(&ssh_ServerBlob, argv[i]);
			}
			continue;
		}
        else if (MOC_STRCMP((const sbyte *)argv[i], (const sbyte *)"-ssh_ca_cert") == 0)
		{
			if (++i < argc)
			{
				setParameter(&ssh_CACert, argv[i]);
			}
			continue;
		}
        else if (MOC_STRCMP((const sbyte *)argv[i], (const sbyte *)"-ocsp_responder_url") == 0)
		{
			if (++i < argc)
			{
				setParameter(&ocsp_ResponderUrl, argv[i]);
			}
			continue;
		}
        else if (MOC_STRCMP((const sbyte *)argv[i], (const sbyte *)"-ocsp_timeout") == 0)
		{
			if (++i < argc)
			{
				temp = argv[i];
				ocsp_Timeout= (ubyte4) MOC_ATOL((const sbyte *)temp,NULL);
			}
			continue;
		}
        else if (MOC_STRCMP((const sbyte *)argv[i], (const sbyte *)"-disable_password_expiry") == 0)
        {
            ssh_disablePasswordExpiryTest = TRUE;
            continue;
        }
#if (defined(__ENABLE_MOCANA_TAP__))
#if (defined(__ENABLE_MOCANA_TAP_REMOTE__))
        else if (MOC_STRCMP((const sbyte *)argv[i], (const sbyte *)"-tap_server_name") == 0)
        {
            if (++i < argc)
            {
                setParameter(&taps_ServerName, argv[i]);
                tapServerNameSet = 1;
            }
            continue;
        }
        else if (MOC_STRCMP((const sbyte *)argv[i], (const sbyte *)"-tap_server_port") == 0)
        {
            if (++i < argc)
            {
                temp = argv[i];
                taps_ServerPort = (unsigned short) MOC_ATOL((const sbyte *)temp,NULL);
                tapServerPortSet = 1;
            }
            continue;
        }
#endif
        else if (MOC_STRCMP((const sbyte *)argv[i], (const sbyte *)"-tap_config_file") == 0)
        {
            if (++i < argc)
            {
                setParameter(&tap_ConfigFile, argv[i]);
                tapConfigFileSet = 1;
            }
            continue;
        }
#endif
    } /*for*/

    if (!userSet)
    {
        setParameter(&ssh_UserName, USERNAME);
    }

    if (!pwdSet)
    {
        setParameter(&ssh_Password, PASSWORD);
    }

#if (defined(__ENABLE_MOCANA_TAP__))
#if (defined(__ENABLE_MOCANA_TAP_REMOTE__))
    if (!tapServerNameSet)
    {
    	DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, "Mandatory argument tap_server_name NOT set");
        status = ERR_SSH_CONFIG;
    }
    if (!tapServerPortSet)
    {
    	DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, "Mandatory argument tap_server_port NOT set");
        status = ERR_SSH_CONFIG;
    }
#endif
    if (!tapConfigFileSet)
    {
        setParameter(&tap_ConfigFile, TPM2_CONFIGURATION_FILE);
    }
#endif

    return status;
} /* SSH_EXAMPLE_getArgs */

/*------------------------------------------------------------------*/
/* If application wants to use the serverBlob only when stack has
 * __ENABLE_MOCANA_SSH_X509V3_RFC_6187_SUPPORT__ flag enabled, make sure to
 * disable the x509v3* mHosyKeySuites entry.\
 */
static sbyte4
SSH_EXAMPLE_loadCertificate(certStorePtr *ppCertStore)
{
    ubyte*      pKeyBlob = NULL;
    ubyte4      keyBlobLen;
    MSTATUS     status = OK;
#if (defined(__ENABLE_MOCANA_SSH_SERVER_CERT_AUTH__))
    ubyte4      numCertificate = 1;
    SizedBuffer certificates = {0};
    SizedBuffer tempCertificate = {0};
#endif
    certDescriptor certDesc = {0};
    AsymmetricKey asymKey={0};

#if ((defined(__ENABLE_MOCANA_SSH_OCSP_SUPPORT__)) || (defined(__ENABLE_MOCANA_SSH_CLIENT_CERT_AUTH__)))
    ubyte*      caCert = NULL;
    ubyte4      caCertLen;
    ubyte*      pTempCert = NULL;
    ubyte4      tempCertLen;
#endif
    hwAccelDescr    hwAccelCtx;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSH, &hwAccelCtx)))
        goto nocleanup;

    if (ssh_ServerBlob == NULL)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#if (defined(__ENABLE_MOCANA_SSH_SERVER_CERT_AUTH__))
    if (ssh_ServerCert == NULL)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* We need an issuer certificate(CACert) for getOCSP and validateOCSP;
     * We need CACert for validation if client is authenticating itself using a certificate.
     */
#if ((defined(__ENABLE_MOCANA_SSH_OCSP_SUPPORT__)) || (defined(__ENABLE_MOCANA_SSH_CLIENT_CERT_AUTH__)))
    if (ssh_CACert == NULL)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
#endif /* __ENABLE_MOCANA_SSH_OCSP_SUPPORT__ || __ENABLE_MOCANA_SSH_CLIENT_CERT_AUTH__ */
#endif /* __ENABLE_MOCANA_SSH_X509V3_RFC_6187_SUPPORT__ */

    /* Read the corresponding Key */
#ifdef __ENABLE_MOCANA_DATA_PROTECTION__
    if (OK > (status = MOCANA_readFileEx(ssh_ServerBlob,
                                       &pKeyBlob,
                                       &keyBlobLen, TRUE)))
#else
    if (OK > (status = MOCANA_readFile(ssh_ServerBlob,
                                       &pKeyBlob,
                                       &keyBlobLen)))
#endif
    {
        DEBUG_ERROR(DEBUG_SSH_EXAMPLE, "failed to read server key. status = %d\n", status);
        goto exit;
    }

    status = CRYPTO_initAsymmetricKey(&asymKey);
    if (OK != status)
        goto exit;

    status = CRYPTO_deserializeAsymKey(MOC_ASYM(hwAccelCtx) pKeyBlob, keyBlobLen, NULL, &asymKey);
    if (OK != status)
        goto exit;

    status = CRYPTO_serializeAsymKey(MOC_ASYM(hwAccelCtx) &asymKey, mocanaBlobVersion2, &certDesc.pKeyBlob, &certDesc.keyBlobLength);
    if (OK != status)
        goto exit;

#if (defined(__ENABLE_MOCANA_SSH_SERVER_CERT_AUTH__))
    /* Read the certificate used for authentication */
#ifdef __ENABLE_MOCANA_DATA_PROTECTION__
    if (OK > (status = DPM_readSignedFile(ssh_ServerCert,
                                       &certificates.data,
                                       &certificates.length, TRUE, DPM_CERTS)))
#else
    if (OK > (status = MOCANA_readFile(ssh_ServerCert,
                                       &certificates.data,
                                       &certificates.length)))
#endif
    {
        DEBUG_ERROR(DEBUG_SSH_EXAMPLE, "failed to read server cert. status = %d\n", status);
        goto exit;
    }
#if (defined(__ENABLE_MOCANA_PEM_CONVERSION__))
    status = CA_MGMT_decodeCertificate(certificates.data, certificates.length,
        &tempCertificate.data, &tempCertificate.length);
    if (OK == status)
    {
        status = MOC_FREE((void**)&certificates.data);
        if (OK != status)
            goto exit;

        certificates.data = tempCertificate.data;
        certificates.length = tempCertificate.length;
        tempCertificate.data = NULL;
        tempCertificate.length = 0;
    }
#endif
    if (OK > (status = CERT_STORE_addIdentityWithCertificateChain(*ppCertStore,
                                                                  &certificates,
                                                                  numCertificate,
                                                                  certDesc.pKeyBlob,
                                                                  certDesc.keyBlobLength)))
    {
        DEBUG_ERROR(DEBUG_SSH_EXAMPLE, "SSH_EXAMPLE_loadCertificate: Failed to read server cert. status = %d\n", status);
        goto exit;
    }
#if ((defined(__ENABLE_MOCANA_SSH_OCSP_SUPPORT__)) || (defined(__ENABLE_MOCANA_SSH_CLIENT_CERT_AUTH__)))
    /* Read the issuer/CACert certificate */
#ifdef __ENABLE_MOCANA_DATA_PROTECTION__
    if (OK > (status = DPM_readSignedFile(ssh_CACert,
                                       &caCert,
                                       &caCertLen, TRUE, DPM_CA_CERTS)))
#else
    if (OK > (status = MOCANA_readFile(ssh_CACert,
                                       &caCert,
                                       &caCertLen)))
#endif
    {
        DEBUG_ERROR(DEBUG_SSH_EXAMPLE, "SSH_EXAMPLE_loadCertificate: Failed to read CA cert. status = %d\n", status);
        goto exit;
    }

#if (defined(__ENABLE_MOCANA_PEM_CONVERSION__))
    status = CA_MGMT_decodeCertificate(caCert, caCertLen,
        &pTempCert, &tempCertLen);
    if (OK == status)
    {
        status = MOC_FREE((void**)&caCert);
        if (OK != status)
            goto exit;

        caCert = pTempCert;
        caCertLen = tempCertLen;
        pTempCert = NULL;
        tempCertLen = 0;
    }
#endif
    if (OK > (status = CERT_STORE_addTrustPoint(*ppCertStore, caCert, caCertLen)))
    {
        goto exit;
    }
#endif /* ((defined(__ENABLE_MOCANA_SSH_OCSP_SUPPORT__)) || (defined(__ENABLE_MOCANA_SSH_CLIENT_CERT_AUTH__))) */
#else

    if (OK > (status = CERT_STORE_addIdentityNakedKey(*ppCertStore, certDesc.pKeyBlob,
                           certDesc.keyBlobLength)))
        goto exit;

#endif
#if (defined(__ENABLE_MOCANA_TPM__))
    AsymmetricKey *pRetKey = NULL;
      /* After adding a TPM RSA key to a cert store, you must reassign the secmod context to the key */
      /* We do this by retrieving the key from the cert store, then setting the context to the key */
    if(OK > (status = CERT_STORE_findIdentityByTypeFirst(*ppCertStore,
            CERT_STORE_AUTH_TYPE_RSA, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3,
            (const struct AsymmetricKey **)&pRetKey, NULL, NULL, NULL)))
    {
        printf("Unable to retrieve key from cert store!\n");
        printf("CERT_STORE_findIdentityByTypeFirst status %d = %s\n", status, MERROR_lookUpErrorCode(status));
        goto exit;
    }
    if (OK > (status = MOCTAP_initializeTPMKeyContext(mh, pRetKey, &reqKeyContext)))
    {
        printf("Unable to initialize TPM Key");
        goto exit;
    }
#endif

exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSH, &hwAccelCtx);

    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
    if (pKeyBlob)
    {
        MOC_FREE((void**)&pKeyBlob);
    }

#if ((defined(__ENABLE_MOCANA_SSH_OCSP_SUPPORT__)) || (defined(__ENABLE_MOCANA_SSH_CLIENT_CERT_AUTH__)))
    if(caCert)
        MOC_FREE((void**)&caCert);

    if (NULL != pTempCert)
        MOC_FREE((void**)&pTempCert);
#endif

#if (defined(__ENABLE_MOCANA_SSH_SERVER_CERT_AUTH__))
    MOC_FREE((void**)&certificates.data);
    MOC_FREE((void**)&tempCertificate.data);
#endif
    MOC_FREE((void**)&certDesc.pKeyBlob);
nocleanup:
    return status;
}

/*------------------------------------------------------------------*/

/* This is only for build the SSL client using Microsoft Visual Studio project */
#if defined(__ENABLE_MOCANA_WIN_STUDIO_BUILD__) && !defined(__ENABLE_CMAKE_BUILD__)
int main(int argc, char *argv[])
{
	void* dummy = NULL;
#else
extern int
SSH_EXAMPLE_main(sbyte4 dummy)
{
#endif
	MSTATUS status = OK;

#ifdef __ENABLE_MOCANA_MEM_PART__
    if (NULL != gMemPartDescr)
    {
        /* make sure it's thread-safe! */
        MEM_PART_enableMutexGuard(gMemPartDescr);
    }
#endif

#ifdef __ENABLE_DIGICERT_SECURE_PATH__
    if (OK > (status = FMGMT_changeCWD(MANDATORY_BASE_PATH)))
        goto exit;
#endif

#if defined(__ENABLE_MOCANA_WIN_STUDIO_BUILD__) && !defined(__ENABLE_CMAKE_BUILD__)
	if (OK > ( status = SSH_EXAMPLE_getArgs(argc, argv))) /* Initialize parameters to default values */
		return status;

	if (OK > (status = MOCANA_initMocana()))
      goto exit;
#endif

    MOC_UNUSED(dummy);

    DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, (sbyte *)"SSH_EXAMPLE_main: Starting up SSH Server");

    /* initialize the SSH tables and structures */
    if (0 > SSH_init(MAX_SSH_CONNECTIONS_ALLOWED))
        goto exit;

#ifdef __ENABLE_MOCANA_TPM__
#ifdef __USE_TPM_EMULATOR__
    if (OK > (status = MOCTAP_initSecurityDescriptor(NULL, NULL, NULL, secmod_TPM12RSAKey, 9, (ubyte *)"localhost", &mh)))
    {
        DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE,"Unable to initialize MOCTAP Context");
        goto exit;
    }
#else
    if (OK > (status = MOCTAP_initSecurityDescriptor(NULL, NULL, NULL, secmod_TPM12RSAKey, 9, (ubyte *)"/dev/tpm0", &mh)))
    {
        DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE,"Unable to initialize MOCTAP Context");
        goto exit;
    }
#endif /* __USE_TPM_EMULATOR__ */
#endif /* __ENABLE_MOCANA_TPM__ */

#ifdef __ENABLE_MOCANA_TAP__
    if (OK != (status = SSH_EXAMPLE_InitializeTapContext(tap_ConfigFile, &g_pTapContext,
                                                         &g_pTapEntityCred,
                                                         &g_pTapKeyCred)))
    {
        DEBUG_ERROR(DEBUG_SSH_EXAMPLE, "SSHC_EXAMPLE_InitializeTapContext failed. status = %d\n", status);
        goto exit;
    }

    if (OK > (status = CRYPTO_INTERFACE_registerTapCtxCallback((void *)&SSH_EXAMPLE_getTapContext)))
        goto exit;
#endif

    /* If the keyBlob is provided via commandline load it into our certStore */
    if (ssh_ServerBlob != NULL)
    {
        // Remove the above flag, check for keyBlob
        if (OK > (status = CERT_STORE_createStore(&pSshCertStore)))
            goto exit;

        if (OK > (status = SSH_EXAMPLE_loadCertificate(&pSshCertStore)))
            goto exit;
    }
    else
    {
#ifndef __DISABLE_MOCANA_FILE_SYSTEM_HELPER__
        /* if necessary, create host keys */
        if (OK > (status = SSH_EXAMPLE_sshCertStoreInit(&pSshCertStore)))
            goto exit;
#else
        if ( OK > (status = SSH_EXAMPLE_sshCertStoreInitFS(&pSshCertStore)))
            goto exit;
#endif /* __DISABLE_MOCANA_FILE_SYSTEM_HELPER__ */
    }

#ifdef __ENABLE_MOCANA_SSH_FTP_SERVER__
    SFTP_EXAMPLE_init();
#endif

    /* customize SSH settings and callbacks here */
    SSH_sshSettings()->funcPtrPostAccept                = SSH_EXAMPLE_postAccept;
#ifdef SSH_EXAMPLE_simpleSerialChannelDemo
    SSH_sshSettings()->funcPtrConnection                = SSH_EXAMPLE_simpleSerialChannelDemo;
#else
    SSH_sshSettings()->funcPtrConnection                = SSH_EXAMPLE_simpleDemo;
#endif
    SSH_sshSettings()->funcPtrSessionReKey               = SSH_EXAMPLE_reKeyFunction;

    SSH_sshSettings()->pBannerString                    = (sbyte *)SSH_EXAMPLE_banner;
    SSH_sshSettings()->funcPtrGetAuthAdvertizedMethods  = SSH_EXAMPLE_authMethod;
#if defined(__ENABLE_MOCANA_EXAMPLE_SSH_RADIUS_PASSWORD_AUTH__)
    SSH_sshSettings()->funcPtrPasswordAuth              = SSH_RADIUS_EXAMPLE_authPasswordFunction;
#else
    SSH_sshSettings()->funcPtrPasswordAuth              = SSH_EXAMPLE_authPasswordFunction;
#endif

#ifndef __DISABLE_MOCANA_FILE_SYSTEM_HELPER__
    SSH_sshSettings()->funcPtrPubKeyAuth                = SSH_EXAMPLE_pubkeyNotify;
#endif
    SSH_sshSettings()->funcPtrCertStatus                = SSH_EXAMPLE_certstatus ;
    SSH_sshSettings()->funcPtrKeyIntAuthReq             = SSH_EXAMPLE_keyboardInteractiveAuth;
    SSH_sshSettings()->funcPtrReleaseKeyIntReq          = SSH_EXAMPLE_releaseKeyboardInteractiveRequest;

    SSH_sshSettings()->sshListenPort	        		= ssh_ServerPort;

#if ((defined(__ENABLE_MOCANA_SSH_OCSP_SUPPORT__)) && (defined(__ENABLE_MOCANA_OCSP_CLIENT__)))
    SSH_sshSettings()->pOcspResponderUrl                = (sbyte *)ocsp_ResponderUrl;
#if (defined(__ENABLE_MOCANA_OCSP_TIMEOUT_CONFIG__))
    SSH_sshSettings()->ocspTimeout                      = ocsp_Timeout;
#endif
#endif

    /* startup the SSH Server */
#ifdef __USE_MOCANA_SSH_SERVER__
    SSH_startServer();
#else
    SSH_EXAMPLE_startServer();
#endif

exit:
    SSH_shutdown();

    SSH_releaseTables();
#ifdef __ENABLE_MOCANA_TPM__
    MOCTAP_deinitializeTPMKeyContext(mh, &reqKeyContext) ;
#endif
#ifdef __ENABLE_MOCANA_TAP__
    TAP_ErrorContext *pErrContext = NULL;

    TAP_uninit(pErrContext);
    /* Free module list */
    status = TAP_freeModuleList(&g_moduleList);
    if (OK != status)
        printf("TAP_freeModuleList : %d\n", status);

    if (g_pTapContext)
      free(g_pTapContext);

    if (NULL != g_pTapEntityCred)
    {
        status = TAP_UTILS_clearEntityCredentialList(g_pTapEntityCred);
        if (OK != status)
            printf("TAP_UTILS_clearEntityCredentialList: %d\n", status);
        MOC_FREE((void **)&g_pTapEntityCred);
    }
#if (defined(__ENABLE_MOCANA_TAP_REMOTE__))
    if (NULL != taps_ServerName)
    {
        MOC_FREE((void **)&taps_ServerName);
    }
#endif
    if (NULL != tap_ConfigFile)
    {
        MOC_FREE((void **)&tap_ConfigFile);
    }
#endif

    if (ssh_UserName)
        FREE(ssh_UserName);

    if (ssh_Password)
        FREE(ssh_Password);

    if(ssh_CACert)
        FREE(ssh_CACert);

    if(ssh_ServerCert)
        FREE(ssh_ServerCert);

    if(ssh_ServerBlob)
        FREE(ssh_ServerBlob);

    CERT_STORE_releaseStore(&pSshCertStore);
    return status;
}

#endif /* (defined( __ENABLE_MOCANA_SSH_SERVER_EXAMPLE__ ) && !defined( __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__ ) && !defined(__ENABLE_MOCANA_SSH_PORT_FORWARDING__)) */

