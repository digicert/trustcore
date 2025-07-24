/*
 * sshc_example.c
 *
 * SSHC Example Code
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

#include "common/moptions.h"

#if (defined(__ENABLE_MOCANA_SSH_CLIENT_EXAMPLE__) && defined(__ENABLE_MOCANA_SSH_FTP_CLIENT__) && (defined(__ENABLE_MOCANA_EXAMPLES__) || defined(__ENABLE_MOCANA_BIN_EXAMPLES__))) && (!defined(__ENABLE_MOCANA_SSH_REMOTE_PORT_FORWARDING__) && !defined(__ENABLE_MOCANA_SSH_PORT_FORWARDING__))

#include "common/mtypes.h"
#include "common/mdefs.h"
#include "common/mocana.h"
#include "crypto/hw_accel.h"
#include "common/merrors.h"
#include "common/mrtos.h"
#include "common/mtcp.h"
#include "common/mstdlib.h"
#include "common/debug_console.h"
#include "common/sizedbuffer.h"
#include "common/mfmgmt.h"
#include "crypto/pubcrypto.h"
#include "crypto/ca_mgmt.h"
#include "crypto/cert_store.h"
#include "crypto/cert_chain.h"
#include "ssh/client/sshc.h"
#include "ssh/client/sshc_filesys.h"
#include "ssh/ssh_defs.h"
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

#include <stdio.h>

static certStorePtr pSshClientCertStore;

#if 0
/* Enable this flag, if you decide to use public key authentication example*/
#define __ENABLE_MOCANA_SSH_CLIENT_EXAMPLE_AUTH__
#endif

/* WARNING: Hardcoded credentials used below are for illustrative purposes ONLY.
   DO NOT use hardcoded credentials in production. */
/* Defaults */
#define DEFAULT_USERNAME                              "admin"
#define DEFAULT_PASSWORD                              "secure"
#define DEFAULT_IP                                    "127.0.0.1"
#define DEFAULT_PORT                                  9000


/*------------------------------------------------------------------*/

/* Number of simultaneous remote server connections to maintain */
#define MAX_SSHC_CONNECTIONS_ALLOWED            1


/*------------------------------------------------------------------*/

/* My public/private host key pair --- for authenticating myself to a server */
#define KEYBLOB_AUTH_KEY_FILE_NAME              "sshc_keys.dat"
#define SSH_PUBLIC_KEY_FILE_NAME                "sshc_keys.pub"

/* A trusted remote server's public key */
#define AUTH_KEYFILE_NAME                       "sshc_remote.pub"

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

/*------------------------------------------------------------------*/

/* Select authentication methods I want to use to authenticate myself to remote server */
/* Methods: */
/*      MOCANA_SSH_AUTH_PUBLIC_KEY (public key based) */
/*      MOCANA_SSH_AUTH_PASSWORD (simple username / password) */
/*      MOCANA_SSH_AUTH_CERT (certificate based authentication) */
#if (!(defined(__ENABLE_MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE__)))
#if (!(defined(__ENABLE_MOCANA_SSH_CLIENT_EXAMPLE_AUTH_NONE__)))
#if (!(defined(__ENABLE_MOCANA_SSH_CLIENT_CERT_AUTH__)))
#if (!(defined(__ENABLE_MOCANA_SSH_CLIENT_EXAMPLE_AUTH__)))
#define SSHC_EXAMPLE_AUTH_METHOD                MOCANA_SSH_AUTH_PASSWORD
#else
#define SSHC_EXAMPLE_AUTH_METHOD                MOCANA_SSH_AUTH_PUBLIC_KEY
#endif /* __ENABLE_MOCANA_SSH_CLIENT_EXAMPLE_AUTH__ */
#else
#define SSHC_EXAMPLE_AUTH_METHOD                MOCANA_SSH_AUTH_CERT
#endif /* __ENABLE_MOCANA_SSH_CLIENT_CERT_AUTH__ */
#else
#define SSHC_EXAMPLE_AUTH_METHOD                MOCANA_SSH_AUTH_NONE
#endif /* __ENABLE_MOCANA_SSH_CLIENT_EXAMPLE_AUTH_NONE__ */
#else
#define SSHC_EXAMPLE_AUTH_METHOD                MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE
#endif /* __ENABLE_MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE__ */


/* This is used for the callback SSHC_EXAMPLE_userAuthRequestInfoUpcallEx */
unsigned int authenticationMethods[] = {
#ifdef __ENABLE_MOCANA_SSH_CLIENT_CERT_AUTH__
    MOCANA_SSH_AUTH_CERT,
#else
#ifdef __ENABLE_MOCANA_SSH_CLIENT_EXAMPLE_AUTH__
    MOCANA_SSH_AUTH_PUBLIC_KEY,
#endif
#endif
#ifdef __ENABLE_MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE__
    MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE,
#endif
    MOCANA_SSH_AUTH_PASSWORD
};

#ifdef __ENABLE_MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE__
#define KEYBOARD_AUTH 1
#else
#define KEYBOARD_AUTH 0
#endif

#if (defined(__ENABLE_MOCANA_SSH_CLIENT_CERT_AUTH__) || defined(__ENABLE_MOCANA_SSH_CLIENT_EXAMPLE_AUTH__))
#define PUBKEY_AUTH 1
#else
#define PUBKEY_AUTH 0
#endif

/* password authentication is always enabled */
#define AUTH_METHOD_COUNT (KEYBOARD_AUTH + PUBKEY_AUTH + 1)

unsigned int authenticationMethodIndex = 0;

static char *          ocsp_ResponderUrl = NULL;

/* (REQUIRED) MY username */
static char * sshc_exampleUserName     = NULL;
static ubyte usrname[16];

/* (OPTIONAL) MY password, for simple username / password authentication */
static char * sshc_examplePassword     = NULL;
static ubyte password[16];


/*------------------------------------------------------------------*/

/* Remote server's IP address / port */
#ifdef __ENABLE_MOCANA_IPV6__
static const char *sshc_exampleIPAddress     = "::01";
#else
static char * sshc_exampleIPAddress     = NULL;
#endif

static unsigned short sshc_ServerPort = DEFAULT_PORT;
static char * 	      ssh_CACert      = NULL;
static char *         ssh_ClientCert  = NULL;
static char *         ssh_ClientBlob  = NULL;

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

/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_TAP__

static sbyte4
SSHC_EXAMPLE_getTapContext(TAP_Context **ppTapContext,
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
            DEBUG_ERROR(DEBUG_SSL_EXAMPLE, (sbyte*)"SSL_EXAMPLE: TAP_uninitContext failed with status: ", status);
        }
    }

exit:
    return status;
}


static MSTATUS
SSHC_EXAMPLE_InitializeTapContext(ubyte *pTpm2ConfigFile, TAP_Context **ppTapCtx,
                                 TAP_EntityCredentialList **ppTapEntityCred,
                                 TAP_CredentialList **ppTapKeyCred)
{
    MSTATUS status = OK;
    TAP_ConfigInfoList configInfoList = { 0, };
    TAP_Context *pTapContext = NULL;
    TAP_ErrorContext *pErrContext = NULL;
    ubyte tapInit = FALSE;
    ubyte gotModuleList = FALSE;
    ubyte contextInit = FALSE;
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

    status = TAP_readConfigFile(pTpm2ConfigFile, &configInfoList.pConfig[0].configInfo, 0);
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
    tapInit = TRUE;

#if (defined(__ENABLE_MOCANA_TAP_REMOTE__))

    connInfo.serverName.bufferLen = MOC_STRLEN((sbyte *)taps_ServerName)+1;
    status = MOC_CALLOC ((void **)&(connInfo.serverName.pBuffer), 1, connInfo.serverName.bufferLen);
    if (OK != status)
    goto exit;

    status = MOC_MEMCPY ((void *)(connInfo.serverName.pBuffer), (void *)taps_ServerName, MOC_STRLEN((sbyte *)taps_ServerName));
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
    gotModuleList = TRUE;
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
SSHC_EXAMPLE_sshCertStoreInit(certStorePtr *ppNewStore)
{
    sbyte4 status;

#if (defined(__ENABLE_MOCANA_SSH_X509V3_RFC_6187_SUPPORT__))
    ubyte* cert = 0;
    ubyte4 certLen;

    ubyte* pTemp = NULL;
    ubyte4 tempLen;
#endif

    if (OK > (status = CERT_STORE_createStore(ppNewStore)))
        goto exit;

#if (defined(__ENABLE_MOCANA_SSH_X509V3_RFC_6187_SUPPORT__))
#ifndef __DISABLE_MOCANA_FILE_SYSTEM_HELPER__
    if (ssh_CACert != NULL)
    {
#ifdef __ENABLE_MOCANA_DATA_PROTECTION__
        if (OK > (status = DPM_readSignedFile(ssh_CACert, &cert, &certLen, TRUE, DPM_CA_CERTS)))
#else
        if (OK > (status = MOCANA_readFile(ssh_CACert, &cert, &certLen)))
#endif
        {
            DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, (sbyte *)"Reading CA certificate failed\n");
            goto exit;
        }

        status = CA_MGMT_decodeCertificate(cert, certLen, &pTemp, &tempLen);
        if (OK == status)
        {
            status = MOC_FREE((void**)&cert);
            if (OK != status)
            {
                goto exit;
            }

            cert = pTemp;
            certLen = tempLen;
            pTemp = NULL;
            tempLen = 0;
        }
    }
    else
    {
        cert = cacert;
        certLen = sizeof(cacert);
    }
#else /* __DISABLE_MOCANA_FILE_SYSTEM_HELPER__ */
    cert    = cacert;
    certLen = sizeof(cacert);
#endif /* __DISABLE_MOCANA_FILE_SYSTEM_HELPER__ */

    if (OK > (status = CERT_STORE_addTrustPoint(*ppNewStore, cert, certLen)))
        goto exit;
#endif/* __ENABLE_MOCANA_SSH_X509V3_RFC_6187_SUPPORT__ */

exit:
#if (defined(__ENABLE_MOCANA_SSH_X509V3_RFC_6187_SUPPORT__))
#ifndef __DISABLE_MOCANA_FILE_SYSTEM_HELPER__
    if (ssh_CACert != NULL)
    {
        if(cert)
            MOC_FREE((void**)&cert) ;
    }
#endif /* __DISABLE_MOCANA_FILE_SYSTEM_HELPER__ */
#endif
    return status;
}

#if (defined(__ENABLE_MOCANA_SSH_CLIENT_CERT_AUTH__))
static sbyte4
SSHC_EXAMPLE_loadCertificate(certStorePtr *ppNewStore)
{
    sbyte4       status;
    SizedBuffer  certificates = {0};
    SizedBuffer  tempCertificates = {0};
    ubyte*       pKeyBlob = NULL;
    ubyte4       keyBlobLen = 0;

    ubyte*       cert = NULL;
    ubyte4       certLen;
    ubyte*       pTempCert = NULL;
    ubyte4       tempCertLen;
    ubyte4       numCertificate = 1;
    certDescriptor certDesc = {0};
    hwAccelDescr hwAccelCtx;

#if (defined(__ENABLE_MOCANA_PEM_DER_PRIVATE_KEY__) || defined(__ENABLE_MOCANA_TAP__))
    AsymmetricKey asymKey = {0};
#endif

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSH, &hwAccelCtx)))
        goto nocleanup;

    if (ssh_ClientBlob == NULL)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = CERT_STORE_createStore(ppNewStore)))
        goto exit;

#ifndef __DISABLE_MOCANA_FILE_SYSTEM_HELPER__
    if (ssh_CACert != NULL)
    {
#ifdef __ENABLE_MOCANA_DATA_PROTECTION__
        if (OK > (status = DPM_readSignedFile(ssh_CACert, &cert, &certLen, TRUE, DPM_CA_CERTS)))
#else
        if (OK > (status = MOCANA_readFile(ssh_CACert, &cert, &certLen)))
#endif
        {
            DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, (sbyte *)"Reading Ceritificate in client failed \n");
            goto exit;
        }
#if (defined(__ENABLE_MOCANA_PEM_CONVERSION__))
        status = CA_MGMT_decodeCertificate(cert, certLen,
            &pTempCert, (ubyte4*) &tempCertLen);
        if (OK == status)
        {
            status = MOC_FREE((void**)&cert);
            if (OK != status)
                goto exit;

            cert = pTempCert;
            certLen = tempCertLen;
            pTempCert = NULL;
            tempCertLen = 0;
        }
#endif
    }
    else
    {
        cert = cacert;
        certLen = sizeof(cacert);
    }
#else
    cert = cacert;
    certLen = sizeof(cacert);
#endif/* __DISABLE_MOCANA_FILE_SYSTEM_HELPER__ */

    if (OK > (status = CERT_STORE_addTrustPoint(*ppNewStore, cert, certLen)))
        goto exit;

#ifdef __ENABLE_MOCANA_DATA_PROTECTION__
    if (OK > (status = DPM_readSignedFile(ssh_ClientCert,
                                       &certificates.data,
                                       &certificates.length, TRUE, DPM_CERTS)))
#else
    if (OK > (status = MOCANA_readFile(ssh_ClientCert,
                                       &certificates.data,
                                       &certificates.length)))
#endif
    {
        DEBUG_ERROR(DEBUG_SSL_EXAMPLE, "failed to read client cert. status = %d\n", status);
        goto exit;
    }
#if (defined(__ENABLE_MOCANA_PEM_CONVERSION__))
    status = CA_MGMT_decodeCertificate(certificates.data, certificates.length,
        &tempCertificates.data, &tempCertificates.length);
    if (OK == status)
    {
        status = MOC_FREE((void**)&certificates.data);
        if (OK != status)
            goto exit;

        certificates.data = tempCertificates.data;
        certificates.length = tempCertificates.length;
        tempCertificates.data = NULL;
        tempCertificates.length = 0;
    }
#endif

#ifdef __ENABLE_MOCANA_DATA_PROTECTION__
    if (OK > (status = MOCANA_readFileEx(ssh_ClientBlob,
                                       &pKeyBlob,
                                       &keyBlobLen, TRUE)))
#else
    if (OK > (status = MOCANA_readFile(ssh_ClientBlob,
                                       &pKeyBlob,
                                       &keyBlobLen)))
#endif
    {
        DEBUG_ERROR(DEBUG_SSL_EXAMPLE, "failed to read client key. status = %d\n", status);
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


    if (OK > (status = CERT_STORE_addIdentityWithCertificateChain(*ppNewStore,
                                                                  &certificates,
                                                                  numCertificate,
                                                                  certDesc.pKeyBlob,
                                                                  certDesc.keyBlobLength)))
    {
        goto exit;
    }

#if (defined(__ENABLE_MOCANA_TPM__))
    AsymmetricKey *pRetKey = NULL;
      /* After adding a TPM RSA key to a cert store, you must reassign the secmod context to the key */
      /* We do this by retrieving the key from the cert store, then setting the context to the key */
    if(OK > (status = CERT_STORE_findIdentityByTypeFirst(*ppNewStore,
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

#ifndef __DISABLE_MOCANA_FILE_SYSTEM_HELPER__
    if (ssh_CACert != NULL)
    {
        if(cert)
            MOC_FREE((void**)&cert) ;

        if (NULL != pTempCert)
            MOC_FREE((void**)&pTempCert);
    }
#endif /* __DISABLE_MOCANA_FILE_SYSTEM_HELPER__ */

    MOC_FREE((void**)&certificates.data);
    MOC_FREE((void**)&tempCertificates.data);
    MOC_FREE((void**)&certDesc.pKeyBlob);
nocleanup:
    return status;
}
#endif /*__ENABLE_MOCANA_SSH_CLIENT_CERT_AUTH__ */
/*------------------------------------------------------------------*/

/* (REQUIRED) this callback is invoked to verify the remote server's public host key is trusted */
static int
SSHC_EXAMPLE_serverPubKeyAuthUpcall(int connectionInstance,
                                    const unsigned char *pPubKey, unsigned int pubKeyLength)
{
    /*!!!! need to move this to cert store too */
    ubyte*  pStoredHostPublicKey = NULL;
    ubyte4  storedHostPublicKeyLength = 0;
    sbyte4  result = 0;
    MOC_UNUSED(connectionInstance);
    ubyte*  pSerializedKey = NULL;
    ubyte4  serializedKeyLength = 0;
    ubyte*  pEncodedKey = NULL;
    ubyte4  encodedKeyLength = 0;
    AsymmetricKey asymKey = { 0 };
    AsymmetricKey asymKey2 = { 0 };
    hwAccelDescr    hwAccelCtx;

    if (OK > (result = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSH, &hwAccelCtx)))
        goto nocleanup;

    /* The SSH Client will only call this function, if the server's */
    /* public key matched the signature provided.  We need to now */
    /* verify that the public key is an acceptable public key (i.e. on record) */

    /* we would want to extract the server's IP address from connectionInstance */
    /* then use that to look up the appropriate host key stored file */

    /* make sure the server provided pubkey matches a public key on file */
    if (0 == MOCANA_readFile(AUTH_KEYFILE_NAME, &pStoredHostPublicKey, &storedHostPublicKeyLength))
    {
        if (OK > SSHC_parseServerAuthKeyFile(pStoredHostPublicKey,
            storedHostPublicKeyLength, &asymKey))
            goto exit;
    }
    else
    {
        if (OK > SSHC_parsePublicKeyBuffer((ubyte *)pPubKey, pubKeyLength, &asymKey))
            goto exit;

        if (OK > CRYPTO_serializeAsymKey(MOC_ASYM(hwAccelCtx) &asymKey, mocanaBlobVersion2,
            &pSerializedKey, &serializedKeyLength))
            goto exit;

        if (OK > SSHC_generateServerAuthKeyFile(pSerializedKey, serializedKeyLength,
                    &pEncodedKey, &encodedKeyLength))
            goto exit;

        /* save the server's host key for the next time we connect */
        /* this code should be smarter; needs to save host key based on server identity */
        MOCANA_writeFile(AUTH_KEYFILE_NAME, (ubyte *)pEncodedKey, encodedKeyLength);

        /* we accept first time server host keys */
        result = 1;
        goto exit;
    }

    if (OK > SSHC_parsePublicKeyBuffer((ubyte *)pPubKey, pubKeyLength, &asymKey2))
        goto exit;

    /* compare keys here */
    if (0 > CRYPTO_matchPublicKey(&asymKey, &asymKey2))
        goto exit;

    /* finally, if we do not recognize this IP address we should store the ip address in a file */
    /* a simple scheme filename convention: /keys/host/sshc/ip_<ip.ad.dr.ess>.pubkey */

    result = 1; /* we made it to the end! */

exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSH, &hwAccelCtx);

    if (NULL != pStoredHostPublicKey)
        MOCANA_freeReadFile(&pStoredHostPublicKey);

    if (NULL != pEncodedKey)
        FREE(pEncodedKey);

    if (NULL != pSerializedKey)
        MOC_FREE((void **) &pSerializedKey);

    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
    CRYPTO_uninitAsymmetricKey(&asymKey2, NULL);

nocleanup:
    return result;
}


/*------------------------------------------------------------------*/

/* (REQUIRED) returns username and what (one) authentication method the user would like to try */
/* (CUSTOMIZABLE) this function will be invoked multiple times, so different methods can be chosen */
static int
SSHC_EXAMPLE_userAuthRequestInfoUpcall(int connectionInstance,
                                       unsigned char *pAuthNameList, unsigned int authNameListLen,
                                       unsigned char **ppUserName, unsigned int *pUserNameLength,
                                       unsigned int *pMethod)
{
    /* MY creditentials for logging on to a remote server */
    int status = 0;
    MOC_UNUSED(connectionInstance);

    if(SSHC_EXAMPLE_AUTH_METHOD == MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE)
    {
        printf("Username: ");
        /* (void) cast no longer ignores unused result. Treating return
         * value as an expression removes warnings. */
        if(0 >= scanf("%15s",usrname))
        {
            printf("Error reading input\n");
            return ERR_GENERAL;
        }
        *ppUserName = (unsigned char*)usrname;
        *pUserNameLength = (unsigned int)MOC_STRLEN((sbyte *) usrname);
    }
    else
    {
        /* return username, possible to use different usernames for each logon attempt */
        *ppUserName = (unsigned char*)sshc_exampleUserName;
        *pUserNameLength = (MOC_STRLEN((sbyte *)sshc_exampleUserName));
    }
    /* return authentication method type, possible to use different authentication method for each logon attempt */
    *pMethod = SSHC_EXAMPLE_AUTH_METHOD;

    return status;
}


/*------------------------------------------------------------------*/

/* (OPTIONAL) returns username and what (one) authentication method the user would like to try */
/* (CUSTOMIZABLE) this function will be invoked multiple times, so different methods can be chosen */
static int
SSHC_EXAMPLE_userAuthRequestInfoUpcallEx(int connectionInstance,
                                       unsigned char messageCode, unsigned int methodType,
                                       unsigned char *pAuthNameList, unsigned int authNameListLen,
                                       unsigned char **ppUserName, unsigned int *pUserNameLength,
                                       unsigned int *pMethod, sbyte4 *pSendSignature)
{
    /* MY creditentials for logging on to a remote server */
    int status = 0;
    MOC_UNUSED(connectionInstance);
    unsigned int selectedAuthMethod = 0;

    /*  if there are no more authentication methods left, nothing else to do */
    if (AUTH_METHOD_COUNT <= authenticationMethodIndex)
    {
        selectedAuthMethod = 0;
        goto exit;
    }

    selectedAuthMethod = authenticationMethods[authenticationMethodIndex];

    if (SSH_MSG_USERAUTH_FAILURE == messageCode)
    {
        /*  if we recieve this message code, we can try a different authenticaiton method  */

        /*  check that the current authentication method selected matches the authentication
        *   method associated with messageCode. If these values are not the same, something
        *   might have gone wrong.
        *   */
        if (selectedAuthMethod != methodType)
        {
            selectedAuthMethod = 0;
            goto exit;
        }

        /*  If authentication method associated with messageCode is MOCANA_SSH_AUTH_PASSWORD
         *  we could try a different method, or retry password. For this example, we will
         *  retry password authentication.
         *  */
        if (MOCANA_SSH_AUTH_PASSWORD             == methodType)
        {
            goto retry;
        }

        authenticationMethodIndex++;
        if (AUTH_METHOD_COUNT <= authenticationMethodIndex)
        {
            selectedAuthMethod = 0;
            goto exit;
        }

        /*  Select different authentication method */
        selectedAuthMethod = authenticationMethods[authenticationMethodIndex];
        if ((MOCANA_SSH_AUTH_PUBLIC_KEY == selectedAuthMethod) ||
            (MOCANA_SSH_AUTH_CERT       == selectedAuthMethod))
         {
            *pSendSignature = FALSE;
         }
    }
    else if (SSH_MSG_SERVICE_ACCEPT == messageCode)
    {

        /*  If this messageCode is recieved, this is the first authentication attempt.
         *  (optional) We can set pSendSignature to FALSE in order to query if the algorithm
         *  chosen is supported first. This value is only used if certificate or public key
         *  authentication method is used.
         *  */
        if ((MOCANA_SSH_AUTH_PUBLIC_KEY == selectedAuthMethod) ||
            (MOCANA_SSH_AUTH_CERT       == selectedAuthMethod))
         {
            *pSendSignature = FALSE;
         }
    }
    else if (SSH_MSG_USERAUTH_PK_OK == messageCode)
    {
        /*  check that the current authentication method selected matches the authentication
        *   method associated with messageCode. If these values are not the same, something
        *   might have gone wrong.
        *   */

        if (selectedAuthMethod != methodType)
        {
            selectedAuthMethod = 0;
            goto exit;
        }

        /*  If authentication method associated with messageCode is MOCANA_SSH_AUTH_PASSWORD or
         *  MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE we could try a different method. For this example,
         *  we will return no method type if this message is recieved for password authentication.
         *  */
        if ((MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE == methodType) ||
            (MOCANA_SSH_AUTH_PASSWORD             == methodType))
        {
            selectedAuthMethod = 0;
            goto exit;
        }

        /*  If we got here, we are using either certificate or public key authentication, and server
         *  supports the algorithm that was sent, we now want to set pSendSignature to TRUE in order
         *  to send the signature in the next authentication message.
         *  */
        *pSendSignature = TRUE;
    }

retry:
    if(MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE == selectedAuthMethod)
    {
        printf("Username: ");
        if(0 >= scanf("%15s",usrname))
        {
            printf("Error reading input\n");
            status = ERR_GENERAL;
            goto exit;
        }
        *ppUserName = (unsigned char*)usrname;
        *pUserNameLength = (unsigned int)MOC_STRLEN((sbyte *)usrname);
    }
    else
    {
        /* return username, possible to use different usernames for each logon attempt */
        *ppUserName = (unsigned char*)sshc_exampleUserName;
        *pUserNameLength = (MOC_STRLEN((sbyte *)sshc_exampleUserName));
    }

exit:
    /*  return authentication method type */
    *pMethod = selectedAuthMethod;

    return status;
}


/*------------------------------------------------------------------*/

/* (OPTIONAL) return what password to use for the given user(name) */
static int
SSHC_EXAMPLE_userPasswordUpcall(int connectionInstance,
                                unsigned char *pUserName, unsigned int userNameLength,
                                unsigned char **ppUserPassword, unsigned int *pUserPasswordLength)
{
    /* MY creditentials for logging on to a remote server */
    MOC_UNUSED(connectionInstance);
    MOC_UNUSED(pUserName);
    MOC_UNUSED(userNameLength);

    if(SSHC_EXAMPLE_AUTH_METHOD == MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE)
    {
        /* (void) cast no longer ignores unused result. Treating return
         * value as an expression removes warnings. */
        printf("Password: ");
        if(0 >= scanf("%15s",password))     /* For unix/linux/BSD getpass() can be used for getting password */
        {
            printf("Error reading input\n");
            return ERR_GENERAL;
        }
        *ppUserPassword = (unsigned char*)password;
        *pUserPasswordLength = (unsigned int)MOC_STRLEN((sbyte *)password);
    }
    else
    {
        /* return password for simple username/password authentication */
        *ppUserPassword = (unsigned char*)sshc_examplePassword;
        *pUserPasswordLength = MOC_STRLEN((sbyte *)sshc_examplePassword);
    }

    return 0;
}

#ifdef __ENABLE_MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE__
static int
SSHC_EXAMPLE_keyboardInteractiveProcessRequestUpcall(int connectionInstance,
    keyIntInfoReq *pRequestInfo, keyIntInfoResp *pResponseInfo)
{
    MSTATUS status;
    keyIntResp *pNewResp = NULL;
    ubyte4 i;
    ubyte pResponse[128];
    ubyte *pResp = NULL;
    ubyte4 respLen = 0;

    if ((NULL == pRequestInfo) || (NULL == pResponseInfo))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (pRequestInfo->nameLen > 0)
    {
        printf("%s\n", pRequestInfo->pName);
    }

    if (pRequestInfo->instructionLen > 0)
    {
        printf("%s\n", pRequestInfo->pInstruction);
    }

    if (0 == pRequestInfo->numPrompts)
    {
        /* there are no prompts to display */
        status = OK;
        pResponseInfo->numResponses = 0;
        goto exit;
    }

    /*
     * RFC 4256:
     *      For each prompt, the corresponding echo field indicates whether the
     *      user input should be echoed as characters are typed.
     *
     * This example ignores the echo field.
     */
    for (i = 0; i < pRequestInfo->numPrompts; i++)
    {
        printf("%s\n", pRequestInfo->prompts[i]->pPrompt);
        /* get input from user */
        if(0 >= scanf("%127s", pResponse))
        {
            printf("Error reading input\n");
            status = ERR_GENERAL;
            goto exit;
        }

        status = MOC_MALLOC((void **)&pNewResp, sizeof(*pNewResp));
        if(OK != status)
            goto exit;

        /* make copy of buffer for keyIntInfoResp */
        respLen = MOC_STRLEN((const sbyte *)pResponse);
        status = MOC_MALLOC((void **)&pResp, respLen + 1);
        if (OK != status)
            goto exit;

        status = MOC_MEMCPY(pResp, pResponse, respLen);
        if (OK != status)
            goto exit;

        pResp[respLen] = '\0';
        pNewResp->pResponse = pResp;
        pNewResp->responseLen = respLen;
        pResponseInfo->responses[i] = pNewResp;
    }
    pResponseInfo->numResponses = pRequestInfo->numPrompts;

exit:
    return status;
}

static sbyte4 SSHC_EXAMPLE_releaseKeyboardInteractiveResponse(sbyte4 connectionInstance,
                                                              keyIntInfoResp *pResponse)
{
    ubyte4 i;
    for(i = 0; i < pResponse->numResponses; i++)
    {
        MOC_FREE((void **)&(pResponse->responses[i]->pResponse));
        MOC_FREE((void **)&(pResponse->responses[i]));
    }

    return OK;
}
#endif

static sbyte4
SSHC_EXAMPLE_certstatus(sbyte4 connectionInstance,
                         sbyte4 cert_status, ubyte *pCertificate, ubyte4 certLen,
                         certChainPtr pCertChain, const ubyte *pAnchorCert, ubyte4 anchorCertLen)
{
    MSTATUS status = OK;
    DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, (sbyte *)"SSHC_EXAMPLE_certstatus:");

    if(cert_status != OK) {
        status = cert_status ;
        goto exit ;
    }

#if ((defined(__ENABLE_MOCANA_SSH_OCSP_SUPPORT__)) && (defined(__ENABLE_MOCANA_OCSP_CLIENT__)) && \
        (defined(__ENABLE_MOCANA_OCSP_CERT_VERIFY__)))
    status = OCSP_CLIENT_getCertStatus((sbyte *) ocsp_ResponderUrl, pCertificate,certLen,pCertChain, pAnchorCert, anchorCertLen  ) ;
#endif

exit:
    return status ;
}

/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_SSH_CLIENT_EXAMPLE_AUTH__
/* (OPTIONAL) this function is used to retrieve MY public/private host key pair (in Mocana keyblob format) */
static int
SSHC_EXAMPLE_retrieveAuthKeys(int connectionInstance,
                              unsigned char **ppRetKeyBlob, unsigned int *pRetKeyBlobLength)
{
    int     status;
    ubyte*       pKeyBlob = NULL;
    ubyte4       keyBlobLen;
#ifdef __ENABLE_MOCANA_TAP__
    MocAsymKey  pMocAsymKey = NULL;
#endif
    MOC_UNUSED(connectionInstance);

    hwAccelDescr  hwAccelCtx;
    AsymmetricKey asymKey;
    *ppRetKeyBlob = NULL;
    *pRetKeyBlobLength = 0;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSH, &hwAccelCtx)))
        goto nocleanup;

#ifdef __ENABLE_MOCANA_DATA_PROTECTION__
    if (0 > (status = MOCANA_readFileEx(KEYBLOB_AUTH_KEY_FILE_NAME, &pKeyBlob, &keyBlobLen, TRUE)))
#else
    if (0 > (status = MOCANA_readFile(KEYBLOB_AUTH_KEY_FILE_NAME, &pKeyBlob, &keyBlobLen)))
#endif
    {
        status = ERR_SSH_MISSING_KEY_FILE;
        goto exit;
    }

    status = CRYPTO_initAsymmetricKey(&asymKey);
    if (OK != status)
        goto exit;

    status = CRYPTO_deserializeAsymKey(MOC_ASYM(hwAccelCtx) pKeyBlob, keyBlobLen, NULL, &asymKey);
    if (OK != status)
        goto exit;

    status = CRYPTO_serializeAsymKey(MOC_ASYM(hwAccelCtx) &asymKey, mocanaBlobVersion2, ppRetKeyBlob, pRetKeyBlobLength);
    if (OK != status)
        goto exit;

exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSH, &hwAccelCtx);

    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

    if (pKeyBlob)
    {
        MOC_FREE((void**)&pKeyBlob);
    }

nocleanup:
    return status;

} /* SSHC_EXAMPLE_retrieveAuthKeys */
#endif  /* __ENABLE_MOCANA_SSH_CLIENT_EXAMPLE_AUTH__ */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_SSH_CLIENT_EXAMPLE_AUTH__
/* (OPTIONAL) this is for releasing any memory allocated (see SSHC_EXAMPLE_retrieveAuthKeys()) */
/* for (MY) public/private host key pair (in Mocana keyblob format) */
static sbyte4
SSHC_EXAMPLE_releaseAuthKeys(sbyte4 connectionInstance, ubyte **ppFreeKeyBlob)
{
    MOC_UNUSED(connectionInstance);

    MOCANA_freeReadFile(ppFreeKeyBlob);

    return 0;
}
#endif /*__ENABLE_MOCANA_SSH_CLIENT_EXAMPLE_AUTH__ */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_SSH_CLIENT_EXAMPLE_AUTH__
static int
SSHC_EXAMPLE_testAuthKeys(void)
{
    ubyte*  pKeyBlob = NULL;
    ubyte4  keyBlobLength;
    int     status;

    if (0 <= (status = MOCANA_readFile(KEYBLOB_AUTH_KEY_FILE_NAME, &pKeyBlob, &keyBlobLength)))
        MOCANA_freeReadFile(&pKeyBlob);

    return status;
}
#endif /* __ENABLE_MOCANA_SSH_CLIENT_EXAMPLE_AUTH__ */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_SSH_CLIENT_EXAMPLE_AUTH__
/* (OPTIONAL) this is example code for generating on the fly (MY) public/private host key pair (in Mocana keyblob format) */
static int
SSHC_EXAMPLE_computeAuthKeys(void)
{
    ubyte*  pKeyBlob = NULL;
    ubyte4  keyBlobLen;
    int     status;
    ubyte* pEncodedKeyBlob = NULL;
    ubyte4 encodedKeyBlobLen;
    AsymmetricKey asymKey = { 0 };
    hwAccelDescr hwAccelCtx;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSH, &hwAccelCtx)))
        goto nocleanup;

    RTOS_sleepMS(1000);

    /* check for pre-existing set of host keys */
    if (0 > (status = SSHC_EXAMPLE_testAuthKeys()))
    {
        DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, (sbyte *) "SSHC_EXAMPLE_computeAuthKeys: host key does not exist, computing new key...");

        /* if not, compute new host keys */
#if defined(__ENABLE_MOCANA_PQC__) && defined(__ENABLE_MOCANA_ECC__)
        if (0 > (status = CA_MGMT_generateNakedKeyPQC(akt_hybrid, cid_EC_P256, cid_PQC_MLDSA_44, &pKeyBlob, &keyBlobLen)))
            goto exit;
#elif defined(__ENABLE_MOCANA_PQC__)
        if (0 > (status = CA_MGMT_generateNakedKeyPQC(akt_qs, 0, cid_PQC_MLDSA_44, &pKeyBlob, &keyBlobLen)))
            goto exit;
#elif defined(__ENABLE_MOCANA_ECC_EDDSA_25519__)
        if (0 > (status = CA_MGMT_generateNakedKey(akt_ecc_ed, 255, &pKeyBlob, &keyBlobLen)))
            goto exit;
#elif defined(__ENABLE_MOCANA_ECC__)
        if (0 > (status = CA_MGMT_generateNakedKey(akt_ecc, 256, &pKeyBlob, &keyBlobLen)))
            goto exit;
#elif defined ( __ENABLE_MOCANA_SSH_RSA_SUPPORT__)
        if (0 > (status = CA_MGMT_generateNakedKey(akt_rsa, 2048, &pKeyBlob, &keyBlobLen)))
            goto exit;
#elif defined (__ENABLE_MOCANA_SSH_DSA_SUPPORT__)
        if (0 > (status = CA_MGMT_generateNakedKey(akt_dsa, 2048, &pKeyBlob, &keyBlobLen)))
            goto exit;
#endif

        /* save keyblob for future reference (see SSHC_EXAMPLE_retrieveAuthKeys()) */
        status = MOCANA_writeFile(KEYBLOB_AUTH_KEY_FILE_NAME, pKeyBlob, keyBlobLen);

        DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, (sbyte *) "SSHC_EXAMPLE_computeAuthKeys: host key computation completed.");

        /* At this point, the client's public key can generated in the BASE64 encoded format, so that it is
         * ready to be exported to the server. The following code snippet will do the needful.
         */

         status = SSHC_generateServerAuthKeyFile(pKeyBlob, keyBlobLen, &pEncodedKeyBlob,
            &encodedKeyBlobLen);
         if (OK != status)
             goto exit;

         /* save public key in SSH Public Key Format for server authorization */
         MOCANA_writeFile(SSH_PUBLIC_KEY_FILE_NAME, pEncodedKeyBlob, encodedKeyBlobLen);
         SSHC_freeGenerateServerAuthKeyFile(&pEncodedKeyBlob);
    }

exit:
    if (NULL != pKeyBlob)
    {
        /* an error must have occurred, release */
        CA_MGMT_freeNakedKey(&pKeyBlob);
    }
    
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSH, &hwAccelCtx);

nocleanup:

    return status;
}
#endif /* __ENABLE_MOCANA_SSH_CLIENT_EXAMPLE_AUTH__ */


/*------------------------------------------------------------------*/

/* (OPTIONAL) callback notification that authentication was successful */
static void
SSHC_EXAMPLE_authOpen(int connectionInstance)
{
    printf("Connection authenticated: %d\n", connectionInstance);
}


/*------------------------------------------------------------------*/

static sbyte4
SSHC_EXAMPLE_openFile(int connectionInstance, sftpcFileHandleDescr *p_sftpFileHandleDescr)
{
    MOC_UNUSED(connectionInstance);
    MOC_UNUSED(p_sftpFileHandleDescr);

    return SSH_FTP_OK;
}


/*------------------------------------------------------------------*/

static sbyte4
SSHC_EXAMPLE_fileClosed(int connectionInstance, sftpcFileHandleDescr *p_sftpFileHandleDescr)
{
    sbyte*  pBuffer;
    MOC_UNUSED(connectionInstance);

    if (NULL == (pBuffer = SSHC_sftpWriteBuffer(p_sftpFileHandleDescr)))
        goto exit;

    FREE(pBuffer);

    /* clear out just for giggles */
    SSHC_sftpSetWriteBuffer(p_sftpFileHandleDescr,  NULL);

exit:
    return SSH_FTP_OK;
}


/*------------------------------------------------------------------*/

#define EXAMPLE_PUT_CHUNK_SIZE      (2048)

static sbyte4
SSHC_EXAMPLE_putFileBlockRead(int connectionInstance, sftpcFileHandleDescr *p_sftpFileHandleDescr)
{
    /* we're doing a PUT's read here */
    FileDescriptor fd = (FileDescriptor) SSHC_sftpGetCookie(p_sftpFileHandleDescr);
    sbyte*  pBuffer  = NULL;
    sbyte4  fileSize = 0;
    sbyte4  bytesRead = 0;
    sbyte4  fileLoc  = SSHC_sftpWriteLocation(p_sftpFileHandleDescr);
    sbyte4  bufferSize;
    sbyte4  status   = SSH_FTP_OK;
    MOC_UNUSED(connectionInstance);

    /* determine file size */
    FMGMT_fseek (fd, 0, MSEEK_END);
    FMGMT_ftell (fd, (ubyte4 *) &fileSize);

    if (0 == fileLoc)
    {
        /* first time in... pre-allocate read buffer */
        SSHC_sftpSetWriteBuffer(p_sftpFileHandleDescr, NULL);
        SSHC_sftpSetWriteBufferSize(p_sftpFileHandleDescr, 0);

        /* read 2048 byte chunks of the file at a time */
        bufferSize = (EXAMPLE_PUT_CHUNK_SIZE > fileSize) ? fileSize : EXAMPLE_PUT_CHUNK_SIZE;

        if (NULL == (pBuffer = MALLOC(bufferSize)))
        {
            status = SSH_FTP_FAILURE;
            goto exit;
        }

        /* set back to the start of the file */
        FMGMT_fseek (fd, 0, MSEEK_SET);

        FMGMT_fread ((ubyte *) pBuffer, 1, bufferSize, fd, (ubyte4 *) &bytesRead);
        if (bufferSize > bytesRead)
        {
            status = SSH_FTP_FAILURE;
            goto exit;
        }

        /* set up for return - this is the data sent ('put') to the server */
        SSHC_sftpSetWriteBuffer(p_sftpFileHandleDescr, pBuffer);
        SSHC_sftpSetWriteBufferSize(p_sftpFileHandleDescr, bufferSize);
        pBuffer = NULL;
    }
    else if (fileLoc < fileSize)
    {
        /* read the next 2048 byte chunk... */
        bufferSize = (EXAMPLE_PUT_CHUNK_SIZE > (fileSize - fileLoc)) ? (fileSize - fileLoc) : EXAMPLE_PUT_CHUNK_SIZE;

        /* get the buffer, and setup in case of read failure */
        pBuffer = SSHC_sftpWriteBuffer(p_sftpFileHandleDescr);
        SSHC_sftpSetWriteBuffer(p_sftpFileHandleDescr, NULL);
        SSHC_sftpSetWriteBufferSize(p_sftpFileHandleDescr, 0);

        /* set to current position in the file --- this is probably not necessary */
        FMGMT_fseek (fd, fileLoc, MSEEK_SET);

        /* read the chunk */
        FMGMT_fread ((ubyte *) pBuffer, 1, bufferSize, fd, (ubyte4 *) &bytesRead);
        if (bufferSize > bytesRead)
        {
            status = SSH_FTP_FAILURE;
            goto exit;
        }

        /* set the number of bytes waiting to be sent */
        SSHC_sftpSetWriteBuffer(p_sftpFileHandleDescr, pBuffer);
        SSHC_sftpSetWriteBufferSize(p_sftpFileHandleDescr, bufferSize);
        pBuffer = NULL;
    }
    else
    {
        /* end of file reached --- pBuffer will be freed */
        pBuffer = SSHC_sftpWriteBuffer(p_sftpFileHandleDescr);

        SSHC_sftpSetWriteBuffer(p_sftpFileHandleDescr, NULL);
        SSHC_sftpSetWriteBufferSize(p_sftpFileHandleDescr, 0);
    }

exit:
    if (NULL != pBuffer)
        FREE(pBuffer);

    return status;
}


/*------------------------------------------------------------------*/

static sbyte4
SSHC_EXAMPLE_getFileBlockWrite(int connectionInstance, sftpcFileHandleDescr *p_sftpFileHandleDescr)
{
    /* we're doing a GET's write here */
    FileDescriptor fd = (FileDescriptor) SSHC_sftpGetCookie(p_sftpFileHandleDescr);
    sbyte*  pBuffer;
    sbyte4  bufferSize;
    sbyte4  bytesWritten = 0;
    sbyte4  offset;
    sbyte4  status = SSH_FTP_OK;
    MOC_UNUSED(connectionInstance);

    /* fetch the buffer, and max bytes that can be sent at the moment */
    offset     = SSHC_sftpReadLocation(p_sftpFileHandleDescr);
    pBuffer    = SSHC_sftpReadBuffer(p_sftpFileHandleDescr);
    bufferSize = SSHC_sftpReadBufferSize(p_sftpFileHandleDescr);

    /* set the position to write from */
    FMGMT_fseek (fd, offset, MSEEK_SET);

    /* write the bytes */
    FMGMT_fwrite ((ubyte *) pBuffer, 1, bufferSize, fd, (ubyte4 *) &bytesWritten);
    if (bufferSize != bytesWritten)
    {
        /* write failed */
        status = SSH_FTP_FAILURE;
    }

    return status;
}

#ifdef __ENABLE_MOCANA_SSH_AUTH_BANNER__
static void
SSHC_EXAMPLE_displayBanner(sbyte4 connectionInstance, ubyte *pBanner,ubyte4 msgLength, ubyte *pMsgLanguageTag)
{

    ubyte4 i;

    for(i = 0; i < msgLength ; i++)
        printf("%c", pBanner[i]);


    printf("\nLanguage Tag: %d\n", *pMsgLanguageTag);

}
#endif

/*------------------------------------------------------------------*/

static void
SSHC_EXAMPLE_initSshCommands(void)
{
    /* Verify remote server's public host key */
    SSHC_sshClientSettings()->funcPtrServerPubKeyAuth              = SSHC_EXAMPLE_serverPubKeyAuthUpcall;

#ifdef __ENABLE_MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE__
    SSHC_sshClientSettings()->funcPtrKeyIntAuthResp                = SSHC_EXAMPLE_keyboardInteractiveProcessRequestUpcall;
    SSHC_sshClientSettings()->funcPtrReleaseKeyIntAuthResp         = SSHC_EXAMPLE_releaseKeyboardInteractiveResponse;
#endif

    /* Retreive creditentials for connecting to a remote server */
    SSHC_sshClientSettings()->funcPtrRetrieveUserAuthRequestInfo   = SSHC_EXAMPLE_userAuthRequestInfoUpcall;
    SSHC_sshClientSettings()->funcPtrRetrieveUserAuthRequestInfoEx = SSHC_EXAMPLE_userAuthRequestInfoUpcallEx;
    SSHC_sshClientSettings()->funcPtrRetrieveUserPassword          = SSHC_EXAMPLE_userPasswordUpcall;
#if ((defined(__ENABLE_MOCANA_SSH_CLIENT_EXAMPLE_AUTH__)) && (!defined(__ENABLE_MOCANA_SSH_CLIENT_CERT_AUTH__)))
    SSHC_sshClientSettings()->funcPtrRetrieveNakedAuthKeys         = SSHC_EXAMPLE_retrieveAuthKeys;
    SSHC_sshClientSettings()->funcPtrReleaseNakedAuthKeys          = SSHC_EXAMPLE_releaseAuthKeys;
#endif
    SSHC_sshClientSettings()->funcPtrCertStatus                    = SSHC_EXAMPLE_certstatus ;
#ifdef __ENABLE_MOCANA_SSH_AUTH_BANNER__
    SSHC_sshClientSettings()->funcPtrDisplayBanner                 = SSHC_EXAMPLE_displayBanner;
#endif

    /* Callback notification for successful authentication to remote server */
    SSHC_sshClientSettings()->funcPtrAuthOpen                      = SSHC_EXAMPLE_authOpen;
}


/*------------------------------------------------------------------*/

static void
SSHC_EXAMPLE_initSftpCommands(void)
{
    /* Callbacks for file i/o operations */
    SSHC_sftpClientSettings()->funcPtrOpenFileClientUpcall         = SSHC_EXAMPLE_openFile;
    SSHC_sftpClientSettings()->funcPtrCloseFileUpcall              = SSHC_EXAMPLE_fileClosed;
    SSHC_sftpClientSettings()->funcPtrWriteFileUpcall              = SSHC_EXAMPLE_putFileBlockRead;
    SSHC_sftpClientSettings()->funcPtrReadFileUpcall               = SSHC_EXAMPLE_getFileBlockWrite;
}


/*------------------------------------------------------------------*/

/* example SFTP PUT file on remote server */
static int
SSHC_EXAMPLE_putFile(int connectionInstance)
{
    sftpcFileHandleDescr*   pSftpPutFile  = NULL;
    sftpcFileHandleDescr*   pSftpFileInfo = NULL;
    ubyte*                  fileName = (ubyte *)"./temp.txt";
    FileDescriptor          fd = 0;
    ubyte4                  size;
    ubyte4                  type;
    ubyte4                  permissions;
    sbyte4                  bytesWritten;
    intBoolean              isPresent;
    int                     status = 0;

    /* request server to open a file for writing */
    /* on return, we will have a file handle for manipulating a file on the remote server */
    if (OK > (status = SSHC_openFile(connectionInstance, fileName, (ubyte4)MOC_STRLEN((sbyte *)fileName),
                                     SFTP_OPEN_FILE_WRITE_BINARY, &pSftpPutFile)))
    {
        goto exit;
    }

    /* check if request was successful */
    if (SSH_FTP_OK != SSHC_sftpRequestStatusCode(pSftpPutFile))
    {
        /* unable to open the file for writing */
        printf("SSHC_EXAMPLE_putFile: unable to create a file on remote server, sftp_status = %d\n", SSHC_sftpRequestStatusCode(pSftpPutFile));
        goto exit;
    }

    if (OK == FMGMT_fopen ((sbyte *) "src.txt", (sbyte *) "rb", &fd))
    {
        /* write new test file, if none exists */
        /* create file - this is done to automate the SSH client/server testing */
        /* So now, there is no need to create "src.txt" manually every time we test */
        if (OK == FMGMT_fopen ((sbyte *) "src.txt", (sbyte *) "w", &fd))
        {
            /* unable to create file */
            printf("SSHC_EXAMPLE_putFile: call to FMGMT_fopen(\"src.txt\") failed while creating file\n");
            goto exit;
        }
        else
        {
            char test_str[] = "Hello world!\n";

            FMGMT_fwrite ((ubyte *) test_str, 1, sizeof(test_str), fd, (ubyte4 *) &bytesWritten);

            /* close the file */
            FMGMT_fclose (&fd);
        }

        if (OK == FMGMT_fopen ((sbyte *) "src.txt", (sbyte *) "rb", &fd))
        {
            /* unable to open file */
            printf("SSHC_EXAMPLE_putFile: call to FMGMT_fopen(\"src.txt\") failed.\n");
            goto exit;
        }
    }

    /* store the file descriptor (fd) for the transfer upcalls */
    SSHC_sftpSetCookie(pSftpPutFile, fd);

    /* kick off the SFTP file transfer */
    if (OK > (status = SSHC_writeFile(connectionInstance, pSftpPutFile)))
    {
        /* PUT */
        printf("SSHC_EXAMPLE_putFile: SSHC_writeFile() failed, status = %d.\n", status);
        goto exit;
    }

    /* at this point the file transfer should be complete, check status to ensure */
    if (SSH_FTP_OK != SSHC_sftpRequestStatusCode(pSftpPutFile))
    {
        /* for writes, if the entire file was written successfully, the status should be ok */
        printf("SSHC_EXAMPLE_putFile: file put did not complete, sftp_status = %d\n", SSHC_sftpRequestStatusCode(pSftpPutFile));
    }

    /* output the number of bytes written to the server */
    /* x bytes written to sftp server */
    printf("SSHC_EXAMPLE_putFile: PUT file wrote %d bytes\n", SSHC_sftpNumBytesWritten(pSftpPutFile));

    /* locally close the file descriptor (fd), which was opened above */
    FMGMT_fclose (&fd);

    /* free the handle that was opened by SSHC_openFile() */
    /* SSH servers may have a limited number of handles available, be sure to close them! */
    if (OK > (status = SSHC_closeFile(connectionInstance, pSftpPutFile)))
        goto exit;

    /* to prevent double close */
    pSftpPutFile = NULL;

    /* (OPTIONAL) confirm file PUT was successful for giggles */

    /* get remote file stats for the file we just PUT on the remote server */
    if (OK > (status = SSHC_getFileStat(connectionInstance, fileName, (ubyte4)MOC_STRLEN((sbyte *)fileName), &pSftpFileInfo)))
        goto exit;

    /* if the request for file stats is successful we can dump them out */
    if (SSH_FTP_OK == SSHC_sftpRequestStatusCode(pSftpFileInfo))
    {
        printf("SSHC_EXAMPLE_putFile: SSHC_getFileStat() returned SSH_FTP_OK.\n");

        /* sometimes file stats are missing due to server support, so we must check if the stat is actually present */
        SSHC_sftpGetDirEntryFileSize(connectionInstance, pSftpFileInfo, &size, &isPresent);
        if (isPresent)
            printf("SSHC_EXAMPLE_putFile: size = %d\n", size);

        SSHC_sftpGetDirEntryFileType(connectionInstance, pSftpFileInfo, &type, &isPresent);
        if (isPresent)
            printf("SSHC_EXAMPLE_putFile: type = %d\n", type);

        SSHC_sftpGetDirEntryFilePermission(connectionInstance, pSftpFileInfo, &permissions, &isPresent);
        if (isPresent)
            printf("SSHC_EXAMPLE_putFile: permissions = %d\n", permissions);

        printf("\n");
    }
    else
    {
        printf("SSHC_EXAMPLE_putFile: SSHC_getFileStat() failed, sftp_status = %d.\n", SSHC_sftpRequestStatusCode(pSftpFileInfo));
    }

    /* free the handle that was opened by SSHC_getFileStat() */
    /* SSH servers may have a limited number of handles available, be sure to close them! */
    if (OK > (status = SSHC_freeHandle(connectionInstance, &pSftpFileInfo)))
        goto exit;

exit:
    if (0 != fd)
        FMGMT_fclose (&fd);

    if (NULL != pSftpPutFile)
        SSHC_closeFile(connectionInstance, pSftpPutFile);

    return status;

} /* SSHC_EXAMPLE_putFile */


/*------------------------------------------------------------------*/

/* example SFTP GET file from remote server */
static int
SSHC_EXAMPLE_getFile(int connectionInstance)
{
    ubyte*                  fileName = (ubyte *)"./temp.txt";
    FileDescriptor          fd = 0;
    sftpcFileHandleDescr*   pSftpGetFile = NULL;
    int                     status = OK;

    /* request server to open a file for reading */
    /* on return, we will have a file handle for manipulating a file on the remote server */
    if (OK > (status = SSHC_openFile(connectionInstance, fileName, (ubyte4)MOC_STRLEN((sbyte *)fileName),
                                     SFTP_OPEN_FILE_READ_BINARY, &pSftpGetFile)))
    {
        goto exit;
    }

    /* check if request was successful */
    if (SSH_FTP_OK != SSHC_sftpRequestStatusCode(pSftpGetFile))
    {
        /* unable to open the file for writing */
        printf("SSHC_EXAMPLE_getFile: unable to create a file on remote server, sftp_status = %d\n", SSHC_sftpRequestStatusCode(pSftpGetFile));
        goto exit;
    }

    /* open local file to make copy of server's file */
    if (OK == FMGMT_fopen ((sbyte *) "dst.txt", (sbyte *) "wb", &fd))
    {
        /* unable to create local file */
        printf("SSHC_EXAMPLE_getFile: call to FMGMT_fopen(\"dst.txt\") failed.\n");
        SSHC_closeFile(connectionInstance, pSftpGetFile);
        goto exit;
    }

    /* store the file descriptor (fd) for the transfer upcalls */
    SSHC_sftpSetCookie(pSftpGetFile, fd);

    /* kick off the SFTP file transfer */
    if (OK > (status = SSHC_readFile(connectionInstance, pSftpGetFile)))
    {
        /* GET */
        printf("SSHC_EXAMPLE_getFile: SSHC_readFile() failed, status = %d.\n", status);
        SSHC_closeFile(connectionInstance, pSftpGetFile);
        goto exit;
    }

    /* at this point the file transfer should be complete, check status to ensure */
    if (SSH_FTP_EOF != SSHC_sftpRequestStatusCode(pSftpGetFile))
    {
        /* for reads, if the entire file was read successfully, the status should be eof */
        printf("SSHC_EXAMPLE_getFile: file get did not complete, sftp_status = %d\n", SSHC_sftpRequestStatusCode(pSftpGetFile));
    }

    /* x bytes read from sftp server */
    printf("SSHC_EXAMPLE_getFile: GET file read %d bytes\n", SSHC_sftpNumBytesRead(pSftpGetFile));

exit:
    if (0 != fd)
        FMGMT_fclose (&fd);

    if (NULL != pSftpGetFile)
        SSHC_closeFile(connectionInstance, pSftpGetFile);

    return status;

} /* SSHC_EXAMPLE_getFile */


/*------------------------------------------------------------------*/

/* example SFTP create directory on remote server */
static int
SSHC_EXAMPLE_createDirectory(int connectionInstance)
{
    sftpcFileHandleDescr*   pSftpFileInfo = NULL;
    int                     status;

    /* create a directory */
    if (OK > (status = SSHC_mkdir(connectionInstance, (ubyte *)"./hello", 7, &pSftpFileInfo, NULL)))
        goto exit;

    if (SSH_FTP_OK != SSHC_sftpRequestStatusCode(pSftpFileInfo))
        printf("SSHC_EXAMPLE_createDirectory: SSHC_mkdir() did not complete, sftp_status = %d\n", SSHC_sftpRequestStatusCode(pSftpFileInfo));

    /* release handle from previous call to SSHC_mkdir */
    if (OK > (status = SSHC_freeHandle(connectionInstance, &pSftpFileInfo)))
        goto exit;

exit:
    return status;

} /* SSHC_EXAMPLE_createDirectory */


/*------------------------------------------------------------------*/

/* example SFTP directory list on remote server */
static int
SSHC_EXAMPLE_directoryListing(int connectionInstance)
{
    sftpcFileHandleDescr*   pSftpFileInfo = NULL;
    sftpcFileHandleDescr*   pSftpDirInfo = NULL;
    ubyte*                  pRealpath = NULL;
    ubyte4                  realPathLen = 0;
    ubyte*                  pFilename = NULL;
    ubyte4                  filenameLen;
    ubyte4                  size;
    ubyte4                  type;
    ubyte4                  permissions;
    intBoolean              isPresent;
    int                     status;

    /* usually, first step is to find real path for user's home directory on the remote server */
    if (OK > (status = SSHC_realpath(connectionInstance, (ubyte *)".", 1, &pSftpFileInfo, &pRealpath, &realPathLen)))
        goto exit;

    if (SSH_FTP_OK != SSHC_sftpRequestStatusCode(pSftpFileInfo))
    {
        /* real path failed... */
        printf("SSHC_EXAMPLE_directoryListing: SSHC_realpath() did not complete, sftp_status = %d\n", SSHC_sftpRequestStatusCode(pSftpFileInfo));
        goto exit;
    }

    printf("SSHC_EXAMPLE_directoryListing: SSHC_realpath(\".\") return realpath = %s\n", pRealpath);

    /* release handle from previous call to SSHC_realpath */
    if (OK > (status = SSHC_freeHandle(connectionInstance, &pSftpFileInfo)))
        goto exit;

    /* open user's home directory */
    if (OK > (status = SSHC_openDirectory(connectionInstance, pRealpath, realPathLen, &pSftpDirInfo)))
        goto exit;

    SSHC_freeFilename(connectionInstance, &pRealpath);

    /* check if directory open successful on remote server */
    if (SSH_FTP_OK != SSHC_sftpRequestStatusCode(pSftpDirInfo))
    {
        printf("SSHC_EXAMPLE_directoryListing: SSHC_openDirectory() did not complete, sftp_status = %d\n", SSHC_sftpRequestStatusCode(pSftpDirInfo));

        /* close the directory and free the handle to prevent memory leaks */
        SSHC_closeDirectory(connectionInstance, pSftpDirInfo);
        SSHC_freeHandle(connectionInstance, &pSftpDirInfo);
    }
    else
    {
        /* iterate through directory one file at a time outputing stats */
        do
        {
            if (OK > (status = SSHC_readDirectory(connectionInstance, pSftpDirInfo, &pFilename, &filenameLen)))
            {
                SSHC_closeDirectory(connectionInstance, pSftpDirInfo);
                SSHC_freeHandle(connectionInstance, &pSftpDirInfo);
                goto exit;
            }

            if (SSH_FTP_OK == SSHC_sftpRequestStatusCode(pSftpDirInfo))
            {
                printf("File listing: %s\n", pFilename);
                SSHC_freeFilename(connectionInstance, &pFilename);

                /* sometimes file stats are missing due to server support, so we must check if the stat is actually present */
                SSHC_sftpGetDirEntryFileSize(connectionInstance, pSftpDirInfo, &size, &isPresent);
                if (isPresent)
                    printf("SSHC_EXAMPLE_directoryListing: size = %d\n", size);

                SSHC_sftpGetDirEntryFileType(connectionInstance, pSftpDirInfo, &type, &isPresent);
                if (isPresent)
                    printf("SSHC_EXAMPLE_directoryListing: type = %d\n", type);

                SSHC_sftpGetDirEntryFilePermission(connectionInstance, pSftpDirInfo, &permissions, &isPresent);
                if (isPresent)
                    printf("SSHC_EXAMPLE_directoryListing: permissions = %d\n", permissions);

                printf("\n");
            }
            else
            {
                printf("SSHC_EXAMPLE_directoryListing: SSHC_readDirectory() did not complete, sftp_status = %d\n", SSHC_sftpRequestStatusCode(pSftpDirInfo));
                SSHC_freeFilename(connectionInstance, &pFilename);
                break;
            }
        }
        while (SSH_FTP_OK == SSHC_sftpRequestStatusCode(pSftpDirInfo));

        /* close the directory (frees up memory) */
        status = SSHC_closeDirectory(connectionInstance, pSftpDirInfo);

        /* free up the handle, when finished */
        SSHC_freeHandle(connectionInstance, &pSftpDirInfo);
    }

exit:
    SSHC_freeFilename(connectionInstance, &pRealpath);
    return status;

} /* SSHC_EXAMPLE_directoryListing */


/*------------------------------------------------------------------*/

/* example SFTP remove file on remote server */
static int
SSHC_EXAMPLE_removeFile(int connectionInstance)
{
    ubyte*                  fileName = (ubyte *)"./temp.txt";
    sftpcFileHandleDescr*   pSftpFileInfo = NULL;
    int                     status;

    /* remove temp.txt */
    if (OK > (status = SSHC_removeFile(connectionInstance, fileName, (ubyte4)MOC_STRLEN((sbyte *)fileName), &pSftpFileInfo)))
    {
        printf("SSHC_EXAMPLE_removeFile: SSHC_removeFile(\"%s\") failed\n", fileName);
        goto exit;
    }

    if (SSH_FTP_OK != SSHC_sftpRequestStatusCode(pSftpFileInfo))
        printf("SSHC_EXAMPLE_removeFile: SSHC_removeFile() did not complete, sftp_status = %d\n", SSHC_sftpRequestStatusCode(pSftpFileInfo));
    else
        printf("SSHC_EXAMPLE_removeFile: SSHC_removeFile() successfully remove file\n");

exit:
    return status;

} /* SSHC_EXAMPLE_removeFile */


/*------------------------------------------------------------------*/

/* example SFTP remove directory on remote server */
static int
SSHC_EXAMPLE_removeDirectory(int connectionInstance)
{
    sftpcFileHandleDescr*   pSftpFileInfo = NULL;
    int                     status;

    /* remove dir hello */
    if (OK > (status = SSHC_rmdir(connectionInstance, (ubyte *)"./hello", 7, &pSftpFileInfo)))
    {
        printf("SSHC_EXAMPLE_removeDirectory: SSHC_rmdir(\"./hello\") failed\n");
        goto exit;
    }

    if (SSH_FTP_OK != SSHC_sftpRequestStatusCode(pSftpFileInfo))
        printf("SSHC_EXAMPLE_removeDirectory: SSHC_rmdir() did not complete, sftp_status = %d\n", SSHC_sftpRequestStatusCode(pSftpFileInfo));
    else
        printf("SSHC_EXAMPLE_removeDirectory: SSHC_rmdir() successfully remove dir\n");

exit:
    return status;

} /* SSHC_EXAMPLE_removeDirectory */


/*------------------------------------------------------------------*/

static void
SSHC_EXAMPLE_doSftpCommands(void)
{
    int                     connectionInstance = -1;
    TCP_SOCKET              mySocket;
    signed char*            serverIpAddress = (signed char*)sshc_exampleIPAddress;
    unsigned short          serverPort = (unsigned short)sshc_ServerPort;
    int                     status = OK;

    /* Connect to remote server with simple TCP/IP socket */
    if (OK > (status = TCP_CONNECT(&mySocket, serverIpAddress, serverPort)))
        goto exit;

    /* Initialize context for SSH session to remote server */
    if (OK > (status = SSHC_connect(mySocket, &connectionInstance, NULL, pSshClientCertStore)))
        goto exit;

#if 0
    /* (OPTIONAL) in between connect and negotiate you can customize the session establishment here */
    /* for example, rather than the default behavior chosing the strongest cipher */
    /* available, we can chose a particular cipher suite */
    if (OK > (status = SSHC_useThisCipher(connectionInstance, "aes256-ctr")))
        goto exit;
#endif

    /* setup a secure, fully authenticated session */
    if (OK > (status = SSHC_negotiateConnection(connectionInstance)))
        goto exit;

    /* open up a SSH session on remote server */
    if (OK > (status = SSHC_negotiateSession(connectionInstance)))
        goto exit;

    /* open up a SFTP session */
    if (OK > (status = SSHC_negotiateSubsystemSFTPChannelRequest(connectionInstance)))
        goto exit;

    /* negotiate SFTP version support */
    if (OK > (status = SSHC_negotiateSFTPHello(connectionInstance)))
        goto exit;

    /* SFTP session is now open! */
    /* put file on remote server */
    if (OK > (status = SSHC_EXAMPLE_putFile(connectionInstance)))
        goto exit;

    /* get file on remote server */
    if (OK > (status = SSHC_EXAMPLE_getFile(connectionInstance)))
        goto exit;

    /* make a directory on remote server */
    if (OK > (status = SSHC_EXAMPLE_createDirectory(connectionInstance)))
        goto exit;

    /* read directory listing on a remote server */
    if (OK > (status = SSHC_EXAMPLE_directoryListing(connectionInstance)))
        goto exit;

    /* remove file on remote server */
    if (OK > (status = SSHC_EXAMPLE_removeFile(connectionInstance)))
        goto exit;

    /* remove directory on remote server */
    if (OK > (status = SSHC_EXAMPLE_removeDirectory(connectionInstance)))
        goto exit;

#ifdef __ENABLE_MOCANA_SSH_SERIAL_CHANNEL__
    /* negotiate closing of a channel */
    if (OK > (status = SSHC_negotiateCloseChannel(connectionInstance, 0)))
        goto exit;

    /* open up a SSH session on remote server */
    if (OK > (status = SSHC_negotiateSession(connectionInstance)))
        goto exit;

    /* open up a SFTP session */
    if (OK > (status = SSHC_negotiateSubsystemSFTPChannelRequest(connectionInstance)))
        goto exit;

    /* negotiate SFTP version support */
    if (OK > (status = SSHC_negotiateSFTPHello(connectionInstance)))
        goto exit;

    /* put file on remote server */
    if (OK > (status = SSHC_EXAMPLE_putFile(connectionInstance)))
        goto exit;

    /* get file on remote server */
    if (OK > (status = SSHC_EXAMPLE_getFile(connectionInstance)))
        goto exit;

    /* remove file on remote server */
    if (OK > (status = SSHC_EXAMPLE_removeFile(connectionInstance)))
        goto exit;
#endif
exit:
    printf("SSHC_EXAMPLE_doSftpCommands: test finished, status = %d\n", status);

    SSHC_close(connectionInstance);
    TCP_CLOSE_SOCKET(mySocket);

    /* Allow time for SSH messages to be communicated over the network */
    RTOS_sleepMS(1000);

    return;

} /* SSHC_EXAMPLE_doSftpCommands */

#if defined(__ENABLE_MOCANA_SSH_EXAMPLE_GRACEFUL_SHUTDOWN__)
static void
SSHC_EXAMPLE_GracefulShutdownCommands(void)
{
    int                     connectionInstance = -1;
    TCP_SOCKET              mySocket;
    signed char*            serverIpAddress = (signed char*)sshc_exampleIPAddress;
    unsigned short          serverPort = (unsigned short)sshc_ServerPort;
    int                     status = OK;
    ubyte4                  bytesSent;

    /* Connect to remote server with simple TCP/IP socket */
    if (OK > (status = TCP_CONNECT(&mySocket, serverIpAddress, serverPort)))
        goto exit;

    /* Initialize context for SSH session to remote server */
    if (OK > (status = SSHC_connect(mySocket, &connectionInstance, NULL, pSshClientCertStore)))
        goto exit;

    /* setup a secure, fully authenticated session */
    if (OK > (status = SSHC_negotiateConnection(connectionInstance)))
        goto exit;

    /* open up a SSH session on remote server */
    if (OK > (status = SSHC_negotiateSession(connectionInstance)))
        goto exit;

    /* negotiate PTY */
    if (OK > (status = SSHC_negotiatePtyTerminalChannelRequest(connectionInstance)))
        goto exit;

    /* negotiate shell */
    if (OK > (status = SSHC_negotiateShellChannelRequest(connectionInstance)))
        goto exit;

    if (OK > (status = SSHC_sendMessage(connectionInstance, (ubyte *)"bye!", 4, (ubyte4 *)&bytesSent)))
        goto exit;

exit:
    printf("SSHC_EXAMPLE_GracefulShutdownCommands: test finished, status = %d\n", status);

    SSHC_close(connectionInstance);
    RTOS_sleepMS(1000);
    TCP_CLOSE_SOCKET(mySocket);

    return;

} /* SSHC_EXAMPLE_GracefulShutdownCommands */
#endif

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
SSHC_EXAMPLE_displayHelp(char *prog)
{

    printf("option:\n");
    printf("  -ip <ipaddr>            sets remote IP address \n");
    printf("  -username <username>    sets username for remote host\n");
    printf("  -password <password>    sets password for remote host\n");
    printf("  -port <port>            sets port for remote host\n");
    printf("  -ssh_ca_cert <ca_cert>  sets the CA certificate path (used for authenticating cert provided by the server)\n");
    printf("  -ssh_client_cert <cert> sets the certificate path (used by client to authenticate itself)\n");
    printf("  -ssh_client_blob <key>  sets the corresponding blob path\n");
#if (defined(__ENABLE_MOCANA_TAP__))
#if (defined(__ENABLE_MOCANA_TAP_REMOTE__))
    printf("  -tap_server_port <tap_server_port> TAP server port\n");
    printf("  -tap_server_name <tap_server_name> TAP server name\n");
#endif
    printf("  -tap_config_file <tap_config_file> TAP config file\n");
#endif
    printf("\n");

    return;
} /*SSHC _EXAMPLE_displayHelp */

/*------------------------------------------------------------------*/

extern sbyte4
SSHC_EXAMPLE_getArgs(int argc, char *argv[])
{
    sbyte4 status = 0;
    int i;
    int ipSet=0, userSet=0, pwdSet=0;

#if (defined(__ENABLE_MOCANA_TAP__))
    char *temp;
    int tapServerNameSet = 0, tapServerPortSet = 0, tapConfigFileSet = 0;
#endif
    if ((2 <= argc) && ('?' == argv[1][0]))
    {
        SSHC_EXAMPLE_displayHelp(argv[0]);
        return -1;
    }

    for (i = 1; i < argc; i++) /*Skiping argv[0] which is example progam name*/
    {
        if (MOC_STRCMP((sbyte *) argv[i], (sbyte *) "-ip") == 0)
        {
            ipSet = 1; /*Ip should not be set to dafault*/
            i++;
            setParameter(&sshc_exampleIPAddress, argv[i]);
            continue;
        }
        else if (MOC_STRCMP((sbyte *) argv[i], (sbyte *) "-port") == 0)
        {
            i++;
            sshc_ServerPort = atoi(argv[i]);
            continue;
        }
        else if (MOC_STRCMP((sbyte *) argv[i], (sbyte *) "-username") == 0)
        {
            userSet = 1; /*Username should not be set to default*/
            i++;
            setParameter(&sshc_exampleUserName, argv[i]);
            continue;
        }
        else if (MOC_STRCMP((sbyte *) argv[i], (sbyte *) "-password") == 0)
        {
            pwdSet = 1; /*password should not be set to default*/
            i++;
            setParameter(&sshc_examplePassword, argv[i]);
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
        else if (MOC_STRCMP((const sbyte *)argv[i], (const sbyte *)"-ssh_client_cert") == 0)
        {
            if (++i < argc)
            {
                setParameter(&ssh_ClientCert, argv[i]);
            }
            continue;
        }
        else if (MOC_STRCMP((const sbyte *)argv[i], (const sbyte *)"-ssh_client_blob") == 0)
        {
            if (++i < argc)
            {
                setParameter(&ssh_ClientBlob, argv[i]);
            }
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

    /*Set defaults if nothing entered from command line*/
    if (!ipSet)
    {
        setParameter(&sshc_exampleIPAddress, DEFAULT_IP);
    }
    if (!userSet)
    {
        setParameter(&sshc_exampleUserName, DEFAULT_USERNAME);
    }
    if (!pwdSet)
    {
        setParameter(&sshc_examplePassword, DEFAULT_PASSWORD);
    }
#if (defined(__ENABLE_MOCANA_TAP__))
#if (defined(__ENABLE_MOCANA_TAP_REMOTE__))
    if (!tapServerNameSet)
    {
    	DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, (sbyte *) "Mandatory argument tap_server_name NOT set");
        status = ERR_SSH_CONFIG;
    }
    if (!tapServerPortSet)
    {
    	DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, (sbyte *) "Mandatory argument tap_server_port NOT set");
        status = ERR_SSH_CONFIG;
    }
#endif
    if (!tapConfigFileSet)
    {
        setParameter(&tap_ConfigFile, TPM2_CONFIGURATION_FILE);
    }
#endif
    /*End of defaults*/

    return status;

} /* SSHC_EXAMPLE_getArgs */

/*------------------------------------------------------------------*/

/* This is only for build the SSL client using Microsoft Visual Studio project */
#if defined(__ENABLE_MOCANA_WIN_STUDIO_BUILD__) && !defined(__ENABLE_CMAKE_BUILD__)
int main(int argc, char *argv[])
{
	void* dummy = NULL;
#else
extern void
SSH_CLIENTEXAMPLE_main(sbyte4 dummy)
{
#endif

    int                     status = OK;

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
	if (OK > ( status = SSHC_EXAMPLE_getArgs(argc, argv))) /* Initialize parameters to default values */
		return status;

	if (OK > (status = MOCANA_initMocana()))
      goto exit;

#endif

	MOC_UNUSED(dummy);

    if (0 > (status = SSHC_init(MAX_SSHC_CONNECTIONS_ALLOWED)))
        goto exit;

    /* set callbacks for SSH */
    SSHC_EXAMPLE_initSshCommands();
#ifdef __ENABLE_MOCANA_TPM__
#ifdef __USE_TPM_EMULATOR__
    if (OK > (status = MOCTAP_initSecurityDescriptor(NULL, NULL, NULL, secmod_TPM12RSAKey, 9, (ubyte *)"localhost", &mh)))
    {
        DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, (sbyte *) "Unable to initialize MOCTAP Context");
        goto exit;
    }
#else
    if (OK > (status = MOCTAP_initSecurityDescriptor(NULL, NULL, NULL, secmod_TPM12RSAKey, 9, (ubyte *)"/dev/tpm0", &mh)))
    {
        DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, (sbyte *) "Unable to initialize MOCTAP Context");
        goto exit;
    }
#endif /* __USE_TPM_EMULATOR__ */
#endif /* __ENABLE_MOCANA_TPM__ */

#ifdef __ENABLE_MOCANA_TAP__
    if (OK != (status = SSHC_EXAMPLE_InitializeTapContext(tap_ConfigFile, &g_pTapContext,
                                                         &g_pTapEntityCred,
                                                         &g_pTapKeyCred)))
    {
        DEBUG_ERROR(DEBUG_SSL_EXAMPLE, "SSHC_EXAMPLE_InitializeTapContext failed. status = %d\n", status);
        goto exit;
    }

    if (OK > (status = CRYPTO_INTERFACE_registerTapCtxCallback((void *)&SSHC_EXAMPLE_getTapContext)))
        goto exit;
#endif

    /* We need cert and key only if client is authenticating itself using a certificate */
#if (defined(__ENABLE_MOCANA_SSH_CLIENT_CERT_AUTH__))
    if (ssh_ClientCert != NULL)
    {
        /* If client Cert is provided, we load cert and key into the certStore */
        if (OK > (status = SSHC_EXAMPLE_loadCertificate(&pSshClientCertStore)))
            goto exit;
    }
    else
#endif
    {
        /* initalize SSH client cert store */
        if (0 > (status = SSHC_EXAMPLE_sshCertStoreInit(&pSshClientCertStore)))
            goto exit;
    }

    /* set callbacks for SFTP */
    SSHC_EXAMPLE_initSftpCommands();

#ifdef __ENABLE_MOCANA_SSH_CLIENT_EXAMPLE_AUTH__
    /* if using public key authentication, create client auth keys */
    /* this is optional, in most instance you will probably use password authentication */
    if (ssh_ClientCert == NULL)
    {
#ifdef __ENABLE_MOCANA_DATA_PROTECTION__
        /* Do not generate a key when using data protect, but check if it exists */
        if (FALSE == FMGMT_pathExists(KEYBLOB_AUTH_KEY_FILE_NAME, NULL))
        {
            DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE,(sbyte *) "No public key found to use for authentication");
            goto exit;
        }
#else
        /* Create Auth keys only if we do not have a Certificate already loaded into the certStore */
        if (0 > SSHC_EXAMPLE_computeAuthKeys())
            goto exit;
#endif
    }
#endif

    /* Go through SFTP command examples */
    SSHC_EXAMPLE_doSftpCommands();

#if defined(__ENABLE_MOCANA_SSH_EXAMPLE_GRACEFUL_SHUTDOWN__)
    SSHC_EXAMPLE_GracefulShutdownCommands();
#endif

exit:
    printf("SSH_CLIENTEXAMPLE_main: test finished, status = %d\n", status);

    if (sshc_exampleIPAddress)
        FREE(sshc_exampleIPAddress);

    if (sshc_examplePassword)
        FREE(sshc_examplePassword);

    if(sshc_exampleUserName)
        FREE(sshc_exampleUserName);

    if(ssh_CACert)
        FREE(ssh_CACert);

    if(ssh_ClientCert)
        FREE(ssh_ClientCert);

    if(ssh_ClientBlob)
        FREE(ssh_ClientBlob);


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
    CERT_STORE_releaseStore(&pSshClientCertStore);

    /* (IMPORTANT) for real world use scenarios, Mocana recommends not shutting down */
    SSHC_shutdown();

    return;

} /* SSH_CLIENTEXAMPLE_main */

#endif /* (defined(__ENABLE_MOCANA_SSH_CLIENT_EXAMPLE__) && defined(__ENABLE_MOCANA_SSH_FTP_CLIENT__) && defined(__ENABLE_MOCANA_EXAMPLES__)) */
