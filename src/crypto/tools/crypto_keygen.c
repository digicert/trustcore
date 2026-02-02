/**
 * crypto_keygen.c
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 */

/* keygen not built for hwAccelCtx, don't build such for tests */

#if (defined(__ENABLE_DIGICERT_CRYPTO_KEYGEN__) || defined(__ENABLE_DIGICERT_CRYPTO_KEYGEN_LIB__)) &&\
    !defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__)

#if defined(__RTOS_WIN32__)
#include <stdio.h>
#include <windows.h>
#include <sys/types.h>
#include <sys/stat.h>
#endif /* __RTOS_WIN32__ */

#include "../../common/moptions.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mdefs.h"
#include "../../common/mstdlib.h"
#include "../../common/mocana.h"
#include "../../common/mrtos.h"
#include "../../common/datetime.h"
#include "../../common/tree.h"
#include "../../common/absstream.h"
#include "../../common/memfile.h"
#include "../../common/vlong.h"
#include "../../common/random.h"
#include "../../common/base64.h"
#include "../../common/debug_console.h"
#include "../../common/msg_logger.h"
#ifdef __ENABLE_KEYSTORE_PATH__
#include "../../common/mfmgmt.h"
#include "../../common/common_utils.h"
#endif

#include "../../asn1/parseasn1.h"
#include "../../asn1/oiddefs.h"
#include "../../asn1/derencoder.h"
#include "../../asn1/parsecert.h"

#include "../../cap/capasym.h"

#include "../../crypto/pubcrypto.h"
#include "../../crypto/ca_mgmt.h"
#include "../../crypto/asn1cert.h"
#include "../../crypto/pkcs_key.h"
#include "../../crypto/pkcs7.h"
#include "../../crypto/pkcs10.h"
#include "../../crypto/pkcs12.h"
#include "../../crypto/malgo_id.h"
#include "../../crypto/cert_chain.h"
#include "../../crypto/cert_store.h"

#include "../../ssh/ssh_key.h"

#include "../../crypto_interface/crypto_interface_ecc.h"
#include "../../crypto_interface/crypto_interface_rsa.h"

#ifndef  __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#include "../../crypto_interface/crypto_interface_dsa.h"
#endif

#ifdef __ENABLE_DIGICERT_PQC__
#include "../../crypto_interface/crypto_interface_qs.h"
#ifdef __ENABLE_MLDSA_LONG_FORM_PRIV_KEY_SER__
#include "../../crypto/pqc/pqc_ser.h"
#endif
#endif

#ifdef __ENABLE_DIGICERT_TAP__
#include "../../crypto/mocasym.h"
#include "../../crypto_interface/cryptointerface.h"
#include "../../tap/tap.h"
#include "../../tap/tap_api.h"
#include "../../tap/tap_utils.h"
#include "../../crypto/mocasymkeys/tap/rsatap.h"
#include "../../crypto/mocasymkeys/tap/ecctap.h"
#endif

#include "../../cert_enroll/cert_enroll.h"

#ifdef __ENABLE_DIGICERT_CV_CERT__
#include "../../crypto/cvcert.h"
#endif

#if defined(__RTOS_LINUX__)
#include <sys/stat.h>
#include <stdio.h>
#include <signal.h>
#include <termios.h>
#if !defined(__RTOS_ZEPHYR__)
#include <dirent.h>
#include <unistd.h>
#endif /* __RTOS_ZEPHYR__ */
#endif /* __RTOS_LINUX__ */

#if defined(__RTOS_OSX__)
#include <stdio.h>
#include <unistd.h>
#endif /* RTOS_OSX__ */

#include "../../crypto/tools/crypto_keygen.h"

/* global arguments */
static KeyGenArgs gKeyGenArgs = {0};

#define TC_KEYGEN_LOG_LABEL "TC_KEYGEN"

#define FORMAT_PEM 0
#define FORMAT_DER 1
#define FORMAT_SSH 2

#define MAX_PASSWORD_LEN 129  /* one extra so that 128 bytes is allowd */
#define MAX_PASSWORD_LEN_STR "128"
#define MAX_RETRIES 3

#define MAX_CSR_NAME_ATTRS                      (10)
#define MAX_NUM_SUBJECTALTNAMES                 (10)
#define MAX_LINE_LENGTH                         (256)

#ifndef MOC_KEYGEN_PKCS8_ALGO
#define MOC_KEYGEN_PKCS8_ALGO PCKS8_EncryptionType_pkcs5_v2_aes256
#endif

#ifndef MOC_KEYGEN_PKCS8_HASH
#define MOC_KEYGEN_PKCS8_HASH PKCS8_PrfType_pkcs5_v2_hmacSHA256Digest
#endif

#define NOT_SPECIFIED (-1)

#ifdef __ENABLE_DIGICERT_PQC__
void SERIALQS_setOqsCompatibleFormat(byteBoolean format);
#endif

#ifdef __ENABLE_DIGICERT_TAP__

#ifndef KEYGEN_TAP_DEFAULT_MODNUM
#define KEYGEN_TAP_DEFAULT_MODNUM 1
#endif

#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
#ifndef KEYGEN_TAP_DEFAULT_PROVIDER
#define KEYGEN_TAP_DEFAULT_PROVIDER TAP_PROVIDER_TPM2
#endif
#ifndef KEYGEN_TAP_DEFAULT_PORT
#define KEYGEN_TAP_DEFAULT_PORT 8277
#endif
#endif /* __ENABLE_DIGICERT_TAP_REMOTE__ */
#endif /* __ENABLE_DIGICERT_TAP__ */

#define MOC_NUM_EXT_KEY_USG_FIELDS 6

typedef struct extKeyUsageInfo
{
    ubyte serverAuth;
    ubyte clientAuth;
    ubyte codeSign;
    ubyte emailProt;
    ubyte timeStamp;
    ubyte ocspSign;
} extKeyUsageInfo;

/* Most library mode builds will not use the TAP init function here,
   but just in case, set a default of TPM2 */
#if defined(__ENABLE_DIGICERT_CRYPTO_KEYGEN_LIB__) && defined(__ENABLE_DIGICERT_TAP__)
#if !defined(__ENABLE_DIGICERT_SMP_PKCS11__) && !defined(__ENABLE_DIGICERT_TPM2__)
#define __ENABLE_DIGICERT_TPM2__
#endif
#endif

#ifdef __ENABLE_DIGICERT_TAP__

#ifndef __ENABLE_DIGICERT_TAP_REMOTE__

#ifndef KEYGEN_TAP_CONFIG_PATH
#if defined(__ENABLE_DIGICERT_SMP_PKCS11__)
#define KEYGEN_TAP_CONFIG_PATH "/etc/mocana/pkcs11_smp.conf"
#elif defined(__ENABLE_DIGICERT_TPM2__)
#include "../../common/tpm2_path.h"
#define KEYGEN_TAP_CONFIG_PATH TPM2_CONFIGURATION_FILE
#else
#error "SMP flag not specified. Cannot set default path to TAP config file."
#endif
#endif

#ifndef KEYGEN_TAP_PROVIDER
#if defined(__ENABLE_DIGICERT_SMP_PKCS11__)
#define KEYGEN_TAP_PROVIDER TAP_PROVIDER_PKCS11
#elif defined(__ENABLE_DIGICERT_TPM2__)
#define KEYGEN_TAP_PROVIDER TAP_PROVIDER_TPM2
#else
#error "SMP flag not specified. Cannot set TAP provider."
#endif
#endif

#if defined(__ENABLE_DIGICERT_SMP_PKCS11__)
#define KEYGEN_TAP_PROVIDER_NAME " PKCS11"
#else
#define KEYGEN_TAP_PROVIDER_NAME " TPM2"
#endif

#else
#define KEYGEN_TAP_PROVIDER_NAME ""
#endif /* !__ENABLE_DIGICERT_TAP_REMOTE__ */

static KeyGenTapArgs gTapArgs = {0};

static TAP_ErrorContext gErrContext = {0};
static TAP_ErrorContext *gpErrContext = &gErrContext;
static TAP_ConfigInfoList gConfigInfoList = {0, };

/*---------------------------------------------------------------------------*/

static MSTATUS KEYGEN_TAP_getCtx(
    TAP_Context **ppTapCtx, TAP_EntityCredentialList **ppTapEntityCred,
    TAP_CredentialList **ppTapKeyCred, void *pKey, TapOperation op,
    ubyte getContext)
{
    if (1 == getContext)
    {
        if (NULL != ppTapCtx) *ppTapCtx = gTapArgs.gpTapCtx;
        if (NULL != ppTapEntityCred) *ppTapEntityCred = gTapArgs.gpTapEntityCredList;
        if (NULL != ppTapKeyCred) *ppTapKeyCred = gTapArgs.gpTapCredList;
    }
    else
    {
        if (NULL != ppTapCtx) *ppTapCtx = NULL;
        if (NULL != ppTapEntityCred) *ppTapEntityCred = NULL;
        if (NULL != ppTapKeyCred) *ppTapKeyCred = NULL;
    }

    return OK;
}

/*---------------------------------------------------------------------------*/

static void KEYGEN_TAP_clean(KeyGenTapArgs *pTapArgs)
{
    sbyte4 i = 0;

    if (NULL != gConfigInfoList.pConfig)
    {
        (void) TAP_UTILS_freeConfigInfoList(&gConfigInfoList);
    }

    if (NULL != pTapArgs->gpTapEntityCredList)
    {
        (void) TAP_UTILS_clearEntityCredentialList(pTapArgs->gpTapEntityCredList);
        (void) DIGI_FREE((void**) &pTapArgs->gpTapEntityCredList);
    }

    if (NULL != pTapArgs->gpTapCredList)
    {
        if (NULL != pTapArgs->gpTapCredList->pCredentialList)
        {
            for (i = 0; i < pTapArgs->gpTapCredList->numCredentials; i++)
            {
                if (pTapArgs->gpTapCredList->pCredentialList[i].credentialData.pBuffer != NULL)
                    (void) DIGI_FREE((void**)&(pTapArgs->gpTapCredList->pCredentialList[i].credentialData.pBuffer));
            }
            (void) DIGI_FREE((void**) &(pTapArgs->gpTapCredList->pCredentialList));
        }

        (void) DIGI_FREE((void**) &pTapArgs->gpTapCredList);
    }

    if (NULL != pTapArgs->gpTapCtx)
    {
        (void) TAP_uninitContext(&pTapArgs->gpTapCtx, gpErrContext);
    }

    (void) TAP_uninit(gpErrContext);

    return;
}

/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
static TAP_Module *getTapModule(TAP_ModuleList *pModuleList, TAP_ModuleId moduleNum)
{
    ubyte4 i;
    TAP_Module *pModule = NULL;

    if (NULL != pModuleList)
    {
        if (0 == moduleNum)
        {
            if (0 < pModuleList->numModules)
                pModule = &(pModuleList->pModuleList[0]);
        }
        else
        {
            for (i = 0; i < pModuleList->numModules; i++)
            {
                if (pModuleList->pModuleList[i].moduleId == moduleNum)
                {
                    pModule = &(pModuleList->pModuleList[i]);
                    break;
                }
            }
        }
    }
    return pModule;
}
#endif /* __ENABLE_DIGICERT_TAP_REMOTE__ */

/*---------------------------------------------------------------------------*/

static MSTATUS KEYGEN_TAP_init(KeyGenArgs *pArgs, KeyGenTapArgs *pTapArgs)
{
    MSTATUS status = 0;
    TAP_Module module = {0};
    TAP_Module *pModule = NULL;

#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
    TAP_ConnectionInfo connInfo = { 0 };
    TAP_ModuleList moduleList = { 0 };

    /* Discover modules */
    connInfo.serverName.pBuffer = (ubyte *) pArgs->gpServer;
    connInfo.serverName.bufferLen = DIGI_STRLEN(pArgs->gpServer) + 1; /* treat as a string */
    connInfo.serverPort = pArgs->gPort;

    status = TAP_init(&gConfigInfoList, gpErrContext);
    if (OK != status)
        goto exit;

    status = TAP_getModuleList(&connInfo, pArgs->gTapProvider, NULL, &moduleList, gpErrContext);
    if (OK != status)
        goto exit;

    pModule = getTapModule(&moduleList, (TAP_ModuleId) pArgs->gModNum);

#else

    status = DIGI_CALLOC((void **)&(gConfigInfoList.pConfig), 1, sizeof(TAP_ConfigInfo));
    if (OK != status)
        goto exit;

    status = TAP_readConfigFile((char *) KEYGEN_TAP_CONFIG_PATH, &gConfigInfoList.pConfig[0].configInfo, FALSE);
    if (OK != status)
        goto exit;

    gConfigInfoList.count = 1;
    gConfigInfoList.pConfig[0].provider = KEYGEN_TAP_PROVIDER;

    status = TAP_init(&gConfigInfoList, gpErrContext);
    if (OK != status)
        goto exit;

    module.providerType = KEYGEN_TAP_PROVIDER;
    module.moduleId = pArgs->gModNum;
    pModule = &module;

    status = TAP_getModuleCredentials(pModule, (char *) KEYGEN_TAP_CONFIG_PATH, TRUE, &pTapArgs->gpTapEntityCredList, gpErrContext);
    if (OK != status)
        goto exit;

#endif

    status = TAP_initContext(pModule, pTapArgs->gpTapEntityCredList, NULL, &pTapArgs->gpTapCtx, gpErrContext);
    if (OK != status)
        goto exit;

    /* also allocate an empty credList */
    status = DIGI_CALLOC((void **) &pTapArgs->gpTapCredList, 1, sizeof(TAP_CredentialList));
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_registerTapCtxCallback(KEYGEN_TAP_getCtx);

exit:

#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
    if (NULL != moduleList.pModuleList)
    {
        (void) TAP_freeModuleList(&moduleList);
    }
#endif

    if (OK != status)
    {
        KEYGEN_TAP_clean(&gTapArgs);
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_TAP__ */

/*---------------------------------------------------------------------------*/

#ifdef __RTOS_WIN32__
static TCHAR KEYGEN_WIN32_getch()
{
    DWORD mode, cc;
    TCHAR c = 0;
    HANDLE h = GetStdHandle (STD_INPUT_HANDLE);

    if (h == NULL)
    {
        return 0; /* Error */
    }
    GetConsoleMode (h, &mode);
    SetConsoleMode (h, mode & ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT));

    ReadConsole (h, &c, 1, &cc, NULL);

    SetConsoleMode  (h, mode);
    return c;
}

static void KEYGEN_getEnteredPassword(ubyte *pPassword)
{
    ubyte4 i = 0;
    int c = 0;

    do
    {
        c = KEYGEN_WIN32_getch();

        switch (c)
        {
            case 0x00:
                break;

            case 0x08:          /* backspace */
                if (i > 1)
                    --i;
                break;

            case 0x0D:
                break;

            default:
                if (c >= 20)
                {
                    if (i < MAX_PASSWORD_LEN)
                    {
                        pPassword[i++] = c;
                    }
                }
                break;
        }
    } while (c != 0x0D);
}

static MSTATUS KEYGEN_getPassword(ubyte **ppRetPassword, ubyte4 *pRetPasswordLen, char *pPwName, char *pFileName)
{
    ubyte pPass1[MAX_PASSWORD_LEN] = {0};
    ubyte pPass2[MAX_PASSWORD_LEN] = {0};
    ubyte *pRetPw = NULL;
    ubyte4 retries = 0;

    /* internal method, NULL checks not necc */

    *pRetPasswordLen = 0;

    printf ("Enter %s pass phrase for protecting the %s: ", pPwName, pFileName);

    KEYGEN_getEnteredPassword(pPass1);

    printf("\n");

    while (retries < MAX_RETRIES)
    {
        printf("Re-enter %s pass phrase for protecting the %s: ", pPwName, pFileName);

        KEYGEN_getEnteredPassword(pPass2);

        printf("\n");

        if (i == j && 0 == DIGI_STRCMP((sbyte *) pPass1, (sbyte *) pPass2))
        {
            break;
        }
        else
        {
            printf("ERROR: Passwords do not match, please try again.\n");
            retries++;

            if (retries >= MAX_RETRIES)
            {
                printf("ERROR: Passwords do not match after %d retries.\n", MAX_RETRIES);
                status = ERR_INVALID_INPUT;
                goto exit;
            }
        }
    }

    if (i == MAX_PASSWORD_LEN)
    {
        printf("ERROR: password too long, must be no more than " MAX_PASSWORD_LEN_STR " characters.\n");
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    /* allocate one extra space so we have a non NULL buffer no matter what */
    status = DIGI_MALLOC((void **) &pRetPw, i + 1);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY( pRetPw, pPass1, i);
    if (OK != status)
        goto exit;

    pRetPw[i] = 0;

    *ppRetPassword = pRetPw; pRetPw = NULL;
    *pRetPasswordLen = i;

exit:

    if (NULL != pRetPw)
    {
        (void) DIGI_MEMSET_FREE(&pRetPw, i);
    }

    return OK;
}

#endif /* __RTOS_WIN32__ */

#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__)
static MSTATUS KEYGEN_getEnteredPassword(char *pBuffer, ubyte4 bufferLen) 
{
    MSTATUS status = OK;
    int c;
    ubyte4 pos = 0;
    struct termios term;

	signal(SIGINT, SIG_IGN);
	signal(SIGTERM, SIG_IGN);

	tcgetattr(1, &term);
	term.c_lflag &= ~ECHO;
	tcsetattr(1, TCSANOW, &term);

	while ((c=fgetc(stdin)) != '\n') 
    {
		pBuffer[pos++] = (char) c;
		if (pos >= bufferLen)
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }		
	}
	pBuffer[pos] = '\0';

exit:
	term.c_lflag |= ECHO;
	tcsetattr(1, TCSANOW, &term);
    return status;
}

MOC_EXTERN MSTATUS KEYGEN_getPassword(ubyte **ppRetPassword, ubyte4 *pRetPasswordLen, char *pPwName, char *pFileName)
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte *pPassword1 = NULL;
    sbyte pTempPassword[MAX_PASSWORD_LEN] = {0};
    ubyte4 passwordLen = 0;
    ubyte4 retries = 0;

    /* internal method, NULL checks not necc */
    *pRetPasswordLen = 0;

    printf("Enter %s pass phrase for protecting the %s: ", pPwName, pFileName);
#ifndef __RTOS_ZEPHYR__
    status = KEYGEN_getEnteredPassword(pTempPassword, MAX_PASSWORD_LEN);
#else
    status = DIGI_MEMCMP(pTempPassword, "abcde", 6); /* copy the '\0' at the end too */
#endif
    if (OK != status) /* only error is too long */
    {
        printf("\nERROR: password too long, must be no more than " MAX_PASSWORD_LEN_STR " characters.\n");
        goto exit;
    }
    passwordLen = DIGI_STRLEN(pTempPassword);
    status = DIGI_MALLOC_MEMCPY((void **) &pPassword1, passwordLen + 1, (void *) pTempPassword, passwordLen + 1);
    if (OK != status)
        goto exit;

    while (retries < MAX_RETRIES)
    {
        printf("\nRe-enter %s pass phrase for protecting the %s: ", pPwName, pFileName);
#ifndef __RTOS_ZEPHYR__
        status = KEYGEN_getEnteredPassword(pTempPassword, MAX_PASSWORD_LEN);
#else
        status = DIGI_MEMCMP(pTempPassword, "abcde", 6); /* copy the '\0' at the end too */
#endif
        if (OK != status)
            goto exit;

        if((passwordLen == DIGI_STRLEN(pTempPassword)) && (0 == DIGI_STRCMP(pPassword1, pTempPassword)))
        {
            printf("\n");
            break;
        }
        else
        {
            printf("\nERROR: Passwords do not match, please try again.\n");
            retries++;

            if (retries >= MAX_RETRIES)
            {
                printf("ERROR: Passwords do not match after %d retries.\n", MAX_RETRIES);
                status = ERR_INVALID_INPUT;
                goto exit;
            }
        }
    }

    *ppRetPassword = (ubyte *) pPassword1; pPassword1 = NULL;
    *pRetPasswordLen = passwordLen;

exit:

    (void) DIGI_MEMCPY(pTempPassword, 0x00, MAX_PASSWORD_LEN);

    if (NULL != pPassword1)
    {
        (void) DIGI_MEMSET_FREE((ubyte **)&pPassword1, passwordLen);
    }

    return status;
}
#endif /* __RTOS_LINUX__ */

#ifdef __ENABLE_DIGICERT_TAP__
MOC_EXTERN MSTATUS KEYGEN_addCreds(TAP_CredentialList *pCredList)
{
    MSTATUS status = ERR_NULL_POINTER;
    TAP_Credential *pNewList = NULL;
    TAP_Credential *pCred = NULL;
    ubyte4 numCreds = 1;
    ubyte *pPassword = NULL;
    ubyte4 passwordLen = 0;

    if (NULL == pCredList)
        goto exit;

    /* if there is an old list we'll copy and add one more */
    if (NULL != pCredList->pCredentialList && pCredList->numCredentials > 0)
    {
        numCreds = (pCredList->numCredentials + 1);
    }

    /* allocate the new credential list */
    status = DIGI_CALLOC((void **) &pNewList, numCreds, sizeof(TAP_Credential));
    if (OK != status)
        goto exit;

    /* copy previous creds if there, shallow copy ok */
    if (NULL != pCredList->pCredentialList && pCredList->numCredentials > 0)
    {
        status = DIGI_MEMCPY((ubyte *) pNewList, (ubyte *) pCredList->pCredentialList,
                            (numCreds - 1) * sizeof(TAP_Credential));
        if (OK != status)
            goto exit;
    }

    /* Set the new credential */
    pCred = &pNewList[numCreds - 1];

    status = KEYGEN_getPassword(&pPassword, &passwordLen, "TAP", "private key");
    if (OK != status)
        goto exit;

    /* allocate extra space just in case password is empty, let the smp deal with it */
    status = DIGI_MALLOC((void **) &pCred->credentialData.pBuffer, passwordLen + 1);
    if (OK != status)
        goto exit;

    pCred->credentialData.bufferLen = passwordLen;

    /* extra space is there on pPassword too */
    status = DIGI_MEMCPY(pCred->credentialData.pBuffer, pPassword, passwordLen + 1);
    if (OK != status)
        goto exit;

    pCred->credentialType = TAP_CREDENTIAL_TYPE_PASSWORD;
    pCred->credentialFormat = TAP_CREDENTIAL_FORMAT_PLAINTEXT;
    pCred->credentialContext = TAP_CREDENTIAL_CONTEXT_ENTITY;

    /* replace and free the old list */
    if (NULL != pCredList->pCredentialList && pCredList->numCredentials > 0)
    {
        status = DIGI_MEMSET_FREE((ubyte **) &pCredList->pCredentialList,
                                 pCredList->numCredentials * sizeof(TAP_Credential));
        if (OK != status)
            goto exit;
    }

    pCredList->pCredentialList = pNewList; pNewList = NULL;
    pCredList->numCredentials = numCreds;

exit:

    if (NULL != pPassword)
    {
        (void) DIGI_MEMSET_FREE(&pPassword, passwordLen);
    }

    if (NULL != pNewList)
    {
        /* pCred still points to the new credential */
        if (NULL != pCred)
        {
            (void) DIGI_MEMSET_FREE(&pCred->credentialData.pBuffer,
                                    pCred->credentialData.bufferLen);
        }
        (void) DIGI_FREE((void**) &pNewList);
    }

    return status;
}

static MSTATUS KEYGEN_deletePrimaryKeyAttributes(
    TAP_AttributeList **ppAttributes)
{
    MSTATUS status = OK, fstatus;
    ubyte4 i;

    if (NULL != ppAttributes && NULL != *ppAttributes)
    {
        for (i = 0; i < (*ppAttributes)->listLen; i++)
        {
            if (i == 0)
            {
                fstatus = DIGI_FREE((void **) &((*ppAttributes)->pAttributeList[0].pStructOfType));
                if (OK == status)
                    status = fstatus;
            }
            else if (i == 1)
            {
                fstatus = DIGI_FREE((void **) &((TAP_Buffer *) (*ppAttributes)->pAttributeList[1].pStructOfType)->pBuffer);
                if (OK == status)
                    status = fstatus;

                fstatus = DIGI_FREE((void **) &(*ppAttributes)->pAttributeList[1].pStructOfType);
                if (OK == status)
                    status = fstatus;
            }
        }

        fstatus = DIGI_FREE((void **) &((*ppAttributes)->pAttributeList));
        if (OK == status)
            status = fstatus;

        fstatus = DIGI_FREE((void **) ppAttributes);
        if (OK == status)
            status = fstatus;
    }

    return status;
}

static MSTATUS KEYGEN_createPrimaryKeyAttributes(
    ubyte4 keyType,
    ubyte4 keySize,
    TAP_Buffer *pKeyHandle,
    TAP_AttributeList **ppKeyAttributes)
{
    MSTATUS status;
    TAP_AttributeList *pAttrs = NULL;
    ubyte4 keyNonceByteLen = 0;

    /* Input validation not required */

    status = DIGI_CALLOC((void **) &pAttrs, 1, sizeof(TAP_AttributeList));
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_CALLOC(
        (void **) &(pAttrs->pAttributeList), 3, sizeof(TAP_Attribute));
    if (OK != status)
    {
        goto exit;
    }
    pAttrs->listLen = 3;

    status = DIGI_CALLOC((void **) &(pAttrs->pAttributeList[0].pStructOfType), 1, sizeof(TAP_CREATE_KEY_TYPE));
    if (OK != status)
    {
        goto exit;
    }

    pAttrs->pAttributeList[0].type = TAP_ATTR_CREATE_KEY_TYPE;
    pAttrs->pAttributeList[0].length = sizeof(TAP_CREATE_KEY_TYPE);
    *((TAP_CREATE_KEY_TYPE *) pAttrs->pAttributeList[0].pStructOfType) = TAP_CREATE_KEY_TYPE_PRIMARY;

    if ((keyType & 0xFF) == akt_rsa)
    {
        keyNonceByteLen = keySize / 8;
    }
    else if ((keyType & 0xFF) == akt_ecc)
    {
        switch (keySize)
        {
            case 192:
                keyNonceByteLen = 24;
                break;
            case 224:
                keyNonceByteLen = 28;
                break;
            case 256:
                keyNonceByteLen = 32;
                break;
            case 384:
                keyNonceByteLen = 48;
                break;
            case 521:
                keyNonceByteLen = 66;
                break;
            default:
                status = ERR_TAP_INVALID_CURVE_ID;
                goto exit;
        }
    }
    else
    {
        status = ERR_BAD_KEY_TYPE;
        goto exit;
    }

    status = DIGI_CALLOC(
        (void **) &(pAttrs->pAttributeList[1].pStructOfType),
        1, sizeof(TAP_Buffer));
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_MALLOC((void **) &(((TAP_Buffer *) pAttrs->pAttributeList[1].pStructOfType)->pBuffer), keyNonceByteLen);
    if (OK != status)
    {
        goto exit;
    }

    pAttrs->pAttributeList[1].type = TAP_ATTR_CREATE_KEY_ENTROPY;
    pAttrs->pAttributeList[1].length = sizeof(TAP_Buffer);

    status = RANDOM_numberGenerator(
        g_pRandomContext,
        ((TAP_Buffer *) pAttrs->pAttributeList[1].pStructOfType)->pBuffer,
        keyNonceByteLen);
    if (OK != status)
    {
        goto exit;
    }
    ((TAP_Buffer *) pAttrs->pAttributeList[1].pStructOfType)->bufferLen = keyNonceByteLen;

    pAttrs->pAttributeList[2].type = TAP_ATTR_OBJECT_ID_BYTESTRING;
    pAttrs->pAttributeList[2].length = sizeof(TAP_Buffer);
    pAttrs->pAttributeList[2].pStructOfType = pKeyHandle;

    *ppKeyAttributes = pAttrs;
    pAttrs = NULL;

exit:

    if (NULL != pAttrs)
    {
        KEYGEN_deletePrimaryKeyAttributes(&pAttrs);
    }

    return status;
}

extern MSTATUS KEYGEN_persistDataAtNVIndex(
    TAP_Context *pTapCtx,
    TAP_EntityCredentialList *pTapEntityCredList,
    ubyte8 index, ubyte *pData, ubyte4 dataLen,
    TAP_AUTH_CONTEXT_PROPERTY inputAuthProp)
{
    MSTATUS status;
    TAP_ObjectInfoList objectInfoList = {0};
    TAP_StorageInfo storageInfo = {0};
    TAP_CredentialList storageCredentials = {0};
    TAP_AttributeList setAttributes = {0};
    TAP_AUTH_CONTEXT_PROPERTY authContext = inputAuthProp;
    TAP_Attribute keyAttribute = {
        TAP_ATTR_AUTH_CONTEXT, sizeof(TAP_AUTH_CONTEXT_PROPERTY), &authContext
    };
    TAP_Buffer nvIn = { 0 };
    ubyte4 i;

    status = TAP_getPolicyStorageList(
        pTapCtx, pTapEntityCredList,
        NULL, &objectInfoList, NULL);
    if (OK != status)
    {
        goto exit;
    }

    /* Verify index does not exist */
    for (i = 0; i < objectInfoList.count; i++)
    {
        if (objectInfoList.pInfo[i].objectId == index)
        {
            status = ERR_TAP_NV_INDEX_EXISTS;
            goto exit;
        }
    }

    storageInfo.index = index;
    storageInfo.size = dataLen;
    storageInfo.storageType = TAP_WRITE_OP_DIRECT;
    storageInfo.ownerPermission = (TAP_PERMISSION_BITMASK_READ | TAP_PERMISSION_BITMASK_WRITE
                                        | TAP_PERMISSION_BITMASK_DELETE);
    storageInfo.publicPermission = (TAP_PERMISSION_BITMASK_READ | TAP_PERMISSION_BITMASK_WRITE
                                        | TAP_PERMISSION_BITMASK_DELETE);
    storageInfo.pAttributes = NULL;
    storageInfo.authContext = authContext;

    /* Create index */
    status = TAP_allocatePolicyStorage(
        pTapCtx, pTapEntityCredList,
        &storageInfo, NULL, &storageCredentials, NULL);
    if (OK != status)
    {
        goto exit;
    }

    if (NULL != objectInfoList.pInfo)
    {
        DIGI_FREE((void**) &objectInfoList.pInfo);
    }

    status = TAP_getPolicyStorageList(
        pTapCtx, pTapEntityCredList,
        NULL, &objectInfoList, NULL);
    if (OK != status)
    {
        goto exit;
    }

    /* Verify index exists */
    for (i = 0; i < objectInfoList.count; i++)
    {
        if (objectInfoList.pInfo[i].objectId == index)
        {
            break;
        }
    }

    if (i == objectInfoList.count)
    {
        status = ERR_NOT_FOUND;
        goto exit;
    }

    nvIn.pBuffer = pData;
    nvIn.bufferLen = dataLen;

    if (TAP_AUTH_CONTEXT_PLATFORM == authContext)
    {
        setAttributes.listLen++;
        setAttributes.pAttributeList = &keyAttribute;
    }

    status = TAP_setPolicyStorage(
        pTapCtx, pTapEntityCredList,
        &objectInfoList.pInfo[i], &setAttributes, &nvIn, NULL);

exit:

    if (NULL != objectInfoList.pInfo)
    {
        DIGI_FREE((void**) &objectInfoList.pInfo);
    }

    return status;
}

#endif

MOC_EXTERN MSTATUS KEYGEN_generateKey(KeyGenArgs *pArgs, void *pKeyGenTapArgs, AsymmetricKey *pKey, randomContext *pRand)
{
    MSTATUS status = ERR_BAD_KEY_TYPE;

#ifdef __ENABLE_DIGICERT_TAP__
    ECCKey *pEccKey = NULL;
    RSAKey *pRsaKey = NULL;
    KeyGenTapArgs *pTapArgs = (KeyGenTapArgs *) pKeyGenTapArgs;
    TAP_AttributeList *pAttrList = NULL;
#endif

    if (akt_rsa == pArgs->gKeyType || akt_rsa_pss == pArgs->gKeyType)
    {
        status = CRYPTO_createRSAKey(pKey, NULL);
        if (OK != status)
            goto exit;

        /* TO DO need crypto interface form that takes in a public key */
        status = CRYPTO_INTERFACE_RSA_generateKey (pRand, pKey->key.pRSA, pArgs->gKeySize, NULL);
        if (OK != status)
            goto exit;

        pKey->type = pArgs->gKeyType;

        /* we add a pAlgoId to the key if the user specified the hash or the salt, otherwise leave empty */
        if (akt_rsa_pss == pArgs->gKeyType && ( NOT_SPECIFIED != pArgs->gKeyHashAlgo || NOT_SPECIFIED != pArgs->gKeySaltLen) )
        {
            ubyte hashAlgo = ht_sha1; /* default */
            ubyte4 saltLen = 20; /* default */

            if (NOT_SPECIFIED != pArgs->gKeyHashAlgo)
            {
                hashAlgo = (ubyte) pArgs->gKeyHashAlgo;
            }

            if (NOT_SPECIFIED != pArgs->gKeySaltLen)
            {
                saltLen = (ubyte) pArgs->gKeySaltLen;
            }
            else
            {
                switch (hashAlgo)
                {
                    case ht_md5:
                        saltLen = 16;
                        break;
                    /* sha1 already the default */
                    case ht_sha224:
                        saltLen = 28;
                        break;
                    case ht_sha256:
                        saltLen = 32;
                        break;
                    case ht_sha384:
                        saltLen = 48;
                        break;
                    case ht_sha512:
                        saltLen = 64;
                        break;
                }
            }

            status = ALG_ID_createRsaPssParams(hashAlgo, MOC_PKCS1_ALG_MGF1, hashAlgo, saltLen, 0xBC, &pKey->pAlgoId);
            if (OK != status)
                goto exit;
        }
    }
#ifdef __ENABLE_DIGICERT_TAP__
    else if (akt_tap_rsa == pArgs->gKeyType)
    {
        MRsaTapKeyGenArgs rsaTapArgs = {0};

        if (pArgs->gProtected)
        {
            status = KEYGEN_addCreds(pTapArgs->gpTapCredList);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR, "Unable to create password credential for TAP RSA key.%s\n","");
                goto exit;
            }
        }

        rsaTapArgs.algKeyInfo.rsaInfo.sigScheme = pArgs->gSigScheme;
        rsaTapArgs.algKeyInfo.rsaInfo.encScheme = pArgs->gEncScheme;
        rsaTapArgs.keyUsage = pArgs->gKeyUsage;
        rsaTapArgs.pTapCtx = pTapArgs->gpTapCtx;
        rsaTapArgs.pEntityCredentials = pTapArgs->gpTapEntityCredList;
        if (pArgs->gProtected)
        {
            rsaTapArgs.pKeyCredentials = pTapArgs->gpTapCredList;
        }
        else
        {
            rsaTapArgs.pKeyCredentials = NULL;
        }

        if (TRUE == pArgs->gPrimary)
        {
            status = KEYGEN_createPrimaryKeyAttributes(
                pArgs->gKeyType, pArgs->gKeySize, pArgs->gpKeyHandle,
                &pAttrList);
            if (OK != status)
                goto exit;

            rsaTapArgs.tokenId = pArgs->gHierarchy;
            rsaTapArgs.pKeyAttributes = pAttrList;
        }

        status = CRYPTO_INTERFACE_RSA_generateKeyAlloc(NULL, (void **) &pRsaKey, pArgs->gKeySize, NULL, pArgs->gKeyType, &rsaTapArgs);
        if (OK != status)
            goto exit;

        status = CRYPTO_loadAsymmetricKey(pKey, pArgs->gKeyType, (void **) &pRsaKey);
        if (OK != status)
            goto exit;
    }
#endif
    else if (akt_ecc == pArgs->gKeyType)
    {
        /* if curve is Edward's form this API will set the proper key type in pKey */
        status = CRYPTO_createECCKeyEx(pKey, pArgs->gCurve);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_EC_generateKeyPairAux(pKey->key.pECC, RANDOM_rngFun, (void *) pRand);
    }
#ifdef __ENABLE_DIGICERT_TAP__
    else if (akt_tap_ecc == pArgs->gKeyType)
    {
        MEccTapKeyGenArgs eccTapArgs = {0};

        if (TAP_KEY_USAGE_DECRYPT == pArgs->gKeyUsage)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "TAP ECC keys must be TAP_KEY_USAGE_GENERAL or TAP_KEY_USAGE_SIGNING.%s\n","");
            status = ERR_INVALID_INPUT;
            goto exit;
        }

        if (pArgs->gProtected)
        {
            status = KEYGEN_addCreds(pTapArgs->gpTapCredList);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR, "Unable to create password credential for TAP ECC key.%s\n","");
                goto exit;
            }
        }

        eccTapArgs.keyUsage = pArgs->gKeyUsage;
        eccTapArgs.pTapCtx = pTapArgs->gpTapCtx;
        eccTapArgs.pEntityCredentials = pTapArgs->gpTapEntityCredList;
        if (pArgs->gProtected)
        {
            eccTapArgs.pKeyCredentials = pTapArgs->gpTapCredList;
        }
        else
        {
            eccTapArgs.pKeyCredentials = NULL;
        }

        switch (pArgs->gCurve)
        {
            case cid_EC_P192:
                eccTapArgs.algKeyInfo.eccInfo.sigScheme = TAP_SIG_SCHEME_ECDSA_SHA1;
                break;

            case cid_EC_P224:
                eccTapArgs.algKeyInfo.eccInfo.sigScheme = TAP_SIG_SCHEME_ECDSA_SHA224;
                break;

            case cid_EC_P256:
                eccTapArgs.algKeyInfo.eccInfo.sigScheme = TAP_SIG_SCHEME_ECDSA_SHA256;
                break;

            case cid_EC_P384:
                eccTapArgs.algKeyInfo.eccInfo.sigScheme = TAP_SIG_SCHEME_ECDSA_SHA384;
                break;

            case cid_EC_P521:
                eccTapArgs.algKeyInfo.eccInfo.sigScheme = TAP_SIG_SCHEME_ECDSA_SHA512;
                break;

            default:
                status = ERR_INVALID_INPUT;
                MSG_LOG_print(MSG_LOG_ERROR, "ECC curve selected is not valid for TAP.%s\n","");
                goto exit;
        }

        if (TRUE == pArgs->gPrimary)
        {
            status = KEYGEN_createPrimaryKeyAttributes(
                pArgs->gKeyType, pArgs->gKeySize, pArgs->gpKeyHandle,
                &pAttrList);
            if (OK != status)
                goto exit;

            eccTapArgs.tokenId = pArgs->gHierarchy;
            eccTapArgs.pKeyAttributes = pAttrList;
        }

        status = CRYPTO_INTERFACE_EC_generateKeyPairAlloc(pArgs->gCurve, (void **) &pEccKey, RANDOM_rngFun, (void *) pRand, pArgs->gKeyType, &eccTapArgs);
        if (OK != status)
            goto exit;

        status = CRYPTO_loadAsymmetricKey(pKey, pArgs->gKeyType, (void **) &pEccKey);
        if (OK != status)
            goto exit;
    }
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    else if (akt_hybrid == pArgs->gKeyType)
    {
        if (pArgs->gCurve) /* Ecdsa or Eddsa, curve already validated */
        {
            status = CRYPTO_INTERFACE_EC_generateKeyPairAlloc(pArgs->gCurve, (void **) &pKey->key.pECC, RANDOM_rngFun, pRand, akt_ecc, NULL);
            if (OK != status)
                goto exit;

            pKey->clAlg = pArgs->gCurve;
        }
        else /* pArgs->gKeySize, ie RSA */
        {
            status = CRYPTO_createRSAKey(pKey, NULL);
            if (OK != status)
                goto exit;

            /* TO DO need crypto interface form that takes in a public key */
            status = CRYPTO_INTERFACE_RSA_generateKey (pRand, pKey->key.pRSA, pArgs->gKeySize, NULL);
            if (OK != status)
                goto exit;

            if (pArgs->gKeyIsPss)
            {
                ubyte hashAlgo = ht_sha256; /* default */
                ubyte4 saltLen = 32; /* default */

                switch (pArgs->gKeySize) /* Get pss params from keySize, ignore input hash and salt TODO WARNINGS TO USER */
                {
                    case 2048:
                        pKey->clAlg = cid_RSA_2048_PSS;
                        break;
                    case 3072:
                        pKey->clAlg = cid_RSA_3072_PSS;
                        break;
                    case 4096:
                        pKey->clAlg = cid_RSA_4096_PSS;
                        hashAlgo = ht_sha384;
                        saltLen = 48;
                        break;
                    default:
                        status = ERR_INVALID_INPUT; /* already should have been validated */
                        goto exit;
                }

                status = ALG_ID_createRsaPssParams(hashAlgo, MOC_PKCS1_ALG_MGF1, hashAlgo, saltLen, 0xBC, &pKey->pAlgoId);
                if (OK != status)
                    goto exit;
            }
            else
            {
                switch (pArgs->gKeySize)
                {
                    case 2048:
                        pKey->clAlg = cid_RSA_2048_PKCS15;
                        break;
                    case 3072:
                        pKey->clAlg = cid_RSA_3072_PKCS15;
                        break;
                    case 4096:
                        pKey->clAlg = cid_RSA_4096_PKCS15;
                        break;
                    default:
                        status = ERR_INVALID_INPUT;
                        goto exit;
                }
            }
        }

        /* Change keytype to hybrid */
        pKey->type = akt_hybrid;

        status = CRYPTO_INTERFACE_QS_newCtx(&pKey->pQsCtx, pArgs->gQsAlg);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_QS_generateKeyPair(pKey->pQsCtx, RANDOM_rngFun, pRand);
    }
    else if (akt_qs == pArgs->gKeyType)
    {
        /* Change keytype to qs */
        pKey->type = akt_qs;

        status = CRYPTO_INTERFACE_QS_newCtx(&pKey->pQsCtx, pArgs->gQsAlg);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_QS_generateKeyPair(pKey->pQsCtx, RANDOM_rngFun, pRand);
    }
#endif
#ifndef  __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
    else if (akt_dsa == pArgs->gKeyType)
    {
#ifdef __ENABLE_DIGICERT_DSA__
        DSAHashType hashType = ( 160 == pArgs->gQSize ? DSA_sha1 : (224 == pArgs->gQSize ? DSA_sha224 : DSA_sha256) );

        status = CRYPTO_createDSAKey(pKey, NULL);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_DSA_generateKeyAux2(pRand, pKey->key.pDSA, pArgs->gKeySize, pArgs->gQSize, hashType, NULL);
        if (OK != status)
            goto exit;
#endif
    }
#endif

#ifdef __ENABLE_DIGICERT_TAP__
    if (TRUE == pArgs->gPrimary && 0 != pArgs->gKeyNonceHandle)
    {
        status = KEYGEN_persistDataAtNVIndex(
            pTapArgs->gpTapCtx, pTapArgs->gpTapEntityCredList,
            pArgs->gKeyNonceHandle,
            ((TAP_Buffer *) pAttrList->pAttributeList[1].pStructOfType)->pBuffer,
            ((TAP_Buffer *) pAttrList->pAttributeList[1].pStructOfType)->bufferLen,
            TAP_AUTH_CONTEXT_PLATFORM);
        if (OK != status)
            goto exit;
    }
#endif

exit:

#ifdef __ENABLE_DIGICERT_TAP__
    if (NULL != pAttrList)
    {
        KEYGEN_deletePrimaryKeyAttributes(&pAttrList);
    }
    if (NULL != pEccKey)
    {
        (void) CRYPTO_INTERFACE_EC_deleteKeyAux(&pEccKey);
    }

    if (NULL != pRsaKey)
    {
        (void) CRYPTO_INTERFACE_RSA_freeKeyAux(&pRsaKey, NULL);
    }
#endif

    return status;
}

#ifdef __ENABLE_KEYSTORE_PATH__
MOC_EXTERN MSTATUS KEYGEN_validateKeystorePath(sbyte *pKeyStorePath, ubyte keyStoreBitMap)
{
    MSTATUS status = OK;
    sbyte *pFullPath = NULL;

    /* CA dir */
    if (keyStoreBitMap & KEYGEN_KEYSTORE_CA_MASK)
    {
        status = COMMON_UTILS_addPathComponent(pKeyStorePath, KEYGEN_FOLDER_CA, &pFullPath);
        if (OK != status)
            goto exit;

        if (FALSE == FMGMT_pathExists(pFullPath, NULL))
        {
            status = ERR_PATH_IS_INVALID;
            MSG_LOG_print(MSG_LOG_ERROR, "%s subdir inside keystore does not exist: status = %d\n", KEYGEN_FOLDER_CA, status);
            goto exit;
        }
    }

    /* Certs dir */
    if (keyStoreBitMap & KEYGEN_KEYSTORE_CERTS_MASK)
    {
        (void) DIGI_FREE((void**)&pFullPath);
        status = COMMON_UTILS_addPathComponent(pKeyStorePath, KEYGEN_FOLDER_CERTS, &pFullPath);
        if (OK != status)
            goto exit;

        if (FALSE == FMGMT_pathExists(pFullPath, NULL))
        {
            status = ERR_PATH_IS_INVALID;
            MSG_LOG_print(MSG_LOG_ERROR, "%s subdir inside keystore does not exist: status = %d\n", KEYGEN_FOLDER_CERTS, status);
            goto exit;
        }
    }

    /* Keys dir */
    if (keyStoreBitMap & KEYGEN_KEYSTORE_KEYS_MASK)
    {
        (void) DIGI_FREE((void**)&pFullPath);
        status = COMMON_UTILS_addPathComponent(pKeyStorePath, KEYGEN_FOLDER_KEYS, &pFullPath);
        if (OK != status)
            goto exit;

        if (FALSE == FMGMT_pathExists(pFullPath, NULL))
        {
            status = ERR_PATH_IS_INVALID;
            MSG_LOG_print(MSG_LOG_ERROR, "%s subdir inside keystore does not exist: status = %d\n", KEYGEN_FOLDER_KEYS, status);
            goto exit;
        }
    }

    /* Req dir */
    if (keyStoreBitMap & KEYGEN_KEYSTORE_REQ_MASK)
    {
        (void) DIGI_FREE((void**)&pFullPath);
        status = COMMON_UTILS_addPathComponent(pKeyStorePath, KEYGEN_FOLDER_REQ, &pFullPath);
        if (OK != status)
            goto exit;

        if (FALSE == FMGMT_pathExists(pFullPath, NULL))
        {
            status = ERR_PATH_IS_INVALID;
            MSG_LOG_print(MSG_LOG_ERROR, "%s subdir inside keystore does not exist: status = %d\n", KEYGEN_FOLDER_REQ, status);
            goto exit;
        }
    }

    /* Conf dir */
    if (keyStoreBitMap & KEYGEN_KEYSTORE_CONF_MASK)
    {
        (void) DIGI_FREE((void**)&pFullPath);
        status = COMMON_UTILS_addPathComponent(pKeyStorePath, KEYGEN_FOLDER_CONF, &pFullPath);
        if (OK != status)
            goto exit;

        if (FALSE == FMGMT_pathExists(pFullPath, NULL))
        {
            status = ERR_PATH_IS_INVALID;
            MSG_LOG_print(MSG_LOG_ERROR, "%s subdir inside keystore does not exist: status = %d\n", KEYGEN_FOLDER_CONF, status);
            goto exit;
        }
    }

exit:
    (void) DIGI_FREE((void**)&pFullPath);
    return status;
}
#endif

static MSTATUS KEYGEN_getSigningCertificate(KeyGenArgs *pArgs, certDescriptor *pCert, byteBoolean keyOnly)
{
    MSTATUS status = OK;

    ubyte4 pemType = 0;
    ubyte *pPwd = NULL;
    ubyte4 pwdLen = 0;
#ifdef __ENABLE_KEYSTORE_PATH__
    sbyte *pFullPath = NULL;
#endif

    if (!keyOnly)
    {
        /* internal method, NULL checks not necc */
        MSG_LOG_print(MSG_LOG_VERBOSE, "Reading in Signing Certificate...%s\n","");

        if (FORMAT_PEM == pArgs->gInForm)
        {
            if (NULL != pArgs->gpSigningCert && NULL == pArgs->gpSigningCertBuffer)
            {
#ifdef __ENABLE_KEYSTORE_PATH__
                status = CERT_ENROLL_getFullPath(pArgs->gpKeyStorePath, KEYGEN_FOLDER_CERTS,
                                                pArgs->gpSigningCert, NULL, &pFullPath);
                if (OK != status)
                    goto exit;

                status = DIGICERT_readFile( (const char* ) pFullPath, &pArgs->gpSigningCertBuffer, &pArgs->gSigningCertLen);
#else
                status = DIGICERT_readFile( (const char* ) pArgs->gpSigningCert, &pArgs->gpSigningCertBuffer, &pArgs->gSigningCertLen);
#endif
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR, "Unable to open or read file: %s\n", pArgs->gpSigningCert);
                    goto exit;
                }
            }

            status = BASE64_decodePemMessageAlloc (pArgs->gpSigningCertBuffer, pArgs->gSigningCertLen, &pemType, &pCert->pCertificate, &pCert->certLength);
            if (OK != status)
                goto exit;

            if (MOC_PEM_TYPE_CERT != pemType)
            {
                MSG_LOG_print(MSG_LOG_ERROR, "Invalid PEM Form Signing Certificate.\n%s","");
                status = ERR_INVALID_INPUT;
                goto exit;
            }
        }
        else /* FORMAT_DER == gInForm */
        {
            /* DER buffered form not supported (yet) */

            /* we'll have to assume the input is valid for now */
#ifdef __ENABLE_KEYSTORE_PATH__
            status = CERT_ENROLL_getFullPath(pArgs->gpKeyStorePath, KEYGEN_FOLDER_CERTS,
                                            pArgs->gpSigningCert, NULL, &pFullPath);
            if (OK != status)
                goto exit;
            status = DIGICERT_readFile( (const char* ) pFullPath, &pCert->pCertificate, &pCert->certLength);
#else
            status = DIGICERT_readFile( (const char* ) pArgs->gpSigningCert, &pCert->pCertificate, &pCert->certLength);
#endif
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR, "Unable to open or read file: %s\n", pArgs->gpSigningCert);
                goto exit;
            }
        }
        MSG_LOG_print(MSG_LOG_VERBOSE, "Done%s\n","");
    }
    MSG_LOG_print(MSG_LOG_VERBOSE, "Reading in Signing Key...%s\n","");

    if (NULL != pArgs->gpSigningKey && NULL == pArgs->gpSigningKeyBuffer)
    {
#ifdef __ENABLE_KEYSTORE_PATH__
        if (NULL != pFullPath)
            (void) DIGI_FREE((void **) &pFullPath);

        status = CERT_ENROLL_getFullPath(pArgs->gpKeyStorePath, KEYGEN_FOLDER_KEYS,
                                        pArgs->gpSigningKey, NULL, &pFullPath);
        if (OK != status)
            goto exit;

        status = DIGICERT_readFile( (const char* ) pFullPath, &pArgs->gpSigningKeyBuffer, &pArgs->gSigningKeyLen);
#else
        status = DIGICERT_readFile( (const char* ) pArgs->gpSigningKey, &pArgs->gpSigningKeyBuffer, &pArgs->gSigningKeyLen);
#endif
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "Unable to open or read file: %s\n", pArgs->gpSigningKey);
            goto exit;
        }
    }

    status = DIGI_MALLOC((void **) &pCert->pKey, sizeof(AsymmetricKey));
    if (OK != status)
        goto exit;

    status = CRYPTO_initAsymmetricKey(pCert->pKey);
    if (OK != status)
        goto exit;

    if (pArgs->gGetSigningKeyPw)
    {
        status = KEYGEN_getPassword(&pPwd, &pwdLen, "PEM", "signing key");
        if (OK != status)
            goto exit;
    }

    /* OK to call if pPwd is null, it'll still deserialize non-pw protected keys */
    status = CRYPTO_deserializeAsymKeyWithCreds ( pArgs->gpSigningKeyBuffer, pArgs->gSigningKeyLen, NULL, pPwd, pwdLen, NULL, pCert->pKey);
    if (OK != status)
    {
        if (pArgs->gGetSigningKeyPw)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "Cannot retrieve signing key. Make sure the password you entered is correct.%s\n","");
        }
        else
        {
            MSG_LOG_print(MSG_LOG_ERROR, "Cannot retrieve signing key. Use -skt argument if the key is TAP and/or the -skp argument if the key is password protected.%s\n","");
        }
        goto exit;
    }

    /* if RSA, CRYPTO_deserializeAsymKey will only produce type akt_rsa, so check oidFlag for PSS */
    if (akt_rsa == pCert->pKey->type && NULL != pCert->pKey->pAlgoId && ALG_ID_RSA_SSA_PSS_OID == pCert->pKey->pAlgoId->oidFlag)
    {
        pCert->pKey->type = akt_rsa_pss;

        if (NULL != pCert->pKey->pAlgoId->pParams)
        {
            RsaSsaPssAlgIdParams *pParams = (RsaSsaPssAlgIdParams *) (pCert->pKey->pAlgoId->pParams);

            if (MOC_PKCS1_ALG_MGF1 != pParams->mgfAlgo)
            {
                MSG_LOG_print(MSG_LOG_ERROR, "PSS Signing Key's MGF identifier is not the standard MGF1. This is not supported.%s\n","");
                status = ERR_INVALID_INPUT;
                goto exit;
            }

            if (pParams->digestId != pParams->mgfDigestId)
            {
                MSG_LOG_print(MSG_LOG_ERROR, "Signing Key's digest algorithm is not the same as the MGF's digest algorithm. This is not supported.%s\n","");
                status = ERR_INVALID_INPUT;
                goto exit;
            }

            if (0xBC != pParams->trailerField)
            {
                MSG_LOG_print(MSG_LOG_ERROR, "Signing Key's trailer field is not the default value of 1. This is not supported.%s\n","");
                status = ERR_INVALID_INPUT;
                goto exit;
            }

            if (NOT_SPECIFIED == pArgs->gHashAlgo)
            {
                pArgs->gHashAlgo = pParams->digestId;
            }
            else if ((ubyte) pArgs->gHashAlgo != pParams->digestId)
            {
                MSG_LOG_print(MSG_LOG_WARNING, "Signing Key's digest algorithm (possibly the default of SHA1) differs from -d command line option, using the -d option.%s\n","");
                pParams->digestId = (ubyte) pArgs->gHashAlgo;
                pParams->mgfDigestId = (ubyte) pArgs->gHashAlgo;
            }

            if (NOT_SPECIFIED == pArgs->gSaltLen)
            {
                pArgs->gSaltLen = (sbyte4) pParams->saltLen;
            }
            else if ((ubyte4) pArgs->gSaltLen != pParams->saltLen)
            {
                MSG_LOG_print(MSG_LOG_WARNING, "Signing Key's salt length differs from -slt command line option, using the -slt option.%s\n","");
                pParams->saltLen = (ubyte4) pArgs->gSaltLen;
            }
        }
    }

    MSG_LOG_print(MSG_LOG_VERBOSE, "Done.%s\n","");

exit:

#ifdef __ENABLE_KEYSTORE_PATH__
    if (NULL != pFullPath)
    {
        (void) DIGI_FREE((void **) &pFullPath);
    }
#endif

    if (NULL != pPwd)
    {
        (void) DIGI_MEMSET_FREE(&pPwd, pwdLen);
    }

    return status;
}

#ifdef __ENABLE_DIGICERT_PKCS12__
static MSTATUS KEYGEN_generatePkcs12(KeyGenArgs *pArgs, AsymmetricKey *pKey, certDescriptor *pCert, randomContext *pRand)
{
    MSTATUS status = OK;
    SizedBuffer certs = {0};
    ubyte *pKeyBlob = NULL;
    ubyte4 keyBlobLen = 0;
    ubyte *pEncPw = NULL;
    ubyte4 encPwLen = 0;
    ubyte *pPrivacyPswd = NULL;
    ubyte4 privacyPswdLen = 0;
    ubyte *pIntegrityPswd = NULL;
    ubyte4 integrityPswdLen = 0;
    ubyte *pRetPkcs12CertDer = NULL;
    ubyte4 retPkcs12CertDerLen = 0;

#ifdef __ENABLE_KEYSTORE_PATH__
    sbyte *pFullPath = NULL;
#endif

    /* internal method, NULL checks not necc */

    certs.length = pCert->certLength;
    certs.data = pCert->pCertificate;

    status = CRYPTO_serializeAsymKey (pKey, mocanaBlobVersion2, &pKeyBlob, &keyBlobLen);
    if (OK != status)
        goto exit;

    /* get passwords, buffers will be allocated even if password is the empty string */
    if (pArgs->gPkcs12GetKeyPw)
    {
        status = KEYGEN_getPassword(&pEncPw, &encPwLen, "Key Encryption", "private key");
        if (OK != status)
            goto exit;

        if (!encPwLen)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "Encryption Key password cannot be empty string.%s\n","");
            status = ERR_INVALID_INPUT;
            goto exit;
        }
    }

    if (pArgs->gPkcs12GetPrivacyPw)
    {
        status = KEYGEN_getPassword(&pPrivacyPswd, &privacyPswdLen, "Privacy", "pkcs12 document");
        if (OK != status)
            goto exit;
    }

    if (pArgs->gPkcs12GetIntegrityPw)
    {
        status = KEYGEN_getPassword(&pIntegrityPswd, &integrityPswdLen, "Integrity", "pkcs12 document");
        if (OK != status)
            goto exit;
    }

    status = PKCS12_EncryptPFXPduPwMode(pRand, &certs, 1, pKeyBlob, keyBlobLen, NULL, 0, pEncPw, encPwLen, pArgs->gPkcs12EncryptionType, pPrivacyPswd, privacyPswdLen,
                                        pIntegrityPswd, integrityPswdLen, &pRetPkcs12CertDer, &retPkcs12CertDerLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR, "Unable to generate pkcs12 pxf file, status = %d\n", status);
        goto exit;
    }

    MSG_LOG_print(MSG_LOG_VERBOSE, "Writing pkcs12 pxf file %s...\n", pArgs->gpPkcs12File);

#ifdef __ENABLE_KEYSTORE_PATH__
    status = CERT_ENROLL_getFullPath(pArgs->gpKeyStorePath, KEYGEN_FOLDER_KEYS,
                                        pArgs->gpPkcs12File, NULL, &pFullPath);
    if (OK != status)
        goto exit;

    status = DIGICERT_writeFile((const char *) pFullPath, pRetPkcs12CertDer, retPkcs12CertDerLen);
#else
    status = DIGICERT_writeFile((const char *) pArgs->gpPkcs12File, pRetPkcs12CertDer, retPkcs12CertDerLen);
#endif

exit:

#ifdef __ENABLE_KEYSTORE_PATH__
    if (NULL != pFullPath)
    {
        (void) DIGI_FREE((void **) &pFullPath);
    }
#endif

    if (NULL != pKeyBlob)
    {
        (void) DIGI_MEMSET_FREE(&pKeyBlob, keyBlobLen);
    }

    if (NULL != pEncPw)
    {
        (void) DIGI_MEMSET_FREE(&pEncPw, encPwLen);
    }

    if (NULL != pPrivacyPswd)
    {
        (void) DIGI_MEMSET_FREE(&pPrivacyPswd, privacyPswdLen);
    }

    if (NULL != pIntegrityPswd)
    {
        (void) DIGI_MEMSET_FREE(&pIntegrityPswd, integrityPswdLen);
    }

    if (NULL != pRetPkcs12CertDer)
    {
        (void) DIGI_MEMSET_FREE(&pRetPkcs12CertDer, retPkcs12CertDerLen);
    }

    return status;
}
#endif

static intBoolean KEYGEN_isLeapYear(ubyte2 year)
{
    return (((year % 100) != 0) && ((year % 4) == 0)) || ((year % 400) == 0);
}

MOC_EXTERN MSTATUS KEYGEN_calculateEndDate(KeyGenArgs *pArgs)
{
    MSTATUS status = OK;
    ubyte daysInCurrentMonth;
    ubyte currentDay;
    ubyte currentMonth;
    ubyte currentYear;
    ubyte4 totalDays;
    TimeDate startDate = {0};

    if (NULL == pArgs)
    {
        return ERR_NULL_POINTER;
    }

    if (TRUE == pArgs->gHasStartDate)
    {
        pArgs->gStartDate.m_year -= 1970;
        startDate.m_year = pArgs->gStartDate.m_year;
        startDate.m_month = pArgs->gStartDate.m_month;
        startDate.m_day = pArgs->gStartDate.m_day;
        startDate.m_hour = 0;
        startDate.m_minute = 0;
        startDate.m_second = 0;
    }
    else
    {
        RTOS_timeGMT(&startDate);
        (void) DIGI_MEMCPY((ubyte *) &pArgs->gStartDate, (ubyte *) &startDate, sizeof(TimeDate));
    }

    totalDays    = pArgs->gDays;
    currentDay   = startDate.m_day;
    currentMonth = startDate.m_month;
    currentYear  = startDate.m_year;

    (void) DIGI_MEMCPY((ubyte *) &pArgs->gEndDate, (ubyte *) &startDate, sizeof(TimeDate));

    if (((2 == currentMonth) && ((30 == currentDay) || (31 == currentDay) || ((FALSE == KEYGEN_isLeapYear(1970 + currentYear)) && (29 == currentDay)))) ||
        (((4 == currentMonth) || (6 == currentMonth) || (9 == currentMonth) || (11 == currentMonth)) && (31 == currentDay)))
    {
        status = ERR_INVALID_ARG;
        MSG_LOG_print(MSG_LOG_ERROR, "Invalid date or an invalid leap year provided. status = %d\n", status);
        return status;
    }
    do
    {
        switch(currentMonth)
        {
            /* FALLTHROUGH */
            case  1:
            case  3:
            case  5:
            case  7:
            case  8:
            case 10:
            case 12: daysInCurrentMonth = 31;
                     break;
            /* FALLTHROUGH */
            case  4:
            case  6:
            case  9:
            case 11: daysInCurrentMonth = 30;
                     break;
            // February case
            default: daysInCurrentMonth = ((KEYGEN_isLeapYear(1970 + currentYear) == TRUE) ? 29 : 28);
        }

        if (totalDays + currentDay <= daysInCurrentMonth)
        {
            currentDay += totalDays;
            break;
        }

        totalDays -= (daysInCurrentMonth - currentDay + 1);
        currentDay = 1;
        if (12 == currentMonth)
        {
            currentMonth = 1;
            currentYear += 1;
        }
        else
        {
            currentMonth++;
        }
    } while (totalDays > 0);

    pArgs->gEndDate.m_day = currentDay;
    pArgs->gEndDate.m_month = currentMonth;
    pArgs->gEndDate.m_year = currentYear;
    return status;
}

static MSTATUS KEYGEN_parseCSR(KeyGenArgs *pArgs, certExtensions *pExtensions, certDistinguishedName **ppSubject)
{
    MSTATUS status = OK;
#ifdef __ENABLE_KEYSTORE_PATH__
    sbyte *pFullPath = NULL;
#endif

    if (NULL != pArgs->gpInCsrFile && NULL == pArgs->gpInCsrBuffer)
    {
#ifdef __ENABLE_KEYSTORE_PATH__
        status = CERT_ENROLL_getFullPath(pArgs->gpKeyStorePath, KEYGEN_FOLDER_CONF,
                                        pArgs->gpInCsrFile, NULL, &pFullPath);
        if (OK != status)
            goto exit;

        status = DIGICERT_readFile( (const char* ) pFullPath, &pArgs->gpInCsrBuffer, &pArgs->gInCsrLen);
#else
        status = DIGICERT_readFile( (const char* ) pArgs->gpInCsrFile, &pArgs->gpInCsrBuffer, &pArgs->gInCsrLen);
#endif
        if (OK != status)
        {
            status = ERR_FILE_OPEN_FAILED;
            MSG_LOG_print(MSG_LOG_ERROR, "Failed to open input CSR conf file: %s\n", pArgs->gpInCsrFile);
            goto exit;
        }
    }

    status = CERT_ENROLL_addCsrAttributeTOML(pArgs->gpInCsrBuffer, pArgs->gInCsrLen, NULL, ppSubject, &pExtensions);
    if (OK != status)
        goto exit;

    status = KEYGEN_calculateEndDate(pArgs);
    if (OK != status)
        goto exit;

    status = CERT_ENROLL_setCertDates(*ppSubject, &(pArgs->gStartDate), &(pArgs->gEndDate));

exit:

#ifdef __ENABLE_KEYSTORE_PATH__
    if (NULL != pFullPath)
    {
        (void) DIGI_FREE((void **) &pFullPath);
    }
#endif

    return status;
}

MOC_EXTERN MSTATUS KEYGEN_createCSR(KeyGenArgs *pArgs)
{
    MSTATUS status = OK;

    certDescriptor signingCert = {0};
    certDistinguishedName *pDN = NULL;
    certExtensions extensions = {0};

    ubyte *pOutReq = NULL;
    ubyte4 reqLen = 0;

    ubyte *pOutCsr = NULL;
    ubyte4 outCsrLen = 0;

#ifdef __ENABLE_KEYSTORE_PATH__
    sbyte *pFullPath = NULL;
#endif

    /* This call will get both the cert and key in the certDescriptor */
    status = KEYGEN_getSigningCertificate(pArgs, &signingCert, pArgs->gpSigningCert ? FALSE : TRUE);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_TAP__
    if (pArgs->gSignKeyTap)
    {
        if (0x2 != (signingCert.pKey->type >> 16))
        {
            MSG_LOG_print(MSG_LOG_WARNING, "TAP signing key requested but key is not TAP. Continuing.%s\n","");
        }
    }
    else
    {
        if (signingCert.pKey->type >> 16)
        {
            MSG_LOG_print(MSG_LOG_WARNING, "TAP signing key not requested but key is TAP. Continuing.%s\n","");
        }
    }
#endif

    if (NULL == pArgs->gpSigningCert)
    {
        status = KEYGEN_parseCSR(pArgs, &extensions, &pDN);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "Unable to parse the input CSR file in order to generate a signed CSR. status = %d\n", status);
            goto exit;
        }
    }
    else
    {
        status = CA_MGMT_allocCertDistinguishedName(&pDN);
        if (OK != status)
            goto exit;

        status = CA_MGMT_extractCertDistinguishedName(signingCert.pCertificate,
                                                    signingCert.certLength,
                                                    TRUE, pDN);
        if (OK != status)
            goto exit;
    }

    status = PKCS10_GenerateCertReqFromDNEx(signingCert.pKey, pArgs->gHashAlgo,
                                            pDN, NULL, &pOutReq, &reqLen);
    if (OK != status)
        goto exit;

    status = PKCS10_CertReqToCSR(pOutReq, reqLen, &pOutCsr, &outCsrLen);
    if (OK != status)
        goto exit;

    MSG_LOG_print(MSG_LOG_VERBOSE, "Writing signed CSR request to file.%s\n","");

#ifdef __ENABLE_KEYSTORE_PATH__
    status = CERT_ENROLL_getFullPath(pArgs->gpKeyStorePath, KEYGEN_FOLDER_REQ,
                                     pArgs->gpOutFile, NULL, &pFullPath);
    if (OK != status)
        goto exit;

    status = DIGICERT_writeFile((const char *) pFullPath, pOutCsr, outCsrLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR, "Failed to write CSR to file: %s\n", pArgs->gpOutFile);
    }
#else
    status = DIGICERT_writeFile((const char *) pArgs->gpOutFile, pOutCsr, outCsrLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR, "Failed to write CSR to file: %s\n", pArgs->gpOutFile);
    }
#endif

exit:

#ifdef __ENABLE_KEYSTORE_PATH__
    if (NULL != pFullPath)
    {
        (void) DIGI_FREE((void **) &pFullPath);
    }
#endif

    (void) CA_MGMT_freeCertDistinguishedName(&pDN);

    if (NULL != signingCert.pKey)
    {
        (void) CRYPTO_uninitAsymmetricKey(signingCert.pKey, 0);
        (void) DIGI_FREE((void **) &signingCert.pKey);
    }

    if (NULL == pArgs->gpSigningCert)
    {
        CERT_ENROLL_freeExtensions(&extensions);
    }
    else
    {
        (void) CA_MGMT_freeCertificate(&signingCert);
    }

    if (NULL != pOutReq)
    {
        (void) DIGI_MEMSET_FREE(&pOutReq, reqLen);
    }

    if (NULL != pOutCsr)
    {
        (void) DIGI_MEMSET_FREE(&pOutCsr, outCsrLen);
    }

    return status;
}

MOC_EXTERN MSTATUS KEYGEN_generateCertificate(KeyGenArgs *pArgs, AsymmetricKey *pKey, randomContext *pRand, ubyte **ppCert, ubyte4 *pCertLen)
{
    MSTATUS status = OK;
    ubyte hashAlgo = 0;
    ubyte4 saltLen = 0;

    certDescriptor retCert = {0};
    certDescriptor signingCert = {0};
    ASN1_ITEMPTR pRootItem = NULL;

    certExtensions extensions = {0};
    certDistinguishedName *pSubject = NULL;

    ubyte *pCertPem = NULL;
    ubyte4 certPemLen = 0;
    ubyte4 signingKeyType = pArgs->gKeyType; /* default for self signed */
    ubyte4 signingKeySize = pArgs->gKeySize; /* default for self signed */
    ubyte4 signingKeyCurve = pArgs->gCurve; /* default for self signed */

#ifdef __ENABLE_KEYSTORE_PATH__
    sbyte *pFullPath = NULL;
#endif

    /* Get the signing key and certificate if there is one */
    if (NULL != pArgs->gpSigningKey || NULL != pArgs->gpSigningKeyBuffer)
    {
        status = KEYGEN_getSigningCertificate(pArgs, &signingCert, FALSE);
        if (OK != status)
            goto exit;

        signingKeyType = signingCert.pKey->type;

#ifdef __ENABLE_DIGICERT_TAP__
        if (pArgs->gSignKeyTap)
        {
            if (0x2 != (signingKeyType >> 16))
            {
                MSG_LOG_print(MSG_LOG_WARNING, "TAP signing key requested but key is not TAP. Continuing.%s\n","");
            }
        }
        else
        {
            if (signingKeyType >> 16)
            {
                MSG_LOG_print(MSG_LOG_WARNING, "TAP signing key not requested but key is TAP. Continuing.%s\n","");
            }
        }
#endif

        if (akt_rsa == signingKeyType || akt_tap_rsa == signingKeyType) /* rsa_pss type already has its pAlgoId */
        {
            sbyte4 keyByteLen = 0;

            status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux(signingCert.pKey->key.pRSA, &keyByteLen);
            if (OK != status)
                goto exit;

            signingKeySize = (ubyte4) (8 * keyByteLen);
        }
        else if (akt_ecc == signingKeyType || akt_tap_ecc == signingKeyType || akt_ecc_ed == signingKeyType)
        {
             status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(signingCert.pKey->key.pECC, &signingKeyCurve);
             if (OK != status)
                goto exit;

        }
#ifdef __ENABLE_DIGICERT_PQC__
        else if (akt_hybrid != signingKeyType && akt_qs != signingKeyType && akt_rsa_pss != signingKeyType && akt_ecc_ed != signingKeyType)
#else
        else if (akt_rsa_pss != signingKeyType)
#endif
        {
            MSG_LOG_print(MSG_LOG_ERROR, "Input Signing Key and Certificate type not supported.%s\n","");
            status = ERR_INVALID_INPUT;
            goto exit;
        }
    }
    else if (akt_rsa_pss == signingKeyType)
    {
        /* self signed rsa pss may need a pAlgoId if key-digest and key-salt were not specified, try to use -d and -slt if not */
        if (NULL == pKey->pAlgoId)
        {
            if (NOT_SPECIFIED != pArgs->gHashAlgo)
            {
                hashAlgo = (ubyte) pArgs->gHashAlgo;
            }
            else
            {
                if (signingKeySize <= 1024)
                {
                    hashAlgo = ht_sha1;
                }
                else if (signingKeySize <= 2048)
                {
                    hashAlgo = ht_sha256;
                }
                else if (signingKeySize <= 3072)
                {
                    hashAlgo = ht_sha384;
                }
                else
                {
                    hashAlgo = ht_sha512;
                }
            }

            if (NOT_SPECIFIED != pArgs->gSaltLen)
            {
                saltLen = (ubyte4) pArgs->gSaltLen;
            }
            else
            {
                switch (hashAlgo)
                {
                    case ht_md5:
                        saltLen = 16;
                        break;
                    case ht_sha1:
                        saltLen = 20;
                        break;
                    case ht_sha224:
                        saltLen = 28;
                        break;
                    case ht_sha256:
                        saltLen = 32;
                        break;
                    case ht_sha384:
                        saltLen = 48;
                        break;
                    case ht_sha512:
                        saltLen = 64;
                        break;
                }
            }

            status = ALG_ID_createRsaPssParams(hashAlgo, MOC_PKCS1_ALG_MGF1, hashAlgo, saltLen, 0xBC, &pKey->pAlgoId);
            if (OK != status)
                goto exit;
        }
        else /* Warn what will be ignored */
        {
            if (NOT_SPECIFIED != pArgs->gHashAlgo && pArgs->gHashAlgo != pArgs->gKeyHashAlgo)
            {
                MSG_LOG_print(MSG_LOG_WARNING, "Key digest algorithm specified for self-signed certificate, ignoring -d parameter.%s\n","");
            }

            if (NOT_SPECIFIED != pArgs->gSaltLen && pArgs->gSaltLen != pArgs->gKeySaltLen)
            {
                MSG_LOG_print(MSG_LOG_WARNING, "Key digest or key salt length specified for self-signed certificate, ignoring -slt parameter.%s\n","");
            }
        }
    }

    if (akt_rsa == signingKeyType || akt_tap_rsa == signingKeyType)
    {
        if (NOT_SPECIFIED == pArgs->gHashAlgo)
        {
            if (signingKeySize <= 2048)
            {
                hashAlgo = ht_sha256;
            }
            else if (signingKeySize <= 3072)
            {
                hashAlgo = ht_sha384;
            }
            else
            {
                hashAlgo = ht_sha512;
            }
        }
        else
        {
            hashAlgo = (ubyte) pArgs->gHashAlgo;
        }
    }
    else if (akt_ecc == signingKeyType || akt_tap_ecc == signingKeyType || akt_ecc_ed == signingKeyType)
    {
        if (NOT_SPECIFIED == pArgs->gHashAlgo)
        {
            switch (signingKeyCurve)
            {
                case cid_EC_P192:
                    hashAlgo = ht_sha1;
                    break;

                case cid_EC_P224:
                    hashAlgo = ht_sha224;
                    break;

                case cid_EC_P256:
                    hashAlgo = ht_sha256;
                    break;

                case cid_EC_P384:
                    hashAlgo = ht_sha384;
                    break;

                case cid_EC_P521:
                    hashAlgo = ht_sha512;
                    break;

                case cid_EC_Ed25519:
                    hashAlgo = ht_none; /* intrinsic */
                    break;

                case cid_EC_Ed448:
                    hashAlgo = ht_none; /* intrinsic */
                    break;

                default:
                    status = ERR_INVALID_INPUT;
                    goto exit;
            }
        }
        else
        {
            if (cid_EC_Ed25519 == signingKeyCurve || cid_EC_Ed448 == signingKeyCurve)
            {
                MSG_LOG_print(MSG_LOG_WARNING, "The digest -d specified will be ignored since it is an EdDSA signing key.%s\n","");
                hashAlgo = ht_none;
            }
            else
            {
                hashAlgo = (ubyte) pArgs->gHashAlgo;
            }
        }
    }
    /* certs not available for DSA */
#ifdef __ENABLE_DIGICERT_PQC__
    else if (akt_qs == signingKeyType)
    {
        if (NOT_SPECIFIED != pArgs->gHashAlgo)
        {
            MSG_LOG_print(MSG_LOG_WARNING, "The digest -d specified will be ignored since signing key is type qs.%s\n","");
        }
        hashAlgo = ht_none; /* intrinsic */
    }
    else if (akt_hybrid == signingKeyType)
    {
        ubyte hashAlgo = ht_sha256; /* default */

        if (cid_EC_P384 == pKey->clAlg || cid_RSA_4096_PKCS15 == pKey->clAlg || cid_RSA_4096_PSS == pKey->clAlg)
            hashAlgo = ht_sha384;

        if (NOT_SPECIFIED != pArgs->gHashAlgo)
        {
            MSG_LOG_print(MSG_LOG_WARNING, "The digest -d specified will be ignored since signing key is type hybrid.%s\n","");
        }
    }
#endif

    status = KEYGEN_parseCSR(pArgs, &extensions, &pSubject);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR, "Unable to parse the CSR file in order to generate the certificate. status = %d\n", status);
        goto exit;
    }

#ifndef __DISABLE_DIGICERT_CERT_SUBJECT_KEY_IDENTIFIER__
    status = CERT_ENROLL_addSubjectKeyIdentifier(pKey, &extensions);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR, "Unable to add the subjectKeyIndentifier to the certificate. status = %d\n", status);
        goto exit;
    }
#endif

    /* Get the signing certificate if there is one */
    if (NULL != pArgs->gpSigningKey || NULL != pArgs->gpSigningKeyBuffer)
    {
        ASN1_ITEMPTR pIssuerInfo = NULL;
        CStream cs = {0};
        MemFile mf = {0};

        MF_attach( &mf, signingCert.certLength, signingCert.pCertificate);
        CS_AttachMemFile( &cs, &mf);

        status = X509_parseCertificate( cs, &pRootItem);
        if (OK != status)
            goto exit;

        status = X509_getCertificateSubject(ASN1_FIRST_CHILD(pRootItem), &pIssuerInfo);
        if (OK != status)
            goto exit;


        status = ASN1CERT_generateCertificate(pKey, pSubject, signingCert.pKey, pIssuerInfo, cs, hashAlgo, &extensions,
                                              RANDOM_rngFun, pRand, &retCert.pCertificate, &retCert.certLength);
        if (ERR_BAD_LENGTH == status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "Unable to generate certificate. Key Size may be incompatible with digest size.%s\n","");
            goto exit;
        }
#ifdef __ENABLE_DIGICERT_TAP__
        else if (ERR_TAP_RC_AUTH_FAIL == status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "Unable to generate certificate. Incorrect or missing password for the sigining key.%s\n","");
            goto exit;
        }
#endif
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "Unable to generate certificate. status = %d\n", status);
            goto exit;
        }
    }
    else
    {
        status = ASN1CERT_generateSelfSignedCertificate(pKey, pSubject, hashAlgo, &extensions, RANDOM_rngFun, pRand,
                                                        &retCert.pCertificate, &retCert.certLength);
        if (ERR_BAD_LENGTH == status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "Unable to generate certificate. Key Size may be incompatible with digest size.%s\n","");
        }
        if (OK != status)
            goto exit;
    }

    if (pArgs->gVerbose)
    {
        const char *pOutForm = (FORMAT_DER == pArgs->gOutForm ? "DER" : "PEM");
        MSG_LOG_print(MSG_LOG_VERBOSE, "Writing certificate to file %s in %s form...\n", pArgs->gpOutCertFile, pOutForm);
    }

    if (FORMAT_DER == pArgs->gOutForm)
    {
#ifdef __ENABLE_KEYSTORE_PATH__
        status = CERT_ENROLL_getFullPath(pArgs->gpKeyStorePath, KEYGEN_FOLDER_CERTS,
                                         pArgs->gpOutCertFile, NULL, &pFullPath);
        if (OK != status)
            goto exit;

        /* write the certificate which is already in DER form */
        status = DIGICERT_writeFile((const char *) pFullPath, retCert.pCertificate, retCert.certLength);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "Failed to write certificate to file: %s\n", pArgs->gpOutCertFile);
            goto exit;
        }
#else
        /* write the certificate which is already in DER form */
        status = DIGICERT_writeFile((const char *) pArgs->gpOutCertFile, retCert.pCertificate, retCert.certLength);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "Failed to write certificate to file: %s\n", pArgs->gpOutCertFile);
            goto exit;
        }
#endif
    }
    else /* FORMAT_PEM == gOutForm, SSH is only for the gOutPubForm */
    {
        status = BASE64_makePemMessageAlloc (MOC_PEM_TYPE_CERT, retCert.pCertificate, retCert.certLength, &pCertPem, &certPemLen);
        if (OK != status)
            goto exit;

        /* Buffer mode output available for PEM form */
        if (NULL != ppCert)
        {
            *ppCert = pCertPem; pCertPem = NULL;
            *pCertLen = certPemLen;
        }
        else
        {
#ifdef __ENABLE_KEYSTORE_PATH__
            status = CERT_ENROLL_getFullPath(pArgs->gpKeyStorePath, KEYGEN_FOLDER_CERTS,
                                             pArgs->gpOutCertFile, NULL, &pFullPath);
            if (OK != status)
                goto exit;

            status = DIGICERT_writeFile((const char *) pFullPath, pCertPem, certPemLen);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR, "Failed to write certificate to file: %s\n", pArgs->gpOutCertFile);
                goto exit;
            }
#else
            status = DIGICERT_writeFile((const char *) pArgs->gpOutCertFile, pCertPem, certPemLen);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR, "Failed to write certificate to file: %s\n", pArgs->gpOutCertFile);
                goto exit;
            }
#endif
        }
    }

    if (NULL != pArgs->gpPkcs12File)
    {
#ifdef __ENABLE_DIGICERT_PKCS12__
        status = KEYGEN_generatePkcs12(pArgs, pKey, &retCert, pRand);
#else
        status = ERR_NOT_IMPLEMENTED;
#endif
    }

exit:

#ifdef __ENABLE_KEYSTORE_PATH__
    if (NULL != pFullPath)
    {
        (void) DIGI_FREE((void **) &pFullPath);
    }
#endif

    if (pSubject != NULL)
    {
        (void) CA_MGMT_freeCertDistinguishedName(&pSubject);
    }

    CERT_ENROLL_freeExtensions(&extensions);

    (void) CA_MGMT_freeCertificate(&retCert); /* don't change status, ignore return code */

    if (NULL != signingCert.pKey)
    {
        (void) CRYPTO_uninitAsymmetricKey(signingCert.pKey, 0);
        (void) DIGI_FREE((void **) &signingCert.pKey);
    }

    if (NULL != pRootItem)
    {
        TREE_DeleteTreeItem( (TreeItem*) pRootItem);
    }

    (void) CA_MGMT_freeCertificate(&signingCert);

    if (NULL != pCertPem)
    {
        (void) DIGI_MEMSET_FREE(&pCertPem, certPemLen);
    }

    return status;
}

/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_CV_CERT__
static MSTATUS KEYGEN_getSigningCvCertificate(KeyGenArgs *pArgs)
{
    MSTATUS status = OK;
    CV_CERT *pSigningCert = NULL;
    ubyte *pCert = NULL;
    ubyte4 certLen = 0;
    ubyte *pSerKey = NULL;
    ubyte4 serKeyLen = 0;
    ubyte4 signHashAlgo = 0;
    byteBoolean signIsPss = 0;
    AsymmetricKey *pSigningKey = NULL;

#ifdef __ENABLE_KEYSTORE_PATH__
    sbyte *pFullPath = NULL;

    status = CERT_ENROLL_getFullPath(pArgs->gpKeyStorePath, KEYGEN_FOLDER_CERTS,
                                     pArgs->gpSigningCert, NULL, &pFullPath);
    if (OK != status)
        goto exit;

    /* CV certs not supported in buffered mode */
    status = DIGICERT_readFile( (const char* ) pFullPath, &pCert, &certLen);
#else
    status = DIGICERT_readFile( (const char* ) pArgs->gpSigningCert, &pCert, &certLen);
#endif
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR, "Unable to open or read file: %s\n", pArgs->gpSigningCert);
        goto exit;
    }

    status = CV_CERT_parseCert(pCert, certLen, &pSigningCert);
    if (OK != status)
        goto exit;

    /* don't actually need public key */
    status = CV_CERT_parseKey(pSigningCert->pCvcKey, pSigningCert->cvcKeyLen, NULL, &signHashAlgo, &signIsPss);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_KEYSTORE_PATH__
    /* reuse */
    (void) DIGI_FREE((void **) &pFullPath);

    status = CERT_ENROLL_getFullPath(pArgs->gpKeyStorePath, KEYGEN_FOLDER_KEYS,
                                     pArgs->gpSigningKey, NULL, &pFullPath);
    if (OK != status)
        goto exit;

    status = DIGICERT_readFile( (const char* ) pFullPath, &pSerKey, &serKeyLen);
#else
    status = DIGICERT_readFile( (const char* ) pArgs->gpSigningKey, &pSerKey, &serKeyLen);
#endif
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR, "Unable to open or read file: %s\n", pArgs->gpSigningKey);
        goto exit;
    }

    status = DIGI_MALLOC((void **) &pSigningKey, sizeof(AsymmetricKey));
    if (OK != status)
        goto exit;

    status = CRYPTO_initAsymmetricKey(pSigningKey);
    if (OK != status)
        goto exit;

    status = CRYPTO_deserializeAsymKey (pSerKey, serKeyLen, NULL, pSigningKey);
    if (OK != status)
        goto exit;

    pArgs->gCvcData.pSignerKey = pSigningKey; pSigningKey = NULL;
    pArgs->gCvcData.signHashAlgo = signHashAlgo;
    pArgs->gCvcData.signIsPss = signIsPss;

    status = DIGI_MALLOC((void **) &pArgs->gCvcData.pSignerAuthRef, pSigningCert->certHolderRefLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pArgs->gCvcData.pSignerAuthRef, pSigningCert->pCertHolderRef, pSigningCert->certHolderRefLen);
    if (OK != status)
        goto exit;

    pArgs->gCvcData.signerAuthRefLen = pSigningCert->certHolderRefLen;

exit:

#ifdef __ENABLE_KEYSTORE_PATH__
    if (NULL != pFullPath)
    {
        (void) DIGI_FREE((void **) &pFullPath);
    }
#endif

    if (NULL != pSigningCert)
    {
        (void) DIGI_FREE((void **) &pSigningCert);
    }

    if (NULL != pSigningKey)
    {
        (void) CRYPTO_uninitAsymmetricKey(pSigningKey, NULL);
        (void) DIGI_FREE((void **) &pSigningKey);
    }

    if (NULL != pCert)
    {
        (void) DIGI_MEMSET_FREE(&pCert, certLen);
    }

    if (NULL != pSerKey)
    {
        (void) DIGI_MEMSET_FREE(&pSerKey, serKeyLen);
    }

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS KEYGEN_generateCvCertificate(KeyGenArgs *pArgs, AsymmetricKey *pKey)
{
    MSTATUS status = OK;

    ubyte *pCert = NULL;
    ubyte4 certLen = 0;

    pArgs->gCvcData.pCertKey = pKey;

#ifdef __ENABLE_KEYSTORE_PATH__
    sbyte *pFullPath = NULL;
#endif

    /* Get the signing key and certificate if there is one */
    if (NULL != pArgs->gpSigningKey)
    {
        status = KEYGEN_getSigningCvCertificate(pArgs);
        if (OK != status)
            goto exit;

    } /* else self signed, leave the signing data all NULL */

    status = CV_CERT_generateCert(&pArgs->gCvcData, &pCert, &certLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR, "Failed to generate CV Certificate! status = %d\n", status);
        goto exit;
    }

    MSG_LOG_print(MSG_LOG_VERBOSE, "Writing certificate to file %s in CV form...\n", pArgs->gpOutCertFile);

#ifdef __ENABLE_KEYSTORE_PATH__
    status = CERT_ENROLL_getFullPath(pArgs->gpKeyStorePath, KEYGEN_FOLDER_CERTS,
                                     pArgs->gpOutCertFile, NULL, &pFullPath);
    if (OK != status)
        goto exit;

    /* write the certificate which is already in DER form */
    status = DIGICERT_writeFile((const char *) pFullPath, pCert, certLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR, "Failed to write certificate to file %s in CV form\n", pArgs->gpOutCertFile);
        goto exit;
    }
#else
    status = DIGICERT_writeFile((const char *) pArgs->gpOutCertFile, pCert, certLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR, "Failed to write certificate to file %s in CV form\n", pArgs->gpOutCertFile);
        goto exit;
    }
#endif

exit:

#ifdef __ENABLE_KEYSTORE_PATH__
    if (NULL != pFullPath)
    {
        (void) DIGI_FREE((void **) &pFullPath);
    }
#endif

    if (NULL != pCert)
    {
        (void) DIGI_MEMSET_FREE(&pCert, certLen);
    }

    return status;
}

static MSTATUS KEYGEN_printCvCertKey(ubyte *pKey, sbyte4 keyLen)
{
    MSTATUS status = ERR_INVALID_INPUT;
    ubyte *pPtr = pKey;
    ubyte *pNextPtr = NULL;
    ubyte4 elemLen = 0;
    sbyte4 i = 0;
    byteBoolean isEcc = FALSE;

    /* OID */
    if (keyLen < 2 || 0x06 != pPtr[0])
        goto exit;

    status = CV_CERT_getLenAndValue(pPtr + 1, &pNextPtr, &elemLen);
    if (OK != status)
        goto exit;

    status = ERR_INVALID_INPUT;
    if (elemLen < 2)
        goto exit;

    DB_PRINT("OID : 0.");
    for (i = 0; i < elemLen - 1; i++)
    {
        DB_PRINT("%d.", (unsigned int) pNextPtr[i]);
    }
    DB_PRINT("%d id_TA_", (unsigned int) pNextPtr[elemLen - 1]);

    if (0x01 == pNextPtr[elemLen - 2])
    {
        DB_PRINT("RSA_");
        switch(pNextPtr[elemLen - 1])
        {
            case 0x01:
                DB_PRINT("SHA_1\n");
                break;
            case 0x02:
                DB_PRINT("SHA_256\n");
                break;
            case 0x03:
                DB_PRINT("PSS_SHA_1\n");
                break;
            case 0x04:
                DB_PRINT("PSS_SHA_256\n");
                break;
            default:
                goto exit;
        }
    }
    else if (0x02 == pNextPtr[elemLen - 2])
    {
        isEcc = TRUE;
        DB_PRINT("ECDSA_");
        switch(pNextPtr[elemLen - 1])
        {
            case 0x01:
                DB_PRINT("SHA_1\n");
                break;
            case 0x02:
                DB_PRINT("SHA_224\n");
                break;
            case 0x03:
                DB_PRINT("SHA_256\n");
                break;
            case 0x04:
                DB_PRINT("SHA_384\n");
                break;
            case 0x05:
                DB_PRINT("SHA_512\n");
                break;
            default:
                goto exit;
        }
    }
    else
    {
        goto exit;
    }

    pNextPtr += elemLen;
    keyLen -= (sbyte4)(pNextPtr - pPtr);
    pPtr = pNextPtr;

    /* MODULUS */
    if (keyLen > 2 && 0x81 == pPtr[0])
    {
        char eccStr[23] = "Prime modulus p:      ";
        char rsaStr[23] = "Comoposite modulus n: ";
        char *pTemp = (char *) (isEcc ? eccStr : rsaStr);
        status = CV_CERT_getLenAndValue(pPtr + 1, &pNextPtr, &elemLen);
        if (OK != status)
            goto exit;

        if (elemLen > 2)
        {
            DB_PRINT("0x81 %s %02x%02x%02x... (%d bytes)\n", pTemp, pNextPtr[0], pNextPtr[1], pNextPtr[2], elemLen);
        }
        else if (2 == elemLen)
        {
            DB_PRINT("0x81 %s %02x%02x (2 bytes)\n", pTemp, pNextPtr[0], pNextPtr[1]);
        }
        else if (1 == elemLen)
        {
            DB_PRINT("0x81 %s %02x (1 bytea)\n", pTemp, pNextPtr[0]);
        }

        pNextPtr += elemLen;
        keyLen -= (sbyte4)(pNextPtr - pPtr);
        pPtr = pNextPtr;
    }

    /* A or public exponenent */
    if (keyLen > 2 && 0x82 == pPtr[0])
    {
        char eccStr[23] = "First coefficient a:  ";
        char rsaStr[23] = "Public exponent e:    ";
        char *pTemp = (char *) (isEcc ? eccStr : rsaStr);
        status = CV_CERT_getLenAndValue(pPtr + 1, &pNextPtr, &elemLen);
        if (OK != status)
            goto exit;

        if (elemLen > 2)
        {
            DB_PRINT("0x82 %s %02x%02x%02x... (%d bytes)\n", pTemp, pNextPtr[0], pNextPtr[1], pNextPtr[2], elemLen);
        }
        else if (2 == elemLen)
        {
            DB_PRINT("0x82 %s %02x%02x (2 bytes)\n", pTemp, pNextPtr[0], pNextPtr[1]);
        }
        else if (1 == elemLen)
        {
            DB_PRINT("0x82 %s %02x (1 bytea)\n", pTemp, pNextPtr[0]);
        }

        pNextPtr += elemLen;
        keyLen -= (sbyte4)(pNextPtr - pPtr);
        pPtr = pNextPtr;
    }

    if (isEcc)
    {
        /* B */
        if (keyLen > 2 && 0x83 == pPtr[0])
        {
            status = CV_CERT_getLenAndValue(pPtr + 1, &pNextPtr, &elemLen);
            if (OK != status)
                goto exit;

            if (elemLen > 2)
            {
                DB_PRINT("0x83 Second coefficient b:  %02x%02x%02x... (%d bytes)\n", pNextPtr[0], pNextPtr[1], pNextPtr[2], elemLen);
            }
            else if (2 == elemLen)
            {
                DB_PRINT("0x83 Second coefficient b:  %02x%02x (2 bytes)\n", pNextPtr[0], pNextPtr[1]);
            }
            else if (1 == elemLen)
            {
                DB_PRINT("0x83 Second coefficient b:  %02x (1 bytea)\n", pNextPtr[0]);
            }

            pNextPtr += elemLen;
            keyLen -= (sbyte4)(pNextPtr - pPtr);
            pPtr = pNextPtr;
        }

        /* G */
        if (keyLen > 2 && 0x84 == pPtr[0])
        {
            status = CV_CERT_getLenAndValue(pPtr + 1, &pNextPtr, &elemLen);
            if (OK != status)
                goto exit;

            if (elemLen > 2)
            {
                DB_PRINT("0x84 Base point G:          %02x%02x%02x... (%d bytes)\n", pNextPtr[0], pNextPtr[1], pNextPtr[2], elemLen);
            }
            else if (2 == elemLen)
            {
                DB_PRINT("0x84 Base point G:          %02x%02x (2 bytes)\n", pNextPtr[0], pNextPtr[1]);
            }
            else if (1 == elemLen)
            {
                DB_PRINT("0x84 Base point G:          %02x (1 bytea)\n", pNextPtr[0]);
            }

            pNextPtr += elemLen;
            keyLen -= (sbyte4)(pNextPtr - pPtr);
            pPtr = pNextPtr;
        }

        /* R */
        if (keyLen > 2 && 0x85 == pPtr[0])
        {
            status = CV_CERT_getLenAndValue(pPtr + 1, &pNextPtr, &elemLen);
            if (OK != status)
                goto exit;

            if (elemLen > 2)
            {
                DB_PRINT("0x85 Order of base point r: %02x%02x%02x... (%d bytes)\n", pNextPtr[0], pNextPtr[1], pNextPtr[2], elemLen);
            }
            else if (2 == elemLen)
            {
                DB_PRINT("0x85 Order of base point r: %02x%02x (2 bytes)\n", pNextPtr[0], pNextPtr[1]);
            }
            else if (1 == elemLen)
            {
                DB_PRINT("0x85 Order of base point r: %02x (1 bytea)\n", pNextPtr[0]);
            }

            pNextPtr += elemLen;
            keyLen -= (sbyte4)(pNextPtr - pPtr);
            pPtr = pNextPtr;
        }

        /* Y */
        if (keyLen > 2 && 0x86 == pPtr[0])
        {
            status = CV_CERT_getLenAndValue(pPtr + 1, &pNextPtr, &elemLen);
            if (OK != status)
                goto exit;

            if (elemLen > 2)
            {
                DB_PRINT("0x86 Public point Y:        %02x%02x%02x... (%d bytes)\n", pNextPtr[0], pNextPtr[1], pNextPtr[2], elemLen);
            }
            else if (2 == elemLen)
            {
                DB_PRINT("0x86 Public point Y:        %02x%02x (2 bytes)\n", pNextPtr[0], pNextPtr[1]);
            }
            else if (1 == elemLen)
            {
                DB_PRINT("0x86 Public point Y:        %02x (1 bytea)\n", pNextPtr[0]);
            }

            pNextPtr += elemLen;
            keyLen -= (sbyte4)(pNextPtr - pPtr);
            pPtr = pNextPtr;
        }

        /* f */
        if (keyLen > 2 && 0x87 == pPtr[0])
        {
            status = CV_CERT_getLenAndValue(pPtr + 1, &pNextPtr, &elemLen);
            if (OK != status)
                goto exit;

            if (elemLen > 2)
            {
                DB_PRINT("0x87 Cofactor f:            %02x%02x%02x... (%d bytes)\n", pNextPtr[0], pNextPtr[1], pNextPtr[2], elemLen);
            }
            else if (2 == elemLen)
            {
                DB_PRINT("0x87 Cofactor f:            %02x%02x (2 bytes)\n", pNextPtr[0], pNextPtr[1]);
            }
            else if (1 == elemLen)
            {
                DB_PRINT("0x87 Cofactor f:            %02x (1 bytea)\n", pNextPtr[0]);
            }

            pNextPtr += elemLen;
            keyLen -= (sbyte4)(pNextPtr - pPtr);
        }
    }

    /* sanity check, user should know */
    status = ERR_INVALID_INPUT;
    if (keyLen != 0)
        goto exit;

    status = OK;
    DB_PRINT("\n");

exit:

    return status;
}

MOC_EXTERN MSTATUS KEYGEN_printCvCertificate(KeyGenArgs *pArgs)
{
    MSTATUS status = OK;
    ubyte *pCert = NULL;
    ubyte4 certLen = 0;
    CV_CERT *pCertData = NULL;
    ubyte temp[17] = {0}; /* big enough to hold 16 byte string form auth and holder refs */
    sbyte4 i = 0;

#ifdef __ENABLE_KEYSTORE_PATH__
    sbyte *pFullPath = NULL;

    status = CERT_ENROLL_getFullPath(pArgs->gpKeyStorePath, KEYGEN_FOLDER_CERTS,
                                     pArgs->gpSigningCert, NULL, &pFullPath);
    if (OK != status)
        goto exit;
    status = DIGICERT_readFile((const char *) pFullPath, &pCert, &certLen);
#else
    status = DIGICERT_readFile((const char *) pArgs->gpSigningCert, &pCert, &certLen);
#endif
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR, "Unable to open or read file: %s\n", pArgs->gpSigningCert);
        goto exit;
    }

    status = CV_CERT_parseCert(pCert, certLen, &pCertData);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(temp, pCertData->pCertAuthRef, pCertData->certAuthRefLen);
    if (OK != status)
        goto exit;

    DB_PRINT("\nCertificate Auth Ref   (CAR): %s\n", (char *) temp);

    status = DIGI_MEMCPY(temp, pCertData->pCertHolderRef, pCertData->certHolderRefLen);
    if (OK != status)
        goto exit;

    temp[pCertData->certHolderRefLen] = '\0';
    DB_PRINT("Certificate Holder Ref (CHR): %s\n\nPublic Key\n", (char *) temp);

    /* parse key just to make sure it's a supported format */
    status = KEYGEN_printCvCertKey(pCertData->pCvcKey, (sbyte4) pCertData->cvcKeyLen);
    if (OK != status)
        goto exit;

    DB_PRINT("Certificate Holder Auth Template (CHAT): ");
    for (i = 0; i < pCertData->certHolderAuthTemplateLen; i++)
    {
        DB_PRINT("%02x", pCertData->pCertHolderAuthTemplate[i]);
    }

    temp[0] = (ubyte) (pCertData->effectiveDate.m_year - 30) / 10;
    temp[1] = (ubyte) (pCertData->effectiveDate.m_year - 30) % 10;

    temp[2] = (ubyte) pCertData->effectiveDate.m_month / 10;
    temp[3] = (ubyte) pCertData->effectiveDate.m_month % 10;

    temp[4] = (ubyte) pCertData->effectiveDate.m_day / 10;
    temp[5] = (ubyte) pCertData->effectiveDate.m_day % 10;

    DB_PRINT("\nCertificate Effective Date  (YYMMDD): %d%d%d%d%d%d\n", temp[0], temp[1], temp[2], temp[3], temp[4], temp[5]);

    temp[0] = (ubyte) (pCertData->expDate.m_year - 30) / 10;
    temp[1] = (ubyte) (pCertData->expDate.m_year - 30) % 10;

    temp[2] = (ubyte) pCertData->expDate.m_month / 10;
    temp[3] = (ubyte) pCertData->expDate.m_month % 10;

    temp[4] = (ubyte) pCertData->expDate.m_day / 10;
    temp[5] = (ubyte) pCertData->expDate.m_day % 10;

    DB_PRINT("Certificate Expiration Date (YYMMDD): %d%d%d%d%d%d\n\n", temp[0], temp[1], temp[2], temp[3], temp[4], temp[5]);

    DB_PRINT("Certificate Extensions:\n");
    if (NULL != pCertData->pExtensions)
    {
        DB_PRINT(" -> ");
        for (i = 0; i < pCertData->extLen; i++)
        {
            DB_PRINT("%02x", pCertData->pExtensions[i]);
        }
    }
    else
    {
        DB_PRINT(" -> No Extensions");
    }

    DB_PRINT("\n\nSignature: ");
    for (i = 0; i < pCertData->sigLen; i++)
    {
        DB_PRINT("%02x", pCertData->pSig[i]);
    }
    DB_PRINT("\n\n");

exit:

#ifdef __ENABLE_KEYSTORE_PATH__
    if (NULL != pFullPath)
    {
        (void) DIGI_FREE((void **) &pFullPath);
    }
#endif

    if (NULL != pCertData)
    {
        (void) DIGI_FREE((void **) &pCertData);
    }

    if (NULL != pCert)
    {
        (void) DIGI_FREE((void **) &pCert);
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_CV_CERT__ */

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS KEYGEN_outputPrivKey(KeyGenArgs *pArgs, AsymmetricKey *pKey, randomContext *pRand, byteBoolean savePw,
                                        ubyte **ppKey, ubyte4 *pKeyLen)
{
    MSTATUS status = OK;

    ubyte *pPass = NULL;
    ubyte4 passLen = 0;

    ubyte *pPrivDer = NULL;
    ubyte4 privDerLen = 0;

    ubyte *pPriv = NULL;
    ubyte4 privLen = 0;

#ifdef __ENABLE_KEYSTORE_PATH__
    sbyte *pFullPath = NULL;
#endif

    if (pArgs->gProtected && !pArgs->gTap)
    {
        status = KEYGEN_getPassword(&pPass, &passLen, "PEM", "private key");
        if (OK != status)
            goto exit;

        MSG_LOG_print(MSG_LOG_VERBOSE, "PKCS8 protecting the key...%s\n","");

        status = PKCS_setPKCS8Key(pKey, pRand, MOC_KEYGEN_PKCS8_ALGO, MOC_KEYGEN_PKCS8_HASH,
                                  pPass, passLen, &pPriv, &privLen);
        if (OK != status)
            goto exit;

        if (savePw)
        {
            pArgs->gpPkcs8Pw = pPass; pPass = NULL;
            pArgs->gPkcs8PwLen = passLen;
        }

        if (FORMAT_PEM == pArgs->gOutForm)
        {
            status = BASE64_makePemMessageAlloc (MOC_PEM_TYPE_ENCR_PRI_KEY, pPriv, privLen, &pPrivDer, &privDerLen);
            if (OK != status)
                goto exit;

            /* free pPriv now so we can re-use the pointer for the PEM form key to be output */
            status = DIGI_MEMSET_FREE(&pPriv, privLen);
            if (OK != status)
                goto exit;

            pPriv = pPrivDer; pPrivDer = NULL;
            privLen = privDerLen; privDerLen = 0;
        }
    }
    else
    {
        serializedKeyFormat privForm = privateKeyPem;

        if (FORMAT_DER == pArgs->gOutForm)
            privForm = privateKeyInfoDer;

        status = CRYPTO_serializeAsymKey (pKey, privForm, &pPriv, &privLen);
        if (OK != status)
            goto exit;
    }

    if (pArgs->gVerbose)
    {
        const char *pOutForm = (FORMAT_PEM == pArgs->gOutForm ? "PEM" : "DER");
#ifdef __ENABLE_DIGICERT_PQC__
        if (akt_qs == pArgs->gKeyType || akt_hybrid == pArgs->gKeyType)
        {
            MSG_LOG_print(MSG_LOG_VERBOSE, "Writing private key to file %s in %s form...\n", pArgs->gpOutFile, pOutForm);
        }
        else
#endif
        {
            MSG_LOG_print(MSG_LOG_VERBOSE, "Writing private/public key pair to file %s in %s form...\n", pArgs->gpOutFile, pOutForm);
        }
    }

    /* Buffer mode output available for PEM form */
    if (NULL != ppKey)
    {
        *ppKey = pPriv; pPriv = NULL;
        *pKeyLen = privLen;
    }
    else
    {
#ifdef __ENABLE_KEYSTORE_PATH__
        status = CERT_ENROLL_getFullPath(pArgs->gpKeyStorePath, KEYGEN_FOLDER_KEYS,
                                         pArgs->gpOutFile, NULL, &pFullPath);
        if (OK != status)
            goto exit;

        /* Now write the files */
        status = DIGICERT_writeFile((const char *) pFullPath, pPriv, privLen);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "Failed to write private key (or keypair) to file %s\n", pArgs->gpOutFile);
        }
#else
        status = DIGICERT_writeFile((const char *) pArgs->gpOutFile, pPriv, privLen);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "Failed to write private key (or keypair) to file %s\n", pArgs->gpOutFile);
        }
#endif
    }

exit:

#ifdef __ENABLE_KEYSTORE_PATH__
    if (NULL != pFullPath)
    {
        (void) DIGI_FREE((void **) &pFullPath);
    }
#endif

    if (NULL != pPass)
    {
        DIGI_MEMSET_FREE(&pPass, passLen);
    }

    if (NULL != pPriv)
    {
        DIGI_MEMSET_FREE(&pPriv, privLen);
    }

    if (NULL != pPrivDer)
    {
        DIGI_MEMSET_FREE(&pPrivDer, privDerLen);
    }

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS KEYGEN_outputPubKey(KeyGenArgs *pArgs, AsymmetricKey *pKey)
{
    MSTATUS status = OK;

    ubyte *pPub = NULL;
    ubyte4 pubLen = 0;
    serializedKeyFormat pubForm = publicKeyPem;

    AsymmetricKey pubKey = {0};
    AsymmetricKey *pKeyPtr = &pubKey;
    MEccKeyTemplate eccTemplate = {0};
    MRsaKeyTemplate rsaTemplate = {0};
#if !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__) && defined(__ENABLE_DIGICERT_DSA__)
    MDsaKeyTemplate dsaTemplate = {0};
#endif

#ifdef __ENABLE_KEYSTORE_PATH__
    sbyte *pFullPath = NULL;
#endif

    if (FORMAT_DER == pArgs->gOutPubForm)
        pubForm = publicKeyInfoDer;

    /* We need to get just the public keys from the pKey */
    status = CRYPTO_initAsymmetricKey(&pubKey);
    if (OK != status)
        goto exit;

    if (akt_rsa == pArgs->gKeyType || akt_rsa_pss == pArgs->gKeyType)
    {
        status = CRYPTO_createRSAKey(&pubKey, NULL);
        if (OK != status)
            goto exit;

        /* TO DO need crypto interface form that takes in a public key */
        status = CRYPTO_INTERFACE_RSA_getKeyParametersAllocAux(pKey->key.pRSA, &rsaTemplate, MOC_GET_PUBLIC_KEY_DATA);
        if (OK != status)
            goto exit;

        /* set it in the new key */
        status = CRYPTO_INTERFACE_RSA_setPublicKeyData(pubKey.key.pRSA, rsaTemplate.pE, rsaTemplate.eLen, rsaTemplate.pN, rsaTemplate.nLen, NULL);
        if (OK != status)
            goto exit;

        /* set the type so we don't miss pss */
        pubKey.type = pArgs->gKeyType;

        /* set the pAlgoId in case there is one */
        pubKey.pAlgoId = pKey->pAlgoId;
    }
    else if (akt_ecc == pArgs->gKeyType)
    {
        /* if curve is Edward's form this API will set the proper key type in pKey */
        status = CRYPTO_createECCKeyEx(&pubKey, pArgs->gCurve);
        if (OK != status)
            goto exit;

        /* get the public key from the private key passed into the method */
        status = CRYPTO_INTERFACE_EC_getKeyParametersAllocAux(pKey->key.pECC, &eccTemplate, MOC_GET_PUBLIC_KEY_DATA);
        if (OK != status)
            goto exit;

        /* set it in the new key */
        status = CRYPTO_INTERFACE_EC_setKeyParametersAux (pubKey.key.pECC, eccTemplate.pPublicKey, eccTemplate.publicKeyLen, NULL, 0);
        if (OK != status)
            goto exit;
    }
#ifdef __ENABLE_DIGICERT_TAP__
    else if (akt_tap_rsa == pArgs->gKeyType)
    {
        status = CRYPTO_INTERFACE_getRSAPublicKey(pKey, &pubKey.key.pRSA);
        if (OK != status)
            goto exit;

        pubKey.type = akt_rsa;
    }
    else if (akt_tap_ecc == pArgs->gKeyType)
    {
        status = CRYPTO_INTERFACE_getECCPublicKey(pKey, &pubKey.key.pECC);
        if (OK != status)
            goto exit;

        pubKey.type = akt_ecc;
    }
#endif
#ifndef  __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
    else if (akt_dsa == pArgs->gKeyType)
    {
#if defined(__ENABLE_DIGICERT_DSA__)
        status = CRYPTO_createDSAKey(&pubKey, NULL);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_DSA_getKeyParametersAlloc(pKey->key.pDSA, &dsaTemplate, MOC_GET_PUBLIC_KEY_DATA);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_DSA_setKeyParametersAux(pubKey.key.pDSA, &dsaTemplate);
        if (OK != status)
            goto exit;
#else
        status = ERR_CRYPTO_DSA_DISABLED;
        goto exit;
#endif
    }
#endif

#ifdef __ENABLE_DIGICERT_PQC__
    if (akt_hybrid == pArgs->gKeyType)   /* ok to serialize the input private key in public form */
        pKeyPtr = pKey;
#endif

    if (FORMAT_SSH == pArgs->gOutPubForm)
    {
#ifndef __ENABLE_DIGICERT_CRYPTO_KEYGEN_LIB__
        status = SSH_KEY_generateServerAuthKeyFileAsymKey(pKeyPtr, &pPub, &pubLen);
        if (OK != status)
            goto exit;
#else
        status = ERR_NOT_IMPLEMENTED;
        goto exit;
#endif
    }
    else
    {
        status = CRYPTO_serializeAsymKey (pKeyPtr, pubForm, &pPub, &pubLen);
        if (OK != status)
            goto exit;
    }

    if (pArgs->gVerbose)
    {
        const char *pOutForm = (FORMAT_DER == pArgs->gOutPubForm ? "DER" : (FORMAT_PEM == pArgs->gOutPubForm ? "PEM" : "SSH"));
        MSG_LOG_print(MSG_LOG_VERBOSE, "Writing public key to file %s in %s form...\n", pArgs->gpOutPubFile, pOutForm);
    }

#ifdef __ENABLE_KEYSTORE_PATH__
    status = CERT_ENROLL_getFullPath(pArgs->gpKeyStorePath, KEYGEN_FOLDER_KEYS,
                                     pArgs->gpOutPubFile, NULL, &pFullPath);
    if (OK != status)
        goto exit;

    status = DIGICERT_writeFile((const char *) pFullPath, pPub, pubLen);
#else
    status = DIGICERT_writeFile((const char *) pArgs->gpOutPubFile, pPub, pubLen);
#endif

exit:

#ifdef __ENABLE_KEYSTORE_PATH__
    if (NULL != pFullPath)
    {
        (void) DIGI_FREE((void **) &pFullPath);
    }
#endif

    /* free the templates first if needbe, to be safe and not double free, check the key type */

    if (akt_rsa == pArgs->gKeyType || akt_rsa_pss == pArgs->gKeyType)
    {
        (void) CRYPTO_INTERFACE_RSA_freeKeyTemplateAux(pubKey.key.pRSA, &rsaTemplate);  /* ok to ignore return */
    }
    else if (akt_ecc == pArgs->gKeyType)
    {
        (void) CRYPTO_INTERFACE_EC_freeKeyTemplateAux(pubKey.key.pECC, &eccTemplate);
    }
#ifndef  __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
    else if (akt_dsa == pArgs->gKeyType)
    {
#if defined(__ENABLE_DIGICERT_DSA__)
        (void) CRYPTO_INTERFACE_DSA_freeKeyTemplate(pubKey.key.pDSA, &dsaTemplate);
#else
        status = ERR_CRYPTO_DSA_DISABLED;
        goto exit;
#endif
    }
#endif

    (void) CRYPTO_uninitAsymmetricKey(&pubKey, NULL);

    if (NULL != pPub)
    {
        DIGI_MEMSET_FREE(&pPub, pubLen);
    }

    return status;
}

/*---------------------------------------------------------------------------*/

static void KEYGEN_displayHelp()
{
    DB_PRINT("Usage: tc_keygen -o outputfile [-a algorithm] [-c curve] [-s size] [-pss] [-q size]");
#ifdef __ENABLE_DIGICERT_PQC__
    DB_PRINT(" [-g qs_alg] [-qsf]\n");
#else
    DB_PRINT("\n");
#endif
#ifdef __ENABLE_DIGICERT_TAP__
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
    DB_PRINT("                 [-t] [-ts server] [-tp port] [-tpr provider] [-tm modnum]\n");
    DB_PRINT("                 [-tku usage] [-tss scheme] [-tes scheme]\n");
#else
    DB_PRINT("                 [-t] [-tku usage] [-tm modulenum] [-tss scheme] [-tes scheme]\n");
#endif
#endif
#ifdef __ENABLE_DIGICERT_CV_CERT__
    DB_PRINT("                 [-cvc certfile] [-cve date] [-cvo code] [-cvm mnemonic]\n");
    DB_PRINT("                 [-cvs seqnum] [-cva auth] [-cvx extensions] [-pcvc certfile]\n");
#endif
    DB_PRINT("                 [-kd digest] [-kslt saltLen] [-u puboutfile] [-x certfile] [-p12 pkcs12file]\n");
    DB_PRINT("                 [-i csrfile] [-d digest] [-slt saltLen] [-y years] [-f form]\n");
    DB_PRINT("                 [-sc signingCert] [-sk signingKey] [-skp] [-csr] [-if form] [-p] [-v]\n");
#if defined(__ENABLE_DIGICERT_PQC__) && !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)
    DB_PRINT(" -a, --algorithm       ECC, RSA, DSA, QS, or HYBRID.\n");
#elif defined(__ENABLE_DIGICERT_PQC__)
    DB_PRINT(" -a, --algorithm       ECC, RSA, QS, or HYBRID.\n");
#elif !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)
    DB_PRINT(" -a, --algorithm       ECC, RSA, or DSA.\n");
#else
    DB_PRINT(" -a, --algorithm       ECC or RSA.\n");
#endif
    DB_PRINT(" -o, --output-file     Path to the output file that contains the generated private\n");
    DB_PRINT("                       key (or keypair) or the signed csr. PEM is the default format.\n");
#ifdef __ENABLE_DIGICERT_TAP__
    DB_PRINT(" -t,   --tap              [Optional] Generate a hardware-based%s TAP key\n", KEYGEN_TAP_PROVIDER_NAME);
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
    DB_PRINT(" -ts,  --tap-server       [Required with -t/--tap] Tap Server address or ip.\n");
    DB_PRINT(" -tp,  --tap-port         [Optional] Tap Server port. Default is 8277.\n");
    DB_PRINT(" -tpr, --tap-provider     [Optional] Tap Provider. PKCS11 or TPM2 (default is TPM2).\n");
#endif
    DB_PRINT(" -tm,  --tap-modnum       [Optional] The TAP Module to use (default is 1).\n");
    DB_PRINT(" -tku, --tap-key-usage    [Optional] TAP_KEY_USAGE_GENERAL (default), TAP_KEY_USAGE_SIGNING, or TAP_KEY_USAGE_DECRYPT\n");
    DB_PRINT(" -tss, --tap-sig-scheme   [Optional] Default is TAP_SIG_SCHEME_NONE\n");
    DB_PRINT("                          TAP_SIG_SCHEME_NONE\n");
    DB_PRINT("                          TAP_SIG_SCHEME_PKCS1_5\n");
    DB_PRINT("                          TAP_SIG_SCHEME_PKCS1_5_SHA1\n");
    DB_PRINT("                          TAP_SIG_SCHEME_PKCS1_5_SHA256\n");
    DB_PRINT("                          TAP_SIG_SCHEME_PKCS1_5_SHA384\n");
    DB_PRINT("                          TAP_SIG_SCHEME_PKCS1_5_SHA512\n");
    DB_PRINT("                          TAP_SIG_SCHEME_PKCS1_5_DER\n");
    DB_PRINT("                          TAP_SIG_SCHEME_PSS\n");
    DB_PRINT("                          TAP_SIG_SCHEME_PSS_SHA1\n");
    DB_PRINT("                          TAP_SIG_SCHEME_PSS_SHA256\n");
    DB_PRINT("                          TAP_SIG_SCHEME_PSS_SHA384\n");
    DB_PRINT("                          TAP_SIG_SCHEME_PSS_SHA512\n");
    DB_PRINT("                          TAP_SIG_SCHEME_ECDSA_SHA1\n");
    DB_PRINT("                          TAP_SIG_SCHEME_ECDSA_SHA224\n");
    DB_PRINT("                          TAP_SIG_SCHEME_ECDSA_SHA256\n");
    DB_PRINT("                          TAP_SIG_SCHEME_ECDSA_SHA384\n");
    DB_PRINT("                          TAP_SIG_SCHEME_ECDSA_SHA512\n");
    DB_PRINT(" -tes, --tap-enc-scheme   [Optional] Default is TAP_ENC_SCHEME_NONE\n");
    DB_PRINT("                          TAP_ENC_SCHEME_NONE\n");
    DB_PRINT("                          TAP_ENC_SCHEME_PKCS1_5\n");
    DB_PRINT("                          TAP_ENC_SCHEME_OAEP_SHA1\n");
    DB_PRINT("                          TAP_ENC_SCHEME_OAEP_SHA256\n");
    DB_PRINT("                          TAP_ENC_SCHEME_OAEP_SHA384\n");
    DB_PRINT("                          TAP_ENC_SCHEME_OAEP_SHA512\n");
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    DB_PRINT(" -c, --curve           [Required for ECC]\n");
    DB_PRINT("                       For ECC: P192, P224, P256, P384, P521, curve25519, or curve448.\n");
    DB_PRINT(" -g, --pq-alg          [Required for QS or HYBRID]. The supported values are:\n");
    DB_PRINT("                       MLDSA_44\n");
    DB_PRINT("                       MLDSA_65\n");
    DB_PRINT("                       MLDSA_87\n");
    DB_PRINT("                       FNDSA_512\n");
    DB_PRINT("                       FNDSA_1024\n");
    DB_PRINT("                       SLHDSA_SHA2_128S\n");
    DB_PRINT("                       SLHDSA_SHA2_128F\n");
    DB_PRINT("                       SLHDSA_SHA2_192S\n");
    DB_PRINT("                       SLHDSA_SHA2_192F\n");
    DB_PRINT("                       SLHDSA_SHA2_256S\n");
    DB_PRINT("                       SLHDSA_SHA2_256F\n");
    DB_PRINT("                       SLHDSA_SHAKE_128S\n");
    DB_PRINT("                       SLHDSA_SHAKE_128F\n");
    DB_PRINT("                       SLHDSA_SHAKE_192S\n");
    DB_PRINT("                       SLHDSA_SHAKE_192F\n");
    DB_PRINT("                       SLHDSA_SHAKE_256S\n");
    DB_PRINT("                       SLHDSA_SHAKE_256F\n");
    DB_PRINT(" -qsf, --qs-format-oqs [Optional] Format keys as per oqs specifications (non-draft rfc compatible).\n");
#else
    DB_PRINT(" -c, --curve           [Required for ECC]. The supported values are:\n");
    DB_PRINT("                       P192, P224, P256, P384, P521, curve25519, or curve448.\n");
#endif
#ifndef  __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
    DB_PRINT(" -s, --size            [Required for RSA or DSA]\n");
    DB_PRINT("                       For RSA specify bit size of private key (from 1024 to 8192, and must be\n");
    DB_PRINT("                       a multiple of 128).\n");
    DB_PRINT("                       For DSA specify the bit size of the prime p (1024 or 2048).\n");
    DB_PRINT(" -q, --q-size          [Required for DSA]. Specify bit size of the prime q (160 for 1024 primes\n");
    DB_PRINT("                       and 224 or 256 for 2048-bit primes).\n");
#else
    DB_PRINT(" -s, --size            [Required for RSA]. Specify bit size of private key (from 1024 to 8192,\n");
    DB_PRINT("                       and must be a multiple of 128.\n");
#endif
    DB_PRINT(" -pss, --pss           [Optional]. For RSA keys designate them for RSA-PSS signing.\n");
    DB_PRINT(" -kd, --key-digest     [Optional]. For RSA-PSS keys this will designate both the key's hash\n");
    DB_PRINT("                       algorithm and the mgf-hash algorithm. The supported values are:\n");
    DB_PRINT("                       MD5, SHA1, SHA224, SHA256, SHA384, or SHA512.\n");
    DB_PRINT(" -kslt, --key-salt     [Optional]. For RSA-PSS keys this will designate the salt length in bytes.\n");
    DB_PRINT("                       Default is the key digest output size in bytes.\n");
    DB_PRINT(" -u, --output-pub-file [Optional]. Path to the output file that contains the public key only.\n");
    DB_PRINT(" -x, --x509-cert       [Optional]. If provided, path to the certificate to be generated\n");
    DB_PRINT("                       using the input CSR file.\n");
#ifdef __ENABLE_DIGICERT_CV_CERT__
    DB_PRINT(" -cvc, --cv-cert         [Optional]. If provided, path to the CV certificate to be generated.\n");
    DB_PRINT(" -cve, --cv-eff-date     [Required with -cv/--cv-cert]. A CV certificate's effective date. YYMMDD format.\n");
    DB_PRINT(" -cvo, --cv-country-code [Optional]. A CV certificate's country code. Default is US\n");
    DB_PRINT(" -cvm, --cv-mnemonic     [Required with -cv/--cv-cert]. A CV certificate's mnemonic.\n");
    DB_PRINT(" -cvs, --cv-seqnum       [Required with -cv/--cv-cert]. A CV certificate's sequence number.\n");
    DB_PRINT(" -cva, --cv-holder-auth-temp [Required with -cv/--cv-cert]. A CV certificate's holder auth template.\n");
    DB_PRINT(" -cvx, --cv-extensions   [Optional]. A CV certificate's extensions in CV serialized form.\n");
    DB_PRINT(" -pcvc,  --print-cvcert  [Optional]. Prints a certificate in readable form. Follow with path and name of existing cert.\n");
#endif
    DB_PRINT(" -p12, --pkcs12        [Optional]. If provided, path to the pkcs12 PFX file to be created containing\n");
    DB_PRINT("                       the generated certificate and key pair. Options -x, -i and -da must be given.\n");
    DB_PRINT("                       Output format for this file is always DER.\n");
    DB_PRINT(" -p12e, --pkcs12-encryption-type [Optional]. Default is sha_3des:\n");
#ifdef __ENABLE_DIGICERT_2KEY_3DES__
    DB_PRINT("                                 sha_2des\n");
#endif
    DB_PRINT("                                 sha_3des\n");
#ifdef __ENABLE_ARC2_CIPHERS__
    DB_PRINT("                                 sha_rc2_40\n");
    DB_PRINT("                                 sha_rc2_128\n");
#endif
    DB_PRINT("                                 sha_rc4_40\n");
    DB_PRINT("                                 sha_rc4_128\n");
    DB_PRINT(" -p12i, --pkcs12-integrity-pw    [Optional]. If provided the user will be prompted for the pkcs12\n");
    DB_PRINT("                                 integrity password.\n");
    DB_PRINT(" -p12p, --pkcs12-privacy-pw      [Optional]. If provided the user will be prompted for the pkcs12\n");
    DB_PRINT("                                 privacy password.\n");
    DB_PRINT(" -p12k, --pkcs12-key-pw          [Optional]. If provided the user will be prompted for the key\n");
    DB_PRINT("                                 password.\n");
    DB_PRINT(" -i, --input-csr       [Required with -x/--x509-cert]. The certificate signing request file\n");
    DB_PRINT("                       used to generate a certificate for the newly generated key pair.\n");
    DB_PRINT(" -d, --digest          [Required with -csr/--cert-sign-req]. Digest for the signing algorithm. The supported values are:\n");
    DB_PRINT("                       MD5, SHA1, SHA224, SHA256, SHA384, or SHA512. If not provided, a default\n");
    DB_PRINT("                       digest will be chosen based on the signing key size.\n");
    DB_PRINT(" -slt, --salt          [Optional] For RSA-PSS Signing Keys, the salt length in bytes. Default\n");
    DB_PRINT("                       is the digest output size in bytes.\n");
    DB_PRINT(" -da, --days           [Required with -x/--x509-cert/-cv/--cv-cert]. The number of days for which the\n");
    DB_PRINT("                       generated certificate is valid.\n");
    DB_PRINT(" -sd, --start-date     [Optional] The starting date for a generated certificate, MMDDYYYY format.\n");
    DB_PRINT("                       Default is today.\n");
    DB_PRINT(" -f, --output-form     [Optional]. PEM, DER, or SSH. If not specified, the output file(s) are in\n");
    DB_PRINT("                       PEM format. For SSH, the private key (and certificate generated) is in\n");
    DB_PRINT("                       PEM format and the public key is in SSH format.\n");
    DB_PRINT(" -sc, --signing-cert   [Optional]. The signing certificate. If not provided a generated certificate\n");
    DB_PRINT("                       will be self-signed.\n");
    DB_PRINT(" -sk, --signing-key    [Required with -csr/--cert-sign-req]. The signing key. If not provided a generated certificate will be\n");
    DB_PRINT("                       self-signed.\n");
#ifdef __ENABLE_DIGICERT_TAP__
    DB_PRINT(" -skt, --signing-key-tap [Optional]. This option must be given if the signing key (-sk) is a TAP key.\n");
#endif
    DB_PRINT(" -skp, --signing-key-pw  [Optional]. If provided the user will prompted for the signing key's password.\n");
    DB_PRINT(" -csr, --cert-sign-req [Optional]. Create a signed CSR from a signing key, and input csr or input cert.\n");
    DB_PRINT(" -if, --input-form     [Optional]. PEM or DER. Format of the signing certificate and key. Default is PEM.\n");
#ifdef __ENABLE_DIGICERT_TAP__
    DB_PRINT(" -p, --protect         [Optional]. Password protect the new TAP or software (PKCS8) key.\n");
    DB_PRINT("                       Prompts for the password.\n");
#else
    DB_PRINT(" -p, --protect         [Optional]. PKCS8 password to protect the private key (or keypair). This\n");
    DB_PRINT("                       is for the PEM or SSH output formats. Prompts for the password.\n");
#endif
    DB_PRINT(" -v, --verbose         [Optional]. Verbose mode.\n");
#ifdef __ENABLE_DIGICERT_CERTIFICATE_PRINT__
    DB_PRINT(" -pc, --print-cert     [Optional] Print a certificate or CSR in readable form. Follow with it path and name of existing certificate or CSR\n");
#endif
    return;
}

/*---------------------------------------------------------------------------*/

static MSTATUS KEYGEN_getArgs(KeyGenArgs *pArgs, int argc, char *argv[])
{
    MSTATUS status = OK;
    sbyte4 i = 0;
#ifdef __ENABLE_DIGICERT_CV_CERT__
    ubyte4 numReqArg = 0;
#endif

    if (NULL == argv)
    {
        KEYGEN_displayHelp();
        return (MSTATUS) -1;
    }

    for (i = 1; i < argc; i++)
    {
        if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-h") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--help") ||
            0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"?"))
        {
            KEYGEN_displayHelp();
            return (MSTATUS) -1;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-a") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--algorithm"))
        {
            if (++i < argc)
            {
                if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"ECC") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"ecc"))
                {
                    pArgs->gKeyType = akt_ecc; /* Note, key creation method will know to change this to akt_ecc_ed if needbe */
                }
                else if(0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"RSA") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"rsa"))
                {
                    pArgs->gKeyType = akt_rsa;
                }
#ifdef __ENABLE_DIGICERT_PQC__
                else if(0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"HYBRID") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"hybrid"))
                {
                    pArgs->gKeyType = akt_hybrid;
                }
                else if(0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"QS") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"qs"))
                {
                    pArgs->gKeyType = akt_qs;
                }
#endif
#ifndef  __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
                else if(0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"DSA") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"dsa"))
                {
                    pArgs->gKeyType = akt_dsa;
                }
#endif
                else
                {
                    DB_PRINT("ERROR: Invalid -a or --algorithm option: %s.\n", argv[i]);
                    KEYGEN_displayHelp();
                    return (MSTATUS) -1;
                }
            }
            continue;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-o") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--output-file"))
        {
            if (++i < argc)
            {
                pArgs->gpOutFile = (sbyte *) argv[i];
            }
            continue;
        }
#ifdef __ENABLE_DIGICERT_TAP__
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-t") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--tap"))
        {
            pArgs->gTap = TRUE;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-tm") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--tap-modnum"))
        {
            if (++i < argc)
            {
                pArgs->gModNum = (ubyte4) DIGI_ATOL((sbyte *) argv[i], NULL);
            }
            continue;
        }
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-ts") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--tap-server"))
        {
            if (++i < argc)
            {
                pArgs->gpServer = (sbyte *) argv[i];
            }
            continue;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-tp") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--tap-port"))
        {
            if (++i < argc)
            {
                pArgs->gPort = (ubyte4) DIGI_ATOL((sbyte *) argv[i], NULL);
            }
            continue;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-tpr") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--tap-provider"))
        {
            if (++i < argc)
            {
                if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"TPM2") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"tpm2"))
                {
                    pArgs->gTapProvider = TAP_PROVIDER_TPM2;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"pkcs11") || DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"pkcs11"))
                {
                    pArgs->gTapProvider = TAP_PROVIDER_PKCS11;
                }
                /* else leave default */
            }
            continue;
        }
#endif
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-tku") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--tap-key-usage"))
        {
            if (++i < argc)
            {
                /* gKeyUsage already TAP_KEY_USAGE_GENERAL by default */
                if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"TAP_KEY_USAGE_SIGNING"))
                {
                    pArgs->gKeyUsage = TAP_KEY_USAGE_SIGNING;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"TAP_KEY_USAGE_DECRYPT"))
                {
                    pArgs->gKeyUsage = TAP_KEY_USAGE_DECRYPT;
                }
                else if (0 != DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"TAP_KEY_USAGE_GENERAL"))
                {
                    DB_PRINT("ERROR: Invalid -tku or --tap-key-usage option: %s.\n", argv[i]);
                    KEYGEN_displayHelp();
                    return (MSTATUS) -1;
                }
            }
            continue;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-tss") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--tap-sig-scheme"))
        {
            if (++i < argc)
            {
                /* gSigScheme already TAP_SIG_SCHEME_NONE by default */
                if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"TAP_SIG_SCHEME_PKCS1_5"))
                {
                    pArgs->gSigScheme = TAP_SIG_SCHEME_PKCS1_5;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"TAP_SIG_SCHEME_PKCS1_5_SHA1"))
                {
                    pArgs->gSigScheme = TAP_SIG_SCHEME_PKCS1_5_SHA1;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"TAP_SIG_SCHEME_PKCS1_5_SHA256"))
                {
                    pArgs->gSigScheme = TAP_SIG_SCHEME_PKCS1_5_SHA256;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"TAP_SIG_SCHEME_PKCS1_5_SHA384"))
                {
                    pArgs->gSigScheme = TAP_SIG_SCHEME_PKCS1_5_SHA384;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"TAP_SIG_SCHEME_PKCS1_5_SHA512"))
                {
                    pArgs->gSigScheme = TAP_SIG_SCHEME_PKCS1_5_SHA512;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"TAP_SIG_SCHEME_PKCS1_5_DER"))
                {
                    pArgs->gSigScheme = TAP_SIG_SCHEME_PKCS1_5_DER;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"TAP_SIG_SCHEME_PSS"))
                {
                    pArgs->gSigScheme = TAP_SIG_SCHEME_PSS;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"TAP_SIG_SCHEME_PSS_SHA1"))
                {
                    pArgs->gSigScheme = TAP_SIG_SCHEME_PSS_SHA1;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"TAP_SIG_SCHEME_PSS_SHA256"))
                {
                    pArgs->gSigScheme = TAP_SIG_SCHEME_PSS_SHA256;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"TAP_SIG_SCHEME_PSS_SHA384"))
                {
                    pArgs->gSigScheme = TAP_SIG_SCHEME_PSS_SHA384;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"TAP_SIG_SCHEME_PSS_SHA512"))
                {
                    pArgs->gSigScheme = TAP_SIG_SCHEME_PSS_SHA512;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"TAP_SIG_SCHEME_ECDSA_SHA1"))
                {
                    pArgs->gSigScheme = TAP_SIG_SCHEME_ECDSA_SHA1;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"TAP_SIG_SCHEME_ECDSA_SHA224"))
                {
                    pArgs->gSigScheme = TAP_SIG_SCHEME_ECDSA_SHA224;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"TAP_SIG_SCHEME_ECDSA_SHA256"))
                {
                    pArgs->gSigScheme = TAP_SIG_SCHEME_ECDSA_SHA256;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"TAP_SIG_SCHEME_ECDSA_SHA384"))
                {
                    pArgs->gSigScheme = TAP_SIG_SCHEME_ECDSA_SHA384;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"TAP_SIG_SCHEME_ECDSA_SHA512"))
                {
                    pArgs->gSigScheme = TAP_SIG_SCHEME_ECDSA_SHA512;
                }
                else if (0 != DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"TAP_SIG_SCHEME_NONE"))
                {
                    DB_PRINT("ERROR: Invalid -tss or --tap-sig-scheme option: %s.\n", argv[i]);
                    KEYGEN_displayHelp();
                    return (MSTATUS) -1;
                }
            }
            continue;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-tes") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--tap-enc-scheme"))
        {
            if (++i < argc)
            {
                /* gEncScheme already TAP_ENC_SCHEME_NONE by default */
                if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"TAP_ENC_SCHEME_PKCS1_5"))
                {
                    pArgs->gEncScheme = TAP_ENC_SCHEME_PKCS1_5;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"TAP_ENC_SCHEME_OAEP_SHA1"))
                {
                    pArgs->gEncScheme = TAP_ENC_SCHEME_OAEP_SHA1;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"TAP_ENC_SCHEME_OAEP_SHA256"))
                {
                    pArgs->gEncScheme = TAP_ENC_SCHEME_OAEP_SHA256;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"TAP_ENC_SCHEME_OAEP_SHA384"))
                {
                    pArgs->gEncScheme = TAP_ENC_SCHEME_OAEP_SHA384;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"TAP_ENC_SCHEME_OAEP_SHA512"))
                {
                    pArgs->gEncScheme = TAP_ENC_SCHEME_OAEP_SHA512;
                }
                else if (0 != DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"TAP_ENC_SCHEME_NONE"))
                {
                    DB_PRINT("ERROR: Invalid -tes or --tap-enc-scheme option: %s.\n", argv[i]);
                    KEYGEN_displayHelp();
                    return (MSTATUS) -1;
                }
            }
            continue;
        }
#endif
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-c") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--curve"))
        {
            if (++i < argc)
            {
                if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"P192") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"p192"))
                {
                    pArgs->gCurve = cid_EC_P192;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"P224") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"p224"))
                {
                    pArgs->gCurve = cid_EC_P224;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"P256") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"p256"))
                {
                    pArgs->gCurve = cid_EC_P256;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"P384") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"p384"))
                {
                    pArgs->gCurve = cid_EC_P384;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"P521") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"p521"))
                {
                    pArgs->gCurve = cid_EC_P521;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"curve25519") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"CURVE25519"))
                {
                    pArgs->gCurve = cid_EC_Ed25519;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"curve448") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"CURVE448"))
                {
                    pArgs->gCurve = cid_EC_Ed448;
                }
                else
                {
                    DB_PRINT("ERROR: Invalid -c or --curve option: %s.\n", argv[i]);
                    KEYGEN_displayHelp();
                    return (MSTATUS) -1;
                }
            }
            continue;
        }
#ifdef __ENABLE_DIGICERT_PQC__
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-g") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--pq-alg"))
        {
            if (++i < argc)
            {
                if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"MLDSA_44"))
                {
                    pArgs->gQsAlg = cid_PQC_MLDSA_44;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"MLDSA_65"))
                {
                    pArgs->gQsAlg = cid_PQC_MLDSA_65;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"MLDSA_87"))
                {
                    pArgs->gQsAlg = cid_PQC_MLDSA_87;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"FNDSA_512"))
                {
                    pArgs->gQsAlg = cid_PQC_FNDSA_512;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"FNDSA_1024"))
                {
                    pArgs->gQsAlg = cid_PQC_FNDSA_1024;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"SLHDSA_SHA2_128S"))
                {
                    pArgs->gQsAlg = cid_PQC_SLHDSA_SHA2_128S;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"SLHDSA_SHA2_192S"))
                {
                    pArgs->gQsAlg = cid_PQC_SLHDSA_SHA2_192S;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"SLHDSA_SHA2_256S"))
                {
                    pArgs->gQsAlg = cid_PQC_SLHDSA_SHA2_256S;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"SLHDSA_SHA2_128F"))
                {
                    pArgs->gQsAlg = cid_PQC_SLHDSA_SHA2_128F;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"SLHDSA_SHA2_192F"))
                {
                    pArgs->gQsAlg = cid_PQC_SLHDSA_SHA2_192F;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"SLHDSA_SHA2_256F"))
                {
                    pArgs->gQsAlg = cid_PQC_SLHDSA_SHA2_256F;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"SLHDSA_SHAKE_128S"))
                {
                    pArgs->gQsAlg = cid_PQC_SLHDSA_SHAKE_128S;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"SLHDSA_SHAKE_192S"))
                {
                    pArgs->gQsAlg = cid_PQC_SLHDSA_SHAKE_192S;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"SLHDSA_SHAKE_256S"))
                {
                    pArgs->gQsAlg = cid_PQC_SLHDSA_SHAKE_256S;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"SLHDSA_SHAKE_128F"))
                {
                    pArgs->gQsAlg = cid_PQC_SLHDSA_SHAKE_128F;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"SLHDSA_SHAKE_192F"))
                {
                    pArgs->gQsAlg = cid_PQC_SLHDSA_SHAKE_192F;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"SLHDSA_SHAKE_256F"))
                {
                    pArgs->gQsAlg = cid_PQC_SLHDSA_SHAKE_256F;
                }
                else
                {
                    DB_PRINT("ERROR: Invalid -g or --pq-alg option: %s.\n", argv[i]);
                    KEYGEN_displayHelp();
                    return (MSTATUS) -1;
                }
            }
            continue;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-qsf") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--qs-format-oqs"))
        {
            SERIALQS_setOqsCompatibleFormat(TRUE);
#ifdef __ENABLE_MLDSA_LONG_FORM_PRIV_KEY_SER__
            MLDSA_setLongFormPrivKeyFormat(TRUE);
#endif
        }
#endif /* __ENABLE_DIGICERT_PQC__ */
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-s") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--size"))
        {
            if (++i < argc)
            {
                sbyte4 mTemp = DIGI_ATOL((sbyte *) argv[i], NULL);
                if (1024 > mTemp || 8192 < mTemp || mTemp & 0x7f)
                {
                    DB_PRINT("ERROR: Invalid -s or --size option: %s.\n", argv[i]);
                    KEYGEN_displayHelp();
                    return (MSTATUS) -1;
                }
                pArgs->gKeySize = (ubyte4) mTemp;
            }
            continue;
        }
#ifndef  __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-q") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--q-size"))
        {
            if (++i < argc)
            {
                sbyte4 mTemp = DIGI_ATOL((sbyte *) argv[i], NULL);
                if (160 != mTemp && 224 != mTemp && 256 != mTemp)
                {
                    DB_PRINT("ERROR: Invalid -q or --q-size option: %s.\n", argv[i]);
                    KEYGEN_displayHelp();
                    return (MSTATUS) -1;
                }
                pArgs->gQSize = (ubyte4) mTemp;
            }
            continue;
        }
#endif            
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-u") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--output-pub-file"))
        {
            if (++i < argc)
            {
                pArgs->gpOutPubFile = (sbyte *) argv[i];
            }
            continue;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-x") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--x509-cert"))
        {
            if (++i < argc)
            {
                pArgs->gpOutCertFile = (sbyte *) argv[i];
            }
            continue;
        }
#ifdef __ENABLE_DIGICERT_CV_CERT__
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-cvc") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--cv-cert"))
        {
            if (++i < argc)
            {
                pArgs->gpOutCertFile = (sbyte *) argv[i];
                pArgs->gIsCvc = TRUE;
            }
            continue;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-cve") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--cv-eff-date"))
        {
            if (++i < argc)
            {
                sbyte temp[3] = {0};
                ubyte4 len = DIGI_STRLEN((sbyte *) argv[i]);
                if (6 == len)  /* date is 6 chars YYMMDD */
                {
                    (void) DIGI_MEMCPY(temp, (ubyte *) argv[i], 2);
                    pArgs->gCvcData.effectiveDate.m_year = (ubyte2) DIGI_ATOL( (sbyte *) temp, NULL);
                    pArgs->gCvcData.effectiveDate.m_year += 30; /* stored date begins in 1970, not 2000, so add 30 */

                    (void) DIGI_MEMCPY(temp, (ubyte *) argv[i] + 2, 2);
                    pArgs->gCvcData.effectiveDate.m_month = (ubyte) DIGI_ATOL( (sbyte *) temp, NULL);

                    (void) DIGI_MEMCPY(temp, (ubyte *) argv[i] + 4, 2);
                    pArgs->gCvcData.effectiveDate.m_day = (ubyte) DIGI_ATOL( (sbyte *) temp, NULL);
                }
                else
                {
                    DB_PRINT("ERROR: Invalid -cve or --cv-eff-date option, should be YYMMDD format: %s.\n", argv[i]);
                    KEYGEN_displayHelp();
                    return (MSTATUS) -1;
                }
            }

            pArgs->gHasStartDate = TRUE;
            continue;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-cvo") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--cv-country-code"))
        {
            if (++i < argc)
            {
                ubyte4 len = DIGI_STRLEN((sbyte *) argv[i]);
                if (2 == len)
                {
                     (void) DIGI_MEMCPY(pArgs->gCvcData.countryCode, (ubyte *) argv[i], 2);
                }
                else
                {
                    DB_PRINT("ERROR: Invalid -cvo or --cv-country-code option: %s.\n", argv[i]);
                    KEYGEN_displayHelp();
                    return (MSTATUS) -1;
                }
            }
            continue;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-cvm") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--cv-mnemonic"))
        {
            if (++i < argc)
            {
                ubyte4 len = DIGI_STRLEN((sbyte *) argv[i]);
                if (len < 10) /* max of 9 chars */
                {
                     (void) DIGI_MEMCPY(pArgs->gCvcData.mnemonic, (ubyte *) argv[i], len);
                     pArgs->gCvcData.mnemonicLen = len;
                     numReqArg++;
                }
                else
                {
                    DB_PRINT("ERROR: Invalid -cvm or --cv-mnemonic option: %s.\n", argv[i]);
                    KEYGEN_displayHelp();
                    return (MSTATUS) -1;
                }
            }
            continue;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-cvs") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--cv-seqnum"))
        {
            if (++i < argc)
            {
                ubyte4 len = DIGI_STRLEN((sbyte *) argv[i]);
                if (5 == len) /* must be 5 chars */
                {
                     (void) DIGI_MEMCPY(pArgs->gCvcData.seqNum, (ubyte *) argv[i], len);
                     numReqArg++;
                }
                else
                {
                    DB_PRINT("ERROR: Invalid -cvs or --cv-seqnum option: %s.\n", argv[i]);
                    KEYGEN_displayHelp();
                    return (MSTATUS) -1;
                }
            }
            continue;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-cva") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--cv-holder-auth-temp"))
        {
            if (++i < argc)
            {
                ubyte4 len = DIGI_STRLEN((sbyte *) argv[i]);
                if (len > 1)
                {
                    status = DIGI_MALLOC((void **) &pArgs->gCvcData.pCertHolderAuthTemplate, len/2);
                    if (OK != status)
                    {
                        DB_PRINT("ERROR: Out of memory.\n");
                        return status;
                    }

                    status = DIGI_ATOH((ubyte *) argv[i], len, pArgs->gCvcData.pCertHolderAuthTemplate);
                    if (OK != status)
                    {
                        DB_PRINT("ERROR: Invalid -cva or --cv-holder-auth-temp option. Should be hex, no leading 0x: %s.\n", argv[i]);
                        return status;
                    }

                    pArgs->gCvcData.certHolderAuthTemplateLen = len/2;
                    numReqArg++;
                }
                else
                {
                    DB_PRINT("ERROR: Invalid -cva or --cv-holder-auth-temp option. Should be hex, no leading 0x: %s.\n", argv[i]);
                    return status;
                }
            }
            continue;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-cvx") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--cv-extensions"))
        {
            if (++i < argc)
            {
                ubyte4 len = DIGI_STRLEN((sbyte *) argv[i]);
                if (len > 1)
                {
                    status = DIGI_MALLOC((void **) &pArgs->gCvcData.pExtensions, len/2);
                    if (OK != status)
                    {
                        DB_PRINT("ERROR: Out of memory.\n");
                        return status;
                    }

                    status = DIGI_ATOH((ubyte *) argv[i], len, pArgs->gCvcData.pExtensions);
                    if (OK != status)
                    {
                        DB_PRINT("ERROR: Invalid -cvx or --cv-extensions option. Should be hex, no leading 0x: %s.\n", argv[i]);
                        return status;
                    }

                    pArgs->gCvcData.extLen = len/2;
                }
                else
                {
                    DB_PRINT("ERROR: Invalid -cvx or --cv-extensions option. Should be hex, no leading 0x: %s.\n", argv[i]);
                    return status;
                }
            }
            continue;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-pcvc") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--print-cvcert"))
        {
            if (++i < argc)
            {
                /* reuse gpSigningCert for cert path */
                pArgs->gpSigningCert = (sbyte *) argv[i];
                pArgs->gIsPrintCVCert = TRUE;
            }
            continue;
        }
#endif /* __ENABLE_DIGICERT_CV_CERT__ */
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-p12") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--pkcs12"))
        {
            if (++i < argc)
            {
                pArgs->gpPkcs12File = (sbyte *) argv[i];
            }
            continue;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-p12e") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--pkcs12-encryption-type"))
        {
            if (++i < argc)
            {
                pArgs->gPkcs12EncryptionType = PCKS8_EncryptionType_undefined;
#if !defined(__DISABLE_3DES_CIPHERS__)
                if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"sha_3des") || DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"SHA_3DES"))
                {
                    pArgs->gPkcs12EncryptionType = PCKS8_EncryptionType_pkcs12_sha_3des;
                }
#endif
#ifdef __ENABLE_DIGICERT_2KEY_3DES__
                if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"sha_2des") || DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"SHA_2DES"))
                {
                    pArgs->gPkcs12EncryptionType = PCKS8_EncryptionType_pkcs12_sha_2des;
                }
#endif
#ifdef __ENABLE_ARC2_CIPHERS__
                 if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"sha_rc2_40") || DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"SHA_RC2_40"))
                {
                    pArgs->gPkcs12EncryptionType = PCKS8_EncryptionType_pkcs12_sha_rc2_40;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"sha_rc2_128") || DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"SHA_RC2_128"))
                {
                    pArgs->gPkcs12EncryptionType = PCKS8_EncryptionType_pkcs12_sha_rc2_128
                }
#endif
#ifndef __DISABLE_ARC4_CIPHERS__
                if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"sha_rc4_40") || DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"SHA_RC4_40"))
                {
                    pArgs->gPkcs12EncryptionType = PCKS8_EncryptionType_pkcs12_sha_rc4_40;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"sha_rc4_128") || DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"SHA_RC4_128"))
                {
                    pArgs->gPkcs12EncryptionType = PCKS8_EncryptionType_pkcs12_sha_rc4_128;
                }
#endif
                if (pArgs->gPkcs12EncryptionType == PCKS8_EncryptionType_undefined)
                {
                    DB_PRINT("ERROR: Invalid -p12e or --pkcs12-encryption-type option: %s.\n", argv[i]);
                    KEYGEN_displayHelp();
                    return (MSTATUS) -1;
                }
            }
            continue;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-p12i") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--pkcs12-integrity-pw"))
        {
            pArgs->gPkcs12GetIntegrityPw = TRUE;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-p12p") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--pkcs12-privacy-pw"))
        {
            pArgs->gPkcs12GetPrivacyPw = TRUE;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-p12k") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--pkcs12-key-pw"))
        {
            pArgs->gPkcs12GetKeyPw = TRUE;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-i") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--input-csr"))
        {
            if (++i < argc)
            {
                pArgs->gpInCsrFile = (sbyte *) argv[i];
            }
            continue;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-kd") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--key-digest"))
        {
            if (++i < argc)
            {
                if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"MD5") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"md5"))
                {
                    pArgs->gKeyHashAlgo = (sbyte4) ht_md5;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"SHA1") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"sha1"))
                {
                    pArgs->gKeyHashAlgo = (sbyte4) ht_sha1;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"SHA224") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"sha224"))
                {
                    pArgs->gKeyHashAlgo = (sbyte4) ht_sha224;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"SHA256") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"sha256"))
                {
                    pArgs->gKeyHashAlgo = (sbyte4) ht_sha256;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"SHA384") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"sha384"))
                {
                    pArgs->gKeyHashAlgo = (sbyte4) ht_sha384;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"SHA512") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"sha512"))
                {
                    pArgs->gKeyHashAlgo = (sbyte4) ht_sha512;
                }
                else
                {
                    DB_PRINT("ERROR: Invalid -kd or --key-digest option: %s.\n", argv[i]);
                    KEYGEN_displayHelp();
                    return (MSTATUS) -1;
                }
            }
            continue;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-d") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--digest"))
        {
            if (++i < argc)
            {
                if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"MD5") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"md5"))
                {
                    pArgs->gHashAlgo = (sbyte4) ht_md5;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"SHA1") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"sha1"))
                {
                    pArgs->gHashAlgo = (sbyte4) ht_sha1;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"SHA224") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"sha224"))
                {
                    pArgs->gHashAlgo = (sbyte4) ht_sha224;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"SHA256") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"sha256"))
                {
                    pArgs->gHashAlgo = (sbyte4) ht_sha256;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"SHA384") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"sha384"))
                {
                    pArgs->gHashAlgo = (sbyte4) ht_sha384;
                }
                else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"SHA512") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"sha512"))
                {
                    pArgs->gHashAlgo = (sbyte4) ht_sha512;
                }
                else
                {
                    DB_PRINT("ERROR: Invalid -d or --digest option: %s.\n", argv[i]);
                    KEYGEN_displayHelp();
                    return (MSTATUS) -1;
                }
            }
            continue;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-kslt") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--key-salt"))
        {
            if (++i < argc)
            {
                pArgs->gKeySaltLen = DIGI_ATOL((sbyte *) argv[i], NULL);
                if (pArgs->gKeySaltLen < 0)
                {
                    DB_PRINT("ERROR: Invalid -kslt or --key-salt option: %s.\n", argv[i]);
                    KEYGEN_displayHelp();
                    return (MSTATUS) -1;
                }
            }
            continue;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-slt") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--salt"))
        {
            if (++i < argc)
            {
                pArgs->gSaltLen = DIGI_ATOL((sbyte *) argv[i], NULL);
                if (pArgs->gSaltLen < 0)
                {
                    DB_PRINT("ERROR: Invalid -slt or --salt option: %s.\n", argv[i]);
                    KEYGEN_displayHelp();
                    return (MSTATUS) -1;
                }
            }
            continue;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-pss") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--pss"))
        {
            pArgs->gKeyIsPss = TRUE;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-sd") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--start-date"))
        {
            if (++i < argc)
            {
                sbyte temp[5] = {0};
                ubyte4 len = DIGI_STRLEN(argv[i]);
                if (8 == len)  /* date is 8 chars MMDDYYYY */
                {
                    (void) DIGI_MEMCPY(temp, (sbyte *) argv[i], 2);
                    pArgs->gStartDate.m_month = (ubyte) DIGI_ATOL( (sbyte *) temp, NULL);

                    (void) DIGI_MEMCPY(temp, (sbyte *) argv[i] + 2, 2);
                    pArgs->gStartDate.m_day = (ubyte) DIGI_ATOL( (sbyte *) temp, NULL);

                    (void) DIGI_MEMCPY(temp, (sbyte *) argv[i] + 4, 4);
                    pArgs->gStartDate.m_year = (ubyte2) DIGI_ATOL( (sbyte *) temp, NULL);
                }
                else
                {
                    status = ERR_INVALID_ARG;
                    DB_PRINT("\nERROR: Invalid -sd or --start-date option, should be MMDDYYYY format: %s, status = %s (%d)\n", argv[i],
                              MERROR_lookUpErrorCode(status), status);
                    KEYGEN_displayHelp();
                    return (MSTATUS) -1;
                }
            }
            pArgs->gHasStartDate = TRUE;
            continue;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-da") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--days"))
        {
            if (++i < argc)
            {
                sbyte4 mTemp = DIGI_ATOL((sbyte *) argv[i], NULL);
                if (mTemp < 1)
                {
                    DB_PRINT("ERROR: Invalid -da or --days option: %s.\n", argv[i]);
                    KEYGEN_displayHelp();
                    return (MSTATUS) -1;
                }
                pArgs->gDays = (ubyte4) mTemp;
            }
            continue;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-f") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--output-form"))
        {
            if (++i < argc)
            {
                if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"PEM") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"pem"))
                {
                    pArgs->gOutForm = FORMAT_PEM;
                    pArgs->gOutPubForm = FORMAT_PEM;
                }
                else if(0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"DER") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"der"))
                {
                    pArgs->gOutForm = FORMAT_DER;
                    pArgs->gOutPubForm = FORMAT_DER;
                }
                else if(0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"SSH") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"ssh"))
                {
                    pArgs->gOutForm = FORMAT_PEM;
                    pArgs->gOutPubForm = FORMAT_SSH;
                }
                else
                {
                    DB_PRINT("ERROR: Invalid -f or --output-form option: %s.\n", argv[i]);
                    KEYGEN_displayHelp();
                    return (MSTATUS) -1;
                }
            }
            continue;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-sc") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--signing-cert"))
        {
            if (++i < argc)
            {
                pArgs->gpSigningCert = (sbyte *) argv[i];
            }
            continue;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-sk") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--signing-key"))
        {
            if (++i < argc)
            {
                pArgs->gpSigningKey = (sbyte *) argv[i];
            }
            continue;
        }
#ifdef __ENABLE_DIGICERT_TAP__
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-skt") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--signing-key-tap"))
        {
            pArgs->gSignKeyTap = TRUE;
        }
#endif
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-skp") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--signing-key-pw"))
        {
            pArgs->gGetSigningKeyPw = TRUE;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-if") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--input-form"))
        {
            if (++i < argc)
            {
                if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"PEM") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"pem"))
                {
                    pArgs->gInForm = FORMAT_PEM;
                }
                else if(0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"DER") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"der"))
                {
                    pArgs->gInForm = FORMAT_DER;
                }
                else
                {
                    DB_PRINT("ERROR: Invalid -if or --input-form option: %s.\n", argv[i]);
                    KEYGEN_displayHelp();
                    return (MSTATUS) -1;
                }
            }
            continue;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-csr") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--cert-sign-req"))
        {
            pArgs->gCreateCsr = TRUE;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-p") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--protect"))
        {
            pArgs->gProtected = TRUE;
        }
#ifdef __ENABLE_DIGICERT_CERTIFICATE_PRINT__
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-pc") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--print-cert"))
        {
            if (++i < argc)
            {
                /* reuse gpSigningCert for cert path */
                pArgs->gpSigningCert = (sbyte *) argv[i];
                pArgs->gIsPrintCert = TRUE;
            }
            continue;
        }
#endif
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-v") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--verbose"))
        {
            pArgs->gVerbose = TRUE;
        }
    }

#ifdef __ENABLE_DIGICERT_CV_CERT__
    /* skip validations if print cert */
    if (pArgs->gIsPrintCVCert)
        goto skip_validations;
#endif

#ifdef __ENABLE_DIGICERT_CERTIFICATE_PRINT__
    if (pArgs->gIsPrintCert)
        goto skip_validations;
#endif

    /* A few more validations */
    if (!pArgs->gKeyType && !pArgs->gCreateCsr)
    {
        DB_PRINT("ERROR: Must specify an algorithm, -a <ECC,RSA>.\n");
        KEYGEN_displayHelp();
        return (MSTATUS) -1;
    }

    if (NULL == pArgs->gpOutFile)
    {
        DB_PRINT("ERROR: Must specify an output file, -o <path to file>.\n");
        KEYGEN_displayHelp();
        return (MSTATUS) -1;
    }

    if (akt_rsa == pArgs->gKeyType && !pArgs->gKeySize)
    {
        DB_PRINT("ERROR: Must specify a key size, -s <size>, for RSA algorithm.\n");
        KEYGEN_displayHelp();
        return (MSTATUS) -1;
    }

    if (akt_ecc == pArgs->gKeyType && !pArgs->gCurve)
    {
        DB_PRINT("ERROR: Must specify a curve, -c <curve>, for ECC algorithm.\n");
        KEYGEN_displayHelp();
        return (MSTATUS) -1;
    }

#ifdef __ENABLE_DIGICERT_PQC__
    if (akt_hybrid == pArgs->gKeyType)
    {
        /* TODO validate RSA sizes or curve sizes match MLDSA size */
        if (!pArgs->gCurve && !pArgs->gKeySize)
        {
            DB_PRINT("ERROR: Must specify a curve, -c <curve>, or RSA keysize, -s <size>, for HYBRID algorithm.\n");
            KEYGEN_displayHelp();
            return (MSTATUS) -1;
        }

        if (pArgs->gCurve && pArgs->gKeySize)
        {
            DB_PRINT("ERROR: Cannot specify both a curve -c, and keysize -s, for HYBRID algorithm.\n");
            KEYGEN_displayHelp();
            return (MSTATUS) -1;
        }

        if (!pArgs->gQsAlg)
        {
            DB_PRINT("ERROR: Must specify a post quantum alg, -g <alg>, for HYBRID algorithm.\n");
            KEYGEN_displayHelp();
            return (MSTATUS) -1;
        }
    }
    else if (akt_qs == pArgs->gKeyType && !pArgs->gQsAlg)
    {
        DB_PRINT("ERROR: Must specify a post quantum alg, -g <alg>, for QS algorithm.\n");
        KEYGEN_displayHelp();
        return (MSTATUS) -1;
    }
#endif

#ifndef  __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
    if (akt_dsa == pArgs->gKeyType)
    {
        if ( !( (1024 == pArgs->gKeySize && 160 == pArgs->gQSize) || (2048 == pArgs->gKeySize && 224 == pArgs->gQSize) || (2048 == pArgs->gKeySize && 256 == pArgs->gQSize) || (3072 == pArgs->gKeySize && 256 == pArgs->gQSize) ) )
        {
            DB_PRINT("ERROR: Invlalid <prime size -s, q-size -q> options. Valid combinations are <1024, 160>, <2048, 224>, <2048, 256>, and <3072, 256>.\n");
            KEYGEN_displayHelp();
            return (MSTATUS) -1;
        }

        if (NULL != pArgs->gpOutCertFile)
        {
            DB_PRINT("ERROR: Certificate generation is not valid for algorithm DSA.\n");
            KEYGEN_displayHelp();
            return (MSTATUS) -1;
        }
    }
#endif

#ifdef __ENABLE_DIGICERT_CV_CERT__
    if (NULL != pArgs->gpOutCertFile && !pArgs->gIsCvc && NULL == pArgs->gpInCsrFile)
#else
    if (NULL != pArgs->gpOutCertFile && NULL == pArgs->gpInCsrFile)
#endif
    {
        DB_PRINT("ERROR: Must specify an input csr file, -i <file>, to generate an x509 certificate.\n");
        KEYGEN_displayHelp();
        return (MSTATUS) -1;
    }

    if (pArgs->gCreateCsr)
    {
        if (NULL == pArgs->gpSigningKey)
        {
            DB_PRINT("ERROR: Signing key must be provided for a CSR request.\n");
            KEYGEN_displayHelp();
            return (MSTATUS) -1;
        }

        if (NULL == pArgs->gpSigningCert && NULL == pArgs->gpInCsrFile)
        {
            DB_PRINT("ERROR: Input csr OR signing certificate must be provided for a CSR request.\n");
            KEYGEN_displayHelp();
            return (MSTATUS) -1;
        }

        if (NULL != pArgs->gpSigningCert && NULL != pArgs->gpInCsrFile)
        {
            DB_PRINT("WARNING: Input csr and signing certificate provided for a CSR request. Will only use the csr file.\n");
            pArgs->gpSigningCert = NULL;
        }

        if (!(ht_sha256 == pArgs->gHashAlgo || ht_sha384 == pArgs->gHashAlgo || ht_sha512 == pArgs->gHashAlgo))
        {
            DB_PRINT("ERROR: -d or --digest must be SHA256, SHA384, or SHA512 for a CSR request.\n");
            KEYGEN_displayHelp();
            return (MSTATUS) -1;
        }
    }
    else if ((NULL != pArgs->gpSigningCert && NULL == pArgs->gpSigningKey) || (NULL == pArgs->gpSigningCert && NULL != pArgs->gpSigningKey))
    {
        DB_PRINT("ERROR: Signing Certificate or Key provided without the other.\n");
        KEYGEN_displayHelp();
        return (MSTATUS) -1;
    }

#ifndef __ENABLE_DIGICERT_CV_CERT__
    if ((NULL != pArgs->gpOutCertFile) && (TRUE == pArgs->gHasStartDate) && ((0 == pArgs->gStartDate.m_day) || (pArgs->gStartDate.m_day > 31) || (0 == pArgs->gStartDate.m_month) || (pArgs->gStartDate.m_month > 12) || (0 == pArgs->gStartDate.m_year)))
    {
        DB_PRINT("\nERROR: Must specify a valid -sd or --start-date option in MMDDYYYY format.\n");
        KEYGEN_displayHelp();
        return (MSTATUS) -1;
    }
#endif

    if (NULL != pArgs->gpOutCertFile && 0 == pArgs->gDays)
    {
        DB_PRINT("ERROR: Must specify the number of days of validity, -da <days>, to generate an x509 or CV certificate.\n");
        KEYGEN_displayHelp();
        return (MSTATUS) -1;
    }

    if (NULL != pArgs->gpPkcs12File && NULL == pArgs->gpOutCertFile)
    {
        DB_PRINT("ERROR: Must specify certificate generation -x in order to specify pkcs12 file generation -p12.\n");
        KEYGEN_displayHelp();
        return (MSTATUS) -1;
    }

    if (!pArgs->gCreateCsr && NULL == pArgs->gpOutCertFile && NULL != pArgs->gpInCsrFile)
    {
        DB_PRINT("WARNING: input csr file -i specified but -x not specified so no certificate will be generated.\n");
    }

    if (!pArgs->gCreateCsr && NULL == pArgs->gpOutCertFile && NOT_SPECIFIED != pArgs->gHashAlgo)
    {
        DB_PRINT("WARNING: digest -d specified but -x not specified so no certificate will be generated.\n");
    }

#ifdef __ENABLE_DIGICERT_CV_CERT__
    if (!pArgs->gIsCvc && NULL == pArgs->gpOutCertFile && pArgs->gDays)
#else
    if (NULL == pArgs->gpOutCertFile && pArgs->gDays)
#endif
    {
        DB_PRINT("WARNING: days -da specified but -x not specified so no certificate will be generated.\n");
    }

#ifdef __ENABLE_DIGICERT_CV_CERT__
    if (pArgs->gIsCvc)   /* validate and fill in other defaults */
    {
        /* memory was possibly allocated so don't return until it's freed */
        if (akt_rsa == pArgs->gKeyType)
        {
            if (ht_sha1 != pArgs->gKeyHashAlgo && ht_sha256 != pArgs->gKeyHashAlgo)
            {
                DB_PRINT("ERROR: must specify key digest -kd [sha1 or sha256] to generate an RSA CV certificate.\n");
                KEYGEN_displayHelp();
                status = -1;
            }
        }
        else if (akt_ecc == pArgs->gKeyType)
        {
            if (ht_sha1 != pArgs->gKeyHashAlgo && ht_sha224 != pArgs->gKeyHashAlgo && ht_sha256 != pArgs->gKeyHashAlgo && ht_sha384 != pArgs->gKeyHashAlgo && ht_sha512 != pArgs->gKeyHashAlgo)
            {
                DB_PRINT("ERROR: must specify key digest -kd to generate an ECC CV certificate.\n");
                KEYGEN_displayHelp();
                status = -1;
            }

            if (cid_EC_Ed25519 == pArgs->gCurve || cid_EC_Ed448 == pArgs->gCurve)
            {
                DB_PRINT("ERROR: Edwards form curves are not supported with ECC CV certificates.\n");
                KEYGEN_displayHelp();
                status = -1;
            }
        }
        else
        {
            DB_PRINT("ERROR: Key type must be ECC or RSA in order to generate a CV certificate.\n");
            KEYGEN_displayHelp();
            status = -1;
        }

        if (3 != numReqArg)
        {
            DB_PRINT("ERROR: Missing required args -cvm, -cvs, or -cva needed in order to generate a CV certificate.\n");
            KEYGEN_displayHelp();
            status = -1;
        }

        /* get the expiration date */
        if (pArgs->gHasStartDate)
        {
            (void) DIGI_MEMCPY((ubyte *) &pArgs->gStartDate, (ubyte *) &pArgs->gCvcData.effectiveDate, sizeof(TimeDate));
            pArgs->gStartDate.m_year += 1970;
        }

        if (OK == KEYGEN_calculateEndDate(pArgs))
        {
            (void) DIGI_MEMCPY((ubyte *) &pArgs->gCvcData.expDate, (ubyte *) &pArgs->gEndDate, sizeof(TimeDate));
            if (pArgs->gCvcData.expDate.m_year > 129)
            {
                DB_PRINT("ERROR: Certificate can not be valid after year 2099.\n");
                status = -1;
            }
        }
        else
        {
            status = -1;
        }

        if (OK != status)
        {
            if (NULL != pArgs->gCvcData.pCertHolderAuthTemplate)
            {
                (void) DIGI_FREE((void **) &pArgs->gCvcData.pCertHolderAuthTemplate);
            }
            if (NULL != pArgs->gCvcData.pExtensions)
            {
                (void) DIGI_FREE((void **) &pArgs->gCvcData.pExtensions);
            }

            return status;
        }

        /* Country Code default of US */
        if(0x00 == pArgs->gCvcData.countryCode[0] && 0x00 == pArgs->gCvcData.countryCode[1])
        {
            pArgs->gCvcData.countryCode[0] = (ubyte) 'U';
            pArgs->gCvcData.countryCode[1] = (ubyte) 'S';
        }

        pArgs->gCvcData.isPss = pArgs->gKeyIsPss;
        pArgs->gCvcData.hashAlgo = pArgs->gKeyHashAlgo;

        /* For now no validation on alphanumeric properites of mnemonic or seqNum */
    }
#endif

    if (akt_rsa == pArgs->gKeyType && pArgs->gCurve)
    {
        DB_PRINT("WARNING: RSA algorithm but curve specified. It will be ignored.\n");
    }
    else if (akt_ecc == pArgs->gKeyType && pArgs->gKeySize)
    {
        DB_PRINT("WARNING: ECC algorithm but key size specified. It will be ignored.\n");
    }

    if (akt_rsa == pArgs->gKeyType && pArgs->gKeyIsPss)
    {
        if (!pArgs->gTap)
        {
            pArgs->gKeyType = akt_rsa_pss;
        }
    }
    else if (akt_rsa != pArgs->gKeyType && akt_hybrid != pArgs->gKeyType && pArgs->gKeyIsPss)
    {
        DB_PRINT("WARNING: -pss specified but key is not an RSA or HYBRID key. -pss will be ignored.\n");
    }

    if ((akt_rsa_pss != pArgs->gKeyType || !pArgs->gKeyIsPss) && NOT_SPECIFIED != pArgs->gKeySaltLen )
    {
        DB_PRINT("WARNING: key salt length -kslt specified but key is not an RSA-PSS key. It will be ignored.\n");
    }

#ifdef __ENABLE_DIGICERT_CV_CERT__
    if (!pArgs->gIsCvc && ((akt_rsa_pss != pArgs->gKeyType || !pArgs->gKeyIsPss) && NOT_SPECIFIED != pArgs->gKeyHashAlgo ))
#else
    if ((akt_rsa_pss != pArgs->gKeyType || !pArgs->gKeyIsPss) && NOT_SPECIFIED != pArgs->gKeyHashAlgo )
#endif
    {
        DB_PRINT("WARNING: key digest -kd specified but key is not an RSA-PSS key. It will be ignored.\n");
    }

#ifdef __ENABLE_DIGICERT_TAP__
    if (pArgs->gTap && (akt_rsa == pArgs->gKeyType || akt_ecc == pArgs->gKeyType) )
    {
        pArgs->gKeyType |= 0x00020000; /* will modify gKeyType to akt_tap_rsa or akt_tap_ecc */
    }
    else if(pArgs->gTap)
    {
        DB_PRINT("ERROR: -t/--tap option only available for ECC or RSA.\n");
        KEYGEN_displayHelp();
        return (MSTATUS) -1;
    }

    if (NULL != pArgs->gpPkcs12File && pArgs->gTap)
    {
        DB_PRINT("ERROR: Pkcs12 file generation -p12 not available for TAP keys.\n");
        KEYGEN_displayHelp();
        return (MSTATUS) -1;
    }
#endif

    if (FORMAT_SSH == pArgs->gOutPubForm && NULL == pArgs->gpOutPubFile)
    {
        DB_PRINT("WARNING: SSH output form specified but no output public key file specified. Only a PEM private key (or keypair) file being created\n");
    }

#if defined(__ENABLE_DIGICERT_CV_CERT__) || defined(__ENABLE_DIGICERT_CERTIFICATE_PRINT__)
skip_validations:
#endif

    return OK;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN void KEYGEN_resetArgs(KeyGenArgs *pArgs)
{
    pArgs->gKeyType = 0;
    pArgs->gKeySize = 0;
    pArgs->gHashAlgo = NOT_SPECIFIED;
    pArgs->gSaltLen = NOT_SPECIFIED;
    pArgs->gKeyIsPss = FALSE;
    pArgs->gKeyHashAlgo = NOT_SPECIFIED;
    pArgs->gKeySaltLen = NOT_SPECIFIED;
#ifndef  __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
    pArgs->gQSize = 0;
#endif
    pArgs->gCurve = 0;
#ifdef __ENABLE_DIGICERT_PQC__
    pArgs->gQsAlg  = 0;
#endif
    pArgs->gTap = FALSE;
#ifdef __ENABLE_DIGICERT_TAP__
    pArgs->gSignKeyTap = FALSE;
    pArgs->gModNum = KEYGEN_TAP_DEFAULT_MODNUM;
    pArgs->gKeyUsage = TAP_KEY_USAGE_GENERAL;
    pArgs->gEncScheme = TAP_ENC_SCHEME_NONE;
    pArgs->gSigScheme = TAP_SIG_SCHEME_NONE;
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
    pArgs->gpServer = NULL;
    pArgs->gPort = KEYGEN_TAP_DEFAULT_PORT; /* set back to defaults */
    pArgs->gTapProvider = KEYGEN_TAP_DEFAULT_PROVIDER;
#endif
#endif

    pArgs->gOutForm = FORMAT_PEM; /* default */
    pArgs->gOutPubForm = FORMAT_PEM; /* default */

    pArgs->gpInCsrFile = NULL;

    pArgs->gpOutFile = NULL;
    pArgs->gpOutCertFile = NULL;
    pArgs->gpOutPubFile = NULL;

#ifdef __ENABLE_KEYSTORE_PATH__
    pArgs->gpKeyStorePath = NULL;
#endif

    pArgs->gDays = 0;
    (void) DIGI_MEMSET((ubyte *) &pArgs->gStartDate, 0x00, sizeof(TimeDate));
    (void) DIGI_MEMSET((ubyte *) &pArgs->gEndDate, 0x00, sizeof(TimeDate));
    pArgs->gHasStartDate = FALSE;
    pArgs->gpSigningCert = NULL;
    pArgs->gpSigningKey = NULL;
    pArgs->gInForm = FORMAT_PEM; /* default */
    pArgs->gCreateCsr = FALSE;
    pArgs->gProtected = FALSE;

    if (NULL != pArgs->gpPkcs8Pw)
    {
        (void) DIGI_MEMSET_FREE(&pArgs->gpPkcs8Pw, pArgs->gPkcs8PwLen);
        pArgs->gPkcs8PwLen = 0;
    }

    pArgs->gVerbose = FALSE;
    pArgs->gpPkcs12File = NULL;
#if !defined(__DISABLE_3DES_CIPHERS__)
    pArgs->gPkcs12EncryptionType = PCKS8_EncryptionType_pkcs12_sha_3des;
#endif
    pArgs->gPkcs12GetIntegrityPw = FALSE;
    pArgs->gPkcs12GetPrivacyPw = FALSE;
    pArgs->gPkcs12GetKeyPw = FALSE;

#ifdef __ENABLE_DIGICERT_CV_CERT__
    pArgs->gIsCvc = FALSE;
    (void) DIGI_MEMSET((ubyte *) &pArgs->gCvcData, 0x00, sizeof(CV_CERT_GEN_DATA));
    pArgs->gIsPrintCVCert = FALSE;
#endif

    return;
}

/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_CRYPTO_KEYGEN_LIB__
/* This API right now is set up to handle QS algorithms only
   TODO in future this can be changed to handle all possible tc_keygen arguments */
static MSTATUS KEYGEN_setArgs(
    KeyGenArgs *pArgs,
    sbyte *pKeyType, /* NULL terminated string specifying algorithm */
    ubyte *pCsr,
    ubyte4 csrLen,
    ubyte4 expireInDays,
    ubyte *pCAKey, /* Optional - if not provided assume self-signed */
    ubyte4 caKeyLen,
    ubyte *pCACert, /* Optional - if not provided assume self-signed */
    ubyte4 caCertLen)
{
#ifdef __ENABLE_DIGICERT_PQC__

    MSTATUS status = OK;

    pArgs->gKeyType = akt_qs;

    if (0 == DIGI_STRCMP((const sbyte *)pKeyType, (const sbyte *)"MLDSA_65"))
    {
        pArgs->gQsAlg = cid_PQC_MLDSA_65;
    }
    else if (0 == DIGI_STRCMP((const sbyte *)pKeyType, (const sbyte *)"MLDSA_87"))
    {
        pArgs->gQsAlg = cid_PQC_MLDSA_87;
    }
    else if (0 == DIGI_STRCMP((const sbyte *)pKeyType, (const sbyte *)"FNDSA_512"))
    {
        pArgs->gQsAlg = cid_PQC_FNDSA_512;
    }
    else if (0 == DIGI_STRCMP((const sbyte *)pKeyType, (const sbyte *)"FNDSA_1024"))
    {
        pArgs->gQsAlg = cid_PQC_FNDSA_1024;
    }
    else if (0 == DIGI_STRCMP((const sbyte *)pKeyType, (const sbyte *)"SLHDSA_128S"))
    {
        pArgs->gQsAlg = cid_PQC_SLHDSA_SHAKE_128S;
    }
    else if (0 == DIGI_STRCMP((const sbyte *)pKeyType, (const sbyte *)"SLHDSA_192S"))
    {
        pArgs->gQsAlg = cid_PQC_SLHDSA_SHAKE_192S;
    }
    else if (0 == DIGI_STRCMP((const sbyte *)pKeyType, (const sbyte *)"SLHDSA_256S"))
    {
        pArgs->gQsAlg = cid_PQC_SLHDSA_SHAKE_256S;
    }
    else if (0 == DIGI_STRCMP((const sbyte *)pKeyType, (const sbyte *)"SLHDSA_128F"))
    {
        pArgs->gQsAlg = cid_PQC_SLHDSA_SHAKE_128F;
    }
    else if (0 == DIGI_STRCMP((const sbyte *)pKeyType, (const sbyte *)"SLHDSA_192F"))
    {
        pArgs->gQsAlg = cid_PQC_SLHDSA_SHAKE_192F;
    }
    else if (0 == DIGI_STRCMP((const sbyte *)pKeyType, (const sbyte *)"SLHDSA_256F"))
    {
        pArgs->gQsAlg = cid_PQC_SLHDSA_SHAKE_256F;
    }
    else
    {
        status = ERR_CRYPTO_QS_UNSUPPORTED_CIPHER;
        goto exit;
    }

    status = ERR_INVALID_INPUT;
    if (NULL == pCsr || !csrLen)
        goto exit;

    pArgs->gpInCsrBuffer = pCsr;
    pArgs->gInCsrLen = csrLen;

    if (0 == expireInDays)
        goto exit;

    pArgs->gDays = expireInDays;
    pArgs->gInForm = FORMAT_PEM;
    pArgs->gOutForm = FORMAT_PEM;

    if ((caKeyLen && NULL == pCAKey) || (caCertLen && NULL == pCACert))
        goto exit;

    if ((pCAKey && !pCACert) || (!pCAKey && pCACert))
        goto exit;

    status = OK;

    pArgs->gpSigningKeyBuffer = pCAKey;
    pArgs->gSigningKeyLen = caKeyLen;

    pArgs->gpSigningCertBuffer = pCACert;
    pArgs->gSigningCertLen = caCertLen;

exit:

    return status;
#else
    return ERR_NOT_IMPLEMENTED;
#endif /* __ENABLE_DIGICERT_PQC__ */
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS KEYGEN_keyCertGen(
    sbyte *pKeyType, /* NULL terminated string specifying algorithm */
    ubyte *pCsr,
    ubyte4 csrLen,
    ubyte4 expireInDays,
    ubyte *pCAKey, /* Optional - if not provided assume self-signed */
    ubyte4 caKeyLen,
    ubyte *pCACert, /* Optional - if not provided assume self-signed */
    ubyte4 caCertLen,
    ubyte **ppKey,
    ubyte4 *pKeyLen,
    ubyte **ppCert,
    ubyte4 *pCertLen)
{
    MSTATUS status = OK;
    AsymmetricKey key = {0};
    randomContext *pRand = NULL;
    ubyte *pKey = NULL;
    ubyte4 keyLen = 0;
    ubyte *pCert = NULL;
    ubyte4 certLen = 0;

    KEYGEN_resetArgs(&gKeyGenArgs);

    status = KEYGEN_setArgs(&gKeyGenArgs, pKeyType, pCsr, csrLen, expireInDays, pCAKey, caKeyLen, pCACert, caCertLen);
    if (OK != status)
        goto exit;

    status = RANDOM_acquireContext(&pRand);
    if (OK != status)
        goto exit;

    status = CRYPTO_initAsymmetricKey(&key);
    if (OK != status)
        goto exit;

#ifdef __EMABLE_DIGICERT_TAP__
    status = KEYGEN_generateKey(&gKeyGenArgs, (void *) &gTapArgs, &key, pRand);
#else
    status = KEYGEN_generateKey(&gKeyGenArgs, NULL, &key, pRand);
#endif
    if (OK != status)
        goto exit;

    status = KEYGEN_outputPrivKey(&gKeyGenArgs, &key, pRand, FALSE, &pKey, &keyLen);
    if (OK != status)
        goto exit;

    status = KEYGEN_generateCertificate(&gKeyGenArgs, &key, pRand, &pCert, &certLen);
    if (OK != status)
        goto exit;

    *ppKey = pKey; pKey = NULL;
    *pKeyLen = keyLen;
    *ppCert = pCert; pCert = NULL;
    *pCertLen = certLen;

exit:

    if (NULL != pKey)
    {
        (void) DIGI_MEMSET_FREE(&pKey, keyLen);
    }

    if (NULL != pCert)
    {
        (void) DIGI_MEMSET_FREE(&pCert, certLen);
    }

    (void) CRYPTO_uninitAsymmetricKey(&key, NULL);
    (void) RANDOM_releaseContext(&pRand);
    KEYGEN_resetArgs(&gKeyGenArgs);

    return (int) status;
}

#endif /* __ENABLE_DIGICERT_CRYPTO_KEYGEN_LIB__ */

/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_CERTIFICATE_PRINT__

MOC_EXTERN MSTATUS KEYGEN_printCertificateOrCsr(KeyGenArgs *pArgs)
{
     MSTATUS status = OK;
    ubyte *pCert = NULL;
    ubyte4 certLen = 0;
    sbyte4 result = -1;
    ubyte4 pemType = 0;
    ubyte *out = NULL;
    ubyte4 outLen = 0;

    status = DIGICERT_readFile((const char *)pArgs->gpSigningCert, &pCert, &certLen);
    if (OK != status)
    {
        DB_PRINT("ERROR: Unable to read file: %s  status = %d\n", pArgs->gpSigningCert ,status);
        goto exit;
    }

    if ((OK == DIGI_MEMCMP(pCert, "-", 1, &result)) && result == 0)
    {
        status = BASE64_decodePemMessageAlloc(pCert, certLen , &pemType, &out, &outLen);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "Failed to decode certificate file: %s\n", pArgs->gpSigningCert);
            goto exit;
        }

        status = X509_printCertificateOrCsr(out, outLen);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "Failed to print certificate file: %s\n", pArgs->gpSigningCert);
            goto exit;
        }
    }
    else
    {
        status = X509_printCertificateOrCsr(pCert, certLen);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "Failed to print certificate file: %s\n", pArgs->gpSigningCert);
            goto exit;
        }
    }


exit:

    if (NULL != out)
    {
        (void) DIGI_MEMSET_FREE(&out, outLen);
    }

    if (NULL != pCert)
    {
        (void) DIGI_MEMSET_FREE(&pCert, certLen);
    }

    return status;

}
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_KEYGEN_LIB__
int KEYGEN_main(int argc, char *argv[])
#else
int main(int argc, char *argv[])
#endif
{
    MSTATUS status = OK;
    AsymmetricKey key = {0};
    randomContext *pRand = NULL;

    /* call reset to set defaults*/
    KEYGEN_resetArgs(&gKeyGenArgs);
    /* we'll set error and warning to true though */

    status = KEYGEN_getArgs(&gKeyGenArgs, argc, argv);
    if (OK != status)
        goto exit;

    /* we'll always set at least the warning level */
    status = MSG_LOG_init(gKeyGenArgs.gVerbose ? MSG_LOG_VERBOSE : MSG_LOG_WARNING);
    if (OK != status)
    {
        /* Failed to initialize logger, exit without printing error message */
        goto exit;
    }

    MSG_LOG_setLabel(TC_KEYGEN_LOG_LABEL);

#ifdef __ENABLE_DIGICERT_CERTIFICATE_PRINT__
    if (gKeyGenArgs.gIsPrintCert)
    {
        status = KEYGEN_printCertificateOrCsr(&gKeyGenArgs);
        if (OK != status)
        {
            DB_PRINT("Invalid input file: %s  status = %d\n", gKeyGenArgs.gpSigningCert, status);
            goto exit;
        }
    }
#endif

#ifdef __ENABLE_DIGICERT_CV_CERT__
    if (gKeyGenArgs.gIsPrintCVCert)
    {
        status = KEYGEN_printCvCertificate(&gKeyGenArgs);
        if (OK != status)
        {
            DB_PRINT("ERROR: Unable to parse and print entire CV Certificate: %s  status = %d\n", gKeyGenArgs.gpSigningCert ,status);
        }

        goto exit;
    }
#endif

    if (gKeyGenArgs.gVerbose)
    {
        if (akt_rsa == gKeyGenArgs.gKeyType)
        {
            DB_PRINT("Generating RSA %d bit key, public key = 0x10001\n", gKeyGenArgs.gKeySize); /* TO DO other public keys */
        }
        else if (akt_rsa_pss == gKeyGenArgs.gKeyType)
        {
            DB_PRINT("Generating RSA-PSS %d bit key, public key = 0x10001\n", gKeyGenArgs.gKeySize);
        }
        else if (akt_tap_rsa == gKeyGenArgs.gKeyType)
        {
            DB_PRINT("Generating RSA %d bit TAP key.\n", gKeyGenArgs.gKeySize);  /* 0x10001 may depend on the underlying implementation */
        }
        else if (akt_ecc == gKeyGenArgs.gKeyType || akt_tap_ecc == gKeyGenArgs.gKeyType )
        {
            DB_PRINT("Generating ECC %s key, curve = ", akt_tap_ecc == gKeyGenArgs.gKeyType ? "TAP" : "");
            switch (gKeyGenArgs.gCurve)
            {
                case cid_EC_P192:
                    DB_PRINT("P192.\n");
                    break;
                case cid_EC_P224:
                    DB_PRINT("P224.\n");
                    break;
                case cid_EC_P256:
                    DB_PRINT("P256.\n");
                    break;
                case cid_EC_P384:
                    DB_PRINT("P384.\n");
                    break;
                case cid_EC_P521:
                    DB_PRINT("P521.\n");
                    break;
                case cid_EC_Ed25519:
                    DB_PRINT("curve25519.\n");
                    break;
                case cid_EC_Ed448:
                    DB_PRINT("curve448.\n");
                    break;
                default:
                    break;
            }
        }
    }

    status = (MSTATUS) DIGICERT_initDigicert();
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_TAP__
    if (gKeyGenArgs.gTap || gKeyGenArgs.gSignKeyTap)
    {
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
        if (NULL != gKeyGenArgs.gpServer)
        {
#endif
            /* signing keys might be tap keys attempt to init if tap local or a server is given */
            status = KEYGEN_TAP_init(&gKeyGenArgs, &gTapArgs);
            if (OK != status)
            {
                DB_PRINT("ERROR: TAP initialization failed, status = %d\n", status);
                goto exit;
            }
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
        }
        else
        {
            status = ERR_INVALID_ARG;
            DB_PRINT("ERROR: -ts (or --tap-server) argument is required in order to generate or use a TAP key, status = %d\n", status);
            goto exit;
        }
#endif
    }
#endif /* __ENABLE_DIGICERT_TAP__ */

    if (gKeyGenArgs.gCreateCsr)
    {
        /* different flow for CSR creation, no keygen */
        status = KEYGEN_createCSR(&gKeyGenArgs);
        if (OK != status)
        {
            DB_PRINT("ERROR: Unable to generate signed CSR, error code = %d\n", status);
        }
        goto done;
    }

    status = RANDOM_acquireContext(&pRand);
    if (OK != status)
        goto exit;

    status = CRYPTO_initAsymmetricKey(&key);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_TAP__
    status = KEYGEN_generateKey(&gKeyGenArgs, (void *) &gTapArgs, &key, pRand);
#else
    status = KEYGEN_generateKey(&gKeyGenArgs, NULL, &key, pRand);
#endif
    if (OK != status)
        goto exit;

    status = KEYGEN_outputPrivKey(&gKeyGenArgs, &key, pRand, FALSE, NULL, NULL);
    if (OK != status)
        goto exit;

    if (NULL != gKeyGenArgs.gpOutCertFile)
    {
#ifdef __ENABLE_DIGICERT_CV_CERT__
        if (gKeyGenArgs.gIsCvc)
        {
            status = KEYGEN_generateCvCertificate(&gKeyGenArgs, &key); /* TODO may want to pass in pRand someday */
            if (OK != status)
                goto exit;
        }
        else
#endif
        {
            status = KEYGEN_generateCertificate(&gKeyGenArgs, &key, pRand, NULL, NULL);
            if (OK != status)
                goto exit;
        }
    }

    if (NULL != gKeyGenArgs.gpOutPubFile)
    {
#ifdef __ENABLE_DIGICERT_PQC__
        if (akt_qs == gKeyGenArgs.gKeyType)
        {
            DB_PRINT("WARNING: Not outputting public key for QS alg. This feature is not yet supported.\n");
        }
        else
#endif
        {
            status = KEYGEN_outputPubKey(&gKeyGenArgs, &key);
            if (OK != status)
                goto exit;
        }
    }

done:

    if (gKeyGenArgs.gVerbose)
    {
        DB_PRINT("Done!\n");
    }

exit:

    if (NULL != gKeyGenArgs.gpInCsrBuffer)
    {
        (void) DIGI_MEMSET_FREE(&gKeyGenArgs.gpInCsrBuffer, gKeyGenArgs.gInCsrLen);
    }
    if (NULL != gKeyGenArgs.gpSigningCertBuffer)
    {
        (void) DIGI_MEMSET_FREE(&gKeyGenArgs.gpSigningCertBuffer, gKeyGenArgs.gSigningCertLen);
    }
    if (NULL != gKeyGenArgs.gpSigningKeyBuffer)
    {
        (void) DIGI_MEMSET_FREE(&gKeyGenArgs.gpSigningKeyBuffer, gKeyGenArgs.gSigningKeyLen);
    }

#ifdef __ENABLE_DIGICERT_CV_CERT__
    if (gKeyGenArgs.gIsCvc)
    {
        if (NULL != gKeyGenArgs.gCvcData.pSignerKey && (uintptr) gKeyGenArgs.gCvcData.pSignerKey != (uintptr) gKeyGenArgs.gCvcData.pCertKey)
        {
            (void) CRYPTO_uninitAsymmetricKey(gKeyGenArgs.gCvcData.pSignerKey, NULL);
            (void) DIGI_FREE((void **) &gKeyGenArgs.gCvcData.pSignerKey);
        }

        if (NULL != gKeyGenArgs.gCvcData.pSignerAuthRef)
        {
            (void) DIGI_FREE((void **) &gKeyGenArgs.gCvcData.pSignerAuthRef);
        }

        if (NULL != gKeyGenArgs.gCvcData.pCertHolderAuthTemplate)
        {
            (void) DIGI_FREE((void **) &gKeyGenArgs.gCvcData.pCertHolderAuthTemplate);
        }

        if (NULL != gKeyGenArgs.gCvcData.pExtensions)
        {
            (void) DIGI_FREE((void **) &gKeyGenArgs.gCvcData.pExtensions);
        }
    }
#endif

#ifdef __ENABLE_DIGICERT_TAP__
    /* If the generated key is a TAP key and was not used to sign a (self signed) cert, it needs to be unloaded */
    if (gKeyGenArgs.gTap && (NULL == gKeyGenArgs.gpOutCertFile || (NULL != gKeyGenArgs.gpOutCertFile && NULL != gKeyGenArgs.gpSigningKey)))
    {
        TAP_Key *pTapKey = NULL;
        (void) CRYPTO_INTERFACE_getTapKey(&key, &pTapKey);
        (void) TAP_unloadKey(pTapKey, gpErrContext);
    }
#endif
    (void) CRYPTO_uninitAsymmetricKey(&key, NULL);
    (void) RANDOM_releaseContext(&pRand);

#ifdef __ENABLE_DIGICERT_TAP__
    (void) KEYGEN_TAP_clean(&gTapArgs);
#endif

    (void) DIGICERT_freeDigicert();
    KEYGEN_resetArgs(&gKeyGenArgs);

    MSG_LOG_uninit();

    return (int) status;
}
#endif /* #if (defined(__ENABLE_DIGICERT_CRYPTO_KEYGEN__) || defined(__ENABLE_DIGICERT_CRYPTO_KEYGEN_LIB__)) &&\
              !defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__) */
