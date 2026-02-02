/*
 * tap_extern.c
 *
 * @details  This file contains the TAP Extern functions
 *
 * Trust Anchor Platform APIs
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#if (defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_TAP_EXTERN__))
#include <stdio.h>
#include "../smp/smp_cc.h"
#include "../tap/tap.h"
#include "../tap/tap_api.h"
#include "../tap/tap_utils.h"
#include "../tap/tap_smp.h"
#include "../crypto/mocasym.h"
#include "../crypto/mocasymkeys/tap/rsatap.h"
#include "../crypto/mocasymkeys/tap/ecctap.h"
#include "../crypto_interface/tap_extern.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/cert_store.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/pkcs_key.h"
#include "../common/sizedbuffer.h"
#include "../common/mocana.h"
#include "../common/moc_config.h"
#include "../common/mfmgmt.h"
#include "../crypto/hw_accel.h"

#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
#include "../tap/tap_conf_common.h"
#endif

#if defined( __RTOS_LINUX__) || defined(__RTOS_VXWORKS__) || defined(__RTOS_CYGWIN__) || \
    defined(__RTOS_SOLARIS__) || defined(__RTOS_IRIX__) || defined(__RTOS_OPENBSD__) || \
    defined(__RTOS_ANDROID__) || defined(__RTOS_FREEBSD__) || defined(__RTOS_OSX__)
#include <signal.h>
#include <termios.h>
#endif

#define MAX_NAME_LENGTH 256
#define DEF_TAPPROVIDER "TAP_PROVIDER_TPM2"
#include "../common/tpm2_path.h"
#define DEF_TAPCCONFIG "/etc/digicert/tapc.conf"
#define DEF_TAPSERVERNAME "ssltest.mocana.com"
#define DEF_TAPSERVERPORT "8277"

#define MAX_PASSWORD_SIZE   (128)

/* root certs */
typedef struct TAP_EXTERN_ROOT_CERT_INFO
{
    struct TAP_EXTERN_ROOT_CERT_INFO *next;

    char* fileName;
    ubyte* certData;
    ubyte4 certLength;
} TAP_EXTERN_ROOT_CERT_INFO;

typedef struct
{
    ubyte4 enableMutualAuth;
    ubyte4 enableunsecurecomms;
    char *certificateFileName;
    char *certificateKeyFileName;
    certStorePtr pSslCertStore;
    TAP_EXTERN_ROOT_CERT_INFO *pRootCerts;
    ubyte4 serverPort;
    ubyte4  isNonFsMode;
    TAP_Buffer configData;
} tapConfigInfo;

typedef MSTATUS (*CONFIG_Callback)(ubyte* pLineStart, ubyte4 bytesLeft,
				   void* arg, ubyte4 *bytesUsed);

typedef struct
{
  const sbyte *       key;
  CONFIG_Callback     callback;
  void*               callback_arg;
} configItem;

typedef struct
{
    union
    {
        ubyte4 *pIntValue;
        ubyte **ppStrValue;
        ubyte *pContext;
        TAP_EXTERN_ROOT_CERT_INFO **ppRootCerts;
    } u;
    char *name;
} TAP_EXTERN_PARSE_PARMS;

/*typedef int sbyte4;*/
static int g_isTAPInitialized = 0;
static ubyte4 gClientConfigFileParsed = 0;
static tapConfigInfo g_TapClientConfigInfo = {0};
static certStorePtr g_pCertStore;

static TAP_EntityCredentialList *g_pTapEntityCred = NULL;
static TAP_CredentialList       *g_pTapKeyCred    = NULL;
static TAP_ModuleList            g_moduleList     = { 0 };
static TAP_Context              *g_pTapContext    = NULL;

typedef enum extern_tap_env
{
    tap_config = 0,
    tap_provider,
    tap_client_config,
    tap_server_name,
    tap_server_port
} extern_tap_env;

#if defined(__RTOS_WIN32__)

static TCHAR
WIN32_getch()
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

static MSTATUS getPassword(
    ubyte *pBuffer,
    ubyte4 bufferLen,
    ubyte4 *pOutLen
    )
{
    ubyte4 i;
    int c = 0;

    printf ("Enter PEM pass phrase : ");

    i = 0;
    do
    {
        c = WIN32_getch();

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
                    if (i < bufferLen)
                    {
                        pBuffer[i++] = c;
                    }
                }
                break;
        }
    } while (c != 0x0D);

    printf("\n");

    *pOutLen = i;

    return OK;
}

#elif defined( __RTOS_LINUX__) || defined(__RTOS_VXWORKS__) || defined(__RTOS_CYGWIN__) || \
      defined(__RTOS_SOLARIS__) || defined(__RTOS_IRIX__) || defined(__RTOS_OPENBSD__) || \
      defined(__RTOS_ANDROID__) || defined(__RTOS_FREEBSD__) || defined(__RTOS_OSX__)

static MSTATUS getEnteredPassword(char *pBuffer, ubyte4 bufferLen) 
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

static MSTATUS getPassword(
    ubyte *pBuffer,
    ubyte4 bufferLen,
    ubyte4 *pOutLen
    )
{
    MSTATUS status;
    sbyte pPassword[MAX_PASSWORD_SIZE + 1] = {0};
    ubyte4 passwordLen;

    *pOutLen = 0;

#ifdef __RTOS_ANDROID__
    status = ERR_INVALID_INPUT;
#else
    printf("Enter PEM pass phrase : ");
    status = getEnteredPassword(pPassword, MAX_PASSWORD_SIZE + 1);
    printf("\n");
#endif
    if (OK != status)
        goto exit;

    passwordLen = DIGI_STRLEN(pPassword);

    if (passwordLen > bufferLen)
        passwordLen = bufferLen;

    status = DIGI_MEMCPY(pBuffer, (ubyte *) pPassword, passwordLen);
    if (OK != status)
        goto exit;

    *pOutLen = passwordLen;

exit:

    (void) DIGI_MEMSET(pPassword, 0x00, MAX_PASSWORD_SIZE + 1);
    return status;
}
#endif /* ifdef __RTOS_WIN32__ */

static MSTATUS
getTapProvider(const char* providerString, ubyte *tapProvider)
{
    MSTATUS status = OK;

    if(DIGI_STRCMP((const sbyte *)providerString, (const sbyte *)"TAP_PROVIDER_TPM2") == 0)
    {
        *tapProvider = TAP_PROVIDER_TPM2;
    }
    else if(DIGI_STRCMP((const sbyte *)providerString, (const sbyte *)"TAP_PROVIDER_PKCS11") == 0)
    {
        *tapProvider = TAP_PROVIDER_PKCS11;
    }
    else
    {
        status = ERR_TAP_NO_PROVIDERS_AVAILABLE;
    }

    return status;
}

static MSTATUS
getENVVariables(extern_tap_env env, char **value)
{
    MSTATUS status = OK;
    sbyte *env_value = NULL;

    switch(env)
    {
    case tap_config:
        status = FMGMT_getEnvironmentVariableValueAlloc ("MOCANA_TAPCONFIGFILE", &env_value);
        if (OK == status)
        {
            status = DIGI_MEMCPY((void *)(*value), (void *)env_value, DIGI_STRLEN((sbyte *)env_value));
        }
        else
        {
            status = DIGI_MEMCPY((void *)(*value), (void *)TPM2_CONFIGURATION_FILE, MAX_NAME_LENGTH);
        }
        break;
    case tap_provider:
        status = FMGMT_getEnvironmentVariableValueAlloc ("MOCANA_TAPPROVIDER", &env_value);
        if (OK == status)
        {
            status = DIGI_MEMCPY((void *)(*value), (void *)env_value, DIGI_STRLEN((sbyte *)env_value));
        }
        else
        {
            status = DIGI_MEMCPY((void *)(*value), (void *)DEF_TAPPROVIDER, MAX_NAME_LENGTH);
        }
        break;
    case tap_client_config:
        status = FMGMT_getEnvironmentVariableValueAlloc ("MOCANA_TAPCCONFIG", &env_value);
        if (OK == status)
        {
            status = DIGI_MEMCPY((void *)(*value), (void *)env_value, DIGI_STRLEN((sbyte *)env_value));
        }
        else
        {
            status = DIGI_MEMCPY((void *)(*value), (void *)DEF_TAPCCONFIG, MAX_NAME_LENGTH);
        }
        break;
    case tap_server_name:
        status = FMGMT_getEnvironmentVariableValueAlloc ("MOCANA_TAPSERVERNAME", &env_value);
        if (OK == status)
        {
            status = DIGI_MEMCPY((void *)(*value), (void *)env_value, DIGI_STRLEN((sbyte *)env_value));
        }
        else
        {
            status = DIGI_MEMCPY((void *)(*value), (void *)DEF_TAPSERVERNAME, MAX_NAME_LENGTH);
        }
        break;
    case tap_server_port:
        status = FMGMT_getEnvironmentVariableValueAlloc ("MOCANA_TAPSERVERPORT", &env_value);
        if (OK == status)
        {
            status = DIGI_MEMCPY((void *)(*value), (void *)env_value, DIGI_STRLEN((sbyte *)env_value));
        }
        else
        {
            status = DIGI_MEMCPY((void *)(*value), (void *)DEF_TAPSERVERPORT, MAX_NAME_LENGTH);
        }
        break;
    default:
        break;
    }

    if (NULL != env_value)
        DIGI_FREE ((void **) &env_value);

    if (*value == NULL)
        status = -1;

    return status;
}

static MSTATUS
parseStrValue(ubyte* line, ubyte4 bytesLeft, void* arg, ubyte4* bytesUsed)
{
    MSTATUS status;
    ubyte4  offset = 0, i, sLen;
    TAP_EXTERN_PARSE_PARMS *pTapParseParms = (TAP_EXTERN_PARSE_PARMS *)arg;
    ubyte *pValString = NULL;

    if (NULL == pTapParseParms)
    	return ERR_INVALID_ARG;

    if (OK != (status = CONFIG_gotoValue(line, bytesLeft, (const sbyte *)pTapParseParms->name, '=', &offset)))
    {
        return status;
    }

    /* value is a number */
    for ( i = offset;
            i < bytesLeft && line[i] != '\n' && line[i] != '\r';
            ++i)
    {
    }

    /* go back and look for space */
    for ( --i; i >= offset && DIGI_ISSPACE(line[i]); --i)
    {
    }

    sLen =  i + 2 - offset;
    status = DIGI_MALLOC((void **)&pValString, sLen);
    if (OK != status)
    {
        printf("ParseStrVal: Error allocating %d bytes for string value\n", sLen);
    }
    else
    {
        DIGI_MEMCPY(pValString, line+offset, sLen-1);
        pValString[sLen-1] = 0;
        *pTapParseParms->u.ppStrValue = (ubyte *)pValString;

        /* Tell the parser we've eaten the rest of the line */
        *bytesUsed = CONFIG_nextLine(line, bytesLeft);
    }

    return status;
}

static MSTATUS
parseIntValue(ubyte* line, ubyte4 bytesLeft, void* arg, ubyte4* bytesUsed)
{
    MSTATUS status;
    ubyte4  offset = 0, i, sLen;
    TAP_EXTERN_PARSE_PARMS *pTapParseParms = (TAP_EXTERN_PARSE_PARMS *)arg;
    char *valString;

    if (NULL == pTapParseParms)
        return ERR_INVALID_ARG;

    if (OK != (status = CONFIG_gotoValue(line, bytesLeft, (const sbyte *)pTapParseParms->name, '=', &offset)))
    {
        return status;
    }

    /* value is a number */
    for ( i = offset;
            i < bytesLeft && line[i] != '\n' && line[i] != '\r';
            ++i)
    {
    }

    /* go back and look for space */
    for ( --i; i >= offset && DIGI_ISSPACE(line[i]); --i)
    {
    }

    sLen =  i + 2 - offset;
    status = DIGI_MALLOC((void **)&valString, sLen);
    if (OK != status)
    {
        printf("ParseIntVal: Error allocating %d bytes for integer value\n", sLen);
    }
    else
    {
        DIGI_MEMCPY(valString, line+offset, sLen-1);
        valString[sLen-1] = 0;
        *pTapParseParms->u.pIntValue = DIGI_ATOL((const sbyte *)valString, NULL);

        /* Tell the parser we've eaten the rest of the line */
        *bytesUsed = CONFIG_nextLine(line, bytesLeft);
        DIGI_FREE((void **)&valString);
    }

    return status;
}

static MSTATUS
parseRootCertificateFileLine(ubyte* line, ubyte4 bytesLeft, void* arg, ubyte4* bytesUsed)
{
    MSTATUS status;
    ubyte4  offset = 0, i, sLen;
    char *rootCertificateFileName = NULL;
    TAP_EXTERN_PARSE_PARMS *pTapParseParms = (TAP_EXTERN_PARSE_PARMS *)arg;
    TAP_EXTERN_ROOT_CERT_INFO *pRootCertNode;

    if (NULL == pTapParseParms)
        return ERR_INVALID_ARG;

    if (OK != (status = CONFIG_gotoValue(line, bytesLeft, (const sbyte *)pTapParseParms->name, '=', &offset)))
    {
        return status;
    }

    /* value is the path to a certificate */
    for ( i = offset;
            i < bytesLeft && line[i] != '\n' && line[i] != '\r';
            ++i)
    {
    }

    /* go back and look for space */
    for ( --i; i >= offset && DIGI_ISSPACE(line[i]); --i)
    {
    }

    /* rootCertificateFileName is the string between offset and i */
    /* it needs to be null terminated so we will make a copy */
    /* i >= offset */
    sLen =  i + 2 - offset;
    status = DIGI_MALLOC((void **)&rootCertificateFileName, sLen);
    if (OK != status)
    {
        printf("ParseRootCertificateFileLine: Error allocating memory (%d) for a rootCertificateFileName string\n", sLen);
    }
    else
    {
        DIGI_MEMCPY(rootCertificateFileName, line+offset, sLen-1);
        rootCertificateFileName[sLen-1] = 0;

        /* Allocate Root Certificate File node */
        if (OK != (status = DIGI_MALLOC((void **)&pRootCertNode, sizeof(TAP_EXTERN_ROOT_CERT_INFO))))
        {
            goto exit;
        }

        DIGI_MEMSET((ubyte *)pRootCertNode, 0, sizeof(TAP_EXTERN_ROOT_CERT_INFO));

        /* Add new Certificate to top of the list */
        pRootCertNode->next = *pTapParseParms->u.ppRootCerts;
        *pTapParseParms->u.ppRootCerts = pRootCertNode;

        pRootCertNode->fileName = rootCertificateFileName;

        /* Tell the parser we've eaten the rest of the line */
        *bytesUsed = CONFIG_nextLine(line, bytesLeft);
    }

exit:

    return status;
}

MSTATUS
parseData(ubyte* data, ubyte4 dataLen, configItem* configs)
{
  ubyte4 offset = 0;
  ubyte4 index;
  MSTATUS result = OK;
  ubyte found;

  /* jump over white space */
  while ( DIGI_ISSPACE( *data))
  {
    ++data;
    --dataLen;
  }

  while (offset < dataLen)
  {
    found = 0;

    for (index = 0; configs[index].key; index++)
    {
      /* Quickly skip lines that are empty or begin with # */
      if ('#' == *(data+offset) || '\r' == *(data+offset) ||
	  '\n' == *(data+offset))
	break;

      if ( 0 == DIGI_STRNICMP( (sbyte*)data+offset, configs[index].key, DIGI_STRLEN(configs[index].key )))
      {
	ubyte4 used = DIGI_STRLEN(configs[index].key);

	/* Only call the callback if it's not-NULL */
	if (configs[index].callback)
	{
	  found = 1;
	  result = configs[index].callback(data+offset, dataLen-offset,
					   configs[index].callback_arg, &used);
	  if (result != OK)
	    goto exit;

	  offset += used;
	}

	break;
      }
    }

    if (!found)
      offset += CONFIG_nextLine(data+offset, dataLen-offset);
  }

 exit:

  return result;
}


static MSTATUS
parseTAPConfig(tapConfigInfo *pTapClientInfo, const char *fullPath)
{
    MSTATUS status = OK;
    ubyte *pConfig = NULL;
    ubyte4 configLen;
    static configItem configItems[] =
    {
        {(const sbyte *)"serverport", 0, 0},
        {(const sbyte *)"enablemutualauthentication", 0, 0},
        {(const sbyte *)"enableunsecurecomms", 0, 0},
        {(const sbyte *)"sslcertificatefile", 0, 0},
        {(const sbyte *)"sslcertificatekeyfile", 0, 0},
        {(const sbyte *)"sslrootcertificatefile", 0, 0},
        {NULL, 0, 0}
    };
    TAP_EXTERN_PARSE_PARMS parseParms[sizeof(configItems)/sizeof(configItem)];
    TAP_EXTERN_PARSE_PARMS *pParseParms;
#ifdef __RTOS_WIN32__
    char *pTapClientConfigFile = NULL;
#endif

    if(!pTapClientInfo->isNonFsMode)
    {
        if (fullPath)
        {
            status = DIGICERT_readFile(fullPath, &pConfig, &configLen);
        }
        else
        {
            if (OK > (status = DIGICERT_readFile(fullPath, &pConfig, &configLen)))
            {
                goto exit;
            }
        }
    }
    else
    {
        pConfig     = pTapClientInfo->configData.pBuffer;
        configLen   = pTapClientInfo->configData.bufferLen;
    }

    if (OK == status)
    {
        pTapClientInfo->pRootCerts = NULL;
        pParseParms = &parseParms[0];

        configItems[0].callback = parseIntValue;
        pParseParms->u.pIntValue = &pTapClientInfo->serverPort;
        pParseParms->name = (char *)configItems[0].key;
        configItems[0].callback_arg = pParseParms;

        pParseParms++;

        configItems[1].callback = parseIntValue;
        pParseParms->u.pIntValue = &pTapClientInfo->enableMutualAuth;
        pParseParms->name = (char *)configItems[1].key;
        configItems[1].callback_arg = pParseParms;

        pParseParms++;

        configItems[2].callback = parseIntValue;
        pParseParms->u.pIntValue = &pTapClientInfo->enableunsecurecomms;
        pParseParms->name = (char *)configItems[2].key;
        configItems[2].callback_arg = pParseParms;

        pParseParms++;

        configItems[3].callback = parseStrValue;
        pParseParms->u.ppStrValue = (ubyte **)&pTapClientInfo->certificateFileName;
        pParseParms->name = (char *)configItems[3].key;
        configItems[3].callback_arg = pParseParms;

        pParseParms++;

        configItems[4].callback = parseStrValue;
        pParseParms->u.ppStrValue = (ubyte **)&pTapClientInfo->certificateKeyFileName;
        pParseParms->name = (char *)configItems[4].key;
        configItems[4].callback_arg = pParseParms;

        pParseParms++;

        configItems[5].callback = parseRootCertificateFileLine;
        pParseParms->name = (char *)configItems[5].key;
        pParseParms->u.ppRootCerts = &pTapClientInfo->pRootCerts;
        configItems[5].callback_arg = pParseParms;

        status = parseData(pConfig, configLen, configItems);

        if(!pTapClientInfo->isNonFsMode)
            DIGICERT_freeReadFile(&pConfig);

        if (OK != status)
        {
            /* Debug */
            goto exit;
        }
        gClientConfigFileParsed = 1;
    }
    else
    {
        /* Debug */
        status = ERR_FILE_OPEN_FAILED;
    }

exit:
#ifdef __RTOS_WIN32__
    if (NULL != pTapClientConfigFile)
    {
        DIGI_FREE(&pTapClientConfigFile);
    }
#endif /*__RTOS_WIN32__*/

    if(!pTapClientInfo->isNonFsMode)
    {
        if(pConfig)
            FREE(pConfig);
    }
    return status;
}

static MSTATUS
loadCertStore(certStorePtr *pCertStore, ubyte *pTapcConfigFileName)
{
    certDescriptor certDesc = { 0 };
    ubyte* pContents = NULL;
    ubyte4 contentsLen = 0;
    ubyte* CACert = NULL;
    ubyte4 CACertLength = 0;
    AsymmetricKey asymKey = { 0 };
    SizedBuffer certificate;
    MSTATUS status = OK;
    hwAccelDescr hwAccelCtx = 0;

    /* Read PKCS8 , handle encryoted PEM */
    ubyte *pKeyBlob = NULL;
    ubyte4 keyBlobLength = 0;
    ubyte* pw = NULL;
    ubyte4 pwLen = 0;

    // Initialioze the certStore and pass it here.
    // Read cert, key and ca from tap config file. Load it to cert store.

    if (OK > (status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
    {
        goto exit;
    }

    if (OK > (status = parseTAPConfig(&g_TapClientConfigInfo, pTapcConfigFileName)))
    {
        goto exit;
    }

    if (!g_TapClientConfigInfo.enableunsecurecomms)
    {
        /* Create cert Store */
        if (OK > (status = CERT_STORE_createStore(pCertStore)))
        {
            goto exit;
        }

        if (g_TapClientConfigInfo.enableMutualAuth)
        {
            /* Read the certificate */
            if (OK > (status = DIGICERT_readFile(g_TapClientConfigInfo.certificateFileName,
                                               &certDesc.pCertificate, &certDesc.certLength)))
            {
                goto exit;
            }

            certificate.data   = certDesc.pCertificate;
            certificate.length = certDesc.certLength;

            /* Read the key */
            if (OK > (status = DIGICERT_readFile(g_TapClientConfigInfo.certificateKeyFileName,
                                               &pContents, &contentsLen)))
            {
                goto exit;
            }

            if (OK > (status = CRYPTO_initAsymmetricKey(&asymKey)))
            {
                goto exit;
            }
            if (OK > (status = CRYPTO_deserializeAsymKey(pContents, contentsLen, NULL, &asymKey)))
            {
                /* Convert the PEM to DER before calling PKCS8 function */
                if ( OK > (status = CA_MGMT_decodeCertificate( pContents, contentsLen,
                                                               &pKeyBlob, &keyBlobLength)))
                {
                    goto exit1;
                }

                if (OK > (status = PKCS_getPKCS8KeyEx(MOC_HW(hwAccelCtx) pKeyBlob, keyBlobLength, (ubyte*)"", 0, &asymKey)))
                {
                    if (ERR_PKCS8_ENCRYPTED_KEY == status)
                    {
                        if (OK > (status = DIGI_CALLOC((void**)&pw, 1, MAX_PASSWORD_SIZE)))
                        {
                            goto exit1;
                        }

                    /* Invoke the password callback. The callback will take care of casting the callback information
                     * into the appropriate type. Upon success the password should be placed in the buffer and
                     * the function should output the length of the password as well. If the operation failed then
                     * the output length should be 0 and the status should indicate the type of error that occured.
                     */
                        status = getPassword(pw, MAX_PASSWORD_SIZE, &pwLen);
                    }
                    if ( (OK != status) || (0 >= pwLen) )
                        goto exit1;

                    if (OK > (status = PKCS_getPKCS8KeyEx(MOC_HW(hwAccelCtx) pKeyBlob, keyBlobLength, pw, pwLen, &asymKey)))
                        goto exit1;
                }
            }

            if (OK > (status = KEYBLOB_makeKeyBlobEx(&asymKey, &certDesc.pKeyBlob, &certDesc.keyBlobLength)))
            {
                goto exit1;
            }

            /* Load key and certificate */
            if (OK > (status = CERT_STORE_addIdentityWithCertificateChain(
                *pCertStore, &certificate, 1, certDesc.pKeyBlob, certDesc.keyBlobLength)))
            {
                goto exit1;
            }
        }

        if (NULL == g_TapClientConfigInfo.pRootCerts)
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }

        /* Read the CA Cert */
        if (OK > (status = DIGICERT_readFile(g_TapClientConfigInfo.pRootCerts->fileName,
                                           &CACert, &CACertLength)))
        {
            goto exit1;
        }

        /* Load CA Cert */
        if (OK > (status = CERT_STORE_addTrustPoint(*pCertStore, CACert, CACertLength)))
        {
            goto exit1;
        }

exit1:

        CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

    }

exit:
    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

    if (pContents)
    {
        FREE(pContents);
    }

    if (certDesc.pCertificate)
    {
        FREE(certDesc.pCertificate);
    }

    if (certDesc.pKeyBlob)
    {
        FREE(certDesc.pKeyBlob);
    }

    if(CACert)
    {
         FREE(CACert);
    }

    if (pw)
    {
        DIGI_MEMSET(pw, 0, pwLen);
        DIGI_FREE ((void**)&pw);
    }


    if (pKeyBlob)
    {
        DIGI_FREE ((void**)&pKeyBlob);
    }


    return status;
}

static MSTATUS
DIGICERT_TAP_EXTERN_InitializeTapContext()
{
    MSTATUS status = OK;
    TAP_ConfigInfoList configInfoList = { 0, };
    TAP_ErrorContext *pErrContext = NULL;
    char *pTapConfigFile = NULL;
    char *pTapProviderString = NULL;
    ubyte tapProvider;
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
    TAP_ConnectionInfo connInfo = { 0 };
    char *pTapServer = NULL;
    char *pTapServerPort = NULL;
    char *pTapcConfig = NULL;
    TAP_Buffer tapCConfigBuffer = { 0 };
#endif

    if (OK > (status = DIGI_CALLOC((void **)&pTapProviderString, 1, MAX_NAME_LENGTH)))
    {
        printf("Failed to allocate memory, status = %d", status);
        goto exit;
    }

    if (OK > (status = getENVVariables(tap_provider, &pTapProviderString)))
    {
        status = ERR_GENERAL;
        goto exit;
    }

    if (OK > (status = getTapProvider(pTapProviderString, &tapProvider)))
    {
        goto exit;
    }

#ifndef __ENABLE_DIGICERT_TAP_REMOTE__
    status = DIGI_CALLOC((void **)&(configInfoList.pConfig), 1,
			sizeof(TAP_ConfigInfo));
    if (OK != status)
    {
        printf("Failed to allocate memory, status = %d", status);
        goto exit;
    }

    if (OK > (status = DIGI_CALLOC((void **)&pTapConfigFile, 1, MAX_NAME_LENGTH)))
    {
        printf("Failed to allocate memory, status = %d", status);
        goto exit;
    }

    if (OK > getENVVariables(tap_config, &pTapConfigFile))
    {
        printf("TAP config file incorrect;");
        status = ERR_GENERAL;
        goto exit;
    }

    status = TAP_readConfigFile(pTapConfigFile,
				&configInfoList.pConfig[0].configInfo, 0);
    if (OK != status)
    {
        printf("Failed to read config file, status = %d", status);
        goto exit;
    }

    configInfoList.count = 1;
    configInfoList.pConfig[0].provider = tapProvider;

    status = TAP_init(&configInfoList, pErrContext);
    if (OK != status)
    {
        printf("TAP_init : %d", status);
        goto exit;
    }

    status = TAP_getModuleList(NULL, tapProvider, NULL,
                               &g_moduleList, pErrContext);
#else

    if (OK > (status = DIGI_CALLOC((void **)&pTapcConfig, 1, MAX_NAME_LENGTH)))
    {
        printf("Failed to allocate memory, status = %d", status);
        goto exit;
    }

    if (OK > (status = getENVVariables(tap_client_config, &pTapcConfig)))
    {
        status = ERR_GENERAL;
        goto exit;
    }

    if (OK > (status = DIGICERT_readFile(pTapcConfig, (ubyte **)&(tapCConfigBuffer.pBuffer),
                                       &(tapCConfigBuffer.bufferLen))))
    {
        goto exit;
    }

    if (OK > (status = loadCertStore(&g_pCertStore, (ubyte *)pTapcConfig)))
    {
        goto exit;
    }

    if (OK > (status = TAP_initEx(&tapCConfigBuffer, g_pCertStore)))
    {
        printf("TAP_initEx : %d", status);
        goto exit;
    }

    if (OK > (status = DIGI_CALLOC((void **)&pTapServer, 1, MAX_NAME_LENGTH)))
    {
        printf("Failed to allocate memory, status = %d", status);
        goto exit;
    }

    if (OK > (status = DIGI_CALLOC((void **)&pTapServerPort, 1, MAX_NAME_LENGTH)))
    {
        printf("Failed to allocate memory, status = %d", status);
        goto exit;
    }

    if (OK > getENVVariables(tap_server_name, &pTapServer))
    {
        printf("TAP servername incorrect;");
        status = ERR_GENERAL;
        goto exit;
    }

    if (OK > getENVVariables(tap_server_port, &pTapServerPort))
    {
        printf("TAP server port incorrect incorrect;");
        status = ERR_GENERAL;
        goto exit;
    }

    connInfo.serverName.bufferLen = DIGI_STRLEN((sbyte *)pTapServer)+1;
    status = DIGI_CALLOC ((void **)&(connInfo.serverName.pBuffer), 1, connInfo.serverName.bufferLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY ((void *)(connInfo.serverName.pBuffer), (void *)pTapServer, DIGI_STRLEN((sbyte *)pTapServer));
    if (OK != status)
        goto exit;

    connInfo.serverPort = DIGI_ATOL (pTapServerPort, NULL);

    status = TAP_getModuleList(&connInfo, tapProvider, NULL,
                               &g_moduleList, pErrContext);
#endif
    if (OK != status)
    {
        printf("TAP_getModuleList : %d \n", status);
        goto exit;
    }
    if (0 == g_moduleList.numModules)
    {
        printf("No TAP modules found\n");
        goto exit;
    }

    /* For local TAP, parse the config file and get the Entity Credentials */
#if (!defined(__ENABLE_DIGICERT_TAP_REMOTE__))
    status = TAP_getModuleCredentials(&(g_moduleList.pModuleList[0]),
                                      pTapConfigFile, 0,
                                      &g_pTapEntityCred,
                                      pErrContext);

    if (OK != status)
    {
        printf("Failed to get credentials from Credential configuration file %d\n", status);
        goto exit;
    }
#else
    /* The module ID represents the number of TAP providers loaded. TAP extern
     * always loads in a single provider so hardcode the module ID to 1.
     */
    g_moduleList.pModuleList[0].moduleId = 1;
#endif

    /* Free config info */
    if (NULL != configInfoList.pConfig)
    {
        status = TAP_UTILS_freeConfigInfoList(&configInfoList);
        if (OK != status)
            printf("TAP_UTILS_freeConfigInfoList : %d\n", status);
    }

exit:
    if (pTapConfigFile)
        FREE(pTapConfigFile);

    if (pTapProviderString)
        FREE(pTapProviderString);

#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
    if (pTapServer)
        FREE((void *)pTapServer);

    if (pTapServerPort)
        FREE((void *)pTapServerPort);

    if (pTapcConfig)
        FREE(pTapcConfig);

    if((void **)&(connInfo.serverName.pBuffer))
        FREE((void *)connInfo.serverName.pBuffer);

    if(NULL != tapCConfigBuffer.pBuffer)
       DIGI_FREE ((void**)&(tapCConfigBuffer.pBuffer));

#endif

    return status;
}

extern sbyte4
DIGICERT_TAP_EXTERN_getTapContext(TAP_Context **ppTapContext,
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
        if (g_pTapContext == NULL)
        {
            /* Initialize context on first module */
            status = TAP_initContext(&(g_moduleList.pModuleList[0]),
                                     g_pTapEntityCred,
                                     NULL, &g_pTapContext, pErrContext);
            if (OK != status)
            {
                printf("TAP_initContext : %d\n", status);
                goto exit;
            }
        }

        *ppTapContext = g_pTapContext;
        *ppTapEntityCred = g_pTapEntityCred;
        *ppTapKeyCred    = g_pTapKeyCred;
    }
    else
    {
        /* Do NOT free the context. This application uses a global TAP Context */
    }

exit:
    return status;
}

extern sbyte4
DIGICERT_TAPExternInit(void **ppFuncPtrGetTapContext)
{
    MSTATUS status = OK;

    if (!g_isTAPInitialized)
    {
        if (OK > (status = DIGICERT_TAP_EXTERN_InitializeTapContext()))
            goto exit;
    }

    *ppFuncPtrGetTapContext = (void *)&DIGICERT_TAP_EXTERN_getTapContext;

    g_isTAPInitialized = 1;

exit:
    return status;
}

extern sbyte4
DIGICERT_TAPExternDeinit(void **ppFuncPtrGetTapContext)
{
    MSTATUS status = OK;
    TAP_ErrorContext *pErrContext = NULL;

    if (g_isTAPInitialized)
    {
        if (g_pTapContext != NULL)
        {
            TAP_uninitContext(&g_pTapContext, pErrContext);
            g_pTapContext = NULL;
        }

        status = TAP_uninit(pErrContext);
        *ppFuncPtrGetTapContext = NULL;
    }

    if (g_pCertStore)
    {
        CERT_STORE_releaseStore(&g_pCertStore);
    }

#ifdef __ENABLE_DIGICERT_TAP_REMOTE__

    if (OK != (status = TAP_CONF_COMMON_freeCertFilenameBuffers((TAP_OPERATIONAL_INFO *) &g_TapClientConfigInfo)))
    {
       printf("Error %d freeing certificate filename buffers\n", (int)status);
    }

#endif

    if (g_pTapEntityCred)
    {
      TAP_UTILS_clearEntityCredentialList(g_pTapEntityCred);
      DIGI_FREE((void **)&g_pTapEntityCred);
    }

     if (g_pTapKeyCred)
    {
      TAP_UTILS_clearCredentialList(g_pTapKeyCred);
      DIGI_FREE((void **)&g_pTapKeyCred);
    }

    if (g_moduleList.pModuleList)
    {
        status = TAP_freeModuleList(&g_moduleList);
        if (OK != status)
            printf("TAP_freeModuleList : %d\n", status);
    }

    return status;
}
#endif
