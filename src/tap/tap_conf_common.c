/*
 * tap_conf_common.c
 *
 * Trust Anchor Platform Common Configuration functions
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

#ifndef __RTOS_FREERTOS__
#include <sys/types.h>
#include <sys/stat.h>
#ifndef __RTOS_WIN32__
#include <unistd.h>
#endif
#include <fcntl.h>
#if defined(__LINUX_RTOS__)
#include <signal.h>
#endif
#endif

#include "../common/moptions.h"

#ifdef __ENABLE_DIGICERT_TAP__
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mprintf.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/vlong.h"
#include "../common/random.h"
#include "../common/prime.h"
#include "../common/debug_console.h"
#include "../common/memory_debug.h"
#include "../common/moc_config.h"
#include "../common/sizedbuffer.h"

#include "../crypto/pubcrypto.h"

#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto/aes.h"
#include "../common/base64.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/cert_store.h"
#include "../crypto/pkcs8.h"

#include "tap_serialize.h"
#include "tap_remote.h"
#include "tap_conf_common.h"
#include "tap_serialize_remote.h"

#ifdef __RTOS_WIN32__
#include "tap_utils.h"
#endif

static ubyte gClientConfigFileParsed = 0;

MSTATUS TAP_CONF_COMMON_freeModuleConfigFileInfo(
        TAP_MODULE_CONFIG_FILE_INFO **ppModuleConfigFileInfo)
{
    MSTATUS status = OK;
    TAP_MODULE_CONFIG_FILE_INFO *pModuleConfigFileInfo;
    TAP_MODULE_CONFIG_FILE_INFO *pNextModuleConfigFileInfo;

    if ((NULL == ppModuleConfigFileInfo) ||
        (NULL == *ppModuleConfigFileInfo))
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

    pModuleConfigFileInfo = *ppModuleConfigFileInfo;
    while (pModuleConfigFileInfo)
    {
        pNextModuleConfigFileInfo = pModuleConfigFileInfo->pNext;

        if (NULL != pModuleConfigFileInfo->name.pBuffer)
            DIGI_FREE((void **)&pModuleConfigFileInfo->name.pBuffer);

        DIGI_FREE((void **)&pModuleConfigFileInfo);

        pModuleConfigFileInfo = pNextModuleConfigFileInfo;
    }
    *ppModuleConfigFileInfo = NULL;

exit:
    return status;
}

#ifndef __ENABLE_TAP_MIN_SIZE__
MSTATUS
TAP_CONF_COMMON_freeCertStore(TAP_OPERATIONAL_INFO *pTapCert)
{
    MSTATUS status = OK;

    if (NULL != pTapCert->pSslCertStore)
    {
        CERT_STORE_releaseStore(&pTapCert->pSslCertStore);
        pTapCert->pSslCertStore = NULL;
    }

    return status;
}
#endif

MSTATUS
TAP_CONF_COMMON_freeCertFilenameBuffers(TAP_OPERATIONAL_INFO *pTapCert)
{
    MSTATUS status = OK;
    TAP_ROOT_CERT_INFO *pRootCertNode = NULL;

    if(pTapCert->certificateFileName)
    {
        DIGI_FREE((void **)&pTapCert->certificateFileName);
    }

    if(pTapCert->certificateKeyFileName)
    {
        DIGI_FREE((void **)&pTapCert->certificateKeyFileName);
    }

    if (pTapCert->pRootCerts)
    {
        for (pRootCertNode = pTapCert->pRootCerts; pRootCertNode;
                pRootCertNode = pRootCertNode->next)
        {
            if(pRootCertNode->fileName)
            {
                DIGI_FREE((void **)&pRootCertNode->fileName);
            }
            if (pRootCertNode->certData)
            {
                DIGI_FREE((void **)&pRootCertNode->certData);
            }
        }
        DIGI_FREE((void **)&pTapCert->pRootCerts);
    }

    if (pTapCert->pServerName)
        DIGI_FREE((void **)&pTapCert->pServerName);

    return status;
}

#ifndef __ENABLE_TAP_MIN_SIZE__
MSTATUS
TAP_CONF_COMMON_loadCertificateAndKey(const char *certificateFileName,
        const char *certificateKeyFileName,
        certStorePtr pSslCertStore)
{
    MSTATUS status = OK;
    certDescriptor retCertDescr = {0};
    SizedBuffer certificate[1];
    ubyte *keyBlob = NULL;
    ubyte4 keyBlobLength = 0;

    if (0 > (status = DIGICERT_readFile(certificateFileName,
                                      &retCertDescr.pCertificate,
                                      &retCertDescr.certLength)))
        goto exit;

    if (0 > (status = DIGICERT_readFile(certificateKeyFileName,
                             &keyBlob,
                             &keyBlobLength)))
        goto exit;

    /* Try PKCS1 format first */
    if (OK != (status = CA_MGMT_convertKeyPEM(keyBlob, keyBlobLength,
        &retCertDescr.pKeyBlob, &retCertDescr.keyBlobLength)))
    {
        if (OK != (status = PKCS8_decodePrivateKeyPEM(keyBlob, keyBlobLength,
                        &retCertDescr.pKeyBlob, &retCertDescr.keyBlobLength)))
        {
            goto exit;
        }
    }

    certificate[0].data = retCertDescr.pCertificate;
    certificate[0].length = retCertDescr.certLength;

    if (OK > (status = CERT_STORE_addIdentityWithCertificateChain(
                    pSslCertStore, certificate, 1,
                    retCertDescr.pKeyBlob, retCertDescr.keyBlobLength)))
        goto exit;

exit:
    if (retCertDescr.pKeyBlob)
        FREE(retCertDescr.pKeyBlob);

    if(retCertDescr.pCertificate)
        DIGICERT_freeReadFile(&retCertDescr.pCertificate);

    if(keyBlob)
        DIGICERT_freeReadFile(&keyBlob);

    return status;
}

MSTATUS
TAP_CONF_COMMON_setCertStore(TAP_OPERATIONAL_INFO *pTapModInfo)
{
    MSTATUS         status = OK;
    TAP_ROOT_CERT_INFO *pRootCertNode = NULL;

    /* Initialize Cert Store */
    if (OK != (status = CERT_STORE_createStore(&pTapModInfo->pSslCertStore)))
        goto exit;

    if (pTapModInfo->pRootCerts)
    {
        /* Populate cert store with root certificates */
        for (pRootCertNode = pTapModInfo->pRootCerts; pRootCertNode;
                pRootCertNode = pRootCertNode->next)
        {
            pRootCertNode->certData = NULL;
            pRootCertNode->certLength = 0;

            /* Read root certs */
            if (OK > (status = DIGICERT_readFile(pRootCertNode->fileName,
                            &pRootCertNode->certData,
                            &pRootCertNode->certLength)))
                continue;

            /* Add root certs as trust points */
            if (OK > (status = CERT_STORE_addTrustPoint(pTapModInfo->pSslCertStore,
                            pRootCertNode->certData,
                            pRootCertNode->certLength)))
                goto exit;
        }
    }

exit:
    for (pRootCertNode = pTapModInfo->pRootCerts; pRootCertNode;
            pRootCertNode = pRootCertNode->next)
    {
        if (pRootCertNode->certData)
            DIGICERT_freeReadFile(&pRootCertNode->certData);
        pRootCertNode->certData = NULL;
    }

    return status;
}
#endif

MSTATUS
TAP_CONF_COMMON_ParseStrValue(ubyte* line, ubyte4 bytesLeft, void* arg, ubyte4* bytesUsed)
{
    MSTATUS status;
    ubyte4  offset = 0, i, sLen;
    TAP_PARSE_PARMS *pTapParseParms = (TAP_PARSE_PARMS *)arg;
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
        DB_PRINT("ParseStrVal: Error allocating %d bytes for string value\n", sLen);
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

MSTATUS
TAP_CONF_COMMON_ParseIntValue(ubyte* line, ubyte4 bytesLeft, void* arg, ubyte4* bytesUsed)
{
    MSTATUS status;
    ubyte4  offset = 0, i, sLen;
    TAP_PARSE_PARMS *pTapParseParms = (TAP_PARSE_PARMS *)arg;
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
        DB_PRINT("ParseIntVal: Error allocating %d bytes for integer value\n", sLen);
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

MSTATUS
TAP_CONF_COMMON_ParseRootCertificateFileLine(ubyte* line, ubyte4 bytesLeft, void* arg, ubyte4* bytesUsed)
{
    MSTATUS status;
    ubyte4  offset = 0, i, sLen;
    char *rootCertificateFileName = NULL;
    TAP_PARSE_PARMS *pTapParseParms = (TAP_PARSE_PARMS *)arg;
    TAP_ROOT_CERT_INFO *pRootCertNode;

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
        DB_PRINT("ParseRootCertificateFileLine: Error allocating memory (%d) for a rootCertificateFileName string\n", sLen);
    }
    else
    {
        DIGI_MEMCPY(rootCertificateFileName, line+offset, sLen-1);
        rootCertificateFileName[sLen-1] = 0;

        /* Allocate Root Certificate File node */
        if (OK != (status = DIGI_MALLOC((void **)&pRootCertNode, sizeof(TAP_ROOT_CERT_INFO))))
        {
        	goto exit;
        }

        DIGI_MEMSET((ubyte *)pRootCertNode, 0, sizeof(TAP_ROOT_CERT_INFO));

        /* Add new Certificate to top of the list */
        pRootCertNode->next = *pTapParseParms->u.ppRootCerts;
        pRootCertNode->fileName = rootCertificateFileName; rootCertificateFileName = NULL;

        *pTapParseParms->u.ppRootCerts = pRootCertNode; pRootCertNode = NULL;

        /* Tell the parser we've eaten the rest of the line */
        *bytesUsed = CONFIG_nextLine(line, bytesLeft);
    }

exit:

    if (NULL != rootCertificateFileName)
    {
        (void) DIGI_FREE((void **) &rootCertificateFileName);
    }

    /* pRootCertNode allocated last, no need to free on error */
    return status;
}

MSTATUS
TAP_CONF_COMMON_ParseModuleConfigFileLine(ubyte* line, ubyte4 bytesLeft, void* arg,
    ubyte4* bytesUsed)
{
    MSTATUS status;
    ubyte4  offset = 0, i, sLen;
    char *pModuleConfigFileName = NULL;
    TAP_PARSE_PARMS *pTapParseParms = (TAP_PARSE_PARMS *)arg;
    TAP_MODULE_CONFIG_FILE_INFO *pModuleConfigFileNode;

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

    /* Config file name is the string between offset and i */
    /* it needs to be null terminated so we will make a copy */
    /* i >= offset */
    sLen =  i + 2 - offset;
    status = DIGI_MALLOC((void **)&pModuleConfigFileName, sLen);
    if (OK != status)
    {
        DB_PRINT("ParseModuleConfigFileLine: Error allocating memory (%d) for config file name string\n", sLen);
    }
    else
    {
        DIGI_MEMCPY(pModuleConfigFileName, line+offset, sLen-1);
        pModuleConfigFileName[sLen-1] = 0;

        /* Allocate Module Config File node */
        if (OK != (status = DIGI_MALLOC((void **)&pModuleConfigFileNode, sizeof(*pModuleConfigFileNode))))
        {
        	goto exit;
        }

        DIGI_MEMSET((ubyte *)pModuleConfigFileNode, 0, sizeof(*pModuleConfigFileNode));

        /* Add new config file name node to top of the list */
        pModuleConfigFileNode->pNext = *(pTapParseParms->u.ppModuleConfigFileList);
        *(pTapParseParms->u.ppModuleConfigFileList) = pModuleConfigFileNode;

        pModuleConfigFileNode->name.pBuffer = (ubyte *)pModuleConfigFileName;
        pModuleConfigFileNode->name.bufferLen = sLen;

        /* Tell the parser we've eaten the rest of the line */
        *bytesUsed = CONFIG_nextLine(line, bytesLeft);
    }

exit:

    return status;
}

/**
 * @private
 * @internal
 *
 * @ingroup tapc_functions
 *
 * @brief  Function to parse configuration file
 * @details Parses the TAP communications configuration file to get
 * 		SSL configuration and other operational information
 *
 * @return OK on success
 *
 */
MOC_EXTERN MSTATUS
parseCommConfiguration(TAP_OPERATIONAL_INFO *pTapClientInfo, const char *fullPath)
{
    MSTATUS status = OK;
    ubyte *pConfig = NULL;
    ubyte4 configLen;
    static CONFIG_ConfigItem configItems[] = {
        {(const sbyte *)"serverport", 0, 0},
        {(const sbyte *)"enablemutualauthentication", 0, 0},
        {(const sbyte *)"enableunsecurecomms", 0, 0},
        {(const sbyte *)"sslcertificatefile", 0, 0},
        {(const sbyte *)"sslcertificatekeyfile", 0, 0},
        {(const sbyte *)"sslrootcertificatefile", 0, 0},
        {(const sbyte *)"servername", 0, 0},
        {NULL, 0, 0}
    };
    TAP_PARSE_PARMS parseParms[sizeof(configItems)/sizeof(CONFIG_ConfigItem)];
    TAP_PARSE_PARMS *pParseParms;
#ifdef __RTOS_WIN32__
    char *pTapClientConfigFile = NULL;
#endif

    if(!pTapClientInfo->isNonFsMode)
    {
        /*
         * In case FS is present, application could choose
         * to parse the conf file itself and pass the buffer.
         * We read the buffer if it is not empty.
         */
        if ((pTapClientInfo->configData.pBuffer != NULL) &&
            (pTapClientInfo->configData.bufferLen > 0))
        {
            pConfig     = pTapClientInfo->configData.pBuffer;
            configLen   = pTapClientInfo->configData.bufferLen;
        }
        else
        {
            if (fullPath)
            {
                status = DIGICERT_readFile(fullPath, &pConfig, &configLen);
            }
            else
            {
                /* First try TAP_CLIENT_CONFIG_FILE, if not found look for one in
                   local directory */
#ifdef __RTOS_WIN32__
                status = TAP_UTILS_getWinConfigFilePath(&pTapClientConfigFile, TAP_CLIENT_CONFIG_FILE);
                if (OK != status)
                {
                    goto exit;
                }
                status = DIGICERT_readFile(pTapClientConfigFile, &pConfig, &configLen);
#else
                status = DIGICERT_readFile(TAP_CLIENT_CONFIG_FILE, &pConfig, &configLen);
#endif
                if (OK != status)
                {
                    status = DIGICERT_readFile(TAP_CLIENT_CONFIG_FILE_LOCAL,
                                                &pConfig, &configLen);
                }
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

        configItems[0].callback = TAP_CONF_COMMON_ParseIntValue;
        pParseParms->u.pIntValue = &pTapClientInfo->serverPort;
        pParseParms->name = (char *)configItems[0].key;
        configItems[0].callback_arg = pParseParms;

        pParseParms++;

        configItems[1].callback = TAP_CONF_COMMON_ParseIntValue;
        pParseParms->u.pIntValue = &pTapClientInfo->enableMutualAuth;
        pParseParms->name = (char *)configItems[1].key;
        configItems[1].callback_arg = pParseParms;

        pParseParms++;

        configItems[2].callback = TAP_CONF_COMMON_ParseIntValue;
        pParseParms->u.pIntValue = &pTapClientInfo->enableunsecurecomms;
        pParseParms->name = (char *)configItems[2].key;
        configItems[2].callback_arg = pParseParms;

        pParseParms++;

        configItems[3].callback = TAP_CONF_COMMON_ParseStrValue;
        pParseParms->u.ppStrValue = (ubyte **)&pTapClientInfo->certificateFileName;
        pParseParms->name = (char *)configItems[3].key;
        configItems[3].callback_arg = pParseParms;

        pParseParms++;

        configItems[4].callback = TAP_CONF_COMMON_ParseStrValue;
        pParseParms->u.ppStrValue = (ubyte **)&pTapClientInfo->certificateKeyFileName;
        pParseParms->name = (char *)configItems[4].key;
        configItems[4].callback_arg = pParseParms;

        pParseParms++;

        configItems[5].callback = TAP_CONF_COMMON_ParseRootCertificateFileLine;
        pParseParms->name = (char *)configItems[5].key;
        pParseParms->u.ppRootCerts = &pTapClientInfo->pRootCerts;
        configItems[5].callback_arg = pParseParms;

        pParseParms++;

        configItems[6].callback = TAP_CONF_COMMON_ParseStrValue;
        pParseParms->name = (char *)configItems[6].key;
        pParseParms->u.ppStrValue = (ubyte **)&pTapClientInfo->pServerName;
        configItems[6].callback_arg = pParseParms;

        status = CONFIG_parseData(pConfig, configLen, configItems);

        if( NULL != pConfig)
        {
            DIGICERT_freeReadFile(&pConfig);
            if ((pTapClientInfo->configData.pBuffer != NULL) &&
                (pTapClientInfo->configData.bufferLen > 0))
            {
                pTapClientInfo->configData.pBuffer   = NULL;
                pTapClientInfo->configData.bufferLen = 0;
            }
        }

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

    return status;
}

#endif /* __ENABLE_DIGICERT_TAP__ */
