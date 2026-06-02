/*
 * mcp_example.c
 *
 * Sample implementation of an MCP service
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
 */

#include "../common/moptions.h"

#if defined(__ENABLE_DIGICERT_EXAMPLES__) || defined(__ENABLE_DIGICERT_BIN_EXAMPLES__)
#if defined(__ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__) && defined(__ENABLE_DIGICERT_MCP_EXAMPLE__)

#include <string.h>
#include <stdio.h>
#include <ctype.h>
#ifdef __RTOS_LINUX__
#include <signal.h>
#endif
#ifndef __RTOS_WINCE__
#include <errno.h>
#endif

#ifdef __PLATFORM_HAS_GETOPT__
#ifdef __OSE_RTOS__
#include <getopt.h>
#include <string.h>
#endif
#include <unistd.h>
#include <stdlib.h>
#endif

#if defined(__WIN32_RTOS__) || defined(__RTOS_WINCE__)
  #define WIN32_LEAN_AND_MEAN
  #ifndef _WIN32_WINNT
  #define _WIN32_WINNT 0x0400
  #endif

  #include <windows.h>
  #include <winbase.h>
  #include <winsock2.h>
  #include <Ws2tcpip.h>
  #include <iphlpapi.h>
  #if defined(_DEBUG) && !defined(__RTOS_WINCE__)
  #include <crtdbg.h>
  #endif
#elif defined(__LINUX_RTOS__) || defined(__OPENBSD_RTOS__) || defined(__QNX_RTOS__) || defined(__CYGWIN_RTOS__) || defined(__ANDROID_RTOS__) || defined(__OSX_RTOS__)
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <netdb.h>
  #include <arpa/inet.h>
#elif defined(__VXWORKS_RTOS__)
  #include <vxWorks.h>
  #include <sockLib.h>
  #include <inetLib.h>
#elif defined(__OSE_RTOS__)
  #include <inet.h>
#elif defined(__INTEGRITY_RTOS__)
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <netdb.h>
  #include <arpa/inet.h>
#endif
#ifdef __RTOS_LINUX__
  #include <time.h>
#endif

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mocana.h"
#include "../common/debug_console.h"
#include "../common/mstdlib.h"
#include "../common/mudp.h"
#include "../common/vlong.h"
#include "../common/random.h"
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../common/tree.h"
#include "../common/hash_table.h"
#include "../common/property.h"
#include "../common/mfmgmt.h"
#include "../crypto/crypto.h"
#include "../crypto/pubcrypto.h"
#include "../common/base64.h"
#include "../crypto/ca_mgmt.h"
#include "../common/sizedbuffer.h"
#include "../crypto/cert_store.h"
#include "../crypto/hw_accel.h"
#ifdef __ENABLE_DIGICERT_MEM_PART__
#include "../common/mem_part.h"
#endif
#include "../asn1/oiddefs.h"
#include "../asn1/parseasn1.h"
#include "../asn1/parsecert.h"
#ifdef __ENABLE_DIGICERT_PFKEY__
#include "../pfkey/pfkey.h"
#endif
#include "../ipsec/ipsec.h"
#include "../ipsec/ipsec_defs.h"
#include "../ipsec/ipsecconf.h"
#include "../ipsec/ipseckey.h"
#include "../ipsec/script.h"
#include "../ike/ike.h"
#include "../ike/ike_defs.h"
#include "../ike/ike_event.h"
#include "../ike/ike_utils.h"
#include "../ike/ike_status.h"
#include "../ike/ike_state.h"
#include "../ike/ikesa.h"
#include "../ike/ikekey.h"
#include "../mcp/config_keys.h"
#include "../mcp/ike_server.h"
#if defined(__VXWORKS_RTOS__)
#include "../examples/ipsec/vxworks7/vxworks_ipsec.h"
#else
#include "../mcp/win32/event_log.h"
#endif

#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
#include "../data_protection/file_protect.h"
#endif

#include "if_mapping.h"

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PFKEY__
extern sbyte4   PFKEY_EXAMPLE_main(void);
#else
extern sbyte4   IPSECKEY_EXAMPLE_main(void);
#endif
#ifdef MOCANA_IKEADM_PORT
extern sbyte4   IKEADM_EXAMPLE_main(void);
#endif
#ifdef __ENABLE_DIGICERT_DUAL_MODE__
extern MSTATUS create_ifmap(sbyte *addrTransFile);
extern MSTATUS multicast_close_ipv4(void);
#endif

/*------------------------------------------------------------------*/

static intBoolean mIsHexPSK = TRUE;    /* hexadecimal */
static sbyte *mPSK  = (sbyte *)"6578616d706c6520707265736861726564206b6579"; /* pragma: allowlist secret */
static sbyte4 mPSKlen = 42;

/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_GDOI_SERVER__)
/* KDC */
static sbyte *DEFAULT_KEYSYNC_FILE = (sbyte *)"./keysync.dat";
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__)
    /* secondary KDC */
    #define DEFAULT_MODE OP_MODE_SERVER_SECONDARY
#else
    /* primary KDC */
    #define DEFAULT_MODE OP_MODE_SERVER_PRIMARY
#endif
#elif defined(__ENABLE_DIGICERT_GDOI_CLIENT__)
/* Agent */
static sbyte *DEFAULT_POLICY_FILE = (sbyte *)"./agent.policy";
#define DEFAULT_MODE OP_MODE_CLIENT
#else
#error Must define __ENABLE_DIGICERT_GDOI_SERVER__ or __ENABLE_DIGICERT_GDOI_CLIENT__
#endif


/*------------------------------------------------------------------*/

IkeServConfig m_ikeConfig = { 0 };
IkeServCtx *m_ikeCtx = NULL;
extern ubyte4 m_groupListCount;

/*------------------------------------------------------------------*/

#ifdef __RTOS_LINUX__
static void
valgrindSigHandler(int signo)
{
    m_ikeCtx->stopEventThread = TRUE;
    DIGICERT_log(MOCANA_IKE, LS_INFO, (sbyte *)"Caught signal sigusr1... deinit called");
}
#endif

#ifndef __ENABLE_DIGICERT_GDOI_SERVER__

MSTATUS
Mcp_SetAgentPolicyEx(sbyte *pFileName)
{
    MSTATUS status = OK;

    ubyte *pFileBuf = NULL;
    ubyte *pFileBuf2 = NULL;
    ubyte4 fileSize = 0;

    if (NULL == pFileName)
    {
        ERROR_PRINT(("Policy file is not specified"));
        status = ERR_IPSEC_NO_POLICY;
        goto exit;
    }

    if (OK > (status = (MSTATUS) DIGICERT_readFile((const char *)pFileName,
                                                 &pFileBuf, &fileSize)))
    {
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
        DEBUG_ERROR(DEBUG_CUSTOM, (sbyte *)"MCP: Cannot read policy file, status = ", status);
#else
        CONFIG_ERROR(kConfigKey_PolicyFile, pFileName, "Cannot read policy file");
#endif
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_MCP_TRUSTEDGE_MODE__) && defined(__ENABLE_DIGICERT_MCP_FQDN_SUPPORT__)
    MCP_setFqdnName(m_ikeConfig.fqdnMappingConfFile);
#endif

    pFileBuf[fileSize] = (ubyte)0;
    pFileBuf2 = pFileBuf;
    if (OK > (status = IPSEC_ParseScript((const sbyte*)pFileBuf2, 1, m_ikeConfig.hostIp)))   /* parse the list map config file here first*/
    {
        if (ERR_IPSEC_SCRIPT_UNKNOWN_PORT_LIST == status)
        {
            IKE_RUNTIME_ERROR("Policy configuration error; invalid port list configured", status);
        }
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
        DEBUG_ERROR(DEBUG_CUSTOM, (sbyte *)"MCP: Failed to parse policy file, status = ", status);
#else
        CONFIG_ERROR(kConfigKey_PolicyFile, pFileName, "Failed to parse policy file");
        IKE_RUNTIME_ERROR("Policy configuration error; failed to parse policy file", status);
#endif
    }
    else
    {
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
        if (OK > (status = MCP_parseGroupList((const char*)m_ikeConfig.fqdnMappingConfFile, m_ikeConfig.hostIp)))
        {
            CONFIG_ERROR(kConfigKey_FQDNMappingFile, m_ikeConfig.fqdnMappingConfFile, "Failed to parse unicast group list mapping file");
            IKE_RUNTIME_ERROR("Policy configuration error; failed to parse unicast group list mapping file", status);
        }
        else
#endif
        {
            if (OK > (status = IPSEC_ParseScript((const sbyte*)pFileBuf, 0, m_ikeConfig.hostIp)))
            {
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
                DEBUG_ERROR(DEBUG_CUSTOM, (sbyte *)"MCP: Failed to parse policy file, status = ", status);
#else
                CONFIG_ERROR(kConfigKey_PolicyFile, pFileName, "Failed to parse policy file");
#endif

            }
            else
            {
                INFO2("Policy file loaded", pFileName);
            }
        }
    }

    FREE(pFileBuf);

exit:
    return status;
} /* Mcp_SetAgentPolicyEx */

MSTATUS
Mcp_SetAgentPolicy()
{
    return Mcp_SetAgentPolicyEx(m_ikeConfig.gdoiPolicyFile);
}

#endif


/*------------------------------------------------------------------*/

void
Mcp_ClearConfig()
{
    sbyte4 i;

    for (i=0; i < m_ikeConfig.numCertsInChain; i++)
    {
        certDescriptor *descr = &m_ikeConfig.certChain[i];

        if (descr->pCertificate)
        {
            FREE(descr->pCertificate);
        }

        if (descr->pKeyBlob)
        {
            FREE(descr->pKeyBlob);
        }
    }

    for (i=0; i < m_ikeConfig.numTrustAnchor; i++)
    {
        certDescriptor *descr = &m_ikeConfig.trustAnchor[i];

        if (descr->pCertificate)
        {
            FREE(descr->pCertificate);
        }
    }

    for (i=0; i < m_ikeConfig.numSrvInstance; i++)
    {
        if (m_ikeConfig.hostIp[i])
        {
            FREE(m_ikeConfig.hostIp[i]);
        }
    }

    for (i=0; i < m_ikeConfig.numGroupMember; i++)
    {
        if (m_ikeConfig.groupMember[i])
        {
            FREE(m_ikeConfig.groupMember[i]);
        }
    }

    if (m_ikeConfig.groupMemberFile)
    {
        FREE(m_ikeConfig.groupMemberFile);
    }

    if (m_ikeConfig.gdoiPolicyFile)
    {
        FREE(m_ikeConfig.gdoiPolicyFile);
    }

#if (defined(__ENABLE_DIGICERT_DUAL_MODE__) && defined(__ENABLE_DIGICERT_MCP_TRUSTEDGE_MODE__))
    if (m_ikeConfig.translationPolicyFile)
    {
        FREE(m_ikeConfig.translationPolicyFile);
    }
#endif

#ifdef __ENABLE_DIGICERT_MULTICAST_MCP__

    for (i=0; i < m_ikeConfig.num_gdoiKeySyncFile; i++)
    {
        if (m_ikeConfig.gdoiKeySyncFile[i])
        {
            FREE(m_ikeConfig.gdoiKeySyncFile[i]);
        }
    }
#else
    if (m_ikeConfig.gdoiKeySyncFile)
    {
        FREE(m_ikeConfig.gdoiKeySyncFile);
    }
#endif

    if (m_ikeConfig.gdoiHostDnsName)
    {
        FREE(m_ikeConfig.gdoiHostDnsName);
    }

#ifdef __ENABLE_DIGICERT_NW_REDUNDANCY__
    for(i=0; i < MOC_MAX_HEARTBEAT_INTERFACES; i++)
    {
        if (m_ikeConfig.gdoiServerIp[i])
        {
            FREE(m_ikeConfig.gdoiServerIp[i]);
        }
    }
#else
    if (m_ikeConfig.gdoiServerIp)
    {
        FREE(m_ikeConfig.gdoiServerIp);
    }
#endif

#ifdef __ENABLE_DIGICERT_NW_REDUNDANCY__
    for(i=0; i < MOC_MAX_HEARTBEAT_INTERFACES; i++)
    {
        if (m_ikeConfig.gdoiSecondaryServerIp[i])
        {
            FREE(m_ikeConfig.gdoiSecondaryServerIp[i]);
        }
    }
#else
    if (m_ikeConfig.gdoiSecondaryServerIp)
    {
        FREE(m_ikeConfig.gdoiSecondaryServerIp);
    }
#endif

    if (m_ikeConfig.gdoiServerDnsName)
    {
        FREE(m_ikeConfig.gdoiServerDnsName);
    }

    if (m_ikeConfig.gdoiSecondaryServerDnsName)
    {
        FREE(m_ikeConfig.gdoiSecondaryServerDnsName);
    }

    if (m_ikeConfig.psk)
    {
        FREE(m_ikeConfig.psk);
    }

    if (m_ikeConfig.fqdnMappingConfFile)
    {
        FREE(m_ikeConfig.fqdnMappingConfFile);
    }

    if (m_ikeConfig.addrTranslationFile)
    {
        FREE(m_ikeConfig.addrTranslationFile);
    }

    if (m_ikeConfig.portListFile)
    {
        FREE(m_ikeConfig.portListFile);
    }

    DIGI_MEMSET((ubyte *)&m_ikeConfig, 0x0, sizeof(m_ikeConfig));
    return;
} /* ClearConfig */


/*------------------------------------------------------------------*/

static sbyte4 VerifyCertName(sbyte *, ubyte *, ubyte4);

static MSTATUS
callbackMalformedLine(void *pCookie, const sbyte *pMalformedLine, ubyte4 lineNum)
{
    return OK;
}

extern sbyte4
MCP_LoadConfig(const sbyte *fileName)
{
    MSTATUS status;

    ubyte *pFileBuf = NULL;
    ubyte4 fileSize = 0;

    propertyTable *pPropertyTable = NULL;
    sbyte *val = NULL;
    intBoolean isValFound;

    ubyte *data = NULL;
    ubyte4 dataLen = 0;
    sbyte4 cmpRes = -1;
    ubyte *pDerData = NULL;
    ubyte4 derDataLen = 0;
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
    DirectoryDescriptor dir = NULL;
    DirectoryEntry ent;
#endif

    char prop_name[32] = {0};
    sbyte4 i;

    if (NULL == fileName)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
    if (OK > (status = (MSTATUS) DPM_readSignedFile((const char *)fileName,
                                                 &pFileBuf, &fileSize, TRUE, DPM_CONFIG)))
#else
    if (OK > (status = (MSTATUS) DIGICERT_readFile((const char *)fileName,
                                                 &pFileBuf, &fileSize)))
#endif
    {
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
        DEBUG_ERROR(DEBUG_CUSTOM, (sbyte *)"MCP: Cannot read configuration file, status = ", status);
#else
        HANDLE_ERROR_INT("Cannot read configuration file", status);
#endif
        goto exit;
    }

    if (OK > (status = PROPERTY_newInstance(&pPropertyTable)))
    {
        goto exit;
    }

    if (OK > (status = PROPERTY_parseLines(pPropertyTable,
                                           pFileBuf, fileSize,
                                           0, policyOverwriteAlways,
                                           NULL, callbackMalformedLine)))
    {
        goto exit;
    }
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
    sbyte *pServerName = NULL;
    sbyte4 serverNameLen = 0;
    if (OK > (status = PROPERTY_findPropertyValue(pPropertyTable, (const sbyte*)
                                                  kConfigKey_TapServerName,
                                                  &val, &isValFound)))
    {
        goto exit;
    }

    if ((TRUE == isValFound) && (NULL != val))
    {
        serverNameLen = DIGI_STRLEN(val);
        status = DIGI_MALLOC((void **) &pServerName, serverNameLen + 1);
        if (OK != status) {
            goto exit;
        }

        status = DIGI_MEMCPY(pServerName, val, serverNameLen);
        if (OK != status)
        {
            if (pServerName) { DIGI_FREE((void **) &pServerName); }
            goto exit;
        }

        pServerName[serverNameLen] = '\0';
    }

    if (val) { DIGI_FREE((void **) &val); }

    if (OK > (status = PROPERTY_findPropertyValue(pPropertyTable, (const sbyte*)
                                                  kConfigKey_TapServerPort,
                                                  &val, &isValFound)))
    {
        if (pServerName) { DIGI_FREE((void **) &pServerName); }
        goto exit;
    }

    if ((TRUE == isValFound) && (NULL != val))
    {
        status = MCP_setTapServerInfo(pServerName, val);
    }
    if (pServerName) { DIGI_FREE((void **) &pServerName); }
    if (val) { DIGI_FREE((void **) &val); }
    if (OK != status)
        goto exit;
#endif
#ifdef __ENABLE_DIGICERT_MCP_TRUSTEDGE_MODE__
    if (OK > (status = PROPERTY_findPropertyValue(pPropertyTable, (const sbyte*)
                                                  kConfigKey_AuthInfo,
                                                  &val, &isValFound)))
    {
        goto exit;
    }

    if ((TRUE == isValFound) && (NULL != val))
    {
        status = MCP_parseAuthInfo (&m_ikeConfig, val, kConfigKey_CACertificateFolder,
            kConfigKey_PreSharedKey, kConfigKey_PreSharedKeyFormat);
        if (OK != status)
            goto exit;
    }
    if (val) { DIGI_FREE((void **) &val); }
#else
    /* CACertificate 0..n */
    if (OK > (status = PROPERTY_findPropertyValue(pPropertyTable, (const sbyte*)
                                                  kConfigKey_CACert,
                                                  &val, &isValFound)))
    {
        goto exit;
    }

    if ((1 == isValFound) && val && *val)
    {
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
        byteBoolean isFileEntryTypeDir;
        ubyte *pFullPath = NULL;
        ubyte4 fullPathLen = 0, certificateNameLen = 0;
        byteBoolean isValidCertificate;
        sbyte4 validExtension;

        /* Open directory ead first entry */
        status = FMGMT_getFirstFile (val, &dir, &ent);
        if (OK != status)
        {
            CONFIG_ERROR(kConfigKey_CACert, val, "Unable to open CA certificate directory");
            goto exit;
        }

        while ((FTNone != ent.type) && (m_ikeConfig.numTrustAnchor < MAX_NUM_TRUST_ANCHOR))
        {
            isValidCertificate = FALSE;
            validExtension = -1;

            /* Check if entry is a file */
            if (FTFile == ent.type)
            {
                status = MCP_getFullPath((const sbyte *)val, (const sbyte *)ent.pName, &pFullPath);
                if (OK != status)
                {
                    CONFIG_ERROR(kConfigKey_CACert, pFullPath, "Unable to read CA certificate");
                    goto exit;
                }

                fullPathLen = DIGI_STRLEN(pFullPath);

                if (OK > (status = (MSTATUS) DIGICERT_readFile((char *)pFullPath, &data, &dataLen)))
                {
                    CONFIG_ERROR(kConfigKey_CACert, pFullPath, "Unable to read CA certificate");
                    goto exit;
                }

                status = DIGI_MEMCMP(pFullPath + fullPathLen - 4, ".pem", 4, &validExtension);
                if (OK != status)
                {
                    CONFIG_ERROR(kConfigKey_CACert, pFullPath, "Error reading file in CA certificate directory");
                    goto exit;
                }

                if (0 == validExtension)
                {
                    ubyte *pDecodedData = NULL;
                    ubyte4 decodedDataLen;

                    status = CA_MGMT_decodeCertificate(data, dataLen, &pDecodedData, &decodedDataLen);
                    if (OK != status)
                    {
                        CONFIG_ERROR(kConfigKey_CACert, pFullPath, "Error reading file in CA certificate directory");
                        goto exit;
                    }

                    DIGI_FREE((void **) &data);
                    data = pDecodedData;
                    dataLen = decodedDataLen;
                    isValidCertificate = TRUE;
                }
                else
                {
                    status = DIGI_MEMCMP(pFullPath + fullPathLen - 4, ".der", 4, &validExtension);
                    if (OK != status)
                        goto exit;

                    if (0 == validExtension)
                    {
                        isValidCertificate = TRUE;
                    }
                }

                if (TRUE == isValidCertificate)
                {
                    status = DPM_verifyFile((const char *)pFullPath, TRUE, DPM_CA_CERTS);
                    if (OK != status)
                    {
                        CONFIG_ERROR(kConfigKey_CACert, pFullPath, "Cannot verify certificate file");
                        goto exit;
                    }

                    status = CA_MGMT_verifyCertDate(data, dataLen);
                    if (OK == status)
                    {
                        m_ikeConfig.trustAnchor[m_ikeConfig.numTrustAnchor].pCertificate = data;
                        m_ikeConfig.trustAnchor[m_ikeConfig.numTrustAnchor].certLength = dataLen;
                        data = NULL;
                        m_ikeConfig.numTrustAnchor++;
                    }

                }

                DIGI_FREE((void **) &pFullPath);
                DIGI_FREE((void **) &data);
            }

            status = FMGMT_getNextFile (dir, &ent);
            if (OK != status)
            {
                CONFIG_ERROR(kConfigKey_CACert, pFullPath, "Cannot get next file");
                goto exit;
            }
        }
#else
        if (OK > (status = (MSTATUS) DIGICERT_readFile((char *)val, &data, &dataLen)))
        {
            CONFIG_ERROR(kConfigKey_CACert, val, "Cannot read certificate file");
            goto exit;
        }

        cmpRes = -1;
        if (dataLen >= MOC_PEM_CERT_HEADER_LEN)
        {
            status = DIGI_MEMCMP(data, (ubyte *) MOC_PEM_CERT_HEADER, MOC_PEM_CERT_HEADER_LEN, &cmpRes);
            if (OK != status)
                goto exit;
        }

        if (0 == cmpRes)
        {
            status = CA_MGMT_decodeCertificate(data, dataLen, &pDerData, &derDataLen);
            if (OK != status)
                goto exit;

            m_ikeConfig.trustAnchor[0].pCertificate = pDerData;
            m_ikeConfig.trustAnchor[0].certLength = derDataLen;
            DIGI_FREE((void**)&data);
            pDerData = NULL;
            derDataLen = 0;
        }
        else
        {
            m_ikeConfig.trustAnchor[0].pCertificate = data;
            m_ikeConfig.trustAnchor[0].certLength = dataLen;
            data = NULL;
        }

        m_ikeConfig.numTrustAnchor++;
#endif
    }
    if (val) { DIGI_FREE((void **)&val); }

#ifndef __ENABLE_DIGICERT_DATA_PROTECTION__
    for (i = m_ikeConfig.numTrustAnchor; i < MAX_NUM_TRUST_ANCHOR; i++)
    {
        sprintf(prop_name, "%s_%d", kConfigKey_CACert, i);
        if (OK > (status = PROPERTY_findPropertyValue(pPropertyTable, (const sbyte*)
                                                      prop_name,
                                                      &val, &isValFound)))
        {
            goto exit;
        }
        if ((1 == isValFound) && val && *val)
        {
            if (OK > (status = (MSTATUS) DIGICERT_readFile((char *)val, &data, &dataLen)))
            {
                CONFIG_ERROR(prop_name, val, "Cannot read certificate file");
                goto exit;
            }
            cmpRes = -1;
            if (dataLen >= MOC_PEM_CERT_HEADER_LEN)
            {
                status = DIGI_MEMCMP(data, (ubyte *) MOC_PEM_CERT_HEADER, MOC_PEM_CERT_HEADER_LEN, &cmpRes);
                if (OK != status)
                    goto exit;
            }

            if (0 == cmpRes)
            {
                status = CA_MGMT_decodeCertificate(data, dataLen, &pDerData, &derDataLen);
                if (OK != status)
                    goto exit;
                m_ikeConfig.trustAnchor[i].pCertificate = pDerData;
                m_ikeConfig.trustAnchor[i].certLength = derDataLen;
                DIGI_FREE((void **) &data);
                pDerData = NULL;
                derDataLen = 0;
            }
            else
            {
                m_ikeConfig.trustAnchor[i].pCertificate = data;
                m_ikeConfig.trustAnchor[i].certLength = dataLen;
            }
            data = NULL;
            FREE(val); val = NULL;
            m_ikeConfig.numTrustAnchor++;
        }
        else
        {
            if (val) { FREE(val); val = NULL; }
            break;
        }
    }
#endif
#endif /* __ENABLE_DIGICERT_MCP_TRUSTEDGE_MODE__ */

    /* HostCertificate 0..n */
    if (OK > (status = PROPERTY_findPropertyValue(pPropertyTable, (const sbyte*)
                                                  kConfigKey_HostCert,
                                                  &val, &isValFound)))
    {
        goto exit;
    }

    if ((1 == isValFound) && val && *val)
    {
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
        if (OK > (status = (MSTATUS) DPM_readSignedFile((char *)val, &data, &dataLen, TRUE, DPM_CERTS)))
        {
            CONFIG_ERROR(kConfigKey_HostCert, val, "Cannot read certificate file");
            goto exit;
        }
#else
        if (OK > (status = (MSTATUS) DIGICERT_readFile((char *)val, &data, &dataLen)))
        {
            CONFIG_ERROR(kConfigKey_HostCert, val, "Cannot read certificate file");
            goto exit;
        }
#endif

        cmpRes = -1;
        if (dataLen >= MOC_PEM_CERT_HEADER_LEN)
        {
            status = DIGI_MEMCMP(data, (ubyte *) MOC_PEM_CERT_HEADER, MOC_PEM_CERT_HEADER_LEN, &cmpRes);
            if (OK != status)
                goto exit;
        }

        if (0 == cmpRes)
        {
            status = CA_MGMT_decodeCertificate(data, dataLen, &pDerData, &derDataLen);
            if (OK != status)
                goto exit;
            m_ikeConfig.certChain[0].pCertificate = pDerData;
            m_ikeConfig.certChain[0].certLength = derDataLen;
            DIGI_FREE((void **) &data);
            pDerData = NULL;
            derDataLen = 0;
        }
        else
        {
            m_ikeConfig.certChain[0].pCertificate = data;
            m_ikeConfig.certChain[0].certLength = dataLen;
        }
        data = NULL;
        m_ikeConfig.numCertsInChain++;
    }
    if (val) { FREE(val); val = NULL; }

    for (i = m_ikeConfig.numCertsInChain; i < MAX_CERTS_IN_CHAIN; i++)
    {
        sprintf(prop_name, "%s_%d", kConfigKey_HostCert, i);
        if (OK > (status = PROPERTY_findPropertyValue(pPropertyTable, (const sbyte*)
                                                      prop_name,
                                                      &val, &isValFound)))
        {
            goto exit;
        }
        if ((1 == isValFound) && val && *val)
        {
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
            if (OK > (status = (MSTATUS) DPM_readSignedFile((char *)val, &data, &dataLen, TRUE, DPM_CERTS)))
            {
                CONFIG_ERROR(prop_name, val, "Cannot read certificate file");
                goto exit;
            }
#else
            if (OK > (status = (MSTATUS) DIGICERT_readFile((char *)val, &data, &dataLen)))
            {
                CONFIG_ERROR(prop_name, val, "Cannot read certificate file");
                goto exit;
            }
#endif
            /* asume DER */
            m_ikeConfig.certChain[i].pCertificate = data;
            m_ikeConfig.certChain[i].certLength = dataLen;
            data = NULL;
            FREE(val); val = NULL;
            m_ikeConfig.numCertsInChain++;
        }
        else
        {
            if (val) { FREE(val); val = NULL; }
            break;
        }
    }

    if (0 < m_ikeConfig.numCertsInChain)
    {
        /* HostKey */
        if (OK > (status = PROPERTY_findPropertyValue(pPropertyTable, (const sbyte*)
                                                      kConfigKey_HostKey,
                                                      &val, &isValFound)))
        {
            goto exit;
        }
        if ((1 == isValFound) && val && *val)
        {
            ubyte *keyData = NULL;
            ubyte4 keyDataLen = 0;

#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
            if (OK > (status = (MSTATUS) DIGICERT_readFileEx((char *)val, &data, &dataLen, TRUE)))
            {
                CONFIG_ERROR(kConfigKey_HostKey, val, "Cannot read key file");
                goto exit;
            }
#else
            if (OK > (status = (MSTATUS) DIGICERT_readFile((char *)val, &data, &dataLen)))
            {
                CONFIG_ERROR(kConfigKey_HostKey, val, "Cannot read key file");
                goto exit;
            }
#endif

            AsymmetricKey asymKey;
            status = CRYPTO_initAsymmetricKey(&asymKey);
            if (OK != status)
                goto exit;

            status = CRYPTO_deserializeAsymKey(data, dataLen, NULL, &asymKey);
            if (OK != status)
            {
                CONFIG_ERROR(kConfigKey_HostKey, val, "Failed to convert DER key file");
                goto exit;
            }

            status = CRYPTO_serializeAsymKey(&asymKey, mocanaBlobVersion2, &keyData, &keyDataLen);
            if (OK != status)
            {
                CONFIG_ERROR(kConfigKey_HostKey, val, "Failed to convert DER key file");
                goto exit;
            }
            CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

            FREE(data); data = NULL;
            m_ikeConfig.certChain[0].pKeyBlob = keyData;
            m_ikeConfig.certChain[0].keyBlobLength = keyDataLen;
        }
        if (val) { FREE(val); val = NULL; }

        /* HostDNSName */
        if (OK > (status = PROPERTY_findPropertyValue(pPropertyTable, (const sbyte*)
                                                      kConfigKey_HostDNSName,
                                                      &val, &isValFound)))
        {
            goto exit;
        }
        if ((1 == isValFound) && val && *val)
        {
            if (OK > (status = VerifyCertName(val,
                                              m_ikeConfig.certChain[0].pCertificate,
                                              m_ikeConfig.certChain[0].certLength)))
            {
                goto exit;
            }
            m_ikeConfig.gdoiHostDnsName = val; val = NULL;
        }
        if (val) { FREE(val); val = NULL; }
    }

    /* HostIPAddress 0..n */
    if (OK > (status = PROPERTY_findPropertyValue(pPropertyTable, (const sbyte*)
                                                  kConfigKey_HostIPAddress,
                                                  &val, &isValFound)))
    {
        goto exit;
    }
    if ((1 == isValFound) && val && *val)
    {
        m_ikeConfig.hostIp[0] = val; val = NULL;
        m_ikeConfig.numSrvInstance++;
    }
    if (val) { FREE(val); val = NULL; }

    for (i = m_ikeConfig.numSrvInstance; i < MAX_NUM_SERVER_INSTANCE; i++)
    {
        sprintf(prop_name, "%s_%d", kConfigKey_HostIPAddress, i);
        if (OK > (status = PROPERTY_findPropertyValue(pPropertyTable, (const sbyte*)
                                                      prop_name,
                                                      &val, &isValFound)))
        {
            goto exit;
        }
        if ((1 == isValFound) && val && *val)
        {
            m_ikeConfig.hostIp[i] = val; val = NULL;
            m_ikeConfig.numSrvInstance++;
        }
        else
        {
            if (val) { FREE(val); val = NULL; }
            break;
        }
    }

    /* HostStdIKEPort */
    if (OK > (status = PROPERTY_findPropertyValue(pPropertyTable, (const sbyte*)
                                                  kConfigKey_HostStdIKEPort,
                                                  &val, &isValFound)))
    {
        goto exit;
    }
    if ((1 == isValFound) && val && *val)
    {
        m_ikeConfig.stdIkePort = (ubyte2) DIGI_ATOL(val, NULL);
    }
    if (val) { FREE(val); val = NULL; }

    // NW redundancy changes
#ifdef __ENABLE_DIGICERT_NW_REDUNDANCY__
    /* Shared MCAST IP */
    if (OK > (status = PROPERTY_findPropertyValue(pPropertyTable, (const sbyte*)
                    kConfigKey_HeartbeatMcastIP,
                    &val, &isValFound)))
    {
        goto exit;
    }
    if ((1 == isValFound) && val && *val)
    {
        m_ikeConfig.heartbeatMcastIP = val; val = NULL;
    }
    if (val) { FREE(val); val = NULL; }

    /* KDC Heartbeat TX UDP Port */
    if (OK > (status = PROPERTY_findPropertyValue(pPropertyTable, (const sbyte*)
                    kConfigKey_HeartbeatTxPort,
                    &val, &isValFound)))
    {
        goto exit;
    }
    if ((1 == isValFound) && val && *val)
    {
        m_ikeConfig.heartbeatTxPort = (ubyte2) DIGI_ATOL(val, NULL);
    }

    /* KDC Heartbeat TX Frequency */
    if (OK > (status = PROPERTY_findPropertyValue(pPropertyTable, (const sbyte*)
                    kConfigKey_HeartbeatTxFreq,
                    &val, &isValFound)))
    {
        goto exit;
    }

    if ((1 == isValFound) && val && *val)
    {
        m_ikeConfig.heartbeatTxFreq = (ubyte2) DIGI_ATOL(val, NULL);
    }
    else {
        m_ikeConfig.heartbeatTxFreq = DEFAULT_HEARTBEAT_FREQ_IN_SEC;
    }
    if (val) { FREE(val); val = NULL; }

    /* Heartbeat broadcast address */
    if (OK > (status = PROPERTY_findPropertyValue(pPropertyTable, (const sbyte*)
                    kConfigKey_HeartbeatTxIP,
                    &val, &isValFound)))
    {
        goto exit;
    }
    if ((1 == isValFound) && val && *val)
    {
        m_ikeConfig.heartbeatTxIP[0] = val; val = NULL;
    }
    if (val) { FREE(val); val = NULL; }

    for (i = 1; i < MOC_MAX_HEARTBEAT_INTERFACES; i++)
    {
        sprintf(prop_name, "%s_%d", kConfigKey_HeartbeatTxIP, i);
        if (OK > (status = PROPERTY_findPropertyValue(pPropertyTable, (const sbyte*)
                        prop_name,
                        &val, &isValFound)))
        {
            goto exit;
        }
        if ((1 == isValFound) && val && *val)
        {
            m_ikeConfig.heartbeatTxIP[i] = val; val = NULL;
        }
        else
        {
            if (val) { FREE(val); val = NULL; }
            break;
        }
    }
#endif

    /* PreSharedKey */
    if (OK > (status = PROPERTY_findPropertyValue(pPropertyTable, (const sbyte*)
                                                  kConfigKey_PreSharedKey,
                                                  &val, &isValFound)))
    {
        goto exit;
    }
    if ((1 == isValFound) && val)
    {
        if (m_ikeConfig.psk) /* jic - command line option -p */
        {
            FREE(m_ikeConfig.psk);
        }
        m_ikeConfig.pskLen = DIGI_STRLEN(val);
        m_ikeConfig.psk = val; val = NULL;
    }
    if (val) { FREE(val); val = NULL; }

    /* SharedKeyFormat */
    if (OK > (status = PROPERTY_findPropertyValue(pPropertyTable, (const sbyte*)
                                                  kConfigKey_PreSharedKeyFormat,
                                                  &val, &isValFound)))
    {
        goto exit;
    }
    if ((1 == isValFound) && val && *val)
    {
        if (0 == DIGI_STRCMP((sbyte *)"hex", val))
            m_ikeConfig.isHexPsk = TRUE;
    }
    if (val) { FREE(val); val = NULL; }

    /* PrimaryKeyServer */
    if (OK > (status = PROPERTY_findPropertyValue(pPropertyTable, (const sbyte*)
                                                  kConfigKey_PrimaryKeyServer,
                                                  &val, &isValFound)))
    {
        goto exit;
    }
    if ((1 == isValFound) && val && *val)
    {
#ifdef __ENABLE_DIGICERT_NW_REDUNDANCY__
        if (m_ikeConfig.gdoiServerIp[0]) /* jic - command line option -z */
        {
            FREE(m_ikeConfig.gdoiServerIp[0]);
        }
        m_ikeConfig.gdoiServerIp[0] = val; val = NULL;
#else
        if (m_ikeConfig.gdoiServerIp) /* jic - command line option -z */
        {
            FREE(m_ikeConfig.gdoiServerIp);
        }
        m_ikeConfig.gdoiServerIp = val; val = NULL;
#endif
    }
    if (val) { FREE(val); val = NULL; }

#ifdef __ENABLE_DIGICERT_NW_REDUNDANCY__
    for (i = 1; i < MAX_NUM_SERVER_INSTANCE; i++)
    {
        sprintf(prop_name, "%s_%d", kConfigKey_PrimaryKeyServer, i);
        if (OK > (status = PROPERTY_findPropertyValue(pPropertyTable, (const sbyte*)
                                                      prop_name,
                                                      &val, &isValFound)))
        {
            goto exit;
        }
        if ((1 == isValFound) && val && *val)
        {
            m_ikeConfig.gdoiServerIp[i] = val; val = NULL;
        }
        else
        {
            if (val) { FREE(val); val = NULL; }
            break;
        }
    }
#endif

    /* PrimaryServerDNSName */
    if (OK > (status = PROPERTY_findPropertyValue(pPropertyTable, (const sbyte*)
                                                  kConfigKey_PrimaryServerDNSName,
                                                  &val, &isValFound)))
    {
        goto exit;
    }
    if ((1 == isValFound) && val && *val)
    {
        m_ikeConfig.gdoiServerDnsName = val; val = NULL;
    }
    if (val) { FREE(val); val = NULL; }

    /* SecondaryKeyServer */
    if (OK > (status = PROPERTY_findPropertyValue(pPropertyTable, (const sbyte*)
                                                  kConfigKey_SecondaryKeyServer,
                                                  &val, &isValFound)))
    {
        goto exit;
    }
    if ((1 == isValFound) && val && *val)
    {
#ifdef __ENABLE_DIGICERT_NW_REDUNDANCY__
        m_ikeConfig.gdoiSecondaryServerIp[0] = val; val = NULL;
#else
        m_ikeConfig.gdoiSecondaryServerIp = val; val = NULL;
#endif
    }
    if (val) { FREE(val); val = NULL; }

#ifdef __ENABLE_DIGICERT_NW_REDUNDANCY__
    for (i = 1; i < MAX_NUM_SERVER_INSTANCE; i++)
    {
        sprintf(prop_name, "%s_%d", kConfigKey_SecondaryKeyServer, i);
        if (OK > (status = PROPERTY_findPropertyValue(pPropertyTable, (const sbyte*)
                                                      prop_name,
                                                      &val, &isValFound)))
        {
            goto exit;
        }
        if ((1 == isValFound) && val && *val)
        {
            m_ikeConfig.gdoiSecondaryServerIp[i] = val; val = NULL;
        }
        else
        {
            if (val) { FREE(val); val = NULL; }
            break;
        }
    }
#endif

    /* SecondaryServerDNSName */
    if (OK > (status = PROPERTY_findPropertyValue(pPropertyTable, (const sbyte*)
                                                  kConfigKey_SecondaryServerDNSName,
                                                  &val, &isValFound)))
    {
        goto exit;
    }
    if ((1 == isValFound) && val && *val)
    {
        m_ikeConfig.gdoiSecondaryServerDnsName = val; val = NULL;
    }
    if (val) { FREE(val); val = NULL; }

    /* PolicyFile */
    if (OK > (status = PROPERTY_findPropertyValue(pPropertyTable, (const sbyte*)
                                                  kConfigKey_PolicyFile,
                                                  &val, &isValFound)))
    {
        goto exit;
    }
    if ((1 == isValFound) && val && *val)
    {
        if (m_ikeConfig.gdoiPolicyFile) /* jic - command line option -Z */
        {
            FREE(m_ikeConfig.gdoiPolicyFile);
        }
        m_ikeConfig.gdoiPolicyFile = val; val = NULL;
    }
    if (val) { FREE(val); val = NULL; }

#if (defined(__ENABLE_DIGICERT_DUAL_MODE__) && defined(__ENABLE_DIGICERT_MCP_TRUSTEDGE_MODE__))
    /* TranslationPolicyFile */
    if (OK > (status = PROPERTY_findPropertyValue(pPropertyTable, (const sbyte*)
                                                  kConfigKey_TranslationPolicyFile,
                                                  &val, &isValFound)))
    {
        goto exit;
    }
    if ((1 == isValFound) && val && *val)
    {
        if (m_ikeConfig.translationPolicyFile) /* jic - command line option -Z */
        {
            FREE(m_ikeConfig.translationPolicyFile);
        }
        m_ikeConfig.translationPolicyFile = val; val = NULL;
    }
    if (val) { FREE(val); val = NULL; }
#endif

    if (OK > (status = PROPERTY_findPropertyValue(pPropertyTable, (const sbyte*)
                                                  kConfigKey_FQDNMappingFile,
                                                  &val, &isValFound)))
    {
        goto exit;
    }
    if ((1 == isValFound) && val && *val)
    {
        if (m_ikeConfig.fqdnMappingConfFile)
        {
            FREE(m_ikeConfig.fqdnMappingConfFile);
        }
        m_ikeConfig.fqdnMappingConfFile = val; val = NULL;
    }
    if (val) { FREE(val); val = NULL; }

    if (OK > (status = PROPERTY_findPropertyValue(pPropertyTable, (const sbyte*)
                                                  kConfigKey_AddrTranslationFile,
                                                  &val, &isValFound)))
    {
        goto exit;
    }
    if ((1 == isValFound) && val && *val)
    {
        if (m_ikeConfig.addrTranslationFile)
        {
            FREE(m_ikeConfig.addrTranslationFile);
        }
        m_ikeConfig.addrTranslationFile = val; val = NULL;
    }
    if (val) { FREE(val); val = NULL; }

    if (OK > (status = PROPERTY_findPropertyValue(pPropertyTable, (const sbyte*)
                                                  kConfigKey_PortListFile,
                                                  &val, &isValFound)))
    {
        goto exit;
    }
    if ((1 == isValFound) && val && *val)
    {
        if (m_ikeConfig.portListFile)
        {
            FREE(m_ikeConfig.portListFile);
        }
        m_ikeConfig.portListFile = val; val = NULL;
    }
    if (val) { FREE(val); val = NULL; }

#ifdef __ENABLE_DIGICERT_INFINTE_KEY_TIMEOUT__
    m_ikeConfig.isrekeyforever = FALSE; /* intialise with default value here*/

    /* Rekey infinte timeout value */
    if (OK > (status = PROPERTY_findPropertyValue(pPropertyTable, (const sbyte*)
                                                  kConfigKey_InfiniteTimeout,
                                                  &val, &isValFound)))
    {
        goto exit;
    }
    if ((1 == isValFound) && val && *val)
    {
        if (0 == DIGI_STRCMP((sbyte *)"enable", val))
            m_ikeConfig.isrekeyforever = TRUE;
        else
            m_ikeConfig.isrekeyforever = FALSE;
    }
    if (val) { FREE(val); val = NULL; }
#endif
    /* KeySyncFile */
    if (OK > (status = PROPERTY_findPropertyValue(pPropertyTable, (const sbyte*)
                                                  kConfigKey_KeySyncFile,
                                                  &val, &isValFound)))
    {
        goto exit;
    }
    if ((1 == isValFound) && val && *val)
    {

#ifdef __ENABLE_DIGICERT_MULTICAST_MCP__
        m_ikeConfig.gdoiKeySyncFile[0] = val; val = NULL;
        m_ikeConfig.num_gdoiKeySyncFile++;
#else
        if (m_ikeConfig.gdoiKeySyncFile) /* jic - command line option -Z */
        {
            FREE(m_ikeConfig.gdoiKeySyncFile);
        }
        m_ikeConfig.gdoiKeySyncFile = val; val = NULL;
#endif
    }
    if (val) { FREE(val); val = NULL; }

#ifdef __ENABLE_DIGICERT_MULTICAST_MCP__
    for (i = m_ikeConfig.num_gdoiKeySyncFile; i < MAX_GROUP_NEGOTIATION; i++)
    {
        sprintf(prop_name, "%s_%d", kConfigKey_KeySyncFile, i);
        if (OK > (status = PROPERTY_findPropertyValue(pPropertyTable, (const sbyte*)
                                                      prop_name,
                                                      &val, &isValFound)))
        {
            goto exit;
        }
        if ((1 == isValFound) && val && *val)
        {
            m_ikeConfig.gdoiKeySyncFile[i] = val; val = NULL;
            m_ikeConfig.num_gdoiKeySyncFile++;
        }
        else
        {
            if (val) { FREE(val); val = NULL; }
            break;
        }
    }
#endif

    /* GroupMember 0..n */
    if (OK > (status = PROPERTY_findPropertyValue(pPropertyTable, (const sbyte*)
                                                  kConfigKey_GroupMember,
                                                  &val, &isValFound)))
    {
        goto exit;
    }
    if ((1 == isValFound) && val && *val)
    {
        m_ikeConfig.groupMember[0] = val; val = NULL;
        m_ikeConfig.numGroupMember++;
    }
    if (val) { FREE(val); val = NULL; }

    for (i = m_ikeConfig.numGroupMember; i < MAX_NUM_GROUP_MEMBER; i++)
    {
        sprintf(prop_name, "%s_%d", kConfigKey_GroupMember, i);
        if (OK > (status = PROPERTY_findPropertyValue(pPropertyTable, (const sbyte*)
                                                      prop_name,
                                                      &val, &isValFound)))
        {
            goto exit;
        }
        if ((1 == isValFound) && val && *val)
        {
            m_ikeConfig.groupMember[i] = val; val = NULL;
            m_ikeConfig.numGroupMember++;
        }
        else
        {
            if (val) { FREE(val); val = NULL; }
            break;
        }
    }

exit:
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
    if (NULL != dir)
    {
        FMGMT_closeDir (&dir);
    }
#endif

    PROPERTY_deleteInstance(&pPropertyTable);
    DIGICERT_freeReadFile(&pFileBuf);
    if (val)
    {
        FREE(val);
    }
    if (data)
    {
        FREE(data);
    }
    return (sbyte4)status;
} /* LoadConfig */


/*------------------------------------------------------------------*/

#if !defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__) && \
    !defined(__DISABLE_DIGICERT_FILE_SYSTEM_HELPER__) && \
    !defined(__RTOS_ANDROID__) && !defined(__UCOS_DIRECT_RTOS__)

static FILE *m_logFd = NULL;

static void
mcpLogFn(sbyte4 module, sbyte4 severity, sbyte *msg)
{
    sbyte *moduleStr;
    sbyte *severityStr;

    switch (module)
    {
    case MOCANA_EAP:    moduleStr = (sbyte *)"EAP"; break;
    case MOCANA_HTTP:   moduleStr = (sbyte *)"HTTP"; break;
    case MOCANA_IKE:    moduleStr = (sbyte *)"IKE"; break;
    case MOCANA_IPSEC:  moduleStr = (sbyte *)"IPSEC"; break;
    case MOCANA_RADIUS: moduleStr = (sbyte *)"RADIUS"; break;
    case MOCANA_SSH:    moduleStr = (sbyte *)"SSH"; break;
    case MOCANA_SSL:    moduleStr = (sbyte *)"SSL"; break;
    default:            moduleStr = (sbyte *)"MCP"; break;
    }

    switch (severity)
    {
    case LS_CRITICAL:   severityStr = (sbyte *)"CRITICAL";    break;
    case LS_MAJOR:      severityStr = (sbyte *)"MAJOR";       break;
    case LS_MINOR:      severityStr = (sbyte *)"MINOR";       break;
    case LS_WARNING:    severityStr = (sbyte *)"WARNING";     break;
    case LS_INFO:       severityStr = (sbyte *)"INFO";        break;
    default:            severityStr = (sbyte *)"UNKNOWN";     break;
    }

    if (m_logFd)
    {
#ifdef __RTOS_LINUX__
        time_t clock;
        time(&clock);
#endif
        fprintf(m_logFd, "%s%s [%s] %s\n",
#ifdef __RTOS_LINUX__
                ctime(&clock),
#else
                "",
#endif
                moduleStr, severityStr, msg);
        (void) fflush(m_logFd);
    }

    return;
} /* mcpLogFn */

#endif


/*------------------------------------------------------------------*/

static void
DisplayHelp(char *prog)
{
    printf("Usage: %s <option>* <ipaddr>*\n\n", prog);

    printf("  option:\n");
    printf("    -d <mins>       sets DPD interval (in minutes)\n");
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
    printf("    -m <mode>       sets phase 1 exchange mode\n");
#endif
    printf("    -n <secs>       sets negotiation timeout (in seconds)\n");
    printf("    -p <key>        sets pre-shared key\n");
    printf("\n");

    printf("    -g <dh>         sets DH group\n");
    printf("    -l <secs>       sets IKE_SA lifetime seconds\n");
    printf("\n");

    printf("    -f <file>       loads configuration file.\n");
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
    printf("    -z <ipaddr>     sets primary KDC address.\n");
#endif
#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
    printf("    -Z <file>       sets synchronizable key file.\n");
#else
    printf("    -Z <file>       sets agent policy file.\n");
#endif
    printf("\n");

    printf("    -h              displays this help\n");
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    printf("    -o <file>       sets debug console output\n");
#else
    printf("    -o <file>       sets log file\n");
#endif
    printf("    -w <secs>       sets socket wait time (in seconds)\n");
    printf("\n");

    printf("  dh:   { 1 | 2 | 5 | 14 | 15 | 16 | 17 | 18%s%s%s | 24%s%s }\n",
#if defined(__ENABLE_DIGICERT_ECC__) && !defined(__DISABLE_DIGICERT_ECC_P256__)
           " | 19",
#else
           "",
#endif
#if defined(__ENABLE_DIGICERT_ECC__) && !defined(__DISABLE_DIGICERT_ECC_P384__)
           " | 20",
#else
           "",
#endif
#if defined(__ENABLE_DIGICERT_ECC__) && !defined(__DISABLE_DIGICERT_ECC_P521__)
           " | 21",
#else
           "",
#endif
#if defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_ECC_P192__)
           " | 25",
#else
           "",
#endif
#if defined(__ENABLE_DIGICERT_ECC__) && !defined(__DISABLE_DIGICERT_ECC_P224__)
           " | 26"
#else
           ""
#endif
           );
    printf("  key:  { <ascii string> | 0x<hexadecimal digits> }\n");
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
    printf("  mode: { main | aggressive | m | a | M | A }\n");
#endif

    printf("\n");
    return;
} /* DisplayHelp */


/*------------------------------------------------------------------*/

#if defined(__DISABLE_DIGICERT_MAIN_FUNC_ENTRY__) && defined(__PLATFORM_HAS_GETOPT__)
#undef __PLATFORM_HAS_GETOPT__
#endif

extern sbyte4
MCP_EXAMPLE_getArgs(int argc, char *argv[])
{
    sbyte4 status = 0;

    int i;
    sbyte4 len;

#ifndef __PLATFORM_HAS_GETOPT__
    int optind = 1;
    int optopt;
    char *optarg;
#else
    extern int optind;
    extern int optopt;
    extern char *optarg;
#endif

    int c;

    if ((2 <= argc) && ('?' == argv[1][0]))
    {
        DisplayHelp(argv[0]);
        return -1;
    }

    m_ikeConfig.oMode = DEFAULT_MODE;

#ifndef __PLATFORM_HAS_GETOPT__
    for (; optind < argc; optind++)
    {
        int optarg_len;

        optarg = argv[optind];
        optarg_len = strlen(optarg);

        if ((0 >= optarg_len) || ('-' != optarg[0]))
            break;

        if ((1 >= optarg_len) || ('-' == (c = optarg[1])))
        {
            optind++;
            break;
        }

        optopt = c;
        optarg += 2;
        optarg_len -= 2;

        switch (c)
        {
        case 'h':
            if (0 < optarg_len)
            {
                fprintf(stderr, "MCP: Option -%c operand is ignored.\n", optopt);
            }
            break;

        case 'd':
        case 'f':
        case 'g':
        case 'l':
        case 'm':
        case 'n':
        case 'o':
        case 'p':
        case 'w':
        case 'z':
        case 'Z':
            if (0 >= optarg_len)
            {
                if (((1 + optind) >= argc) ||
                    (('-' == argv[optind + 1][0]) &&
                     isalpha(argv[optind + 1][1])))
                {
                    c = ':';
                }
                else
                {
                    optind++;
                    optarg = argv[optind];
                }
            }
            break;
/*
        case 'h':
*/
        default :
            break;
        }
#else
    while ((c = getopt(argc, argv, "d:f:g:hl:m:n:o:p:w:z:Z:")) != -1)
    {
#endif
        switch (c)
        {
        case 'd': /* set DPD interval (in mins) */
        {
            sbyte4 ikeTimeoutDpd = strtol(optarg, NULL, 0);
            if (0 >= ikeTimeoutDpd)
            {
                fprintf(stderr, "MCP: Bad option value -d %s (invalid)\n", optarg);
                break;
            }
            m_ikeConfig.timeoutDpd = (ubyte4)(ikeTimeoutDpd * 60); /* secs */
            break;
        }
        case 'g': /* set default DH group for phase 1 */
        {
            sbyte4 ikeP1DHgroup = strtol(optarg, NULL, 0);
            if (0 >= ikeP1DHgroup)
            {
                fprintf(stderr, "MCP: Bad option value -g %s (invalid)\n", optarg);
                break;
            }
            m_ikeConfig.p1DHgroup = (ubyte2)ikeP1DHgroup;
            break;
        }
        case 'h':
            DisplayHelp(argv[0]);
            break;

        case 'l': /* set IKE_SA lifetime seconds */
        {
            sbyte4 ikeP1LifeSecs = strtol(optarg, NULL, 0);
            if (0 >= ikeP1LifeSecs)
            {
                fprintf(stderr, "MCP: Bad option value -l %s (invalid)\n", optarg);
                break;
            }
            m_ikeConfig.p1LifeSecs = (ubyte4)ikeP1LifeSecs;
            m_ikeConfig.p1LifeSecsMax =(ubyte4)ikeP1LifeSecs; /* FOR NOW */
            break;
        }
        case 'm': /* set phase 1 mode */
        {
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
            int m = optarg[0];
            if (('M' == m) || ('m' == m))
            {
                m_ikeConfig.p1Mode = 2; /* 2=main */;
            }
            else if (('A' == m) || ('a' == m))
            {
                m_ikeConfig.p1Mode = 4; /* 4=aggressive */;
            }
            else fprintf(stderr, "MCP: Bad option value -m %s\n", optarg);
#else
            fprintf(stderr, "MCP: Bad option -m (disabled)\n");
#endif
            break;
        }
        case 'n': /* set negotiation timeout (in secs) */
        {
            sbyte4 ikeTimeoutNegotiation = strtol(optarg, NULL, 0);
            if ((5 > ikeTimeoutNegotiation) || (300 < ikeTimeoutNegotiation)) /* FOR NOW */
            {
                fprintf(stderr, "MCP: Bad option value -n %s\n", optarg);
                break;
            }
            m_ikeConfig.timeoutNegotiation = (ubyte4)ikeTimeoutNegotiation;
            break;
        }
        case 'o':
#if defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
            DEBUG_CONSOLE_setOutput(optarg);
#elif !defined(__DISABLE_DIGICERT_FILE_SYSTEM_HELPER__) && \
      !defined(__RTOS_ANDROID__) && !defined(__UCOS_DIRECT_RTOS__)
            if (NULL == (m_logFd = fopen(optarg, "w")))
            {
                fprintf(stderr, "MCP: Failed to open log file %s\n", optarg);
                status = (sbyte4)ERR_FILE_OPEN_FAILED;
                goto exit;
            }
            if (0 > (status = DIGICERT_initLog(mcpLogFn)))
                goto exit;
#else
            fprintf(stderr, "MCP: Bad option -o (disabled)\n");
#endif
            break;

        case 'p': /* set pre-shared key */
        {
            int psklen = strlen((char *)optarg);

            if ((2 < psklen) && ('0' == optarg[0]) &&
                (('x' == optarg[1]) || ('X' == optarg[1])))
            {
                mIsHexPSK = TRUE;
                mPSK = (sbyte *)(optarg + 2);
                mPSKlen = psklen - 2;
                psklen = (psklen - 1) / 2;
            }
            else
            {
                mIsHexPSK = FALSE;
                mPSK = (sbyte *)optarg;
                mPSKlen = psklen;
            }

            DEBUG_PRINT(DEBUG_CUSTOM, (sbyte *)"MCP: Preshared key is set (");
            if (IKE_PSK_MAX < psklen)
            {
                psklen = IKE_PSK_MAX;
                mPSKlen = mIsHexPSK ? (2 * IKE_PSK_MAX) : IKE_PSK_MAX;
                DEBUG_PRINTNL(DEBUG_CUSTOM, (sbyte *)"truncated ");
            }
            DEBUG_INT(DEBUG_CUSTOM, psklen);
            DEBUG_PRINTNL(DEBUG_CUSTOM, (sbyte *)" bytes)");

            if (m_ikeConfig.psk)
            {
                FREE(m_ikeConfig.psk);
            }
            if (NULL == (m_ikeConfig.psk = (sbyte *)MALLOC(mPSKlen)))
            {
                status = (sbyte4)ERR_MEM_ALLOC_FAIL;
                goto exit;
            }
            DIGI_MEMCPY(m_ikeConfig.psk, mPSK, mPSKlen);
            m_ikeConfig.pskLen = mPSKlen;
            m_ikeConfig.isHexPsk = mIsHexPSK;
            break;
        }

        case 'w': /* set socket listen timeout (in secs) */
        {
            sbyte4 ikeTimeoutSocket = strtol(optarg, NULL, 0);
            if ((0 >= ikeTimeoutSocket) || (60 < ikeTimeoutSocket))
            {
                fprintf(stderr, "MCP: Bad option value -w %s (invalid or too large)\n", optarg);
                break;
            }
            m_ikeConfig.timeoutSocket = (ubyte4)ikeTimeoutSocket;
            break;
        }
        case 'f':
            if (0 > (status = MCP_LoadConfig((sbyte *)optarg)))
            {
                goto exit;
            }
            break;

        case 'z': /* set primary KDC address */
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
            len = (sbyte4) DIGI_STRLEN((sbyte *)optarg) + 1;
#ifdef __ENABLE_DIGICERT_NW_REDUNDANCY__
            if (m_ikeConfig.gdoiServerIp[0])
            {
                FREE(m_ikeConfig.gdoiServerIp[0]);
            }
            if (NULL == (m_ikeConfig.gdoiServerIp[0] = (sbyte *) MALLOC(len)))
            {
                status = (sbyte4)ERR_MEM_ALLOC_FAIL;
                goto exit;
            }
            DIGI_MEMCPY(m_ikeConfig.gdoiServerIp[0], optarg, len);
#else
            if (m_ikeConfig.gdoiServerIp)
            {
                FREE(m_ikeConfig.gdoiServerIp);
            }
            if (NULL == (m_ikeConfig.gdoiServerIp = (sbyte *) MALLOC(len)))
            {
                status = (sbyte4)ERR_MEM_ALLOC_FAIL;
                goto exit;
            }
            DIGI_MEMCPY(m_ikeConfig.gdoiServerIp, optarg, len);
#endif
#else
            fprintf(stderr, "MCP: Bad option -z (disabled)\n");
#endif
            break;

        case 'Z':
            len = (sbyte4) DIGI_STRLEN((sbyte *)optarg) + 1;
#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
            /* set KDC key sync file */
#ifdef __ENABLE_DIGICERT_MULTICAST_MCP__

    if (m_ikeConfig.gdoiKeySyncFile[0])
    {
        FREE(m_ikeConfig.gdoiKeySyncFile[0]);
    }
#else
    if (m_ikeConfig.gdoiKeySyncFile)
    {
        FREE(m_ikeConfig.gdoiKeySyncFile);
    }
#endif
#ifdef __ENABLE_DIGICERT_MULTICAST_MCP__
            if (NULL == (m_ikeConfig.gdoiKeySyncFile[0] = (sbyte *) MALLOC(len)))
            {
                status = (sbyte4)ERR_MEM_ALLOC_FAIL;
                goto exit;
            }
            DIGI_MEMCPY(m_ikeConfig.gdoiKeySyncFile[0], optarg, len);
#else
            if (NULL == (m_ikeConfig.gdoiKeySyncFile = (sbyte *) MALLOC(len)))
            {
                status = (sbyte4)ERR_MEM_ALLOC_FAIL;
                goto exit;
            }
            DIGI_MEMCPY(m_ikeConfig.gdoiKeySyncFile, optarg, len);
#endif
#else
            /* set Agent IPsec policy file */
            if (m_ikeConfig.gdoiPolicyFile)
            {
                FREE(m_ikeConfig.gdoiPolicyFile);
            }
            if (NULL == (m_ikeConfig.gdoiPolicyFile = (sbyte *) MALLOC(len)))
            {
                status = (sbyte4)ERR_MEM_ALLOC_FAIL;
                goto exit;
            }
            DIGI_MEMCPY(m_ikeConfig.gdoiPolicyFile, optarg, len);

#if (defined(__ENABLE_DIGICERT_DUAL_MODE__) && defined(__ENABLE_DIGICERT_MCP_TRUSTEDGE_MODE__))
            /* set Translation policy file */
            if (m_ikeConfig.translationPolicyFile)
            {
                FREE(m_ikeConfig.translationPolicyFile);
            }
            if (NULL == (m_ikeConfig.translationPolicyFile = (sbyte *) MALLOC(len)))
            {
                status = (sbyte4)ERR_MEM_ALLOC_FAIL;
                goto exit;
            }
            DIGI_MEMCPY(m_ikeConfig.translationPolicyFile, optarg, len);
#endif /* (defined(__ENABLE_DIGICERT_DUAL_MODE__) && defined(__ENABLE_DIGICERT_MCP_TRUSTEDGE_MODE__)) */
#endif
            break;

        case ':': /* without operand */
            fprintf(stderr, "MCP: Option -%c requires an operand.\n", optopt);
            break;

        default:
            fprintf(stderr, "MCP: Invalid option -%c\n", optopt);
            break;
        }
    }

    if (NULL == m_ikeConfig.psk)
    {
        if (NULL == (m_ikeConfig.psk = (sbyte *) MALLOC(mPSKlen)))
        {
            status = (sbyte4)ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        DIGI_MEMCPY(m_ikeConfig.psk, mPSK, mPSKlen);
        m_ikeConfig.pskLen = mPSKlen;
        m_ikeConfig.isHexPsk = mIsHexPSK;
    }

#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
#ifdef __ENABLE_DIGICERT_MULTICAST_MCP__
    if (0 == m_ikeConfig.num_gdoiKeySyncFile)
#else
    if (NULL == m_ikeConfig.gdoiKeySyncFile)
#endif
    {
        len = (sbyte4) DIGI_STRLEN(DEFAULT_KEYSYNC_FILE) + 1;

#ifdef __ENABLE_DIGICERT_MULTICAST_MCP__
        if (NULL == (m_ikeConfig.gdoiKeySyncFile[0] = (sbyte *) MALLOC(len)))
        {
            status = (sbyte4)ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        DIGI_MEMCPY(m_ikeConfig.gdoiKeySyncFile[0], DEFAULT_KEYSYNC_FILE, len);
        m_ikeConfig.num_gdoiKeySyncFile++;
#else
        if (NULL == (m_ikeConfig.gdoiKeySyncFile = (sbyte *) MALLOC(len)))
        {
            status = (sbyte4)ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        DIGI_MEMCPY(m_ikeConfig.gdoiKeySyncFile, DEFAULT_KEYSYNC_FILE, len);

#endif
        DEBUG_PRINT(DEBUG_CUSTOM, (sbyte *)"MCP: Use default synchronizable key file: ");
        DEBUG_PRINTNL(DEBUG_CUSTOM, DEFAULT_KEYSYNC_FILE);
    }
#else
    if (NULL == m_ikeConfig.gdoiPolicyFile)
    {
        len = (sbyte4) DIGI_STRLEN(DEFAULT_POLICY_FILE) + 1;
        if (NULL == (m_ikeConfig.gdoiPolicyFile = (sbyte *) MALLOC(len)))
        {
            status = (sbyte4)ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        DIGI_MEMCPY(m_ikeConfig.gdoiPolicyFile, DEFAULT_POLICY_FILE, len);
        DEBUG_PRINT(DEBUG_CUSTOM, (sbyte *)"MCP: Use default agent policy file: ");
        DEBUG_PRINTNL(DEBUG_CUSTOM, DEFAULT_POLICY_FILE);
    }
#endif

    for (i=0 ; optind < argc; optind++, i++)
    {
        int j = (m_ikeConfig.numSrvInstance % MAX_NUM_SERVER_INSTANCE);
        optarg = argv[optind];
        DEBUG_PRINT(DEBUG_CUSTOM, (sbyte *)"MCP: Host IP address is ");
        DEBUG_PRINTNL(DEBUG_CUSTOM, (sbyte *)optarg);
        if (MAX_NUM_SERVER_INSTANCE <= i)
        {
            DEBUG_PRINTNL(DEBUG_CUSTOM, (sbyte *)"(Skipped)");
            continue;
        }
        len = (sbyte4) DIGI_STRLEN((sbyte *)optarg) + 1;
        if (m_ikeConfig.hostIp[j])
        {
            FREE(m_ikeConfig.hostIp[j]);
        }
        if (NULL == (m_ikeConfig.hostIp[j] = (sbyte *)MALLOC(len)))
        {
            status = (sbyte4)ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        DIGI_MEMCPY(m_ikeConfig.hostIp[j], optarg, len);
        if (MAX_NUM_SERVER_INSTANCE > m_ikeConfig.numSrvInstance)
            m_ikeConfig.numSrvInstance++;
    } /* for */

exit:
    if (0 > status)
    {
        DEBUG_ERROR(DEBUG_CUSTOM, (sbyte *)"MCP: Failed to process command-line options, status = ", status);
        Mcp_ClearConfig();
    }
    return status;
} /* MCP_EXAMPLE_getArgs */


/*------------------------------------------------------------------*/

static sbyte4
CertNameValidate(const sbyte* dnsName, ASN1_ITEMPTR pCert, CStream cs)
{
    sbyte4 status;

    /* check Subject Alt Name */
    status = X509_compSubjectAltNames(pCert, cs, dnsName, (1<<2));

    /* if it fails check the common name */
    if (OK > status)
    {
        return X509_compSubjectCommonName(pCert, cs, dnsName);
    }

    return status;
} /* CertNameValidate */


/*------------------------------------------------------------------*/

sbyte4
Mcp_VerifyLeafCert(void *arg, sbyte4 serverInstance,
               struct ikesa *pxSa,
               ubyte *pCertificate, ubyte4 certificateLen)
{
    sbyte4 status;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pCertItem = NULL, pRootItem;

    MOC_UNUSED(arg);
    MOC_UNUSED(serverInstance);

    MF_attach(&mf, certificateLen, (ubyte *)pCertificate);
    CS_AttachMemFile(&cs, &mf);

    if (OK > (status = ASN1_Parse(cs, &pCertItem)))
    {
        goto exit;
    }

    pRootItem = ASN1_FIRST_CHILD(pCertItem);

#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
    if (OP_MODE_CLIENT == m_ikeConfig.oMode)
    {
        MOC_IP_ADDRESS keyServerAddr = REF_MOC_IPADDR(pxSa->ikePeerConfig->keyServerAddr);

        if (SAME_MOC_IPADDR(keyServerAddr, m_ikeCtx->primaryKeyServerAddr))
        {
            sbyte *primaryServerName = m_ikeConfig.gdoiServerDnsName;
            if (primaryServerName)
                status = CertNameValidate(primaryServerName, pRootItem, cs);
        }
        else if (SAME_MOC_IPADDR(keyServerAddr, m_ikeCtx->secondaryKeyServerAddr))
        {
            sbyte *secondaryServerName = m_ikeConfig.gdoiSecondaryServerDnsName;
            if (secondaryServerName)
                status = CertNameValidate(secondaryServerName, pRootItem, cs);
        }
    }
    else
#endif
    {
#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
        sbyte4 i;
        for (i = 0; i < m_ikeConfig.numGroupMember; ++i)
        {
            if (OK <= (status = CertNameValidate(m_ikeConfig.groupMember[i],
                                                 pRootItem, cs)))
            {
                break;
            }
        }
        if (OK > status)
        {
            sbyte *serverName = NULL;

            if (OP_MODE_SERVER_PRIMARY == m_ikeConfig.oMode)
                serverName = m_ikeConfig.gdoiSecondaryServerDnsName;
            else
                serverName = m_ikeConfig.gdoiServerDnsName;

            if (serverName)
                status = CertNameValidate(serverName, pRootItem, cs);
        }
#endif
    }

exit:
    if (pCertItem)
    {
        TREE_DeleteTreeItem((TreeItem *)pCertItem);
    }
    if (OK > status)
    {
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
        DEBUG_ERROR(DEBUG_CUSTOM, (sbyte *)"MCP: Cannot validate peer certificate name, status = ", status);
#else
        IKE_RUNTIME_ERROR("Cannot validate peer certificate name", status);
#endif
    }
    return status;
} /* VerifyLeafCert */


/*------------------------------------------------------------------*/

static sbyte4
VerifyCertName(sbyte *certDnsName, ubyte *pCertificate, ubyte4 certificateLen)
{
    sbyte4 status;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pRootItem = NULL;

    MF_attach(&mf, certificateLen, (ubyte *)pCertificate);
    CS_AttachMemFile(&cs, &mf);

    if (OK > (status = ASN1_Parse(cs, &pRootItem)))
    {
        goto exit;
    }

    status = CertNameValidate(certDnsName, ASN1_FIRST_CHILD(pRootItem), cs);

    TREE_DeleteTreeItem((TreeItem *)pRootItem);

exit:
    if (OK > status)
    {
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
        DEBUG_ERROR(DEBUG_CUSTOM, (sbyte *)"MCP: Cannot validate host certificate name, status = ", status);
#else
        IKE_RUNTIME_ERROR("Cannot validate host certificate name", status);
#endif
    }
    return status;
} /* VerifyCertName */


/*------------------------------------------------------------------*/

#if (defined(__WIN32_RTOS__) || defined (__RTOS_WINCE__))
static BOOL
WINAPI HandlerRoutine(DWORD dw)
{
    MOC_UNUSED(dw);
    if (m_ikeCtx) m_ikeCtx->stopEventThread = TRUE;

    return TRUE;
}
#endif

/*------------------------------------------------------------------*/
/* IKE Server Main Entry                                            */
/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_MEM_PART__
extern memPartDescr *gMemPartDescr;
#endif

extern void
MCP_EXAMPLE_main(void* dummy)
{
    sbyte4 status;

    MOC_UNUSED(dummy);

#ifdef __ENABLE_DIGICERT_SECURE_PATH__
    if (OK > (status = FMGMT_changeCWD(MANDATORY_BASE_PATH)))
        goto exit;
#endif

#ifdef __ENABLE_DIGICERT_MEM_PART__
    if (NULL != gMemPartDescr)
    {
        /* make sure it's thread-safe! */
        MEM_PART_enableMutexGuard(gMemPartDescr);
    }
#endif

#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
#ifdef __ENABLE_DIGICERT_NW_REDUNDANCY__
    if (NULL == m_ikeConfig.gdoiServerIp[0])
#else
    if (NULL == m_ikeConfig.gdoiServerIp)
#endif
    {
        CONFIG_ERROR(kConfigKey_PrimaryKeyServer, "", "Not specified");
        goto exit;
    }
#endif

    /* Read port list mapping file */
    status = read_portlist_from_file(m_ikeConfig.portListFile);
    if (OK != status)
    {
        CONFIG_ERROR(kConfigKey_PortListFile, m_ikeConfig.portListFile, "Failed to parse Port list mapping file");
        HANDLE_ERROR_INT("Failed to parse Port list mapping file", status);
        goto exit;
    }

    /* handle mapping config file */
#ifdef __ENABLE_DIGICERT_DUAL_MODE__
    status = create_ifmap(m_ikeConfig.addrTranslationFile);
    if (OK != status)
       goto exit;
#endif
    status = MCP_Platform_init();

    if(0 != status && ERR_FILE_OPEN_FAILED != status) /* if tpm2.conf is not present than no need to stop the service*/
    {
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
#ifdef __ENABLE_DIGICERT_NW_REDUNDANCY__
    if (NULL == m_ikeConfig.gdoiServerIp[0])
#else
    if (NULL == m_ikeConfig.gdoiServerIp)
#endif
    {
        CONFIG_ERROR(kConfigKey_PrimaryKeyServer, "", "Not specified");
        goto exit;
    }
#endif

    /* initialize the IKE tables and structures */
    if (0 > (status = MCP_init(&m_ikeConfig, NULL, Mcp_VerifyLeafCert, &m_ikeCtx)))
    {
        HANDLE_ERROR_INT("MCP_init failed", status);
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_PFKEY__
    if (0 > PFKEY_EXAMPLE_main())
    {
        goto exit;
    }

    /* - Implement RPC's from IKE (user) to IPsec (kernel).
       - Create a uni-directional channel from IPsec (kernel) to IKE (user).
     */
#else
    if (0 > (status = IPSECKEY_EXAMPLE_main()))
    {
        HANDLE_ERROR_INT("Failed to connect to Mocana IPsec", status);
        goto exit;
    }
#endif

#ifdef MOCANA_IKEADM_PORT
    IKEADM_EXAMPLE_main();
#endif

#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
#ifndef __ENABLE_DIGICERT_GDOI_CLIENT__ /* primary kdc */
    if (0 > (status = MCP_keyGen(m_ikeCtx)))
    {
        HANDLE_ERROR_INT("MCP_keyGen failed", status);
        /*goto exit;*/
    }
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
    /* Keysync read success , now read config which is required for negotiation mapping of unicast ip adddress*/
    MCP_setFqdnName((const sbyte*)m_ikeConfig.fqdnMappingConfFile);  /* for future file reads*/

    if (OK > (status = MCP_parseGroupList((const char*)m_ikeConfig.fqdnMappingConfFile, m_ikeConfig.hostIp)))
    {
        CONFIG_ERROR(kConfigKey_FQDNMappingFile, m_ikeConfig.fqdnMappingConfFile, "Failed to parse unicast group list mapping file");
        HANDLE_ERROR_INT("Failed to parse group list mapping file", status);
        goto exit;
    }
#endif
#else /* secondary kdc */
    MCP_setFqdnName((const sbyte*)m_ikeConfig.fqdnMappingConfFile);

#ifdef __ENABLE_DIGICERT_NW_REDUNDANCY__
    if (0 > (status = IKE_keyConnect(REF_MOC_IPADDR(m_ikeCtx->primaryKeyServerAddr[0]),
                                     1, 0, FALSE, NULL, TRUE, FALSE, TRUE, NULL)))
#else
    if (0 > (status = IKE_keyConnect(REF_MOC_IPADDR(m_ikeCtx->primaryKeyServerAddr),
                                     1, 0, FALSE, NULL, TRUE, FALSE, TRUE, NULL)))
#endif
    {
        HANDLE_ERROR_INT("IKE_keyConnect failed", status);
        goto exit;
    }
#endif
#endif

#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
#ifdef __ENABLE_DIGICERT_NW_REDUNDANCY__
    MCP_RedundancyCheck_start(&m_ikeConfig);
#endif
#endif

    /* start up the IKE server */
    if (0 > (status = MCP_IKE_start(m_ikeCtx)))
    {
        HANDLE_ERROR_INT("MCP_IKE_start failed", status);
        goto exit;
    }

#ifndef __ENABLE_DIGICERT_GDOI_SERVER__

    status = Mcp_SetAgentPolicy();
#ifdef __ENABLE_DIGICERT_MULTICAST_MCP__
    if (0 > status)
    {
        HANDLE_ERROR_INT("Mcp_SetAgentPolicy failed", status);
        goto exit;
    }
#endif
#if (defined(__ENABLE_DIGICERT_DUAL_MODE__) && defined(__ENABLE_DIGICERT_MCP_TRUSTEDGE_MODE__))
    status = Mcp_SetAgentPolicyEx(m_ikeConfig.translationPolicyFile);
    if (0 > status)
    {
        HANDLE_ERROR_INT("Mcp_SetAgentPolicyEx failed", status);
        goto exit;
    }
#endif /* (defined(__ENABLE_DIGICERT_DUAL_MODE__) && defined(__ENABLE_DIGICERT_MCP_TRUSTEDGE_MODE__)) */
#endif

#if defined(__WIN32_RTOS__) && !defined(__RTOS_WINCE__)
    SetConsoleCtrlHandler(HandlerRoutine, TRUE);
#endif

#ifdef __RTOS_LINUX__
    if (SIG_ERR == signal(SIGUSR1, valgrindSigHandler))
    {
        DIGICERT_log(MOCANA_IKE, LS_INFO, (sbyte *)"Registering signal sigusr1 failed");
    }
#endif
    while (m_ikeCtx && (FALSE == m_ikeCtx->stopEventThread))
        RTOS_sleepMS(1000);

exit:
    /* close multicast sockets used to configure NIC */
#ifdef __ENABLE_DIGICERT_DUAL_MODE__
    multicast_close_ipv4();
#endif
    /* shut down MCP service */
    if (m_ikeCtx)
    {
        MCP_IKE_stop(m_ikeCtx);
        MCP_shutdown(&m_ikeCtx);
    }

    /* clean up IKE configiration */
    Mcp_ClearConfig();

    /* CLean Up digicert init and tap init context*/
    MCP_Platform_deinit();

    /* in your design, you will want to wait for upper layer to signal it's dead */
    RTOS_sleepMS(2000);
    return;
} /* MCP_EXAMPLE_main */

#ifdef __ENABLE_DIGICERT_INFINTE_KEY_TIMEOUT__
intBoolean is_mcp_infinite_timeout()
{
    return m_ikeConfig.isrekeyforever;
}
#endif /* __ENABLE_DIGICERT_INFINTE_KEY_TIMEOUT__ */
#endif /* defined(__ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__) && defined(__ENABLE_DIGICERT_MCP_EXAMPLE__) */
#endif /* __ENABLE_DIGICERT_EXAMPLES__ */
