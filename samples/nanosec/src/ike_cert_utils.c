/*
 * ike_cert_utils.c
 *
 * Handle certificate data for IKE
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

#ifdef __ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__
#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)

#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_EAP_PEER__)
#error "Must not define both __ENABLE_DIGICERT_EAP_AUTH__ & __ENABLE_DIGICERT_EAP_PEER__ for IKE example"
#endif

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/secmod.h"
#include "../common/random.h"
#include "../common/debug_console.h"
#include "../common/mstdlib.h"
#include "../crypto/hw_accel.h"
#include "../common/vlong.h"
#include "../crypto/crypto.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/ca_mgmt.h"
#include "../asn1/oiddefs.h"
#include "../common/sizedbuffer.h"
#include "../crypto/cert_store.h"
#include "../ike/ike.h"
#include "../ike/ike_defs.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../common/mrtos.h"

#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
#include "../data_protection/file_protect.h"
#endif

#ifdef __ENABLE_DIGICERT_EAP_AUTH__
#ifdef __ENABLE_DIGICERT_DER_CONVERSION__
#ifndef __ENABLE_DIGICERT_PKCS8__
#ifdef __WIN32_RTOS__
#pragma message ("__ENABLE_DIGICERT_PKCS8__ is not defined!")
#else
#warning "__ENABLE_DIGICERT_PKCS8__ is not defined!"
#endif
#endif
#else
#ifdef __WIN32_RTOS__
#pragma message ("__ENABLE_DIGICERT_DER_CONVERSION__ is not defined!")
#else
#warning "__ENABLE_DIGICERT_DER_CONVERSION__ is not defined!"
#endif
#endif
#endif

#define SERVER_KEYS_FNAME       "serverkey"
#define SERVER_CERT_FNAME       "server"
#define CLIENT_KEYS_FNAME       "clientkey"
#define CLIENT_CERT_FNAME       "client"

#ifdef __ENABLE_DIGICERT_EAP_AUTH__
#define HOST_KEYS_FNAME         SERVER_KEYS_FNAME
#define HOST_CERT_FNAME         SERVER_CERT_FNAME
#else
#define HOST_KEYS_FNAME         CLIENT_KEYS_FNAME
#define HOST_CERT_FNAME         CLIENT_CERT_FNAME
#endif
#define CA_CERT_FNAME           "ca"

#if defined (__RTOS_VXWORKS__)
#define HOST_KEYS_FILE          "NVRAM:/" HOST_KEYS_FNAME
#define HOST_CERT_FILE          "NVRAM:/" HOST_CERT_FNAME
#define CA_CERT_FILE            "NVRAM:/" CA_CERT_FNAME
#define SERVER_CERT_FILE        "NVRAM:/" SERVER_CERT_FNAME
#elif defined (__RTOS_OSE__)
#define HOST_KEYS_FILE          "/ram/" HOST_KEYS_FNAME
#define HOST_CERT_FILE          "/ram/" HOST_CERT_FNAME
#define CA_CERT_FILE            "/ram/" CA_CERT_FNAME
#define SERVER_CERT_FILE        "/ram/" SERVER_CERT_FNAME
#elif defined(__RTOS_WIN32__)
#define HOST_KEYS_FILE          "C:/" HOST_KEYS_FNAME
#define HOST_CERT_FILE          "C:/" HOST_CERT_FNAME
#define CA_CERT_FILE            "C:/" CA_CERT_FNAME
#define SERVER_CERT_FILE        "C:/" SERVER_CERT_FNAME
#else
#define HOST_KEYS_FILE          HOST_KEYS_FNAME
#define HOST_CERT_FILE          HOST_CERT_FNAME
#define CA_CERT_FILE            CA_CERT_FNAME
#define SERVER_CERT_FILE        SERVER_CERT_FNAME
#endif

#define HOST_KEYS               (HOST_KEYS_FILE ".dat")

#define CERTIFICATE_DER_FILE    (HOST_CERT_FILE ".der")
#define HOST_KEYS_DER_FILE      (HOST_KEYS_FILE ".der")
#define ROOT_DER_FILE           (CA_CERT_FILE ".der")
#define SERVER_CERT_DER_FILE    (SERVER_CERT_FILE ".der")

/* root certs */
typedef struct rootCertInfo
{
    const char* fileName;
    ubyte* certData;
    ubyte4 certLength;
} rootCertInfo;

static rootCertInfo sRootCerts[] =
{
    {"rootCert.der", 0, 0 },
    {ROOT_DER_FILE, 0, 0 },
    {CERTIFICATE_DER_FILE, 0, 0 }
};

static sbyte* sCertPath = NULL;

/* Shared with others */
certStorePtr g_pIKECertStore = NULL;
certDescriptor g_IKECert = { NULL };
#ifdef __ENABLE_DIGICERT_EAP_TLS__
#define COMMON_NAME_MAX_LENGTH 256
sbyte g_IKECertCommonName[COMMON_NAME_MAX_LENGTH] = { 0 };

extern void setCertCommonName (ubyte *pName, ubyte4 nameLength)
{
    if (COMMON_NAME_MAX_LENGTH >= nameLength)
    {
        DIGI_MEMSET ((ubyte *) g_IKECertCommonName, 0x00, COMMON_NAME_MAX_LENGTH);
        DIGI_MEMCPY ((ubyte *) g_IKECertCommonName, pName, nameLength);
    }
    else
    {
        printf ("argument given to --eap_server_commonname is too long\n");
    }
}
#endif
/* used in setIKECertStore */
extern ikeSettings m_ikeOptSettings;

#ifdef __ENABLE_DIGICERT_EAP_PEER__
extern intBoolean m_bEapProtoPeer;
#endif

static ubyte*
getIKEFullPath(const sbyte* name, ubyte** buffer)
{
    int len;
    int certLen, nameLen;

    /* clean up */
    if (*buffer)
        FREE(*buffer);

    certLen = DIGI_STRLEN(sCertPath);
    nameLen = DIGI_STRLEN(name);

#if (!defined (__RTOS_VXWORKS__) && !defined (__RTOS_OSE__) && !defined(__RTOS_WIN32__))
    /* What size? */
    len = certLen;
    len += 1;
    len += nameLen;
    len += 1;

    /* Create concatenated string */
    *buffer = MALLOC(len);
    DIGI_MEMCPY(*buffer, sCertPath, certLen);
    (*buffer)[certLen] = '/';
    DIGI_MEMCPY((*buffer)+certLen+1, name, nameLen);
    (*buffer)[certLen+1+nameLen] = '\0';
#else
    /* Do not change! */
    len = nameLen;
    len += 1;

    /* Create duplicated string */
    *buffer = MALLOC(len);
    DIGI_MEMCPY(*buffer, name, nameLen);
    (*buffer)[nameLen] = '\0';
#endif
    return *buffer;
}

static sbyte4
setIKECertStore()
{
    ubyte*  pLeaf = NULL;
    ubyte4  leafLen = 0;
#ifdef __ENABLE_DIGICERT_EAP_TLS__
    certDistinguishedName *pLeafDN;
#endif
#ifdef __ENABLE_DIGICERT_DER_CONVERSION__
    ubyte*  pDerKey = NULL;
    ubyte4  derKeyLen;
#endif
    ubyte*  pKeyBlob = NULL;
    ubyte4  keyBlobLen;
    SizedBuffer certificates[2];
    ubyte4  numCertificate;
    sbyte4  i,j;
    MSTATUS status = OK;
    ubyte*  fullPath = NULL;
    certDescriptor caDescr[COUNTOF(sRootCerts)] = {{ NULL }};
    AsymmetricKey asymKey = {0};
    hwAccelDescr    hwAccelCtx;
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
        ubyte4 verify = 0;
        intBoolean fileExists;
#endif

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_IKE, &hwAccelCtx)))
        goto nocleanup;

    /*Initialize Cert Store*/
    if (OK > (status = CERT_STORE_createStore(&g_pIKECertStore)))
        goto exit;

    /*Populate cert store with root certificates*/
    for (i = 0, j = 0 ; j < (sbyte4) COUNTOF(sRootCerts); ++j)
    {
        /*Read root certs*/
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
        if (OK > (status = DIGICERT_readSignedFile((const char*)getIKEFullPath((sbyte*)sRootCerts[j].fileName, &fullPath),
                                           &sRootCerts[j].certData,
                                           &sRootCerts[j].certLength, TRUE)))
#else
        if (OK > (status = DIGICERT_readFile((const char*)getIKEFullPath((sbyte*)sRootCerts[j].fileName, &fullPath),
                                           &sRootCerts[j].certData,
                                           &sRootCerts[j].certLength)))
#endif
        {
            if (fullPath)
                FREE(fullPath);
            fullPath = NULL;
            continue;
        }

        status = CA_MGMT_verifyCertDate(sRootCerts[j].certData, sRootCerts[j].certLength);
        if (OK != status)
        {
            DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_CERT_UTILS: CA_MGMT_verifyCertDate() failed, status = ", status);
            goto exit;
        }

        /*Add root certs as trust points*/
        if (OK > (status = CERT_STORE_addTrustPoint(g_pIKECertStore,
                                                    sRootCerts[j].certData,
                                                    sRootCerts[j].certLength)))
        {
            DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_CERT_UTILS: CERT_STORE_addTrustPoint() failed, status = ", status);
            goto exit;
        }
        caDescr[i].pCertificate = sRootCerts[j].certData;
        caDescr[i++].certLength = sRootCerts[j].certLength;

        if (fullPath)
        {
            FREE(fullPath);
            fullPath = NULL;
        }

    }

    /* call IKE_initTrustAnchor() */
    if (i)
    {
        DEBUG_PRINTNL(DEBUG_EAP_EXAMPLE, (sbyte *)"Initialize IKE trust anchor(s)");
        if (OK > (status = IKE_initTrustAnchor((certDescriptor*)&caDescr, i)))
        {
            DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_CERT_UTILS: IKE_initTrustAnchor() failed, status = ", status);
        }
    }

#ifdef __ENABLE_DIGICERT_EAP_TLS__
    /* get server certificate Subject's Common Name */
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
    status = DIGICERT_readSignedFile((const char*)getIKEFullPath((sbyte*)SERVER_CERT_DER_FILE, &fullPath), &pLeaf, &leafLen, TRUE);
#else
    status = DIGICERT_readFile((const char*)getIKEFullPath((sbyte*)SERVER_CERT_DER_FILE, &fullPath), &pLeaf, &leafLen);
#endif
    if (OK > status )
    {
#if defined(__ENABLE_DIGICERT_EAP_AUTH__)
        DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_CERT_UTILS: SERVER_CERT_DER_FILE failed, status = ", status);
        goto exit;
#endif
    }
    else
    {
        if (OK > (status = CA_MGMT_allocCertDistinguishedName(&pLeafDN)))
        {
            DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_CERT_UTILS: CA_MGMT_allocCertDistinguishedName() failed, status = ", status);
        }
        else
        {
            if (OK > (status = CA_MGMT_extractCertDistinguishedName(pLeaf, leafLen, TRUE, pLeafDN)))
            {
                DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_CERT_UTILS: CA_MGMT_extractCertDistinguishedName() failed, status = ", status);
            }
            else
            {
                relativeDN *dn = pLeafDN->pDistinguishedName;
                for (i = pLeafDN->dnCount; i > 0; i--, dn++)
                {
                    nameAttr *na = dn->pNameAttr;
                    for (j = dn->nameAttrCount; j > 0; j--, na++)
                    {
                        if (EqualOID(commonName_OID, na->oid)) /* found */
                        {
#ifndef __ENABLE_DIGICERT_EAP_PEER__
                            ubyte4 len = (255 < na->valueLen) ? 255 : na->valueLen;
                            DIGI_MEMCPY((ubyte *)g_IKECertCommonName, na->value, len);
                            g_IKECertCommonName[len] = 0;
#endif
                            i = 1; /* to break the outer loop */
                            break;
                        }
                    }
                }
            }
            CA_MGMT_freeCertDistinguishedName(&pLeafDN);
        }
    }
#ifdef __ENABLE_DIGICERT_EAP_PEER__
    if (pLeaf)
    {
        FREE(pLeaf); pLeaf = NULL;
    }
#endif
    if (fullPath)
    {
        FREE(fullPath);
        fullPath = NULL;
    }
#endif /* __ENABLE_DIGICERT_EAP_TLS__ */

#if !defined(__ENABLE_DIGICERT_EAP_TLS__) || defined(__ENABLE_DIGICERT_EAP_PEER__)
    /* read all of the data in... */
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
    status = DIGICERT_readSignedFile((const char*)getIKEFullPath((sbyte*)CERTIFICATE_DER_FILE, &fullPath), &pLeaf, &leafLen, TRUE);
#else
    status = DIGICERT_readFile((const char*)getIKEFullPath((sbyte*)CERTIFICATE_DER_FILE, &fullPath), &pLeaf, &leafLen);
#endif
    if (OK > status)
    {
#if !defined(__ENABLE_DIGICERT_EAP_PEER__)
        DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_CERT_UTILS: CERTIFICATE_DER_FILE failed, status = ", status);
#else
        if (TRUE == m_bEapProtoPeer)
        {
            if ((EAP_PROTO_TLS == m_ikeOptSettings.eapProtoPeer) || (EAP_PROTO_TTLS == m_ikeOptSettings.eapProtoPeer))
            {
                DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_CERT_UTILS: CERTIFICATE_DER_FILE failed, status = ", status);
            }
        }
        else
        {
            DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_CERT_UTILS: CERTIFICATE_DER_FILE failed, status = ", status);
        }
#endif
        goto exit;
    }

    if (fullPath)
    {
        FREE(fullPath);
        fullPath = NULL;
    }

#endif

#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
   if (0 > (status = DIGICERT_readFileEx((const char*)getIKEFullPath((sbyte*)HOST_KEYS, &fullPath),
                                      &pKeyBlob, &keyBlobLen, TRUE)))
#else
   if (0 > (status = DIGICERT_readFile((const char*)getIKEFullPath((sbyte*)HOST_KEYS, &fullPath),
                                      &pKeyBlob, &keyBlobLen)))
#endif
#ifdef __ENABLE_DIGICERT_DER_CONVERSION__
    {
        if (fullPath)
        {
            FREE(fullPath);
            fullPath = NULL;
        }
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
        if (OK > (status = DIGICERT_readFileEx((const char*)getIKEFullPath((sbyte*)HOST_KEYS_DER_FILE, &fullPath), &pDerKey, &derKeyLen, TRUE)))
        {
            DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_CERT_UTILS: HOST_KEYS_DER_FILE failed, status = ", status);
            goto exit;
        }
#else
        if (OK > (status = DIGICERT_readFile((const char*)getIKEFullPath((sbyte*)HOST_KEYS_DER_FILE, &fullPath), &pDerKey, &derKeyLen)))
        {
            DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_CERT_UTILS: HOST_KEYS_DER_FILE failed, status = ", status);
            goto exit;
        }
#endif

        status = CRYPTO_initAsymmetricKey(&asymKey);
        if (OK != status)
            goto exit;

        status = CRYPTO_deserializeAsymKey(MOC_ASYM(hwAccelCtx) pDerKey, derKeyLen, NULL, &asymKey);
        if (OK != status)
            goto exit;

        status = CRYPTO_serializeAsymKey(MOC_ASYM(hwAccelCtx) &asymKey, mocanaBlobVersion2, &pKeyBlob,
            &keyBlobLen);
        if (OK != status)
            goto exit;
    }
    else
    {
        /* convert and write out Digicert key blob into DER file, if it doesn't exist */
        ubyte *pDerKeyTemp = NULL;
        ubyte4 derKeyLenTemp;
        if (fullPath)
        {
            FREE(fullPath);
            fullPath = NULL;
        }

#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
        status = DIGICERT_readFileEx((const char*)getIKEFullPath((sbyte*)HOST_KEYS_DER_FILE, &fullPath),
                                  &pDerKeyTemp, &derKeyLenTemp, TRUE);
#else
        status = DIGICERT_readFile((const char*)getIKEFullPath((sbyte*)HOST_KEYS_DER_FILE, &fullPath),
                                  &pDerKeyTemp, &derKeyLenTemp);
#endif
        if ((OK > status) &&
            (OK == CA_MGMT_keyBlobToDER(pKeyBlob, keyBlobLen, &pDerKeyTemp, &derKeyLenTemp)))
        {
            if (fullPath)
            {
                FREE(fullPath);
                fullPath = NULL;
            }
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
            DIGICERT_writeFileEx((const char *)getIKEFullPath((sbyte*)HOST_KEYS_DER_FILE, &fullPath),
                             pDerKeyTemp, derKeyLenTemp, TRUE);
#else
            DIGICERT_writeFile((const char *)getIKEFullPath((sbyte*)HOST_KEYS_DER_FILE, &fullPath),
                             pDerKeyTemp, derKeyLenTemp);
#endif
        }
        if (pDerKeyTemp) FREE(pDerKeyTemp);
    }
#else
    {
        DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_CERT_UTILS: HOST_KEYS failed, status = ", status);
        goto exit;
    }
#endif

    certificates[0].data = pLeaf;
    certificates[0].length = leafLen;
    numCertificate = 1;

    if (OK > (status = CERT_STORE_addIdentityWithCertificateChain(g_pIKECertStore, certificates, numCertificate, pKeyBlob, keyBlobLen)))
    {
        DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_CERT_UTILS: CERT_STORE_addIdentityWithCertificateChain() failed, status = ", status);
        goto exit;
    }

    g_IKECert.pCertificate = pLeaf;
    g_IKECert.certLength = leafLen;
    pLeaf = NULL;
    g_IKECert.pKeyBlob = pKeyBlob;
    g_IKECert.keyBlobLength = keyBlobLen;
    pKeyBlob = NULL;

exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_IKE, &hwAccelCtx);

    if (fullPath)
        FREE(fullPath);

    if (pLeaf)
        FREE(pLeaf);

    if (pKeyBlob)
        FREE(pKeyBlob);

#ifdef __ENABLE_DIGICERT_DER_CONVERSION__
    if (pDerKey)
        FREE(pDerKey);
#endif
nocleanup:
    return status;
}

static sbyte4
freeIKECertStore()
{
    CERT_STORE_releaseStore(&g_pIKECertStore);
    return 0;
}


/*------------------------------------------------------------------*/

static void
setIKECertParameter(sbyte ** param, char *value)
{
    int l = DIGI_STRLEN((const sbyte*)value);
    *param = (sbyte*)MALLOC(l+1);
    DIGI_MEMCPY(*param, value, l);
    (*param)[l] = '\0';
}

extern void
setIKETapConfig(char *pConfig);

extern void
IKE_CERT_UTILS_getArgs(int argc, char *argv[])
{
    int i;
    int pathSet;

    pathSet = 0;

    for (i = 1; i < argc; i++) /*Skiping argv[0] which is example progam name*/
    {
        if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-ike_certPath") == 0)
        {
            pathSet = 1; /* Path should not be set to default*/
            i++;
            setIKECertParameter(&sCertPath, argv[i]);
            continue;
        }
#ifdef __ENABLE_DIGICERT_TAP__
        else if (DIGI_STRCMP((const sbyte *) argv[i], (const sbyte *)"--tap_config_file") == 0)
        {
            i++;
            setIKETapConfig(argv[i]);
        }
#endif
    }
    if (!pathSet)
    {
        setIKECertParameter(&sCertPath, ".");
    }
}

extern void
IKE_CERT_UTILS_initStore()
{
    setIKECertStore();
}

extern void
IKE_CERT_UTILS_freeStore()
{
    freeIKECertStore();

    if (sCertPath)
    {
        FREE(sCertPath);
    }
}

#endif /* (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__) */
#endif /* __ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__ */

