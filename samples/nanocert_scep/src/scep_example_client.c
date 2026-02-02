/**
 * @file  scep_example_client.c
 * @brief SCEP Example Client Sample Application
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

#include "../common/moptions.h"

#if defined( __ENABLE_DIGICERT_SCEPC__ )
#if (defined(__ENABLE_DIGICERT_EXAMPLES__) || defined(__ENABLE_DIGICERT_BIN_EXAMPLES__))

#include "../common/mtypes.h"
#include "../common/mlimits.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/mfmgmt.h"
#include "../common/debug_console.h"
#include "../common/tree.h"
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../common/vlong.h"
#include "../common/random.h"
#include "../crypto/rsa.h"
#if (defined(__ENABLE_DIGICERT_DSA__))
#include "../crypto/dsa.h"
#endif
#include "../common/uri.h"
#include "../asn1/oiddefs.h"
#include "../crypto/crypto.h"
#if (defined(__ENABLE_DIGICERT_ECC__))
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#endif
#include "../common/base64.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/keyblob.h"
#include "../asn1/parseasn1.h"
#include "../asn1/derencoder.h"
#include "../crypto/pkcs_common.h"
#include "../crypto/pkcs7.h"
#include "../crypto/pkcs10.h"
#include "../crypto/cert_store.h"
#include "../crypto/asn1cert.h"
#include "../crypto/crypto_utils.h"
#include "../http/http_context.h"
#include "../http/http.h"
#include "../http/http_common.h"
#include "../http/client/http_request.h"
#include "../common/mtcp.h"
#include "../asn1/parsecert.h"
#include "../scep/scep.h"
#include "../scep/scep_utils.h"
#include "../scep/scep_context.h"
#include "../scep/scep_client.h"
#include "../scep/scep_message.h"
#ifdef __ENABLE_DIGICERT_TAP__
#include "../tap/tap.h"
#include "../crypto/mocasym.h"
#include "../crypto/mocasymkeys/tap/rsatap.h"
#include "../crypto/mocasymkeys/tap/ecctap.h"
#include "../crypto_interface/cryptointerface.h"
#endif

/* Include data structures which may be initialized for systems that do not support file io */
#include "scep_example_client.h"

/*------------------------------------------------------------------*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define SCEP_ADDR_BUFFER 100
#define PKI_OPERATION_ENROLL "enroll"
#define PKI_OPERATION_RENEW  "renew"
#define PKI_OPERATION_REKEY  "rekey"
#define PKI_OPERATION_GETCACERT "getcacert"
#define MAX_FILE_NAME 256
#define POLL_INTERVAL        3000
#define POLL_COUNT           10

/* TAP key usage enumerations */
#define SCEPC_TAP_KEY_USAGE_SIGNING  "SIGNING"
#define SCEPC_TAP_KEY_USAGE_DECRYPT  "DECRYPT"
#define SCEPC_TAP_KEY_USAGE_GENERAL  "GENERAL"
#define SCEPC_TAP_KEY_USAGE_ATTEST   "ATTEST"

/* TAP signing scheme enumerations */
#define SCEPC_TAP_SIG_SCHEME_NONE            "NONE"
#define SCEPC_TAP_SIG_SCHEME_PKCS1_5         "PKCS1_5"
#define SCEPC_TAP_SIG_SCHEME_PSS_SHA1        "PSS_SHA1"
#define SCEPC_TAP_SIG_SCHEME_PSS_SHA256      "PSS_SHA256"
#define SCEPC_TAP_SIG_SCHEME_PKCS1_5_SHA1    "PKCS1_5_SHA1"
#define SCEPC_TAP_SIG_SCHEME_PKCS1_5_SHA256  "PKCS1_5_SHA256"
#define SCEPC_TAP_SIG_SCHEME_PKCS1_5_DER     "PKCS1_5_DER"
#define SCEPC_TAP_SIG_SCHEME_ECDSA_SHA1      "ECDSA_SHA1"
#define SCEPC_TAP_SIG_SCHEME_ECDSA_SHA224    "ECDSA_SHA224"
#define SCEPC_TAP_SIG_SCHEME_ECDSA_SHA256    "ECDSA_SHA256"
#define SCEPC_TAP_SIG_SCHEME_ECDSA_SHA384    "ECDSA_SHA384"
#define SCEPC_TAP_SIG_SCHEME_ECDSA_SHA512    "ECDSA_SHA512"

/* TAP encryption scheme enumerations */
#define SCEPC_TAP_ENC_SCHEME_NONE            "NONE"
#define SCEPC_TAP_ENC_SCHEME_PKCS1_5         "PKCS1_5"
#define SCEPC_TAP_ENC_SCHEME_OAEP_SHA1       "OAEP_SHA1"
#define SCEPC_TAP_ENC_SCHEME_OAEP_SHA256     "OAEP_SHA256"

/*------------------------------------------------------------------*/
/* request params for certificate enrollment PKCSReq */
nameAttr pNames1[] =
{
    {countryName_OID, 0, (ubyte*)"US", 2}                                /* country */
};
nameAttr pNames2[] =
{
    {stateOrProvinceName_OID, 0, (ubyte*)"California", 10}               /* state or providence */
};
nameAttr pNames3[] =
{
    {localityName_OID, 0, (ubyte*)"San Francisco", 13}                   /* locality */
};
nameAttr pNames4[] =
{
    {organizationName_OID, 0, (ubyte*)"Mocana Corporation", 18}          /* company name */
};
nameAttr pNames5[] =
{
    {organizationalUnitName_OID, 0, (ubyte*)"Engineering", 11}           /* organizational unit */
};
nameAttr pNames6[] =
{
#ifdef __DIGICERT_USE_WEBAPPTAP_CNAME__ /* for demo use only */
    {commonName_OID, 0, (ubyte*)"webapptap.securitydemos.net", 27}                        /* common name */
#else
	{commonName_OID, 0, (ubyte*)"scepclient", 10}                        /* common name */
#endif
};

relativeDN pRDNs[] =
{
    {pNames1, 1},
    {pNames2, 1},
    {pNames3, 1},
    {pNames4, 1},
    {pNames5, 1},
    {pNames6, 1}
};

certDistinguishedName gCertInfo =
{
    pRDNs, 6,
/* Note: Internet Explorer limits a 30 year lifetime for certificates */

                                                /* time format yymmddhhmmss */
    (sbyte *)"161019000126Z",                   /* certificate start date */
    (sbyte *)"261018230126Z"                    /* certificate end date */

/* above start example, Oct 19th, 2006 12:01:26 AM */
/* above end example, Oct 18th, 2016 11:01:26 PM */

};

/* certificate extensions for certificate enrollment request */
certExtensions gExts =
{
        1, /* has basicconstraint */
        1, /* isCA? */
        5, /* certPathLen */
        1, /* has keyUsage */
        15, /* keyUsage */
        NULL,
        0
};
/* certificate enrollment request attributes as defined in PKCS #9 */
requestAttributes gReqAttrs =
{
    /* challengePassword */
    (sbyte *) "password", 8,  /* for Digicert SCEP server */
    /* certExtensions */
    &gExts
};

/* request params for GetCACert, GetCACertChain, GetCACaps.
 * EJBCA requires this to be the same as the CA common name;
 * while Microsoft SCEP add on doesn't seem to take this into consideration. */
caIdent gCaIdent =
{
    (ubyte *)"ca",
    2
};

//************************************************************************************
/* windows SCEP addon RA subject name */

nameAttr pRANames1[] =
{
    {countryName_OID, 0, (ubyte*)"US", 2}                           /* country */
};
nameAttr pRANames6[] =
{
    {commonName_OID, 0, (ubyte*)"ca", 2}                            /* country */
};
relativeDN pRARDNs[] =
{
    {pRANames1, 1},
    {pRANames6, 1}
};

certDistinguishedName gCAOrRACertInfo =
{
    pRARDNs, 2,
    /* Note: Internet Explorer limits a 30 year lifetime for certificates */

    /* time format yymmddhhmmss */
    (sbyte*)"120619113315Z",                            /* certificate start date */
    (sbyte*)"170619114313Z"                             /* certificate end date */

    /* above start example, June 19th, 2012 11:33:15 AM */
    /* above end example, June 19th, 2017 11:43:13 PM */

};

/*------------------------------------------------------------------*/

/* Command line arguments.  Default values are used where command line parameters are not provided */
/* The user is respnsible for setting the required default values.                                 */

sbyte* pChallengePass       = NULL;

sbyte* caCertFileName       = NULL;   /* CA certificate. For Windows NDES is the RA(SCEP server) use the RA cert with key usage Digital signature */
sbyte* adminCertFileName    = NULL;   /* Admin certificate. */
sbyte* cepCertFileName      = NULL;   /* SCEP-Addon/RA Certificate - CEP Encryption */
sbyte* exchangeCertFileName = NULL;   /* RA Certificate that is the Enrollment Agent */
sbyte* pScepServerUrl       = NULL;
sbyte* filePath             = NULL;

ubyte* serverTypeStr = NULL;

/* Paths from tpconf.json */
static sbyte* scepc_certPath = NULL;      /* keystore directory path */
static sbyte* scepc_truststorePath = NULL; /* truststore directory path */
static sbyte* scepc_confPath = NULL;       /* conf directory path */
static sbyte* scepc_http_proxy = NULL;     /* http proxy URL */
/* Existing certificate received via enrollment */
sbyte *pOldCertFile = NULL;
/* Private key used for enrollment */
sbyte *pOldPemKeyFile = NULL;
/* Holds PKI Operation enroll, renew or rekey */
sbyte *pPkiOperation = NULL;

static ubyte role = USER;
/*-------------------------------------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_TAP__
#ifdef __RTOS_WIN32__
#define TPM2_CONFIGURATION_FILE        "tpm2.conf"
#define TPM12_CONFIGURATION_FILE       "tpm12.conf"
#define PKCS11_CONFIGURATION_FILE      "pkcs11_smp.conf"
#define TEE_CONFIGURATION_FILE         "tee_smp.conf"
#else
#define TPM2_CONFIGURATION_FILE        "/etc/digicert/tpm2.conf"
#define TPM12_CONFIGURATION_FILE       "/etc/digicert/tpm12.conf"
#define PKCS11_CONFIGURATION_FILE      "/etc/digicert/pkcs11_smp.conf"
#define TEE_CONFIGURATION_FILE         "/etc/digicert/tee_smp.conf"
#endif
#define SCEP_DEF_TAP_MODULEID           1

static ubyte2		   pScepTapModuleId	   = 0;
static sbyte * 		   pScepTapConfFile   = NULL;
static ubyte2          pScepTapProvider    = 0;
static byteBoolean     pScepTapKeySourceRuntime = FALSE;
/*
    Referenced from - tap_smp.h
    TAP KeyUsage
    0 = TAP_KEY_USAGE_UNDEFINED
    1 = TAP_KEY_USAGE_SIGNING
    2 = TAP_KEY_USAGE_DECRYPT
    3 = TAP_KEY_USAGE_GENERAL
    TODO below need to suported.
    4 = TAP_KEY_USAGE_ATTESTATION
    5 = TAP_KEY_USAGE_STORAGE
*/
static ubyte2          pScepTapKeyUsage   = TAP_KEY_USAGE_UNDEFINED;
/**
 *  Referenced from - tap_smp.h
 *  Supported Encryption schemes
 *   0 - TAP_ENC_SCHEME_NONE
 *   1 - TAP_ENC_SCHEME_PKCS1_5
 *   2 - TAP_ENC_SCHEME_OAEP_SHA1
 *   3 - TAP_ENC_SCHEME_OAEP_SHA256
 */
static ubyte2          pScepTapEncScheme  = TAP_ENC_SCHEME_NONE;
/**
 *  Referenced from - tap_smp.h
 *  Supported Signing schemes
 *  0 - TAP_SIG_SCHEME_NONE
 *  1 - TAP_SIG_SCHEME_PKCS1_5
 *  2 - TAP_SIG_SCHEME_PSS_SHA1
 *  3 - TAP_SIG_SCHEME_PSS_SHA256
 *  4 - TAP_SIG_SCHEME_PKCS1_5_SHA1
 *  5 - TAP_SIG_SCHEME_PKCS1_5_SHA256
 *  6 - TAP_SIG_SCHEME_PKCS1_5_DER
 *  7 - TAP_SIG_SCHEME_ECDSA_SHA1
 *  8 - TAP_SIG_SCHEME_ECDSA_SHA224
 *  9 - TAP_SIG_SCHEME_ECDSA_SHA256
 * 10 - TAP_SIG_SCHEME_ECDSA_SHA384
 * 11 - TAP_SIG_SCHEME_ECDSA_SHA512
 */
static ubyte2          pScepTapSignScheme = TAP_SIG_SCHEME_NONE;
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
static sbyte *         pScepTapServerName  = NULL;
static ubyte4          pScepTapServerPort  = -1;
#endif
static sbyte *         pScepTapKeyPassword = NULL;
#endif /*__ENABLE_DIGICERT_TAP__*/

#if defined(__ENABLE_DIGICERT_TAP__)
static signed char * scepc_keySource = NULL;
#endif

static sbyte* scepc_keyType = NULL;
static sbyte* scepc_confFile = NULL;
static ubyte2 scepc_keySize  = SCEPC_DEF_KEYSIZE;

static ubyte serverType = DEF_SCEP_SERVER_TYPE;
static byteBoolean supportsPost = TRUE; /* Default to TRUE, change to FALSE if Windows server */
static byteBoolean scep_getArgs_called    = 0; /* In case we need to know this was done (in main) */


#if defined(__ENABLE_DIGICERT_TAP__)
TAP_Context *g_pTapContext;
TAP_EntityCredentialList *g_pEntityCredentialList;
TAP_CredentialList *g_pKeyCredentialList = NULL;

sbyte4 gUseTap = 0;
#endif

static void setStringParameter(char ** param, char *value);
static void setFilePath(sbyte *path, sbyte **fname);
static void setFullPath(sbyte *fname, sbyte *path, sbyte **fpath);

#define SCEP_TCP_READ_BUFFER 512
/*------------------------------------------------------------------*/

pFuncPtrGetScepData g_pFuncPtrGetScepData = NULL;

/*------------------------------------------------------------------*/
    /* SCEP Callback Functions */
/*------------------------------------------------------------------*/

static sbyte4 myCertificateStoreLookup(void* reserved,
                                       struct certDistinguishedName *pLookupCertDN,
                                       struct certDescriptor *pReturnCert)
{
    /* For GetCACert operation, we don't need to look up any certificates */
    /* Just return a dummy certificate descriptor */
    if (pReturnCert)
    {
        pReturnCert->pCertificate = NULL;
        pReturnCert->certLength = 0;
    }
    return OK;
}

static sbyte4 myCertificateStoreRelease(void* reserved,
                                        struct certDescriptor *pFreeCert)
{
    return OK;
}

static sbyte4 myKeyPairLookup(void* reserved,
                              struct certDistinguishedName *pLookupKeyDN,
                              ubyte** keyBlob,
                              ubyte4* keyBlobLen,
                              ubyte** signKeyBlob,
                              ubyte4* signKeyBlobLen,
                              intBoolean *pKeyRequired)
{
    if (pKeyRequired)
        *pKeyRequired = FALSE;
    if (keyBlob)
        *keyBlob = NULL;
    if (keyBlobLen)
        *keyBlobLen = 0;
    if (signKeyBlob)
        *signKeyBlob = NULL;
    if (signKeyBlobLen)
        *signKeyBlobLen = 0;
    return OK;
}

/*------------------------------------------------------------------*/

static MSTATUS backupOldFile(const sbyte* pFileName)
{
    MSTATUS status = OK;
    sbyte* pBackupName = NULL;
    ubyte* pFileData = NULL;
    ubyte4 fileSize = 0;

    if (NULL == pFileName)
    {
        return ERR_NULL_POINTER;
    }

    if (OK != DIGICERT_readFile((const char*)pFileName, &pFileData, &fileSize))
    {
        /* File doesn't exist, no backup needed */
        return OK;
    }

    if (pFileData)
    {
        DIGI_FREE((void**)&pFileData);
    }

    ubyte4 nameLen = DIGI_STRLEN(pFileName) + 5; /* +5 for ".old\0" */
    if (OK != (status = DIGI_MALLOC((void**)&pBackupName, nameLen)))
    {
        goto exit;
    }



    sbyte4 ret = snprintf((char*)pBackupName, nameLen, "%s.old", pFileName);
    if (ret < 0 ||ret >= nameLen)
    {
        status = ERR_BUFFER_OVERFLOW;
        goto exit;
    }

    if (OK > (status = DIGICERT_readFile((const char*)pFileName, &pFileData, &fileSize)))
    {
        goto exit;
    }

    status = DIGICERT_writeFile((const char*)pBackupName, pFileData, fileSize);
    if (OK == status)
    {
        DEBUG_PRINT2(DEBUG_SCEP_EXAMPLE, "\nCreated backup: ", pBackupName);
        DEBUG_PRINT(DEBUG_SCEP_EXAMPLE, "\n");
    }

exit:
    if (pBackupName)
    {
        DIGI_FREE((void**)&pBackupName);
    }
    if (pFileData)
    {
        DIGI_FREE((void**)&pFileData);
    }

    return status;
}

/*------------------------------------------------------------------*/
    /* PKCS7 Callbacks */
/*------------------------------------------------------------------*/
static MSTATUS myValCertFun(const void* arg,
							CStream cs,
							struct ASN1_ITEM* pCertificate,
							sbyte4 chainLength)
{
    return OK;
}

/*------------------------------------------------------------------*/

/* this callback is used to load CA certificates */
/* ppCertificate will be released by the PKCS7 stack */
static MSTATUS myGetCertFun(const void* arg,CStream cs,
                            ASN1_ITEM* pSerialNumber,
                            ASN1_ITEM* pIssuerName,
                            ubyte  **ppCertificate,
                            ubyte4 *pcertificateLen)
{
    MSTATUS status = OK;
    SCEP_data *pScepData = NULL;

    if (OK > (status = g_pFuncPtrGetScepData(&pScepData)))
    {
        goto exit;
    }

    if (OK != (status = DIGI_CALLOC((void**)ppCertificate, 1, pScepData->exchangerCertLen)))
    {
        goto exit;
    }
    if (OK != (status = DIGI_MEMCPY((ubyte*)*ppCertificate, pScepData->pExchangerCertificate, pScepData->exchangerCertLen)))
    {
        goto exit;
    }
    *pcertificateLen = pScepData->exchangerCertLen;
exit:
    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS deserializePemKey(ubyte *pPemKeyBlob, ubyte4 pemKeyBlobLen, AsymmetricKey *pKey)
{
    MSTATUS  status = OK;
    ubyte *pDatKeyBlob = NULL;


    if ( (NULL == pPemKeyBlob) || (NULL == pKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    if (OK > (status = CRYPTO_initAsymmetricKey (pKey)))
    {
        goto exit;
    }

    status = CRYPTO_deserializeAsymKey(
        pPemKeyBlob, pemKeyBlobLen, NULL, pKey);
    if (OK != status)
        goto exit;

exit:
    if (pDatKeyBlob != NULL) DIGI_FREE((void**)&pDatKeyBlob);
    if (OK != status)
        CRYPTO_uninitAsymmetricKey(pKey, NULL);
    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS myGetPrivateKeyFun(const void* arg,CStream cs,
                                        ASN1_ITEM* pSerialNumber,
                                        ASN1_ITEM* pIssuerName,
                                        AsymmetricKey* pKey)
{
    MSTATUS status = OK;
    SCEP_data *pScepData = NULL;

    if (OK > (status = g_pFuncPtrGetScepData(&pScepData)))
    {
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_TAP__
    /* Check if the pem keyblob is a tapkey. if not then fallback to sw key */
    if (OK > (status = CRYPTO_deserializeAsymKey(
        pScepData->pPemKeyBlob, pScepData->pemKeyBlobLen, NULL, pKey)))
    {
        if (OK > (status = deserializePemKey(pScepData->pPemKeyBlob, pScepData->pemKeyBlobLen, pKey)))
        {
            goto exit;
        }
    }
#else
    /* This is a PEM key so use below code to convert it to asymkey */
    /* SW Key */
    if (OK > (status = deserializePemKey(pScepData->pPemKeyBlob, pScepData->pemKeyBlobLen, pKey)))
    {
        goto exit;
    }

#endif


exit:
    return status;
}

/*------------------------------------------------------------------*/
    /* Static Functions */
/*------------------------------------------------------------------*/
static MSTATUS
SCEP_SAMPLE_updateCertDistinguishedName(nameAttr** pPnameAttr, int nameAttrLen, certDistinguishedName **ppDest)
{
	MSTATUS    status         = OK;
	ubyte4     rdnOffset      = 0;
	ubyte4     tempRdnOffset  = 0;
	relativeDN *pRDN          = NULL;
    nameAttr   *pNameAttr     = NULL;
    ubyte4 found = 0;
	relativeDN *newRDN = NULL;
	certDistinguishedName *pDest = NULL;

    if (ppDest == NULL)
    {
        status = ERR_NULL_POINTER;
        return status;
    }

    if (nameAttrLen == 0 || pPnameAttr == NULL)
    {
        return OK;
    }
    if (OK > (status = CA_MGMT_allocCertDistinguishedName(&pDest)))
    {
        goto exit;
    }
    if (OK > (status = DIGI_CALLOC((void**)&(pDest->pDistinguishedName), 1, nameAttrLen * sizeof(relativeDN))))
    {
        goto exit;
    }

	rdnOffset = 0;
    /**
     * Override the pDest values(default values) with pPnameAttr(Attributes from configuration file).
     * If some attributes were missing in configuration file, use default values.
     * If both contains the same attribute then use the attributes values from configuration file.
     *
     */
	for (pNameAttr = pPnameAttr[rdnOffset]; rdnOffset < nameAttrLen; pNameAttr = pPnameAttr[rdnOffset])
	{
        /* Outer  loop to loop through the attributes from configuration file */
        tempRdnOffset = 0;
	    for (pRDN = pDest->pDistinguishedName+tempRdnOffset; tempRdnOffset < pDest->dnCount; pRDN = pDest->pDistinguishedName+tempRdnOffset)
        {
            /* This loop is to find if the match is found from the default attributes (pDest)
             * If match is found then free it and assign the attributes from configuration file */
            nameAttr *pNameComponent;
            ubyte4 j = 0;
            found = 0;
            for (pNameComponent = pRDN->pNameAttr;
                j < pRDN->nameAttrCount; pNameComponent = pRDN->pNameAttr + j)
            {
                /* This loop is to verify if same attribute oid is present */
                if (0 == DIGI_STRCMP((const sbyte *)pNameComponent->oid, (const sbyte *)pNameAttr->oid))
                {
                    found = 1;
                    break;
                }
                j = j + 1;
            }
            if (found == 1)
            {
                /* if match is found then clean the memory and override the default one
                 * with the one specified in the configuration file
                 */
                j = 0;
                for (pNameComponent = pRDN->pNameAttr;
                    j < pRDN->nameAttrCount; pNameComponent = pRDN->pNameAttr + j)
                {
                    /* Don't free oid since oid is not an allocated memory */
			         if (pNameComponent->value && pNameComponent->valueLen > 0)
                     {
                         FREE(pNameComponent->value);
                     }
                     j = j + 1;
                }
                FREE(pRDN->pNameAttr);
                pRDN->pNameAttr = pNameAttr;
                pRDN->nameAttrCount = 1;
                break;
            }
            tempRdnOffset = tempRdnOffset +1;
        }
        if (0 == found)
        {
            /* No match found */
            pRDN = pDest->pDistinguishedName;
            newRDN = MALLOC((pDest->dnCount + 1)*sizeof(relativeDN));
            if (NULL == newRDN)
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }
            DIGI_MEMCPY(newRDN, 0x00, (pDest->dnCount + 1)*sizeof(relativeDN));
            DIGI_MEMCPY((void*)newRDN, (void*)pDest->pDistinguishedName, (pDest->dnCount)*sizeof(relativeDN));
            (&newRDN[pDest->dnCount])->pNameAttr = pNameAttr;
            (&newRDN[pDest->dnCount])->nameAttrCount = 1;
            FREE(pDest->pDistinguishedName);
            pDest->pDistinguishedName = newRDN;
            pDest->dnCount = pDest->dnCount + 1;
        }
		rdnOffset = rdnOffset + 1;
	}
	*ppDest = pDest;

exit:
	return status;

}


static MSTATUS
getServerTypeDetails(sbyte *pServerType, byteBoolean *pUsePost, ubyte4 *pServer)
{
    if (0 == DIGI_STRNICMP((const sbyte *)pServerType, (const sbyte *)MOC_SCEP_SERVER_STR,
                DIGI_STRLEN(pServerType))) {
        *pServer = MOC_SCEP_SERVER;
    }
    else if (0 == DIGI_STRNICMP((const sbyte *)pServerType, (const sbyte *)EJBCA_SCEP_SERVER_STR,
                DIGI_STRLEN(pServerType))) {
        *pServer = EJBCA_SCEP_SERVER;
    }
    else if (0 == DIGI_STRNICMP((const sbyte *)pServerType, (const sbyte *)ECDSA_SCEP_SERVER_STR,
                DIGI_STRLEN(pServerType))) {
        *pServer = ECDSA_SCEP_SERVER;
    }
    else if (0 == DIGI_STRNICMP((const sbyte *)pServerType, (const sbyte *)WIN2003_SCEP_SERVER_STR,
                DIGI_STRLEN(pServerType))) {
        *pServer = WIN2003_SCEP_SERVER;
        *pUsePost = FALSE;
    }
    else if (0 == DIGI_STRNICMP((const sbyte *)pServerType, (const sbyte *)WIN2008_SCEP_SERVER_STR,
                DIGI_STRLEN(pServerType))) {
        *pServer = WIN2008_SCEP_SERVER;
        *pUsePost = FALSE;
    }
    else if (0 == DIGI_STRNICMP((const sbyte *)pServerType, (const sbyte *)WIN2012_SCEP_SERVER_STR,
                DIGI_STRLEN(pServerType))) {
        *pServer = WIN2012_SCEP_SERVER;
        *pUsePost = FALSE;
    }
    else if (0 == DIGI_STRNICMP((const sbyte *)pServerType, (const sbyte *)WIN2016_SCEP_SERVER_STR,
                DIGI_STRLEN(pServerType))) {
        *pServer = WIN2016_SCEP_SERVER;
        *pUsePost = TRUE;
    }
    else if (0 == DIGI_STRNICMP((const sbyte *)pServerType, (const sbyte *)GEN_GET_SERVER_STR,
                                                       DIGI_STRLEN(pServerType))) {
        *pServer = GEN_GET_SERVER;
        *pUsePost = FALSE;
    }
    else if (0 == DIGI_STRNICMP((const sbyte *)pServerType, (const sbyte *)GEN_POST_SERVER_STR,
                                                       DIGI_STRLEN(pServerType))) {
        *pServer = GEN_POST_SERVER;
        *pUsePost = TRUE;
    }
    else {
        return -1;
    }

    return OK;
}

/*------------------------------------------------------------------*/

static MSTATUS
setSubjAltNameExtension(SubjectAltNameAttr *pAttrs, int numSans, extensions *pSubAltNameExt)
{
    MSTATUS          status     =  OK;
    DER_ITEMPTR      pRoot      =  NULL;
    ubyte           *pEncoded    =  NULL;
    ubyte4           encodedLen =  0;
    int              pos        =  0;
    ubyte           *pIps       = NULL;
    ubyte4           numIps     = 0;
    ubyte           *pIpPtr     = NULL;
    ubyte4           ipLen      = 0;

    if (OK > (status = DER_AddSequence(NULL, &pRoot)))
    {
        goto exit;
    }

    /* Form of ip addresses need conversion, first get a count of how many ip addresses */
    for (pos = 0; pos < numSans; pos++)
    {
        if (SubjectAltName_iPAddress == pAttrs[pos].subjectAltNameType)
        {
            numIps++;
        }
    }

    if (numIps)
    {
        /* allocate enough space for all v6 ips, 16 bytes each */
        status = DIGI_MALLOC((void **) &pIps, 16 * numIps);
        if (OK != status)
            goto exit;

        pIpPtr = pIps;
    }

    for (pos = 0; pos < numSans; pos++)
    {
        /* Convert IP addresses to raw byte form */
        if (SubjectAltName_iPAddress == pAttrs[pos].subjectAltNameType)
        {
            if (OK > (status = CA_MGMT_convertIpAddress(pAttrs[pos].subjectAltNameValue.data, pIpPtr, &ipLen)))
                goto exit;

            if (OK > (status = DER_AddItem(pRoot, (PRIMITIVE|CONTEXT|(&(pAttrs[pos]))->subjectAltNameType),
                                           ipLen, pIpPtr, NULL)))
                goto exit;

            /* move to the next spot in the array */
            pIpPtr += ipLen;
        }
        else
        {
            if (OK > (status = DER_AddItem(pRoot, (PRIMITIVE|CONTEXT|(&(pAttrs[pos]))->subjectAltNameType),
                                        (&(pAttrs[pos]))->subjectAltNameValue.dataLen,
                                        (&(pAttrs[pos]))->subjectAltNameValue.data, NULL)))
            {
                goto exit;
            }
        }
    }

    if (OK > (status = DER_Serialize(pRoot, &pEncoded, &encodedLen)))
    {
        goto exit;
    }
    pSubAltNameExt->oid = (ubyte*)subjectAltName_OID;
    pSubAltNameExt->isCritical = FALSE;
    pSubAltNameExt->value = pEncoded;
    pSubAltNameExt->valueLen = encodedLen;

exit:

    if (pRoot)
    {
        TREE_DeleteTreeItem((TreeItem*) pRoot);
    }


    if (pIps)
    {
        (void) DIGI_MEMSET_FREE(&pIps, 16 * numIps);
    }

    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS
SCEP_SAMPLE_createNameAttr(ubyte* oid, ubyte type, ubyte* value, ubyte4 valueLen, nameAttr **pPNameAttr)
{
    nameAttr *pNameAttr     = NULL;
    int      actualValueLen = 0;
    MSTATUS status = ERR_MEM_ALLOC_FAIL;

    pNameAttr = (nameAttr*)MALLOC(sizeof(nameAttr));
    if (pNameAttr)
    {
        DIGI_MEMSET((ubyte*) pNameAttr, 0x00, sizeof(nameAttr));
        pNameAttr->oid = oid;
        pNameAttr->type = type;

        if ('\n' == value[valueLen-1])
            actualValueLen = valueLen -1;
        else
            actualValueLen = valueLen;

        pNameAttr->value = (ubyte*)MALLOC(actualValueLen);
        DIGI_MEMCPY((void*)pNameAttr->value, (void*)value, actualValueLen);
        pNameAttr->valueLen = actualValueLen;

        *pPNameAttr = pNameAttr;
        status = OK;
    }

    return status;

}

/*------------------------------------------------------------------*/

static
MSTATUS SCEP_SAMPLE_initContext(scepContext **ppScepContext, void *pCookie,
#ifdef __ENABLE_DIGICERT_TAP__
                                  byteBoolean useTap,
#endif
#ifdef __ENABLE_DIGICERT_CMS_RSA_OAEP__
                                  ubyte isOaep, sbyte *pOaepLabel, ubyte4 oaepHashAlgo,
#endif
                                  ubyte *pPemKeyBlob, ubyte4 pemKeyBlobLen,
                                  ubyte *pOldPemKeyBlob, ubyte4 oldPemKeyBlobLen,
                                  struct certDescriptor pCACerts[], ubyte4 numCaCerts,
                                  struct certDescriptor pRACerts[], ubyte4 numRaCerts,
                                  struct certDescriptor *pRequesterCert)
{
    MSTATUS status = OK;
    pkcsCtxInternal *pPkcsCtxInt;

    if (OK > (status = SCEP_CONTEXT_createContext(ppScepContext, SCEP_CLIENT)))
        goto exit;

    pPkcsCtxInt = (*ppScepContext)->pPkcsCtx;

   /* initialize random generator and crypto algorithms */
    pPkcsCtxInt->rngFun = RANDOM_rngFun;
    pPkcsCtxInt->rngFunArg = g_pRandomContext;
    /* PKCS7 Callbacks */
    pPkcsCtxInt->callbacks.getPrivKeyFun = myGetPrivateKeyFun;
    pPkcsCtxInt->callbacks.valCertFun = myValCertFun;
    pPkcsCtxInt->callbacks.getCertFun = myGetCertFun;

    pPkcsCtxInt->digestAlgoOID = sha256_OID;
    pPkcsCtxInt->encryptAlgoOID = desEDE3CBC_OID;

#ifdef __ENABLE_DIGICERT_CMS_RSA_OAEP__
    pPkcsCtxInt->isOaep = isOaep;
    pPkcsCtxInt->pOaepLabel = pOaepLabel;
    pPkcsCtxInt->oaepHashAlgo = oaepHashAlgo;
#endif

    /* load the key */
#ifdef __ENABLE_DIGICERT_TAP__
    if (useTap)
    {
        status = CRYPTO_deserializeAsymKey(
            pPemKeyBlob, pemKeyBlobLen, NULL, &(pPkcsCtxInt->key));
        if (status < OK)
            goto exit;

        /* Old key */
        if (pOldPemKeyBlob != NULL)
        {
            status = CRYPTO_deserializeAsymKey(
                pOldPemKeyBlob, oldPemKeyBlobLen, NULL, &(pPkcsCtxInt->signKey));
            if (status < OK)
                goto exit;
        }
        else
        {
            status = CRYPTO_deserializeAsymKey(
                pPemKeyBlob, pemKeyBlobLen, NULL, &(pPkcsCtxInt->signKey));
            if (status < OK)
                goto exit;
        }
    }
    else
    {
#endif
        if (OK > (status = deserializePemKey(pPemKeyBlob, pemKeyBlobLen, &(pPkcsCtxInt->key))))
        {
            goto exit;
        }
        if (pOldPemKeyBlob != NULL)
        {
            if (OK > (status = deserializePemKey(pOldPemKeyBlob, oldPemKeyBlobLen, &(pPkcsCtxInt->signKey))))
            {
                goto exit;
            }
        }
        else
        {
            if (OK > (status = deserializePemKey(pPemKeyBlob, pemKeyBlobLen, &(pPkcsCtxInt->signKey))))
            {
                goto exit;
            }
        }

#ifdef __ENABLE_DIGICERT_TAP__
    }
#endif

    /* retrieve CA/RA certificate */
    pPkcsCtxInt->RACertDescriptor.pCertificate = pRACerts[0].pCertificate;
    pPkcsCtxInt->RACertDescriptor.certLength = pRACerts[0].certLength;
    pPkcsCtxInt->RACertDescriptor.cookie = 1;
    MF_attach(&(pPkcsCtxInt->RAMemFile), pPkcsCtxInt->RACertDescriptor.certLength, pPkcsCtxInt->RACertDescriptor.pCertificate);
    CS_AttachMemFile(&(pPkcsCtxInt->RACertStream), &(pPkcsCtxInt->RAMemFile) );

    if (OK > (status = ASN1_Parse( pPkcsCtxInt->RACertStream, &(pPkcsCtxInt->pRACertificate))))
        goto exit;

    /* retrieve CA certificate if different from that of RA */
    pPkcsCtxInt->CACertDescriptor.pCertificate = pCACerts[0].pCertificate;
    pPkcsCtxInt->CACertDescriptor.certLength = pCACerts[0].certLength;
    if (!pPkcsCtxInt->CACertDescriptor.pCertificate)
    {
        status = ERR_SCEP_INIT_FAIL;
        goto exit;
    }
    pPkcsCtxInt->CACertDescriptor.cookie = 1;

    MF_attach(&(pPkcsCtxInt->CAMemFile), pPkcsCtxInt->CACertDescriptor.certLength, pPkcsCtxInt->CACertDescriptor.pCertificate);
    CS_AttachMemFile(&(pPkcsCtxInt->CACertStream), &(pPkcsCtxInt->CAMemFile) );
    if (OK > (status = ASN1_Parse( pPkcsCtxInt->CACertStream, &(pPkcsCtxInt->pCACertificate))))
        goto exit;

    /* initialize self-cert, either self-signed or CA issued */
    /* first see if self cert can be retrived through callback functions */
    /* ignoring error if can't not be retrieved */
    if (pRequesterCert != NULL)
    {
        pPkcsCtxInt->requesterCertDescriptor.pCertificate = pRequesterCert->pCertificate;
        pPkcsCtxInt->requesterCertDescriptor.certLength = pRequesterCert->certLength;
        if (pPkcsCtxInt->requesterCertDescriptor.pCertificate)
        {
            pPkcsCtxInt->requesterCertDescriptor.cookie = 1;
            /* parse the certificate, also cache selfcert for future use */
            MF_attach(&(pPkcsCtxInt->requesterCertMemFile), pPkcsCtxInt->requesterCertDescriptor.certLength, pPkcsCtxInt->requesterCertDescriptor.pCertificate);
            CS_AttachMemFile(&(pPkcsCtxInt->requesterCertStream), &(pPkcsCtxInt->requesterCertMemFile) );
            if (OK > (status = ASN1_Parse( pPkcsCtxInt->requesterCertStream, &(pPkcsCtxInt->pRequesterCert))))
                goto exit;
        }
    }

    SCEP_CLIENT_STATE(*ppScepContext) = certNonExistant;


exit:
    if (status < OK)
    {
        SCEP_CONTEXT_releaseContext(ppScepContext);
    }

    return status;
}

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_TAP__
static MSTATUS SCEP_SAMPLE_createTapAsymKey(AsymmetricKey *pAsymKey,
                                            ubyte *pKeyType,
                                            ubyte4 keySize,
                                            struct vlong **ppVlongQueue,
                                            TAP_Context *pTapContext,
                                            TAP_EntityCredentialList *pEntityCredentialList,
                                            TAP_CredentialList *pCredList,
                                            ubyte keyUsage,
                                            ubyte signScheme,
                                            ubyte encScheme)
{
    MSTATUS status = ERR_NULL_POINTER;
    void *pKey = NULL;

    if (pAsymKey != NULL)
    {
        status = CRYPTO_initAsymmetricKey(pAsymKey);
        if (OK != status)
            goto exit;

        if(DIGI_STRCMP((const sbyte *)pKeyType, (const sbyte *)KEY_TYPE_RSA) == 0)
        {
            MRsaTapKeyGenArgs rsaTapArgs = {0};
            if (keyUsage == TAP_KEY_USAGE_DECRYPT) {
                rsaTapArgs.algKeyInfo.rsaInfo.encScheme = encScheme;
            }
            else if (keyUsage == TAP_KEY_USAGE_GENERAL)
            {
                rsaTapArgs.algKeyInfo.rsaInfo.sigScheme = signScheme;
                rsaTapArgs.algKeyInfo.rsaInfo.encScheme = encScheme;
            }
            else
            {
                rsaTapArgs.algKeyInfo.rsaInfo.sigScheme = signScheme;
            }
            rsaTapArgs.keyUsage = keyUsage;
            rsaTapArgs.pTapCtx = pTapContext;
            rsaTapArgs.pEntityCredentials = pEntityCredentialList;
            rsaTapArgs.pKeyCredentials = pCredList;

            /* Generate a TAP RSA key object.
             */
            status = CRYPTO_INTERFACE_RSA_generateKeyAlloc(
                NULL, &pKey, keySize, ppVlongQueue, akt_tap_rsa,
                &rsaTapArgs);
            if (OK != status)
                goto exit;

            /* Load the TAP RSA key object into the AsymmetricKey and set the
             * key type.
             */
            pAsymKey->type = akt_tap_rsa;
            pAsymKey->key.pRSA = pKey;
        }
#ifdef __ENABLE_DIGICERT_ECC__
        else
        {
            MEccTapKeyGenArgs eccTapArgs = {0};
            ubyte4 curveId;
            eccTapArgs.keyUsage = keyUsage;
            eccTapArgs.pTapCtx = pTapContext;
            eccTapArgs.algKeyInfo.eccInfo.sigScheme = signScheme;
            eccTapArgs.pEntityCredentials = pEntityCredentialList;
            eccTapArgs.pKeyCredentials = pCredList;

            switch (keySize)
            {
                case 192:
                    curveId = cid_EC_P192;
                    break;
                case 224:
                    curveId = cid_EC_P224;
                    break;
                case 256:
                    curveId = cid_EC_P256;
                    break;
                case 384:
                    curveId = cid_EC_P384;
                    break;
                case 521:
                    curveId = cid_EC_P521;
                    break;
                default:
                    status = ERR_TAP_INVALID_CURVE_ID;
                    goto exit;
            }

            /* Generate a TAP ECC key object.
             */
            status = CRYPTO_INTERFACE_EC_generateKeyPairAlloc(
                curveId, &pKey, NULL, NULL, akt_tap_ecc, &eccTapArgs);
            if (OK != status)
                goto exit;

            /* Load the TAP ECC key object into the AsymmetricKey and set the
             * key type.
             */
            pAsymKey->type = akt_tap_ecc;
            pAsymKey->key.pECC = pKey;
        }
#endif
    }

exit:

    return status;
}
#endif /* __ENABLE_DIGICERT_TAP__ */

/*------------------------------------------------------------------*/

static MSTATUS
SCEP_SAMPLE_getSubjectAndReqAttrsFromConfig(ubyte *pCsrAttributes, ubyte4 csrAttrsLen, certDistinguishedName **ppSubject, requestAttributes *pPkcs10_attributes)
{
    sbyte    *pConfigPath    = NULL;
    sbyte    *pFullPath      = NULL;
    char     *ntoken         = NULL;
    char     *value          = NULL;
    char     line[MAX_LINE_LENGTH] = {0};
    nameAttr *pNameAttr[10]  = {0};
    char     *search         = "=";
    int      nameAttrCount   = 0;
    int      len             = 0;
    MSTATUS  status          = OK;
    char *actualValue = NULL;
    int pos = 0, k = 0;
    ubyte *encodedPassword = NULL;
    ubyte4 encodedPassLen;
    int i = 0;

    while(pos < csrAttrsLen)
    {
        if('\n' == pCsrAttributes[pos])
        {
            ntoken = strtok(line, search);
            if (ntoken == NULL)
            {
                status = ERR_NULL_POINTER;
                DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"SCEPC_generateCsrRequestFromConfig::strtok invalid conf file \n");
                goto exit;
            }
            if (0 == DIGI_STRCMP((const sbyte *)"countryName", (const sbyte *)ntoken))
            {
                value = strtok(NULL, search);
                if (value == NULL || *value == '\n')
                    continue;
                len = DIGI_STRLEN((const sbyte *)value);
                SCEP_SAMPLE_createNameAttr((ubyte *)countryName_OID, PRINTABLESTRING, (ubyte *)value, len, &pNameAttr[nameAttrCount]);
                nameAttrCount++;
            }
            else if (0 == DIGI_STRCMP((const sbyte *)"commonName", (const sbyte *)ntoken))
            {
                value = strtok(NULL, search);
                if (value == NULL || *value == '\n')
                    continue;
                len = DIGI_STRLEN((const sbyte *)value);
                SCEP_SAMPLE_createNameAttr((ubyte *)commonName_OID, UTF8STRING, (ubyte *)value, len, &pNameAttr[nameAttrCount]);
                nameAttrCount++;
            }
            else if (0 == DIGI_STRCMP((const sbyte *)"stateOrProvinceName", (const sbyte *)ntoken))
            {
                value = strtok(NULL, search);
                if (value == NULL || *value == '\n')
                    continue;
                len = DIGI_STRLEN((const sbyte *)value);
                SCEP_SAMPLE_createNameAttr((ubyte *)stateOrProvinceName_OID, UTF8STRING, (ubyte *)value, len, &pNameAttr[nameAttrCount]);
                nameAttrCount++;
            }
            else if (0 == DIGI_STRCMP((const sbyte *)"localityName", (const sbyte *)ntoken))
            {
                value = strtok(NULL, search);
                if (value == NULL || *value == '\n')
                    continue;
                len = DIGI_STRLEN((const sbyte *)value);
                SCEP_SAMPLE_createNameAttr((ubyte *)localityName_OID, UTF8STRING, (ubyte *)value, len, &pNameAttr[nameAttrCount]);
                nameAttrCount++;
            }
            else if (0 == DIGI_STRCMP((const sbyte *)"organizationName", (const sbyte *)ntoken))
            {
                value = strtok(NULL, search);
                if (value == NULL || *value == '\n')
                    continue;
                len = DIGI_STRLEN((const sbyte *)value);
                SCEP_SAMPLE_createNameAttr((ubyte *)organizationName_OID, UTF8STRING, (ubyte *)value, len, &pNameAttr[nameAttrCount]);
                nameAttrCount++;
            }
            else if (0 == DIGI_STRCMP((const sbyte *)"organizationalUnitName", (const sbyte *)ntoken))
            {
                value = strtok(NULL, search);
                if (value == NULL || *value == '\n')
                    continue;
                len = DIGI_STRLEN((const sbyte *)value);
                SCEP_SAMPLE_createNameAttr((ubyte *)organizationalUnitName_OID, UTF8STRING, (ubyte *)value, len, &pNameAttr[nameAttrCount]);
                nameAttrCount++;
            }
            /* will still accept the typo "Contraints" for legacy purposes */
            else if (0 == DIGI_STRCMP((const sbyte *)"hasBasicConstraints", (const sbyte *)ntoken) || 0 == DIGI_STRCMP((const sbyte *)"hasBasicContraints", (const sbyte *)ntoken))
            {
                value = strtok(NULL, search);
                if (value == NULL || *value == '\n')
                    continue;
                len = DIGI_STRLEN((const sbyte *)value);
                if ('\n' == value[len-1])
                    len = len -1;
                if ((0 == DIGI_STRNICMP((const sbyte *)"true", (const sbyte *)value, len)))
                {
                    pPkcs10_attributes->pExtensions->hasBasicConstraints = 1;
                }
                else
                {
                    pPkcs10_attributes->pExtensions->hasBasicConstraints = 0;
                }
            }
            else if (0 == DIGI_STRCMP((const sbyte *)"challengePassword", (const sbyte *)ntoken))
            {
                value = strtok(NULL, search);
                if (value == NULL || *value == '\n')
                    continue;
                len = DIGI_STRLEN((const sbyte *)value);
                if ('\n' == value[len-1])
                    len = len -1;
                if (NULL != pPkcs10_attributes->pChallengePwd)
                {
                    FREE(pPkcs10_attributes->pChallengePwd);
                    pPkcs10_attributes->pChallengePwd = NULL;
                }
                if (OK > (status = BASE64_encodeMessage((ubyte *)value, len, &encodedPassword, &encodedPassLen)))
                {
                    goto exit;
                }

                pPkcs10_attributes->pChallengePwd = MALLOC(encodedPassLen);
                if (NULL == pPkcs10_attributes->pChallengePwd)
                {
                    status = ERR_MEM_ALLOC_FAIL;
                }
                else
                {
                    DIGI_MEMSET((ubyte*)pPkcs10_attributes->pChallengePwd, 0x00, encodedPassLen);
                    DIGI_MEMCPY( pPkcs10_attributes->pChallengePwd, encodedPassword, encodedPassLen);
                    pPkcs10_attributes->challengePwdLength = encodedPassLen;
                }
                DIGI_FREE((void**)&encodedPassword);
                if (OK > status)
                    goto exit;
            }
            else if (0 == DIGI_STRCMP((const sbyte *)"isCA", (const sbyte *)ntoken))
            {
                value = strtok(NULL, search);
                if (value == NULL || *value == '\n')
                    continue;
                len = DIGI_STRLEN((const sbyte *)value);
                if ('\n' == value[len-1])
                    len = len -1;
                if ((0 == DIGI_STRNICMP((const sbyte *)"true", (const sbyte *)value, len)))
                {
                    pPkcs10_attributes->pExtensions->isCA = TRUE;
                }
                else
                {
                    pPkcs10_attributes->pExtensions->isCA = FALSE;
                }

            }
            else if (0 == DIGI_STRCMP((const sbyte *)"certPathLen", (const sbyte *)ntoken))
            {
                value = strtok(NULL, search);
                if (value == NULL || *value == '\n')
                    continue;
                len = DIGI_STRLEN((const sbyte *)value);
                if ('\n' == value[len-1])
                    len = len -1;
                if (OK > (status = DIGI_CALLOC((void**)&actualValue, 1, len+1)))
                {
                    goto exit;
                }
                if (OK > (status = DIGI_MEMCPY((ubyte*)actualValue, value, len)))
                {
                    goto exit;
                }
                char *endPtr = NULL;
                long pathLen = strtol(actualValue, &endPtr, 10);
                if (endPtr == actualValue || *endPtr != '\0' || pathLen > (sbyte)SBYTE_MAX)
                {
                    DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"Invalid certPathLen value\n");
                    status = ERR_INVALID_ARG;
                    goto exit;
                }
                pPkcs10_attributes->pExtensions->certPathLen = (sbyte)pathLen;
            }
            else if (0 == DIGI_STRCMP((const sbyte *)"keyUsage", (const sbyte *)ntoken))
            {
                char   ch  = '\0';
                ubyte2 res = 0;
                char   keyUsageVal[MAX_LINE_LENGTH];
                int    i = 0, k = 0;

                value = strtok(NULL, search);
                if (value == NULL || *value == '\n')
                    continue;
                len = DIGI_STRLEN((const sbyte *)value);
                DIGI_MEMSET((ubyte *)keyUsageVal, 0x00, sizeof(keyUsageVal));
                while(i <= len)
                {
                    ch = value[i];
                    if (ch == ',' || ch == '\n' || ch == '\0')
                    {
                        if (0 == DIGI_STRCMP((const sbyte *)"digitalSignature", (const sbyte *)keyUsageVal))
                        {
                            res = res + (1 << digitalSignature);
                        }
                        else if (0 == DIGI_STRCMP((const sbyte *)"nonRepudiation", (const sbyte *)keyUsageVal))
                        {
                            res = res + (1 << nonRepudiation);
                        }
                        else if (0 == DIGI_STRCMP((const sbyte *)"keyEncipherment", (const sbyte *)keyUsageVal))
                        {
                            res = res + (1 << keyEncipherment);
                        }
                        else if (0 == DIGI_STRCMP((const sbyte *)"dataEncipherment", (const sbyte *)keyUsageVal))
                        {
                            res = res + (1 << dataEncipherment);
                        }
                        else if (0 == DIGI_STRCMP((const sbyte *)"keyAgreement", (const sbyte *)keyUsageVal))
                        {
                            res = res + (1 << keyAgreement);
                        }
                        DIGI_MEMSET((ubyte *)keyUsageVal, 0x00, sizeof(keyUsageVal));
                        k  = 0;
                        i++;
                    }
                    else if (ch == ' ')
                    {
                        i++;
                        continue;
                    }
                    else
                    {
                        if (k < MAX_LINE_LENGTH - 1)
                        {
                            keyUsageVal[k++] = ch;
                        }
                        i++;
                    }
                }
                pPkcs10_attributes->pExtensions->hasKeyUsage = TRUE;
                pPkcs10_attributes->pExtensions->keyUsage = res;
            }
            else if (0 == DIGI_STRCMP((const sbyte *)"subjectAltNames", (const sbyte *)ntoken))
            {
                char   ch  = '\0';
                char   keyUsageVal[MAX_LINE_LENGTH];
                int    offset = 0, sansCount = 0, numsans = 0;
                int    i = 0, k = 0;
                char  *pEnd = NULL;
                char  count[MAX_NUM_SUBJECTALTNAMES];/*This variable is used to store the count of subjectAltNames from cofiguration*/
                SubjectAltNameAttr *sans = NULL;

                value = strtok(NULL, search);
                if (value == NULL || *value == '\n' || *value == '\0')
                    continue;
                len = DIGI_STRLEN((const sbyte *)value);
                /*Caluclate num of SANS */
                DIGI_MEMSET((ubyte*)count, 0x00, MAX_NUM_SUBJECTALTNAMES);
                while((i < len) && (value[i] != '\n') && (value[i] != ';') && (value[i] != '\0'))
                {
                    if(i >= MAX_NUM_SUBJECTALTNAMES)
                    {
                        DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"Exceeded Maximum number of Subject Alt Names supported\n");
                        break;
                    }
                    count[i] = value[i];
                    i++;
                }
                if (0 == (numsans = strtol(count, &pEnd, 10)))
                {
                    /* No SubjectAltNames present */
                    continue;
                }
                if (value == pEnd)
                {
                    status = ERR_INTERNAL_ERROR;
                    goto exit;
                }
                sans = MALLOC(numsans * sizeof(SubjectAltNameAttr));
                if (NULL == sans)
                {
                    status = ERR_MEM_ALLOC_FAIL;
                    goto exit;
                }
                DIGI_MEMSET((ubyte *)sans, 0x00, numsans * sizeof(SubjectAltNameAttr));
                DIGI_MEMSET((ubyte *)keyUsageVal, 0x00, sizeof(keyUsageVal));
                i++;/*Move to next position */
                while(i <= len)
                {
                    ch = value[i];
                    if (ch == ',' || ch == ';' || ch == '\n' || ch == '\0')
                    {
                        if (0 == offset)
                        {
                            /* SANS value */
                            ubyte4 dataLen = DIGI_STRLEN((sbyte*)keyUsageVal);
                            (&(sans[sansCount]))->subjectAltNameValue.data = MALLOC(dataLen + 1);
                        if (NULL == (&(sans[sansCount]))->subjectAltNameValue.data)
                        {
                            status = ERR_MEM_ALLOC_FAIL;
                            break;
                        }
                            DIGI_MEMSET((&(sans[sansCount]))->subjectAltNameValue.data, 0x00, dataLen + 1);
                            DIGI_MEMCPY((&(sans[sansCount]))->subjectAltNameValue.data, keyUsageVal, dataLen);
                            (&sans[sansCount])->subjectAltNameValue.dataLen = dataLen;
                            offset++;
                        }
                        else if (1 == offset)
                        {
                            /* Type of SANs */
                            char *endPtr = NULL;
                            long typeVal = strtol(keyUsageVal, &endPtr, 10);
                            if (endPtr == keyUsageVal || *endPtr != '\0' || typeVal < 0 || typeVal > (ubyte)UBYTE_MAX)
                            {
                                DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"Invalid subjectAltName type value\n");
                                status = ERR_INVALID_ARG;
                                break;
                            }
                            (&(sans[sansCount]))->subjectAltNameType = (ubyte)typeVal;
                            offset = 0;
                        }
                        if (ch == ';')
                            sansCount++;
                        DIGI_MEMSET((ubyte *)keyUsageVal, 0x00, sizeof(keyUsageVal));
                        k = 0;
                        i++;
                    }
                    else if (ch == ' ')
                    {
                        i++;
                        continue;
                    }
                    else
                    {
                        if (k < MAX_LINE_LENGTH - 1)
                        {
                            keyUsageVal[k++] = ch;
                        }
                        i++;
                    }
                }
                if (OK == status)
                {
                    pPkcs10_attributes->pExtensions->otherExtCount = 1;
                    pPkcs10_attributes->pExtensions->otherExts = MALLOC(sizeof(extensions));
                    if (NULL == pPkcs10_attributes->pExtensions->otherExts)
                    {
                        status = ERR_MEM_ALLOC_FAIL;
                    }
                    if (OK == status)
                        status = setSubjAltNameExtension(sans, numsans, pPkcs10_attributes->pExtensions->otherExts);
                }
                /* Free the SubjectAltNameAttr array */
                if (NULL != sans)
                {
                    for (i = 0; i < numsans; i++)
                    {
                        SubjectAltNameAttr *sanattr = &sans[i];
                        if (sanattr->subjectAltNameValue.data != NULL)
                        {
                            FREE(sanattr->subjectAltNameValue.data);
                        }
                    }
                    FREE(sans);
                    sans = NULL;
                }
                if(OK > status)
                {
                    goto exit;
                }
            }
            if (OK > (status = DIGI_MEMSET((ubyte*)line, 0x00, sizeof(line))))
            {
                goto exit;
            }
            k = 0;
        }
        else if ('#' == pCsrAttributes[pos])
        {/* Discard the commented lines */
            /* Move position to the next line */
            while(pos < csrAttrsLen && pCsrAttributes[pos] != '\n')
                pos++;
        }
        else
        {
            if (k < MAX_LINE_LENGTH - 1)
            {
                line[k] = pCsrAttributes[pos];
                k++;
            }
            else
            {
                DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"Warning: Line exceeds MAX_LINE_LENGTH, truncating\n");
                while(pos < csrAttrsLen && pCsrAttributes[pos] != '\n')
                    pos++;
                if (OK > (status = DIGI_MEMSET((ubyte*)line, 0x00, sizeof(line))))
                {
                    goto exit;
                }
                k = 0;
            }
        }
        pos++;
    }

    if (nameAttrCount > 0)
        SCEP_SAMPLE_updateCertDistinguishedName(pNameAttr, nameAttrCount, ppSubject);

exit:
    if (actualValue != NULL)
        DIGI_FREE((void**)&actualValue);
    if (NULL != pConfigPath)
        FREE(pConfigPath);
    if (NULL != pFullPath)
        FREE(pFullPath);

    return status;
}
/*------------------------------------------------------------------*/
/**
@brief      Registers callback function, which returns SCEP data.

@details    This function registers callback function, which returns SCEP data.

@param pCallback Pointer to callback function.

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    scep_sample_api.h
*/
MSTATUS SCEP_SAMPLE_registerScepDataCallback(void *pCallback)
{
    g_pFuncPtrGetScepData = pCallback;
    return OK;
}

/*------------------------------------------------------------------*/

/**
@brief      Generates Asymmetric Key.

@details    This function generates Asymmetric key. It could be
            a Software key or a TAP key based on the
            keysource parameter.

@param pKeySource              Type of the source. Possible values:
                                SW
                                TPM2
@param pKeyType                Pointer to the key type.
@param keySize                 Size of the key.
@param mh                      Pointer to MOCTAP_HANDLE.
@param pTapContext             Pointer to the TAP_Context.
@param pEntityCredentialList   Pointer to the entitiy credentials.
@param pCredList               Pointer to the key credential list.
@param keyUsage                key usage value.
@param signScheme              Sign scheme to be used.
@param encScheme               Encryption scheme to be used.
@param ppPemKeyBlob            On return, pointer to the pem key blob.
@param pPemKeyBlobLen          On return, pointer to the length of the key blob.

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    scep_sample_api.c
*/
MSTATUS
SCEP_SAMPLE_generateAsymKey(sbyte *pKeySource,
                            sbyte *pKeyType,
                            ubyte4 keySize,
#ifdef __ENABLE_DIGICERT_TAP__
                            TAP_Context *pTapContext,
                            TAP_EntityCredentialList *pEntityCredentialList,
                            TAP_CredentialList *pCredList,
                            ubyte keyUsage,
                            ubyte signScheme,
                            ubyte encScheme,
#endif
                            ubyte **ppPemKeyBlob,
                            ubyte4 *pPemKeyBlobLen)
{
	MSTATUS status = OK;
	ubyte *pKeyBlob = NULL;
	ubyte4 keyBlobLen = 0;
	ubyte4 keyType = akt_undefined;
	AsymmetricKey asymKey = {0};
	ubyte4 serializedPemKeyLen;
	ubyte *pSerializedPemKey = NULL;
#ifdef __ENABLE_DIGICERT_TAP__
	sbyte4 useTap = 0;
#endif

#ifdef __ENABLE_DIGICERT_TAP__
	if (DIGI_STRCMP((const sbyte *)pKeySource, (const sbyte *)KEY_SOURCE_TPM2) == 0)
	{
		useTap = 1;
	}
#endif

	if(DIGI_STRCMP((const sbyte *)pKeyType, (const sbyte *)KEY_TYPE_ECDSA) == 0)
	{
		keyType = akt_ecc;
#ifdef __ENABLE_DIGICERT_TAP__
		if (useTap)
			keyType = akt_tap_ecc;
#endif
	}
    else if(DIGI_STRCMP((const sbyte *)pKeyType, (const sbyte *)KEY_TYPE_RSA) == 0)
    {
        keyType = akt_rsa;
#ifdef __ENABLE_DIGICERT_TAP__
        if (useTap)
            keyType = akt_tap_rsa;
#endif
    }

	DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"\nGenerating keys....\n");

#ifdef __ENABLE_DIGICERT_TAP__
        if (useTap)
        {
            TAP_ErrorContext errContext;
            TAP_ErrorContext *pErrContext = &errContext;
            struct vlong *pVlongQueue = NULL;

            /* Generate TAP key based on the key type string and key size.
             */
            if (OK != (status = SCEP_SAMPLE_createTapAsymKey(
                &asymKey, (ubyte*)pKeyType, keySize, &pVlongQueue, pTapContext,
                pEntityCredentialList, pCredList, keyUsage, signScheme,
                encScheme)))
            {
                DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "myKeyPairLookup::SCEP_SAMPLE_createTapAsymKey::status:  ", status);
                goto exit;
            }

#ifdef __ENABLE_DIGICERT_SERIALIZE__
            /* Serialize to PEM Format.
             */
            if (OK != (status = CRYPTO_serializeAsymKey(
                &asymKey, privateKeyPem, ppPemKeyBlob, pPemKeyBlobLen)))
            {
                DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "myKeyPairLookup::CRYPTO_serializeAsymKey::status:  ", status);
                goto exit;
            }
#endif
            TAP_Key *pTapKey = NULL;
            status = CRYPTO_INTERFACE_getTapKey(&asymKey, &pTapKey);
            if (OK != status)
                goto exit;

            if (OK > (status = TAP_unloadKey(pTapKey, pErrContext)))
            {
                DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, (sbyte*)"TAP_unloadKey failed with status = ", status);
            }
		}
		else
		{
#endif /*__ENABLE_DIGICERT_TAP__*/
			if (OK > (status = CA_MGMT_generateNakedKey( keyType, keySize, &pKeyBlob, &keyBlobLen)))
			{
				goto exit;
			}

			status = CRYPTO_initAsymmetricKey (&asymKey);
			if (OK != status)
				goto exit;

			/* Read the keyblob */
			if (OK > (status = KEYBLOB_extractKeyBlobEx(pKeyBlob, keyBlobLen, &asymKey)))
			{
				goto exit;
			}
#ifdef __ENABLE_DIGICERT_SERIALIZE__
			/* Serialize the key in PEM Format */
            status = CRYPTO_serializeAsymKey(
                &asymKey, privateKeyPem, &pSerializedPemKey,
                &serializedPemKeyLen);
            if (OK != status)
                goto exit;

			*ppPemKeyBlob = pSerializedPemKey;
			*pPemKeyBlobLen = serializedPemKeyLen;
#endif

#ifdef __ENABLE_DIGICERT_TAP__
		}
#endif

exit:
    if (pKeyBlob)
        DIGI_FREE((void**) &pKeyBlob);
    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
	return status;
}

/*------------------------------------------------------------------*/

/**
@brief      Generates certificate signing request.

@details    This function generates a PKCS#10 CSR based on CSR config
            attributes provided.

@param pKeySource         Pointer to the keysource.
@param MOCTAP_HANDLE      Pointer to the tap handle.
@param pPemKeyBlob        Pointer to the pem key blob.
@param pemKeyBlobLen      Pointer to the length of the key blob.
@param pCsrAttributes     Pointer to the CSR config buffer.
@param csrAttrsLen        Length of the CSR config buffer.
@param pChallengePass     Pointer to the challenge password.
@param passwordLen        Length of the challenge password.
@param ppCsrBuffer        On return, pointer to the CSR buffer in der format.
@param pCsrBufferLen      On return, pointer to the length of CSR buffer.
@param ppReqInfo          On return, Pointer to the requestInfo. This pointer
                          is required to be sent to SCEP_SAMPLE_sendEnrollmentRequest API.

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    scep_sample_api.c
*/
MSTATUS
SCEP_SAMPLE_generateCSRRequest(sbyte *pKeySource,
                               ubyte *pPemKeyBlob, ubyte4 pemKeyBlobLen,
                               ubyte *pCsrAttributes, ubyte4 csrAttrsLen,
                               sbyte *pChallengePass, ubyte4 passwordLen,
                               ubyte **ppCsrBuffer, ubyte4 *pCsrBufferLen,
                               requestInfo **ppReqInfo)
{
    MSTATUS status = OK;
    requestInfo  *pReqInfo = NULL;
    AsymmetricKey asymKey = {0};
#ifdef __ENABLE_DIGICERT_TAP__
    byteBoolean useTap = FALSE;
#endif

    /*validate input parameters */
    if ( (NULL == pKeySource) || (NULL == pPemKeyBlob) || (NULL == pCsrAttributes) ||
         (NULL == pChallengePass) || (NULL == ppCsrBuffer) || (NULL == pCsrBufferLen) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_TAP__
    if ((0 == DIGI_STRCMP(pKeySource, (const sbyte*)KEY_SOURCE_TPM2)))
    {
        useTap = TRUE;
    }
#endif

    /* Initialize asymmetric key */
    if (OK > (status = CRYPTO_initAsymmetricKey (&asymKey)))
    {
        goto exit;
    }
    /* Initialize requesterInfo */
    if (OK > (status = DIGI_CALLOC((void**)&pReqInfo, 1, sizeof(requestInfo))))
    {
        goto exit;
    }
    if (OK > (status = DIGI_CALLOC((void**)&(pReqInfo->value.certInfoAndReqAttrs.pReqAttrs), 1, sizeof(requestAttributesEx))))
    {
        goto exit;
    }
    if (OK > (status = DIGI_CALLOC((void**)&(pReqInfo->value.certInfoAndReqAttrs.pReqAttrs->pExtensions), 1,
                                  sizeof(certExtensions))))
    {
        goto exit;
    }

    /* initialize requestInfo depending on messageType */
    pReqInfo->type = scep_PKCSReq;

    /* Get the subject and requestAttributes from config buffer.*/
    if (OK > (status = SCEP_SAMPLE_getSubjectAndReqAttrsFromConfig(pCsrAttributes, csrAttrsLen, &(pReqInfo->value.certInfoAndReqAttrs.pSubject),
                    pReqInfo->value.certInfoAndReqAttrs.pReqAttrs)))
    {
        goto exit;
    }
    if (pChallengePass != NULL)
    {
        if (pReqInfo->value.certInfoAndReqAttrs.pReqAttrs->pChallengePwd != NULL)
            FREE(pReqInfo->value.certInfoAndReqAttrs.pReqAttrs->pChallengePwd);

        if (NULL == (pReqInfo->value.certInfoAndReqAttrs.pReqAttrs->pChallengePwd = MALLOC(passwordLen+1)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        DIGI_MEMCPY(pReqInfo->value.certInfoAndReqAttrs.pReqAttrs->pChallengePwd, pChallengePass, passwordLen);
        pReqInfo->value.certInfoAndReqAttrs.pReqAttrs->pChallengePwd[passwordLen]='\0';
        pReqInfo->value.certInfoAndReqAttrs.pReqAttrs->challengePwdLength = passwordLen;
    }

    /* Convert pem keyblob to AsymmetricKey */
#ifdef __ENABLE_DIGICERT_TAP__
    if (TRUE == useTap)
    {
        if (OK > (status = CRYPTO_deserializeAsymKey(
            pPemKeyBlob, pemKeyBlobLen, NULL, &asymKey)))
        {
            goto exit;
        }
    }
    else
    {
#endif
        /* SW Key */
        /* Deserialize to keyblob write the Keyblob file */
        if (OK > (status = deserializePemKey(pPemKeyBlob, pemKeyBlobLen, &asymKey)))
        {
            goto exit;
        }
#ifdef __ENABLE_DIGICERT_TAP__
    }
#endif
    if (OK > (status = SCEP_MESSAGE_generatePayLoad(&asymKey, pReqInfo, ppCsrBuffer, pCsrBufferLen)))
        goto exit;

    *ppReqInfo = pReqInfo;
    pReqInfo = NULL;

exit:

    if (NULL != pReqInfo)
    {
        if (NULL != pReqInfo->value.certInfoAndReqAttrs.pReqAttrs)
        {
            if (NULL != pReqInfo->value.certInfoAndReqAttrs.pReqAttrs->pExtensions)
            {
                (void) DIGI_FREE((void **) &pReqInfo->value.certInfoAndReqAttrs.pReqAttrs->pExtensions);
            }

            (void) DIGI_FREE((void **) &pReqInfo->value.certInfoAndReqAttrs.pReqAttrs);
        }

        (void) DIGI_FREE((void **) &pReqInfo);
    }

    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
    return status;
}

/*------------------------------------------------------------------*/

/**
@brief      Sends enrollment request to the server.

@details    This function prepares a PKI message and sent the
            enroll request over http. Get the response from server,
            parse the response and returns the enrolled certificate.

@param pKeySource           Pointer to the keysource.
@param MOCTAP_HANDLE        Pointer to the tap handle.
@param pHttpContext         Pointer to the httpContext.
@param pPemKeyBlob          Pointer to the pem key blob.
@param pemKeyBlobLen        Pointer to the length of the key blob.
@param pPkcs10Csr           Pointer to the CSR config buffer.
@param pkcs10CsrLen         Length of the CSR config buffer.
@param pReqInfo             Pointer to the requestInfo.
@param pServerType          Pointer to the null terminated server type.
@param pServerUrl           Pointer to the null terminated server url.
@param pCACerts             Pointer to the chain of CA certificates.
@param numCaCerts           Number of CA certificates.
@param pRACerts             Pointer to the chain of RA certificates.
@param numRaCerts           Number of RA certifcates.
@param pRequesterCert       Pointer to the requester certificate
                            In case of enroll this should be a self signed certificate.
                            In case of renew or rekey this should certificate issued by CA.
@param requestType          Type of the request. Possible values
                            enroll - 1
                            renew  - 2
                            rekey  - 3
@param pOldPemKeyBlob       Pointer to the old key, which was used for enroll.
                            This parameter is only valid in case of rekey.
@param oldPemKeyBlobLen     Length of the old key, which was used for enroll.
                            This parameter is only valid in case of rekey.
@param ppCert               On return, pointer to the enrolled certificate.
@param pCertLen             On return, pointer to the length of enrolled certificate.
@param ppOutTransactionId   On return, pointer to the transaction id. This pointer
                            will have some valid value only if the pOutStatus is pending
@param pOutTransactionIdLen On return, pointer to the tansaction id length.
@param pOutStatus           On return, Pointer to the return status. Possible values:
                            scep_SUCCESS=0, scep_FAILURE=2, scep_PENDING=3.

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    scep_sample_api.c
*/
MSTATUS
SCEP_SAMPLE_sendEnrollmentRequest(sbyte *pKeySource,
                                  httpContext *pHttpContext,
                                  ubyte *pPemKeyBlob, ubyte4 pemKeyBlobLen,
                                  ubyte *pPkcs10Csr, ubyte4 pkcs10CsrLen,
                                  requestInfo *pReqInfo,
                                  ubyte *pServerType, ubyte *pServerUrl,
                                  struct certDescriptor pCACerts[], ubyte4 numCaCerts,
                                  struct certDescriptor pRACerts[], ubyte4 numRaCerts,
                                  struct certDescriptor *pRequesterCert, ubyte4 requestType,
                                  ubyte *pOldPemKeyBlob, ubyte4 oldPemKeyBlobLen,
#ifdef __ENABLE_DIGICERT_CMS_RSA_OAEP__
                                  ubyte isOaep, sbyte *pOaepLabel, ubyte4 oaepHashAlgo,
#endif
                                  ubyte **ppCert, ubyte4 *pCertLen,
                                  sbyte **ppOutTransactionId, ubyte4 *pOutTransactionIdLen,
                                  ubyte4 *pOutStatus)
{
    MSTATUS status = OK;
    scepContext *pScepContext = NULL;
    ubyte        *pQuery = NULL;
    ubyte4       queryLen;
    sbyte        *completeUri = NULL;
    ubyte4       completeUriLen;
    ubyte        *pHttpResp = NULL;
    ubyte4       httpRespLen;
    void*        pCookie = NULL;
    void*        pCachedCookie = NULL;
    sbyte        tcpBuffer[SCEP_TCP_READ_BUFFER];
    sbyte4       nRet;
    sbyte        *respFile = NULL;
    byteBoolean  usePost = TRUE;
    ubyte4       serverType;
    ubyte4       bodyLen;
    ubyte4 statusCode;
    const ubyte *pContentType;
    ubyte4 contentTypeLen;
    ubyte* respBody;
    ubyte4 respBodyLen;
#ifdef __ENABLE_DIGICERT_TAP__
    byteBoolean  useTap = FALSE;
#endif
    /*validate input parameters */
    if ( (NULL == pKeySource) || (NULL == pPemKeyBlob) || (NULL == pPkcs10Csr) ||
        (NULL == ppCert) || (NULL == pCertLen) ||
        (NULL == pServerUrl) || (NULL == pReqInfo) || (NULL == pHttpContext) ||
        (0 == numCaCerts) || (0 == numRaCerts) ||
        ((requestType == 3 || requestType == 2) && (NULL == pOldPemKeyBlob)))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }


#ifdef __ENABLE_DIGICERT_TAP__
    if ((0 == DIGI_STRCMP((const sbyte *)pKeySource, (const sbyte*)KEY_SOURCE_TPM2)))
    {
        useTap = TRUE;
    }
#endif


    if (OK > (status = SCEP_SAMPLE_initContext(&pScepContext, NULL,
#ifdef __ENABLE_DIGICERT_TAP__
                                               useTap,
#endif
#ifdef __ENABLE_DIGICERT_CMS_RSA_OAEP__
                                               isOaep, pOaepLabel, oaepHashAlgo,
#endif
                                               pPemKeyBlob, pemKeyBlobLen,
                                               pOldPemKeyBlob, oldPemKeyBlobLen,
                                               pCACerts, numCaCerts,
                                               pRACerts, numRaCerts,
                                               pRequesterCert)))
    {
        goto exit;
    }


    if (OK > (status = SCEP_CLIENT_setRequestInfo(pScepContext, pReqInfo)))
        goto exit;

    /* choose which style of request: URL, or POST */
    /* NOTE: win20xx scep addon doesn't support POST mode */
    if (OK > (status = getServerTypeDetails((sbyte*)pServerType, &usePost, &serverType)))
    {
        goto exit;
    }

    if (pScepContext->pPkcsCtx != NULL)
    {
        pScepContext->pPkcsCtx->pPayLoad = pPkcs10Csr;
        pScepContext->pPkcsCtx->payLoadLen = pkcs10CsrLen;
    }

    if (!usePost)
    {
        if (OK > (status = SCEP_CLIENT_generateRequest(pScepContext, &pQuery, &queryLen)))
            goto exit;
    }
    else
    {
        if (OK > (status = SCEP_CLIENT_generateRequestEx(pScepContext, TRUE,
                                                      &pQuery, &queryLen, &bodyLen, &pCookie)))
            goto exit;
        if (OK > (status = HTTP_setCookie(pHttpContext, pCookie)))
            goto exit;
        if (OK > (status = HTTP_REQUEST_setRequestMethodIfNotSet(pHttpContext, &mHttpMethods[POST])))
            goto exit;
        if (OK > (status = HTTP_REQUEST_setContentLengthIfNotSet(pHttpContext, bodyLen)))
            goto exit;

        HTTP_httpSettings()->funcPtrRequestBodyCallback = SCEP_CLIENT_http_requestBodyCallback;
    }

    completeUriLen = DIGI_STRLEN((sbyte*)pServerUrl) + 1 + queryLen;
    if (NULL == (completeUri = MALLOC(completeUriLen+1)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    DIGI_MEMCPY((void *)completeUri, (const void *)pServerUrl, DIGI_STRLEN((sbyte*)pServerUrl));
    *(completeUri+DIGI_STRLEN((sbyte*)pServerUrl)) = '?';
    DIGI_MEMCPY((void *) (completeUri+DIGI_STRLEN((sbyte*)pServerUrl)+1), (const void *) pQuery, queryLen);
    *(completeUri+completeUriLen) = '\0';

    /* set request URI */
    if (OK > (status = HTTP_REQUEST_setRequestUriIfNotSet(pHttpContext, completeUri)))
        goto exit;

    /* send request */
    if (OK > (status = HTTP_recv(pHttpContext, NULL, 0)))
        goto exit;

    /* finish sending the request via transport... */
    while (!HTTP_REQUEST_isDoneSendingRequest(pHttpContext))
    {
        if (OK > (status = HTTP_continue(pHttpContext)))
            goto exit;
    }
    DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"Sent request......\n");

    while (1)
    {
        status = TCP_READ_AVL(pHttpContext->socket, tcpBuffer, SCEP_TCP_READ_BUFFER, (ubyte4 *) &nRet, 50000);

        if (status == ERR_TCP_READ_TIMEOUT)
        {
            DEBUG_PRINT(DEBUG_SCEP_EXAMPLE, "readtimeout......\n");
            continue;
        }
        else if (status < OK)
            goto exit;

        if (nRet <= 0)
            continue;

        /* DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "SCEP_CLIENT_EXAMPLE TCP_READ_AVL = ", nRet); */

        /* process response */
        if (OK > (status = HTTP_recv(pHttpContext, (ubyte*)tcpBuffer, nRet)))
            goto exit;

        if (HTTP_isDone(pHttpContext))
        {
            ubyte4 statusCode;
            if (pHttpResp)
            {
                FREE(pHttpResp);
                pHttpResp = NULL;
                httpRespLen = 0;
            }
            if (OK > (status = HTTP_REQUEST_getStatusCode(pHttpContext, &statusCode)))
            {
                goto exit;
            }

            if (OK > (status = HTTP_REQUEST_getResponseContent(pHttpContext, &pHttpResp, &httpRespLen)))
            {
                goto exit;
            }
            if (statusCode < 300)
            {
                const ubyte *pContentType;
                ubyte4 contentTypeLen;
                if (OK > (status = HTTP_REQUEST_getContentType(pHttpContext, &pContentType, &contentTypeLen)))
                {
                    goto exit;
                }

                if (OK > (status = SCEP_CLIENT_recvResponse(pScepContext, (ubyte*)pContentType, contentTypeLen, pHttpResp, httpRespLen))){

                    goto exit;
                }

                if (SCEP_CLIENT_getStatus(pScepContext) == scep_SUCCESS)
                {
                    ubyte* respBody;
                    ubyte4 respBodyLen;
                    SCEP_CLIENT_getResponseContent(pScepContext, &respBody, &respBodyLen);
                    /*sbyte* filename = (sbyte*)DEF_FILENAME;
                    if (messageType == scep_PKCSReq && user == 0)
                    {
                        if (gSelfCert)
                        {
                            FREE(gSelfCert);
                            gSelfCert = NULL;
                        }
                        gSelfCert = (ubyte*)MALLOC(respBodyLen );
                        DIGI_MEMCPY(gSelfCert, respBody, respBodyLen);
                        gSelfCertLen = respBodyLen;
                    }
                    filename = (sbyte*) REQUESTER_CERT_FILE;*/

                    if (respBodyLen == 0)
                    {
                        DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"WARNING: SCEP_EXAMPLE: Received response 0 length with file name: \n");
                        goto exit;
                    }
                    *ppCert = respBody;
                    *pCertLen = respBodyLen;

                    /*setFullPath(filename, filePath, &respFile);
                    if ( OK > ( status = DIGICERT_writeFile((const char *)respFile, respBody, respBodyLen))){
                        goto exit;
                    }*/
                    if (respFile)
                    {
                        FREE (respFile);
                        respFile = NULL;
                    }
                    /*if (respBody)
                    {
                        FREE(respBody);
                        respBody = NULL;
                        respBodyLen = 0;
                    }*/
                    DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"\n");
                    break;
                }
                else if (SCEP_CLIENT_getStatus(pScepContext) == scep_PENDING)
                {
                    //*ppOutTransactionId
                    if (OK > (status = DIGI_CALLOC((void**)ppOutTransactionId, 1, pScepContext->pTransAttrs->transactionIDLen)))
                    {
                        goto exit;
                    }
                    if (OK > (status = DIGI_MEMCPY((ubyte*)*ppOutTransactionId, pScepContext->pTransAttrs->transactionID, pScepContext->pTransAttrs->transactionIDLen)))
                    {
                        goto exit;
                    }
                    *pOutTransactionIdLen = pScepContext->pTransAttrs->transactionIDLen;
                    *pOutStatus = pScepContext->pTransAttrs->pkiStatus;
                    goto exit;
                }
                else
                {
                    /* failed reason: check failInfo*/
                    SCEP_failInfo failInfo;
                    SCEP_CLIENT_getFailInfo(pScepContext, &failInfo);
                    DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"SCEP_EXAMPLE: Received response with FAILURE status: ");
                    switch (failInfo)
                    {
                        case scep_badAlg:
                            DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"badAlg\n");
                            break;
                        case scep_badMessageCheck:
                            DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"badMessageCheck\n");
                            break;
                        case scep_badRequest:
                            DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"badRequest\n");
                            break;
                        case scep_badTime:
                            DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"badTime\n");
                            break;
                        case scep_badCertId:
                            DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"badCertId\n");
                            break;
                        default:
                            DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"Unknown\n");
                            break;
                    }
                    break;
                }
            }
            else
            {
                /* print out http response reason phrase */
                const ubyte* reasonPhrase;
                ubyte4 reasonPhraseLength;
                sbyte* str = NULL;
                if (OK > (status = HTTP_REQUEST_getStatusPhrase(pHttpContext,
                                &reasonPhrase, &reasonPhraseLength)))
                    goto exit;
                str = MALLOC(reasonPhraseLength+1);
                if (str)
                {
                    DIGI_MEMCPY(str, reasonPhrase, reasonPhraseLength);
                    *(str+reasonPhraseLength) = '\0';
                    DEBUG_PRINT2(DEBUG_SCEP_EXAMPLE,"SCEP_EXAMPLE: Received response with HTTP error status: ", str);
                    DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"\n");
                    FREE(str);
                    str = NULL;
                }
                status = ERR_HTTP;
                break;
            }
        }
    }

exit:
    if (pQuery)
    {
        FREE(pQuery);
        pQuery = NULL;
    }
    if (completeUri)
    {
        FREE(completeUri);
        completeUri = NULL;
    }
    if (pHttpResp)
    {
        FREE(pHttpResp);
        pHttpResp = NULL;
    }
    if (pCookie)
    {
        SCEP_CLIENT_releaseCookie(pCookie);
    }
    if (pCachedCookie)
    {
        SCEP_CLIENT_releasePollCookie(pCachedCookie);
    }

    if (pScepContext && SCEP_CLIENT_getStatus(pScepContext) == scep_PENDING)
    {
        /* Same requestInfo will be used at the time of pending enrollment
           so don't free requestInfo.*/
        pScepContext->pReqInfo = NULL;
    }
    if (pScepContext)
        SCEP_CLIENT_releaseContext(&pScepContext);

    return status;
}

/*------------------------------------------------------------------*/

/**
@brief      Sends pending enrollment request to the server.

@details    This function prepares a PKI message and sent the
            enroll request over http. Get the response from server,
            parse the response and returns the enrolled certificate.
            This can be used only in case of previous request of
            enrollment is pending on server.

@param pKeySource         Pointer to the keysource.
@param MOCTAP_HANDLE      Pointer to the tap handle.
@param pHttpContext       Pointer to the httpContext.
@param pPemKeyBlob        Pointer to the pem key blob.
@param pemKeyBlobLen      Pointer to the length of the key blob.
@param pPkcs10Csr         Pointer to the CSR config buffer.
@param pkcs10CsrLen       Length of the CSR config buffer.
@param pServerType        Pointer to the null terminated server type.
@param pServerUrl         Pointer to the server url.
@param pCACerts           Pointer to the chain of CA certificates.
@param numCaCerts         Number of CA certificates.
@param pRACerts           Pointer to the chain of RA certificates.
@param numRaCerts         Number of RA certifcates.
@param pRequesterCert     Pointer to the requester certificate (self signed certificate).
@param requestType        Type of the request. Possible values
                          enroll - 1
                          renew  - 2
                          rekey  - 3
@param pOldPemKeyBlob     Pointer to the old key, which was used for enroll.
                          This parameter is only valid in case of rekey.
@param oldPemKeyBlobLen   Length of the old key, which was used for enroll.
                          This parameter is only valid in case of rekey.
@param pTrasactionId      Pointer to the null terminated transaction id.
@param transactionIdLen   Length of the transaction id.
@param pollInterval       Polling interval.
@param pollCount          Polling count.
@param ppCert             On return, pointer to the enrolled certificate.
@param pCertLen           On return, pointer to the length of enrolled certificate.

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    scep_sample_api.h
*/
MSTATUS
SCEP_SAMPLE_retryPendingEnrollmentRequest(sbyte *pKeySource,
                                  httpContext *pHttpContext,
                                  ubyte *pPemKeyBlob, ubyte4 pemKeyBlobLen,
                                  ubyte *pPkcs10Csr, ubyte4 pkcs10CsrLen,
                                  requestInfo *pReqInfo,
                                  ubyte *pServerType, ubyte *pServerUrl,
                                  struct certDescriptor pCACerts[], ubyte4 numCaCerts,
                                  struct certDescriptor pRACerts[], ubyte4 numRaCerts,
                                  struct certDescriptor *pRequesterCert, ubyte4 requestType,
                                  ubyte *pOldPemKeyBlob, ubyte4 oldPemKeyBlobLen,
                                  sbyte* pTransactionID, ubyte4 transactionIdLen,
                                  const ubyte4 pollInterval, const ubyte4 pollCount,
#ifdef __ENABLE_DIGICERT_CMS_RSA_OAEP__
                                  ubyte isOaep, sbyte *pOaepLabel, ubyte4 oaepHashAlgo,
#endif
                                  ubyte **ppCert, ubyte4 *pCertLen)
{
    MSTATUS status = OK;
    scepContext *pScepContext = NULL;
    ubyte        *pQuery = NULL;
    ubyte4       queryLen;
    sbyte        *completeUri = NULL;
    ubyte4       completeUriLen=0;
    ubyte        *pHttpResp = NULL;
    ubyte4       httpRespLen;
    void*        pCookie = NULL;
    void*        pCachedCookie = NULL;
    sbyte        tcpBuffer[SCEP_TCP_READ_BUFFER];
    sbyte4       nRet;
    sbyte        *respFile = NULL;
    byteBoolean  usePost = TRUE;
    ubyte4       serverType;
    ubyte4       bodyLen;
#ifdef __ENABLE_DIGICERT_TAP__
    byteBoolean  useTap = FALSE;
#endif

    /*validate input parameters */
    if ( (NULL == pKeySource) || (NULL == pPemKeyBlob) || (NULL == pPkcs10Csr) ||
        (NULL == ppCert) || (NULL == pCertLen) ||
        (NULL == pServerUrl) || (NULL == pReqInfo) || (NULL == pHttpContext) ||
        (NULL == pRequesterCert) || (0 == numCaCerts) || (0 == numRaCerts)  ||
        (NULL == pTransactionID) || (0 == transactionIdLen) ||
        ((requestType == 3 || requestType == 2) && (NULL == pOldPemKeyBlob)))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }


#ifdef __ENABLE_DIGICERT_TAP__
    if ((0 == DIGI_STRCMP((const sbyte*)pKeySource, (const sbyte*)KEY_SOURCE_TPM2)))
    {
        useTap = TRUE;
    }
#endif

    if (OK > (status = SCEP_SAMPLE_initContext(&pScepContext, NULL,
#ifdef __ENABLE_DIGICERT_TAP__
                                               useTap,
#endif
#ifdef __ENABLE_DIGICERT_CMS_RSA_OAEP__
                                               isOaep, pOaepLabel, oaepHashAlgo,
#endif
                                               pPemKeyBlob, pemKeyBlobLen,
                                               pOldPemKeyBlob, oldPemKeyBlobLen,
                                               pCACerts, numCaCerts,
                                               pRACerts, numRaCerts,
                                               pRequesterCert)))
    {
        goto exit;
    }

    if (OK > (status = SCEP_CLIENT_setRequestInfo(pScepContext, pReqInfo)))
        goto exit;

	if (NULL == (pScepContext->pTransAttrs = MALLOC(sizeof(transactionAttributes))))
	{
		status = ERR_MEM_ALLOC_FAIL;
		goto exit;
	}
	DIGI_MEMSET((ubyte*)pScepContext->pTransAttrs, 0x00, sizeof(transactionAttributes));

    pScepContext->pTransAttrs->messageType = scep_PKCSReq;
    if (OK != (status = DIGI_CALLOC((void**)&(pScepContext->pTransAttrs->transactionID), 1, transactionIdLen)))
    {
        goto exit;
    }
    if (OK != (status = DIGI_MEMCPY((ubyte*)pScepContext->pTransAttrs->transactionID, pTransactionID, transactionIdLen)))
    {
        goto exit;
    }
    pScepContext->pTransAttrs->transactionIDLen = transactionIdLen;
    pScepContext->pTransAttrs->pkiStatus = scep_PENDING;

    /* TODO resetContext should be done here or in application ? */
	HTTP_CONTEXT_resetContext(pHttpContext);

    /* choose which style of request: URL, or POST */
    /* NOTE: win20xx scep addon doesn't support POST mode */
    if (OK > (status = getServerTypeDetails((sbyte*)pServerType, &usePost, &serverType)))
    {
        goto exit;
    }

     /* Incase of Pending Retry also use the generateRequest API - inorder to handle HTTP
      POST related initializations*/
     if (!usePost)
     {
       if (OK > (status = SCEP_CLIENT_generateRequest(pScepContext, &pQuery, &queryLen)))
          goto exit;
     }
     else
     {
       if (OK > (status = SCEP_CLIENT_generateRequestEx(pScepContext, TRUE,
                                                  &pQuery, &queryLen, &bodyLen, &pCookie)))
          goto exit;
       if (OK > (status = HTTP_setCookie(pHttpContext, pCookie)))
         goto exit;
       if (OK > (status = HTTP_REQUEST_setRequestMethodIfNotSet(pHttpContext, &mHttpMethods[POST])))
            goto exit;
       if (OK > (status = HTTP_REQUEST_setContentLengthIfNotSet(pHttpContext, bodyLen)))
          goto exit;
      }


    /* set request method to GET if not set already */
    if (OK > (status = HTTP_REQUEST_setRequestMethodIfNotSet(pHttpContext,
                    &mHttpMethods[GET])))
       goto exit;

    completeUriLen = (ubyte4) DIGI_STRLEN((sbyte*)pServerUrl) + 1 + queryLen;
    if (NULL == (completeUri = MALLOC(completeUriLen+1)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    DIGI_MEMCPY((void *) completeUri, (const void *) pServerUrl, (sbyte4)DIGI_STRLEN((sbyte*)pServerUrl));
    *(completeUri+DIGI_STRLEN((sbyte*)pServerUrl)) = '?';
    DIGI_MEMCPY((void *) (completeUri+(sbyte4)DIGI_STRLEN((void *)pServerUrl)+1),
            (const void *) pQuery, queryLen);
    *(completeUri+completeUriLen) = '\0';

    /* set request URI */
    if (OK > (status = HTTP_REQUEST_setRequestUriIfNotSet(pHttpContext, completeUri)))
        goto exit;

    /* send request */
    if (OK > (status = HTTP_recv(pHttpContext, NULL, 0)))
        goto exit;

    /* finish sending the request via transport... */
    while (!HTTP_REQUEST_isDoneSendingRequest(pHttpContext))
    {
        if (OK > (status = HTTP_continue(pHttpContext)))
            goto exit;
    }
    DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"Sent request......\n");

    int retryCount = pollCount;
    while (retryCount)
    {
        status = TCP_READ_AVL(pHttpContext->socket, tcpBuffer, SCEP_TCP_READ_BUFFER, (ubyte4 *) &nRet, 50000);

        if (status == ERR_TCP_READ_TIMEOUT)
        {
            DEBUG_PRINT(DEBUG_SCEP_EXAMPLE, "readtimeout......\n");
            continue;
        }
        else if (status < OK)
            goto exit;

        if (nRet <= 0)
            continue;

        /* DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "SCEP_CLIENT_EXAMPLE TCP_READ_AVL = ", nRet); */

        /* process response */
        if (OK > (status = HTTP_recv(pHttpContext, (ubyte*)tcpBuffer, nRet)))
            goto exit;

        if (HTTP_isDone(pHttpContext))
        {
            ubyte4 statusCode;
            if (pHttpResp)
            {
                FREE(pHttpResp);
                pHttpResp = NULL;
                httpRespLen = 0;
            }
            if (OK > (status = HTTP_REQUEST_getStatusCode(pHttpContext, &statusCode)))
            {
                goto exit;
            }

            if (OK > (status = HTTP_REQUEST_getResponseContent(pHttpContext, &pHttpResp, &httpRespLen)))
            {
                goto exit;
            }
            if (statusCode < 300)
            {
                const ubyte *pContentType;
                ubyte4 contentTypeLen;
                if (OK > (status = HTTP_REQUEST_getContentType(pHttpContext, &pContentType, &contentTypeLen)))
                {
                    goto exit;
                }

                if (OK > (status = SCEP_CLIENT_recvResponse(pScepContext, (ubyte*)pContentType, contentTypeLen, pHttpResp, httpRespLen))){

                    goto exit;
                }

                if (SCEP_CLIENT_getStatus(pScepContext) == scep_SUCCESS)
                {
                    ubyte* respBody;
                    ubyte4 respBodyLen;
                    SCEP_CLIENT_getResponseContent(pScepContext, &respBody, &respBodyLen);
                    /*sbyte* filename = (sbyte*)DEF_FILENAME;
                    if (messageType == scep_PKCSReq && user == 0)
                    {
                        if (gSelfCert)
                        {
                            FREE(gSelfCert);
                            gSelfCert = NULL;
                        }
                        gSelfCert = (ubyte*)MALLOC(respBodyLen );
                        DIGI_MEMCPY(gSelfCert, respBody, respBodyLen);
                        gSelfCertLen = respBodyLen;
                    }
                    filename = (sbyte*) REQUESTER_CERT_FILE;*/

                    if (respBodyLen == 0)
                    {
                        DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"WARNING: SCEP_EXAMPLE: Received response 0 length with file name: \n");
                        goto exit;
                    }
                    *ppCert = respBody;
                    *pCertLen = respBodyLen;

                    if (respFile)
                    {
                        FREE (respFile);
                        respFile = NULL;
                    }
                    DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"\n");
                    break;
                }
                else if (SCEP_CLIENT_getStatus(pScepContext) == scep_PENDING)
                {
                    DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"SCEP_EXAMPLE: Received response with PENDING status.\n");
                    retryCount--;
                    if (completeUri)
                    {
                        FREE(completeUri);
                        completeUri = NULL;
                    }
                    if (pQuery)
                    {
                        FREE(pQuery);
                        pQuery = NULL;
                    }
                    if (pCookie)
                    {
                        SCEP_CLIENT_releaseCookie(pCookie);
                        pCookie = NULL;
                    }
                    /* EJBCA doesn't support polling */
                    RTOS_sleepMS(pollInterval); /* sleep for one minute etc */
                    /* pCachedCookie is an opaque cookie that once obtained,
                     * can be saved to resume with SCEP_CLIENT_pollServer later on */
                    HTTP_CONTEXT_resetContext(pHttpContext);
                    if (OK > (status = SCEP_CLIENT_generatePollServerRequest(pScepContext,
                                    &pQuery, &queryLen, &bodyLen, &pCookie, &pCachedCookie)))
                        goto exit;

                    /* send polling request */
                    if (pScepContext->useHttpPOST)
                    {
                        if (OK > (status = HTTP_setCookie(pHttpContext, pCookie)))
                            goto exit;
                        if (OK > (status = HTTP_REQUEST_setRequestMethodIfNotSet(pHttpContext,
                                        &mHttpMethods[POST])))
                            goto exit;
                        if (OK > (status = HTTP_REQUEST_setContentLengthIfNotSet(pHttpContext, bodyLen)))
                            goto exit;
                    }

                    /* set request method to GET if not set already */
                    if (OK > (status = HTTP_REQUEST_setRequestMethodIfNotSet(pHttpContext,
                                    &mHttpMethods[GET])))
                        goto exit;
                    completeUriLen = (ubyte4) DIGI_STRLEN((sbyte *)pServerUrl) + 1 + queryLen;
                    if (NULL == (completeUri = MALLOC(completeUriLen+1)))
                    {
                        status = ERR_MEM_ALLOC_FAIL;
                        goto exit;
                    }
                    DIGI_MEMCPY((void *) completeUri, (const void *) pServerUrl, (sbyte4)DIGI_STRLEN((sbyte*)pServerUrl));
                    *(completeUri+DIGI_STRLEN((sbyte *)pServerUrl)) = '?';
                    DIGI_MEMCPY((void *) (completeUri+(sbyte4)DIGI_STRLEN((void *)pServerUrl)+1),
                            (const void *) pQuery, queryLen);
                    *(completeUri+completeUriLen) = '\0';

                    /* set request URI */
                    if (OK > (status = HTTP_REQUEST_setRequestUriIfNotSet(pHttpContext, completeUri)))
                        goto exit;

                    /* send request */
                    if (OK > (status = HTTP_recv(pHttpContext, NULL, 0)))
                        goto exit;
                    /* finish sending the request via transport... */
                    while (!HTTP_REQUEST_isDoneSendingRequest(pHttpContext))
                    {
                        if (OK > (status = HTTP_continue(pHttpContext)))
                            goto exit;
                    }
                }
                else
                {
                    /* failed reason: check failInfo*/
                    SCEP_failInfo failInfo;
                    SCEP_CLIENT_getFailInfo(pScepContext, &failInfo);
                    DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"SCEP_EXAMPLE: Received response with FAILURE status: ");
                    switch (failInfo)
                    {
                        case scep_badAlg:
                            DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"badAlg\n");
                            break;
                        case scep_badMessageCheck:
                            DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"badMessageCheck\n");
                            break;
                        case scep_badRequest:
                            DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"badRequest\n");
                            break;
                        case scep_badTime:
                            DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"badTime\n");
                            break;
                        case scep_badCertId:
                            DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"badCertId\n");
                            break;
                        default:
                            DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"Unknown\n");
                            break;
                    }
                    break;
                }
            }
            else
            {
                /* print out http response reason phrase */
                const ubyte* reasonPhrase;
                ubyte4 reasonPhraseLength;
                sbyte* str = NULL;
                if (OK > (status = HTTP_REQUEST_getStatusPhrase(pHttpContext,
                                &reasonPhrase, &reasonPhraseLength)))
                    goto exit;
                str = MALLOC(reasonPhraseLength+1);
                if (str)
                {
                    DIGI_MEMCPY(str, reasonPhrase, reasonPhraseLength);
                    *(str+reasonPhraseLength) = '\0';
                    DEBUG_PRINT2(DEBUG_SCEP_EXAMPLE,"SCEP_EXAMPLE: Received response with HTTP error status: ", str);
                    DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"\n");
                    DIGI_FREE((void**)&str);
                }
                status = ERR_HTTP;
                break;
            }
        }
    }

exit:
    if (pQuery)
    {
        FREE(pQuery);
        pQuery = NULL;
    }
    if (completeUri)
    {
        FREE(completeUri);
        completeUri = NULL;
    }
    if (pHttpResp)
    {
        FREE(pHttpResp);
        pHttpResp = NULL;
    }
    if (pCookie)
    {
        SCEP_CLIENT_releaseCookie(pCookie);
    }
    if (pCachedCookie)
    {
        SCEP_CLIENT_releasePollCookie(pCachedCookie);
    }
    if (pScepContext && SCEP_CLIENT_getStatus(pScepContext) == scep_PENDING)
    {
        /* Same requestInfo will be used at the time of pending enrollment
           so don't free requestInfo.*/
        pScepContext->pReqInfo = NULL;
    }
    if (pScepContext)
        SCEP_CLIENT_releaseContext(&pScepContext);
    return status;

}

/*------------------------------------------------------------------*/

static sbyte4 my_HttpTcpSend(httpContext *pHttpContext, sbyte4 socket,
                                ubyte *pDataToSend, ubyte4 numBytesToSend,
                                ubyte4 *pRetNumBytesSent, sbyte4 isContinueFromBlock)
{
    TCP_WRITE(socket, (sbyte *)pDataToSend,numBytesToSend, pRetNumBytesSent);
    return 0;
}

static
MSTATUS getAddressInfo(sbyte *pHost, sbyte **ppAddr)
{
    struct addrinfo hints, *pRes = NULL, *pTmp = NULL;
    int errcode;
    char addrStr[SCEP_ADDR_BUFFER];
    void *pData = NULL;
    MSTATUS status = OK;

    if (OK > (status = DIGI_MEMSET((ubyte*)&hints, 0, sizeof (hints))))
    {
        goto exit;
    }
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_CANONNAME;

    errcode = getaddrinfo ((const char *)pHost, NULL, &hints, &pRes);
    if (errcode != 0)
    {
        status = ERR_HTTP;
        DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "Failed to get addrinfo: ", status);
        goto exit;
    }
    pTmp = pRes;
    while (pTmp)
    {
        switch (pTmp->ai_family)
        {
            case AF_INET:
                pData = &((struct sockaddr_in *) pTmp->ai_addr)->sin_addr;
                break;
            case AF_INET6:
                pData = &((struct sockaddr_in6 *) pTmp->ai_addr)->sin6_addr;
                break;
            default:
                pData = NULL;
                break;
        }

        if (NULL == pData || NULL == inet_ntop (pTmp->ai_family, pData, addrStr, SCEP_ADDR_BUFFER))
        {
            DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"Warning: inet_ntop failed\n");
            goto exit;
        }

        pTmp = pTmp->ai_next;
    }

    if (OK != (status = DIGI_CALLOC((void**)ppAddr, 1, DIGI_STRLEN((const sbyte*)addrStr)+1)))
    {
        goto exit;
    }

    if (OK != (status = DIGI_MEMCPY((ubyte*)*ppAddr, addrStr, DIGI_STRLEN((const sbyte*)addrStr))))
    {
        DIGI_FREE((void**)ppAddr);
        goto exit;
    }

exit:
    if (pRes != NULL)
        freeaddrinfo(pRes);
    return status;
}

#ifdef __ENABLE_DIGICERT_TAP__
MSTATUS SCEP_CLIENT_EXAMPLE_tapUninitialize()
{
    MSTATUS status = OK;
    TAP_ErrorContext errContext;

    /* Uninitialize context */
    if ((NULL != g_pTapContext))
    {
        status = TAP_uninitContext(&g_pTapContext, &errContext);
        if (OK != status)
        {
            DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "SCEP_CLIENT_EXAMPLE_tapUninitialize::TAP_uninitContext::status: ", status);
            goto exit;
        }
    }
    status = TAP_uninit(&errContext);
    if (OK != status)
        DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "SCEP_CLIENT_EXAMPLE_tapUninitialize::TAP_uninit::status: ", status);

exit:
    return status;
}

MSTATUS SCEP_CLIENT_EXAMPLE_tapInitialize(ubyte *pTpm2ConfigFile)
{
    MSTATUS status = OK;
    TAP_ConfigInfo config = {0};
    TAP_ConfigInfoList configInfoList = { 0, };
    TAP_Context *pTapContext = NULL;
    TAP_ErrorContext errContext;
    TAP_ErrorContext *pErrContext = &errContext;
    TAP_EntityCredentialList *pEntityCredentialList = NULL;
    TAP_Module module = {0};
    ubyte2 tapProvider = 0;
    ubyte *pPassBuf = NULL;
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
    TAP_ConnectionInfo connInfo = { 0 };
#endif

    /* Determine TAP provider from key source */
    if (NULL == scepc_keySource)
    {
        status = ERR_TAP_NO_PROVIDERS_AVAILABLE;
        DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "SCEP_CLIENT_EXAMPLE_tapInitialize::Key source not specified: ", status);
        goto exit;
    }

    if(DIGI_STRCMP((const sbyte *)scepc_keySource, (const sbyte *)"TPM2") == 0)
    {
        tapProvider = TAP_PROVIDER_TPM2;
    }
    else if(DIGI_STRCMP((const sbyte *)scepc_keySource, (const sbyte *)"TPM1.2") == 0)
    {
        tapProvider = TAP_PROVIDER_TPM;
    }
    else if(DIGI_STRCMP((const sbyte *)scepc_keySource, (const sbyte *)"PKCS11") == 0)
    {
        tapProvider = TAP_PROVIDER_PKCS11;
    }
    else if(DIGI_STRCMP((const sbyte *)scepc_keySource, (const sbyte *)"NXPA71") == 0)
    {
        tapProvider = TAP_PROVIDER_NXPA71;
    }
    else if(DIGI_STRCMP((const sbyte *)scepc_keySource, (const sbyte *)"STSAFE") == 0)
    {
        tapProvider = TAP_PROVIDER_STSAFE;
    }
    else if(DIGI_STRCMP((const sbyte *)scepc_keySource, (const sbyte *)"SGX") == 0)
    {
        tapProvider = TAP_PROVIDER_SGX;
    }
    else if(DIGI_STRCMP((const sbyte *)scepc_keySource, (const sbyte *)"TEE") == 0)
    {
        tapProvider = TAP_PROVIDER_TEE;
    }
    else if(DIGI_STRCMP((const sbyte *)scepc_keySource, (const sbyte *)"GEMSIM") == 0)
    {
        tapProvider = TAP_PROVIDER_GEMSIM;
    }
    else
    {
        status = ERR_TAP_NO_PROVIDERS_AVAILABLE;
        DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "SCEP_CLIENT_EXAMPLE_tapInitialize::Unsupported key source: ", status);
        goto exit;
    }

    pScepTapProvider = tapProvider;

    config.provider = tapProvider;
    configInfoList.count = 1;
    configInfoList.pConfig = &config;

#ifndef __ENABLE_DIGICERT_TAP_REMOTE__
    status = TAP_readConfigFile((char *)pTpm2ConfigFile,
                   &configInfoList.pConfig[0].configInfo, FALSE);
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "SCEP_CLIENT_EXAMPLE_tapInitialize::TAP_readConfigFile::status: ", status);
        goto exit;
    }
#endif

    status = TAP_init(&configInfoList, pErrContext);
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "SCEP_CLIENT_EXAMPLE_tapInitialize::TAP_init::status: ", status);
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
    /* Discover modules */
    connInfo.serverName.bufferLen = DIGI_STRLEN((const sbyte *)pScepTapServerName)+1;
    status = DIGI_CALLOC ((void **)&(connInfo.serverName.pBuffer), 1, connInfo.serverName.bufferLen);
    if (OK != status)
    goto exit;

    status = DIGI_MEMCPY ((void *)(connInfo.serverName.pBuffer), (void *)pScepTapServerName,
                                                DIGI_STRLEN((const sbyte *)pScepTapServerName));
    if (OK != status)
    goto exit;

    connInfo.serverPort = pScepTapServerPort;
    module.hostInfo = connInfo;
#endif

    if (0 == pScepTapModuleId)
    {
        status = ERR_TAP_BAD_MODULE_ID;
        goto exit;
    }
    module.providerType = tapProvider;
    module.moduleId = pScepTapModuleId;

    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "SCEP_CLIENT_EXAMPLE_tapInitialize::DIGI_CALLOC::status: ", status);
        goto exit;
    }


#ifndef __ENABLE_DIGICERT_TAP_REMOTE__
    status = TAP_getModuleCredentials(&module,
            (char *)pTpm2ConfigFile, TRUE,
            &pEntityCredentialList,
            pErrContext);

    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "SCEP_CLIENT_EXAMPLE_tapInitialize::TAP_getModuleCredentials::status: ", status);
        goto exit;
    }
#endif

    /* Initialize context on first module */
    pTapContext = NULL;
    status = TAP_initContext(&module, pEntityCredentialList,
                                NULL, &pTapContext, pErrContext);
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "SCEP_CLIENT_EXAMPLE_tapInitialize::TAP_initContext::status: ", status);
        goto exit;
    }
    g_pTapContext = pTapContext;
    g_pEntityCredentialList = pEntityCredentialList;

    if (NULL != pScepTapKeyPassword)
    {
        if (OK != (status = DIGI_CALLOC((void**)&g_pKeyCredentialList, 1, sizeof(TAP_CredentialList))))
        {
            DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "SCEP_CLIENT_EXAMPLE_tapInitialize::DIGI_CALLOC::status: ", status);
            goto exit;
        }

        /* Set Key Credentials */
        status = DIGI_CALLOC((void **) &(g_pKeyCredentialList->pCredentialList), 1, sizeof(TAP_Credential));
        if (OK != status)
        {
            DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "SCEP_CLIENT_EXAMPLE_tapInitialize::DIGI_CALLOC::status: ", status);
            goto exit;
        }
        g_pKeyCredentialList->numCredentials = 1;
        g_pKeyCredentialList->pCredentialList[0].credentialType = TAP_CREDENTIAL_TYPE_PASSWORD;
        g_pKeyCredentialList->pCredentialList[0].credentialFormat = TAP_CREDENTIAL_FORMAT_PLAINTEXT;
        g_pKeyCredentialList->pCredentialList[0].credentialContext = TAP_CREDENTIAL_CONTEXT_ENTITY;
        status = DIGI_MALLOC((void**)&pPassBuf, DIGI_STRLEN(pScepTapKeyPassword));
        if (OK != status)
        {
            DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "SCEP_CLIENT_EXAMPLE_tapInitialize::DIGI_MALLOC::status: ", status);
            goto exit;
        }
        status = DIGI_MEMCPY((ubyte*)pPassBuf, pScepTapKeyPassword, DIGI_STRLEN(pScepTapKeyPassword));
        if (OK != status)
        {
            DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "SCEP_CLIENT_EXAMPLE_tapInitialize::DIGI_MEMCPY::status: ", status);
            if (pPassBuf) DIGI_FREE((void**)&pPassBuf);
            goto exit;
        }
        g_pKeyCredentialList->pCredentialList[0].credentialData.bufferLen = DIGI_STRLEN(pScepTapKeyPassword);
        g_pKeyCredentialList->pCredentialList[0].credentialData.pBuffer = pPassBuf;
    }

exit:

    /* Free config info */
    if (NULL != configInfoList.pConfig)
    {
        (void) TAP_UTILS_freeBuffer(&(configInfoList.pConfig[0].configInfo)); /* ok if empty configInfo */
    }

#if (defined(__ENABLE_DIGICERT_TAP_REMOTE__))
    if (connInfo.serverName.pBuffer != NULL)
    {
        DIGI_FREE((void**)&connInfo.serverName.pBuffer);
    }
#endif
    return status;
}

static sbyte4
SCEP_CLIENT_EXAMPLE_getTapContext(TAP_Context **ppTapContext,
                                  TAP_EntityCredentialList **ppTapEntityCred,
                                  TAP_CredentialList **ppTapKeyCred,
                                  void *pKey, TapOperation op, ubyte getContext)
{
    MSTATUS status = OK;
    if ((pKey == NULL) || (NULL == ppTapContext) ||
        (NULL == ppTapEntityCred) || (NULL == ppTapKeyCred))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    if (getContext)
    {
        *ppTapContext = g_pTapContext;
        *ppTapEntityCred = g_pEntityCredentialList;
        *ppTapKeyCred = g_pKeyCredentialList;
    }
    else
    {
        /* tapContext, tap key credentails and EntityCredentials will be freed at the end of the application */
        *ppTapContext = NULL;
        *ppTapEntityCred = NULL;
        *ppTapKeyCred = NULL;
    }

exit:
    return status;
}

#endif /*__ENABLE_DIGICERT_TAP__*/

/*------------------------------------------------------------------*/

/* Forward declarations */
static void setFullPathWithSubdir(sbyte *fname, sbyte *basePath, const sbyte *subdir, sbyte **fpath);
static void setFullPath(sbyte *fname, sbyte *path, sbyte **fpath);

/*------------------------------------------------------------------*/

static MSTATUS
scep_write_cacerts(ubyte *pResponse, ubyte4 responseLen, sbyte *pFileName, sbyte *pBasePath)
{
    ubyte4 i = 0, certLen, tag;
    sbyte *pRespFile = NULL;
    ubyte pOutCert[MAX_FILE_NAME];
    MSTATUS status = OK;
    sbyte4 cmpRes = -1, tagAndCount;
    ubyte *pExtractedCerts = NULL;
    ubyte4 extractedCertsLen = 0;
    byteBoolean freeExtracted = FALSE;
    MemFile certRepMemFile;
    CStream certRepStream;
    ASN1_ITEMPTR pCertRepSignedRoot = NULL;
    ASN1_ITEMPTR pFirstCert = NULL;

    if (NULL == pResponse)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Check if this is a PKCS#7 degenerate SignedData and extract certificates */
    if (responseLen > 10 && pResponse[0] == 0x30)
    {
        MF_attach(&certRepMemFile, responseLen, pResponse);
        CS_AttachMemFile(&certRepStream, &certRepMemFile);

        if (OK == ASN1_Parse(certRepStream, &pCertRepSignedRoot))
        {
            /* Try to extract certificates from PKCS#7 SignedData */
            if (OK == PKCS7_GetCertificates(pCertRepSignedRoot, certRepStream, &pFirstCert) && pFirstCert != NULL)
            {
                /* Calculate total length of all certificates */
                ASN1_ITEMPTR pCert = pFirstCert;
                extractedCertsLen = 0;

                while (pCert != NULL)
                {
                    extractedCertsLen += pCert->headerSize + pCert->length;
                    pCert = ASN1_NEXT_SIBLING(pCert);
                }

                if (extractedCertsLen > 0)
                {
                    if (OK == DIGI_CALLOC((void**)&pExtractedCerts, 1, extractedCertsLen))
                    {
                        /* Copy all certificates */
                        pCert = pFirstCert;
                        ubyte4 offset = 0;

                        while (pCert != NULL)
                        {
                            ubyte4 certLen = pCert->headerSize + pCert->length;
                            ubyte4 certStart = pCert->dataOffset - pCert->headerSize;
                            const ubyte *certData = CS_memaccess(certRepStream, certStart, certLen);

                            if (certData != NULL)
                            {
                                DIGI_MEMCPY(pExtractedCerts + offset, certData, certLen);
                                CS_stopaccess(certRepStream, certData);
                                offset += certLen;
                            }
                            pCert = ASN1_NEXT_SIBLING(pCert);
                        }

                        /* Use extracted certificates instead of original response */
                        pResponse = pExtractedCerts;
                        responseLen = extractedCertsLen;
                        freeExtracted = TRUE;
                        DEBUG_PRINTNL(DEBUG_SCEP_EXAMPLE, "Extracted certificates from PKCS#7 wrapper");
                    }
                }
            }
            TREE_DeleteTreeItem((TreeItem*)pCertRepSignedRoot);
        }
    }

    if (responseLen > 28)
    {
        status = DIGI_MEMCMP(
            pResponse, (ubyte *) "-----BEGIN CERTIFICATE-----", 27, &cmpRes);
        if (OK != status)
            goto exit;
    }

    if (0 == cmpRes)
    {
        if (pBasePath != NULL)
        {
            setFullPathWithSubdir((sbyte *)pFileName, pBasePath, (const sbyte*)"ca", &pRespFile);
        }
        else
        {
            setFullPath((sbyte *)pFileName, filePath, &pRespFile);
        }

        if (NULL == pRespFile)
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }

        status = DIGI_MEMCPY(
            pRespFile + DIGI_STRLEN(pRespFile) - 3, (ubyte *) "pem", 3);
        if (OK != status)
            goto exit;

        if (OK > (status = DIGICERT_writeFile(
            (const char *) pRespFile, pResponse, responseLen)))
        {
            DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "scep_write_cacerts::DIGICERT_writeFile: ", status);
        }
        else
        {
            DEBUG_PRINT2(DEBUG_SCEP_EXAMPLE, "CA certificate saved to: ", pRespFile);
            DEBUG_PRINTNL(DEBUG_SCEP_EXAMPLE, "");
        }

        goto exit;
    }

    /* If the certificate is in DER format then loop through each certificate
     * and write out each one to a separate file */
    while (responseLen != 0)
    {
        status = ASN1_readTagAndLen(
            pResponse, responseLen, &tag, &certLen, &tagAndCount);
        if (OK != status)
        {
            DEBUG_ERROR(
                DEBUG_SCEP_EXAMPLE, "scep_write_cacerts::ASN1_readTagAndLen: ",
                status);
            goto exit;
        }

        certLen += tagAndCount;

        if (responseLen < certLen)
        {
            status = ERR_BAD_LENGTH;
            DEBUG_ERROR(
                DEBUG_SCEP_EXAMPLE,
                "scep_write_cacerts::Invalid certificate length: ", status);
            goto exit;
        }

        status = DIGI_MEMSET(pOutCert, 0x00, MAX_FILE_NAME);
        if (OK != status)
        {
            DEBUG_ERROR(
                DEBUG_SCEP_EXAMPLE, "scep_write_cacerts::DIGI_MEMSET: ", status);
            goto exit;
        }

        if (pBasePath != NULL)
        {
            setFullPathWithSubdir((sbyte *)pFileName, pBasePath, (const sbyte*)"ca", &pRespFile);
        }
        else
        {
            setFullPath((sbyte *)pFileName, filePath, &pRespFile);
        }

        if (NULL == pRespFile)
        {
            status = ERR_SCEP;
            DEBUG_ERROR(
                DEBUG_SCEP_EXAMPLE,
                "scep_write_cacerts::SetFullPath returned NULL: ", status);
            goto exit;
        }

        status = DIGI_MEMCPY(
            pOutCert, pRespFile, DIGI_STRLEN(pRespFile) - 4);
        if (OK != status)
        {
            DEBUG_ERROR(
                DEBUG_SCEP_EXAMPLE, "scep_write_cacerts::DIGI_MEMCPY: ", status);
            goto exit;
        }

        ubyte4 currentLen = DIGI_STRLEN((sbyte*)pOutCert);
        ubyte4 remainingSpace = MAX_FILE_NAME - currentLen;
        sbyte4 ret = snprintf((char *)pOutCert + currentLen, remainingSpace, ".der");
        if (ret < 0 || ret >= remainingSpace)
        {
            status = ERR_BUFFER_OVERFLOW;
            DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "scep_write_cacerts::filename too long: ", status);
            goto exit;
        }
        DIGI_FREE((void**)&pRespFile);
        pRespFile = NULL;

        DEBUG_PRINT2(DEBUG_SCEP_EXAMPLE, "CA certificate saved to: ", (sbyte*)pOutCert);
        DEBUG_PRINTNL(DEBUG_SCEP_EXAMPLE, "");

        status = DIGICERT_writeFile((const char *) pOutCert, pResponse, certLen);
        if (OK != status)
        {
            DEBUG_ERROR(
                DEBUG_SCEP_EXAMPLE, "scep_write_cacerts::DIGICERT_writeFile: ",
                status);
            goto exit;
        }

        responseLen -= certLen;
        pResponse += certLen;
        i++;
    }

exit:
    if (pRespFile)
    {
        DIGI_FREE((void**)&pRespFile);
    }
    if (freeExtracted && pExtractedCerts)
    {
        DIGI_FREE((void**)&pExtractedCerts);
    }
    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS
SCEP_SAMPLE_getCACert(httpContext *pHttpContext, ubyte *pServerUrl, sbyte *pBasePath)
{
    MSTATUS status = OK;
    scepContext *pScepContext = NULL;
    requestInfo *pReqInfo = NULL;
    ubyte *pQuery = NULL;
    ubyte4 queryLen;
    sbyte *completeUri = NULL;
    ubyte4 completeUriLen;
    void *pCookie = NULL;
    byteBoolean usePost = FALSE;
    ubyte *respBody = NULL;
    ubyte4 respBodyLen = 0;
    sbyte tcpBuffer[SCEP_TCP_READ_BUFFER];
    sbyte4 nRet;
    ubyte4 statusCode;

    DEBUG_PRINT(DEBUG_SCEP_EXAMPLE, "\nFetching CA Certificate(s)...\n");

    if (OK > (status = SCEP_CONTEXT_createContext(&pScepContext, SCEP_CLIENT)))
    {
        DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "SCEP_SAMPLE_getCACert::SCEP_CONTEXT_createContext::status", status);
        goto exit;
    }

    if (NULL == (pReqInfo = MALLOC(sizeof(requestInfo))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    DIGI_MEMSET((ubyte*)pReqInfo, 0, sizeof(requestInfo));
    pReqInfo->type = scep_GetCACert;

    pReqInfo->value.caIdent.ident = NULL;
    pReqInfo->value.caIdent.identLen = 0;

    if (OK > (status = SCEP_CLIENT_setRequestInfo(pScepContext, pReqInfo)))
    {
        DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "SCEP_SAMPLE_getCACert::SCEP_CLIENT_setRequestInfo::status", status);
        goto exit;
    }
    pReqInfo = NULL;

    if (OK > (status = SCEP_CLIENT_generateRequest(pScepContext, &pQuery, &queryLen)))
    {
        DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "SCEP_SAMPLE_getCACert::SCEP_CLIENT_generateRequest::status", status);
        goto exit;
    }

    completeUriLen = DIGI_STRLEN(pServerUrl) + queryLen + 2;
    completeUri = MALLOC(completeUriLen);
    if (NULL == completeUri)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(completeUri, pServerUrl, DIGI_STRLEN(pServerUrl));
    completeUri[DIGI_STRLEN(pServerUrl)] = '?';
    DIGI_MEMCPY(&completeUri[DIGI_STRLEN(pServerUrl) + 1], pQuery, queryLen);
    completeUri[completeUriLen - 1] = '\0';

    /* Send SCEP message */
    /* set request URI */
    if (OK > (status = HTTP_REQUEST_setRequestUriIfNotSet(pHttpContext, completeUri)))
    {
        DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "SCEP_SAMPLE_getCACert::HTTP_REQUEST_setRequestUriIfNotSet::status", status);
        goto exit;
    }

    /* send request */
    if (OK > (status = HTTP_recv(pHttpContext, NULL, 0)))
    {
        DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "SCEP_SAMPLE_getCACert::HTTP_recv::status", status);
        goto exit;
    }

    /* finish sending the request via transport... */
    while (!HTTP_REQUEST_isDoneSendingRequest(pHttpContext))
    {
        if (OK > (status = HTTP_continue(pHttpContext)))
        {
            DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "SCEP_SAMPLE_getCACert::HTTP_continue::status", status);
            goto exit;
        }
    }

    /* Read response */
    while (1)
    {
        status = TCP_READ_AVL(pHttpContext->socket, tcpBuffer, SCEP_TCP_READ_BUFFER, (ubyte4 *) &nRet, 50000);

        if (status == ERR_TCP_READ_TIMEOUT)
        {
            continue;
        }
        else if (status < OK)
        {
            DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "SCEP_SAMPLE_getCACert::TCP_READ_AVL::status", status);
            goto exit;
        }

        if (nRet <= 0)
            continue;

        /* process response */
        if (OK > (status = HTTP_recv(pHttpContext, (ubyte*)tcpBuffer, nRet)))
        {
            DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "SCEP_SAMPLE_getCACert::HTTP_recv(2)::status", status);
            goto exit;
        }

        if (HTTP_isDone(pHttpContext))
        {
            if (OK > (status = HTTP_REQUEST_getStatusCode(pHttpContext, &statusCode)))
            {
                DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "SCEP_SAMPLE_getCACert::HTTP_REQUEST_getStatusCode::status", status);
                goto exit;
            }

            if (OK > (status = HTTP_REQUEST_getResponseContent(pHttpContext, &respBody, &respBodyLen)))
            {
                DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "SCEP_SAMPLE_getCACert::HTTP_REQUEST_getResponseContent::status", status);
                goto exit;
            }

            if (statusCode >= 300)
            {
                DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "SCEP_SAMPLE_getCACert: HTTP error status", statusCode);
                status = ERR_SCEP;
                goto exit;
            }
            break;
        }
    }

    if (0 == respBodyLen || NULL == respBody)
    {
        status = ERR_SCEP;
        DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "SCEP_SAMPLE_getCACert: Empty response body", status);
        goto exit;
    }

    /* Write CA certificate(s) to file */
    status = scep_write_cacerts(respBody, respBodyLen, (sbyte*)SCEP_CA_CERT_FILE, pBasePath);
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "SCEP_SAMPLE_getCACert::scep_write_cacerts::status", status);
        goto exit;
    }

    DEBUG_PRINTNL(DEBUG_SCEP_EXAMPLE, "CA certificate(s) retrieved successfully");

exit:
    if (pScepContext)
    {
        SCEP_CLIENT_releaseContext(&pScepContext);
    }
    if (pReqInfo)
    {
        if (pReqInfo->value.caIdent.ident)
            FREE(pReqInfo->value.caIdent.ident);
        FREE(pReqInfo);
    }
    if (pQuery)
        FREE(pQuery);
    if (completeUri)
        FREE(completeUri);
    if (respBody)
        FREE(respBody);
    if (pCookie)
        SCEP_CLIENT_releaseCookie(pCookie);

    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS
SCEP_CLIENT_readTrustedConfig(void)
{
    MSTATUS status = OK;

    status = CRYPTO_UTILS_readTrustedPathsWithProxyURL(
            &scepc_confPath, &scepc_certPath, &scepc_truststorePath, NULL, &scepc_http_proxy);
    if (OK != status)
    {
        DEBUG_PRINTNL(DEBUG_SCEP_EXAMPLE, (sbyte *)"Warning: Unable to read tpconf.json");
        goto exit;
    }

    DEBUG_PRINT2(DEBUG_SCEP_EXAMPLE, "\nLoaded keystore path from tpconf.json: ", scepc_certPath);
    DEBUG_PRINT2(DEBUG_SCEP_EXAMPLE, "\nLoaded truststore path from tpconf.json: ", scepc_truststorePath);
    DEBUG_PRINT(DEBUG_SCEP_EXAMPLE, "\n");
    if (filePath == NULL && scepc_certPath != NULL)
    {
        setStringParameter((char **)&filePath, (char *)scepc_certPath);
    }

exit:
    return status;
}

/*------------------------------------------------------------------*/

static void
setStringParameter(char ** param, char *value)
{
    sbyte4 valuestrsize = 0;
    if (value == NULL)
        return;
    valuestrsize = DIGI_STRLEN((const sbyte *)value);
    *param = MALLOC(valuestrsize+1);
    if (*param)
    {
        DIGI_MEMCPY(*param, value, valuestrsize);
        (*param)[valuestrsize] = '\0';
    }
}

/*------------------------------------------------------------------*/

static void
setFilePath(sbyte *path, sbyte **fname)
{
   sbyte *fullPath;
   ubyte4 fullPathLen;

   if ((*fname == NULL) || (path == NULL)) {
      return;
   }

   fullPathLen = DIGI_STRLEN(path) + DIGI_STRLEN(*fname) + 2; /* +2 for file seperator and ending null */
   fullPath = MALLOC(fullPathLen);
   if (fullPath)
   {
       DIGI_MEMCPY(fullPath, path, DIGI_STRLEN(path));
       fullPath[DIGI_STRLEN(path)] = DEF_FILESEP;
       DIGI_MEMCPY(&fullPath[DIGI_STRLEN(path) + 1], *fname, DIGI_STRLEN(*fname));

       fullPath[fullPathLen - 1] = '\0';
       DIGI_FREE((void**)fname);
       *fname = fullPath;
   }
}

/*-------------------------------------------------------------------*/
static void
setFullPath(sbyte *fname, sbyte *path, sbyte **fpath)
{
   sbyte *fullPath;
   ubyte4 fullPathLen;

   if ((fname == NULL) || (path == NULL) || (NULL == fpath)) {
      return;
   }

   fullPathLen = DIGI_STRLEN(path) + DIGI_STRLEN(fname) + 2; /* +2 for file seperator and ending null */
   fullPath = MALLOC(fullPathLen);
   if (fullPath)
   {
       DIGI_MEMCPY(fullPath, path, DIGI_STRLEN(path));
       fullPath[DIGI_STRLEN(path)] = DEF_FILESEP;
       DIGI_MEMCPY(&fullPath[DIGI_STRLEN(path) + 1], fname, DIGI_STRLEN(fname));

       fullPath[fullPathLen - 1] = '\0';
       *fpath = fullPath;
   }
}

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_TAP__

typedef struct ScepStrMapping
{
    sbyte *pStr;
    ubyte2 value;
} ScepStrMapping;

static MSTATUS SCEP_convertTapKeyUsageString(sbyte *pStr, ubyte4 strLen, ubyte2 *pValue)
{
    MSTATUS status = ERR_TAP_INVALID_INPUT;
    ScepStrMapping pMapping[] = {
        { SCEPC_TAP_KEY_USAGE_SIGNING, TAP_KEY_USAGE_SIGNING },
        { SCEPC_TAP_KEY_USAGE_DECRYPT, TAP_KEY_USAGE_DECRYPT },
        { SCEPC_TAP_KEY_USAGE_GENERAL, TAP_KEY_USAGE_GENERAL },
        { SCEPC_TAP_KEY_USAGE_ATTEST, TAP_KEY_USAGE_ATTESTATION }
    };
    ubyte4 i, length;

    if (NULL == pStr)
    {
        goto exit;
    }

    for (i = 0; i < sizeof(pMapping)/sizeof(pMapping[0]); i++)
    {
        length = DIGI_STRLEN(pMapping[i].pStr);
        if (length == strLen)
        {
            if (0 == DIGI_STRNCMP(pMapping[i].pStr, pStr, length))
            {
                *pValue = pMapping[i].value;
                break;
            }
        }
    }

    if (i < sizeof(pMapping)/sizeof(pMapping[0]))
    {
        status = OK;
    }

exit:
    return status;
}

static MSTATUS SCEP_convertTapSigSchemeString(sbyte *pStr, ubyte4 strLen, ubyte2 *pValue)
{
    MSTATUS status = ERR_TAP_INVALID_INPUT;
    ScepStrMapping pMapping[] = {
        { SCEPC_TAP_SIG_SCHEME_NONE, TAP_SIG_SCHEME_NONE },
        { SCEPC_TAP_SIG_SCHEME_PKCS1_5, TAP_SIG_SCHEME_PKCS1_5 },
        { SCEPC_TAP_SIG_SCHEME_PSS_SHA1, TAP_SIG_SCHEME_PSS_SHA1 },
        { SCEPC_TAP_SIG_SCHEME_PSS_SHA256, TAP_SIG_SCHEME_PSS_SHA256 },
        { SCEPC_TAP_SIG_SCHEME_PKCS1_5_SHA1, TAP_SIG_SCHEME_PKCS1_5_SHA1 },
        { SCEPC_TAP_SIG_SCHEME_PKCS1_5_SHA256, TAP_SIG_SCHEME_PKCS1_5_SHA256 },
        { SCEPC_TAP_SIG_SCHEME_PKCS1_5_DER, TAP_SIG_SCHEME_PKCS1_5_DER },
        { SCEPC_TAP_SIG_SCHEME_ECDSA_SHA1, TAP_SIG_SCHEME_ECDSA_SHA1 },
        { SCEPC_TAP_SIG_SCHEME_ECDSA_SHA224, TAP_SIG_SCHEME_ECDSA_SHA224 },
        { SCEPC_TAP_SIG_SCHEME_ECDSA_SHA256, TAP_SIG_SCHEME_ECDSA_SHA256 },
        { SCEPC_TAP_SIG_SCHEME_ECDSA_SHA384, TAP_SIG_SCHEME_ECDSA_SHA384 },
        { SCEPC_TAP_SIG_SCHEME_ECDSA_SHA512, TAP_SIG_SCHEME_ECDSA_SHA512 }
    };
    ubyte4 i, length;

    if (NULL == pStr)
    {
        goto exit;
    }

    for (i = 0; i < sizeof(pMapping)/sizeof(pMapping[0]); i++)
    {
        length = DIGI_STRLEN(pMapping[i].pStr);
        if (length == strLen)
        {
            if (0 == DIGI_STRNCMP(pMapping[i].pStr, pStr, length))
            {
                *pValue = pMapping[i].value;
                break;
            }
        }
    }

    if (i < sizeof(pMapping)/sizeof(pMapping[0]))
    {
        status = OK;
    }

exit:
    return status;
}

static MSTATUS SCEP_convertTapEncSchemeString(sbyte *pStr, ubyte4 strLen, ubyte2 *pValue)
{
    MSTATUS status = ERR_TAP_INVALID_INPUT;
    ScepStrMapping pMapping[] = {
        { SCEPC_TAP_ENC_SCHEME_NONE, TAP_ENC_SCHEME_NONE },
        { SCEPC_TAP_ENC_SCHEME_PKCS1_5, TAP_ENC_SCHEME_PKCS1_5 },
        { SCEPC_TAP_ENC_SCHEME_OAEP_SHA1, TAP_ENC_SCHEME_OAEP_SHA1 },
        { SCEPC_TAP_ENC_SCHEME_OAEP_SHA256, TAP_ENC_SCHEME_OAEP_SHA256 }
    };
    ubyte4 i, length;

    if (NULL == pStr)
    {
        goto exit;
    }

    for (i = 0; i < sizeof(pMapping)/sizeof(pMapping[0]); i++)
    {
        length = DIGI_STRLEN(pMapping[i].pStr);
        if (length == strLen)
        {
            if (0 == DIGI_STRNCMP(pMapping[i].pStr, pStr, length))
            {
                *pValue = pMapping[i].value;
                break;
            }
        }
    }

    if (i < sizeof(pMapping)/sizeof(pMapping[0]))
    {
        status = OK;
    }

exit:
    return status;
}

#endif /* __ENABLE_DIGICERT_TAP__ */

/*------------------------------------------------------------------*/

/* Helper function to build full path with subdirectory */
static void
setFullPathWithSubdir(sbyte *fname, sbyte *basePath, const sbyte *subdir, sbyte **fpath)
{
   sbyte *fullPath;
   ubyte4 fullPathLen;

   if ((fname == NULL) || (basePath == NULL) || (NULL == fpath)) {
      return;
   }

   /* Calculate: basePath + '/' + subdir + '/' + fname + '\0' */
   fullPathLen = DIGI_STRLEN(basePath);
   if (subdir != NULL && DIGI_STRLEN(subdir) > 0) {
       fullPathLen += DIGI_STRLEN(subdir) + 1; /* +1 for separator */
   }
   fullPathLen += DIGI_STRLEN(fname) + 2; /* +2 for separator and null */

   fullPath = MALLOC(fullPathLen);
   if (fullPath)
   {
       DIGI_MEMCPY(fullPath, basePath, DIGI_STRLEN(basePath));
       ubyte4 offset = DIGI_STRLEN(basePath);

       if (subdir != NULL && DIGI_STRLEN(subdir) > 0) {
           fullPath[offset++] = DEF_FILESEP;
           DIGI_MEMCPY(&fullPath[offset], subdir, DIGI_STRLEN(subdir));
           offset += DIGI_STRLEN(subdir);
       }

       fullPath[offset++] = DEF_FILESEP;
       DIGI_MEMCPY(&fullPath[offset], fname, DIGI_STRLEN(fname));
       offset += DIGI_STRLEN(fname);
       fullPath[offset] = '\0';

       *fpath = fullPath;
   }
}

/*------------------------------------------------------------------*/

static void
SCEP_CLIENT_EXAMPLE_displayHelp(char *prog)
{

	printf(" Usage: %s ", prog);
	printf(" <options>\n");
	printf("  options:\n");
	printf("    -scepc_serverURL     <URL>          specifies the scep server url\n");
	printf("    -scepc_serverType    <server type>  specifies the SCEP server type\n");
	printf("                                    < MOC | EJBCA | ECDSA | WIN2003 | WIN2008 | WIN2012 | WIN2016 > \n");
	printf("    -scepc_challengePass <password>     specifies the challenge password\n");
	printf("\n");
	printf("    -scepc_keyType <key type>           specifies key type to be used for key generation \n");
    printf("                                        <RSA|ECDSA>\n");
	printf("    -scepc_keySize <key size>           specifies key size to be used for key generation \n");
	printf("    -scepc_csr_conf                           specifies the configuration file name to generate CSR \n");
	printf("    -scepc_pkiOperation                 specifies the pkioperation \n");
    printf("                                        enroll|renew|rekey|getcacert \n");
	printf("    -scepc_oldCert                      specifies existing certificate path issued by CA. \n");
    printf("                                        This is used in case of renew or rekey.\n");
	printf("    -scepc_oldPemKey                    specifies existing pem key which was used for enrollement\n");
    printf("                                        This is used in case of renew or rekey.\n");
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
    printf("    -scepc_tapservername <name>                   Name of the remote TAP server.\n");
    printf("    -scepc_tapserverport <port>                   Port of the remote TAP server.\n");
#endif
#if defined(__ENABLE_DIGICERT_TAP__)
	printf("    -scepc_keySource                    specifies the source of Key genration \n");
    printf("                                        < SW | TPM2 >\n");
#endif
	printf("\n");
} /* SCEP_CLIENT_EXAMPLE_displayHelp */

/*------------------------------------------------------------------*/
extern sbyte4
SCEP_CLIENT_EXAMPLE_freeArgs()
{
    /* Free all the parameter that we put on the heap. */
    if (pChallengePass != NULL)
    {
        DIGI_FREE((void**)&pChallengePass);
    }
    if (pPkiOperation != NULL) {
        DIGI_FREE((void**)&pPkiOperation);
    }
	if (pOldCertFile != NULL)
	{
		DIGI_FREE((void**)&pOldCertFile);
	}
	if (pOldPemKeyFile != NULL)
	{
		DIGI_FREE((void**)&pOldPemKeyFile);
	}
    if (serverTypeStr != NULL)
    {
        DIGI_FREE((void**)&serverTypeStr);
    }
    if (filePath != NULL)
    {
        DIGI_FREE((void**)&filePath);
    }
    if (pScepServerUrl != NULL)
    {
        DIGI_FREE((void**)&pScepServerUrl);
    }
    if (scepc_keyType != NULL)
    {
        DIGI_FREE((void**)&scepc_keyType);
    }
#if defined(__ENABLE_DIGICERT_TAP__)
    if (scepc_keySource != NULL)
    {
        DIGI_FREE((void**)&scepc_keySource);
    }
#endif
    if (scepc_confFile != NULL)
    {
        DIGI_FREE((void**)&scepc_confFile);
    }
    if (scepc_certPath != NULL)
    {
        DIGI_FREE((void**)&scepc_certPath);
    }
    if (scepc_truststorePath != NULL)
    {
        DIGI_FREE((void**)&scepc_truststorePath);
    }
    if (scepc_confPath != NULL)
    {
        DIGI_FREE((void**)&scepc_confPath);
    }
    if (scepc_http_proxy != NULL)
    {
        DIGI_FREE((void**)&scepc_http_proxy);
    }
#ifdef __ENABLE_DIGICERT_TAP__
    if (pScepTapConfFile != NULL)
    {
        DIGI_FREE((void**)&pScepTapConfFile);
    }
    if (pScepTapKeyPassword != NULL)
    {
        DIGI_FREE((void**)&pScepTapKeyPassword);
    }
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
    if (pScepTapServerName != NULL)
    {
        DIGI_FREE((void**)&pScepTapServerName);
    }
#endif
#endif

    scep_getArgs_called = 0;
    return OK;
}


extern sbyte4
SCEP_CLIENT_getArgs(int argc, char *argv[])
{
    sbyte4 status = 0;
    int i;
    int srvSet=0, cpassSet=0, keyTypeSet=0, keySizeSet=0, oldCertSet=0,
        oldKeySet=0, pkiOperationSet=0;

#if defined(__ENABLE_DIGICERT_TAP__)
    int keySourceSet=0;
    char *pTemp = NULL;
    int	tapModuleIdSet=0, tapconfFileSet =0, tapKeyUsageSet = 0, tapEncSchemeSet=0, tapSignSchemeSet=0;
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
    int tapServerNameSet=0, tapServerPortSet=0;
#endif
#endif

    if (argc < 2)
    {
        SCEP_CLIENT_EXAMPLE_displayHelp(argv[0]);
        return -1;
    }

    if ('?' == argv[1][0])
    {
        SCEP_CLIENT_EXAMPLE_displayHelp(argv[0]);
        return -1;
    }

    /* If we get this far, then mark it as called. */
    scep_getArgs_called++;

    /*Skipping argv[0] which is example program name. */
    for (i = 1; i < argc; i++)
    {
        if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-scepc_serverURL") == 0)
        {
            if (++i < argc)
            {
                setStringParameter((char **)&pScepServerUrl, argv[i]);
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-scepc_serverType") == 0)
        {
            if (++i < argc)
            {
                setStringParameter((char **)&serverTypeStr, argv[i]);
                srvSet = 1;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-scepc_challengePass") == 0)
        {
            if (++i < argc)
            {
               setStringParameter((char **)&pChallengePass, argv[i]);
               cpassSet = 1;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-scepc_oldCert") == 0)
        {
            if (++i < argc)
            {
               setStringParameter((char **)&pOldCertFile, argv[i]);
               oldCertSet = 1;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-scepc_oldPemKey") == 0)
        {
            if (++i < argc)
            {
               setStringParameter((char **)&pOldPemKeyFile, argv[i]);
               oldKeySet = 1;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-scepc_pkiOperation") == 0)
        {
            if (++i < argc)
            {
               setStringParameter((char **)&pPkiOperation, argv[i]);
               pkiOperationSet = 1;
            }
            continue;
        }
		else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-scepc_keyType") == 0)
		{
			if (++i < argc)
			{
				setStringParameter((char **)&scepc_keyType, argv[i]);
				keyTypeSet = 1;
			}
			continue;
		}
		else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-scepc_keySize") == 0)
		{
			if (++i < argc)
			{
				scepc_keySize = (unsigned short) DIGI_ATOL((const sbyte *)argv[i],NULL);
				keySizeSet = 1;
			}
			continue;
		}
		else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-scepc_csr_conf") == 0)
		{
			if (++i < argc)
			{
				setStringParameter((char **)&scepc_confFile, argv[i]);
			}
			continue;
		}
#if defined(__ENABLE_DIGICERT_TAP__)
		else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-scepc_keySource") == 0)
		{
			if (++i < argc)
			{
				setStringParameter((char **)&scepc_keySource, argv[i]);
				keySourceSet = 1;
			}
			continue;
		}
        else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-scepc_tapmoduleid") == 0)
        {
            if (++i < argc)
            {
                pTemp = argv[i];
                pScepTapModuleId = (unsigned short) DIGI_ATOL((const sbyte *)pTemp, NULL);
                tapModuleIdSet = 1;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-scepc_tapconfig") == 0)
        {
            if (++i < argc)
            {
                setStringParameter((char**)&pScepTapConfFile, argv[i]);
                tapconfFileSet = 1;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-scepc_tapkeyusage") == 0)
        {
            if (++i < argc)
            {
                pTemp = argv[i];
                if (DIGI_STRLEN(pTemp) > 0 && FALSE == DIGI_ISDIGIT(pTemp[0]))
                {
                    status = SCEP_convertTapKeyUsageString(
                        pTemp, DIGI_STRLEN(pTemp), &pScepTapKeyUsage);
                    if (OK != status)
                    {
                        DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "Invalid TAP key usage string: ", status);
                        return status;
                    }
                }
                else
                {
                    pScepTapKeyUsage = (unsigned short) DIGI_ATOL((const sbyte *)pTemp, NULL);
                }
                tapKeyUsageSet = 1;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-scepc_tapsignscheme") == 0)
        {
            if (++i < argc)
            {
                pTemp = argv[i];
                if (DIGI_STRLEN(pTemp) > 0 && FALSE == DIGI_ISDIGIT(pTemp[0]))
                {
                    status = SCEP_convertTapSigSchemeString(
                        pTemp, DIGI_STRLEN(pTemp), &pScepTapSignScheme);
                    if (OK != status)
                    {
                        DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "Invalid TAP signing scheme string: ", status);
                        return status;
                    }
                }
                else
                {
                    pScepTapSignScheme = (unsigned short) DIGI_ATOL((const sbyte *)pTemp, NULL);
                }
                tapSignSchemeSet = 1;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-scepc_tapencscheme") == 0)
        {
            if (++i < argc)
            {
                pTemp = argv[i];
                if (DIGI_STRLEN(pTemp) > 0 && FALSE == DIGI_ISDIGIT(pTemp[0]))
                {
                    status = SCEP_convertTapEncSchemeString(
                        pTemp, DIGI_STRLEN(pTemp), &pScepTapEncScheme);
                    if (OK != status)
                    {
                        DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "Invalid TAP encryption scheme string: ", status);
                        return status;
                    }
                }
                else
                {
                    pScepTapEncScheme = (unsigned short) DIGI_ATOL((const sbyte *)pTemp, NULL);
                }
                tapEncSchemeSet = 1;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-scepc_tapkeypassword") == 0)
        {
            if (++i < argc)
            {
                setStringParameter((char**)&pScepTapKeyPassword, argv[i]);
            }
            continue;
        }
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
        else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-scepc_tapservername") == 0)
        {
            if (++i < argc)
            {
                setStringParameter((char**)&pScepTapServerName, argv[i]);
                tapServerNameSet = 1;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-scepc_tapserverport") == 0)
        {
            if (++i < argc)
            {
                pTemp = argv[i];
                pScepTapServerPort = (ubyte4) DIGI_ATOL((const sbyte *)pTemp, NULL);
                tapServerPortSet = 1;
            }
            continue;
        }
#endif
#endif /*__ENABLE_DIGICERT_TAP__*/
	    else
        {
            SCEP_CLIENT_EXAMPLE_displayHelp(argv[0]);
            return -1;
        }
    } /*for*/

    /*Set defaults if nothing entered from command line*/
	if (!srvSet)
    {
       serverType = DEF_SCEP_SERVER_TYPE;
       setStringParameter((char **)&serverTypeStr, MOC_SCEP_SERVER_STR);
    }
    if (!cpassSet)
    {
       setStringParameter((char **)&pChallengePass, DEF_SCEP_CHALLENGE_PASS);
    }
	if (!keyTypeSet)
	{
		setStringParameter((char **)&scepc_keyType, SCEPC_DEF_KEYTYPE);
	}
	if (!keySizeSet)
	{
		scepc_keySize = SCEPC_DEF_KEYSIZE;
	}
#if defined(__ENABLE_DIGICERT_TAP__)
    if (!keySourceSet)
    {
		setStringParameter((char **)&scepc_keySource, SCEPC_DEF_KEYSOURCE);
    }

    /* Determine if TAP should be used based on key source */
    if ((DIGI_STRCMP((const sbyte *)scepc_keySource, (const sbyte *)KEY_SOURCE_TPM2) == 0) ||
        (DIGI_STRCMP((const sbyte *)scepc_keySource, (const sbyte *)KEY_SOURCE_TPM1_2) == 0) ||
        (DIGI_STRCMP((const sbyte *)scepc_keySource, (const sbyte *)KEY_SOURCE_PKCS11) == 0) ||
        (DIGI_STRCMP((const sbyte *)scepc_keySource, (const sbyte *)KEY_SOURCE_NXPA71) == 0) ||
        (DIGI_STRCMP((const sbyte *)scepc_keySource, (const sbyte *)KEY_SOURCE_STSAFE) == 0) ||
        (DIGI_STRCMP((const sbyte *)scepc_keySource, (const sbyte *)KEY_SOURCE_TEE) == 0))
    {
		gUseTap = 1;
		pScepTapKeySourceRuntime = TRUE;
    }

    if (!tapModuleIdSet)
    {
        pScepTapModuleId = SCEP_DEF_TAP_MODULEID;
    }

    /* Set default config file based on key source if not explicitly provided */
    if (!tapconfFileSet && gUseTap)
    {
        if (DIGI_STRCMP((const sbyte *)scepc_keySource, (const sbyte *)KEY_SOURCE_TPM2) == 0)
        {
            setStringParameter((char**)&pScepTapConfFile, TPM2_CONFIGURATION_FILE);
        }
        else if (DIGI_STRCMP((const sbyte *)scepc_keySource, (const sbyte *)KEY_SOURCE_TPM1_2) == 0)
        {
            setStringParameter((char**)&pScepTapConfFile, TPM12_CONFIGURATION_FILE);
        }
        else if (DIGI_STRCMP((const sbyte *)scepc_keySource, (const sbyte *)KEY_SOURCE_PKCS11) == 0)
        {
            setStringParameter((char**)&pScepTapConfFile, PKCS11_CONFIGURATION_FILE);
        }
        else if (DIGI_STRCMP((const sbyte *)scepc_keySource, (const sbyte *)KEY_SOURCE_TEE) == 0)
        {
            setStringParameter((char**)&pScepTapConfFile, TEE_CONFIGURATION_FILE);
        }
        else
        {
            /* Default to TPM2 config if unknown */
            setStringParameter((char**)&pScepTapConfFile, TPM2_CONFIGURATION_FILE);
        }
    }

    if (!tapKeyUsageSet)
    {
        pScepTapKeyUsage = TAP_KEY_USAGE_GENERAL;
    }
    if (!tapSignSchemeSet)
    {
        if (DIGI_STRCMP((const sbyte *)scepc_keyType, (const sbyte *)KEY_TYPE_ECDSA) == 0)
        {
            pScepTapSignScheme = TAP_SIG_SCHEME_ECDSA_SHA256;
        }
        else
        {
            pScepTapSignScheme = TAP_SIG_SCHEME_NONE;
        }
    }
    if (!tapEncSchemeSet)
    {
        pScepTapEncScheme = TAP_ENC_SCHEME_PKCS1_5;
    }
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
    if (1 == gUseTap)
    {
        if (!tapServerNameSet)
        {
            status = ERR_SCEP;
            DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "Mandatory argument scepc_tapservername NOT set ", status);
            return status;
        }
        if (!tapServerPortSet)
        {
            status = ERR_SCEP;
            DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "Mandatory argument scepc_tapserverport NOT set ", status);
            return status;
        }
    }
#endif
#endif /*__ENABLE_DIGICERT_TAP__*/
    if (!pkiOperationSet)
    {
        /* Default set to enroll */
        setStringParameter((char**)&pPkiOperation, PKI_OPERATION_ENROLL);
    }
    if (!oldCertSet)
    {
        if ((0 == DIGI_STRCMP(pPkiOperation, (const sbyte*)PKI_OPERATION_RENEW) ||
            (0 == DIGI_STRCMP(pPkiOperation, (const sbyte*)PKI_OPERATION_REKEY))))
        {
            status = ERR_SCEP;
            DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "Mandatory argument scepc_oldCert not set ", status);
            return status;
        }
    }
    if (!oldKeySet)
    {
        if ((0 == DIGI_STRCMP(pPkiOperation, (const sbyte*)PKI_OPERATION_RENEW) ||
            (0 == DIGI_STRCMP(pPkiOperation, (const sbyte*)PKI_OPERATION_REKEY))))
        {
            status = ERR_SCEP;
            DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "Mandatory argument scepc_oldPemKey not set ", status);
            return status;
        }

    }
    /*End of defaults*/

    /* Set the SCEP_SERVER type based on the string. */
    if (0 == DIGI_STRNICMP((const sbyte *)serverTypeStr, (const sbyte *)MOC_SCEP_SERVER_STR,
                                                       DIGI_STRLEN((const sbyte *)serverTypeStr))) {
        serverType = MOC_SCEP_SERVER;
    }
    else if (0 == DIGI_STRNICMP((const sbyte *)serverTypeStr, (const sbyte *)EJBCA_SCEP_SERVER_STR,
                                                       DIGI_STRLEN((const sbyte *)serverTypeStr))) {
        serverType = EJBCA_SCEP_SERVER;
    }
    else if (0 == DIGI_STRNICMP((const sbyte *)serverTypeStr, (const sbyte *)ECDSA_SCEP_SERVER_STR,
                                                       DIGI_STRLEN((const sbyte *)serverTypeStr))) {
        serverType = ECDSA_SCEP_SERVER;
    }
    else if (0 == DIGI_STRNICMP((const sbyte *)serverTypeStr, (const sbyte *)WIN2003_SCEP_SERVER_STR,
                                                          DIGI_STRLEN((const sbyte *)serverTypeStr))) {
        serverType = WIN2003_SCEP_SERVER;
        supportsPost = FALSE;
    }
    else if (0 == DIGI_STRNICMP((const sbyte *)serverTypeStr, (const sbyte *)WIN2008_SCEP_SERVER_STR,
                                                       DIGI_STRLEN((const sbyte *)serverTypeStr))) {
        serverType = WIN2008_SCEP_SERVER;
        supportsPost = FALSE;
    }
    else if (0 == DIGI_STRNICMP((const sbyte *)serverTypeStr, (const sbyte *)WIN2012_SCEP_SERVER_STR,
                                                       DIGI_STRLEN((const sbyte *)serverTypeStr))) {
        serverType = WIN2012_SCEP_SERVER;
        supportsPost = FALSE;
    }
    else if (0 == DIGI_STRNICMP((const sbyte *)serverTypeStr, (const sbyte *)WIN2016_SCEP_SERVER_STR,
                                                       DIGI_STRLEN((const sbyte *)serverTypeStr))) {
        serverType = WIN2016_SCEP_SERVER;
        supportsPost = TRUE;
    }
    else if (0 == DIGI_STRNICMP((const sbyte *)serverTypeStr, (const sbyte *)GEN_GET_SERVER_STR,
                                                       DIGI_STRLEN((const sbyte*)serverTypeStr))) {
        serverType = GEN_GET_SERVER;
        supportsPost = FALSE;
    }
    else if (0 == DIGI_STRNICMP((const sbyte *)serverTypeStr, (const sbyte *)GEN_POST_SERVER_STR,
                                                       DIGI_STRLEN((const sbyte*)serverTypeStr))) {
        serverType = GEN_POST_SERVER;
        supportsPost = TRUE;
    }
    else {
       SCEP_CLIENT_EXAMPLE_displayHelp(argv[0]);
       return -1;
   }

    /* Create the file paths */
    setStringParameter((char **)&caCertFileName, SCEP_CA_CERT_FILE);
    setStringParameter((char **)&adminCertFileName, SCEP_ADMIN_CERT_FILE);
    setStringParameter((char **)&cepCertFileName, SCEP_CEP_CERT_FILE);
    setStringParameter((char **)&exchangeCertFileName, SCEP_XCHG_CERT_FILE);
    setFilePath(filePath,&caCertFileName);
    setFilePath(filePath,&adminCertFileName);
    setFilePath(filePath,&cepCertFileName);
    setFilePath(filePath,&exchangeCertFileName);

    /*------------------------------------------------------------------*/
    DEBUG_PRINT2(DEBUG_SCEP_EXAMPLE,"SCEP Server url = ",pScepServerUrl);
    DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"\n");
    DEBUG_PRINT2(DEBUG_SCEP_EXAMPLE,"SCEP Server type = ",serverTypeStr);
    DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"\n");
    if (0 != DIGI_STRCMP(pPkiOperation, (const sbyte*)PKI_OPERATION_GETCACERT))
    {
        DEBUG_PRINT2(DEBUG_SCEP_EXAMPLE,"SCEP key type = ",scepc_keyType);
	    DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"\n");
    }
#ifdef __ENABLE_DIGICERT_TAP__
	DEBUG_PRINT2(DEBUG_SCEP_EXAMPLE,"SCEP Key Source = ",scepc_keySource);
    DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"\n");
#endif
    if (scepc_confFile != NULL)
    {
	    DEBUG_PRINT2(DEBUG_SCEP_EXAMPLE,"SCEP conf file = ",scepc_confFile);
        DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"\n");
    }
    /*------------------------------------------------------------------ */

   return status;

} /* SCEP_CLIENT_getArgs */

/*------------------------------------------------------------------*/
extern sbyte4
SCEP_CLIENT_freeArgs()
{
    /* Free all the parameter that we put on the heap. */
    if (pChallengePass != NULL)
    {
        DIGI_FREE((void**)&pChallengePass);
    }
    if (pPkiOperation != NULL) {
        DIGI_FREE((void**)&pPkiOperation);
    }
	if (pOldCertFile != NULL)
	{
		DIGI_FREE((void**)&pOldCertFile);
	}
	if (pOldPemKeyFile != NULL)
	{
		DIGI_FREE((void**)&pOldPemKeyFile);
	}
    if (serverTypeStr != NULL)
    {
        DIGI_FREE((void**)&serverTypeStr);
    }
    if (filePath != NULL)
    {
        DIGI_FREE((void**)&filePath);
    }
    if (pScepServerUrl != NULL)
    {
        DIGI_FREE((void**)&pScepServerUrl);
    }
    if (scepc_keyType != NULL)
    {
        DIGI_FREE((void**)&scepc_keyType);
    }
#if defined(__ENABLE_DIGICERT_TAP__)
    if (scepc_keySource != NULL)
    {
        DIGI_FREE((void**)&scepc_keySource);
    }
#endif
    if (scepc_confFile != NULL)
    {
        DIGI_FREE((void**)&scepc_confFile);
    }
    if (scepc_certPath != NULL)
    {
        DIGI_FREE((void**)&scepc_certPath);
    }
    if (scepc_truststorePath != NULL)
    {
        DIGI_FREE((void**)&scepc_truststorePath);
    }
    if (scepc_confPath != NULL)
    {
        DIGI_FREE((void**)&scepc_confPath);
    }
    if (scepc_http_proxy != NULL)
    {
        DIGI_FREE((void**)&scepc_http_proxy);
    }
#ifdef __ENABLE_DIGICERT_TAP__
    if (pScepTapConfFile != NULL)
    {
        DIGI_FREE((void**)&pScepTapConfFile);
    }
    if (pScepTapKeyPassword != NULL)
    {
        DIGI_FREE((void**)&pScepTapKeyPassword);
    }
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
    if (pScepTapServerName != NULL)
    {
        DIGI_FREE((void**)&pScepTapServerName);
    }
#endif
#endif

    scep_getArgs_called = 0;
    return OK;
}

/*------------------------------------------------------------------*/

static int
init(httpContext **ppHttpContext)
{
    MSTATUS status = 0;

    TCP_SOCKET  socketServer;
    MSTATUS socket_status = 0;
    URI *uri = NULL;
    sbyte* host = NULL;
    sbyte *pAddr = NULL;
    sbyte2 port;

    if((NULL == ppHttpContext))
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }
    *ppHttpContext = NULL;

    /* Initialize SCEP settings callbacks */
    memset((ubyte*)&SCEP_scepSettings()->pkcsCtx, 0x00, sizeof(pkcsCtx));

    SCEP_scepSettings()->funcPtrCertificateStoreLookup = myCertificateStoreLookup;
    SCEP_scepSettings()->funcPtrCertificateStoreRelease = myCertificateStoreRelease;
    SCEP_scepSettings()->funcPtrKeyPairLookup = myKeyPairLookup;

    /* Set up certificate info pointers - similar to scepc.c */
    SCEP_scepSettings()->pkcsCtx.pRACertInfo = &gCAOrRACertInfo;
    SCEP_scepSettings()->pkcsCtx.pCACertInfo = &gCertInfo;  /* Use gCertInfo as placeholder */
    SCEP_scepSettings()->pkcsCtx.pRequesterCertInfo = &gCertInfo;

    /* Set up PKCS7 callbacks in pkcsCtx */
    SCEP_scepSettings()->pkcsCtx.callbacks.getCertFun = myGetCertFun;
    SCEP_scepSettings()->pkcsCtx.callbacks.getPrivKeyFun = myGetPrivateKeyFun;
    SCEP_scepSettings()->pkcsCtx.callbacks.valCertFun = myValCertFun;

    /* Set up RNG function pointer to avoid NULL access */
    SCEP_scepSettings()->pkcsCtx.rngFun = RANDOM_rngFun;
    SCEP_scepSettings()->pkcsCtx.rngFunArg = g_pRandomContext;

    /* initialize transport for HTTP */
    HTTP_httpSettings()->funcPtrHttpTcpSend   = my_HttpTcpSend;
    HTTP_httpSettings()->funcPtrResponseHeaderCallback = SCEP_CLIENT_http_responseHeaderCallback;
    HTTP_httpSettings()->funcPtrResponseBodyCallback = SCEP_CLIENT_http_responseBodyCallback;

    /* start of SCEP operations */
    if (OK > (status = URI_ParseURI(pScepServerUrl, &uri))){
        goto exit;
    }

    if (OK > (status = URI_GetHost(uri, &host)))
    {
        goto exit;
    }

    if (OK > (status = getAddressInfo(host, &pAddr)))
    {
        goto exit;
    }

    if (OK > (status = URI_GetPort(uri, &port))){
        goto exit;
    }

    if (port == 0)
        port = 80;

    if (OK > (status = TCP_CONNECT(&socketServer, pAddr, port))){
        goto exit;
    }
    socket_status = 1;

    if (OK > (status = HTTP_connect(ppHttpContext, socketServer))){
        goto exit;
    }

exit:
    if (NULL != host) {
        FREE(host);
        host = NULL;
    }

    if (NULL != pAddr)
    {
        DIGI_FREE((void**)&pAddr);
    }

    if (NULL != uri)
        URI_DELETE(uri);

    if (OK > status)
    {
        HTTP_CONTEXT_releaseContext(ppHttpContext);
        if(ppHttpContext)
            *ppHttpContext = NULL;
        if (socket_status)
            TCP_CLOSE_SOCKET(socketServer);
    }

    return  status;
}

static SCEP_data *g_pScepData = NULL;

static
MSTATUS getScepData(SCEP_data **ppScepData)
{
    *ppScepData = g_pScepData;
    return OK;
}

/* This is only for build the SSL client using Microsoft Visual Studio project */
#ifdef __ENABLE_DIGICERT_WIN_STUDIO_BUILD__
int main(int argc, char *argv[])
{
	void* dummy = NULL;
#else
extern MSTATUS
SCEP_CLIENT_main(sbyte4 dummy)
{
#endif

	MSTATUS status = OK;
	sbyte *respFile = NULL;
    sbyte *pKeyBlobFile = NULL;
    ubyte *pKeyBlob = NULL;
    ubyte4 keyBlobLen = 0;
    requestInfo  *pReqInfo = NULL;
    AsymmetricKey asymKey = {0};
    ubyte *pPayLoad = NULL;
    ubyte *pCsrFile = NULL;
    ubyte* pLineCsr = 0;
    ubyte4 lineCsrLength;
    ubyte *pCsr = NULL;
    ubyte4 csrLen = 0;
    httpContext *pHttpContext = NULL;
    ubyte *pCSRAttrBuffer = NULL;
    ubyte4 csrAttrBufferLen = 0;
    ubyte *pCsrBuffer = NULL;
    ubyte4 csrBufferLen = 0;
    const ubyte *digestAlgoOID = sha256_OID;
    ubyte4 hashType = ht_sha256; /* default */
    ubyte *pExchangerCert = NULL;
    ubyte4 exchangerCertLen = 0;
    ubyte *pRequesterCert = NULL;
    ubyte4 requesterCertLen = 0;
    certDescriptor reqCertDesc = {0};
    struct certStore *pCertStore = NULL;
    certDescriptor *pTrustCerts = NULL;
    ubyte4 numTrustCerts = 0;
    certDescriptor *pCACerts = NULL;
    ubyte4 numCaCerts = 0;
    certDescriptor *pRACerts = NULL;
    ubyte4 numRaCerts = 0;
    ubyte *pCepCert = NULL;
    ubyte4 cepCertLen = 0;
    sbyte *pCertsPath = NULL;
    ubyte *pOut = NULL;
    ubyte4 outLen = 0;
    sbyte *pTransId = NULL;
    ubyte4 transIdLen = 0;
    ubyte4 outStatus = 0;
    sbyte    *pFullPath      = NULL;
    ubyte *pDatKeyBlob = NULL;
    ubyte *pOldPemKeyBlob = NULL;
    ubyte4 oldPemKeyBlobLen = 0;
    ubyte4 pkiOperation = 0;
    ubyte4 i = 0;
    certDistinguishedName *pIssuer = NULL;
    certDistinguishedName *pSubject = NULL;
    sbyte *pTrustPath = NULL;
    ubyte *pCert = NULL;
    ubyte4 certLen = 0;
    const void *pIterator = NULL;
    ubyte *pDecodedCert = NULL;
    ubyte4 decodedCertLen = 0;

    MOC_UNUSED(dummy);

    gMocanaAppsRunning++;

#ifdef __ENABLE_DIGICERT_WIN_STUDIO_BUILD__
	if (OK > ( status = SCEP_CLIENT_getArgs(argc, argv))) /* Initialize parameters to default values */
		return status;
#endif

    if (scep_getArgs_called == 0)
    {
        SCEP_CLIENT_getArgs(0,NULL); /* Initialize parameters to default values */
    }

#ifdef __ENABLE_DIGICERT_SECURE_PATH__
    if (OK > (status = FMGMT_changeCWD(MANDATORY_BASE_PATH)))
        goto exit;
#endif

    SCEP_CLIENT_readTrustedConfig();

#ifdef __ENABLE_DIGICERT_TAP__
    if (gUseTap)
    {
        /* Initialize */
        if (OK != (status = SCEP_CLIENT_EXAMPLE_tapInitialize((ubyte*)pScepTapConfFile)))
        {
            DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "main::SCEP_CLIENT_EXAMPLE_tapInitialize::status:  ", status);
            goto exit;
        }

        /* Register this callback with Crypto Wrapper to get TAPContext.*/
        CRYPTO_INTERFACE_registerTapCtxCallback(SCEP_CLIENT_EXAMPLE_getTapContext);
    }
#endif /*__ENABLE_DIGICERT_TAP__*/

    role = USER;

    /* Check if this is a GetCACert operation - handle it separately and exit */
    if (0 == DIGI_STRCMP(pPkiOperation, (const sbyte*)PKI_OPERATION_GETCACERT))
    {
        if (OK > (status = init(&pHttpContext)))
        {
            DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "main::init::status:  ", status);
            goto exit;
        }

        status = SCEP_SAMPLE_getCACert(pHttpContext, (ubyte *)pScepServerUrl, filePath);
        if (OK != status)
        {
            DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "main::SCEP_SAMPLE_getCACert::status:  ", status);
            goto exit;
        }

        DEBUG_PRINTNL(DEBUG_SCEP_EXAMPLE, "GetCACert operation completed successfully");
        goto exit;
    }

    /* Below to test the sample APIs for enrollment operations */
    /* 1. SCEP_SAMPLE_generateAsymKey */
    /* 2. SCEP_SAMPLE_generateCSRRequest */
    /* 3. SCEP_SAMPLE_sendEnrollmentRequest */

    if (0 != DIGI_STRCMP(pPkiOperation, (const sbyte*)PKI_OPERATION_RENEW))
    {
        /* 1. SCEP_SAMPLE_generateAsymKey */
        status = SCEP_SAMPLE_generateAsymKey(
#if defined(__ENABLE_DIGICERT_TAP__)
                scepc_keySource,
#else
                (sbyte *)KEY_SOURCE_SW,
#endif
                scepc_keyType,
                scepc_keySize,
#ifdef __ENABLE_DIGICERT_TAP__
                g_pTapContext,
                g_pEntityCredentialList,
                g_pKeyCredentialList,
                pScepTapKeyUsage,
                pScepTapSignScheme,
                pScepTapEncScheme,
#endif
                &pKeyBlob, &keyBlobLen);

        if (OK != status)
        {
            DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "main::SCEP_SAMPLE_generateAsymKey::status: ", status);
            goto exit;
        }
        if (0 == DIGI_STRCMP(pPkiOperation, (const sbyte*)PKI_OPERATION_ENROLL))
            setFullPathWithSubdir((sbyte*)GENPEMKEY_FILE, filePath, (const sbyte*)"keys", (sbyte**)&pKeyBlobFile);
        else if (0 == DIGI_STRCMP(pPkiOperation, (const sbyte*)PKI_OPERATION_REKEY))
            setFullPathWithSubdir((sbyte*)RENEWALPEMKEY_FILE, filePath, (const sbyte*)"keys", (sbyte**)&pKeyBlobFile);
        DEBUG_PRINT2(DEBUG_SCEP_EXAMPLE, "Writing Generated KEY-PAIR in PEM format: ", pKeyBlobFile);
        DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"\n");
        (void)backupOldFile(pKeyBlobFile);
        if (OK > (status = DIGICERT_writeFile((const char *) pKeyBlobFile, pKeyBlob, keyBlobLen)))
        {
            DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "main::DIGICERT_writeFile::status: ", status);
            goto exit;
        }
        DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"\n");
    }
    else
    {
        /* renew case */
        sbyte *pOldKeyPath = NULL;

        /* Construct full path for old key file from keystore/keys */
        if (scepc_certPath != NULL)
        {
            setFullPathWithSubdir((sbyte *)pOldPemKeyFile, scepc_certPath, (const sbyte*)"keys", &pOldKeyPath);
        }
        else
        {
            setFullPathWithSubdir((sbyte *)pOldPemKeyFile, filePath, (const sbyte*)"keys", &pOldKeyPath);
        }

        if (OK != (status = DIGICERT_readFile((char*)pOldKeyPath, &pKeyBlob, &keyBlobLen)))
        {
            DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "\nmain::DIGICERT_readFile::status: ", status);
            if (pOldKeyPath) DIGI_FREE((void**)&pOldKeyPath);
            goto exit;
        }

        if (pOldKeyPath) DIGI_FREE((void**)&pOldKeyPath);
    }

    /* 2. SCEP_SAMPLE_generateCSRRequest */
    if (NULL != scepc_confFile)
    {
        /* Use conf_dir from tpconf.json if available, otherwise use /etc subdirectory */
        if (scepc_confPath != NULL)
        {
            setFullPath((sbyte *)scepc_confFile, scepc_confPath, &pFullPath);
        }
        else
        {
            setFullPathWithSubdir((sbyte *)scepc_confFile, filePath, (const sbyte*)"etc", &pFullPath);
        }
        if (OK > (status = DIGICERT_readFile((const char *) pFullPath, &pCSRAttrBuffer, &csrAttrBufferLen)))
        {
            DEBUG_PRINT2(DEBUG_SCEP_EXAMPLE, "ERROR: Unable to read CSR config file: ", pFullPath);
            DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "\nmain::DIGICERT_readFile::status", status);
            goto exit;
        }

        status = SCEP_SAMPLE_generateCSRRequest(
#if defined(__ENABLE_DIGICERT_TAP__)
                scepc_keySource,
#else
                (sbyte *)KEY_SOURCE_SW,
#endif
                pKeyBlob,
                keyBlobLen,
                pCSRAttrBuffer,
                csrAttrBufferLen,
                pChallengePass,
                DIGI_STRLEN((const sbyte *)pChallengePass),
                &pCsrBuffer,
                &csrBufferLen,
                &pReqInfo);
        if (OK != status)
        {
            DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "main::SCEP_SAMPLE_generateCSRRequest::status  ", status);
            goto exit;
        }
    }
    else
    {
        DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "ERROR: Please provide conf file - ", status);
        goto exit;
    }
    if (OK > (status = BASE64_encodeMessage(pCsrBuffer, csrBufferLen,
                    &pLineCsr, &lineCsrLength)))
    {
        DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "main::BASE64_encodeMessage::status  ", status);
        goto exit;
    }

    if (OK > (status = SCEP_MESSAGE_breakIntoLines(pLineCsr, lineCsrLength,
                    &pCsr, &csrLen)))
    {
        DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "main::SCEP_MESSAGE_breakIntoLines::status  ", status);
        goto exit;
    }

    setFullPathWithSubdir((sbyte*)CSR_CONFIG_FILE, filePath, (sbyte*)"req", (sbyte**)&pCsrFile);
    DEBUG_PRINT2(DEBUG_SCEP_EXAMPLE, "Writing CSR File in PEM format: ", pCsrFile);
    DEBUG_PRINT(DEBUG_SCEP_EXAMPLE, "\n");
    (void)backupOldFile(pCsrFile);
    if (OK > (status = DIGICERT_writeFile((const char *) pCsrFile, pCsr, csrLen)))
    {
        DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "main::DIGICERT_writeFile::status: ", status);
        goto exit;
    }
    DEBUG_PRINT(DEBUG_SCEP_EXAMPLE,"\n");

    /* 3. SCEP_SAMPLE_sendEnrollmentRequest */
    DEBUG_PRINT(DEBUG_SCEP_EXAMPLE, "\n send Enrollment request\n");

    /* Load CA certificate (scep_ca.der) from truststore */
    if (OK > (status = CERT_STORE_createStore(&pCertStore)))
    {
        DEBUG_PRINTNL(DEBUG_SCEP_EXAMPLE, "ERROR: Unable to create certificate store");
        DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "main::CERT_STORE_createStore::status", status);
        goto exit;
    }

    /* Load CA certificate from ca/ subdirectory */
    if (scepc_truststorePath != NULL)
    {
        setFullPath((sbyte *)SCEP_CA_CERT_FILE, scepc_truststorePath, &pTrustPath);
    }
    else
    {
        setFullPathWithSubdir((sbyte *)SCEP_CA_CERT_FILE, filePath, (const sbyte*)"ca", &pTrustPath);
    }

    /* Read CA certificate file */
    if (OK > DIGICERT_readFile((const char *)pTrustPath, &pCert, &certLen))
    {
        DEBUG_PRINT2(DEBUG_SCEP_EXAMPLE, "ERROR: Unable to read CA certificate from: ", pTrustPath);
        DEBUG_PRINTNL(DEBUG_SCEP_EXAMPLE, "");
        DIGI_FREE((void**)&pTrustPath);
        status = ERR_CERT_NOT_FOUND;
        goto exit;
    }

    DEBUG_PRINT2(DEBUG_SCEP_EXAMPLE, "Loaded CA certificate from: ", pTrustPath);
    DEBUG_PRINTNL(DEBUG_SCEP_EXAMPLE, "");

    /* Add CA certificate to cert store */
    status = CERT_STORE_addTrustPoint(pCertStore, pCert, certLen);
    if (OK > status)
    {
        DEBUG_PRINTNL(DEBUG_SCEP_EXAMPLE, "ERROR: Unable to add CA certificate to trust store");
        DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "CERT_STORE_addTrustPoint status", status);
        DIGI_FREE((void**)&pTrustPath);
        goto exit;
    }

    DIGI_FREE((void**)&pTrustPath);
    pTrustPath = NULL;

    /* Setup CA certificate array */
    numTrustCerts = 1;
    pTrustCerts = (certDescriptor *)MALLOC(sizeof(certDescriptor));
    if (NULL == pTrustCerts)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    pTrustCerts[0].pCertificate = pCert;
    pTrustCerts[0].certLength = certLen;
    pTrustCerts[0].pKeyBlob = NULL;
    pTrustCerts[0].keyBlobLength = 0;
    pTrustCerts[0].pKey = NULL;

    /* Load CEP and XCHG certificates from certs directory */
    if (scepc_certPath != NULL)
    {
        setFullPathWithSubdir((sbyte *)SCEP_CEP_CERT_FILE, scepc_certPath, (const sbyte*)"certs", &pCertsPath);
    }
    else
    {
        setFullPathWithSubdir((sbyte *)SCEP_CEP_CERT_FILE, filePath, (const sbyte*)"certs", &pCertsPath);
    }

    /* Try to load CEP certificate (scep_cep.der) */
    if (OK == DIGICERT_readFile((const char *)pCertsPath, &pCepCert, &cepCertLen))
    {
        /* Decode certificate if it's PEM-encoded */
        status = CA_MGMT_decodeCertificate(pCepCert, cepCertLen, &pDecodedCert, &decodedCertLen);
        if (OK == status)
        {
            /* Certificate was PEM-encoded, use decoded version */
            DIGI_FREE((void **)&pCepCert);
            pCepCert = pDecodedCert;
            cepCertLen = decodedCertLen;
        }

        DEBUG_PRINT2(DEBUG_SCEP_EXAMPLE, "Loaded CEP certificate from: ", pCertsPath);
        DEBUG_PRINTNL(DEBUG_SCEP_EXAMPLE, "");
    }
    else
    {
        /* CEP not found, make a copy of CA cert to use as CEP */
        DEBUG_PRINT2(DEBUG_SCEP_EXAMPLE, "CEP certificate not found at: ", pCertsPath);
        DEBUG_PRINTNL(DEBUG_SCEP_EXAMPLE, " (will use CA cert as encryption cert)");

        pCepCert = (ubyte *)MALLOC(certLen);
        if (NULL == pCepCert)
        {
            status = ERR_MEM_ALLOC_FAIL;
            DIGI_FREE((void**)&pCertsPath);
            goto exit;
        }
        DIGI_MEMCPY(pCepCert, pCert, certLen);
        cepCertLen = certLen;
    }
    DIGI_FREE((void**)&pCertsPath);
    pCertsPath = NULL;

    /* Try to load XCHG certificate (scep_xchg.der) */
    if (scepc_certPath != NULL)
    {
        setFullPathWithSubdir((sbyte *)SCEP_XCHG_CERT_FILE, scepc_certPath, (const sbyte*)"certs", &pCertsPath);
    }
    else
    {
        setFullPathWithSubdir((sbyte *)SCEP_XCHG_CERT_FILE, filePath, (const sbyte*)"certs", &pCertsPath);
    }

    if (OK == DIGICERT_readFile((const char *)pCertsPath, &pExchangerCert, &exchangerCertLen))
    {
        /* Decode certificate if it's PEM-encoded */
        ubyte *pDecodedCert = NULL;
        ubyte4 decodedCertLen = 0;

        status = CA_MGMT_decodeCertificate(pExchangerCert, exchangerCertLen, &pDecodedCert, &decodedCertLen);
        if (OK == status)
        {
            /* Certificate was PEM-encoded, use decoded version */
            DIGI_FREE((void **)&pExchangerCert);
            pExchangerCert = pDecodedCert;
            exchangerCertLen = decodedCertLen;
        }

        DEBUG_PRINT2(DEBUG_SCEP_EXAMPLE, "Loaded XCHG certificate from: ", pCertsPath);
        DEBUG_PRINTNL(DEBUG_SCEP_EXAMPLE, "");
    }
    else
    {
        /* XCHG not found, make a copy of CA cert to use as XCHG */
        DEBUG_PRINT2(DEBUG_SCEP_EXAMPLE, "XCHG certificate not found at: ", pCertsPath);
        DEBUG_PRINTNL(DEBUG_SCEP_EXAMPLE, " (will use CA cert as exchanger cert)");

        pExchangerCert = (ubyte *)MALLOC(certLen);
        if (NULL == pExchangerCert)
        {
            status = ERR_MEM_ALLOC_FAIL;
            DIGI_FREE((void**)&pCertsPath);
            goto exit;
        }
        DIGI_MEMCPY(pExchangerCert, pCert, certLen);
        exchangerCertLen = certLen;
    }
    DIGI_FREE((void**)&pCertsPath);
    pCertsPath = NULL;

    /* Setup CA certificate array */
    numCaCerts = numTrustCerts;
    pCACerts = pTrustCerts;

    /* Setup RA certificate array - always use CEP cert (which is either loaded or copied from CA) */
    numRaCerts = 1;
    pRACerts = (certDescriptor *)MALLOC(sizeof(certDescriptor));
    if (NULL == pRACerts)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    pRACerts[0].pCertificate = pCepCert;
    pRACerts[0].certLength = cepCertLen;
    pRACerts[0].pKeyBlob = NULL;
    pRACerts[0].keyBlobLength = 0;
    pRACerts[0].pKey = NULL;

    /* Initialize asymmetric key */
    if (OK > (status = CRYPTO_initAsymmetricKey (&asymKey)))
    {
        DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "main::CRYPTO_initAsymmetricKey::status  ", status);
        goto exit;
    }

    status = CRYPTO_deserializeAsymKey(
        pKeyBlob, keyBlobLen, NULL, &asymKey);
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "main::CRYPTO_deserializeAsymKey::status  ", status);
        goto exit;
    }

    /* Generate self signed certificate */
    if (digestAlgoOID != NULL)
    {
        if (EqualOID(digestAlgoOID, md5_OID))
        {
            hashType = ht_md5;
        } else if (EqualOID(digestAlgoOID, sha1_OID))
        {
            hashType = ht_sha1;
        } else if (EqualOID(digestAlgoOID, sha224_OID))
        {
            hashType = ht_sha224;
        } else if (EqualOID(digestAlgoOID, sha256_OID))
        {
            hashType = ht_sha256;
        } else if (EqualOID(digestAlgoOID, sha384_OID))
        {
            hashType = ht_sha384;
        } else if (EqualOID(digestAlgoOID, sha512_OID))
        {
            hashType = ht_sha512;
        }
        else
        {
            status = ERR_SCEP;
            DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "Hash algorithm not supported  ", status);
            goto exit;
        }
    }
    /* Added startdate and end date */
    int len = DIGI_STRLEN(gCertInfo.pEndDate);
    if (OK > (status = DIGI_CALLOC((void**)&(pReqInfo->value.certInfoAndReqAttrs.pSubject->pEndDate), 1, len+1)))
    {
        DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "main::DIGI_CALLOC::status  ", status);
        goto exit;
    }
    DIGI_MEMCPY(pReqInfo->value.certInfoAndReqAttrs.pSubject->pEndDate, gCertInfo.pEndDate, len);
    *((pReqInfo->value.certInfoAndReqAttrs.pSubject->pEndDate)+len) = '\0';
    len = DIGI_STRLEN(gCertInfo.pStartDate);
    if (OK > (status = DIGI_CALLOC((void**)&(pReqInfo->value.certInfoAndReqAttrs.pSubject->pStartDate), 1, len+1)))
    {
        DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "main::DIGI_CALLOC::status  ", status);
        goto exit;
    }
    DIGI_MEMCPY(pReqInfo->value.certInfoAndReqAttrs.pSubject->pStartDate, gCertInfo.pStartDate, len);
    *((pReqInfo->value.certInfoAndReqAttrs.pSubject->pStartDate)+len) = '\0';

    if ((0 == DIGI_STRCMP(pPkiOperation, (const sbyte*)PKI_OPERATION_RENEW)) ||
            (0 == DIGI_STRCMP(pPkiOperation, (const sbyte*)PKI_OPERATION_REKEY)))
    {
        sbyte *pOldKeyPath = NULL;
        sbyte *pOldCertPath = NULL;

        /* Construct full path for old key file from keystore/keys */
        if (scepc_certPath != NULL)
        {
            setFullPathWithSubdir((sbyte *)pOldPemKeyFile, scepc_certPath, (const sbyte*)"keys", &pOldKeyPath);
        }
        else
        {
            setFullPathWithSubdir((sbyte *)pOldPemKeyFile, filePath, (const sbyte*)"keys", &pOldKeyPath);
        }

        /* Construct full path for old cert file from keystore/certs */
        if (scepc_certPath != NULL)
        {
            setFullPathWithSubdir((sbyte *)pOldCertFile, scepc_certPath, (const sbyte*)"certs", &pOldCertPath);
        }
        else
        {
            setFullPathWithSubdir((sbyte *)pOldCertFile, filePath, (const sbyte*)"certs", &pOldCertPath);
        }

        if (OK != (status = DIGICERT_readFile((char*)pOldKeyPath, &pOldPemKeyBlob, &oldPemKeyBlobLen)))
        {
            DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "\nmain::DIGICERT_readFile::status  ", status);
            if (pOldKeyPath) DIGI_FREE((void**)&pOldKeyPath);
            if (pOldCertPath) DIGI_FREE((void**)&pOldCertPath);
            goto exit;
        }

        if (OK != (status = DIGICERT_readFile((char*)pOldCertPath, &pRequesterCert, &requesterCertLen)))
        {
            DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "\nmain::DIGICERT_readFile::status  ", status);
            if (pOldKeyPath) DIGI_FREE((void**)&pOldKeyPath);
            if (pOldCertPath) DIGI_FREE((void**)&pOldCertPath);
            goto exit;
        }

        /* Free the temporary path variables */
        if (pOldKeyPath) DIGI_FREE((void**)&pOldKeyPath);
        if (pOldCertPath) DIGI_FREE((void**)&pOldCertPath);
    }
    else
    {

        if (OK > (status = ASN1CERT_generateSelfSignedCertificate(MOC_ASYM(hwAccelCtx) &asymKey,
                        pReqInfo->value.certInfoAndReqAttrs.pSubject,
                        hashType,
                        pReqInfo->value.certInfoAndReqAttrs.pReqAttrs->pExtensions,
                        RANDOM_rngFun, g_pRandomContext,
                        &pRequesterCert, &requesterCertLen)))
        {
            DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "main::ASN1CERT_generateSelfSignedCertificate::status  ", status);
            goto exit;
        }
    }
    reqCertDesc.pCertificate = pRequesterCert;
    reqCertDesc.certLength = requesterCertLen;
    if ( OK > (status = init(&pHttpContext)))
    {
        DEBUG_ERROR(DEBUG_SCEP_EXAMPLE,"SCEP_CLIENT_EXAMPLE init() return status = ", status);
        goto exit;
    }

    if (OK > (status = DIGI_CALLOC((void**)&g_pScepData, 1, sizeof(SCEP_data))))
    {
        DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "main::DIGI_CALLOC::status  ", status);
        goto exit;
    }

    /* Fill the SCEP Data */
    g_pScepData->pExchangerCertificate = pExchangerCert;
    g_pScepData->exchangerCertLen = exchangerCertLen;
    if ( (0 == DIGI_STRCMP(pPkiOperation, (const sbyte*)PKI_OPERATION_REKEY)))
    {
        g_pScepData->pPemKeyBlob = pOldPemKeyBlob;
        g_pScepData->pemKeyBlobLen = oldPemKeyBlobLen;
    }
    else
    {
        g_pScepData->pPemKeyBlob = pKeyBlob;
        g_pScepData->pemKeyBlobLen = keyBlobLen;
    }
    SCEP_SAMPLE_registerScepDataCallback(getScepData);

    if ((0 == DIGI_STRCMP(pPkiOperation, (const sbyte*)PKI_OPERATION_RENEW)))
    {
        pkiOperation = 2;
    }
    else if (0 == DIGI_STRCMP(pPkiOperation, (const sbyte*)PKI_OPERATION_REKEY))
    {
        pkiOperation = 3;
    }
    else if (0 == DIGI_STRCMP(pPkiOperation, (const sbyte*)PKI_OPERATION_ENROLL))
    {
        pkiOperation = 1;
    }

    status = SCEP_SAMPLE_sendEnrollmentRequest(
#if defined(__ENABLE_DIGICERT_TAP__)
            scepc_keySource,
#else
            (sbyte *)KEY_SOURCE_SW,
#endif
            pHttpContext,
            pKeyBlob, keyBlobLen,
            pCsrBuffer, csrBufferLen,
            pReqInfo,
            serverTypeStr, (ubyte *)pScepServerUrl,
            pCACerts, numCaCerts,
            pRACerts, numRaCerts,
            &reqCertDesc, pkiOperation,
            pOldPemKeyBlob, oldPemKeyBlobLen,
#ifdef __ENABLE_DIGICERT_CMS_RSA_OAEP__
            0, NULL, 0,
#endif
            &pOut, &outLen,
            &pTransId, &transIdLen, &outStatus);
    pReqInfo = NULL;
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "main::SCEP_SAMPLE_sendEnrollmentRequest::status: ", status);
        goto exit;
    }
    else
    {
        if (outStatus == scep_PENDING && pTransId != NULL)
        {
            if (pTransId == NULL)
            {
                status = ERR_NULL_POINTER;
                DEBUG_PRINT(DEBUG_SCEP_EXAMPLE, "TransactionId is null");
                goto exit;
            }
            DEBUG_PRINT(DEBUG_SCEP_EXAMPLE, "Received pending status. Retry pending request...\n");

            if (((serverType == GEN_GET_SERVER) || (serverType == GEN_POST_SERVER)) &&
                ((0 == DIGI_STRCMP(pPkiOperation, (const sbyte*)PKI_OPERATION_RENEW)) ||
                    (0 == DIGI_STRCMP(pPkiOperation, (const sbyte*)PKI_OPERATION_REKEY))))
            {
                (void) DIGI_FREE((void **) &pRequesterCert);
				if (OK > (status = ASN1CERT_generateSelfSignedCertificate(MOC_ASYM(hwAccelCtx) &asymKey,
								pReqInfo->value.certInfoAndReqAttrs.pSubject,
								hashType,
								pReqInfo->value.certInfoAndReqAttrs.pReqAttrs->pExtensions,
								RANDOM_rngFun, g_pRandomContext,
								&pRequesterCert, &requesterCertLen)))
				{
					DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "main::ASN1CERT_generateSelfSignedCertificate::status  ", status);
					goto exit;
				}
                reqCertDesc.pCertificate = pRequesterCert;
                reqCertDesc.certLength = requesterCertLen;
                g_pScepData->pPemKeyBlob = pKeyBlob;
                g_pScepData->pemKeyBlobLen = keyBlobLen;
            }
            status = SCEP_SAMPLE_retryPendingEnrollmentRequest(
#if defined(__ENABLE_DIGICERT_TAP__)
                    scepc_keySource,
#else
                    (sbyte *)KEY_SOURCE_SW,
#endif
                    pHttpContext,
                    pKeyBlob, keyBlobLen,
                    pCsrBuffer, csrBufferLen,
                    pReqInfo,
                    serverTypeStr, (ubyte *)pScepServerUrl,
                    pCACerts, numCaCerts,
                    pRACerts, numRaCerts,
                    &reqCertDesc, pkiOperation,
                    pOldPemKeyBlob, oldPemKeyBlobLen,
                    pTransId, transIdLen,
                    POLL_INTERVAL, POLL_COUNT,
#ifdef __ENABLE_DIGICERT_CMS_RSA_OAEP__
                    0, NULL, 0,
#endif
                    &pOut, &outLen);
            if (OK != status)
            {
                DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "main::SCEP_SAMPLE_retryPendingEnrollmentRequest::status: ", status);
                goto exit;
            }
            else
            {
                setFullPathWithSubdir((sbyte*) REQUESTER_CERT_FILE, filePath, (const sbyte*)"certs", (sbyte **)&respFile);
                (void)backupOldFile(respFile);
                if ( OK > ( status = DIGICERT_writeFile((const char *)respFile, pOut, outLen)))
                {
                    DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "SCEP_TEST_SAMPLE: Received response with SUCCESS status - ", status);
                    goto exit;
                }
                DEBUG_PRINT2(DEBUG_SCEP_EXAMPLE, "SCEP_TEST_SAMPLE: Received response with SUCCESS status - ", respFile);
                DEBUG_PRINT(DEBUG_SCEP_EXAMPLE, "\n");
            }
        }
        else
        {
            setFullPathWithSubdir((sbyte*) REQUESTER_CERT_FILE, filePath, (const sbyte*)"certs", (sbyte **)&respFile);
            (void)backupOldFile(respFile);
            if ( OK > ( status = DIGICERT_writeFile((const char *)respFile, pOut, outLen)))
            {
                DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "SCEP_TEST_SAMPLE: Received response with SUCCESS status - ", status);
                goto exit;
            }
            DEBUG_PRINT2(DEBUG_SCEP_EXAMPLE, "SCEP_TEST_SAMPLE: Received response with SUCCESS status - ", respFile);
            DEBUG_PRINT(DEBUG_SCEP_EXAMPLE, "\n");
        }
    }

exit:
   if (g_pScepData)
       DIGI_FREE((void**)&g_pScepData);
    DIGI_FREE((void**)&respFile);
    DIGI_FREE((void**)&pFullPath);
    DIGI_FREE((void**)&pRequesterCert);
    DIGI_FREE((void**)&pTransId);
    DIGI_FREE((void**)&pCSRAttrBuffer);
    DIGI_FREE((void**)&pKeyBlobFile);
    if (pCsrBuffer) DIGI_FREE((void**)&pCsrBuffer);
    if (pOut) DIGI_FREE((void**)&pOut);
    if (pKeyBlob) DIGI_FREE((void**)&pKeyBlob);
    if (pOldPemKeyBlob) DIGI_FREE((void**)&pOldPemKeyBlob);

    /* Free exchanger cert (always separately allocated now) */
    if (pExchangerCert) DIGI_FREE((void**)&pExchangerCert);

    /* Free CEP cert and RA certs array (always separately allocated now) */
    if (pRACerts)
    {
        /* pRACerts[0].pCertificate points to pCepCert, will be freed separately */
        DIGI_FREE((void**)&pRACerts);
    }
    if (pCepCert) DIGI_FREE((void**)&pCepCert);

    if (pCsrFile) DIGI_FREE((void**)&pCsrFile);
    if (pLineCsr) DIGI_FREE((void**)&pLineCsr);
    if (pCsr) DIGI_FREE((void**)&pCsr);
    if (pPayLoad) DIGI_FREE((void**)&pPayLoad);
    if (pReqInfo) SCEP_CONTEXT_releaseRequestInfo(pReqInfo);
    if (pCert) DIGI_FREE((void**)&pCert);
    if (pTrustCerts)
    {
        DIGI_FREE((void**)&pTrustCerts);
    }
    /* Release cert store - this will free the certificate data */
    if (pCertStore) CERT_STORE_releaseStore(&pCertStore);
    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
    SCEP_CLIENT_EXAMPLE_freeArgs();
    if (pHttpContext != NULL)
        HTTP_CONTEXT_releaseContext(&pHttpContext);
    DIGI_FREE((void**)&caCertFileName);
    DIGI_FREE((void**)&adminCertFileName);
    DIGI_FREE((void**)&cepCertFileName);
    DIGI_FREE((void**)&exchangeCertFileName);
    DIGI_FREE((void**)&pDatKeyBlob);

#ifdef __ENABLE_DIGICERT_TAP__
    if (gUseTap)
    {
		if (NULL != g_pEntityCredentialList)
		{
			status = TAP_UTILS_clearEntityCredentialList(g_pEntityCredentialList);
			if (OK != status)
				DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "main::TAP_UTILS_clearEntityCredentialList::status: ", status);
            DIGI_FREE((void**)&g_pEntityCredentialList);
		}
        if (g_pKeyCredentialList != NULL)
        {
            for (i = 0; i < g_pKeyCredentialList->numCredentials; i++)
            {
                if (g_pKeyCredentialList->pCredentialList[i].credentialData.pBuffer != NULL)
                    DIGI_FREE((void**)&(g_pKeyCredentialList->pCredentialList[i].credentialData.pBuffer));
            }
            DIGI_FREE((void**)&(g_pKeyCredentialList->pCredentialList));
            DIGI_FREE((void**)&g_pKeyCredentialList);
        }

        if (OK != (status = SCEP_CLIENT_EXAMPLE_tapUninitialize()))
        {
            DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "main::EST_CLIENT_TAP_uninitialize::status:  ", status);
            goto exit;
        }
    }
#endif

    RTOS_sleepMS(1000); /* sleep for one second etc */
    gMocanaAppsRunning--;
    return status;
}

#endif /* (defined(__ENABLE_DIGICERT_EXAMPLES__) || defined(__ENABLE_DIGICERT_BIN_EXAMPLES__)) */
#endif /* defined( __ENABLE_DIGICERT_SCEPC__) */
