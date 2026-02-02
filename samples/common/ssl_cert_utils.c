/* Version: test_package */
/*
    ssl_cert_utils.c

    Copyright Mocana Corp 2006-2017. All Rights Reserved.
    Proprietary and Confidential Material.
*/

#if defined _MSC_VER
#include <direct.h>
#else
#ifndef __RTOS_FREERTOS__
#include <sys/types.h>
#include <sys/stat.h>
#endif
#endif

#include "ssl_cert_utils.h"
#include <errno.h>

#ifdef __ENABLE_DIGICERT_DSA__
#define ALG_DSA 1
#else
#define ALG_DSA 0
#endif

#ifdef __ENABLE_DIGICERT_ECC__
#define ALG_ECC 1
#else
#define ALG_ECC 0
#endif

#ifndef __DISABLE_DIGICERT_SSL_RSA_SUPPORT__
#define ALG_RSA 1
#else
#define ALG_RSA 0
#endif

#define ALG_COUNT (ALG_DSA + ALG_ECC + ALG_RSA)

nameAttr pDNames1[] =
{
    {countryName_OID, 0, (ubyte*)"US", 2}
};
nameAttr pDNames2[] =
{
    {stateOrProvinceName_OID, 0, (ubyte*)"California", 10}
};
nameAttr pDNames3[] =
{
    {localityName_OID, 0, (ubyte*)"San Francisco", 13}
};
nameAttr pDNames4[] =
{
    {organizationName_OID, 0, (ubyte*)"Mocana Corporation", 18}
};
nameAttr pDNames5[] =
{
    {organizationalUnitName_OID, 0, (ubyte*)"Engineering", 11}
};
nameAttr pDNames6[] =
{
#ifdef __ENABLE_DIGICERT_SSL_SERVER__
    {commonName_OID, 0, (ubyte*)"webapptap.securitydemos.net", 27}
#else
    {commonName_OID, 0, (ubyte*)"ssltest.mocana.com", 18}
#endif
};
nameAttr pDNames7[] =
{
    {pkcs9_emailAddress_OID, 0, (ubyte*)"info@mocana.com", 15}
};

relativeDN pRDNames[] =
{
    {pDNames1, 1},
    {pDNames2, 1},
    {pDNames3, 1},
    {pDNames4, 1},
    {pDNames5, 1},
    {pDNames6, 1},
    {pDNames7, 1}
};

certDistinguishedName certDistNames =
{
	pRDNames, 7,
    (sbyte*) "150529110000Z",                /* certificate start date */
    (sbyte*) "450529110000Z"                 /* certificate end date */
};

/* Mutual authentication testing: client certificate */
nameAttr pClientDNames6[] =
{
    {commonName_OID, 0, (ubyte*)"sales.mocana.com", 18}            /* common name */
};

relativeDN pClientRDNames[] =
{
    {pDNames1, 1},
    {pDNames2, 1},
    {pDNames3, 1},
    {pDNames4, 1},
    {pDNames5, 1},
    {pClientDNames6, 1},
    {pDNames7, 1}
};

certDistinguishedName clientCertDistNames =
{
	pClientRDNames, 7,
    (sbyte*) "051115110000Z",                            /* certificate start date */
    (sbyte*) "251115110000Z"                             /* certificate end date */
};

typedef intBoolean (*CertInfoPredFun)( const CertificateInfo* pCI, void* arg);

static CertificateInfo gCertificateInfos[] =
{
#if (defined(__ENABLE_DIGICERT_DSA__))
    CERTIFICATE_INFO(akt_dsa, "DSACertCA", "Engineering CA (DSA 2048)", 2048),
    CERTIFICATE_INFO(akt_dsa, "DSACertCA1024", "Engineering CA (DSA 1024)", 1024),
#endif
#ifndef __DISABLE_DIGICERT_SSL_RSA_SUPPORT__
    CERTIFICATE_INFO(akt_rsa, "RSACertCA", "Engineering CA (RSA 2048)", 2048),
    CERTIFICATE_INFO(akt_rsa, "ClientRSACert", "Sales CA (RSA 2048)", 2048),
#endif
#if (defined(__ENABLE_DIGICERT_ECC__))
    CERTIFICATE_INFO(akt_ecc, "ECCCertCA384", "Engineering CA (ECDSA 384)", 384),
    CERTIFICATE_INFO(akt_ecc, "ClientECCCertCA384", "Engineering CA (ECDSA 384)", 384),
#endif
};

MOC_EXTERN MSTATUS
SSL_CERT_UTILS_checkServerIsOnline(const sbyte* pIpAddress, ubyte2 portNo, int maxtries)
{
	int i;
	TCP_SOCKET mySocket;
	MSTATUS status = ERR_GENERAL;

	i = -1;
	do
	{
		if(i == 1 || i==2)
		{
			DEBUG_PRINT2(DEBUG_SSL_EXAMPLE, (sbyte *)"Wait for server at ", pIpAddress);
			DEBUG_PRINTSTR1INT1(DEBUG_SSL_EXAMPLE, (sbyte *)":", portNo);
			DEBUG_PRINTSTR1INT1(DEBUG_SSL_EXAMPLE, (sbyte *)":", i);
			DEBUG_PRINTNL(DEBUG_SSL_EXAMPLE, NULL);
		}

		status = TCP_CONNECT(&mySocket, (sbyte*) pIpAddress, portNo);
		if (OK == status)
		{
            (void) TCP_CLOSE_SOCKET(mySocket);
			break;
		}
		RTOS_sleepMS(2000);
		if (maxtries != 0)
			i++; /* Run forever. */
	} while (i < maxtries);

	return status;
}

#if 0
static void
SSL_CERT_UTILS_setStringParameter(char** param, char* value)
{
	*param = MALLOC((DIGI_STRLEN((const sbyte *)value))+1);
	DIGI_MEMCPY(*param, value, DIGI_STRLEN((const sbyte *)value));
	(*param)[DIGI_STRLEN((const sbyte *)value)] = '\0';
}
#endif  /* function is not used in this file */

MOC_EXTERN MSTATUS
SSL_CERT_UTILS_createDirectory(char *directory) {
	int  status;

#if defined _MSC_VER
    status = _mkdir(directory);
#elif defined(__RTOS_VXWORKS__)
    #if defined(__VX7_SR640__)
        status = mkdir(directory, 0777);
    #else
        status = mkdir(directory);
    #endif
#elif defined(__RTOS_FREERTOS__) && !defined(__FREERTOS_SIMULATOR__) && !defined(__RTOS_FREERTOS_ESP32__)
    status = f_mkdir(directory);
#else
    status = mkdir(directory, 0777);
#endif
	if (0 > status) {
	    if (errno == EEXIST)
		status = ERR_FILE_EXISTS;
	}
        return (MSTATUS)status;
}

MOC_EXTERN char* SSL_CERT_UTILS_getFullPath(const char* directory, const char* name, char **ppFull)
{
    int len;

    /* clean up */
    if (*ppFull)
        FREE(*ppFull);

    /* allocate enough memory for directory+name+separators+padding */
    len = strlen(directory);
    len += strlen(name);
    len += 10;
    *ppFull = MALLOC(len);
    if (NULL == *ppFull)
        return *ppFull;

#if (defined(__RTOS_WIN32__))
    /* Create concatenated string */
    strcpy(*ppFull, directory);
    strcat(*ppFull, "\\");
    strcat(*ppFull, name);
#elif (defined (__RTOS_VXWORKS__) || !defined (__RTOS_OSE__))
    /* Create concatenated string */
    strcpy(*ppFull, directory);
    strcat(*ppFull, "/");
    strcat(*ppFull, name);
#else
    /* Create duplicated string */
    strcpy(*ppFull, name);
#endif
    DB_PRINT("Full path is:  %s\n", *ppFull);
    return *ppFull;
}

MOC_EXTERN MSTATUS
SSL_CERT_UTILS_populateCertificateDir(char* KeyStore)
{
	MSTATUS status = ERR_GENERAL;
	ubyte4 i;

	status = (MSTATUS)SSL_CERT_UTILS_createDirectory(KeyStore);
    if ((OK != status) && (ERR_FILE_EXISTS != status))
    {
        DEBUG_ERROR(DEBUG_SSL_EXAMPLE, (sbyte *) "----------------------------> SSL_CERT_UTILS_createDirectory::status: ", status);
        return status;
    }

	for ( i = 0; i < COUNTOF( gCertificateInfos); ++i)
	{
		if (OK > (status = SSL_CERT_UTILS_createCertificate(KeyStore, gCertificateInfos + i)))
		{
			DEBUG_ERROR(DEBUG_SSL_EXAMPLE, (sbyte *)
					"----------------------------> SSL_CERT_UTILS_populateCertificateDir::status: ", status);
		}
	}
	return status;
}

MOC_EXTERN MSTATUS
SSL_CERT_UTILS_createCertificate(char* KeyStore, CertificateInfo* pCI)
{
    MSTATUS                 status = ERR_GENERAL;
    certDistinguishedName * pCertNames = &certDistNames;
    certExtensions          extensions;
    const CertificateInfo*  pParentCI = 0;
	char * fullpath = NULL;

	AsymmetricKey asymKey = {0};
	/* ubyte4 flag, contentsLen; */
	ubyte4 serializedDerKeyLen, serializedPemKeyLen;
	/* ubyte *pContents = NULL; */
	ubyte *pSerializedDerKey = NULL;
	ubyte *pSerializedPemKey = NULL;

    hwAccelDescr hwAccelCtx = 0;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
    {
        goto exit;
    }

    SSL_CERT_UTILS_getFullPath(KeyStore, pCI->certFileName, &fullpath);
    if(NULL == fullpath)
        goto exit;

    if ( OK > ( status =  DIGICERT_readFile(fullpath,
    		&pCI->certDesc.pCertificate,
    		&pCI->certDesc.certLength)))
    {

    	/* free any allocated stuff to start from scratch */
    	(void) CA_MGMT_freeCertificate( &pCI->certDesc);

    	extensions.hasBasicConstraints = TRUE;
    	extensions.certPathLen = -1; /* omit */
    	extensions.hasKeyUsage = TRUE;
    	extensions.otherExts = NULL;
    	extensions.otherExtCount = 0;

    	if (pCI->keyType == akt_ecc) /* ECC */
    	{
    		extensions.keyUsage = (1 << digitalSignature) | ( 1 << keyAgreement);
    	}
    	else if (pCI->keyType == akt_dsa) /* ECC */
	{
	    extensions.keyUsage = (1 << digitalSignature) | ( 1 << keyAgreement);
	}
	else
    	{
    		extensions.keyUsage = (1 << digitalSignature) | ( 1 << keyEncipherment);
    		/* key encipherment, digital signature */
    	}

    	if ( pCI->caCertFileName) /* parent certificate */
    	{
    		/* find the parent certificate info by name */
#if 0   /* C++ style comments impact Wind River build */
    		//        pParentCI = SSL_SERV_findCertificate( SSL_SERV_MatchCIName, (void*) pCI->caCertFileName);
    		//        if (!pParentCI || !pParentCI->certDesc.pCertificate)
    		//        {
    		//            retVal = ERR_FALSE; /* CA cert should have been loaded before*/
    		//            goto exit;
    		//        }
#endif
    		extensions.isCA = FALSE;

#ifdef __SSLSERV_EXPIRED_CERTS__
    		pCertNames = &expiredCertNames;
#endif

    	}
    	else
    	{
    		extensions.isCA = TRUE;
    		extensions.keyUsage |=  (1 << keyCertSign) | ( 1 << cRLSign);
    		/* certificate and CRL signing */
    	}

    	/* change the certNames OU */
    	(certDistNames.pDistinguishedName+4)->pNameAttr->value = (ubyte*) pCI->orgUnit;
    	(certDistNames.pDistinguishedName+4)->pNameAttr->valueLen = DIGI_STRLEN( (const sbyte*) pCI->orgUnit);

    	/* if CN specified in CertificateInfo, use it */
    	if (pCI->commonName)
    	{
    		(certDistNames.pDistinguishedName+5)->pNameAttr->value = (ubyte*) pCI->commonName;
    		(certDistNames.pDistinguishedName+5)->pNameAttr->valueLen = DIGI_STRLEN( (const sbyte*) pCI->commonName);
    	}


    	if (OK > (status = (MSTATUS) CA_MGMT_generateCertificateExType( &pCI->certDesc, pCI->keyType, pCI->keySize,
    			pCertNames, ht_sha256, &extensions,
    			(pCI->caCertFileName) ? &pParentCI->certDesc : NULL)))
    	{
    		goto exit;
    	}

    	/* save to file */
        SSL_CERT_UTILS_getFullPath(KeyStore, pCI->certFileName, &fullpath);
        if(NULL != fullpath)
        {
            if (OK > ( status = DIGICERT_writeFile(fullpath,
                pCI->certDesc.pCertificate, pCI->certDesc.certLength)))
            {
                goto exit;
            }
        }

        SSL_CERT_UTILS_getFullPath(KeyStore, pCI->certKeyFileName, &fullpath);
        if(NULL != fullpath)
        {
            if (OK > ( status = DIGICERT_writeFile(fullpath,
                    pCI->certDesc.pKeyBlob, pCI->certDesc.keyBlobLength)))
            {
                goto exit;
            }
        }

        status = CRYPTO_initAsymmetricKey (&asymKey);
        if (OK != status)
            goto exit;

        status = CRYPTO_deserializeAsymKey(MOC_ASYM(hwAccelCtx) pCI->certDesc.pKeyBlob, pCI->certDesc.keyBlobLength, NULL,&asymKey);
        if (OK != status)
           goto exit1;

#ifdef __ENABLE_DIGICERT_SERIALIZE__
        /* Serialize the in DER Format */
        status = CRYPTO_serializeAsymKey (
             MOC_ASYM(hwAccelCtx) &asymKey, privateKeyInfoDer, &pSerializedDerKey,
             &serializedDerKeyLen);
        if (OK != status)
            goto exit1;

        if (OK > ( status = DIGICERT_writeFile(SSL_CERT_UTILS_getFullPath(KeyStore, pCI->certKeyDerFileName, &fullpath),
                                             pSerializedDerKey, serializedDerKeyLen)))
        {
           goto exit1;
        }

        /* Serialize the in PEM Format */
        status = CRYPTO_serializeAsymKey (
          MOC_ASYM(hwAccelCtx) &asymKey, privateKeyPem, &pSerializedPemKey,
          &serializedPemKeyLen);
        if (OK != status)
           goto exit1;


        if (OK > ( status = DIGICERT_writeFile(SSL_CERT_UTILS_getFullPath(KeyStore, pCI->certKeyPemFileName, &fullpath),
                                           pSerializedPemKey, serializedPemKeyLen)))
        {
           goto exit1;
        }
#endif
exit1:
        CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
    }

exit:
    if (NULL != pSerializedPemKey)
        DIGI_FREE((void **) &pSerializedPemKey);
    if (NULL != pSerializedDerKey)
        DIGI_FREE((void **) &pSerializedDerKey);
    if (fullpath)
        FREE(fullpath);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return status;
}

extern MSTATUS
SSL_CERT_UTILS_releaseCertificateInfos()
{
	MSTATUS status = ERR_GENERAL;
	ubyte4  i;

	for (i = 0; i < COUNTOF( gCertificateInfos); ++i)
	{
		status = (MSTATUS) CA_MGMT_freeCertificate(&gCertificateInfos[i].certDesc);
		if (OK > status)
            goto exit;
	}

exit:
       return status;
}
