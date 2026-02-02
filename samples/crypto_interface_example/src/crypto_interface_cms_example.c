/*
 * crypto_interface_cms_example.c
 *
 * Crypto Interface CMS Example Code
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

#include "../../common/moptions.h"
#include "../../common/mtypes.h"
#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mrtos.h"
#include "../../common/mstdlib.h"
#include "../../common/mocana.h"
#include "../../common/random.h"
#include "../../common/absstream.h"
#include "../../common/memfile.h"
#include "../../common/tree.h"
#include "../../asn1/oiddefs.h"
#include "../../asn1/parseasn1.h"
#include "../../crypto/hw_accel.h"
#include "../../crypto/pubcrypto.h"
#include "../../crypto/cms.h"

/* For our signing callback example we need actual crypto code */
#include "../../crypto/rsa.h"
#include "../../crypto/dsa.h"
#include "../../crypto/primeec.h"
#include "../../crypto_interface/crypto_interface_rsa.h"
#include "../../crypto_interface/crypto_interface_dsa.h"
#include "../../crypto_interface/crypto_interface_ecc.h"

/* Helper Structure to hold a buffer and its length */
typedef struct _OutBufferInfo
{
    ubyte *pBuffer;
    ubyte4 bufferLen;

} OutBufferInfo;

/*------------------------------------------------------------------------------------*/

/* User defined callback that can obtain the certificate from the given input 
   In practice one would likely use the serial number and/or issuer to find 
   and match the certificate in the cert store. The parameter pArg is an
   optional pointer to a context. To keep things simple for this illustraion, 
   we'll just use pArg as the C String name of the certificate file.
*/
static MSTATUS myGetCertFun(const void* pArg,
                            CStream cs,
                            ASN1_ITEM* pSerialNumber,
                            ASN1_ITEM* pIssuerName,
                            ubyte** ppCertificate,
                            ubyte4* pCertLen)
{
    return DIGICERT_readFile((const char*) pArg, ppCertificate, pCertLen);
}

/*------------------------------------------------------------------------------------*/

/* User defined callback that can validate a certificate in parsed ASN1 form.
   pArg is a pointer to an optional context. To keep things simple for this
   illustration, we'll just always return OK */
static MSTATUS myValCertFun(const void* pArg, CStream cs,
                            ASN1_ITEM* pCertificate)
{
    return OK;
}

/*------------------------------------------------------------------------------------*/

/* User defined callback that will obtain the private key from the given input.*/
static MSTATUS myGetPrivKeyFun(const void* pArg, CStream cs,
                               const CMSRecipientId* pId,
                               AsymmetricKey* pKey)
{
    MSTATUS status = OK;
    ubyte* pSerKey = NULL;
    ubyte4 keyLen = 0;

    /* The cert's recipient ID is passed in and can be used to find
       the proper cert and key pair. To keep things simple We know 
       a priori that the cert is cert.der and the key is key.der, but
       for illustrative purposes we'll validate that cert.der is what's
       being requested by checking the issuer and serial number. */

    /* Variables need for cert validaton */
    ubyte* pCert = NULL;
    ubyte4 certLen = 0;
    MemFile memFile = {0};
    CStream certCS = {0};
    ASN1_ITEMPTR pCertRoot = NULL, pIssuer = NULL, pSerialNumber = NULL;

    /* we require pKey to be non-null */
    if (NULL == pKey)
        return ERR_NULL_POINTER;

    /* Get the issuer and serial number from the CMSRecipientId pId */
    switch (pId->type)
    {
        case NO_TAG:

            if (NO_TAG == pId->ri.ktrid.type)
            {
                pIssuer = pId->ri.ktrid.u.issuerAndSerialNumber.pIssuer;
                pSerialNumber = pId->ri.ktrid.u.issuerAndSerialNumber.pSerialNumber;
            }
            else
            {
                status = ERR_FALSE;
                goto exit;
            }
            break;

        case 1:

            if (NO_TAG == pId->ri.karid.type)
            {
                pIssuer = pId->ri.ktrid.u.issuerAndSerialNumber.pIssuer;
                pSerialNumber = pId->ri.ktrid.u.issuerAndSerialNumber.pSerialNumber;
            }
            else
            {
                status = ERR_FALSE;
                goto exit;
            }
            break;

        default:
            status = ERR_FALSE;
            goto exit;
    }

    /* verify that the pSerialNumber and pIssuer match our own */
    status = DIGICERT_readFile( "cert.der", &pCert, &certLen);
    if (OK != status)
        goto exit;

    MF_attach(&memFile, certLen, pCert);
    CS_AttachMemFile(&certCS, &memFile);

    status = ASN1_Parse(certCS, &pCertRoot);
    if (OK != status)
        goto exit;

    status = X509_checkCertificateIssuerSerialNumber( pIssuer, pSerialNumber, cs,
                                                      ASN1_FIRST_CHILD(pCertRoot), certCS);
    if (OK != status)
        goto exit;

    /* all is good, read in the key associated with the cert */
    status = DIGICERT_readFile("key.der", &pSerKey, &keyLen);
    if (OK != status)
        goto exit;
   
    /* deserialize the key into an AsymmetricKey structure,
       cleanup any previous key if it's possible */
    status = CRYPTO_uninitAsymmetricKey( pKey, NULL);
    if (OK != status)
        goto exit;

    status = CRYPTO_initAsymmetricKey( pKey);
    if (OK != status)
        goto exit;

    status = CRYPTO_deserializeAsymKey(pSerKey, keyLen, NULL, pKey);

exit:

    /* cleanup, zero out any sensitive data */
    if (NULL != pSerKey)
        (void) DIGI_MEMSET_FREE(&pSerKey, keyLen);

    if (NULL != pCert)
        (void) DIGI_FREE((void **) &pCert);

    if (NULL != pCertRoot)
    {
        (void) TREE_DeleteTreeItem((TreeItem*)pCertRoot);
    }

    return status;
}

/*------------------------------------------------------------------------------------*/

/* User defined callback that can sign a buffer of data. For RSA signatures a digest info
   must be created with the given pDigestAlgoOID and that's what gets signed. For ECC and DSA
   this callback is required to place the signature in pSigBuffer in an R concatenated by S
   form with both R and S padded to the appropriate number of bytes based on the curve size
   or DSA Q prime size. pCbInfo is an optional user defined context, but to keep things
   simple here it'll simply be the C string name of the file storing the key. */
static MSTATUS mySignFun(void *pCbInfo, const ubyte* pDigestAlgoOID, const ubyte *pDataToSign,
                         ubyte4 dataToSignLen, ubyte *pSigBuffer, ubyte4 sigBufferLen)
{
    MSTATUS status = OK;

    /* variables needed to recover the key */
    ubyte *pKey = NULL;
    ubyte4 keyLen = 0;
    AsymmetricKey key = {0};

    /* signature or signature component length, re-used for all algs */
    ubyte4 elementLen = 0;

    /* variables needed for RSA digestInfo creation */
    DER_ITEMPTR pDigestInfo = 0;
    ubyte* pDerDigestInfo = 0;
    ubyte4 derDigestInfoLen = 0;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_DSA__
    /* variables for DSA signatures */
    ubyte *pR = NULL;
    ubyte4 rLen = 0;
    ubyte *pS = NULL;
    ubyte4 sLen = 0;
    ubyte4 padLen = 0;
#endif

    /* variables for ECDSA signatures */
    ubyte4 bytesWritten = 0;

    /* Read in the key whose file name should be in the pCbInfo */
    status = DIGICERT_readFile( (const char*) pCbInfo, &pKey, &keyLen);
    if (OK != status)
        goto exit;
    
    /* deserialize the key into an AsymmetricKey structure */
    status = CRYPTO_initAsymmetricKey( &key);
    if (OK != status)
        goto exit;

    status = CRYPTO_deserializeAsymKey(pKey, keyLen, NULL, &key);
    if (OK != status)
        goto exit;

    /* switch on whether we're doing RSA, DSA, or ECC, masking by 0xffff strips TAP info */
    switch (0xffff & key.type)
    {
        case akt_rsa:
           
            /* Get the length of the signature */
            status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux(key.key.pRSA, (sbyte4 *) &elementLen);
            if (OK != status)
                goto exit;

            /* validate the buffer has room */
            if (sigBufferLen < elementLen)
            {
                status = ERR_BUFFER_OVERFLOW;
                goto exit;
            }

            /* A signed Digest Info is expected, create it */
            status = DER_AddSequence ( NULL, &pDigestInfo);
            if (OK != status)
                goto exit;

            /* Add the OID */
            status = DER_StoreAlgoOID ( pDigestInfo, pDigestAlgoOID, TRUE /* addNullTag */);
            if (OK != status)
                goto exit;

            /* Add the data itself */
            status = DER_AddItem( pDigestInfo, OCTETSTRING, dataToSignLen, pDataToSign, NULL);
            if (OK != status)
                goto exit;

            /* Serialize into the buffer we'll actually sign */
            status = DER_Serialize( pDigestInfo, &pDerDigestInfo, &derDigestInfoLen);
            if (OK != status)
                goto exit;

            /* Sign */
            status = CRYPTO_INTERFACE_RSA_signMessageAux(key.key.pRSA, pDerDigestInfo, derDigestInfoLen,
                                                         pSigBuffer, NULL);
            if (OK != status)
                goto exit;

            break;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_DSA__
        case akt_dsa:

            /* Get the length of each component R and S of the signature */
            status = CRYPTO_INTERFACE_DSA_getSignatureLength (key.key.pDSA, &elementLen);
            if (OK != status)
                goto exit;

            /* Validate the buffer has room, note the full signature is R concatenated by S */
            if (sigBufferLen < 2 * elementLen)
            {
                status = ERR_BUFFER_OVERFLOW;
                goto exit;
            }

            status = CRYPTO_INTERFACE_DSA_computeSignatureAux (g_pRandomContext, key.key.pDSA,
                                                               (ubyte *) pDataToSign, dataToSignLen,
                                                               NULL, &pR, &rLen, &pS, &sLen, NULL);
            if (OK != status)
                goto exit;

            padLen = elementLen - rLen; 
            /* Copy each over to pSigBuffer with appropriate padding */
            if (padLen)
            {
                status = DIGI_MEMSET(pSigBuffer, 0x00, padLen);
                if (OK != status)
                    goto exit;
            }

            status = DIGI_MEMCPY(pSigBuffer + padLen, pR, rLen);
            if (OK != status)
                goto exit;

            /* Now S */
            padLen = elementLen - sLen; 
            if (padLen)
            {
                status = DIGI_MEMSET(pSigBuffer + elementLen, 0x00, padLen);
                if (OK != status)
                    goto exit;
            }

            status = DIGI_MEMCPY(pSigBuffer + elementLen + padLen, pS, sLen);
            if (OK != status)
                goto exit;

            break;
#endif
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_ECC__
        case akt_ecc:
        
            /* We can directly sign, this API will validate the buffer has room and 
               format the signature correctly */
            status = CRYPTO_INTERFACE_ECDSA_signDigestAux (key.key.pECC,
                                                           RANDOM_rngFun, g_pRandomContext,
                                                           (ubyte *) pDataToSign, dataToSignLen,
                                                           pSigBuffer, sigBufferLen,
                                                           &bytesWritten);
            if (OK != status)
                goto exit;

            /* optionally you could validate bytesWritten based on the curve, but here
               we know apriori that bytesWritten comes out correctly for OK status return */
            break;
#endif

        default:
            status = ERR_BAD_KEY_TYPE;
    }

exit:

    /* cleanup, zero out any sensitive data */
    if (NULL != pKey)
        (void) DIGI_MEMSET_FREE(&pKey, keyLen);

    (void) CRYPTO_uninitAsymmetricKey(&key, NULL);

    /* RSA stuff if non-null */
    if (NULL != pDerDigestInfo)
        (void) DIGI_MEMSET_FREE(&pDerDigestInfo, derDigestInfoLen);

    if (NULL != pDigestInfo)
        (void) TREE_DeleteTreeItem( (TreeItem*) pDigestInfo);

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_DSA__        
    /* DSA stuff if non-null */
    if (NULL != pR)
        (void) DIGI_MEMSET_FREE(&pR, rLen);

    if (NULL != pS)
        (void) DIGI_MEMSET_FREE(&pS, sLen);
#endif

    return status;
}

/*------------------------------------------------------------------------------------*/

/* String of Data to be used in our examples */
static const char* gCMSSampleData =
    "Gallia est omnis divisa in partes tres, quarum unam incolunt Belgae, "
    "aliam Aquitani, tertiam qui ipsorum lingua Celtae, nostra Galli appellantur."
    "Hi omnes lingua, institutis, legibus inter se differunt. Gallos ab Aquitanis "
    "Garumna flumen, a Belgis Matrona et Sequana dividit. Horum omnium "
    "fortissimi sunt Belgae, propterea quod a cultu atque humanitate provinciae "
    "longissime absunt, minimeque ad eos mercatores saepe commeant atque ea quae "
    "ad effeminandos animos pertinent important, proximique sunt Germanis, "
    "qui trans Rhenum incolunt, quibuscum continenter bellum gerunt. Qua de causa "
    "Helvetii quoque reliquos Gallos virtute praecedunt, quod fere cotidianis "
    "proeliis cum Germanis contendunt, cum aut suis finibus eos prohibent aut "
    "ipsi in eorum finibus bellum gerunt. Eorum una, pars, quam Gallos obtinere "
    "dictum est, initium capit a flumine Rhodano, continetur Garumna flumine, "
    "Oceano, finibus Belgarum, attingit etiam ab Sequanis et Helvetiis flumen "
    "Rhenum, vergit ad septentriones. Belgae ab extremis Galliae finibus "
    "oriuntur, pertinent ad inferiorem partem fluminis Rheni, spectant in "
    "septentrionem et orientem solem. Aquitania a Garumna flumine ad Pyrenaeos "
    "montes et eam partem Oceani quae est ad Hispaniam pertinet; spectat inter "
    "occasum solis et septentriones.";

/* We'll split input data into chunks for illustrative purposes. */
#define CMS_CHUNK_SIZE 256

/*------------------------------------------------------------------------------------*/

static MSTATUS crypto_interface_cms_create_signed_example(ubyte **ppOutput, ubyte4 *pOutLen)
{
    MSTATUS status = OK;

    /* Context and Signer, these are opaque pointers */
    CMS_signedDataContext myCtx = NULL;
    CMS_signerInfo mySigner = NULL;

    /* Input parameters */
    ubyte4 inLen = DIGI_STRLEN(gCMSSampleData);
    ubyte* pCert = NULL;
    ubyte4 certLen = 0;
    ubyte* pKey = NULL;
    ubyte4 keyLen = 0;
    AsymmetricKey key = {0};
    
    /* Output parameters */

    /* Each call to CMS_signedUpdateContext allocates a buffer. For
       illustrative purposes we will make 3 calls and use 3 copies
       of the OutBufferInfo structure defined above */
    OutBufferInfo pOutBuffers[3] = {0};
    
    /* Buffer where the final output will be copied */
    ubyte *pOutput = NULL;
    ubyte4 totalOutLen = 0;

    /* Read in the certificate and key from files. The certificate
       must be in DER form for the following APIs. The key may
       be in DER, PEM or Mocana Key Blob format. */
    status = DIGICERT_readFile("cert.der", &pCert, &certLen);
    if (OK != status)
        goto exit;  

    status = DIGICERT_readFile("key.der", &pKey, &keyLen);
    if (OK != status)
        goto exit;

    /* deserialize the key into an AsymmetricKey structure */
    status = CRYPTO_initAsymmetricKey( &key);
    if (OK != status)
        goto exit;

    status = CRYPTO_deserializeAsymKey(pKey, keyLen, NULL, &key);
    if (OK != status)
        goto exit;
    
    /* Initiate a context for pkcs7 data and a non-detached signature. We provide
       random entropy through the RANDOM_rngFun and g_pRandomContext (initialized
       via DIGICERT_initDigicert which has been called previously). */
    status = CMS_signedNewContext( &myCtx,
                                   pkcs7_data_OID, /* payload type OID */
                                   FALSE,          /* detached */
                                   RANDOM_rngFun, 
                                   g_pRandomContext);
    if (OK != status)
        goto exit;     

    /* add the certificate for signer explicitly */
    status = CMS_signedAddCertificate( myCtx, pCert, certLen);
    if (OK != status)
        goto exit;

    /* add a signer for this cert/key pair with sha1 digest. 
       This API may be called multiple times to add multiple signers. */
    status = CMS_signedAddSigner( myCtx, pCert, certLen, &key, sha1_OID, 0 /*flags*/, &mySigner);
    if (OK != status)
        goto exit;
    
    /* add an authenticated attribute to the signer */
    status = CMS_signedAddSignerAttribute( myCtx, mySigner, pkcs9_emailAddress_OID,
                                           PRINTABLESTRING, /* content type of the attribute */
                                           (const ubyte*) "nobody@mocana.com",
                                           17,    /* string length of nobody@mocana.com */
                                           TRUE); /* authenticated */
    if (OK != status)
        goto exit;

    /* update the context with two chunks and then the remaining bytes */
    status = CMS_signedUpdateContext(myCtx, gCMSSampleData, CMS_CHUNK_SIZE,
                                     &pOutBuffers[0].pBuffer, &pOutBuffers[0].bufferLen, FALSE);
    if (OK != status)
        goto exit;

    status = CMS_signedUpdateContext(myCtx, gCMSSampleData + CMS_CHUNK_SIZE, CMS_CHUNK_SIZE,
                                     &pOutBuffers[1].pBuffer, &pOutBuffers[1].bufferLen, FALSE);
    if (OK != status)
        goto exit;    

    status = CMS_signedUpdateContext(myCtx, gCMSSampleData + 2*CMS_CHUNK_SIZE, inLen - CMS_CHUNK_SIZE,
                                     &pOutBuffers[2].pBuffer, &pOutBuffers[2].bufferLen, TRUE);
    if (OK != status)
        goto exit;

    /* consolidate everything into a single buffer that can be output */
    totalOutLen = pOutBuffers[0].bufferLen + pOutBuffers[1].bufferLen + pOutBuffers[2].bufferLen;
    status = DIGI_MALLOC((void **) &pOutput, totalOutLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pOutput, pOutBuffers[0].pBuffer, pOutBuffers[0].bufferLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pOutput + pOutBuffers[0].bufferLen, 
                        pOutBuffers[1].pBuffer, pOutBuffers[1].bufferLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pOutput + pOutBuffers[0].bufferLen + pOutBuffers[1].bufferLen, 
                        pOutBuffers[2].pBuffer, pOutBuffers[2].bufferLen);
    if (OK != status)
        goto exit;

    /* transfer the output buffer */
    *ppOutput = pOutput; pOutput = NULL;
    *pOutLen = totalOutLen;

exit:

    /* cleanup */
    if (NULL != pOutput)
        (void) DIGI_FREE((void **) &pOutput);

    if (NULL != pOutBuffers[0].pBuffer)
        (void) DIGI_FREE((void **) &pOutBuffers[0].pBuffer);

    if (NULL != pOutBuffers[1].pBuffer)
        (void) DIGI_FREE((void **) &pOutBuffers[1].pBuffer);

    if (NULL != pOutBuffers[2].pBuffer)
        (void) DIGI_FREE((void **) &pOutBuffers[2].pBuffer);
 
    if (NULL != pCert)
        (void) DIGI_FREE((void **)&pCert);

    if (NULL != pKey)
        (void) DIGI_MEMSET_FREE(&pKey, keyLen); /* make sure to zero out sensitive data */

    /* mySigner will be also deleted/freed as part of CMS_signedDeleteContext */
    (void) CMS_signedDeleteContext(&myCtx);
    (void) CRYPTO_uninitAsymmetricKey( &key, NULL);  

    return status;
}

/*------------------------------------------------------------------------------------*/

static MSTATUS crypto_interface_cms_create_signed_w_callback_example(ubyte **ppOutput, ubyte4 *pOutLen)
{
    MSTATUS status = OK;

    /* Context and Signer, these are opaque pointers */
    CMS_signedDataContext myCtx = NULL;
    CMS_signerInfo mySigner = NULL;

    /* Input parameters */
    ubyte4 inLen = DIGI_STRLEN(gCMSSampleData);
    ubyte* pCert = NULL;
    ubyte4 certLen = 0;
    
    /* Output parameters */

    /* Each call to CMS_signedUpdateContext allocates a buffer. For
       illustrative purposes we will make 3 calls and use 3 copies
       of the OutBufferInfo structure defined above */
    OutBufferInfo pOutBuffers[3] = {0};
    
    /* Buffer where the final output will be copied */
    ubyte *pOutput = NULL;
    ubyte4 totalOutLen = 0;

    /* Read in the certificate from the file. The certificate
       must be in DER form for the following APIs. */
    status = DIGICERT_readFile("cert.der", &pCert, &certLen);
    if (OK != status)
        goto exit;  
    
    /* Initiate a context for pkcs7 data and a non-detached signature. We provide
       random entropy through the RANDOM_rngFun and g_pRandomContext (initialized
       via DIGICERT_initDigicert which has been called previously). */
    status = CMS_signedNewContext( &myCtx, 
                                   pkcs7_data_OID, /* payload type OID */
                                   FALSE,          /* detached */
                                   RANDOM_rngFun, 
                                   g_pRandomContext);
    if (OK != status)
        goto exit;     

    /* add the certificate for signer explicitly */
    status = CMS_signedAddCertificate( myCtx, pCert, certLen);
    if (OK != status)
        goto exit;

    /* add a signer for this cert/key pair with sha1 digest. Here
       we don't have a key so we provide the callback method that will
       actually do the signing. We give the key name as the callback arg.
       This API may be called multiple times to add multiple signers. */
    status = CMS_signedAddSignerWithCallback(myCtx, pCert, certLen,
                                             mySignFun, (void *) "key.der",
                                             sha1_OID, 0 /*flags*/, &mySigner);
    if (OK != status)
        goto exit;
    
    /* add an authenticated attribute to the signer */
    status = CMS_signedAddSignerAttribute( myCtx, mySigner, pkcs9_emailAddress_OID,
                                           PRINTABLESTRING, /* content type of the attribute */
                                           (const ubyte*) "nobody@mocana.com",
                                           17,    /* string length of nobody@mocana.com */
                                           TRUE); /* authenticated */
    if (OK != status)
        goto exit;

    /* update the context with two chunks and then the remaining bytes */
    status = CMS_signedUpdateContext(myCtx, gCMSSampleData, CMS_CHUNK_SIZE,
                                     &pOutBuffers[0].pBuffer, &pOutBuffers[0].bufferLen, FALSE);
    if (OK != status)
        goto exit;

    status = CMS_signedUpdateContext(myCtx, gCMSSampleData + CMS_CHUNK_SIZE, CMS_CHUNK_SIZE,
                                     &pOutBuffers[1].pBuffer, &pOutBuffers[1].bufferLen, FALSE);
    if (OK != status)
        goto exit;    

    status = CMS_signedUpdateContext(myCtx, gCMSSampleData + 2*CMS_CHUNK_SIZE, inLen - CMS_CHUNK_SIZE,
                                     &pOutBuffers[2].pBuffer, &pOutBuffers[2].bufferLen, TRUE);
    if (OK != status)
        goto exit;

    /* consolidate everything into a single buffer that can be output */
    totalOutLen = pOutBuffers[0].bufferLen + pOutBuffers[1].bufferLen + pOutBuffers[2].bufferLen;
    status = DIGI_MALLOC((void **) &pOutput, totalOutLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pOutput, pOutBuffers[0].pBuffer, pOutBuffers[0].bufferLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pOutput + pOutBuffers[0].bufferLen, 
                        pOutBuffers[1].pBuffer, pOutBuffers[1].bufferLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pOutput + pOutBuffers[0].bufferLen + pOutBuffers[1].bufferLen, 
                        pOutBuffers[2].pBuffer, pOutBuffers[2].bufferLen);
    if (OK != status)
        goto exit;

    /* transfer the output buffer */
    *ppOutput = pOutput; pOutput = NULL;
    *pOutLen = totalOutLen;

exit:

    /* cleanup */
    if (NULL != pOutput)
        (void) DIGI_FREE((void **) &pOutput);

    if (NULL != pOutBuffers[0].pBuffer)
        (void) DIGI_FREE((void **) &pOutBuffers[0].pBuffer);

    if (NULL != pOutBuffers[1].pBuffer)
        (void) DIGI_FREE((void **) &pOutBuffers[1].pBuffer);

    if (NULL != pOutBuffers[2].pBuffer)
        (void) DIGI_FREE((void **) &pOutBuffers[2].pBuffer);
 
    if (NULL != pCert)
        (void) DIGI_FREE((void **)&pCert);

    /* mySigner will be also deleted/freed as part of CMS_signedDeleteContext */
    (void) CMS_signedDeleteContext(&myCtx);

    return status;
}

/*------------------------------------------------------------------------------------*/

static MSTATUS crypto_interface_cms_read_signed_example(ubyte *pInput, ubyte4 inputLen)
{
    MSTATUS status = OK;

    /* Context (an opaque pointer) and callback structure */
    CMS_context myCtx = NULL;
    CMS_Callbacks myCb = {0};

    /* input parameters */
    ubyte4 inOffset = 0;
    ubyte4 chunkSize = CMS_CHUNK_SIZE;

    /* Buffer to hold the recovered data and each chunk of output */
    ubyte* pRecData = NULL;
    ubyte* pOutput = NULL;
    ubyte4 outputLen = 0;
    ubyte4 totalOutLen = 0;
    intBoolean done = FALSE;

    /* for validation of the correctness of the output */
    ubyte *ecType = 0;
    byteBoolean validType = FALSE;
    sbyte4 numSigners = 0;
    sbyte4 cmp = -1;

    /* set the callbacks */
    myCb.getCertFun = myGetCertFun;
    myCb.valCertFun = myValCertFun;
    myCb.getPrivKeyFun = NULL; /* not needed, there's no private key for validating signed data */

    /* Create a context. We pass the certificate name as the callback argument */
    status = CMS_newContext( &myCtx, (void *) "cert.der", &myCb);
    if (OK != status)
        goto exit;

    /* We don't know the length of the total output but we do know it'll be less than the input */
    status = DIGI_MALLOC((void **) &pRecData, inputLen);
    if (OK != status)
        goto exit;

    /* We'll pretend we don't know the number of update calls needed and will loop until done=TRUE */
    do
    {
        /* if remaining input is less than chunkSize, decrease the chunkSize */
        if (inputLen - inOffset < chunkSize)
            chunkSize = inputLen - inOffset;

        /* update the context with data, this may or may allocated and provide output data */
        status = CMS_updateContext( myCtx, pInput + inOffset, chunkSize, &pOutput, &outputLen, &done);
        if (OK != status)
            goto exit;

        /* If we get output data start copying and validating */
        if (NULL != pOutput)
        {
            /* copy, ok to ignore DIGI_MEMCPY return code since buffers
               are already checked to non-NULL */
            (void) DIGI_MEMCPY(pRecData + totalOutLen, pOutput, outputLen);
            totalOutLen += outputLen;

            /* done now with pOutput, free (and zero if sensitive) to ensure no mem-leak */
            (void) DIGI_MEMSET_FREE(&pOutput, outputLen);
        
            /* First time we have some output we can validate it is the pkcs7_data_OID */
            if (!validType)
            {
                status = CMS_getEncapContentType(myCtx, &ecType);
                if (OK != status)
                    goto exit;

                if( TRUE == EqualOID( ecType, pkcs7_data_OID) )
                {
                    validType = TRUE;
                }
                else
                {
                    status = ERR_FALSE;
                }

                /* free irregardless of status so there is no mem-leak */
                (void) DIGI_FREE((void **) &ecType);

                if (OK != status)
                    goto exit;
            }
        }
        inOffset += chunkSize;
    }
    while (FALSE == done); /* already exited loop on bad status */

    /* We can get the number of signers to validate that */
    status = CMS_getNumSigners(myCtx, &numSigners);
    if (OK != status)
        goto exit;

    /* validate it was only 1 */
    if (1 != numSigners)
    {
        status = ERR_FALSE;
        goto exit;
    }

    /* And for illustrative purposes, we validate the data recovered is the original.
       Note the recovered data has more information than just the sample data. It begins
       with the sample data so we can just compare that. */
    status = DIGI_MEMCMP(pRecData, gCMSSampleData, DIGI_STRLEN(gCMSSampleData), &cmp);
    if (OK != status)
        goto exit;

    if (cmp)
    {
        status = ERR_FALSE;
    }

exit:

    if (NULL != pRecData)
        (void) DIGI_MEMSET_FREE(&pRecData, totalOutLen);

    /* cleanup */
    (void) CMS_deleteContext(&myCtx);
    
    return status;
}

/*------------------------------------------------------------------------------------*/

static MSTATUS crypto_interface_cms_create_enveloped_example(ubyte **ppOutput, ubyte4 *pOutLen)
{
    MSTATUS status = OK;

    /* Context, an opaque pointer */
    CMS_envelopedDataContext myCtx = NULL;

    /* Input parameters */
    ubyte4 inLen = DIGI_STRLEN(gCMSSampleData);
    ubyte* pCert = NULL;
    ubyte4 certLen = 0;
    
    /* Output parameters */

    /* Each call to CMS_envelopedUpdateContext allocates a buffer. For
       illustrative purposes we will make 3 calls and use 3 copies
       of the OutBufferInfo structure defined above */
    OutBufferInfo pOutBuffers[3] = {0};
    
    /* Buffer where the final output will be copied */
    ubyte *pOutput = NULL;
    ubyte4 totalOutLen = 0;

    /* Read in the certificate. The certificate
       must be in DER form for the following APIs. */
    status = DIGICERT_readFile("cert.der", &pCert, &certLen);
    if (OK != status)
        goto exit;  
    
    /* Initiate a context for aes128cbc encryption. We provide
       random entropy through the RANDOM_rngFun and g_pRandomContext (initialized
       via DIGICERT_initDigicert which has been called previously). */
    status = CMS_envelopedNewContext(&myCtx, aes128CBC_OID, RANDOM_rngFun, g_pRandomContext);
    if (OK != status)
        goto exit;

    /* Add the recipient's certificate */
    status = CMS_envelopedAddRecipient( myCtx, pCert, certLen);
    if (OK != status)
        goto exit;

    /* update the context with two chunks and then the remaining bytes */
    status = CMS_envelopedUpdateContext(myCtx, gCMSSampleData, CMS_CHUNK_SIZE,
                                        &pOutBuffers[0].pBuffer, &pOutBuffers[0].bufferLen, FALSE);
    if (OK != status)
        goto exit;

    status = CMS_envelopedUpdateContext(myCtx, gCMSSampleData + CMS_CHUNK_SIZE, CMS_CHUNK_SIZE,
                                        &pOutBuffers[1].pBuffer, &pOutBuffers[1].bufferLen, FALSE);
    if (OK != status)
        goto exit;    

    status = CMS_envelopedUpdateContext(myCtx, gCMSSampleData + 2*CMS_CHUNK_SIZE, inLen - CMS_CHUNK_SIZE,
                                        &pOutBuffers[2].pBuffer, &pOutBuffers[2].bufferLen, TRUE);
    if (OK != status)
        goto exit;

    /* consolidate everything into a single buffer that can be output */
    totalOutLen = pOutBuffers[0].bufferLen + pOutBuffers[1].bufferLen + pOutBuffers[2].bufferLen;
    status = DIGI_MALLOC((void **) &pOutput, totalOutLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pOutput, pOutBuffers[0].pBuffer, pOutBuffers[0].bufferLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pOutput + pOutBuffers[0].bufferLen, 
                        pOutBuffers[1].pBuffer, pOutBuffers[1].bufferLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pOutput + pOutBuffers[0].bufferLen + pOutBuffers[1].bufferLen, 
                        pOutBuffers[2].pBuffer, pOutBuffers[2].bufferLen);
    if (OK != status)
        goto exit;

    /* transfer the output buffer */
    *ppOutput = pOutput; pOutput = NULL;
    *pOutLen = totalOutLen;

exit:

    /* cleanup */
    if (NULL != pOutput)
        (void) DIGI_FREE((void **) &pOutput);

    if (NULL != pOutBuffers[0].pBuffer)
        (void) DIGI_FREE((void **) &pOutBuffers[0].pBuffer);

    if (NULL != pOutBuffers[1].pBuffer)
        (void) DIGI_FREE((void **) &pOutBuffers[1].pBuffer);

    if (NULL != pOutBuffers[2].pBuffer)
        (void) DIGI_FREE((void **) &pOutBuffers[2].pBuffer);
 
    if (NULL != pCert)
        (void) DIGI_FREE((void **)&pCert);

    (void) CMS_envelopedDeleteContext(&myCtx);

    return status;
}

/*------------------------------------------------------------------------------------*/

static MSTATUS crypto_interface_cms_read_enveloped_example(ubyte *pInput, ubyte4 inputLen)
{
    MSTATUS status = OK;

    /* Context (an opaque pointer) and callback structure */
    CMS_context myCtx = NULL;
    CMS_Callbacks myCb = {0};

    /* input parameters */
    ubyte4 inOffset = 0;
    ubyte4 chunkSize = CMS_CHUNK_SIZE;

    /* Buffer to hold the recovered data and each chunk of output */
    ubyte* pRecData = NULL;
    ubyte* pOutput = NULL;
    ubyte4 outputLen = 0;
    ubyte4 totalOutLen = 0;
    intBoolean done = FALSE;

    /* for validation of the correctness of the output */
    ubyte *ecType = 0;
    byteBoolean validType = FALSE;
    sbyte4 cmp = -1;
    ubyte4 numRecipients = 0;
    ubyte* pEncryptionAlgoOID = NULL;

    /* set the callbacks */
    myCb.getCertFun = NULL; /* not needed for decrypt enveloped */
    myCb.valCertFun = NULL; /* not needed for decrypt enveloped */
    myCb.getPrivKeyFun = myGetPrivKeyFun;

    /* Create a context. We pass the certificate name as the callback argument */
    status = CMS_newContext( &myCtx, NULL, &myCb);
    if (OK != status)
        goto exit;

    /* We don't know the length of the total output but we do know it'll be less than the input */
    status = DIGI_MALLOC((void **) &pRecData, inputLen);
    if (OK != status)
        goto exit;

    /* We'll pretend we on't know the number of update calls needed and will loop until done=TRUE */
    do
    {
        /* if remaining input is less than chunkSize, decrease the chunkSize */
        if (inputLen - inOffset < chunkSize)
            chunkSize = inputLen - inOffset;

        /* update the context with data, this may or may allocated and provide output data */
        status = CMS_updateContext( myCtx, pInput + inOffset, chunkSize, &pOutput, &outputLen, &done);
        if (OK != status)
            goto exit;

        /* If we get output data start copying and validating */
        if (NULL != pOutput)
        {
            /* copy, ok to ignore DIGI_MEMCPY return code since buffers
               are already checked to non-NULL */
            (void) DIGI_MEMCPY(pRecData + totalOutLen, pOutput, outputLen);
            totalOutLen += outputLen;

            /* done now with pOutput, free (and zero if sensitive) to ensure no mem-leak */
            (void) DIGI_MEMSET_FREE(&pOutput, outputLen);
        
            /* First time we have some output we can validate it is the pkcs7_data_OID */
            if (!validType)
            {
                status = CMS_getEncapContentType(myCtx, &ecType);
                if (OK != status)
                    goto exit;

                if( TRUE == EqualOID( ecType, pkcs7_data_OID) )
                {
                    validType = TRUE;
                }
                else
                {
                    status = ERR_FALSE;
                }

                /* free irregardless of status so there is no mem-leak */
                (void) DIGI_FREE((void **) &ecType);

                if (OK != status)
                    goto exit;
            }
        }
        inOffset += chunkSize;
    }
    while (FALSE == done); /* already exited loop on bad status */

    /* We can get the number of recipients to validate that */
    status = CMS_getNumRecipients(myCtx, &numRecipients);
    if (OK != status)
        goto exit;

    /* validate it was only 1 */
    if (1 != numRecipients)
    {
        status = ERR_FALSE;
        goto exit;
    }

    /* We can validate the encryption algo */
    status = CMS_getEncryptionAlgo( myCtx, &pEncryptionAlgoOID);
    if (OK != status)
        goto exit;

    if (TRUE != EqualOID( aes128CBC_OID, pEncryptionAlgoOID))
    {
        status = ERR_FALSE;
        goto exit;
    }

    /* And for illustrative purposes, we validate the data recovered is the original.
       Note the recovered data has more information than just the sample data. It begins
       with the sample data so we can just compare that. */
    status = DIGI_MEMCMP(pRecData, gCMSSampleData, DIGI_STRLEN(gCMSSampleData), &cmp);
    if (OK != status)
        goto exit;

    if (cmp)
    {
        status = ERR_FALSE;
    }

exit:

    /* cleanup */
    if (NULL != pRecData)
        (void) DIGI_MEMSET_FREE(&pRecData, totalOutLen);

    if (NULL != pEncryptionAlgoOID)
        (void) DIGI_FREE((void **) &pEncryptionAlgoOID);

    (void) CMS_deleteContext(&myCtx);
    
    return status;
}

/*------------------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS crypto_interface_cms_example()
{
    MSTATUS status = OK;

    /* Buffer to hold the resulting signed or enveloped data */
    ubyte *pResult = NULL;
    ubyte4 resultLen = 0;

    status = crypto_interface_cms_create_signed_example(&pResult, &resultLen);
    if (OK != status)
        goto exit;

    status = crypto_interface_cms_read_signed_example(pResult, resultLen);
    if (OK != status)
        goto exit;

    /* clean and re-use the pResult buffer for further examples */
    status = DIGI_MEMSET_FREE(&pResult, resultLen);
    if (OK != status)
        goto exit;

    resultLen = 0;    

    status = crypto_interface_cms_create_signed_w_callback_example(&pResult, &resultLen);
    if (OK != status)
        goto exit;

    status = crypto_interface_cms_read_signed_example(pResult, resultLen);
    if (OK != status)
        goto exit;

    /* clean and re-use the pResult buffer for further examples */
    status = DIGI_MEMSET_FREE(&pResult, resultLen);
    if (OK != status)
        goto exit;

    status = crypto_interface_cms_create_enveloped_example(&pResult, &resultLen);
    if (OK != status)
        goto exit;

    status = crypto_interface_cms_read_enveloped_example(pResult, resultLen);
    if (OK != status)
        goto exit;

exit:

    if (NULL != pResult)
        (void) DIGI_MEMSET_FREE(&pResult, resultLen);

    return status;
}
