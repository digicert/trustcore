/*
 * crypto_interface_moccms_streaming_example.c
 *
 * Crypto Interface MOCCMS Streaming Example Code
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
#include "../../crypto/moccms.h"

/* For our signing callback example we need actual crypto code */
#include "../../crypto/rsa.h"
#include "../../crypto/dsa.h"
#include "../../crypto/primeec.h"
#include "../../crypto_interface/crypto_interface_rsa.h"
#include "../../crypto_interface/crypto_interface_dsa.h"
#include "../../crypto_interface/crypto_interface_ecc.h"

/* OID 2.16.840.1.101.3.4.2.1 */
static ubyte NIST_SHA256_OID[] =
{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };

/* Helper structure that can hold a buffer and its meta data */

typedef struct _OutBufferInfo
{
   ubyte *pBuf;
   ubyte4 bufUsed;
   ubyte4 bufMax;
   intBoolean done;

} OutBufferInfo;

/*------------------------------------------------------------------------------------*/

/* User defined callback that will be called to process the output data.
   Having a callback allows for the user to process it in chunks and does
   not require the entire output to be preserved in memory at once. However 
   for illustrative purposes we'll just copy the output to an OutBufferInfo. */
static MSTATUS myDataUpdateFun(const void* pArg,
                               MOC_CMS_context pCtx,
                               MOC_CMS_UpdateType type,
                               ubyte* pBuf,
                               ubyte4 bufLen)
{
    OutBufferInfo* pBufInfo = (OutBufferInfo*) pArg;

    /* copy any resulting data */
    if (NULL != pBuf && bufLen)
    {
        if (pBufInfo->bufMax > (pBufInfo->bufUsed + bufLen))
        {
            DIGI_MEMCPY(pBufInfo->pBuf + pBufInfo->bufUsed, pBuf, bufLen);
            pBufInfo->bufUsed += bufLen;
        }
        else
        {
            return ERR_BUFFER_TOO_SMALL;
        }
    }

    /* check if we are done */
    if (E_MOC_CMS_ut_final == type || E_MOC_CMS_ut_result == type)
    {
        pBufInfo->done = TRUE;
    }

    return OK;
}

/*------------------------------------------------------------------------------------*/

/* User defined callback that can obtain the certificate from the given input 
   In practice one would likely use the serial number and/or issuer to find 
   and match the certificate in the cert store. The parameter pArg is an
   optional pointer to a context. To keep things simple for this illustraion, 
   we'll just load cert.der directly.
*/
static MSTATUS myGetCertFun(const void* pArg,
                            ubyte* pSerialNumber,
                            ubyte4 serialNumberLen,
                            ubyte* pIssuer,
                            ubyte4 issuerLen,
                            ubyte** ppCertificate,
                            ubyte4* pCertificateLen)
{
    return DIGICERT_readFile("cert.der", ppCertificate, pCertificateLen);
}

/*------------------------------------------------------------------------------------*/

/* User defined callback that can validate a certificate. To keep things
   simple for this illustration, we'll just always return OK */
static MSTATUS myValCertFun(const void *pArg,
                            ubyte* pCertificate,
                            ubyte4 certificateLen,
                            MOC_CMS_MsgSignInfo *pSigInfo)
{
    return OK;
}

/*------------------------------------------------------------------------------------*/

/* User defined callback that will obtain the private key from the given input.
   This is for NO_TAG type. For type 1 use myGetPrivKeyFunEx */
static MSTATUS myGetPrivKeyFun(const void* pArg,
                               ubyte* pSerialNumber,
                               ubyte4 serialNumberLen,
                               ubyte* pIssuer,
                               ubyte4 issuerLen,
                               struct AsymmetricKey* pKey)
{
    MSTATUS status = OK;
    ubyte *pSerKey = NULL;
    ubyte4 keyLen = 0;

    /* In practice we would use the serial number and issuer 
       to search for the appropriate cert and key pair.
       For simplicity though we already know the key is key.der. */

    /* read in the key associated with the cert */
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

    return status;
}

/*------------------------------------------------------------------------------------*/

/* User defined callback that will obtain the private key from the given input. */
static MSTATUS myGetPrivKeyFunEx(const void* pArg,
                                 const MOC_CMS_RecipientId* pRecipientId,
                                 struct AsymmetricKey* pKey)
{
    MSTATUS status = OK;
    ubyte *pSerKey = NULL;
    ubyte4 keyLen = 0;

    /* In practice we would use the recipientId as follows to get the
       issuer and serial number to search for the appropriate cert and 
       key pair. For simplicity though we already know the key is key.der.

    ubyte* pSerialNumber = NULL;
    ubyte4 serialNumberLen = 0;
    ubyte* pIssuer = NULL;
    ubyte4 issuerLen = 0;

    switch (pRecipientId->type)
    {
    case NO_TAG:
        if (NO_TAG == pRecipientId->ri.ktrid.type)
        {
            pIssuer = pRecipientId->ri.ktrid.u.issuerAndSerialNumber.pIssuer;
            issuerLen = pRecipientId->ri.ktrid.u.issuerAndSerialNumber.issuerLen;
            pSerialNumber = pRecipientId->ri.ktrid.u.issuerAndSerialNumber.pSerialNumber;
            serialNumberLen = pRecipientId->ri.ktrid.u.issuerAndSerialNumber.serialNumberLen;
        }
        else
        {
            status = ERR_FALSE;
        }
        break;

    case 1:
        if (NO_TAG == pRecipientId->ri.karid.type)
        {
            pIssuer = pRecipientId->ri.karid.u.issuerAndSerialNumber.pIssuer;
            issuerLen = pRecipientId->ri.karid.u.issuerAndSerialNumber.issuerLen;
            pSerialNumber = pRecipientId->ri.karid.u.issuerAndSerialNumber.pSerialNumber;
            serialNumberLen = pRecipientId->ri.karid.u.issuerAndSerialNumber.serialNumberLen;
        }
        else
        {
            status = ERR_FALSE;
        }
        break;

    default:
        status = ERR_FALSE;
        goto exit;
    } 
    */

    /* read in the key associated with the cert */
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

static MSTATUS crypto_interface_moccms_create_signed_example(ubyte **ppOutput, ubyte4 *pOutLen)
{
    MSTATUS status = OK;

    /* Context, an opaque pointers */
    MOC_CMS_context ctx = NULL;
 
    /* Input parameters */
    ubyte4 inLen = DIGI_STRLEN(gCMSSampleData);
    ubyte* pCert = NULL;
    ubyte4 certLen = 0;
    ubyte* pKey = NULL;
    ubyte4 keyLen = 0;
    AsymmetricKey key = {0}; 

    /* Output buffer info*/
    OutBufferInfo bufInfo = {0};
    
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

    /* Setup the buffer for output data */
    status = DIGI_MALLOC((void **) &bufInfo.pBuf, 3072);
    if (OK != status)
        goto exit;

    bufInfo.bufMax = 3072;
    bufInfo.bufUsed = 0;
    bufInfo.done = FALSE;

    /* Create context for signing */
    status = DIGI_CMS_newContextOut (&ctx, E_MOC_CMS_ct_signedData,
                                    RANDOM_rngFun, g_pRandomContext,
                                    TRUE,  /* isStreaming */
                                    (void*) &bufInfo, &myDataUpdateFun);
    if (OK != status)
       goto exit;

    /* Set signer data */
    status = DIGI_CMS_addSigner (ctx, pCert, certLen, &key,
                                NIST_SHA256_OID,
                                sizeof(NIST_SHA256_OID),
                                E_MOC_CMS_sa_none,
                                NULL);  /* pSignId */
    if (OK != status)
       goto exit;

    /* Send Data in as many packets as neccessary, we'll illustrate by
       using 3 packets, this calls the callback to process the output data */
    status = DIGI_CMS_updateContextOut (ctx, gCMSSampleData, CMS_CHUNK_SIZE, FALSE /*last*/);
    if (OK != status)
       goto exit;

    status = DIGI_CMS_updateContextOut (ctx, gCMSSampleData + CMS_CHUNK_SIZE, CMS_CHUNK_SIZE, FALSE);
    if (OK != status)
       goto exit;

    status = DIGI_CMS_updateContextOut (ctx, gCMSSampleData + 2 * CMS_CHUNK_SIZE, 
                                       inLen - CMS_CHUNK_SIZE, TRUE);
    if (OK != status)
       goto exit;

    status = DIGI_CMS_finalizeContextOut (ctx);
    if (OK != status)
       goto exit;

    /* transfer the output buffer */
    if (FALSE == bufInfo.done || 0 == bufInfo.bufUsed)
    {
        status = ERR_INTERNAL_ERROR;
        goto exit;
    }

    *ppOutput = bufInfo.pBuf; bufInfo.pBuf = NULL;
    *pOutLen = bufInfo.bufUsed;

exit:

    /* cleanup */
    if (NULL != bufInfo.pBuf)
        (void) DIGI_FREE((void **) &bufInfo.pBuf);
 
    if (NULL != pCert)
        (void) DIGI_FREE((void **)&pCert);

    if (NULL != pKey)
        (void) DIGI_MEMSET_FREE(&pKey, keyLen); /* make sure to zero out sensitive data */

    /* mySigner will be also deleted/freed as part of CMS_signedDeleteContext */
    (void) DIGI_CMS_deleteContext(&ctx);
    (void) CRYPTO_uninitAsymmetricKey( &key, NULL);  

    return status;
}

/*------------------------------------------------------------------------------------*/

static MSTATUS crypto_interface_moccms_read_signed_example(ubyte *pInput, ubyte4 inputLen)
{
    MSTATUS status = OK;

    /* Context (an opaque pointer) and callback structure */
    MOC_CMS_context ctx = NULL;
    MOC_CMS_Callbacks cb = {0};

    /* input parameters */
    ubyte4 inOffset = 0;
    ubyte4 chunkSize = CMS_CHUNK_SIZE;

    /* Output buffer info*/
    OutBufferInfo bufInfo = {0};
    intBoolean done = FALSE;

    /* for validation of the correctness of the output */
    MOC_CMS_ContentType contentType = 0;
    sbyte4 numSigners = 0;
    MOC_CMS_MsgSignInfo signerInfo = {0};
    sbyte4 cmp = -1;

    /* set the callbacks */
    cb.getCertFun = &myGetCertFun;
    cb.dataUpdateFun = &myDataUpdateFun;
    cb.valCertFun = &myValCertFun;

    /* Setup the buffer for output data */
    status = DIGI_MALLOC((void **) &bufInfo.pBuf, 3072);
    if (OK != status)
        goto exit;

    bufInfo.bufMax = 3072;
    bufInfo.bufUsed = 0;
    bufInfo.done = FALSE;

    /* Create a new generic context */
    status = DIGI_CMS_newContext (&ctx, (void*) &bufInfo, &cb);
    if (OK != status)
        goto exit;

    /* We'll pretend we don't know the number of update calls needed and will loop until done=TRUE */
    do
    {
        /* if remaining input is less than chunkSize, decrease the chunkSize */
        if (inputLen - inOffset < chunkSize)
            chunkSize = inputLen - inOffset;

        /* update the context with data. This calls the data update callback to procees output */
        status = DIGI_CMS_updateContext(ctx, pInput + inOffset, chunkSize, &done);
        if (OK != status)
            goto exit;   
       
        inOffset += chunkSize;
    }
    while (FALSE == done); /* already exited loop on bad status */

    /* Check content type */
    status = DIGI_CMS_getContentType (ctx, &contentType);
    if (OK != status)
        goto exit;

    if (E_MOC_CMS_ct_signedData != contentType)
    {
        status = ERR_FALSE;
        goto exit;
    }

    /* Check the number of signers */
    status = DIGI_CMS_getNumSigners(ctx, &numSigners);
    if (OK != status)
        goto exit;

    if (1 != numSigners)
    {
        status = ERR_FALSE;
        goto exit;
    }

    /* Validate the signature for the signer, first get the signer info */
    status = DIGI_CMS_getSignerInfo (ctx, 0 /* signer index */, &signerInfo);
    if (OK != status)
        goto exit;

    if (TRUE != signerInfo.verifies)
    {
        status = ERR_FALSE;
        goto exit;
    }

    /* And for illustrative purposes, we validate the data recovered is the original.
       Note the recovered data has more information than just the sample data. It begins
       with the sample data so we can just compare that. */
    status = DIGI_MEMCMP(bufInfo.pBuf, gCMSSampleData, DIGI_STRLEN(gCMSSampleData), &cmp);
    if (OK != status)
        goto exit;

    if (cmp)
    {
        status = ERR_FALSE;
    }

exit:

    /* cleanup */
    if (NULL != bufInfo.pBuf)
        (void) DIGI_FREE((void **) &bufInfo.pBuf);

    (void) DIGI_CMS_deleteSignerInfo(&signerInfo);
    (void) DIGI_CMS_deleteContext(&ctx);

    return status;
}

/*------------------------------------------------------------------------------------*/

static MSTATUS crypto_interface_moccms_create_enveloped_example(ubyte **ppOutput, ubyte4 *pOutLen)
{
    MSTATUS status = OK;

    /* Context, an opaque pointer */
    MOC_CMS_context ctx = NULL;

    /* Input parameters */
    ubyte4 inLen = DIGI_STRLEN(gCMSSampleData);
    ubyte* pCert = NULL;
    ubyte4 certLen = 0;
    
    /* Output buffer info*/
    OutBufferInfo bufInfo = {0};
        
    /* Read in the certificate. The certificate
       must be in DER form for the following APIs. */
    status = DIGICERT_readFile("cert.der", &pCert, &certLen);
    if (OK != status)
        goto exit;
    
    /* Setup the buffer for output data */
    status = DIGI_MALLOC((void **) &bufInfo.pBuf, 3072);
    if (OK != status)
        goto exit;

    bufInfo.bufMax = 3072;
    bufInfo.bufUsed = 0;
    bufInfo.done = FALSE;

    /* Create context for envelope */
    status = DIGI_CMS_newContextOut (&ctx, E_MOC_CMS_ct_envelopedData,
                                    RANDOM_rngFun, g_pRandomContext,
                                    TRUE, /* isStreaming */
                                    (void*) &bufInfo, &myDataUpdateFun);
    if (OK != status)
        goto exit;

    /* Set the encryption algo */
    status = DIGI_CMS_setEncryption (ctx, aes128CBC_OID + 1, aes128CBC_OID[0],
                                    RANDOM_rngFun, g_pRandomContext);
    if (OK != status)
        goto exit;

    /* Add a single recipient */
    status = DIGI_CMS_addRecipient (ctx, pCert, certLen);
    if (OK != status)
        goto exit;

    /* Send Data in as many packets as neccessary, we'll illustrate by
       using 3 packets, this calls the callback to process the output data */
    status = DIGI_CMS_updateContextOut (ctx, gCMSSampleData, CMS_CHUNK_SIZE, FALSE /* last */);
    if (OK != status)
        goto exit;

    status = DIGI_CMS_updateContextOut (ctx, gCMSSampleData + CMS_CHUNK_SIZE, CMS_CHUNK_SIZE, FALSE);
    if (OK != status)
        goto exit;

    status = DIGI_CMS_updateContextOut (ctx, gCMSSampleData + 2 * CMS_CHUNK_SIZE, 
                                       inLen - CMS_CHUNK_SIZE, TRUE);
    if (OK != status)
        goto exit;

    status = DIGI_CMS_finalizeContextOut (ctx);
    if (OK != status)
        goto exit;

    /* transfer the output buffer */
    if (FALSE == bufInfo.done || 0 == bufInfo.bufUsed)
    {
        status = ERR_INTERNAL_ERROR;
        goto exit;
    }

    *ppOutput = bufInfo.pBuf; bufInfo.pBuf = NULL;
    *pOutLen = bufInfo.bufUsed;

exit:

    /* cleanup */
    if (NULL != bufInfo.pBuf)
        (void) DIGI_FREE((void **) &bufInfo.pBuf);
 
    if (NULL != pCert)
        (void) DIGI_FREE((void **)&pCert);

    (void) DIGI_CMS_deleteContext(&ctx);

    return status;
}

/*------------------------------------------------------------------------------------*/

static MSTATUS crypto_interface_moccms_read_enveloped_example(ubyte *pInput, ubyte4 inputLen)
{
    MSTATUS status = OK;

    /* Context (an opaque pointer) and callback structure */
    MOC_CMS_context ctx = NULL;
    MOC_CMS_Callbacks cb = {0};

    /* input parameters */
    ubyte4 inOffset = 0;
    ubyte4 chunkSize = CMS_CHUNK_SIZE;

    /* Output buffer info*/
    OutBufferInfo bufInfo = {0};
    intBoolean done = FALSE;

    /* for validation of the correctness of the output */
    MOC_CMS_ContentType contentType = 0;
    sbyte4 numRecipients = 0;
    MOC_CMS_RecipientId recInfo = {0};
    sbyte4 cmp = -1;

    /* set the callbacks */
    cb.dataUpdateFun = &myDataUpdateFun;
    cb.getPrivKeyFun = &myGetPrivKeyFun;
    cb.getPrivKeyFunEx = &myGetPrivKeyFunEx;

    /* Setup the buffer for output data */
    status = DIGI_MALLOC((void **) &bufInfo.pBuf, 3072);
    if (OK != status)
        goto exit;

    bufInfo.bufMax = 3072;
    bufInfo.bufUsed = 0;
    bufInfo.done = FALSE;

    /* Create a new generic context */
    status = DIGI_CMS_newContext (&ctx, (void*) &bufInfo, &cb);
    if (OK != status)
        goto exit;

    /* We'll pretend we don't know the number of update calls needed and will loop until done=TRUE */
    do
    {
        /* if remaining input is less than chunkSize, decrease the chunkSize */
        if (inputLen - inOffset < chunkSize)
            chunkSize = inputLen - inOffset;

        /* update the context with data. This calls the data update callback to procees output */
        status = DIGI_CMS_updateContext(ctx, pInput + inOffset, chunkSize, &done);
        if (OK != status)
            goto exit;   
       
        inOffset += chunkSize;
    }
    while (FALSE == done); /* already exited loop on bad status */

    /* Check content type */
    status = DIGI_CMS_getContentType (ctx, &contentType);
    if (OK != status)
        goto exit;

    if (E_MOC_CMS_ct_envelopedData != contentType)
    {
        status = ERR_FALSE;
        goto exit;
    }

    /* Check the number of recipients */
    status = DIGI_CMS_getNumRecipients(ctx, &numRecipients);
    if (OK != status)
        goto exit;
    
    if (1 != numRecipients)
    {
        status = ERR_FALSE;
        goto exit;
    }

    /* Obtain the recipient info if needbe */
    status = DIGI_CMS_getRecipientId (ctx, 0 /* idxRecipient */, &recInfo);
    if (OK != status)
        goto exit;
  
    /* And for illustrative purposes, we validate the data recovered is the original.
       Note the recovered data has more information than just the sample data. It begins
       with the sample data so we can just compare that. */
    status = DIGI_MEMCMP(bufInfo.pBuf, gCMSSampleData, DIGI_STRLEN(gCMSSampleData), &cmp);
    if (OK != status)
        goto exit;

    if (cmp)
    {
        status = ERR_FALSE;
    }

exit:
    
    /* cleanup */
    if (NULL != bufInfo.pBuf)
        (void) DIGI_FREE((void **) &bufInfo.pBuf);

    (void) DIGI_CMS_deleteRecipientId (&recInfo);
    (void) DIGI_CMS_deleteContext(&ctx);

    return status;
}

/*------------------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS crypto_interface_moccms_streaming_example()
{
    MSTATUS status = OK;
    
    /* Buffer to hold the resulting signed or enveloped data */
    ubyte *pResult = NULL;
    ubyte4 resultLen = 0;

    status = crypto_interface_moccms_create_signed_example(&pResult, &resultLen);
    if (OK != status)
        goto exit;

    status = crypto_interface_moccms_read_signed_example(pResult, resultLen);
    if (OK != status)
        goto exit;

    /* clean and re-use the pResult buffer for further examples */
    status = DIGI_MEMSET_FREE(&pResult, resultLen);
    if (OK != status)
        goto exit;

    status = crypto_interface_moccms_create_enveloped_example(&pResult, &resultLen);
    if (OK != status)
        goto exit;

    status = crypto_interface_moccms_read_enveloped_example(pResult, resultLen);
    if (OK != status)
        goto exit;

exit:

    if (NULL != pResult)
        (void) DIGI_MEMSET_FREE(&pResult, resultLen);

    return status;
}
