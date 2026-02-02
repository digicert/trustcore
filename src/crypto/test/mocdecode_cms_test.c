/*
 * mocdecode_cms_test.c
 *
 * CMS Decoder Unit Tests
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

#include "../../asn1/mocasn1.h"
#include "../../asn1/oiddefs.h"

#include "../../../unit_tests/unittest.h"

#include "../../common/absstream.h"
#include "../../common/datetime.h"
#include "../../common/memfile.h"
#include "../../common/mrtos.h"
#include "../../common/utils.h"

#include "../../crypto/aes.h"
#include "../../crypto/pubcrypto.h"
#include "../../crypto/ca_mgmt.h"
#include "../../crypto/pkcs_common.h"
#include "../../crypto/pkcs_key.h"
#include "../../crypto/pkcs7.h"
#include "../../crypto/cms.h"
#include "../../crypto/des.h"
#include "../../crypto/moccms.h"
#include "../../crypto/moccms_util.h"

#include "../../harness/harness.h"

#include <stdio.h>

/**************************************************************/

typedef struct
{
   ubyte* buf;
   ubyte4 bufUsed;
   ubyte4 bufMax;
   intBoolean done;
} internal_test;

typedef struct CertificateInfo
{
   const char* certFileName;
   const char* certKeyFileName;
} CertificateInfo;

/*********************************************************************************/

static CertificateInfo gCertificateInfos[] =
      {
            { "signer1cert.der", "signer1cert_key.dat" },
            { "signer2cert.der", "signer2cert_key.dat" },
            { "recipient1.der", "recipient1.key" },
            { "recipient2.der", "recipient2.key" },
            { "ecc_selfcert.der", "ecc_keyblobFile.dat" },
            { "dsa2048.crt.der", "dsa2048.crt.key" },
            { "rsa4096.crt.der", "rsa4096.key.dat" } ,
            { "cms_test_crt.der", "cms_test_key.der" } ,
            { "signer_rsa_crt.der", "signer_rsa_key.der" } ,
            { "expired_rsa_sign_cert.der", "expired_rsa_sign_key.der" } ,
      };

/*********************************************************************************/

static MSTATUS
internal_CMS_checkCertificateIssuerSerialNumber(
        ubyte* pIssuer,
        ubyte4 issuerLen,
        ubyte* pSerialNumber,
        ubyte4 serialNumberLen,
        ubyte *pCert,
        ubyte4 certLen);

static MSTATUS
filePrivateKeyCB(const void* arg,
                 ubyte* pSerialNumber,
                 ubyte4 serialNumberLen,
                 ubyte* pIssuer,
                 ubyte4 issuerLen,
                 struct AsymmetricKey* pKey);

static MSTATUS
dummyGetPrivateKeyFun(const void* arg,
                      const MOC_CMS_RecipientId* pRecipientId,
                      struct AsymmetricKey* pKey);

static MSTATUS
dummyCertificateCB(const void *arg,
                   ubyte* pSerialNumber,
                   ubyte4 serialNumberLen,
                   ubyte* pIssuer,
                   ubyte4 issuerLen,
                   ubyte **ppCertificate,
                   ubyte4 *pCertificateLen);

/*********************************************************************************/

static MSTATUS
internal_CMS_checkCertificateIssuerSerialNumber(
        ubyte* pIssuer,
        ubyte4 issuerLen,
        ubyte* pSerialNumber,
        ubyte4 serialNumberLen,
        ubyte* pCert,
        ubyte4 certLen)
{
    MSTATUS status;
    ubyte *pData;
    ubyte4 dataLen;

    status = DIGI_CMS_U_parseX509CertForSerialNumber(pCert, certLen,
                                                    &pData, &dataLen);
    if (OK != status)
        goto exit;

    if (dataLen != serialNumberLen)
    {
       status = ERR_FALSE;
    }
    else
    {
       sbyte4 cmpResult;
       status = DIGI_MEMCMP(pData, pSerialNumber, dataLen, &cmpResult);
       if (OK != status)
           goto exit;
       if (0 != cmpResult)
       {
          status = ERR_FALSE;
       }
    }

    /* Already failed? */
    if (OK != status)
        goto exit;

    status = DIGI_CMS_U_parseX509CertForIssuerName(pCert, certLen,
                                                  &pData, &dataLen);
    if (OK != status)
        goto exit;

    if (dataLen != issuerLen)
    {
       status = ERR_FALSE;
    }
    else
    {
       sbyte4 cmpResult;
       status = DIGI_MEMCMP(pData, pIssuer, dataLen, &cmpResult);
       if (OK != status)
           goto exit;
       if (0 != cmpResult)
       {
          status = ERR_FALSE;
       }
    }

exit:
    return status;
}


/*----------------------------------------------------------------------*/

static MSTATUS
dummyVerifyCert(const void* arg,
                ubyte* pCertificate,
                ubyte4 certificateLen,
                MOC_CMS_MsgSignInfo *pSigInfo)
{
    MSTATUS status = OK;

    return status;
}

/*----------------------------------------------------------------------*/

static MSTATUS
dummyVerifyCertSigningTime(const void* arg,
                ubyte* pCertificate,
                ubyte4 certificateLen,
                MOC_CMS_MsgSignInfo *pSigInfo)
{
    MSTATUS status;
    certDistinguishedName *pCertInfo = NULL;
    TimeDate certExpireTime;

    status = CA_MGMT_allocCertDistinguishedName(&pCertInfo);
    if (OK != status)
    {
        goto exit;
    }

    status = CA_MGMT_extractCertTimes(pCertificate, certificateLen, pCertInfo);
    if (OK != status)
    {
        goto exit;
    }

    status = DATETIME_convertFromValidityString(
        pCertInfo->pEndDate, &certExpireTime);
    if (OK != status)
    {
        goto exit;
    }

    /* Certificate expire time must be after signing time.
     */
    if (0 >= DIGI_cmpTimeDate(&certExpireTime, pSigInfo->pSigningTime))
    {
        status = ERR_CERT;
    }

exit:

    if (pCertInfo != NULL)
    {
        CA_MGMT_freeCertDistinguishedName(&pCertInfo);
    }

    return status;
}


/*----------------------------------------------------------------------*/

static MSTATUS
filePrivateKeyCB(const void* arg,
                 ubyte* pSerialNumber,
                 ubyte4 serialNumberLen,
                 ubyte* pIssuer,
                 ubyte4 issuerLen,
                 struct AsymmetricKey* pKey)
{
    MSTATUS status = OK;
    ubyte4 i;
    ubyte* pCert = NULL;
    intBoolean match = FALSE;
    ubyte4 certLen;

    for ( i = 0; i < COUNTOF( gCertificateInfos); ++i)
    {
       status = DIGICERT_readFile(gCertificateInfos[i].certFileName, &pCert, &certLen);
       if (OK != status)
           continue;

       /* Check the signer's certificate matches the Issuer name and Serial Number.
        * If yes, return the signer's certificate, otherwise continue looping for
        * the signer's certificate. */
       status = internal_CMS_checkCertificateIssuerSerialNumber( pIssuer,
                                                                 issuerLen,
                                                                 pSerialNumber,
                                                                 serialNumberLen,
                                                                 pCert,
                                                                 certLen);
       if (OK == status)
       {
          match = TRUE;
          break;
       }
       FREE(pCert);
       pCert = NULL;
    }

    if (match)
    {
        FREE(pCert);
        pCert = NULL;

        status = DIGICERT_readFile(gCertificateInfos[i].certKeyFileName, &pCert, &certLen);
        if (OK != status)
            goto exit;

        status = CA_MGMT_extractKeyBlobEx (pCert, certLen, pKey);
        if (OK != status)
        {
            status = PKCS_getPKCS1Key (MOC_HASH(hwAccelCtx) pCert, certLen, pKey);
            if (OK != status)
            {
                status = PKCS_getPKCS8Key (MOC_HASH(hwAccelCtx) pCert, certLen, pKey);
                if (OK != status)
                    goto exit;
            }
        }
    }

exit:
    if (pCert)
    {
       FREE(pCert);
    }
    return status;
}

static MSTATUS
dummyGetPrivateKeyFun(const void* arg,
                      const MOC_CMS_RecipientId* pRecipientId,
                      struct AsymmetricKey* pKey)
{
    MSTATUS status = OK;
    ubyte2 i;
    ubyte* pCert = NULL;
    ubyte4 certLen = 0;
    intBoolean match = FALSE;

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

    /* For any ID type that is not 'issuerAndSerial' use a hard-code path */
    if (ERR_FALSE == status)
    {
        status = DIGICERT_readFile("ecc_keyblobFile.dat", &pCert, &certLen);
        if (OK != status)
           goto exit;

        status = CA_MGMT_extractKeyBlobEx (pCert, certLen, pKey);
        if (OK != status)
        {
            status = PKCS_getPKCS1Key ( MOC_HASH(hwAccelCtx) pCert, certLen, pKey);
        }

        /* Found a valid key? */
        if (OK == status)
        {
            goto exit;
        }
    }

    for (i = 0; i < COUNTOF (gCertificateInfos); ++i)
    {
        if (NULL != pCert)
        {
            FREE (pCert);
            pCert = NULL;
        }

        /* Read the initial recipient key file */
        status = DIGICERT_readFile(gCertificateInfos[i].certFileName,
                                  &pCert, &certLen);
        if (OK != status)
           goto exit;

        status = internal_CMS_checkCertificateIssuerSerialNumber (pIssuer,
                                                                  issuerLen,
                                                                  pSerialNumber,
                                                                  serialNumberLen,
                                                                  pCert,
                                                                  certLen);

        /* Check the recipient certificate matches the Issuer name and Serial Number.
         * If yes, return the recipient's private key */
        if (OK == status)
        {
            match = TRUE;
            break;
        }
    }

    /* Check if recipient certificate was found, if yes, return the
     * recipient private key. */
    if (TRUE == match)
    {
        FREE (pCert);
        pCert = NULL;

        status = DIGICERT_readFile(gCertificateInfos[i].certKeyFileName, &pCert, &certLen);
        if (OK != status)
            goto exit;

        status = CA_MGMT_extractKeyBlobEx (pCert, certLen, pKey);
        if (OK != status)
        {
            status = PKCS_getPKCS1Key ( MOC_HASH(hwAccelCtx) pCert, certLen, pKey);
            if (OK != status)
                goto exit;
        }
    }

exit:
    if (pCert)
    {
        FREE(pCert);
    }
    return status;
}

static MSTATUS
dummyCertificateCB(const void* arg,
                   ubyte* pSerialNumber,
                   ubyte4 serialNumberLen,
                   ubyte* pIssuer,
                   ubyte4 issuerLen,
                   ubyte** ppCertificate,
                   ubyte4* pCertificateLen)
{
    MSTATUS status = ERR_FALSE;
    ubyte* pCert = NULL;
    ubyte4 certLen;
    intBoolean match = FALSE;
    ubyte4 i;

    for ( i = 0; i < COUNTOF (gCertificateInfos); ++i)
    {
        status = DIGICERT_readFile(gCertificateInfos[i].certFileName, &pCert, &certLen);
        if (OK != status)
            continue;

        status = internal_CMS_checkCertificateIssuerSerialNumber (pIssuer,
                                                                  issuerLen,
                                                                  pSerialNumber,
                                                                  serialNumberLen,
                                                                  pCert, certLen);

        /* Check the signer's certificate matches the Issuer name and Serial Number.
         * If yes, return the signer's certificate, otherwise continue looping for
         * the signer's certificate. */
        if (OK == status)
        {
            match = TRUE;
            break;
        }

        FREE (pCert);
        pCert = NULL;
    }

    if (TRUE == match)
    {
        *ppCertificate = pCert;
        *pCertificateLen = certLen;
        pCert = NULL;
    }

    if (NULL !=pCert)
    {
        FREE(pCert);
        pCert = NULL;
    }
    return status;
}

/***************************************************************************************/

static MSTATUS
internal_verifyCallback(const void* arg,
                        MOC_CMS_context pCtx,
                        MOC_CMS_UpdateType type,
                        ubyte* pBuf,
                        ubyte4 bufLen)
{
    internal_test* t = (internal_test*)arg;

    if (E_MOC_CMS_ut_result == type)
    {
        t->done = TRUE;
    }
    else if (NULL != pBuf)
    {
        if (t->bufMax > (t->bufUsed + bufLen))
        {
            DIGI_MEMCPY(t->buf + t->bufUsed, pBuf, bufLen);
            t->bufUsed += bufLen;
        }
        else
        {
            return ERR_FALSE;
        }
    }

    return OK;
}

static int
run_verifyChunkedSignedCMS(const char* fileName,
                           ubyte4 chunkSize,
                           ubyte4 expectSigners,
                           intBoolean expectFail)
{
   MSTATUS status;
   int retval = 0;
   ubyte* buf = NULL;
   ubyte4 copied = 0;
   intBoolean finished = 0;

   internal_test* t = NULL;
   sbyte4 numSigners = -1;

   ubyte* pCert = NULL;
   ubyte4 certLen;

   MOC_CMS_context     ctx = NULL;
   MOC_CMS_Callbacks   cb = { 0 };
   MOC_CMS_ContentType content_type;

   /* Read data from file */
   status = DIGICERT_readFile(fileName, &pCert, &certLen);
   retval += UNITTEST_STATUS(11, status);
   if (retval > 0)
      goto exit;

   t = MALLOC (sizeof(internal_test));
   t->bufUsed = 0;
   t->bufMax = certLen + 1;
   t->buf = MALLOC (t->bufMax);
   t->done = FALSE;

   cb.getCertFun = &dummyCertificateCB;
   cb.dataUpdateFun = &internal_verifyCallback;
   cb.valCertFun = &dummyVerifyCert;

   status = DIGI_CMS_newContext (&ctx,
                                (void*)t,
                                &cb);
   retval += UNITTEST_STATUS(10, status);
   if (retval > 0)
      goto exit;

   /* Read chunks and pass them into ASN1 parser for processing */
   buf = MALLOC(chunkSize);

   while ((FALSE == finished) && (certLen > copied))
   {
      ubyte4 newData;

      /* Copy next chunk or the final byte(s) */
      if (chunkSize < (certLen - copied))
      {
         newData = chunkSize;
      }
      else
      {
         newData = certLen - copied;
      }
      DIGI_MEMCPY (buf, pCert + copied, newData);

      /* Update parser */
      status = DIGI_CMS_updateContext (ctx,
                                      buf, newData,
                                      &finished);
      if ((TRUE == expectFail) &&
          (TRUE == finished))
      {
          retval += UNITTEST_INT (21, status, ERR_CERT_INVALID_SIGNATURE);
          if (retval > 0)
              goto exit;
      }
      else
      {
          retval += UNITTEST_STATUS (20, status);
          if (retval > 0)
              goto exit;
      }

      copied += newData;
   }

   /* Check final status */
   retval += UNITTEST_TRUE (50, finished);
   if (retval > 0)
      goto exit;

   /* Check content type */
   status = DIGI_CMS_getContentType (ctx,
                                    &content_type);
   retval += UNITTEST_STATUS (60, status);
   if (retval > 0)
      goto exit;

   retval += UNITTEST_INT (61, content_type, E_MOC_CMS_ct_signedData);
   if (retval > 0)
       goto exit;

   /* check size of callback buffer */
   retval += UNITTEST_TRUE (62, t->done);
   if (retval > 0)
       goto exit;

   retval += UNITTEST_TRUE (63, t->bufUsed > 0);
   if (retval > 0)
       goto exit;

   /* Check signature result */
   status = DIGI_CMS_getNumSigners(ctx, &numSigners);
   retval += UNITTEST_STATUS (70, status);
   if (retval > 0)
       goto exit;

   if (TRUE == expectFail)
   {
       retval += UNITTEST_INT (71, numSigners, 0);
   }
   else
   {
       ubyte4 i;

       retval += UNITTEST_INT (71, numSigners, expectSigners);
       if (retval > 0)
           goto exit;

      for (i = 0; i < numSigners; ++i)
      {
          MOC_CMS_MsgSignInfo info;

          status = DIGI_CMS_getSignerInfo (ctx, i, &info);
          retval += UNITTEST_STATUS (80 + i, status);
          if (retval > 0)
              goto exit;

          retval += UNITTEST_TRUE (90 + i, info.verifies);

          status = DIGI_CMS_deleteSignerInfo(&info);
          retval += UNITTEST_STATUS (81 + i, status);
          if (retval > 0)
              goto exit;
      }

      if (retval > 0)
          goto exit;

   }

exit:
   DIGI_CMS_deleteContext(&ctx);
   if (NULL != t)
   {
      FREE (t->buf);
      FREE (t);
   }
   if (NULL != buf)
   {
       FREE (buf);
   }
   if (NULL != pCert)
   {
      FREE (pCert);
   }
   return retval;
}

static int internal_verifyChunkedSignedCMS(ubyte4 chunkSize)
{
    int retval = 0;

#if 1
    retval += run_verifyChunkedSignedCMS ("NCRP_ummaker_s_sha256.cms", chunkSize, 2,
                                          FALSE);
    if (0 < retval)
    {
        printf("FAILED 'NCRP_ummaker_s_sha256.cms'\n");
    }
#endif
#if 1
    retval += run_verifyChunkedSignedCMS ("NCRP_ummaker_s_sha256.hacked", chunkSize, 2,
                                          TRUE);
    if (0 < retval)
    {
        printf("FAILED 'NCRP_ummaker_s_sha256.hacked'\n");
    }
#endif
#if 1
    retval += run_verifyChunkedSignedCMS ("test_data_s1.cms", chunkSize, 1,
                                          FALSE);
    if (0 < retval)
    {
        printf("FAILED 'test_data_s1.cms'\n");
    }
#endif
#if 1
    retval += run_verifyChunkedSignedCMS ("test_data_s2.cms", chunkSize, 1,
                                          FALSE);
    if (0 < retval)
    {
        printf("FAILED 'test_data_s2.cms'\n");
    }
#endif
#if 1
    retval += run_verifyChunkedSignedCMS ("test_data_s1.hacked", chunkSize, 1,
                                          TRUE);
    if (0 < retval)
    {
        printf("FAILED 'test_data_s1.hacked'\n");
    }
#endif
#if 1
    retval += run_verifyChunkedSignedCMS ("test_data_s2.hacked", chunkSize, 1,
                                          TRUE);
    if (0 < retval)
    {
        printf("FAILED 'test_data_s2.hacked'\n");
    }
#endif
#if 1
    retval += run_verifyChunkedSignedCMS ("openssl_certs_s2.cms", chunkSize, 1,
                                          FALSE);
    if (0 < retval)
    {
        printf("FAILED 'openssl_certs_s2.cms'\n");
    }
#endif

    return retval;
}

int mocdecode_cms_test_verifyChunkedSignedCMS()
{
    int retval = 0;
    ubyte4 cLen = 1;

    while (cLen < 1024)
    {
        retval += internal_verifyChunkedSignedCMS (cLen);
        if (retval > 0)
        {
            printf("Failed with chunk size: %d\n", cLen);
            goto exit;
        }
        cLen += 1;
    }

exit:
    return retval;
}

/******************************************************************/

static MSTATUS
internal_decodeCallback(const void* arg,
                        MOC_CMS_context pCtx,
                        MOC_CMS_UpdateType type,
                        ubyte* pBuf,
                        ubyte4 bufLen)
{
    internal_test* t = (internal_test*)arg;

    if (E_MOC_CMS_ut_result == type)
    {
        t->done = TRUE;
    }
    else if (NULL != pBuf)
    {
        if (t->bufMax > (t->bufUsed + bufLen))
        {
            DIGI_MEMCPY(t->buf + t->bufUsed, pBuf, bufLen);
            t->bufUsed += bufLen;
        }
        else
        {
            return ERR_FALSE;
        }
    }

    return OK;
}

static int
run_decodeChunkedEnvelopeCMS(const char* fileName,
                             const char* payloadName,
                             ubyte4 chunkSize,
                             intBoolean expectFail)
{
   MSTATUS status;
   int retval = 0;
   ubyte* buf = NULL;
   ubyte4 copied = 0;
   intBoolean finished = 0;

   internal_test* t = NULL;

   ubyte* pCert = NULL;
   ubyte4 certLen;
   ubyte* pText = NULL;
   ubyte4 textLen;
   sbyte4 i;
   sbyte4 cmpResult;
   sbyte4 numRecipients;

   MOC_CMS_context     ctx = NULL;
   MOC_CMS_Callbacks   cb = { 0 };
   MOC_CMS_ContentType content_type;

   /* Read data from file */
   status = DIGICERT_readFile(fileName, &pCert, &certLen);
   retval += UNITTEST_STATUS(11, status);
   if (retval > 0)
      goto exit;

   /* Compare clear text */
   status = DIGICERT_readFile(payloadName, &pText, &textLen);
   retval += UNITTEST_STATUS(80, status);
   if (retval > 0)
      goto exit;

   t = MALLOC (sizeof(internal_test));
   t->bufUsed = 0;
   t->bufMax = certLen + 1;
   t->buf = MALLOC (t->bufMax);
   t->done = FALSE;

   cb.getPrivKeyFun = &filePrivateKeyCB;
   cb.dataUpdateFun = &internal_decodeCallback;

   status = DIGI_CMS_newContext (&ctx,
                                (void*)t,
                                &cb);
   retval += UNITTEST_STATUS(10, status);
   if (retval > 0)
      goto exit;

   /* Read chunks and pass them into ASN1 parser for processing */
   buf = MALLOC(chunkSize);

   while ((FALSE == finished) && (certLen > copied))
   {
      ubyte4 newData;

      /* Copy next chunk or the final byte(s) */
      if (chunkSize < (certLen - copied))
      {
         newData = chunkSize;
      }
      else
      {
         newData = certLen - copied;
      }
      DIGI_MEMCPY (buf, pCert + copied, newData);

      /* Update parser */
      status = DIGI_CMS_updateContext (ctx,
                                      buf, newData,
                                      &finished);
      if ((TRUE == expectFail) &&
          (TRUE == finished))
      {
          retval += UNITTEST_TRUE (21, status < OK);
          if (retval > 0)
              goto exit;
      }
      else
      {
          retval += UNITTEST_STATUS (20 + (100*copied), status);
          if (retval > 0)
              goto exit;
      }

      copied += newData;
   }

   /* Check final status */
   retval += UNITTEST_TRUE (50, finished);
   if (retval > 0)
      goto exit;

   /* Check content type */
   status = DIGI_CMS_getContentType (ctx,
                                    &content_type);
   retval += UNITTEST_STATUS (60, status);
   if (retval > 0)
      goto exit;

   retval += UNITTEST_INT (61, content_type, E_MOC_CMS_ct_envelopedData);
   if (retval > 0)
       goto exit;

   /* Check recipient */
   status = DIGI_CMS_getNumRecipients(ctx,
                                     &numRecipients);
   retval += UNITTEST_STATUS (62, status);
   if (retval > 0)
      goto exit;

   for (i = 0; i < numRecipients; ++i)
   {
       MOC_CMS_RecipientId info;

       status = DIGI_CMS_getRecipientId (ctx, i, &info);
       retval += UNITTEST_STATUS (80 + i, status);
       if (retval > 0)
           goto exit;

       /* A KeyTransRecipient info */
       retval += UNITTEST_TRUE(81 + i, (info.type == NO_TAG));
       retval += UNITTEST_TRUE(81 + i, (info.ri.ktrid.type == NO_TAG));

       status = DIGI_CMS_deleteRecipientId (&info);
       retval += UNITTEST_STATUS (82 + i, status);
       if (retval > 0)
           goto exit;
   }

   /* check size of callback buffer */
   retval += UNITTEST_TRUE (70, t->done);
   if (retval > 0)
       goto exit;

   retval += UNITTEST_TRUE (71, t->bufUsed > 0);
   if (retval > 0)
       goto exit;

   retval += UNITTEST_INT (72, t->bufUsed, textLen);
   if (retval > 0)
      goto exit;

   status = DIGI_MEMCMP (t->buf, pText, textLen, &cmpResult);
   retval += UNITTEST_STATUS (73, status);
   if (retval > 0)
      goto exit;

   retval += UNITTEST_INT (74, cmpResult, 0);

exit:
   DIGI_CMS_deleteContext(&ctx);
   if (NULL != t)
   {
      FREE (t->buf);
      FREE (t);
   }
   if (NULL != buf)
   {
       FREE (buf);
   }
   if (NULL != pText)
   {
      FREE ( pText);
   }
   if (NULL != pCert)
   {
      FREE (pCert);
   }
   return retval;
}

static int
internal_decodeChunkedEnvelopeCMS(ubyte4 chunkSize)
{
    int retval = 0;

    retval += run_decodeChunkedEnvelopeCMS ("NCRP_ummaker_e_3DES.cms",
                                            "NCRP_ummaker_s_sha256.cms",
                                            chunkSize,
                                            FALSE);
#if 1
    retval += run_decodeChunkedEnvelopeCMS ("NCRP_ummaker_e_AES128.cms",
                                            "NCRP_ummaker_s_sha256.cms",
                                            chunkSize,
                                            FALSE);
#endif
#if 1
    retval += run_decodeChunkedEnvelopeCMS ("test_e.cms",
                                            "test_s.cms",
                                            chunkSize,
                                            FALSE);
#endif

    if (retval > 0)
    {
        printf("decodeCMS: Failed cs=%d\n", chunkSize);
    }
    return retval;
}

int mocdecode_cms_test_decodeChunkedEnvelopeCMS()
{
    int retval = 0;
    ubyte4 cLen = 1;

    while (cLen < 1024)
    {
        retval += internal_decodeChunkedEnvelopeCMS (cLen);
        if (retval > 0)
            goto exit;

        cLen += 1;
    }

exit:
    return retval;
}

/**************************************************************/

typedef struct chained
{
    MOC_CMS_ContentType contentType;
    ubyte*              tmp;
    ubyte4              tmpLen;
    /*---*/
    MOC_CMS_context     pChainedCtx;
    struct chained*     pChain;
    void*               pChainedArg;
} chained;

static MSTATUS
internal_chainedCallback(const void* arg,
                         MOC_CMS_context pCtx,
                         MOC_CMS_UpdateType type,
                         ubyte* pBuf,
                         ubyte4 bufLen);

/**************************************************************/

static MSTATUS
internal_processSigned(chained* pArg,
                       MOC_CMS_context pCtx,
                       MOC_CMS_UpdateType type,
                       ubyte* pBuf,
                       ubyte4 bufLen)
{
    MSTATUS status = OK;
    sbyte4 numSigners = 0;

    switch(type)
    {
    case E_MOC_CMS_ut_update:
    case E_MOC_CMS_ut_final:
        break;

    case E_MOC_CMS_ut_result:
        /* Check signature result */
        status = DIGI_CMS_getNumSigners(pCtx, &numSigners);
        if (OK != status)
            goto exit;

        if (numSigners == 0)
        {
            printf("SIGN: Failed signature check!\n");
        }
        else
        {
            printf("SIGN: Passed signature check!\n");
        }
        break;

    default:
        printf("SIGN(%d): %u [%d]\n", status, bufLen, type);
        status = ERR_INVALID_INPUT;
        break;
    }

    //printf("SIGN(%d): %u [%d]\n", status, bufLen, type);

exit:
    return status;
}

static MSTATUS
internal_processEnvelope(chained* pArg,
                         MOC_CMS_context pCtx,
                         MOC_CMS_UpdateType type,
                         ubyte* pBuf,
                         ubyte4 bufLen)
{
    MSTATUS status = OK;
    sbyte4 numRecipient = -1;
    intBoolean finished = FALSE;


    switch(type)
    {
    case E_MOC_CMS_ut_update:
    case E_MOC_CMS_ut_final:
        if (NULL == pArg->pChainedCtx)
        {
            MOC_CMS_Callbacks cb = { 0 };
            chained* t = NULL;

            cb.getCertFun = &dummyCertificateCB;
            cb.dataUpdateFun = &internal_chainedCallback;
            cb.valCertFun = &dummyVerifyCert;

            t = MALLOC (sizeof (chained));
            t->contentType = E_MOC_CMS_ct_undetermined;
            t->tmp = NULL;
            t->tmpLen = 0;
            t->pChainedCtx = NULL;
            t->pChain = NULL;
            pArg->pChainedArg = (void*)t;

            status = DIGI_CMS_newContext (&(pArg->pChainedCtx),
                                         (void*)t,
                                         &cb);
            if (OK != status)
               goto exit;
        }

        if (bufLen > 0)
        {
            /* Update parser */
            status = DIGI_CMS_updateContext (pArg->pChainedCtx,
                                            pBuf,
                                            bufLen,
                                            &finished);
        }
        break;

    case E_MOC_CMS_ut_result:
        /* Check recipients */
        status = DIGI_CMS_getNumRecipients(pCtx, &numRecipient);
        if (OK != status)
            goto exit;

        if (NULL != pArg->pChain)
        {
            /* clean up if there was stored data */
            if (pArg->pChain->tmp)
            {
                FREE (pArg->pChain->tmp);
                pArg->pChain->tmp = NULL;
                pArg->pChain->tmpLen = 0;
            }
            FREE (pArg->pChain);
        }

        if (NULL != pArg->pChainedCtx)
        {
            DIGI_CMS_deleteContext (&pArg->pChainedCtx);
        }
        if (NULL != pArg->pChainedArg)
        {
            FREE (pArg->pChainedArg);
            pArg->pChainedArg = NULL;
        }
        break;

    default:
        printf("ENV(%d): %u[%d]\n", status, bufLen, type);
        status = ERR_INVALID_INPUT;
        break;
    }


exit:
    //printf("ENV(%d): %u[%d]\n", status, bufLen, type);
    return status;
}

static MSTATUS
internal_chainedCallback(const void* arg,
                         MOC_CMS_context pCtx,
                         MOC_CMS_UpdateType type,
                         ubyte* pBuf,
                         ubyte4 bufLen)
{
    MSTATUS status = OK;
    MOC_CMS_ContentType contentType;
    chained* pArg = (chained*)arg;

    if (NULL == pArg)
    {
        return ERR_NULL_POINTER;
    }

    /* Is the type known? */
    if (E_MOC_CMS_ct_undetermined == pArg->contentType)
    {
        /* Save data before it can be sent further */
        if (NULL == pArg->tmp)
        {
            pArg->tmp = MALLOC(bufLen);
            DIGI_MEMCPY(pArg->tmp,
                       pBuf,
                       bufLen);
            pArg->tmpLen = bufLen;
        }
        else
        {
            ubyte* move = pArg->tmp;

            pArg->tmp = MALLOC (bufLen + pArg->tmpLen);
            DIGI_MEMCPY (pArg->tmp,
                        move,
                        pArg->tmpLen);
            DIGI_MEMCPY (pArg->tmp + pArg->tmpLen,
                        pBuf,
                        bufLen);
            pArg->tmpLen += bufLen;

            FREE (move);
        }

        /* Read content type */
        status = DIGI_CMS_getContentType (pCtx,
                                         &contentType);
        if (OK != status)
            goto exit;

        /* Anything to do? */
        if (E_MOC_CMS_ct_undetermined != contentType)
        {
            /* Start processing the data */
            pArg->contentType = contentType;
            pBuf = pArg->tmp;
            bufLen = pArg->tmpLen;
        }
        else
        {
            /* Skip over and exit */
            goto exit;
        }
    }

    switch(pArg->contentType)
    {
    case E_MOC_CMS_ct_envelopedData:
        status = internal_processEnvelope(pArg,
                                          pCtx,
                                          type,
                                          pBuf,
                                          bufLen);
        break;

    case E_MOC_CMS_ct_signedData:
        status = internal_processSigned(pArg,
                                        pCtx,
                                        type,
                                        pBuf,
                                        bufLen);
        break;

    default:
        status = ERR_UNSUPPORTED_OPERATION; /* FIXME */
        break;
    }

    /* clean up if there was stored data */
    if (NULL != pArg->tmp)
    {
        FREE (pArg->tmp);
        pArg->tmp = NULL;
        pArg->tmpLen = 0;
    }

exit:
    return status;
}

static MSTATUS
run_chainedCMS(const char* fileName,
               ubyte4 chunkSize,
               intBoolean expectFail)
{
    MSTATUS status;
    ubyte* pCert = NULL;
    ubyte4 certLen;

    ubyte* buf = NULL;
    ubyte4 copied = 0;
    intBoolean finished = 0;

    MOC_CMS_context   ctx = NULL;
    MOC_CMS_Callbacks cb = { 0 };
    chained*          t = NULL;

    /* Read data from file */
    status = DIGICERT_readFile(fileName, &pCert, &certLen);
    if (OK != status)
       goto exit;

    t = MALLOC (sizeof (chained));
    t->contentType = E_MOC_CMS_ct_undetermined;
    t->tmp = NULL;
    t->tmpLen = 0;
    t->pChainedCtx = NULL;
    t->pChain = NULL;

    cb.getPrivKeyFun = &filePrivateKeyCB;
    cb.getPrivKeyFunEx = &dummyGetPrivateKeyFun;
    cb.getCertFun = &dummyCertificateCB;
    cb.valCertFun = &dummyVerifyCert;
    cb.dataUpdateFun = &internal_chainedCallback;

    status = DIGI_CMS_newContext (&ctx,
                                 (void*)t,
                                 &cb);
    if (OK != status)
       goto exit;

    /* Read chunks and pass them into ASN1 parser for processing */
    buf = MALLOC(chunkSize);

    while ((FALSE == finished) && (certLen > copied))
    {
       ubyte4 newData;

       /* Copy next chunk or the final byte(s) */
       if (chunkSize < (certLen - copied))
       {
          newData = chunkSize;
       }
       else
       {
          newData = certLen - copied;
       }
       DIGI_MEMCPY (buf, pCert + copied, newData);

       /* Update parser */
       status = DIGI_CMS_updateContext (ctx,
                                       buf, newData,
                                       &finished);
       if (OK != status)
           goto exit;

       copied += newData;
    }

exit:
    if (NULL != buf)
    {
        FREE (buf);
    }
    if (NULL != pCert)
    {
        FREE (pCert);
    }
    if (NULL != t)
    {
        FREE (t);
    }
    DIGI_CMS_deleteContext (&ctx);

    return status;
}

int mocdecode_cms_test_chainedCMS()
{
    MSTATUS status;
    int retval = 0;

#if 1
    printf("RUN: NCRP_ummaker_e_3DES.cms\n");
    status = run_chainedCMS("NCRP_ummaker_e_3DES.cms",
                            2,
                            FALSE);
    retval += UNITTEST_STATUS (10, status);
#endif

#if 1
    printf("RUN: NCRP_ummaker_e_AES128.cms\n");
    status = run_chainedCMS("NCRP_ummaker_e_AES128.cms",
                            2,
                            FALSE);
    retval += UNITTEST_STATUS (11, status);
#endif

#if 1
    printf("RUN: NCRP_ummaker_e_AES128.hacked\n");
    status = run_chainedCMS("NCRP_ummaker_e_AES128.hacked",
                            2,
                            TRUE);
    retval += UNITTEST_INT(12, status, ERR_CERT_INVALID_SIGNATURE);
#endif

#if 1
    printf("RUN: NCRP_ummaker_s_sha256.cms\n");
    status = run_chainedCMS("NCRP_ummaker_s_sha256.cms",
                            2,
                            FALSE);
    retval += UNITTEST_STATUS (11, status);
#endif

#if 1
    printf("RUN: NCRP_ummaker_s_sha256.hacked\n");
    status = run_chainedCMS("NCRP_ummaker_s_sha256.hacked",
                            2,
                            TRUE);
    retval += UNITTEST_INT(12, status, ERR_CERT_INVALID_SIGNATURE);
#endif

#if 1
    printf("RUN: openssl_certs_s2e2.cms\n");
    status = run_chainedCMS("openssl_certs_s2e2.cms",
                            2,
                            FALSE);
    retval += UNITTEST_STATUS(15, status);
#endif

#if 1
    printf("RUN: openssl_certs_s2e2.hacked\n");
    status = run_chainedCMS("openssl_certs_s2e2.hacked",
                            2,
                            TRUE);
    retval += UNITTEST_INT(12, status, ERR_CERT_INVALID_SIGNATURE);
#endif

    return retval;
}

int mocdecode_cms_test_getDigestID()
{
    MSTATUS status;
    int retval = 0;
    intBoolean finished = 0;

    internal_test* t = NULL;
    sbyte4 i, numDigests = -1;

    ubyte* pCert = NULL;
    ubyte4 certLen;

    MOC_CMS_context     ctx = NULL;
    MOC_CMS_Callbacks   cb = { 0 };
    MOC_CMS_ContentType content_type;

    /* Read data from file */
    status = DIGICERT_readFile("NCRP_ummaker_s_sha256.cms", &pCert, &certLen);
    retval += UNITTEST_STATUS(11, status);
    if (retval > 0)
       goto exit;

    t = MALLOC (sizeof(internal_test));
    t->bufUsed = 0;
    t->bufMax = certLen + 1;
    t->buf = MALLOC (t->bufMax);
    t->done = FALSE;

    cb.getCertFun = &dummyCertificateCB;
    cb.dataUpdateFun = &internal_verifyCallback;
    cb.valCertFun = &dummyVerifyCert;

    status = DIGI_CMS_newContext (&ctx,
                                 (void*)t,
                                 &cb);
    retval += UNITTEST_STATUS(10, status);
    if (retval > 0)
       goto exit;

    /* Update parser */
    status = DIGI_CMS_updateContext (ctx,
                                    pCert, certLen,
                                    &finished);
    retval += UNITTEST_STATUS(20, status);
    if (retval > 0)
       goto exit;

    /* Check final status */
    retval += UNITTEST_TRUE (50, finished);
    if (retval > 0)
       goto exit;

    /* Check content type */
    status = DIGI_CMS_getContentType (ctx,
                                     &content_type);
    retval += UNITTEST_STATUS (60, status);
    if (retval > 0)
       goto exit;

    retval += UNITTEST_INT (61, content_type, E_MOC_CMS_ct_signedData);
    if (retval > 0)
        goto exit;

    /* check size of callback buffer */
    retval += UNITTEST_TRUE (62, t->done);
    if (retval > 0)
        goto exit;

    retval += UNITTEST_TRUE (63, t->bufUsed > 0);
    if (retval > 0)
        goto exit;

    /* Check digest list */
    status = DIGI_CMS_getNumDigests (ctx, &numDigests);
    retval += UNITTEST_STATUS (70, status);
    if (retval > 0)
        goto exit;

    retval += UNITTEST_INT (70, numDigests, 1);
    if (retval > 0)
        goto exit;

    for (i = 0; i < numDigests; ++i)
    {
        const ubyte* pOID = NULL;
        sbyte4       cmpResult;

        status = DIGI_CMS_getDigestID (ctx, i,
                                      &pOID);
        retval += UNITTEST_STATUS (100*i+71, status);
        if (retval > 0)
            goto exit;

        retval += UNITTEST_VALIDPTR (100*i+71, pOID);
        if (retval > 0)
            goto exit;

        status = DIGI_MEMCMP (pOID+1, sha256_OID+1, sha256_OID[0], &cmpResult);
        retval += UNITTEST_STATUS (100*i+80, status);
        if (retval > 0)
            goto exit;

        retval += UNITTEST_INT (100*i+80, cmpResult, 0);
        if (retval > 0)
            goto exit;
    }

exit:
    DIGI_CMS_deleteContext (&ctx);
    if (NULL != t)
    {
        FREE (t->buf);
        FREE (t);
    }
    if (NULL != pCert)
    {
        FREE (pCert);
    }
    return retval;
}

int mocdecode_cms_test_signingTimeAttribute()
{
    ubyte pCmsData[] = {
        0x30, 0x80, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
        0xF7, 0x0D, 0x01, 0x07, 0x02, 0xA0, 0x80, 0x30,
        0x80, 0x02, 0x01, 0x01, 0x31, 0x0F, 0x30, 0x0D,
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x02, 0x01, 0x05, 0x00, 0x30, 0x80, 0x06,
        0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
        0x07, 0x01, 0xA0, 0x80, 0x24, 0x80, 0x04, 0x03,
        0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x31, 0x82, 0x02, 0x1A, 0x30, 0x82, 0x02,
        0x16, 0x02, 0x01, 0x01, 0x30, 0x81, 0x83, 0x30,
        0x6B, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55,
        0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13,
        0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C,
        0x0A, 0x43, 0x61, 0x6C, 0x69, 0x66, 0x6F, 0x72,
        0x6E, 0x69, 0x61, 0x31, 0x16, 0x30, 0x14, 0x06,
        0x03, 0x55, 0x04, 0x07, 0x0C, 0x0D, 0x53, 0x61,
        0x6E, 0x20, 0x46, 0x72, 0x61, 0x6E, 0x63, 0x69,
        0x73, 0x63, 0x6F, 0x31, 0x11, 0x30, 0x0F, 0x06,
        0x03, 0x55, 0x04, 0x0A, 0x0C, 0x08, 0x52, 0x6F,
        0x6F, 0x74, 0x20, 0x4C, 0x74, 0x64, 0x31, 0x1C,
        0x30, 0x1A, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C,
        0x13, 0x77, 0x77, 0x77, 0x2E, 0x65, 0x78, 0x61,
        0x6D, 0x70, 0x6C, 0x65, 0x72, 0x6F, 0x6F, 0x74,
        0x2E, 0x63, 0x6F, 0x6D, 0x02, 0x14, 0x07, 0x32,
        0xEA, 0x88, 0x7B, 0xA3, 0x6B, 0x13, 0x15, 0x54,
        0x5F, 0x18, 0xD8, 0x1B, 0x6C, 0x8E, 0xE0, 0x50,
        0xE6, 0x3D, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
        0x00, 0xA0, 0x69, 0x30, 0x1C, 0x06, 0x09, 0x2A,
        0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05,
        0x31, 0x0F, 0x17, 0x0D, 0x32, 0x30, 0x30, 0x32,
        0x30, 0x35, 0x32, 0x31, 0x30, 0x39, 0x32, 0x31,
        0x5A, 0x30, 0x18, 0x06, 0x09, 0x2A, 0x86, 0x48,
        0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03, 0x31, 0x0B,
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
        0x01, 0x07, 0x01, 0x30, 0x2F, 0x06, 0x09, 0x2A,
        0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04,
        0x31, 0x22, 0x04, 0x20, 0x03, 0x90, 0x58, 0xC6,
        0xF2, 0xC0, 0xCB, 0x49, 0x2C, 0x53, 0x3B, 0x0A,
        0x4D, 0x14, 0xEF, 0x77, 0xCC, 0x0F, 0x78, 0xAB,
        0xCC, 0xCE, 0xD5, 0x28, 0x7D, 0x84, 0xA1, 0xA2,
        0x01, 0x1C, 0xFB, 0x81, 0x30, 0x0D, 0x06, 0x09,
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
        0x01, 0x05, 0x00, 0x04, 0x82, 0x01, 0x00, 0x15,
        0x3A, 0x08, 0xC7, 0xC5, 0x2D, 0x39, 0xE1, 0x53,
        0x13, 0x9A, 0xD5, 0xE2, 0x54, 0xAF, 0x72, 0x9E,
        0x9F, 0x14, 0x7D, 0xDD, 0x42, 0x6A, 0xD2, 0xBB,
        0x57, 0xCA, 0x80, 0xE4, 0xBB, 0x82, 0x89, 0x6C,
        0xD6, 0x71, 0xAB, 0xEF, 0xFF, 0xCA, 0x3C, 0xB7,
        0x8D, 0x02, 0x8D, 0x1C, 0x9F, 0x22, 0x82, 0x6F,
        0x64, 0xE7, 0x83, 0xA3, 0x8C, 0xA3, 0x8C, 0xFC,
        0x19, 0xCF, 0x14, 0x42, 0xF7, 0x36, 0x72, 0x42,
        0x85, 0xFC, 0xF9, 0x86, 0xAC, 0xAE, 0x24, 0xD5,
        0xB2, 0x66, 0x30, 0xB8, 0x25, 0xA4, 0x74, 0x10,
        0xCE, 0xD5, 0x90, 0xB1, 0xD0, 0x4C, 0xB1, 0x3B,
        0x5C, 0xA5, 0x40, 0xFC, 0x8F, 0x24, 0xDC, 0x5E,
        0x43, 0x6B, 0x07, 0xF5, 0x4F, 0x7A, 0x89, 0x57,
        0x76, 0x9F, 0x98, 0x2B, 0xFF, 0xEB, 0x87, 0xC0,
        0xA0, 0xE9, 0x64, 0x51, 0x67, 0x4A, 0xDF, 0xA7,
        0xF6, 0x7B, 0x22, 0xF9, 0xAF, 0x24, 0x15, 0x8C,
        0x04, 0x73, 0x15, 0x43, 0xF6, 0xB4, 0x83, 0xCF,
        0x8F, 0xAA, 0x57, 0xEB, 0xDE, 0xD5, 0x4F, 0x5E,
        0xC3, 0xE0, 0xE7, 0x61, 0x0C, 0x47, 0x7F, 0xEA,
        0x58, 0xED, 0x6F, 0x8C, 0x9D, 0x46, 0xDF, 0x28,
        0x40, 0xA7, 0xF5, 0xDC, 0xBC, 0xB3, 0x9E, 0xD2,
        0x92, 0x75, 0x6F, 0xF6, 0x15, 0x84, 0x4E, 0x59,
        0x17, 0xB6, 0x9A, 0x31, 0x3C, 0xF0, 0x8E, 0xDE,
        0x1D, 0xDC, 0xB4, 0xD4, 0x3E, 0x40, 0x86, 0x57,
        0xB9, 0x98, 0xE9, 0x93, 0xAD, 0x08, 0x8D, 0x25,
        0x00, 0xDA, 0x34, 0x0F, 0x50, 0x42, 0xB2, 0xA7,
        0x4E, 0xE8, 0x38, 0x1F, 0x3A, 0xF0, 0xB4, 0x74,
        0xD0, 0xB7, 0x7D, 0xDE, 0x82, 0xFC, 0x64, 0xC1,
        0x04, 0x67, 0x78, 0x90, 0xBA, 0xF7, 0xC4, 0xEF,
        0xA0, 0x18, 0x6D, 0x3E, 0x3D, 0xA9, 0xBA, 0x4B,
        0xCE, 0x45, 0x16, 0x88, 0x3D, 0x2C, 0x08, 0x3C,
        0xAB, 0x23, 0x02, 0x62, 0x72, 0xC7, 0xA5, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00
    };
    MSTATUS status;
    int retVal = 0;
    internal_test* t = NULL;
    MOC_CMS_context     pCtx = NULL;
    MOC_CMS_Callbacks   cb = { 0 };
    MOC_CMS_ContentType content_type;
    intBoolean finished;

    cb.getCertFun = &dummyCertificateCB;
    cb.dataUpdateFun = &internal_verifyCallback;
    cb.valCertFun = &dummyVerifyCertSigningTime;

    t = MALLOC (sizeof(internal_test));
    t->bufUsed = 0;
    t->bufMax = 2048;
    t->buf = MALLOC (t->bufMax);
    t->done = FALSE;

    status = DIGI_CMS_newContext(&pCtx, (void *) t, &cb);
    retVal += UNITTEST_STATUS(1, status);
    if (retVal > 0)
        goto exit;

    status = DIGI_CMS_updateContext(pCtx, pCmsData, sizeof(pCmsData), &finished);
    retVal += UNITTEST_STATUS(2, status);
    if (retVal > 0)
        goto exit;

exit:

    DIGI_CMS_deleteContext(&pCtx);

    if (NULL != t)
    {
        FREE (t->buf);
        FREE (t);
    }

    return retVal;
}

static int basicDecodeEnvelopedData(ubyte *pData, ubyte4 dataLen)
{
    MSTATUS status;
    int retVal = 0;

    internal_test* t = NULL;
    MOC_CMS_context     pCtx = NULL;
    MOC_CMS_Callbacks   cb = { 0 };
    intBoolean finished;

    cb.getPrivKeyFun = &filePrivateKeyCB;
    cb.dataUpdateFun = &internal_verifyCallback;

    t = MALLOC (sizeof(internal_test));
    t->bufUsed = 0;
    t->bufMax = 2048;
    t->buf = MALLOC (t->bufMax);
    t->done = FALSE;

    status = DIGI_CMS_newContext(&pCtx, (void *) t, &cb);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (retVal > 0)
        goto exit;

    status = DIGI_CMS_updateContext(
        pCtx, pData, dataLen, &finished);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (retVal > 0)
        goto exit;

    retVal += UNITTEST_TRUE(__MOC_LINE__, TRUE == finished);
    if (retVal > 0)
        goto exit;

exit:

    DIGI_CMS_deleteContext(&pCtx);

    if (NULL != t)
    {
        FREE (t->buf);
        FREE (t);
    }

    return retVal;
}

int mocdecode_cms_test_keyEncryptionAlgorithmRsaOaep()
{
    MSTATUS status;
    int retVal = 0;

    /* "Hello" as enveloped data */
    ubyte pEnvelopedDataDefault[] = {
        0x30, 0x82, 0x01, 0xfe, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x03, 0xa0, 0x82, 0x01, 0xef, 0x30, 0x82, 0x01, 0xeb, 0x02, 0x01, 0x00, 0x31, 0x82, 0x01, 0xb7, 0x30, 0x82, 0x01, 0xb3, 0x02, 0x01, 0x00, 0x30, 0x81, 0x9a, 0x30, 0x81, 0x94, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0a, 0x4e, 0x69, 0x68, 0x6f, 0x6e, 0x20, 0x5a, 0x61, 0x72, 0x75, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x06, 0x4d, 0x6f, 0x63, 0x61, 0x6e, 0x61, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x03, 0x49, 0x4f, 0x54, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e, 0x69, 0x61, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x0d, 0x53, 0x61, 0x6e, 0x20, 0x46, 0x72, 0x61, 0x6e, 0x63, 0x69, 0x73, 0x63, 0x6f, 0x31, 0x24, 0x30, 0x22, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x15, 0x74, 0x65, 0x73, 0x74, 0x6d, 0x6f, 0x6e, 0x6b, 0x65, 0x79, 0x40, 0x6d, 0x6f, 0x63, 0x61, 0x6e, 0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x02, 0x01, 0x01, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x07, 0x30, 0x00, 0x04, 0x82, 0x01, 0x00, 0x69, 0xa3, 0x34, 0x3c, 0xb4, 0x1b, 0x43, 0xa4, 0xe8, 0x6b, 0x22, 0xc3, 0xdf, 0xfd, 0xe5, 0xa0, 0x5a, 0x95, 0x87, 0xe1, 0xaa, 0xf9, 0x86, 0x95, 0xf3, 0x97, 0x8e, 0xdf, 0x48, 0xb7, 0xe5, 0x89, 0x14, 0xe4, 0x58, 0x56, 0x44, 0xa1, 0x0e, 0x56, 0x7f, 0x92, 0x5e, 0xf3, 0xba, 0x9d, 0xff, 0x06, 0x85, 0x98, 0x19, 0x30, 0x19, 0x29, 0xbb, 0x57, 0x08, 0xd1, 0x2a, 0x2b, 0xc7, 0xaa, 0xab, 0x2b, 0x6c, 0x94, 0x5d, 0x4a, 0x30, 0x0c, 0xc1, 0xfe, 0x8e, 0x05, 0x58, 0x97, 0x0d, 0x0e, 0x1c, 0x6d, 0xea, 0x9b, 0xcc, 0x13, 0x9e, 0x80, 0xdb, 0xd2, 0x2c, 0x7b, 0x0a, 0x5d, 0xe2, 0x8d, 0x99, 0x6f, 0x3a, 0x1f, 0xcb, 0x40, 0xc1, 0xe1, 0x6e, 0x67, 0x12, 0x09, 0xd2, 0xa8, 0xe1, 0x1d, 0x60, 0x5e, 0xec, 0xe9, 0x9a, 0x3c, 0xbc, 0x80, 0x95, 0x8e, 0x86, 0xb2, 0x31, 0x32, 0x76, 0x0a, 0x02, 0xfb, 0x97, 0x37, 0x75, 0xd5, 0x5d, 0xec, 0xaf, 0xd9, 0xbc, 0xc1, 0xff, 0x84, 0xf8, 0x1b, 0x81, 0x04, 0x64, 0xed, 0x99, 0xb2, 0xff, 0xec, 0xe7, 0x13, 0xeb, 0x41, 0xe7, 0xa7, 0x2c, 0x2b, 0xc6, 0x9c, 0x49, 0x47, 0x54, 0x38, 0x2c, 0x98, 0xcd, 0x9b, 0x3b, 0x46, 0x61, 0x6e, 0x5a, 0x5f, 0xfa, 0x1a, 0x09, 0xc9, 0x1e, 0xaf, 0x03, 0x33, 0xe1, 0xd1, 0x95, 0xf1, 0xeb, 0x0f, 0x0a, 0x47, 0x84, 0x24, 0x10, 0x08, 0xb5, 0xe5, 0xfb, 0x8a, 0xa1, 0xf6, 0xf6, 0x70, 0xfa, 0xaf, 0x48, 0xe8, 0xc8, 0x57, 0x2e, 0x7e, 0xc4, 0x67, 0xb1, 0x87, 0xf0, 0x12, 0xc5, 0xad, 0x40, 0xf7, 0x7f, 0x22, 0xd4, 0xf5, 0xcb, 0x90, 0xfe, 0x2d, 0x33, 0x18, 0x8d, 0x41, 0xf1, 0xb9, 0x7e, 0x20, 0x7a, 0x27, 0x62, 0x91, 0x2d, 0xa4, 0x88, 0x9b, 0x32, 0xf5, 0x33, 0xe6, 0x4c, 0xb2, 0x28, 0x8a, 0x39, 0x82, 0x79, 0x16, 0x30, 0x2b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0x30, 0x14, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x07, 0x04, 0x08, 0xc0, 0xe0, 0xe0, 0x70, 0xfa, 0x5c, 0xb4, 0x29, 0x80, 0x08, 0x1d, 0x22, 0x7e, 0x72, 0xea, 0x25, 0x0a, 0x23
    };
    ubyte pEnvelopedDataWith_Label[] = {
        0x30, 0x82, 0x02, 0x1b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x03, 0xa0, 0x82, 0x02, 0x0c, 0x30, 0x82, 0x02, 0x08, 0x02, 0x01, 0x00, 0x31, 0x82, 0x01, 0xd4, 0x30, 0x82, 0x01, 0xd0, 0x02, 0x01, 0x00, 0x30, 0x81, 0x9a, 0x30, 0x81, 0x94, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0a, 0x4e, 0x69, 0x68, 0x6f, 0x6e, 0x20, 0x5a, 0x61, 0x72, 0x75, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x06, 0x4d, 0x6f, 0x63, 0x61, 0x6e, 0x61, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x03, 0x49, 0x4f, 0x54, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e, 0x69, 0x61, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x0d, 0x53, 0x61, 0x6e, 0x20, 0x46, 0x72, 0x61, 0x6e, 0x63, 0x69, 0x73, 0x63, 0x6f, 0x31, 0x24, 0x30, 0x22, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x15, 0x74, 0x65, 0x73, 0x74, 0x6d, 0x6f, 0x6e, 0x6b, 0x65, 0x79, 0x40, 0x6d, 0x6f, 0x63, 0x61, 0x6e, 0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x02, 0x01, 0x01, 0x30, 0x2a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x07, 0x30, 0x1d, 0xa2, 0x1b, 0x30, 0x19, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x09, 0x04, 0x0c, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x5f, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x04, 0x82, 0x01, 0x00, 0xb6, 0x58, 0x73, 0x0b, 0x13, 0x35, 0x0a, 0x1e, 0x55, 0xa2, 0x2b, 0xbe, 0x29, 0x08, 0x14, 0x9a, 0xb5, 0x1e, 0xc5, 0x94, 0x9e, 0x63, 0x60, 0x4f, 0xcc, 0x17, 0xce, 0x63, 0xee, 0x45, 0x76, 0x04, 0x02, 0x20, 0xce, 0x68, 0x81, 0x90, 0x2f, 0x58, 0x3e, 0xe9, 0x63, 0x06, 0xb7, 0xd4, 0x9c, 0xe8, 0x58, 0x0d, 0x3a, 0x86, 0xa8, 0x95, 0x2c, 0x6d, 0xb9, 0x4c, 0x11, 0x29, 0xa6, 0x68, 0xa3, 0xa5, 0x54, 0xf8, 0xa5, 0xb3, 0x05, 0x9a, 0x6b, 0xa9, 0x47, 0x3a, 0x4d, 0x90, 0x55, 0x7c, 0xe5, 0xc8, 0xe8, 0xa3, 0x6a, 0x16, 0x61, 0x9a, 0x7c, 0x7d, 0xe8, 0x60, 0x8f, 0x0b, 0x2a, 0xdb, 0xb4, 0x9f, 0x69, 0x6d, 0x74, 0xfd, 0xd2, 0x4d, 0xff, 0x51, 0x96, 0xcc, 0xf6, 0xfb, 0x1d, 0x33, 0x5a, 0xff, 0x81, 0xd1, 0xba, 0x2a, 0x88, 0xfc, 0xef, 0x3f, 0x6a, 0x7c, 0xdc, 0xf9, 0x4c, 0x17, 0x72, 0xca, 0xd9, 0x25, 0x1f, 0x62, 0x50, 0xe3, 0x3e, 0x7c, 0xe3, 0x91, 0x70, 0x10, 0x67, 0xbe, 0x8c, 0x85, 0x87, 0xb2, 0x15, 0x39, 0x2c, 0x26, 0x35, 0xea, 0xbd, 0xc8, 0x8e, 0xce, 0xaf, 0x7f, 0xb9, 0xb7, 0xd4, 0x1b, 0x08, 0xcb, 0x1a, 0x60, 0x74, 0xed, 0x83, 0xad, 0x0c, 0x43, 0x08, 0x0c, 0xe2, 0x0f, 0x7c, 0xb5, 0x82, 0xeb, 0x06, 0x29, 0x21, 0x3d, 0xf7, 0x23, 0xac, 0x7b, 0xda, 0x94, 0xa0, 0x89, 0x57, 0xff, 0x1f, 0x9a, 0x24, 0x0d, 0x51, 0x19, 0xd1, 0x4d, 0x26, 0xbc, 0xb7, 0x5f, 0xea, 0xc7, 0xd5, 0x90, 0x5a, 0x6a, 0x5e, 0x0a, 0x08, 0x95, 0x78, 0x25, 0xa4, 0x67, 0x35, 0x82, 0x56, 0x04, 0x1e, 0xcf, 0x4a, 0x40, 0x8f, 0x96, 0x7f, 0xcf, 0xdf, 0x1e, 0xea, 0x3d, 0x32, 0x8a, 0xe9, 0x88, 0x69, 0xaf, 0xc4, 0xc1, 0x54, 0x97, 0x16, 0x0d, 0xe9, 0x99, 0x04, 0x09, 0x67, 0xfa, 0x37, 0x88, 0x30, 0x2b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0x30, 0x14, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x07, 0x04, 0x08, 0x11, 0xd4, 0x1e, 0x8e, 0x15, 0xeb, 0x3e, 0x6c, 0x80, 0x08, 0x79, 0x09, 0xa4, 0xb8, 0xcb, 0xfd, 0x5e, 0x90
    };
    ubyte pEnvelopedDataWith_OaepSha384_Mgf1Sha384[] = {
        0x30, 0x82, 0x02, 0x29, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x03, 0xa0, 0x82, 0x02, 0x1a, 0x30, 0x82, 0x02, 0x16, 0x02, 0x01, 0x00, 0x31, 0x82, 0x01, 0xe2, 0x30, 0x82, 0x01, 0xde, 0x02, 0x01, 0x00, 0x30, 0x81, 0x9a, 0x30, 0x81, 0x94, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0a, 0x4e, 0x69, 0x68, 0x6f, 0x6e, 0x20, 0x5a, 0x61, 0x72, 0x75, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x06, 0x4d, 0x6f, 0x63, 0x61, 0x6e, 0x61, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x03, 0x49, 0x4f, 0x54, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e, 0x69, 0x61, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x0d, 0x53, 0x61, 0x6e, 0x20, 0x46, 0x72, 0x61, 0x6e, 0x63, 0x69, 0x73, 0x63, 0x6f, 0x31, 0x24, 0x30, 0x22, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x15, 0x74, 0x65, 0x73, 0x74, 0x6d, 0x6f, 0x6e, 0x6b, 0x65, 0x79, 0x40, 0x6d, 0x6f, 0x63, 0x61, 0x6e, 0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x02, 0x01, 0x01, 0x30, 0x38, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x07, 0x30, 0x2b, 0xa0, 0x0d, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0xa1, 0x1a, 0x30, 0x18, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x04, 0x82, 0x01, 0x00, 0x68, 0x20, 0xb5, 0xc9, 0xa7, 0xdc, 0x7c, 0x5a, 0xb6, 0xd3, 0x12, 0xd1, 0x21, 0x8d, 0x05, 0xb2, 0x51, 0x3b, 0x0f, 0x34, 0x34, 0xe1, 0xe3, 0xb2, 0x0d, 0x9f, 0x9d, 0x6e, 0x8b, 0x53, 0x06, 0x1c, 0x72, 0x93, 0x4f, 0x33, 0x08, 0xb3, 0xaf, 0xb8, 0x88, 0x5b, 0x83, 0x94, 0xcd, 0x64, 0xd3, 0x27, 0x08, 0x23, 0x94, 0xc5, 0x91, 0x8f, 0xb4, 0x1d, 0xde, 0x7a, 0x76, 0xa0, 0x01, 0x9c, 0x21, 0x61, 0x4f, 0x29, 0x19, 0x80, 0x9c, 0x7e, 0xa9, 0x51, 0x3b, 0x30, 0x60, 0x2e, 0x86, 0x92, 0xaf, 0x4b, 0x7b, 0xae, 0xd6, 0xa8, 0x1d, 0x4a, 0xfd, 0xc8, 0x58, 0xb6, 0x50, 0xc2, 0x95, 0xc1, 0xaa, 0xa7, 0x3d, 0x3e, 0x91, 0xae, 0x99, 0x9a, 0xb1, 0xa7, 0x44, 0xc1, 0xe2, 0x77, 0x5e, 0x97, 0x0e, 0x38, 0xa6, 0xe5, 0x20, 0x74, 0x39, 0xcf, 0xa0, 0x87, 0x6c, 0x25, 0x79, 0xa2, 0xbd, 0x70, 0x81, 0x44, 0xb5, 0xc0, 0x1e, 0xcd, 0x0e, 0x12, 0x72, 0x6a, 0x7d, 0x65, 0xa7, 0xdd, 0x87, 0xf8, 0x38, 0x44, 0xfa, 0xc5, 0x33, 0x51, 0x4d, 0x74, 0x3f, 0xf8, 0xcc, 0x0d, 0x91, 0x7b, 0xbd, 0xb5, 0x9c, 0x96, 0xe8, 0x7f, 0xb0, 0xf3, 0x86, 0xbe, 0x40, 0xb3, 0x26, 0x69, 0xfc, 0x2d, 0x1a, 0x7c, 0xdd, 0xfe, 0xb5, 0x41, 0x40, 0xe8, 0x97, 0x89, 0x74, 0x4e, 0x92, 0xc8, 0x12, 0x70, 0x62, 0x4d, 0x1f, 0xc5, 0xa8, 0xdd, 0x83, 0xc1, 0x95, 0x29, 0x94, 0xf9, 0xee, 0xad, 0x89, 0xf1, 0xa9, 0x60, 0xee, 0x7e, 0x3f, 0xd0, 0xa5, 0x07, 0xf1, 0x50, 0xf0, 0xa1, 0xd1, 0xfc, 0x64, 0xa2, 0x18, 0x76, 0x12, 0x55, 0x33, 0x87, 0x75, 0x9b, 0x6f, 0x16, 0x2d, 0x3f, 0xfa, 0xeb, 0x46, 0x69, 0x30, 0xcc, 0x05, 0x80, 0xe2, 0xc8, 0x8a, 0xb3, 0xdc, 0x6b, 0x95, 0x59, 0x19, 0xac, 0x2e, 0x0a, 0x98, 0x84, 0x3a, 0x0a, 0x30, 0x2b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0x30, 0x14, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x07, 0x04, 0x08, 0x63, 0xa1, 0x7f, 0x3a, 0x82, 0xaa, 0xcf, 0xd3, 0x80, 0x08, 0x06, 0xa1, 0x9d, 0x47, 0xe7, 0xef, 0xc1, 0x13
    };
    ubyte pEnvelopedDataWith_OaepSha256_Mgf1Sha256_Label[] = {
        0x30, 0x82, 0x02, 0x46, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x03, 0xa0, 0x82, 0x02, 0x37, 0x30, 0x82, 0x02, 0x33, 0x02, 0x01, 0x00, 0x31, 0x82, 0x01, 0xff, 0x30, 0x82, 0x01, 0xfb, 0x02, 0x01, 0x00, 0x30, 0x81, 0x9a, 0x30, 0x81, 0x94, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0a, 0x4e, 0x69, 0x68, 0x6f, 0x6e, 0x20, 0x5a, 0x61, 0x72, 0x75, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x06, 0x4d, 0x6f, 0x63, 0x61, 0x6e, 0x61, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x03, 0x49, 0x4f, 0x54, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e, 0x69, 0x61, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x0d, 0x53, 0x61, 0x6e, 0x20, 0x46, 0x72, 0x61, 0x6e, 0x63, 0x69, 0x73, 0x63, 0x6f, 0x31, 0x24, 0x30, 0x22, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x15, 0x74, 0x65, 0x73, 0x74, 0x6d, 0x6f, 0x6e, 0x6b, 0x65, 0x79, 0x40, 0x6d, 0x6f, 0x63, 0x61, 0x6e, 0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x02, 0x01, 0x01, 0x30, 0x55, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x07, 0x30, 0x48, 0xa0, 0x0d, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0xa1, 0x1a, 0x30, 0x18, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0xa2, 0x1b, 0x30, 0x19, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x09, 0x04, 0x0c, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x5f, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x04, 0x82, 0x01, 0x00, 0x38, 0x55, 0xa2, 0x00, 0x42, 0xdc, 0xc7, 0x4e, 0x25, 0xa8, 0x6d, 0x3a, 0x80, 0x34, 0xd1, 0xbd, 0x39, 0x87, 0x12, 0x53, 0x1d, 0x4b, 0x62, 0x24, 0xa5, 0x52, 0xfd, 0x69, 0x0d, 0x5c, 0x95, 0x0e, 0x45, 0xb6, 0xf6, 0xcf, 0x5c, 0xab, 0x78, 0x78, 0xee, 0x7e, 0xb6, 0xcf, 0xdc, 0xe4, 0x3d, 0x1b, 0x88, 0x56, 0x7a, 0x66, 0xd6, 0xdb, 0x9b, 0x3f, 0xd2, 0xfe, 0xea, 0xf8, 0x90, 0xcb, 0x3a, 0xae, 0xce, 0x22, 0xcc, 0x5d, 0xea, 0xcc, 0x59, 0x74, 0x67, 0xeb, 0xb0, 0xc3, 0x02, 0x6e, 0xed, 0x78, 0x9a, 0xe1, 0x64, 0x65, 0x39, 0x1e, 0x22, 0xc4, 0xfe, 0x09, 0x6e, 0xfb, 0xa4, 0x20, 0x71, 0x75, 0x5b, 0x87, 0x6b, 0xc3, 0x0b, 0xc3, 0xeb, 0x2b, 0x58, 0x01, 0x2e, 0x8f, 0xc3, 0x30, 0x05, 0x9e, 0x6d, 0xdc, 0x9f, 0x99, 0x62, 0xe3, 0x4a, 0x64, 0xbd, 0xcd, 0xeb, 0xd0, 0x29, 0x30, 0x1a, 0x18, 0x8a, 0xbd, 0x1e, 0x92, 0x29, 0xc7, 0x3a, 0x83, 0x5b, 0xfa, 0xc6, 0x79, 0x9a, 0x41, 0x5d, 0x94, 0x2f, 0xd8, 0x3f, 0x9a, 0x9e, 0x71, 0x7b, 0xf3, 0xe2, 0x8a, 0x4c, 0x1c, 0x30, 0xdc, 0xbc, 0x4f, 0x3b, 0xbe, 0x1f, 0x5e, 0x79, 0xa5, 0x40, 0xde, 0x14, 0x9b, 0x2c, 0xa0, 0x89, 0x9d, 0x74, 0x99, 0x3c, 0x33, 0xf4, 0x94, 0x89, 0xb5, 0x47, 0x75, 0x33, 0x15, 0xdf, 0x87, 0xe8, 0x38, 0x23, 0xb3, 0xbd, 0x26, 0xab, 0xfc, 0x8b, 0xfd, 0x14, 0xdb, 0x86, 0xb0, 0xfa, 0x8e, 0x64, 0xe2, 0x46, 0xc8, 0x52, 0x5c, 0xdd, 0xd0, 0xa6, 0xdf, 0x12, 0xd1, 0x10, 0x3a, 0x11, 0x3c, 0x22, 0xdb, 0xb5, 0x8c, 0x34, 0x9e, 0x00, 0x54, 0xc4, 0x21, 0x78, 0x54, 0xb3, 0xdb, 0x8d, 0xaa, 0x67, 0x99, 0x2a, 0xb9, 0xca, 0xd0, 0xb3, 0x12, 0x96, 0xa8, 0x02, 0x5d, 0x24, 0x80, 0x3b, 0x35, 0x4c, 0x2a, 0x39, 0x6a, 0x30, 0x2b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0x30, 0x14, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x07, 0x04, 0x08, 0x4f, 0x98, 0x48, 0x6b, 0x2d, 0x17, 0x7b, 0x37, 0x80, 0x08, 0x78, 0x52, 0xeb, 0x55, 0x2e, 0x51, 0xc7, 0x9d
    };

    retVal += basicDecodeEnvelopedData(pEnvelopedDataDefault, sizeof(pEnvelopedDataDefault));
    retVal += basicDecodeEnvelopedData(pEnvelopedDataWith_Label, sizeof(pEnvelopedDataWith_Label));
    retVal += basicDecodeEnvelopedData(pEnvelopedDataWith_OaepSha384_Mgf1Sha384, sizeof(pEnvelopedDataWith_OaepSha384_Mgf1Sha384));
    retVal += basicDecodeEnvelopedData(pEnvelopedDataWith_OaepSha256_Mgf1Sha256_Label, sizeof(pEnvelopedDataWith_OaepSha256_Mgf1Sha256_Label));

    return retVal;
}
