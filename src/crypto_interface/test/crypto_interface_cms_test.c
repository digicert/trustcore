/*
 * crypto_interface_cms_test.c
 *
 * unit test for moccms.h and related code
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
#include "../../../unit_tests/unittest.h"

#include "../../asn1/mocasn1.h"
#include "../../asn1/oiddefs.h"
#include "../../common/mtypes.h"
#include "../../common/initmocana.h"
#include "../../crypto/pubcrypto.h"
#include "../../crypto/ca_mgmt.h"
#include "../../crypto/pkcs_common.h"
#include "../../crypto/pkcs_key.h"
#include "../../crypto/pkcs7.h"

#include "../../crypto/moccms.h"
#include "../../crypto/moccms_util.h"
#include "../../crypto/pqc/pqc_ser.h"

#include <stdio.h>

static MocCtx gpMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

/**************************************************************/

typedef struct
{
   ubyte* buf;
   ubyte4 bufUsed;
   ubyte4 bufMax;
   intBoolean done;
   void *pCmsCtx;

} internal_test;

/* OID 1.2.840.113549.1.9.5  */
static ubyte PKCS9_SIGNINGTIME_OID[] =
{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05 };

/* OID 1.3.14.3.2.26 */
static ubyte NIST_SHA1_OID[] =
{ 0x2B, 0x0E, 0x03, 0x02, 0x1A };

/* OID 2.16.840.1.101.3.4.2.1 */
static ubyte NIST_SHA256_OID[] =
{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };

/* OID 2.16.840.1.101.3.4.2.3 */
static ubyte NIST_SHA512_OID[] =
{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 };

/**************************************************************/
MSTATUS
UMP_GetSignerCertInData(ubyte* pSerialNumber,
                        ubyte4 serialNumberLen,
                        ubyte* pIssuer,
                        ubyte4 issuerLen,
                        const ubyte *pX509,
                        ubyte4 x509Len,
                        const ubyte  **ppExternalCert,
                        ubyte4 *pExternalCertLen)
{
    MSTATUS      status = OK;
    MAsn1Element *pRootSig = NULL;
    MAsn1Element *pEnc = NULL;
    ubyte4       bytesRead, idx509;

    MAsn1TypeAndCount encSet[1] =
    {
       {  MASN1_TYPE_ENCODED, 0},
    };

    if ((NULL == pSerialNumber) || (NULL == pIssuer))
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    if ((NULL == pX509) || (NULL == ppExternalCert) || (NULL == pExternalCertLen))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    /* Per RFC-5652, Section 10.2.2., a certificate in the SET is actually a 'CertificateChoices'
     * type that can encode other certificate formats than X509. This code (at this point) only
     * support CHOICE = NO_TAG -> X509
     *
     * Specifically, CHOICE = 3 -> 'other certificates' is not supported
     */

    /* Loop over X509 Set: All entries are sequentially stored in the input memory */
    idx509 = 0;
    while(idx509 < x509Len)
    {
        ubyte *pData;
        ubyte4 dataLen;
        sbyte4 cmpResult = -1;

        /* Obtain actual size of the X509 data */
        status = MAsn1CreateElementArray (encSet, 1, MASN1_FNCT_DECODE,
                                          &MAsn1OfFunction, &pEnc);
        if (OK != status)
            goto exit;

        status = MAsn1Decode ((const ubyte *) pX509 + idx509, x509Len - idx509,
                              pEnc, &bytesRead);
        if (OK != status)
            goto exit;

        /* Read CHOICE value */
        if ((0xA3 == pEnc->value.pValue[0]) ||
            (0xA2 == pEnc->value.pValue[0]))
        {
            status = ERR_CERT_INVALID_STRUCT;
            goto exit;
        }

        /* Check serial number */
        status = DIGI_CMS_U_parseX509CertForSerialNumber (pX509 + idx509,
                                                         bytesRead,
                                                         &pData, &dataLen);
        if (OK != status)
            goto exit;

        if (dataLen != serialNumberLen)
            goto next;

        status = DIGI_MEMCMP (pData, pSerialNumber, dataLen, &cmpResult);
        if ((OK != status) || (0 != cmpResult))
            goto next;

        /* Check issuer name */
        status = DIGI_CMS_U_parseX509CertForIssuerName (pX509 + idx509,
                                                       bytesRead,
                                                       &pData, &dataLen);
        if (OK != status)
            goto exit;

        if (dataLen != issuerLen)
            goto next;

        status = DIGI_MEMCMP (pData, pIssuer, dataLen, &cmpResult);
        if ((OK != status) || (0 != cmpResult))
            goto next;

        /* Found a match, so stop */
        break;

    next:
        /* Set pointer to next entry, if it exists */
        idx509 += bytesRead;
        MAsn1FreeElementArray (&pEnc);
    }

    /* Found an entry? */
    if ((idx509 < x509Len) &&
        (0 < bytesRead))
    {
        ubyte* pCopy = NULL;

        /* Make a copy */
        status = DIGI_MALLOC ((void**)&pCopy, bytesRead);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY(pCopy, pX509 + idx509, bytesRead);
        if (OK != status)
        {
            DIGI_FREE((void **) &pCopy);
            goto exit;
        }

        /* Return data to caller */
        *ppExternalCert = pCopy;
        *pExternalCertLen = bytesRead;
    }

exit:
    MAsn1FreeElementArray (&pEnc);
    MAsn1FreeElementArray (&pRootSig);
    return status;
}

/**************************************************************/

static MSTATUS
internal_verifyCallback(const void* arg,
                        MOC_CMS_context pCtx,
                        MOC_CMS_UpdateType type,
                        ubyte* pBuf,
                        ubyte4 bufLen)
{
    internal_test* t = (internal_test*)arg;

    if (E_MOC_CMS_ut_final == type)
    {
        FILE* tst = NULL;

        if (NULL != pBuf)
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

        t->done = TRUE;
#if 0
        /* For debugging the output */
        tst = fopen ("test_stream.cms", "wb");
        if (NULL != tst)
        {
            fwrite (t->buf, 1, t->bufUsed, tst);
            fclose (tst);
        }
#endif
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

/**************************************************************/

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

/**************************************************************/

/* for similicity we hardcode the cert names, but in practice 
   we would find the cert based on the issuer and serial number */
static const char *gpMldsa65_p256_cert = "mldsa65_p256_cert.der";
static const char *gpMldsa44_cert = "mldsa44_cert.der";
static const char *gpCertForCallback;

static MSTATUS certCB(const void* arg,
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

    status = DIGICERT_readFile(gpCertForCallback, &pCert, &certLen);
    if (OK != status)
        return status;

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
        *ppCertificate = pCert;
        *pCertificateLen = certLen;
        pCert = NULL;
    }

    if (NULL != pCert)
    {
        FREE(pCert);
        pCert = NULL;
    }

    return status;
}

/**************************************************************/

static MSTATUS certCBV3(const void* arg,
    ubyte* pSki,
    ubyte4 skiLen,
    ubyte** ppCertificate,
    ubyte4* pCertificateLen)
{
    /* degenerate method for testing purposes, we know it matches the SKI */
    return DIGICERT_readFile("rsa_cert_ski.der", ppCertificate, pCertificateLen);
}

/**************************************************************/

static MSTATUS inlineCertCB(const void* arg,
                            ubyte* pSerialNumber,
                            ubyte4 serialNumberLen,
                            ubyte* pIssuer,
                            ubyte4 issuerLen,
                            ubyte** ppCertificate,
                            ubyte4* pCertificateLen)
{
    MSTATUS status = OK;
    intBoolean match = FALSE;
    int i = 0;

    const ubyte *pCMSCerts = NULL;
    const ubyte *pCertData = NULL;
    ubyte4      certDataLen, CMSCertsLen = 0;

    internal_test* t = (internal_test *) arg;
    MOC_CMS_context *ppCtx = (MOC_CMS_context *) t->pCmsCtx;

    if (NULL == ppCtx)
    {
        return ERR_NULL_POINTER;
    }

    /* Search the CMS data for a certificate
     * that matches the issuer name and serial number.
     * If found, return the certificate.
     */

    /* Try certificates inside the CMS, if there are any */
    status = DIGI_CMS_getCertificates (*ppCtx, &pCMSCerts, &CMSCertsLen);
    if (OK != status)
        goto exit;

    if ((NULL != pCMSCerts) && (0 < CMSCertsLen))
    {
        status = UMP_GetSignerCertInData (pSerialNumber,
                                          serialNumberLen,
                                          pIssuer,
                                          issuerLen,
                                          pCMSCerts,
                                          CMSCertsLen,
                                          &pCertData,
                                          &certDataLen);
        if (NULL != pCertData)
        {
            /* Success */
            *ppCertificate = (ubyte *)pCertData;
            *pCertificateLen = certDataLen;
        }
        else
        {
            status = ERR_FALSE;
        }
    }
    else
    {
        status = ERR_FALSE;
    }

exit:

    return status;
}

/***************************************************************************************/

static MSTATUS
internal_verifyCallback2(const void* arg,
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

/***************************************************************************************/

static MSTATUS
dummyVerifyCert(const void* arg,
                ubyte* pCertificate,
                ubyte4 certificateLen,
                MOC_CMS_MsgSignInfo *pSigInfo)
{
    MSTATUS status = OK;

    return status;
}

/***************************************************************************************/

static int mocencode_cms_test_signTextDefinite(const char *pKeyFile, const char *pCertFile, byteBoolean isCertInline, byteBoolean isV3)
{
    MSTATUS status;
    int retval = 0;

    internal_test        *t = NULL;
    MOC_CMS_context      ctx = NULL;
    ubyte                *pCert = NULL;
    ubyte4               certLen;
    struct AsymmetricKey key = { 0 };
    ubyte *pCMS = NULL;
    ubyte4 cmsLen = 0;
    MOC_CMS_action action = isCertInline ? E_MOC_CMS_sa_addCert : E_MOC_CMS_sa_none;
    
    /* verify vars */
    ubyte* buf = NULL;
    ubyte4 copied = 0;
    intBoolean finished = 0;
    sbyte4 numSigners = -1;

    MOC_CMS_context     verifyCtx = NULL;
    MOC_CMS_Callbacks   cb = { 0 };
    MOC_CMS_ContentType content_type;
    MOC_CMS_MsgSignInfo info;
    ubyte4 chunkSize = 256;
    
    /* Data to sign */
    ubyte payLoad[] = { 'A', 'U', 'T', 'H', 'E', 'N', 'T', 'I', 'C' };

    if (isV3)
    {
        action = E_MOC_CMS_sa_version3;
    }

    CRYPTO_initAsymmetricKey (&key);

    /* Read key, use pCert as a temp var */
    status = DIGICERT_readFile(pKeyFile, &pCert, &certLen);
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
       goto exit;

    status = CRYPTO_deserializeAsymKey(MOC_ASYM(gpHwAccelCtx) pCert, certLen, NULL, &key);
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
       goto exit;

    DIGI_FREE ((void**)&pCert);

    /* Read certificate */
    status = DIGICERT_readFile(pCertFile, &pCert, &certLen);
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
       goto exit;

    /* Setup callback data */
    t = MALLOC (sizeof(internal_test));
    t->bufUsed = 0;
    t->bufMax = isCertInline ? 10000 : 6144;
    t->buf = MALLOC (t->bufMax);
    t->done = FALSE;

    /* Create context for signing */
    status = DIGI_CMS_newContextOut (MOC_HW(gpHwAccelCtx)
                                    &ctx,
                                    E_MOC_CMS_ct_signedData,
                                    RANDOM_rngFun, g_pRandomContext,
                                    FALSE,
                                    (void*)t,
                                    &internal_verifyCallback);
    retval += UNITTEST_STATUS (10, status);
    if (0 < retval)
       goto exit;

    /* Set signer data */
    status = DIGI_CMS_addSigner (ctx, pCert, certLen,
                                &key,
                                NIST_SHA256_OID,
                                sizeof(NIST_SHA256_OID),
                                action,
                                NULL);
    retval += UNITTEST_STATUS (15, status);
    if (0 < retval)
       goto exit;

    /* Send Data */
    status = DIGI_CMS_updateContextOut (ctx, payLoad, sizeof(payLoad), TRUE);
    retval += UNITTEST_STATUS (20, status);
    if (0 < retval)
       goto exit;

    status = DIGI_CMS_finalizeContextOut (ctx);
    retval += UNITTEST_STATUS (21, status);
    if (0 < retval)
       goto exit;

    /* check size of callback buffer */
    retval += UNITTEST_TRUE (30, t->done);
    if (retval > 0)
        goto exit;

    retval += UNITTEST_TRUE (31, t->bufUsed > 0);
    if (retval > 0)
        goto exit;

    cmsLen = t->bufUsed;
    retval += DIGI_MALLOC((void **) &pCMS, cmsLen);
    if (retval > 0)
        goto exit;

    retval += DIGI_MEMCPY (pCMS, t->buf, cmsLen);
    if (retval > 0)
        goto exit;

    /* reset t */
    t->bufUsed = 0;
    t->bufMax = cmsLen + 1;
    if (NULL != t->buf)
    {
      DIGI_FREE((void **) &t->buf);
    }
    t->buf = MALLOC (t->bufMax);
    t->done = FALSE;

    if (isCertInline)
    {
        cb.getCertFun = &inlineCertCB;
        t->pCmsCtx = &verifyCtx;
    }
    else
    {
        cb.getCertFun = &certCB;
        cb.getCertFunV3 = &certCBV3;
        t->pCmsCtx = NULL;
    }
    cb.dataUpdateFun = &internal_verifyCallback2;
    cb.valCertFun = &dummyVerifyCert;

    status = DIGI_CMS_newContext (MOC_HW(gpHwAccelCtx)
                                  &verifyCtx,
                                  (void *) t,
                                  &cb);
    retval += UNITTEST_STATUS(32, status);
    if (retval > 0)
        goto exit;

    /* Read chunks and pass them into ASN1 parser for processing */
    retval += DIGI_MALLOC((void **) &buf, chunkSize);
    if (retval > 0)
        goto exit;

    while ((FALSE == finished) && (cmsLen > copied))
    {
        ubyte4 newData;

        /* Copy next chunk or the final byte(s) */
        if (chunkSize < (cmsLen - copied))
        {
          newData = chunkSize;
        }
        else
        {
          newData = cmsLen - copied;
        }
        DIGI_MEMCPY (buf, pCMS + copied, newData);

        /* Update parser */
        status = DIGI_CMS_updateContext (verifyCtx,
                                        buf, newData,
                                        &finished);

        retval += UNITTEST_STATUS (33, status);
        if (retval > 0)
            goto exit;
      

        copied += newData;
    }

    /* Check final status */
    retval += UNITTEST_TRUE (50, finished);
    if (retval > 0)
        goto exit;

    /* Check content type */
    status = DIGI_CMS_getContentType (verifyCtx,
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
    status = DIGI_CMS_getNumSigners(verifyCtx, &numSigners);
    retval += UNITTEST_STATUS (70, status);
    if (retval > 0)
        goto exit;

    retval += UNITTEST_INT (71, numSigners, 1);
    if (retval > 0)
        goto exit;

    status = DIGI_CMS_getSignerInfo (verifyCtx, 0, &info);
    retval += UNITTEST_STATUS (80, status);
    if (retval > 0)
        goto exit;

    retval += UNITTEST_TRUE (90, info.verifies);

    status = DIGI_CMS_deleteSignerInfo(&info);
    retval += UNITTEST_STATUS (91, status);

exit:

   DIGI_CMS_deleteContext(&verifyCtx);

   if (NULL != buf)
   {
       FREE (buf);
   }
   if (NULL != pCMS)
   {
      FREE (pCMS);
   }

    CRYPTO_uninitAsymmetricKey (&key, NULL);
    DIGI_FREE ((void**)&pCert);
    DIGI_CMS_deleteContext (&ctx);

    if (NULL != t)
    {
        DIGI_FREE ((void**)&(t->buf));
        DIGI_FREE ((void**)&t);
    }

    return retval;
}

/**************************************************************/

int crypto_interface_cms_test_init()
{
  MSTATUS status = ERR_NULL_POINTER;
  int errorCount = 0;

  InitMocanaSetupInfo setupInfo = { 0 };
  /**********************************************************
   *************** DO NOT USE MOC_NO_AUTOSEED ***************
   ***************** in any production code. ****************
   **********************************************************/
  setupInfo.flags = MOC_NO_AUTOSEED;

  status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
  if (OK != status)
  {
    errorCount = 1;
    goto exit;
  }

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
  status = (MSTATUS) HARDWARE_ACCEL_INIT();
  if (OK != status)
  {
      errorCount = 1;
      goto exit;
  }

  status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
  if (OK != status)
  {
      errorCount = 1;
      goto exit;
  }
#endif

/* can remove the !sig_oqs flag once oqs is updated with mldsa */
#if defined(__ENABLE_DIGICERT_PQC__) && !defined(__ENABLE_DIGICERT_SIG_OQS__)  
  gpCertForCallback = gpMldsa44_cert;
  errorCount += mocencode_cms_test_signTextDefinite("mldsa44_key.der", "mldsa44_cert.der", FALSE, FALSE);
  errorCount += mocencode_cms_test_signTextDefinite("mldsa44_key.der", "mldsa44_cert.der", TRUE, FALSE);
  
  gpCertForCallback = gpMldsa65_p256_cert;
  errorCount += mocencode_cms_test_signTextDefinite("mldsa65_p256.der", "mldsa65_p256_cert.der", FALSE, FALSE);
  errorCount += mocencode_cms_test_signTextDefinite("mldsa65_p256.der", "mldsa65_p256_cert.der", TRUE, FALSE);
#endif
  errorCount += mocencode_cms_test_signTextDefinite("rsa_key_ski.der", "rsa_cert_ski.der", FALSE, TRUE);

exit:

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
  HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
  HARDWARE_ACCEL_UNINIT();
#endif

  DIGICERT_free(&gpMocCtx);

  return errorCount;
}
