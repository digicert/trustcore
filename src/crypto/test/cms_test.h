/*
 * cms_test.h
 *
 * CMS test routines shared across test files
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
 *
 */

#ifndef __CMS_TEST_HEADER__
#define __CMS_TEST_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __ENABLE_DIGICERT_CMS__

int CMSEnvStreamTest( int hint, const char* pkcs7FileName,
                        const char* certFileName,
                        const char* keyBlobFileName,
                        const char* dataFileName,
                        int expectedNumRecipients,
                        int expectedRecipient,
                        const ubyte* expEncryptionAlgoOID,
                        const ubyte* eContentType);

typedef struct CMS_TEST_RR_Info
{
    sbyte4 numFrom;
    const ubyte* from;
    sbyte4 numTo;
    const ubyte* to;
} CMS_TEST_RR_Info;

typedef struct CMS_TEST_RC_Info
{
    RNGFun          rngFun;
    void*           rngFunArg;
    ubyte*          signerCert;
    ubyte4          signerCertLen;
    AsymmetricKey   key;
    ubyte*          messageId;
    ubyte4          messageIdLen;
    ubyte*          digest;
    ubyte4          digestLen;
    ubyte*          signature;
    ubyte4          signatureLen;
} CMS_TEST_RC_Info;


int CMSSignedStreamTest( int hint, const char* pkcs7FileName,
                        const char* certFileName,
                        const char* dataFileName,
                        sbyte4 expectedNumSigners,
                        sbyte4 expectedNumCerts, 
                        sbyte4 lengthCerts[/* expectedNumCerts*/],
                        ubyte hashType, ubyte pubKeyType, 
                        ubyte expectedDetached,
                        const CMS_TEST_RR_Info* receiptRequestInfo,                       
                        const CMS_TEST_RC_Info* receiptCreateInfo,
                        const ubyte* eContentTypeOID);

#endif

#ifdef __cplusplus
}
#endif

#endif  /*#ifndef __CMS_TEST_HEADER__ */
