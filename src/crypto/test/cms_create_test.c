/*
 *  cms_create_test.c
 *
 *   unit test for cms.inc
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
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"
#include "../../common/absstream.h"
#include "../../common/mdefs.h"
#include "../../common/memfile.h"
#include "../../common/merrors.h"
#include "../../common/mrtos.h"
#include "../../common/mstdlib.h"
#include "../../common/random.h"
#include "../../common/tree.h"
#include "../../common/vlong.h"
#include "../../asn1/ASN1TreeWalker.h"
#include "../../asn1/derencoder.h"
#include "../../asn1/oiddefs.h"
#include "../../asn1/parseasn1.h"
#include "../../asn1/parsecert.h"
#include "../../crypto/arc2.h"
#include "../../crypto/arc4.h"
#include "../../crypto/pubcrypto.h" // because reasons...
#include "../../crypto/ca_mgmt.h"
#include "../../crypto/crypto.h"
#include "../../crypto/des.h"
#include "../../crypto/dsa2.h"
#include "../../crypto/md5.h"
#include "../../crypto/pkcs_common.h"
#include "../../crypto/primeec.h"
#include "../../crypto/primefld.h"
#include "../../crypto/rc2algo.h"
#include "../../crypto/rc4algo.h"
#include "../../crypto/rsa.h"
#include "../../crypto/secmod.h"
#include "../../crypto/sha1.h"
#include "../../crypto/sha256.h"
#include "../../crypto/sha512.h"
#include "../../crypto/three_des.h"
#define __IN_DIGICERT_C__     /* FOR TESTING PURPOSES --- ENABLES BASE64 init/free */
#include "../../common/base64.h"
#include "../../crypto/cms.h"
#include "../../crypto/pkcs7.h"

#include "../../crypto/test/cms_test.h" /* shared routines */


#include "../../../unit_tests/unittest.h"

#ifdef __ENABLE_DIGICERT_CMS__

extern const char* kCMSSampleData; /* in cms_test.c */

int decrypt_pkcs7_envelopedData( int hint, const char* file, const char* outFile,
                                const char* certFile, const char* keyFile);

typedef struct OutBufferInfo
{
    ubyte4 buffLen;
    ubyte* buff;
} OutBufferInfo;



/*---------------------------------------------------------------------------*/

const ubyte** CMSCreateRRNameArray( sbyte4 num, const ubyte* nullSepNames)
{
    const ubyte** retVal = NULL;
    sbyte4 i;

    if (num <= 0 || !nullSepNames)
    {
        return retVal;
    }

    retVal = MALLOC( num * sizeof( ubyte *));
    if (!retVal) return retVal;

    for (i = 0; i < num; ++i)
    {
        retVal[i] = nullSepNames;

        nullSepNames += DIGI_STRLEN((const sbyte*) nullSepNames) + 1;
    }

    return retVal;
}

/*---------------------------------------------------------------------------*/

#define CHUNK_SIZE (20)
static int cms_create_test_signed_1(int hint, ubyte4 flags, const char* outFile,
                                    RNGFun rngFun, void* arg,
                                    const char* certFile, const char* keyFile,
                                    ubyte pubKeyType, intBoolean detached,
                                    const CMS_TEST_RR_Info* pRRInfo,
                                    const CMS_TEST_RC_Info* pRCInfo)
{
    int i, slots, retVal = 0;
    CMS_signedDataContext myCtx = 0;
    CMS_signerInfo mySigner;
    ubyte4 len;
    ubyte* cert = 0;
    ubyte4 certLen;
    ubyte* keyBlob = 0;
    ubyte4 keyBlobLen;
    AsymmetricKey key;
    OutBufferInfo* outs = 0;
    ubyte4 totalLen;
    ubyte* totalOut = 0;
    const ubyte** from = 0;
    const ubyte** to = 0;
    hwAccelDescr hwAccelCtx;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    CRYPTO_initAsymmetricKey( &key);

    UNITTEST_STATUS_GOTO(hint, DIGICERT_readFile(certFile, &cert, &certLen), retVal, exit);

    /* read in signer private key */
    UNITTEST_STATUS_GOTO(hint, DIGICERT_readFile( keyFile, &keyBlob, &keyBlobLen),
                            retVal, exit);

    if (flags & e_cms_signer_version3) /* der file in these tests rather than keyblob */
    {
        UNITTEST_STATUS_GOTO(hint, CRYPTO_deserializeAsymKey(MOC_ASYM(hwAccelCtx) keyBlob, keyBlobLen, NULL, &key), retVal, exit);
    }
    else
    {
        UNITTEST_STATUS_GOTO(hint, CA_MGMT_extractKeyBlobEx(keyBlob, keyBlobLen, &key), retVal, exit);
    }

    UNITTEST_STATUS_GOTO(hint, CMS_signedNewContext( &myCtx,
                                                    pkcs7_data_OID,
                                                    detached, rngFun, arg), retVal, exit);


    /* add the certificate for signer explicitly */
    UNITTEST_STATUS_GOTO(hint, CMS_signedAddCertificate( myCtx, cert, certLen),
                            retVal, exit);

    /* add the signer */
    UNITTEST_STATUS_GOTO(hint, CMS_signedAddSigner( myCtx, cert, certLen, &key,
                                                    sha1_OID, flags, &mySigner),
                            retVal, exit);

    /* add receipt request */
    if (pRRInfo)
    {
        from = CMSCreateRRNameArray( pRRInfo->numFrom, pRRInfo->from);
        to = CMSCreateRRNameArray( pRRInfo->numTo, pRRInfo->to);
        UNITTEST_STATUS_GOTO( hint, CMS_signedAddReceiptRequest( MOC_HASH(hwAccelCtx) myCtx,
			                            from, pRRInfo->numFrom,
			                            to, pRRInfo->numTo),
                                retVal, exit);
    }
    else
    {
        /* add an authenticated attribute to the signer */
        UNITTEST_STATUS_GOTO(hint, CMS_signedAddSignerAttribute( myCtx, mySigner,
                                    pkcs9_emailAddress_OID,
                                    PRINTABLESTRING,
                                    (const ubyte*) "nobody@mocana.com", 17, 1),
                            retVal, exit);
    }

    /* update the context */
    len = DIGI_STRLEN( kCMSSampleData);

    slots = 1 + (len / CHUNK_SIZE);
    outs = MALLOC( sizeof(OutBufferInfo) * slots);
    UNITTEST_GOTO(UNITTEST_TRUE( hint, outs != 0), retVal, exit);
    DIGI_MEMSET( (ubyte*) outs, 0, sizeof(OutBufferInfo) * slots);

    for ( i = 0; i < slots - 1; ++i)
    {
        UNITTEST_STATUS_GOTO( hint, CMS_signedUpdateContext( MOC_ASYM(hwAccelCtx) myCtx,
                                                    kCMSSampleData + (i * CHUNK_SIZE),
                                                    CHUNK_SIZE,
                                                    &outs[i].buff, &outs[i].buffLen,
                                                    FALSE),
                                retVal, exit);
    }

    /* final 1 */
    UNITTEST_STATUS_GOTO( hint, CMS_signedUpdateContext( MOC_ASYM(hwAccelCtx) myCtx,
                                                    kCMSSampleData + (i * CHUNK_SIZE),
                                                    len - (i * CHUNK_SIZE),
                                                    &outs[i].buff, &outs[i].buffLen,
                                                    TRUE),
                                retVal, exit);

    /* consolidate everything */
    totalLen = 0;
    for ( i = 0; i < slots; ++i)
    {
        totalLen += outs[i].buffLen;
    }

    totalOut = MALLOC(totalLen);
    UNITTEST_GOTO(UNITTEST_TRUE( hint, totalOut != 0), retVal, exit);

    totalLen = 0;
    for ( i = 0; i < slots; ++i)
    {
        DIGI_MEMCPY( totalOut + totalLen, outs[i].buff, outs[i].buffLen);

        totalLen += outs[i].buffLen;
    }

    UNITTEST_STATUS_GOTO( hint, DIGICERT_writeFile(outFile, totalOut, totalLen),
                            retVal, exit);

    if (pRCInfo)
    {
        UNITTEST_STATUS_GOTO( hint, CMS_signedGetRequestInfo( myCtx, mySigner,
                                                            &pRCInfo->messageId,
                                                            &pRCInfo->messageIdLen,
                                                            &pRCInfo->digest,
                                                            &pRCInfo->digestLen,
                                                            &pRCInfo->signature,
                                                            &pRCInfo->signatureLen),
                            retVal, exit);
    }

    retVal += CMSSignedStreamTest(hint, outFile,
                                    certFile,
                                    FILE_PATH("DeBelloGallico.txt"), 1, 1, &certLen,
                                    ht_sha1, pubKeyType, detached, pRRInfo, pRCInfo,
                                    pkcs7_data_OID);
    if (retVal) goto exit;

exit:

    FREE(from);
    FREE(to);

    FREE( totalOut);

    if (outs)
    {
        for (i = 0; i < slots; ++i)
        {
            FREE( outs[i].buff);
        }
        FREE(outs);
    }

    FREE(cert);
    FREE(keyBlob);

    CMS_signedDeleteContext( MOC_HASH(hwAccelCtx) &myCtx);

    CRYPTO_uninitAsymmetricKey( &key, NULL);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;
}

/*---------------------------------------------------------------------------*/

static MSTATUS cms_do_sign_cb(void *pCbInfo, const ubyte* digestAlgoOID, ubyte *pDataToSign,
                             ubyte4 dataToSignLen, ubyte *pSigBuffer, ubyte4 sigBufferLen)
{
    MSTATUS status = OK;
    AsymmetricKey *pKey = (AsymmetricKey *) pCbInfo;
    vlong *r = NULL;
    vlong *s = NULL;
    PFEPtr sig_r = 0, sig_s = 0;
    PrimeFieldPtr pPF = { 0 };
    ubyte4 elementLen = 0;
    DER_ITEMPTR pDigestInfo = 0;
    ubyte* pDerDigestInfo = 0;
    ubyte4 derDigestInfoLen = 0;

    switch (0xffff & pKey->type)
    {
        case akt_rsa:

            if ( OK > ( status = RSA_getCipherTextLength(pKey->key.pRSA, (sbyte4 *) &elementLen)))
                goto exit;

            if (sigBufferLen < elementLen)
            {
                status = ERR_BUFFER_OVERFLOW;
                goto exit;
            }

            /* A signed Digest Info is expected */
            /* create a DigestInfo */
            if ( OK > ( status = DER_AddSequence ( NULL, &pDigestInfo)))
                goto exit;

            if ( OK > ( status = DER_StoreAlgoOID ( pDigestInfo, digestAlgoOID,
                                                    TRUE)))
            {
                goto exit;
            }
            /* if authenticated attributes is present, use second hash; else use pHash->hashData */

            if ( OK > ( status = DER_AddItem( pDigestInfo, OCTETSTRING,
                                              dataToSignLen, pDataToSign, NULL)))
            {
                goto exit;
            }

            if ( OK > ( status = DER_Serialize( pDigestInfo, &pDerDigestInfo,
                                                &derDigestInfoLen)))
            {
                goto exit;
            }

            if ( OK > ( status = RSA_signMessage(pKey->key.pRSA,
                           pDerDigestInfo, derDigestInfoLen, pSigBuffer, NULL)))
            {
                goto exit;
            }

            break;

        case akt_dsa:

            status = DSA_getSignatureLength (MOC_DSA(hwAccelCtx) pKey->key.pDSA, &elementLen);
            if (OK != status)
                goto exit;

            if (sigBufferLen < 2 * elementLen)
            {
                status = ERR_BUFFER_OVERFLOW;
                goto exit;
            }

            status = DSA_computeSignature2( RANDOM_rngFun, g_pRandomContext, pKey->key.pDSA, pDataToSign, dataToSignLen, &r, &s, NULL);
            if (OK != status)
                goto exit;

            /* write R */
            status = VLONG_fixedByteStringFromVlong (r, pSigBuffer, (sbyte4) elementLen);
            if (OK != status)
                goto exit;

            /* write S */
            status = VLONG_fixedByteStringFromVlong (s, pSigBuffer + elementLen, (sbyte4) elementLen);
            if (OK != status)
                goto exit;

            break;

        case akt_ecc:

            pPF = EC_getUnderlyingField( pKey->key.pECC->pCurve);

            if ( OK > ( status = PRIMEFIELD_getElementByteStringLen( pPF, &elementLen)))
                goto exit;

            if (sigBufferLen < 2 * elementLen)
            {
                status = ERR_BUFFER_OVERFLOW;
                goto exit;
            }

            if (OK > ( status = PRIMEFIELD_newElement( pPF, &sig_r)))
                goto exit;
            if (OK > ( status = PRIMEFIELD_newElement( pPF, &sig_s)))
                goto exit;

            status = ECDSA_signDigestAux( pKey->key.pECC->pCurve, pKey->key.pECC->k,
                                          RANDOM_rngFun, g_pRandomContext,
                                          pDataToSign, dataToSignLen,
                                          sig_r, sig_s);
            if (OK != status)
                goto exit;

            /* write R */
            if ( OK > ( status = PRIMEFIELD_writeByteString( pPF, sig_r, pSigBuffer, elementLen)))
                goto exit;

            /* write S */
            if ( OK > ( status = PRIMEFIELD_writeByteString( pPF, sig_s, pSigBuffer + elementLen, elementLen)))
                goto exit;

            break;

        default:
            status = ERR_BAD_KEY_TYPE;
    }

exit:

    if (pDerDigestInfo)
    {
        (void) DIGI_FREE((void **) &pDerDigestInfo);
    }

    if (pDigestInfo)
    {
        (void) TREE_DeleteTreeItem( (TreeItem*) pDigestInfo);
    }

    VLONG_freeVlong(&r, NULL);
    VLONG_freeVlong(&s, NULL);

    PRIMEFIELD_deleteElement( pPF, &sig_r);
    PRIMEFIELD_deleteElement( pPF, &sig_s);

    return status;
}

/*---------------------------------------------------------------------------*/

static int cms_create_test_signed_w_cb(int hint, ubyte4 flags, const char* outFile,
                                       RNGFun rngFun, void* arg,
                                       const char* certFile, const char* keyFile,
                                       ubyte pubKeyType, intBoolean detached,
                                       const CMS_TEST_RR_Info* pRRInfo,
                                       const CMS_TEST_RC_Info* pRCInfo)
{
    int i, slots, retVal = 0;
    CMS_signedDataContext myCtx = 0;
    CMS_signerInfo mySigner;
    ubyte4 len;
    ubyte* cert = 0;
    ubyte4 certLen;
    ubyte* keyBlob = 0;
    ubyte4 keyBlobLen;
    AsymmetricKey key;
    OutBufferInfo* outs = 0;
    ubyte4 totalLen;
    ubyte* totalOut = 0;
    const ubyte** from = 0;
    const ubyte** to = 0;
    hwAccelDescr hwAccelCtx;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    CRYPTO_initAsymmetricKey( &key);

    UNITTEST_STATUS_GOTO(hint, DIGICERT_readFile(certFile, &cert, &certLen), retVal, exit);

    /* read in signer private key */
    UNITTEST_STATUS_GOTO(hint, DIGICERT_readFile( keyFile, &keyBlob, &keyBlobLen),
                            retVal, exit);

    if (flags & e_cms_signer_version3) /* der file in these tests rather than keyblob */
    {
        UNITTEST_STATUS_GOTO(hint, CRYPTO_deserializeAsymKey(MOC_ASYM(hwAccelCtx) keyBlob, keyBlobLen, NULL, &key), retVal, exit);
    }
    else
    {
        UNITTEST_STATUS_GOTO(hint, CA_MGMT_extractKeyBlobEx(keyBlob, keyBlobLen, &key), retVal, exit);
    }

    UNITTEST_STATUS_GOTO(hint, CMS_signedNewContext( &myCtx,
                                                    pkcs7_data_OID,
                                                    detached, rngFun, arg), retVal, exit);


    /* add the certificate for signer explicitly */
    UNITTEST_STATUS_GOTO(hint, CMS_signedAddCertificate( myCtx, cert, certLen),
                            retVal, exit);


    /* add the signer */
    UNITTEST_STATUS_GOTO(hint, CMS_signedAddSignerWithCallback( myCtx, cert, certLen,
                                                                (CMS_SignData) cms_do_sign_cb,
                                                                (void *) &key,
                                                                sha1_OID, flags, &mySigner),
                            retVal, exit);

    /* add receipt request */
    if (pRRInfo)
    {
        from = CMSCreateRRNameArray( pRRInfo->numFrom, pRRInfo->from);
        to = CMSCreateRRNameArray( pRRInfo->numTo, pRRInfo->to);
        UNITTEST_STATUS_GOTO( hint, CMS_signedAddReceiptRequest( MOC_HASH(hwAccelCtx) myCtx,
			                            from, pRRInfo->numFrom,
			                            to, pRRInfo->numTo),
                                retVal, exit);
    }
    else
    {
        /* add an authenticated attribute to the signer */
        UNITTEST_STATUS_GOTO(hint, CMS_signedAddSignerAttribute( myCtx, mySigner,
                                    pkcs9_emailAddress_OID,
                                    PRINTABLESTRING,
                                    (const ubyte*) "nobody@mocana.com", 17, 1),
                            retVal, exit);
    }

    /* update the context */
    len = DIGI_STRLEN( kCMSSampleData);

    slots = 1 + (len / CHUNK_SIZE);
    outs = MALLOC( sizeof(OutBufferInfo) * slots);
    UNITTEST_GOTO(UNITTEST_TRUE( hint, outs != 0), retVal, exit);
    DIGI_MEMSET( (ubyte*) outs, 0, sizeof(OutBufferInfo) * slots);

    for ( i = 0; i < slots - 1; ++i)
    {
        UNITTEST_STATUS_GOTO( hint, CMS_signedUpdateContext( MOC_ASYM(hwAccelCtx) myCtx,
                                                    kCMSSampleData + (i * CHUNK_SIZE),
                                                    CHUNK_SIZE,
                                                    &outs[i].buff, &outs[i].buffLen,
                                                    FALSE),
                                retVal, exit);
    }

    /* final 1 */
    UNITTEST_STATUS_GOTO( hint, CMS_signedUpdateContext( MOC_ASYM(hwAccelCtx) myCtx,
                                                    kCMSSampleData + (i * CHUNK_SIZE),
                                                    len - (i * CHUNK_SIZE),
                                                    &outs[i].buff, &outs[i].buffLen,
                                                    TRUE),
                                retVal, exit);

    /* consolidate everything */
    totalLen = 0;
    for ( i = 0; i < slots; ++i)
    {
        totalLen += outs[i].buffLen;
    }

    totalOut = MALLOC(totalLen);
    UNITTEST_GOTO(UNITTEST_TRUE( hint, totalOut != 0), retVal, exit);

    totalLen = 0;
    for ( i = 0; i < slots; ++i)
    {
        DIGI_MEMCPY( totalOut + totalLen, outs[i].buff, outs[i].buffLen);

        totalLen += outs[i].buffLen;
    }

    UNITTEST_STATUS_GOTO( hint, DIGICERT_writeFile(outFile, totalOut, totalLen),
                            retVal, exit);

    if (pRCInfo)
    {
        UNITTEST_STATUS_GOTO( hint, CMS_signedGetRequestInfo( myCtx, mySigner,
                                                            &pRCInfo->messageId,
                                                            &pRCInfo->messageIdLen,
                                                            &pRCInfo->digest,
                                                            &pRCInfo->digestLen,
                                                            &pRCInfo->signature,
                                                            &pRCInfo->signatureLen),
                            retVal, exit);
    }

    retVal += CMSSignedStreamTest(hint, outFile,
                                    certFile,
                                    FILE_PATH("DeBelloGallico.txt"), 1, 1, &certLen,
                                    ht_sha1, pubKeyType, detached, pRRInfo, pRCInfo,
                                    pkcs7_data_OID);
    if (retVal) goto exit;

exit:

    FREE(from);
    FREE(to);

    FREE( totalOut);

    if (outs)
    {
        for (i = 0; i < slots; ++i)
        {
            FREE( outs[i].buff);
        }
        FREE(outs);
    }

    FREE(cert);
    FREE(keyBlob);

    CMS_signedDeleteContext( MOC_HASH(hwAccelCtx) &myCtx);

    CRYPTO_uninitAsymmetricKey( &key, NULL);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;
}
#endif


/*---------------------------------------------------------------------------*/

int cms_create_test_signed()
{
    int retVal = 0;

#ifdef __ENABLE_DIGICERT_CMS__
    CMS_TEST_RR_Info rrInfo;
    CMS_TEST_RC_Info rsaRCInfo = { 0 };
    CMS_TEST_RC_Info eccRCInfo = { 0 };
    CMS_TEST_RC_Info dsaRCInfo = { 0 };
    ubyte* rsaKeyBlob = 0;
    ubyte4 rsaKeyBlobLen;
    ubyte* eccKeyBlob = 0;
    ubyte4 eccKeyBlobLen;
    ubyte* dsaKeyBlob = 0;
    ubyte4 dsaKeyBlobLen;

    retVal += UNITTEST_STATUS( 0, DIGICERT_initDigicert());
    if (retVal) goto exit;

    dsaRCInfo.rngFun = eccRCInfo.rngFun = rsaRCInfo.rngFun = RANDOM_rngFun;
    dsaRCInfo.rngFunArg = eccRCInfo.rngFunArg = rsaRCInfo.rngFunArg = g_pRandomContext;

    /* RSA Cert and key */
    UNITTEST_STATUS_GOTO(0,
                        DIGICERT_readFile(FILE_PATH("selfcert.der"),
                                        &rsaRCInfo.signerCert,
                                        &rsaRCInfo.signerCertLen),
                        retVal, exit);

    /* read in signer private key */
    UNITTEST_STATUS_GOTO(0,
                        DIGICERT_readFile( FILE_PATH("keyblobFile.dat"),
                                        &rsaKeyBlob, &rsaKeyBlobLen),
                        retVal, exit);


    UNITTEST_STATUS_GOTO(0,
                        CA_MGMT_extractKeyBlobEx(rsaKeyBlob, rsaKeyBlobLen,
                                                    &rsaRCInfo.key),
                        retVal, exit);

    /* ECC Cert and key */
    UNITTEST_STATUS_GOTO(0,
                        DIGICERT_readFile(FILE_PATH("ecc_selfcert.der"),
                                        &eccRCInfo.signerCert,
                                        &eccRCInfo.signerCertLen),
                        retVal, exit);

    /* read in signer private key */
    UNITTEST_STATUS_GOTO(0,
                        DIGICERT_readFile( FILE_PATH("ecc_keyblobFile.dat"),
                                        &eccKeyBlob, &eccKeyBlobLen),
                        retVal, exit);


    UNITTEST_STATUS_GOTO(0,
                        CA_MGMT_extractKeyBlobEx(eccKeyBlob, eccKeyBlobLen,
                                                    &eccRCInfo.key),
                        retVal, exit);

    /* DSA Cert and key */
    UNITTEST_STATUS_GOTO(0,
                        DIGICERT_readFile(FILE_PATH("dsacert.der"),
                                        &dsaRCInfo.signerCert,
                                        &dsaRCInfo.signerCertLen),
                        retVal, exit);

    /* read in signer private key */
    UNITTEST_STATUS_GOTO(0,
                        DIGICERT_readFile( FILE_PATH("dsa_keyblobFile.dat"),
                                        &dsaKeyBlob, &dsaKeyBlobLen),
                        retVal, exit);


    UNITTEST_STATUS_GOTO(0,
                        CA_MGMT_extractKeyBlobEx(dsaKeyBlob, dsaKeyBlobLen,
                                                    &dsaRCInfo.key),
                        retVal, exit);


    retVal += cms_create_test_signed_1(0, 0, FILE_PATH("cms_signed_rsa.der"),
                                    RANDOM_rngFun, g_pRandomContext,
                                    FILE_PATH("selfcert.der"),
                                    FILE_PATH("keyblobFile.dat"),
                                    akt_rsa, 0, NULL, NULL);

    retVal += cms_create_test_signed_w_cb(0, 0, FILE_PATH("cms_signed_rsa.der"),
                                          RANDOM_rngFun, g_pRandomContext,
                                          FILE_PATH("selfcert.der"),
                                          FILE_PATH("keyblobFile.dat"),
                                          akt_rsa, 0, NULL, NULL);


    retVal += cms_create_test_signed_1(1, 0, FILE_PATH("cms_signed_ecc.der"),
                                    RANDOM_rngFun, g_pRandomContext,
                                    FILE_PATH("ecc_selfcert.der"),
                                    FILE_PATH("ecc_keyblobFile.dat"),
                                    akt_ecc, 0, NULL, NULL);

    retVal += cms_create_test_signed_w_cb(1, 0, FILE_PATH("cms_signed_ecc.der"),
                                          RANDOM_rngFun, g_pRandomContext,
                                          FILE_PATH("ecc_selfcert.der"),
                                          FILE_PATH("ecc_keyblobFile.dat"),
                                          akt_ecc, 0, NULL, NULL);

    retVal += cms_create_test_signed_1(2, 0, FILE_PATH("cms_detached_signed_rsa.der"),
                                    RANDOM_rngFun, g_pRandomContext,
                                    FILE_PATH("selfcert.der"),
                                    FILE_PATH("keyblobFile.dat"),
                                    akt_rsa, 1, NULL, NULL);

    retVal += cms_create_test_signed_w_cb(2, 0,FILE_PATH("cms_detached_signed_rsa.der"),
                                          RANDOM_rngFun, g_pRandomContext,
                                          FILE_PATH("selfcert.der"),
                                          FILE_PATH("keyblobFile.dat"),
                                          akt_rsa, 1, NULL, NULL);

    retVal += cms_create_test_signed_1(3, 0, FILE_PATH("cms_detached_signed_ecc.der"),
                                    RANDOM_rngFun, g_pRandomContext,
                                    FILE_PATH("ecc_selfcert.der"),
                                    FILE_PATH("ecc_keyblobFile.dat"),
                                    akt_ecc, 1, NULL, NULL);

    retVal += cms_create_test_signed_w_cb(3, 0, FILE_PATH("cms_detached_signed_ecc.der"),
                                          RANDOM_rngFun, g_pRandomContext,
                                          FILE_PATH("ecc_selfcert.der"),
                                          FILE_PATH("ecc_keyblobFile.dat"),
                                          akt_ecc, 1, NULL, NULL);
    rrInfo.numFrom = -1;
    rrInfo.from = 0;
    rrInfo.numTo = 1;
    rrInfo.to = "fferino@mocana.com\0";

    retVal += cms_create_test_signed_1(4, 0, FILE_PATH("cms_detached_signed_rsa_rr_all.der"),
                                    RANDOM_rngFun, g_pRandomContext,
                                    FILE_PATH("selfcert.der"),
                                    FILE_PATH("keyblobFile.dat"),
                                    akt_rsa, 1, &rrInfo, &eccRCInfo);

    retVal += cms_create_test_signed_1(5, 0, FILE_PATH("cms_detached_signed_ecc_rr_all.der"),
                                    RANDOM_rngFun, g_pRandomContext,
                                    FILE_PATH("ecc_selfcert.der"),
                                    FILE_PATH("ecc_keyblobFile.dat"),
                                    akt_ecc, 1, &rrInfo, &dsaRCInfo);

    retVal += cms_create_test_signed_1(6, 0, FILE_PATH("cms_detached_signed_dsa_rr_all.der"),
                                    RANDOM_rngFun, g_pRandomContext,
                                    FILE_PATH("dsacert.der"),
                                    FILE_PATH("dsa_keyblobFile.dat"),
                                    akt_dsa, 1, &rrInfo, &rsaRCInfo);

    retVal += cms_create_test_signed_w_cb(6, 0, FILE_PATH("cms_detached_signed_dsa_rr_all.der"),
                                          RANDOM_rngFun, g_pRandomContext,
                                          FILE_PATH("dsacert.der"),
                                          FILE_PATH("dsa_keyblobFile.dat"),
                                          akt_dsa, 1, &rrInfo, &rsaRCInfo);

    rrInfo.numFrom = 0;
    rrInfo.from = 0;
    rrInfo.numTo = 1;
    rrInfo.to = "fferino@mocana.com\0";
    retVal += cms_create_test_signed_1(7, 0, FILE_PATH("cms_detached_signed_rsa_rr_first.der"),
                                    RANDOM_rngFun, g_pRandomContext,
                                    FILE_PATH("selfcert.der"),
                                    FILE_PATH("keyblobFile.dat"),
                                    akt_rsa, 1, &rrInfo, &eccRCInfo);

    retVal += cms_create_test_signed_1(8, 0, FILE_PATH("cms_detached_signed_ecc_rr_first.der"),
                                    RANDOM_rngFun, g_pRandomContext,
                                    FILE_PATH("ecc_selfcert.der"),
                                    FILE_PATH("ecc_keyblobFile.dat"),
                                    akt_ecc, 1, &rrInfo, &dsaRCInfo);

    retVal += cms_create_test_signed_1(9, 0, FILE_PATH("cms_detached_signed_dsa_rr_first.der"),
                                    RANDOM_rngFun, g_pRandomContext,
                                    FILE_PATH("dsacert.der"),
                                    FILE_PATH("dsa_keyblobFile.dat"),
                                    akt_dsa, 1, &rrInfo, &rsaRCInfo);

    rrInfo.numFrom = 1;
    rrInfo.from = "fabrice@mocana.com\0";
    rrInfo.numTo = 1;
    rrInfo.to = "fferino@mocana.com\0";
    retVal += cms_create_test_signed_1(10, 0, FILE_PATH("cms_detached_signed_rsa_rr_fabrice.der"),
                                    RANDOM_rngFun, g_pRandomContext,
                                    FILE_PATH("selfcert.der"),
                                    FILE_PATH("keyblobFile.dat"),
                                    akt_rsa, 1, &rrInfo, &eccRCInfo);

    retVal += cms_create_test_signed_1(11, 0, FILE_PATH("cms_detached_signed_ecc_rr_fabrice.der"),
                                    RANDOM_rngFun, g_pRandomContext,
                                    FILE_PATH("ecc_selfcert.der"),
                                    FILE_PATH("ecc_keyblobFile.dat"),
                                    akt_ecc, 1, &rrInfo, &dsaRCInfo);

    retVal += cms_create_test_signed_1(12, 0, FILE_PATH("cms_detached_signed_dsa_rr_fabrice.der"),
                                    RANDOM_rngFun, g_pRandomContext,
                                    FILE_PATH("dsacert.der"),
                                    FILE_PATH("dsa_keyblobFile.dat"),
                                    akt_dsa, 1, &rrInfo, &rsaRCInfo);

    rrInfo.numFrom = 1;
    rrInfo.from = "fabrice@mocana.com\0";
    rrInfo.numTo = 3;
    rrInfo.to = "fferino@mocana.com\0eng@mocana.com\0support@mocana.com\0";
    retVal += cms_create_test_signed_1(13, 0, FILE_PATH("cms_detached_signed_rsa_rr_mult_to.der"),
                                    RANDOM_rngFun, g_pRandomContext,
                                    FILE_PATH("selfcert.der"),
                                    FILE_PATH("keyblobFile.dat"),
                                    akt_rsa, 1, &rrInfo, &eccRCInfo);

    retVal += cms_create_test_signed_1(14, 0, FILE_PATH("cms_detached_signed_ecc_rr_mult_to.der"),
                                    RANDOM_rngFun, g_pRandomContext,
                                    FILE_PATH("ecc_selfcert.der"),
                                    FILE_PATH("ecc_keyblobFile.dat"),
                                    akt_ecc, 1, &rrInfo, &dsaRCInfo);

    retVal += cms_create_test_signed_1(15, 0, FILE_PATH("cms_detached_signed_dsa_rr_mult_to.der"),
                                    RANDOM_rngFun, g_pRandomContext,
                                    FILE_PATH("dsacert.der"),
                                    FILE_PATH("dsa_keyblobFile.dat"),
                                    akt_dsa, 1, &rrInfo, &rsaRCInfo);

    rrInfo.numFrom = 2;
    rrInfo.from = "fabrice@mocana.com\0sales@mocana.com\0";
    rrInfo.numTo = 3;
    rrInfo.to = "fferino@mocana.com\0eng@mocana.com\0support@mocana.com\0";
    retVal += cms_create_test_signed_1(16, 0, FILE_PATH("cms_detached_signed_rsa_rr_mult_from_to.der"),
                                    RANDOM_rngFun, g_pRandomContext,
                                    FILE_PATH("selfcert.der"),
                                    FILE_PATH("keyblobFile.dat"),
                                    akt_rsa, 1, &rrInfo, &eccRCInfo);

    retVal += cms_create_test_signed_1(17, 0, FILE_PATH("cms_detached_signed_ecc_rr_mult_from_to.der"),
                                    RANDOM_rngFun, g_pRandomContext,
                                    FILE_PATH("ecc_selfcert.der"),
                                    FILE_PATH("ecc_keyblobFile.dat"),
                                    akt_ecc, 1, &rrInfo, &dsaRCInfo);

    retVal += cms_create_test_signed_1(18, 0, FILE_PATH("cms_detached_signed_dsa_rr_mult_from_to.der"),
                                    RANDOM_rngFun, g_pRandomContext,
                                    FILE_PATH("dsacert.der"),
                                    FILE_PATH("dsa_keyblobFile.dat"),
                                    akt_dsa, 1, &rrInfo, &rsaRCInfo);

    /* version3, subjectKeyIdentifier Cert lookup */
    retVal += cms_create_test_signed_1(19, e_cms_signer_version3, FILE_PATH("cms_signed_rsa_ski2.der"),
                                    RANDOM_rngFun, g_pRandomContext,
                                    FILE_PATH("rsa_cert_ski.der"),
                                    FILE_PATH("rsa_key_ski.der"),
                                    akt_rsa, 0, NULL, NULL);

    retVal += cms_create_test_signed_w_cb(20, e_cms_signer_version3, FILE_PATH("cms_signed_rsa_ski_cb.der"),
                                    RANDOM_rngFun, g_pRandomContext,
                                    FILE_PATH("rsa_cert_ski.der"),
                                    FILE_PATH("rsa_key_ski.der"),
                                    akt_rsa, 0, NULL, NULL);

exit:

    FREE(rsaKeyBlob);
    FREE( rsaRCInfo.signerCert);
    CRYPTO_uninitAsymmetricKey( &rsaRCInfo.key, NULL);

    FREE(eccKeyBlob);
    FREE( eccRCInfo.signerCert);
    CRYPTO_uninitAsymmetricKey( &eccRCInfo.key, NULL);

    FREE(dsaKeyBlob);
    FREE( dsaRCInfo.signerCert);
    CRYPTO_uninitAsymmetricKey( &dsaRCInfo.key, NULL);

    DIGICERT_freeDigicert();

#endif

    return retVal;

}

#ifdef __ENABLE_DIGICERT_CMS__


/*---------------------------------------------------------------------------*/

int cms_create_test_enveloped_chunk(int hint, int chunkSize,
                                    const ubyte* oid,
                                    const ubyte* cert,
                                    ubyte4 certLen, RNGFun rngFun,
                                    void* rngArg,
                                    const char* outFile)
{
    int i, retVal = 0;
    CMS_envelopedDataContext myCtx = 0;
    ubyte4 len, slots, totalLen;
    OutBufferInfo* outs = 0;
    ubyte* totalOut = 0;
    hwAccelDescr hwAccelCtx;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    UNITTEST_STATUS_GOTO( hint,
                            CMS_envelopedNewContext(&myCtx, oid,
                                                    rngFun, rngArg),
                            retVal, exit);

    UNITTEST_STATUS_GOTO( hint,
                            CMS_envelopedAddRecipient( myCtx, cert, certLen),
                            retVal, exit);

    /* update the context */
    len = DIGI_STRLEN( kCMSSampleData);

    slots = 1 + (len / chunkSize);
    outs = MALLOC( sizeof(OutBufferInfo) * slots);
    UNITTEST_GOTO(UNITTEST_TRUE( hint, outs != 0), retVal, exit);
    DIGI_MEMSET( (ubyte*) outs, 0, sizeof(OutBufferInfo) * slots);

    for ( i = 0; i < slots - 1; ++i)
    {
        UNITTEST_STATUS_GOTO( hint, CMS_envelopedUpdateContext( MOC_RSA(hwAccelCtx) myCtx,
                                                    kCMSSampleData + (i * chunkSize),
                                                    chunkSize,
                                                    &outs[i].buff, &outs[i].buffLen,
                                                    FALSE),
                                retVal, exit);
    }

    /* final 1 */
    UNITTEST_STATUS_GOTO( hint, CMS_envelopedUpdateContext( MOC_RSA(hwAccelCtx) myCtx,
                                                    kCMSSampleData + (i * chunkSize),
                                                    len - (i * chunkSize),
                                                    &outs[i].buff, &outs[i].buffLen,
                                                    TRUE),
                                retVal, exit);

    /* consolidate everything */
    totalLen = 0;
    for ( i = 0; i < slots; ++i)
    {
        totalLen += outs[i].buffLen;
    }

    totalOut = MALLOC(totalLen);
    UNITTEST_GOTO(UNITTEST_TRUE( hint, totalOut != 0), retVal, exit);

    totalLen = 0;
    for ( i = 0; i < slots; ++i)
    {
        DIGI_MEMCPY( totalOut + totalLen, outs[i].buff, outs[i].buffLen);

        totalLen += outs[i].buffLen;
    }

    UNITTEST_STATUS_GOTO( hint, DIGICERT_writeFile(outFile, totalOut, totalLen),
                            retVal, exit);


exit:

    FREE(totalOut);

    if (outs)
    {
        for (i = 0; i < slots; ++i)
        {
            FREE( outs[i].buff);
        }
        FREE(outs);
    }

    CMS_envelopedDeleteContext( MOC_SYM(hwAccelCtx) &myCtx);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;
}


/*---------------------------------------------------------------------------*/

int cms_create_test_enveloped_1(int hint, const char* outFile,
                                RNGFun rngFun, void* rngArg,
                                const char* recipientCert,
                                const char* recipientKey,
                                ubyte keyType)
{
    int i, retVal = 0;
    ubyte* cert = 0;
    ubyte4 certLen;
    ubyte4 fileNameLen;
    char* outFileName = 0;

    fileNameLen = DIGI_STRLEN( outFile);

    outFileName = MALLOC(fileNameLen + 5);
    UNITTEST_GOTO(UNITTEST_TRUE( hint, outFileName != 0), retVal, exit);

    DIGI_MEMCPY( outFileName, outFile, fileNameLen);

    UNITTEST_STATUS_GOTO(hint, DIGICERT_readFile(recipientCert, &cert, &certLen),
                            retVal, exit);

    for (i = 1; retVal == 0 && i < 20; ++i)
    {
        ubyte* last = DIGI_LTOA( i, outFileName + fileNameLen, 5);
        *last = 0;
        retVal += cms_create_test_enveloped_chunk(((hint<< 8) | i), i,
                                    aes128CBC_OID, cert, certLen,
                                    rngFun, rngArg, outFileName);
        retVal += CMSEnvStreamTest( ((hint<< 8) | i), outFileName,
                                    recipientCert,
                                    recipientKey,
                                    FILE_PATH("DeBelloGallico.txt"),
                                    1, 0, aes128CBC_OID, pkcs7_data_OID);
    }

exit:

    FREE(cert);

    FREE(outFileName);

    return retVal;
}
#endif


/*---------------------------------------------------------------------------*/

int cms_create_test_enveloped()
{
    int retVal = 0;

#ifdef __ENABLE_DIGICERT_CMS__

    retVal += UNITTEST_STATUS( 0, DIGICERT_initDigicert());
    if (retVal) goto exit;

    retVal += cms_create_test_enveloped_1(0, FILE_PATH("cms_enveloped_rsa.der"),
                                    RANDOM_rngFun, g_pRandomContext,
                                    FILE_PATH("selfcert.der"),
                                    FILE_PATH("keyblobFile.dat"),
                                    akt_rsa);

exit:

    DIGICERT_freeDigicert();
#endif

    return retVal;
}
