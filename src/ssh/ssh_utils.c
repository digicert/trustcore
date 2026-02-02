/*
 * ssh_utils.c
 *
 * Utility code for storing and retrieving keys
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

#include "../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_SSH_SERVER__))

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/secmod.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../common/memory_debug.h"
#include "../crypto/crypto.h"
#include "../common/base64.h"
#ifdef __ENABLE_DIGICERT_DSA__
#include "../crypto/dsa.h"
#endif
#include "../crypto/rsa.h"
#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#include "../crypto/ecc.h"
#endif
#include "../crypto/pubcrypto.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../common/sizedbuffer.h"
#include "../crypto/cert_store.h"
#include "../ssh/ssh_str.h"
#include "../ssh/ssh_str_house.h"
#include "../ssh/ssh_utils.h"
#include "../ssh/ssh.h"
#include "../ssh/ssh_mpint.h"
#include "../ssh/ssh_key.h"
#include "../harness/harness.h"
#ifdef __ENABLE_DIGICERT_DER_CONVERSION__
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../common/tree.h"
#include "../asn1/parseasn1.h"
#include "../asn1/ASN1TreeWalker.h"
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_rsa.h"
#include "../crypto_interface/crypto_interface_ecc.h"
#endif

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SSH_OLD_DSA_CONVERSION__) && defined(__ENABLE_DIGICERT_DSA__))
extern MSTATUS
SSH_UTILS_extractKeyBlob(ubyte *pKeyBlob, ubyte4 keyBlobLength,
                         ubyte4 keyType, DSAKey *p_dsaDescr)
{
    ubyte4  index;
    MSTATUS status = OK;

    if (0 == keyBlobLength)
    {
        status = ERR_BAD_KEY_BLOB;
        goto exit;
    }

    if (SSH_PRIVATE_KEY_BLOB == keyType)
    {
        /* x */
        index = 0;
        if (OK > (status = VLONG_newFromMpintBytes(pKeyBlob, keyBlobLength, &(DSA_X(p_dsaDescr)), &index, NULL)))
            goto exit;

        if (0 != keyBlobLength - index)
        {
            status = ERR_BAD_KEY_BLOB;
            goto exit;
        }
    }

    if (SSH_PUBLIC_KEY_BLOB == keyType)
    {
        /* p */
        index = 0;
        if (OK > (status = VLONG_newFromMpintBytes(pKeyBlob, keyBlobLength, &(DSA_P(p_dsaDescr)), &index, NULL)))
            goto exit;

        pKeyBlob += index;
        if (0 >= (sbyte4)(keyBlobLength = (keyBlobLength - index)))
        {
            status = ERR_BAD_KEY_BLOB;
            goto exit;
        }

        /* q */
        if (OK > (status = VLONG_newFromMpintBytes(pKeyBlob, keyBlobLength, &(DSA_Q(p_dsaDescr)), &index, NULL)))
            goto exit;

        pKeyBlob += index;
        if (0 >= (sbyte4)(keyBlobLength = (keyBlobLength - index)))
        {
            status = ERR_BAD_KEY_BLOB;
            goto exit;
        }

        /* g */
        if (OK > (status = VLONG_newFromMpintBytes(pKeyBlob, keyBlobLength, &(DSA_G(p_dsaDescr)), &index, NULL)))
            goto exit;

        pKeyBlob += index;
        if (0 >= (sbyte4)(keyBlobLength = (keyBlobLength - index)))
        {
            status = ERR_BAD_KEY_BLOB;
            goto exit;
        }

        /* y */
        if (OK > (status = VLONG_newFromMpintBytes(pKeyBlob, keyBlobLength, &(DSA_Y(p_dsaDescr)), &index, NULL)))
            goto exit;

        if (0 != keyBlobLength - index)
        {
            status = ERR_BAD_KEY_BLOB;
        }
    }

exit:
    return status;

} /* SSH_UTILS_extractKeyBlob */

#endif /* (defined(__ENABLE_DIGICERT_SSH_OLD_DSA_CONVERSION__) && defined(__ENABLE_DIGICERT_DSA__)) */


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_UTILS_sshParseAuthPublicKeyFile(sbyte* pKeyFile, ubyte4 fileSize,
                                    AsymmetricKey *p_keyDescr)
{
    return SSH_KEY_sshParseAuthPublicKeyFile(pKeyFile, fileSize, p_keyDescr);
} /* SSH_UTILS_sshParseAuthPublicKeyFile */


#if !defined(__DISABLE_DIGICERT_KEY_GENERATION__)

/*------------------------------------------------------------------*/

extern MSTATUS
SSH_publicKeyFingerPrints(ubyte *pKeyBlob, ubyte4 keyBlobLength,
                          ubyte *pRetMd5FingerPrint, ubyte *pRetSha1FingerPrint)
{
    /* generate host key finger print */
    sshStringBuffer *pTempSignature;
    ubyte4          publicKeyBlobLen;
    ubyte*          pPublicKeyBlob = NULL;
    ubyte4          keyType;
    ubyte4          curveId;
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status;

    if (NULL == pKeyBlob)
    {
        status = ERR_NULL_POINTER;
        goto nocleanup;
    }

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSH, &hwAccelCtx)))
        goto nocleanup;

    /* extract public key from our key blob */
    if (OK > (status = SSH_KEY_extractPublicKey(MOC_ASYM(hwAccelCtx) pKeyBlob, keyBlobLength, &pPublicKeyBlob, &publicKeyBlobLen, &keyType, &curveId, NULL)))
        goto exit;

    switch(keyType)
    {
        case akt_dsa:
        {
            pTempSignature = &ssh_dss_signature;
            break;
        }
        case akt_rsa:
        {
            pTempSignature = &ssh_rsa_signature;
            break;
        }
        case akt_ecc:
        {
            pTempSignature = &ssh_ecdsa_signature;
            break;
        }
        case akt_ecc_ed:
        {
            pTempSignature = &ssh_ecdsa_signature_ed25519;
            break;
        }
        default:
            status = ERR_BAD_KEY_TYPE;
            goto exit;
    }

    if (NULL != pRetMd5FingerPrint)
    {
        MD5_CTX ctx;

        MD5Init_m(MOC_HASH(hwAccelCtx) &ctx);

        if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCtx) &ctx, pTempSignature->pString, pTempSignature->stringLen)))
            goto exit;

        if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCtx) &ctx, pPublicKeyBlob, publicKeyBlobLen)))
            goto exit;

        if (OK > (status = MD5Final_m(MOC_HASH(hwAccelCtx) &ctx, pRetMd5FingerPrint)))
            goto exit;
    }

    if (NULL != pRetSha1FingerPrint)
    {
        shaDescr ctx;

        if (OK > (status = SHA1_initDigest(MOC_HASH(hwAccelCtx) &ctx)))
            goto exit;

        if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &ctx, pTempSignature->pString, pTempSignature->stringLen)))
            goto exit;

        if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &ctx, pPublicKeyBlob, publicKeyBlobLen)))
            goto exit;

        if (OK > (status = SHA1_finalDigest(MOC_HASH(hwAccelCtx) &ctx, pRetSha1FingerPrint)))
            goto exit;
    }

exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSH, &hwAccelCtx);

    if (NULL != pPublicKeyBlob)
        FREE(pPublicKeyBlob);

nocleanup:
    return status;

} /* SSH_publicKeyFingerPrints */


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_UTILS_generateHostKeyFile(ubyte *pKeyBlob, ubyte4 keyBlobLength, ubyte **ppRetHostFile, ubyte4 *pRetHostFileLen)
{
    return SSH_KEY_generateHostKeyFile(pKeyBlob, keyBlobLength, ppRetHostFile, pRetHostFileLen);
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_UTILS_generateServerAuthKeyFile(ubyte *pKeyBlob, ubyte4 keyBlobLength,
                                    ubyte **ppRetEncodedAuthKey, ubyte4 *pRetEncodedAuthKeyLen)
{
    return SSH_KEY_generateServerAuthKeyFile(pKeyBlob, keyBlobLength, ppRetEncodedAuthKey,
        pRetEncodedAuthKeyLen);
}
#endif /* !defined(__DISABLE_DIGICERT_KEY_GENERATION__) */


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_UTILS_freeGenerateServerAuthKeyFile(ubyte **ppFreeEncodedAuthKey)
{
    MSTATUS status = ERR_NULL_POINTER;

    if ((NULL != ppFreeEncodedAuthKey) && (NULL != *ppFreeEncodedAuthKey))
    {
        DIGI_FREE((void **) ppFreeEncodedAuthKey);
        status = OK;
    }

    return status;
}


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_DER_CONVERSION__) && defined(__ENABLE_DIGICERT_DSA__))

extern MSTATUS
SSH_UTILS_dsaDerToKeyBlob(MOC_ASYM(hwAccelDescr hwAccelCtx) ubyte *pDerDsaKey, ubyte4 derDsaKeyLength,
                           ubyte **ppRetKeyBlob, ubyte4 *pRetKeyBlobLength )
{
    AsymmetricKey   key = {0};
    MSTATUS         status;

    /* check input */
    if ((NULL == pDerDsaKey) || (NULL == ppRetKeyBlob) || (NULL == pRetKeyBlobLength))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = CRYPTO_initAsymmetricKey(&key)))
        return status;

    status = CRYPTO_deserializeAsymKey(MOC_ASYM(hwAccelCtx) pDerDsaKey, derDsaKeyLength, NULL, &key);
    if (OK > status)
        goto exit;

    status = CA_MGMT_makeKeyBlobEx(&key, ppRetKeyBlob, pRetKeyBlobLength);

exit:
    CRYPTO_uninitAsymmetricKey(&key, NULL);

    return status;
}
#endif /* defined(__ENABLE_DIGICERT_DER_CONVERSION__) && defined(__ENABLE_DIGICERT_DSA__) */

#endif /* (defined(__ENABLE_DIGICERT_SSH_SERVER__)) */
