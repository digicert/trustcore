/*
 * ssh_ecdsa.c
 *
 * SSH ECDSA Host Keys
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

#if ((defined(__ENABLE_DIGICERT_ECC__)) && (defined(__ENABLE_DIGICERT_SSH_SERVER__) || defined(__ENABLE_DIGICERT_SSH_CLIENT__)))

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/secmod.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../common/prime.h"
#ifdef __ENABLE_DIGICERT_DSA__
#include "../crypto/dsa.h"
#endif
#include "../common/memory_debug.h"
#include "../common/sizedbuffer.h"
#include "../crypto/sha1.h"
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/cert_store.h"
#include "../ssh/ssh_str.h"
#ifdef __ENABLE_DIGICERT_SSH_SERVER__
#include "../ssh/ssh_utils.h"
#include "../ssh/ssh.h"
#include "../ssh/ssh_str_house.h"
#endif
#ifdef __ENABLE_DIGICERT_SSH_CLIENT__
#include "../ssh/client/sshc_str_house.h"
#endif
#include "../ssh/ssh_ecdsa.h"
#include "../ssh/ssh_mpint.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/cryptointerface.h"
#include "../crypto/ecc.h"
#include "../crypto_interface/crypto_interface_ecc.h"
#endif

/*------------------------------------------------------------------*/

typedef struct
{
    ubyte*  pOidB64Identifier;
    ubyte4  oidB64IdentifierLen;
    ubyte*  curveName;
    ubyte4  curveNameLen;
    ubyte4  curveLength;
    ubyte4  curveId;

} sshEcdsaCurveIdDescr;


/*------------------------------------------------------------------*/

static sshEcdsaCurveIdDescr m_curveLookupTable[] =
{
    { (ubyte *)"h/SsxnLCtRBh7I9ATyeB3A==", 24, (ubyte *)"nistp521", 8, 521, cid_EC_P521 },
    { (ubyte *)"qcFQaMAMGhTziMT0z+Tuzw==", 24, (ubyte *)"nistp384", 8, 384, cid_EC_P384 },
    { (ubyte *)"9UzNcgwTlEnSCECZa7V1mw==", 24, (ubyte *)"nistp256", 8, 256, cid_EC_P256 },
    { (ubyte *)"VqBg4QRPjxx1EXZdV0GdWQ==", 24, (ubyte *)"nistp224", 8, 224, cid_EC_P224 },
    { (ubyte *)"5pPrSUQtIaTjUSt5VZNBjg==", 24, (ubyte *)"nistp192", 8, 192, cid_EC_P192 },
    { NULL                               ,  0, (ubyte *)"ssh-ed25519", 11, 255, cid_EC_Ed25519 }
};

#define SSH_ECDSA_CURVE_TABLE_SIZE      (sizeof(m_curveLookupTable) / sizeof(sshEcdsaCurveIdDescr))


/*------------------------------------------------------------------*/

static sshEcdsaCurveIdDescr *
SSH_ECDSA_findByCurveId(ubyte4 curveId)
{
    ubyte4 index;

    for (index = 0; index < SSH_ECDSA_CURVE_TABLE_SIZE; index++)
    {
        if (m_curveLookupTable[index].curveId == curveId)
            return &m_curveLookupTable[index];
    }

    return NULL;
}


/*------------------------------------------------------------------*/

static sshEcdsaCurveIdDescr *
SSH_ECDSA_findByCurveName(ubyte *pCurveName, ubyte4 curveNameLen)
{
    sbyte4  result;
    ubyte4  index;

    for (index = 0; index < SSH_ECDSA_CURVE_TABLE_SIZE; index++)
    {
        if ((curveNameLen == m_curveLookupTable[index].curveNameLen) &&
            (OK <= DIGI_MEMCMP(m_curveLookupTable[index].curveName, pCurveName, m_curveLookupTable[index].curveNameLen, &result)) &&
            (0 == result))
        {
            return &m_curveLookupTable[index];
        }
    }

    return NULL;
}

/*  Generate ecc_keyblob as specificed in RFC 5656 Section 3.1.
        The ecc_key_blob value has the following specific encoding:
            string  [identifier]
            string  Q
        
        The string [identifier] is the identifier of the elliptic curve
        domain parameters.
        
        Q is the public key encoded from an elliptic curve point into an
        octet string.
        
    Note: If pPubKeyBuffer is NULL, pPubKeyBufferLen is assigned length of
    required buffer. */
extern MSTATUS
SSH_ECDSA_generateEccKeyBlob(MOC_ECC(hwAccelDescr hwAccelCtx) ECCKey *pECCKey,  ubyte4 curveId, ubyte *pPubKeyBuffer, ubyte4 *pPubKeyBufferLen)
{
    MSTATUS status;
    ubyte4 keyLen, index = 0;
    ubyte4 bufferLen;
    sshEcdsaCurveIdDescr*   pCurveDescr;
    ubyte*                  curveName = 0;
    ubyte4                  curveLen = 0;

    if ((NULL == pECCKey) || (NULL == pPubKeyBufferLen))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == (pCurveDescr = SSH_ECDSA_findByCurveId(curveId)))
    {
        status = ERR_SSH_UNSUPPORTED_CURVE;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_SSH_SERVER__
    /*RFC 5656 Section 6.1*/
    switch (pCurveDescr->curveId)
    {
      case  cid_EC_P192:
                 curveName = pCurveDescr->pOidB64Identifier;
                 curveLen = pCurveDescr->oidB64IdentifierLen;
                 break;
      case  cid_EC_P224:
                 curveName = pCurveDescr->pOidB64Identifier;
                 curveLen = pCurveDescr->oidB64IdentifierLen;
                 break;
      case  cid_EC_P256:
                 curveName = pCurveDescr->curveName;
                 curveLen = pCurveDescr->curveNameLen;
                 break;
      case  cid_EC_P384:
                 curveName = pCurveDescr->curveName;
                 curveLen = pCurveDescr->curveNameLen;
                 break;
      case  cid_EC_P521:
                 curveName = pCurveDescr->curveName;
                 curveLen = pCurveDescr->curveNameLen;
                 break;
      case  cid_EC_Ed25519:
                 curveName = NULL;
                 curveLen = 0;
                 break;
      default:  status = ERR_SSH_UNSUPPORTED_CURVE;
                 goto exit;
    }
#endif

#ifdef __ENABLE_DIGICERT_SSH_CLIENT__
    /*RFC 5656 Section 6.1*/
    switch (pCurveDescr->curveId)
    {
      case  cid_EC_P192:
                 curveName = pCurveDescr->pOidB64Identifier;
                 curveLen = pCurveDescr->oidB64IdentifierLen;
                 break;
      case  cid_EC_P224:
                 curveName = pCurveDescr->pOidB64Identifier;
                 curveLen = pCurveDescr->oidB64IdentifierLen;
                 break;
      case  cid_EC_P256:
                 curveName = pCurveDescr->curveName;
                 curveLen = pCurveDescr->curveNameLen;
                 break;
      case  cid_EC_P384:
                 curveName = pCurveDescr->curveName;
                 curveLen = pCurveDescr->curveNameLen;
                 break;
      case  cid_EC_P521:
                 curveName = pCurveDescr->curveName;
                 curveLen = pCurveDescr->curveNameLen;
                 break;
      case  cid_EC_Ed25519:
                 curveName = NULL;
                 curveLen = 0;
                break;
      default:  status = ERR_SSH_UNSUPPORTED_CURVE;
                 goto exit;
    }
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_getPointByteStringLenAux(pECCKey, &keyLen);
    if (OK != status)
        goto exit;
#else
    if (OK > (status = EC_getPointByteStringLenEx(pECCKey, &keyLen)))
        goto exit;
#endif

    if (cid_EC_Ed25519 == curveId)
    {
        /* curve name | key */
        bufferLen = 4 + keyLen;
    }
    else
    {
        /* curve name | curve identifier | key */
        bufferLen = 4 + curveLen + 4 + keyLen;
    }

    if (NULL == pPubKeyBuffer)
    {
        /* if pPubKeyBuffer is NULL, we just need the length */
        *pPubKeyBufferLen = bufferLen;
        goto exit;
    }

    /* check that buffer is sufficient size for computed
       length */
    if (*pPubKeyBufferLen < bufferLen)
    {
        status = ERR_BUFFER_TOO_SMALL;
        goto exit;
    }

    /* if ECDSA key is being used, we want to add curve ID */
    if (cid_EC_Ed25519 != curveId)
    {
        BIGEND32(pPubKeyBuffer, curveLen);
        index += 4;

        DIGI_MEMCPY(pPubKeyBuffer + index, curveName, curveLen);
        index += curveLen;
    }

    BIGEND32(pPubKeyBuffer + index, keyLen);
    index += 4;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_writePublicKeyToBufferAux(MOC_ECC(hwAccelCtx) pECCKey, pPubKeyBuffer+index, keyLen);
    if (OK != status)
        goto exit;
#else
    status = EC_writePublicKeyToBuffer(MOC_ECC(hwAccelCtx) pECCKey, pPubKeyBuffer + index, keyLen);
    if (OK != status)
        goto exit;
#endif

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
SSH_ECDSA_buildEcdsaCertificate(MOC_ECC(hwAccelDescr hwAccelCtx) AsymmetricKey *pKey,
                                intBoolean isServer, ubyte **ppCertificate, ubyte4 *pRetLen)
{
    ubyte4                  index;
    sshEcdsaCurveIdDescr*   pCurveDescr;
    ECCKey*                 pPub = NULL;
    MSTATUS                 status;
    ubyte*                  buffer = 0;
    sshStringBuffer*        ssh_ecdsa_sig = NULL;
    ubyte4                  curveId = 0;
    ubyte4                  keyMaterialLength = 0;

    if (NULL == pKey || NULL == pRetLen || NULL == ppCertificate)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    *ppCertificate = 0;

    if ((akt_ecc != (pKey->type & 0xff)) && (akt_ecc_ed != (pKey->type & 0xff)))
    {
        status = ERR_SSH_EXPECTED_ECC_KEY;
        goto exit;
    }

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    status = CRYPTO_INTERFACE_getECCPublicKey (pKey, &pPub);
    if (OK != status)
        goto exit;
#else
    pPub = pKey->key.pECC;
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pPub, &curveId);
    if(OK != status)
        goto exit;
#else
    if (OK > (status = EC_getCurveIdFromKey(pPub, &curveId)))
        goto exit;
#endif
    if (NULL == (pCurveDescr = SSH_ECDSA_findByCurveId(curveId)))
    {
        status = ERR_SSH_UNSUPPORTED_CURVE;
        goto exit;
    }
#ifdef __ENABLE_DIGICERT_SSH_SERVER__
    /*RFC 5656 Section 6.1*/
    switch (pCurveDescr->curveId)
    {
      case  cid_EC_P192: ssh_ecdsa_sig = &ssh_ecdsa_signature_p192;
                 break;
      case  cid_EC_P224: ssh_ecdsa_sig = &ssh_ecdsa_signature_p224;
                 break;
      case  cid_EC_P256: ssh_ecdsa_sig = &ssh_ecdsa_signature_p256;
                 break;
      case  cid_EC_P384: ssh_ecdsa_sig = &ssh_ecdsa_signature_p384;
                 break;
      case  cid_EC_P521: ssh_ecdsa_sig = &ssh_ecdsa_signature_p521;
                 break;
      case  cid_EC_Ed25519: ssh_ecdsa_sig = &ssh_ecdsa_signature_ed25519;
                 break;
      default:  status = ERR_SSH_UNSUPPORTED_CURVE;
                 goto exit;
    }
#endif

#ifdef __ENABLE_DIGICERT_SSH_CLIENT__
    /*RFC 5656 Section 6.1*/
    switch (pCurveDescr->curveId)
    {
      case  cid_EC_P192: ssh_ecdsa_sig = &sshc_ecdsa_signature_p192;
                 break;
      case  cid_EC_P224: ssh_ecdsa_sig = &sshc_ecdsa_signature_p224;
                 break;
      case  cid_EC_P256: ssh_ecdsa_sig = &sshc_ecdsa_signature_p256;
                 break;
      case  cid_EC_P384: ssh_ecdsa_sig = &sshc_ecdsa_signature_p384;
                 break;
      case  cid_EC_P521: ssh_ecdsa_sig = &sshc_ecdsa_signature_p521;
                 break;
      case  cid_EC_Ed25519: ssh_ecdsa_sig = &sshc_ecdsa_signature_ed25519;
                break;
      default:  status = ERR_SSH_UNSUPPORTED_CURVE;
                 goto exit;
    }
#endif

    /* get length of key material portion of key encoding */
    status = SSH_ECDSA_generateEccKeyBlob(MOC_ECC(hwAccelCtx) pPub, pCurveDescr->curveId, NULL, &keyMaterialLength);
    if (OK != status)
        goto exit;

    if (isServer)
    {
#ifdef __ENABLE_DIGICERT_SSH_SERVER__
        *pRetLen = ssh_ecdsa_sig->stringLen + keyMaterialLength;
#else
        status = ERR_SSH_CONFIG;
        goto exit;
#endif
    }
    else
    {
#ifdef __ENABLE_DIGICERT_SSH_CLIENT__
        *pRetLen = ssh_ecdsa_sig->stringLen + keyMaterialLength;
#else
        status = ERR_SSH_CONFIG;
        goto exit;
#endif
    }

    status = DIGI_MALLOC((void **) &buffer, 4 + *pRetLen);
    if (OK != status)
        goto exit;

    /* length in big-endian format */
    BIGEND32(buffer, (*pRetLen));
    *pRetLen += 4;
    index     = 4;

    /* signature string */
    if (isServer)
    {
#ifdef __ENABLE_DIGICERT_SSH_SERVER__
        DIGI_MEMCPY(buffer + index, ssh_ecdsa_sig->pString, (sbyte4)ssh_ecdsa_sig->stringLen);
        index += ssh_ecdsa_sig->stringLen;
#endif
    }
    else
    {
#ifdef __ENABLE_DIGICERT_SSH_CLIENT__
        DIGI_MEMCPY(buffer + index, ssh_ecdsa_sig->pString, (sbyte4)ssh_ecdsa_sig->stringLen);
        index += ssh_ecdsa_sig->stringLen;
#endif
    }

    /*
    commented out to allow compatibility with openssh
    BIGEND32(index + buffer, 4 + pCurveDescr->oidB64IdentifierLen + 4 + keyLen);
    BIGEND32(index + buffer, 4 + pCurveDescr->curveNameLen + 4 + keyLen);
    index += 4;
    */

    /* curve identifier length in big-endian format
    BIGEND32(index + buffer, pCurveDescr->oidB64IdentifierLen); */
    /* get key blob */
    status = SSH_ECDSA_generateEccKeyBlob(MOC_ECC(hwAccelCtx) pPub, pCurveDescr->curveId, buffer + index, &keyMaterialLength);
    if (OK != status)
        goto exit;

    *ppCertificate = buffer;
    buffer = 0;

exit:

    if ( buffer)
    {
        FREE(buffer);
    }
#if defined (__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    if ((NULL != pKey) && (akt_tap_ecc == pKey->type) && (NULL != pPub))
    {

        CRYPTO_INTERFACE_EC_deleteKeyAux(&pPub);
    }
#endif

    return status;

} /* SSH_ECDSA_buildEcdsaCertificate */


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_ECDSA_calcEcdsaSignatureLength(AsymmetricKey *pKey, intBoolean isServer, ubyte4 *pSignatureLength)
{
    ECCKey*         pECCKey = NULL;
    ubyte4          elementLen;
    MSTATUS         status;
    ubyte4          curveId;

    sshEcdsaCurveIdDescr*    pCurveDescr;
    sshStringBuffer         ssh_ecdsa_signature ;
    if (NULL == pKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((akt_ecc != (pKey->type & 0xff)) && (akt_ecc_ed != (pKey->type & 0xff)))
    {
        status = ERR_SSH_EXPECTED_ECC_KEY;
        goto exit;
    }

    pECCKey = pKey->key.pECC;
    if (NULL == pECCKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_getElementByteStringLenAux(pECCKey, &elementLen);
    if(OK != status)
        goto exit;
#else
    status = EC_getElementByteStringLen(pECCKey, &elementLen);
    if(OK != status)
        goto exit;
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pECCKey, &curveId);
    if(OK != status)
        goto exit;
#else
    status = EC_getCurveIdFromKey(pECCKey, &curveId);
    if (OK != status)
        goto exit;
#endif

    if (NULL == (pCurveDescr = SSH_ECDSA_findByCurveId(curveId)))
    {
        status = ERR_SSH_UNSUPPORTED_CURVE;
        goto exit;
    }

    if (isServer)
    {
#ifdef __ENABLE_DIGICERT_SSH_SERVER__
        switch (pCurveDescr->curveLength)
        {
            case 192: ssh_ecdsa_signature = ssh_ecdsa_signature_p192;
                    break;
            case 224: ssh_ecdsa_signature = ssh_ecdsa_signature_p224;
                    break;
            case 256: ssh_ecdsa_signature = ssh_ecdsa_signature_p256;
                    break;
            case 384: ssh_ecdsa_signature = ssh_ecdsa_signature_p384;
                    break;
            case 521: ssh_ecdsa_signature = ssh_ecdsa_signature_p521;
                    break;
            default : status = ERR_SSH_UNSUPPORTED_CURVE;
                    goto exit;
        }

        /* MpintR and MpintS lengths can be greater than elementLen. 20 bytes is to accommodate that.
         * Refer RFC 4251 section 5, and vlong.c ByteStringFromVlong.
         */
        *pSignatureLength = 4 + ssh_ecdsa_signature.stringLen + 4 + (2 * elementLen + 20);
#else
        status = ERR_SSH_CONFIG;
#endif
    } else {
#ifdef __ENABLE_DIGICERT_SSH_CLIENT__
       switch (pCurveDescr->curveId)
        {
            case cid_EC_P192: ssh_ecdsa_signature = sshc_ecdsa_signature_p192;
                        break;
            case cid_EC_P224: ssh_ecdsa_signature = sshc_ecdsa_signature_p224;
                        break;
            case cid_EC_P256: ssh_ecdsa_signature = sshc_ecdsa_signature_p256;
                        break;
            case cid_EC_P384: ssh_ecdsa_signature = sshc_ecdsa_signature_p384;
                        break;
            case cid_EC_P521: ssh_ecdsa_signature = sshc_ecdsa_signature_p521;
                        break;
            case cid_EC_Ed25519: ssh_ecdsa_signature = sshc_ecdsa_signature_ed25519;
                        break;
            default : status = ERR_SSH_UNSUPPORTED_CURVE;
                        goto exit;
        }
      /* MpintR and MpintS lengths can be greater than elementLen. 20 bytes is to accommodate that.
       * Refer RFC 4251 section 5, and vlong.c ByteStringFromVlong
       */
        *pSignatureLength = 4 + ssh_ecdsa_signature.stringLen + 4 + (2 * elementLen + 20 );
#else
        status = ERR_SSH_CONFIG;
#endif
    }

exit:
    return status;

} /* SSH_ECDSA_calcEcdsaSignatureLength */


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_ECDSA_buildEcdsaSignatureEx(MOC_ECC(hwAccelDescr hwAccelCtx) AsymmetricKey *pKey,
                              ubyte hashAlgo, const ubyte* hash,
                              ubyte4 hashLen, ubyte **ppSignature, ubyte4 *pSignatureLength)
{
    ubyte*                   pSignature = NULL;
    ECCKey*                  pECCKey = NULL;
    ubyte4                   elementLen;
    ubyte*                   pRawSignature = NULL;
    ubyte4                   rawSignatureLen = 0;
    ubyte4                   index;
    ubyte4                   sigLength;
    ubyte*                   pMpintR = NULL;
    sbyte4                   mpintRLen = 0;
    ubyte*                   pMpintS = NULL;
    sbyte4                   mpintSLen = 0;
    sshEcdsaCurveIdDescr*    pCurveDescr;
    sshStringBuffer*         ssh_ecdsa_signature = NULL;
    MSTATUS                  status = OK;
    ubyte4                   curveId;

    if ((NULL == pKey) || (NULL == pKey->key.pECC) || (NULL == hash) || (NULL == ppSignature) ||
            (NULL == pSignatureLength) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pSignatureLength = 0;

    if ((akt_ecc != (pKey->type & 0xff)) && (akt_ecc_ed != (pKey->type & 0xff)))
    {
        status = ERR_SSH_EXPECTED_ECC_KEY;
        goto exit;
    }

    pECCKey = pKey->key.pECC;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pECCKey, &curveId);
    if(OK != status)
        goto exit;
#else
    status = EC_getCurveIdFromKey(pECCKey, &curveId);
    if(OK != status)
        goto exit;
#endif

    if (NULL == (pCurveDescr = SSH_ECDSA_findByCurveId(curveId)))
    {
        status = ERR_SSH_UNSUPPORTED_CURVE;
        goto exit;
    }
 #ifdef __ENABLE_DIGICERT_SSH_SERVER__
    switch (pCurveDescr->curveId)
    {
      case cid_EC_P192: ssh_ecdsa_signature = &ssh_ecdsa_signature_p192;
                break;
      case cid_EC_P224: ssh_ecdsa_signature = &ssh_ecdsa_signature_p224;
                break;
      case cid_EC_P256: ssh_ecdsa_signature = &ssh_ecdsa_signature_p256;
                break;
      case cid_EC_P384: ssh_ecdsa_signature = &ssh_ecdsa_signature_p384;
                break;
      case cid_EC_P521: ssh_ecdsa_signature = &ssh_ecdsa_signature_p521;
                break;
      case cid_EC_Ed25519: ssh_ecdsa_signature = &ssh_ecdsa_signature_ed25519;
                break;
      default : status = ERR_SSH_UNSUPPORTED_CURVE;
                goto exit;
    }
 #endif
 #ifdef __ENABLE_DIGICERT_SSH_CLIENT__
    switch (pCurveDescr->curveId)
    {
      case cid_EC_P192: ssh_ecdsa_signature = &sshc_ecdsa_signature_p192;
                break;
      case cid_EC_P224: ssh_ecdsa_signature = &sshc_ecdsa_signature_p224;
                break;
      case cid_EC_P256: ssh_ecdsa_signature = &sshc_ecdsa_signature_p256;
                break;
      case cid_EC_P384: ssh_ecdsa_signature = &sshc_ecdsa_signature_p384;
                break;
      case cid_EC_P521: ssh_ecdsa_signature = &sshc_ecdsa_signature_p521;
                break;
      case cid_EC_Ed25519: ssh_ecdsa_signature = &sshc_ecdsa_signature_ed25519;
                break;
      default : status = ERR_SSH_UNSUPPORTED_CURVE;
                goto exit;
    }
 #endif

    /* create buffer for signature */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_getElementByteStringLenAux(pECCKey, &elementLen);
    if(OK != status)
        goto exit;
#else
    status = EC_getElementByteStringLen(pECCKey, &elementLen);
    if (OK != status)
        goto exit;
#endif

    rawSignatureLen = (elementLen * 2);

    /* allocate buffer for signature */
    status = DIGI_MALLOC((void**)&pRawSignature, rawSignatureLen);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (akt_ecc == (pKey->type & 0xff))
    {
        status = CRYPTO_INTERFACE_ECDSA_signDigestAux(MOC_ECC(hwAccelCtx) pECCKey, RANDOM_rngFun, g_pRandomContext, (ubyte*)hash,
            hashLen, pRawSignature, rawSignatureLen, &rawSignatureLen);
    }
    else
    {
        status = CRYPTO_INTERFACE_ECDSA_signMessageExt(MOC_ECC(hwAccelCtx) pECCKey, RANDOM_rngFun, g_pRandomContext, hashAlgo, (ubyte*)hash,
            hashLen, pRawSignature, rawSignatureLen, &rawSignatureLen, NULL);
    }
    if (OK != status)
        goto exit;
#else
    status = ECDSA_signMessage(MOC_ECC(hwAccelCtx) pECCKey, RANDOM_rngFun, g_pRandomContext, hashAlgo, (ubyte*)hash,
        hashLen, pRawSignature, rawSignatureLen, &rawSignatureLen, NULL);
    if (OK != status)
        goto exit;
#endif

    /* allocate buffer for the elements */
    if (cid_EC_Ed25519 != pCurveDescr->curveId)
    {
        /* get r and s mpint if ecdsa */
        status = SSH_mpintByteStringFromByteString(pRawSignature, elementLen, 0, &pMpintR, &mpintRLen);
        if (OK != status)
            goto exit;

        status = SSH_mpintByteStringFromByteString(pRawSignature + elementLen, elementLen, 0, &pMpintS, &mpintSLen);
        if (OK != status)
            goto exit;
    }

#if defined(__ENABLE_DIGICERT_SSH_SERVER__) || defined(__ENABLE_DIGICERT_SSH_CLIENT__)
        if (cid_EC_Ed25519 == pCurveDescr->curveId)
        {
            sigLength = ssh_ecdsa_signature->stringLen + 4 + rawSignatureLen;
        }
        else
        {
            sigLength = ssh_ecdsa_signature->stringLen + 4 + mpintRLen + mpintSLen;
        }
#else
        status = ERR_SSH_CONFIG;
        goto exit;
#endif

    /* malloc for worse case scenario */
    status = DIGI_MALLOC((void**)&pSignature, 4 + sigLength);
    if (OK != status)
        goto exit;

    /* set signature length field */
    BIGEND32(pSignature, sigLength);
    index = 4;

#if defined(__ENABLE_DIGICERT_SSH_SERVER__) || defined(__ENABLE_DIGICERT_SSH_CLIENT__)
    if (OK > (status = DIGI_MEMCPY(pSignature + index, ssh_ecdsa_signature->pString, (sbyte4)ssh_ecdsa_signature->stringLen)))
        goto exit;
    index += ssh_ecdsa_signature->stringLen;
#else
    status = ERR_SSH_CONFIG;
    goto exit;
#endif

    if (cid_EC_Ed25519 == pCurveDescr->curveId)
    {
        /* write length of signature */
        BIGEND32(pSignature + index, rawSignatureLen);
        index += 4;

        if (OK > (status = DIGI_MEMCPY(pSignature + index, pRawSignature, rawSignatureLen)))
            goto exit;
        index += rawSignatureLen;
    }
    else
    {
        /* set rs string length field */
        BIGEND32(pSignature + index, mpintRLen + mpintSLen);
        index += 4;

        /* copy r & s to signature blob */
        if (OK > (status = DIGI_MEMCPY(pSignature + index, pMpintR, mpintRLen)))
            goto exit;
        index += mpintRLen;

        if (OK > (status = DIGI_MEMCPY(pSignature + index, pMpintS, mpintSLen)))
            goto exit;
        index += mpintSLen;
    }

    /* save variables */
    *ppSignature      = pSignature;
    pSignature        = NULL;
    *pSignatureLength = index;

exit:
    if (NULL != pSignature)
        FREE(pSignature);

    if (NULL != pRawSignature)
        DIGI_FREE((void**)&pRawSignature);

    if (NULL != pMpintS)
        FREE(pMpintS);

    if (NULL != pMpintR)
        FREE(pMpintR);

    return status;

} /* SSH_ECDSA_buildEcdsaSignatureEx */


/*------------------------------------------------------------------*/

/*  Generate r and s values as specified in RFC 5656 Section 3.1.2.
        The ecdsa_signature_blob value has the following specific encoding:

            mpint    r
            mpint    s

        The integers r and s are the output of the ECDSA algorithm.

        The width of the integer fields is determined by the curve being
        used.  Note that the integers r and s are integers modulo the order
        of the cryptographic subgroup, which may be larger than the size of
        the finite field.
*/
extern MSTATUS
SSH_ECDSA_signHash(MOC_ECC(hwAccelDescr hwAccelCtx) ECCKey *pECCKey,
                    const ubyte* pHash, ubyte4 hashLen,
                    ubyte **ppMpintR, ubyte4 *pMpintRLen, ubyte **ppMpintS, ubyte4 *pMpintSLen)
{
    ubyte4                   elementLen;
    ubyte*                   pRawSignature = NULL;
    ubyte4                   rawSignatureLen = 0;
    ubyte*                   pMpintR = NULL;
    sbyte4                   mpintRLen = 0;
    ubyte*                   pMpintS = NULL;
    sbyte4                   mpintSLen = 0;
    MSTATUS                  status = OK;

    if ((NULL == pECCKey) || (NULL == pHash) || (NULL == ppMpintR) ||
        (NULL == pMpintRLen) || (NULL == ppMpintS) || (NULL == pMpintSLen))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_getElementByteStringLenAux(pECCKey, &elementLen);
    if(OK != status)
        goto exit;
#else
    status = EC_getElementByteStringLen(pECCKey, &elementLen);
    if (OK != status)
        goto exit;
#endif

    rawSignatureLen = (elementLen * 2);

    /* allocate buffer for signature */
    status = DIGI_MALLOC((void**)&pRawSignature, rawSignatureLen);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_ECDSA_signDigestAux(MOC_ECC(hwAccelCtx) pECCKey, RANDOM_rngFun, g_pRandomContext, (ubyte*)pHash,
        hashLen, pRawSignature, rawSignatureLen, &rawSignatureLen);
    if (OK != status)
        goto exit;
#else
    status = ECDSA_signDigest(MOC_ECC(hwAccelCtx) pECCKey, RANDOM_rngFun, g_pRandomContext, (ubyte*)pHash,
        hashLen, pRawSignature, rawSignatureLen, &rawSignatureLen);
    if (OK != status)
        goto exit;
#endif

    /* convert r value into mpint */
    status = SSH_mpintByteStringFromByteString(pRawSignature, elementLen, 0, &pMpintR, &mpintRLen);
    if (OK != status)
        goto exit;

    /* convert s value into mpint */
    status = SSH_mpintByteStringFromByteString(pRawSignature + elementLen, elementLen, 0, &pMpintS, &mpintSLen);
    if (OK != status)
        goto exit;

    *ppMpintR   = pMpintR;
    *pMpintRLen = (ubyte4) mpintRLen;
    *ppMpintS   = pMpintS;
    *pMpintSLen = (ubyte4) mpintSLen;
    pMpintR = NULL;
    pMpintS = NULL;

exit:
    if (NULL != pMpintR)
        DIGI_FREE((void **) &pMpintR);

    if (NULL != pMpintS)
        DIGI_FREE((void **) &pMpintS);

    if (NULL != pRawSignature)
        DIGI_FREE((void **) &pRawSignature);

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_ECDSA_buildEcdsaSignature(MOC_ECC(hwAccelDescr hwAccelCtx) AsymmetricKey *pKey,
                              intBoolean isServer, const ubyte* hash,
                              ubyte4 hashLen, ubyte **ppSignature, ubyte4 *pSignatureLength)
{
    ubyte*                   pSignature = NULL;
    ECCKey*                  pECCKey = NULL;
    ubyte4                   index;
    ubyte4                   sigLength;
    ubyte*                   pMpintR = NULL;
    ubyte4                   mpintRLen = 0;
    ubyte*                   pMpintS = NULL;
    ubyte4                   mpintSLen = 0;
    sshEcdsaCurveIdDescr*    pCurveDescr;
    sshStringBuffer*         ssh_ecdsa_signature = NULL;
    MSTATUS                  status = OK;
    ubyte4 curveID;


    if ((NULL == pKey) || (NULL == pKey->key.pECC) || (NULL == hash) || (NULL == ppSignature) ||
            (NULL == pSignatureLength) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    *pSignatureLength = 0;

    if ((akt_ecc != (pKey->type & 0xff)) && (akt_ecc_ed != (pKey->type & 0xff)))
    {
        status = ERR_SSH_EXPECTED_ECC_KEY;
        goto exit;
    }

    pECCKey = pKey->key.pECC;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pECCKey, &curveID);
    if(OK != status)
        goto exit;
#else
    status = EC_getCurveIdFromKey(pECCKey, &curveID);
    if(OK != status)
        goto exit;
#endif

    if (NULL == (pCurveDescr = SSH_ECDSA_findByCurveId(curveID)))
    {
        status = ERR_SSH_UNSUPPORTED_CURVE;
        goto exit;
    }
 #ifdef __ENABLE_DIGICERT_SSH_SERVER__
    switch (pCurveDescr->curveLength)
    {
      case 192: ssh_ecdsa_signature = &ssh_ecdsa_signature_p192;
                break;
      case 224: ssh_ecdsa_signature = &ssh_ecdsa_signature_p224;
                break;
      case 256: ssh_ecdsa_signature = &ssh_ecdsa_signature_p256;
                break;
      case 384: ssh_ecdsa_signature = &ssh_ecdsa_signature_p384;
                break;
      case 521: ssh_ecdsa_signature = &ssh_ecdsa_signature_p521;
                break;
      default : status = ERR_SSH_UNSUPPORTED_CURVE;
                goto exit;
    }
 #endif
 #ifdef __ENABLE_DIGICERT_SSH_CLIENT__
    switch (pCurveDescr->curveLength)
    {
      case 192: ssh_ecdsa_signature = &sshc_ecdsa_signature_p192;
                break;
      case 224: ssh_ecdsa_signature = &sshc_ecdsa_signature_p224;
                break;
      case 256: ssh_ecdsa_signature = &sshc_ecdsa_signature_p256;
                break;
      case 384: ssh_ecdsa_signature = &sshc_ecdsa_signature_p384;
                break;
      case 521: ssh_ecdsa_signature = &sshc_ecdsa_signature_p521;
                break;
      default : status = ERR_SSH_UNSUPPORTED_CURVE;
                goto exit;
    }
 #endif

    status = SSH_ECDSA_signHash(MOC_ECC(hwAccelCtx) pECCKey, hash, hashLen, &pMpintR, &mpintRLen, &pMpintS, &mpintSLen);
    if (OK != status)
        goto exit;

    if (isServer)
    {
#ifdef __ENABLE_DIGICERT_SSH_SERVER__
        sigLength = ssh_ecdsa_signature->stringLen + 4 + mpintRLen + mpintSLen;
#else
        status = ERR_SSH_CONFIG;
        goto exit;
#endif
    } else {
#ifdef __ENABLE_DIGICERT_SSH_CLIENT__
        sigLength = ssh_ecdsa_signature->stringLen + 4 + mpintRLen + mpintSLen;
#else
        status = ERR_SSH_CONFIG;
        goto exit;
#endif
    }

    /* malloc for worse case scenario */
    status = DIGI_MALLOC((void **) &pSignature, 4 + sigLength);
    if (OK != status)
        goto exit;

    /* set signature length field */
    BIGEND32(pSignature, sigLength);
    index = 4;

    if (isServer)
    {
#ifdef __ENABLE_DIGICERT_SSH_SERVER__
        if (OK > (status = DIGI_MEMCPY(pSignature + index, ssh_ecdsa_signature->pString, (sbyte4)ssh_ecdsa_signature->stringLen)))
            goto exit;
        index += ssh_ecdsa_signature->stringLen;
#endif
    } else {
#ifdef __ENABLE_DIGICERT_SSH_CLIENT__
        if (OK > (status = DIGI_MEMCPY(pSignature + index, ssh_ecdsa_signature->pString, (sbyte4)ssh_ecdsa_signature->stringLen)))
            goto exit;
        index += ssh_ecdsa_signature->stringLen;
#endif
    }

    /* set rs string length field */
    BIGEND32(pSignature + index, mpintRLen + mpintSLen);
    index += 4;

    /* copy r & s to signature blob */
    if (OK > (status = DIGI_MEMCPY(pSignature + index, pMpintR, mpintRLen)))
        goto exit;
    index += mpintRLen;

    if (OK > (status = DIGI_MEMCPY(pSignature + index, pMpintS, mpintSLen)))
        goto exit;
    index += mpintSLen;

    /* save variables */
    *ppSignature      = pSignature;
    pSignature        = NULL;
    *pSignatureLength = index;

exit:
    if (NULL != pSignature)
        FREE(pSignature);

    if (NULL != pMpintS)
        FREE(pMpintS);

    if (NULL != pMpintR)
        FREE(pMpintR);

    return status;

} /* SSH_ECDSA_buildEcdsaSignature */


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_ECDSA_extractEcdsaCertificate(MOC_ASYM(hwAccelDescr hwAccelCtx) sshStringBuffer* pPublicKeyBlob, AsymmetricKey* pPublicKey,
                                  ubyte4 index, vlong** ppVlongQueue)
{
    /* note: index should be in correct position */
    sshStringBuffer*        pEccKeyBlob = NULL;
    sshStringBuffer*        pCurveName = NULL;
    sshStringBuffer*        pKeyMaterial = NULL;
    sshEcdsaCurveIdDescr*   pCurveDescr;
    ubyte4                  index1 = 4;
    MSTATUS                 status;

    /* extract curve name */
    if (OK > (status = SSH_STR_copyStringFromPayload(pPublicKeyBlob->pString,
                                                     pPublicKeyBlob->stringLen,
                                                     &index1, &pCurveName)))
    {
        goto exit;
    }

    /* extract byte[n] ecc_key_blob, this could also be "key" value of an ssh-ed25519 blob */
    if (OK > (status = SSH_STR_copyStringFromPayload(pPublicKeyBlob->pString,
                                                     pPublicKeyBlob->stringLen,
                                                     &index, &pEccKeyBlob)))
    {
        goto exit;
    }

    DEBUG_RELABEL_MEMORY(pEccKeyBlob);
    /* The "ecdsa-sha2-*" key formats all have the following encoding:
     *
     *      string "ecdsa-sha2-[identifier]"
     *      byte[n] ecc_key_blob
     *
     * The ecc_key_blob value has the following specific encoding:
     *
     *      string  [identifier]
     *      string  Q
     *
     *  Q is the public key encoded from from an elliptic curve point
     *  into an octet string; point compression MAY be used.
     *
     *  The "ssh-ed25519" key format has the following encoding:
     *
     *      string  "ssh-ed25519"
     *      string  key
     *
     *  Here 'key' is the 32-octet public key described by [RFC8032],
     *  Section 5.1.5 [RFC8032].
     *
     *  Here we check if the curve name contains a valid curve name.
     *  It will only match with "ssh-ed25519" since for nist curves it
     *  is looking for an [identifier], not "ecdsa-sha2-[identifier]".
     *
     *  If we get a pCurveDescr, there is no [identifier] and pEccKeyBlob
     *  contains key material.
     *
     *  Otherwise, pEccKeyBlob contains key [identifier] and we have to
     *  extract Q.
     **/
    if (NULL == (pCurveDescr = SSH_ECDSA_findByCurveName(pCurveName->pString + 4, pCurveName->stringLen - 4)))
    {
        /* We have a nist curve, get sshEcdsaCurveIdDescr for curve using [identifier]. */
        if (NULL == (pCurveDescr = SSH_ECDSA_findByCurveName(pEccKeyBlob->pString + 4, pEccKeyBlob->stringLen - 4)))
        {
            status = ERR_SSH_BAD_PUBLIC_KEY_FORMAT;
            goto exit;
        }

        /* extract Q, index offsets pPublicKeyBlob->pString to beginning of Q */
        if (OK > (status = SSH_STR_copyStringFromPayload(pPublicKeyBlob->pString,
                                                         pPublicKeyBlob->stringLen,
                                                         &index, &pKeyMaterial)))
        {
            goto exit;
        }
        if (index != pPublicKeyBlob->stringLen)
        {
            status = ERR_SSH_BAD_PUBLIC_KEY_FORMAT;
            goto exit;
        }
    }
    else
    {
        /* we have an ssh-ed25519 key; pEccKeyBlob contains "key", no offset required */
        index = 0;
        if (OK > (status = SSH_STR_copyStringFromPayload(pEccKeyBlob->pString,
                                                         pEccKeyBlob->stringLen,
                                                         &index, &pKeyMaterial)))
        {
            goto exit;
        }

        if (index != pEccKeyBlob->stringLen)
        {
            status = ERR_SSH_BAD_PUBLIC_KEY_FORMAT;
            goto exit;
        }
    }

    DEBUG_RELABEL_MEMORY(pKeyMaterial);

    if (OK > (status = CRYPTO_setECCParameters(MOC_ECC(hwAccelCtx) (AsymmetricKey *)pPublicKey, pCurveDescr->curveId,
                                               pKeyMaterial->pString + 4, pKeyMaterial->stringLen - 4,
                                               NULL, 0)))
    {
        goto exit;
    }

exit:
    SSH_STR_freeStringBuffer(&pKeyMaterial);
    SSH_STR_freeStringBuffer(&pCurveName);
    SSH_STR_freeStringBuffer(&pEccKeyBlob);

    return status;

} /* SSH_ECDSA_extractEcdsaCertificate */


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_ECDSA_verifyEdDSASignature(MOC_ECC(hwAccelDescr hwAccelCtx) AsymmetricKey *pPublicKey,
                               ubyte hashAlgo, const ubyte* pData, ubyte4 dataLen,
                               sshStringBuffer* pSignature, intBoolean *pIsGoodSignature,
                               vlong **ppVlongQueue)
{
    sshStringBuffer*    tempString = NULL;
    sshStringBuffer*    rsString   = NULL;
    ubyte4              curveId = 0;
    ECCKey*             pECCKey = NULL;
    ubyte4              index      = 4;     /* skip past signature-string-length field */
    sbyte4              result;
    sshEcdsaCurveIdDescr*    pCurveDescr;
    sshStringBuffer*    ssh_ecdsa_signature = NULL;
    MSTATUS             status;
    ubyte*              pSigBuffer = NULL;
    ubyte4              sigBufferLen = 0;

    if (NULL == pIsGoodSignature)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pIsGoodSignature = FALSE;

    if ((akt_ecc != pPublicKey->type) && (akt_ecc_ed != pPublicKey->type))
    {
        status = ERR_SSH_EXPECTED_ECC_KEY;
        goto exit;
    }

    if (NULL == (pECCKey = pPublicKey->key.pECC))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pECCKey, &curveId);
    if(OK != status)
        goto exit;
#else
    status = EC_getCurveIdFromKey(pECCKey, &curveId);
    if (OK != status)
        goto exit;
#endif

    if (NULL == (pCurveDescr = SSH_ECDSA_findByCurveId(curveId)))
    {
        status = ERR_SSH_UNSUPPORTED_CURVE;
        goto exit;
    }
 #ifdef __ENABLE_DIGICERT_SSH_SERVER__
    switch (pCurveDescr->curveId)
    {
      case cid_EC_Ed25519: ssh_ecdsa_signature = &ssh_ecdsa_signature_ed25519;
                break;
      default : status = ERR_SSH_UNSUPPORTED_CURVE;
                goto exit;
    }
 #endif
 #ifdef __ENABLE_DIGICERT_SSH_CLIENT__
    switch (pCurveDescr->curveId)
    {
      case cid_EC_Ed25519: ssh_ecdsa_signature = &sshc_ecdsa_signature_ed25519;
                break;
      default : status = ERR_SSH_UNSUPPORTED_CURVE;
                goto exit;
    }
 #endif

    /* fetch signature type */
    if (OK > (status = SSH_STR_copyStringFromPayload(pSignature->pString, pSignature->stringLen, &index, &tempString)))
        goto exit;

    DEBUG_RELABEL_MEMORY(tempString);
    DEBUG_RELABEL_MEMORY(tempString->pString);

    /* check signature type */
#if (defined(__ENABLE_DIGICERT_SSH_SERVER__) || defined(__ENABLE_DIGICERT_SSH_CLIENT__))
    if (OK > (status = DIGI_MEMCMP(tempString->pString, ssh_ecdsa_signature->pString, ssh_ecdsa_signature->stringLen, &result)))
        goto exit;
#else
    status = ERR_SSH_CONFIG;
    goto exit;
#endif

    if (0 != result)
    {
        status = ERR_SSH_MALFORMED_SIGNATURE;
        goto exit;
    }

    /* If ed25519, this is a 64 byte buffer */
    if (OK > (status = SSH_STR_copyStringFromPayload(pSignature->pString, pSignature->stringLen, &index, &rsString)))
        goto exit;

    DEBUG_RELABEL_MEMORY(rsString);
    DEBUG_RELABEL_MEMORY(rsString->pString);

    if (pSignature->stringLen != index)
    {
        status = ERR_SSH_MALFORMED_SIGNATURE;
        goto exit;
    }

    /* if it is an ed25519 signature, we will retrieve a 64 byte
     * buffer. */
    status = SSH_getByteStringFromMpintBytes(
        rsString->pString, rsString->stringLen, &pSigBuffer, &sigBufferLen);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_ECDSA_verifyMessageExt(MOC_ECC(hwAccelCtx)
        pECCKey, hashAlgo, (ubyte*)pData, dataLen, pSigBuffer,
        sigBufferLen, (ubyte4 *) pIsGoodSignature, NULL);
    if (OK != status)
    {
        *pIsGoodSignature = FALSE;
        goto exit;
    }
#else
    status = ECDSA_verifyMessage(MOC_ECC(hwAccelCtx)
        pECCKey, hashAlgo, pData, dataLen, pSigBuffer,
        sigBufferLen, (ubyte4 *) pIsGoodSignature, NULL);
    if (OK != status)
    {
        *pIsGoodSignature = FALSE;
        goto exit;
    }
#endif
    /* Above API sets to 0 for a good signature, convert to TRUE */
    if (0 == *pIsGoodSignature)
        *pIsGoodSignature = TRUE;
    else
        *pIsGoodSignature = FALSE;
exit:
    SSH_STR_freeStringBuffer(&tempString);
    SSH_STR_freeStringBuffer(&rsString);
    
    if (NULL != pSigBuffer)
        DIGI_FREE((void**)&pSigBuffer);
    return status;

} /* SSH_ECDSA_verifyEdDSASignature */


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_ECDSA_verifyRSValue(MOC_ECC(hwAccelDescr hwAccelCtx) ECCKey *pECCKey,
                               const ubyte* hash, ubyte4 hashLen,
                               sshStringBuffer* rsString, intBoolean *pIsGoodSignature,
                               vlong **ppVlongQueue)
{
    ubyte4              index1;
    MSTATUS             status;
    ubyte*              pR = NULL;
    ubyte4              rLen = 0;
    ubyte*              pS = NULL;
    ubyte4              sLen = 0;
    ubyte*              rsRawString = NULL;
    ubyte4              rsRawLen = 0;

    if ((NULL == pECCKey) || (NULL == rsString) || (NULL == pIsGoodSignature))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* move past signature string length to R's length */
    index1 = 4;

    /* read R */
    rsRawString = rsString->pString;
    rsRawLen = rsString->stringLen;

    status = SSH_getByteStringFromMpintBytes(rsRawString + index1, rsRawLen - index1, &pR, &rLen);
    if (OK != status)
        goto exit;

    /* move pointer forward the # of bytes written */
    rsRawString = (rsRawString + rLen + index1 + index1);
    rsRawLen = (rsRawLen - rLen - index1 - index1);

    status = SSH_getByteStringFromMpintBytes(rsRawString, rsRawLen, &pS, &sLen);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_ECDSA_verifySignatureDigestAux(MOC_ECC(hwAccelCtx) pECCKey, (ubyte*)hash, hashLen, pR, rLen, pS, sLen, (ubyte4*)pIsGoodSignature);
    if (OK != status)
        goto exit;
#else
    status = ECDSA_verifySignatureDigest(MOC_ECC(hwAccelCtx) pECCKey, (ubyte*)hash, hashLen, pR, rLen, pS, sLen, (ubyte4*)pIsGoodSignature);
    if (OK != status)
        goto exit;
#endif
    
    if (0 == *pIsGoodSignature)
        *pIsGoodSignature = 1;
    else
        *pIsGoodSignature = 0;

exit:
    
    if (NULL != pR)
        DIGI_FREE((void**)&pR);

    if (NULL != pS)
        DIGI_FREE((void**)&pS);
    return status;

}


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_ECDSA_verifyEcdsaSignature(MOC_ECC(hwAccelDescr hwAccelCtx) AsymmetricKey *pPublicKey,
                               intBoolean isServer, const ubyte* hash, ubyte4 hashLen,
                               sshStringBuffer* pSignature, intBoolean *pIsGoodSignature,
                               vlong **ppVlongQueue)
{
    sshStringBuffer*    tempString = NULL;
    sshStringBuffer*    rsString   = NULL;
    ubyte4              curveId = 0;
    ECCKey*             pECCKey = NULL;
    ubyte4              index      = 4;     /* skip past signature-string-length field */
    sbyte4              result;
    sshEcdsaCurveIdDescr*    pCurveDescr;
    sshStringBuffer*    ssh_ecdsa_signature = NULL;
    MSTATUS             status;

    if (NULL == pIsGoodSignature)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pIsGoodSignature = FALSE;

    if ((akt_ecc != pPublicKey->type) && (akt_ecc_ed != pPublicKey->type))
    {
        status = ERR_SSH_EXPECTED_ECC_KEY;
        goto exit;
    }

    if (NULL == (pECCKey = pPublicKey->key.pECC))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pECCKey, &curveId);
    if(OK != status)
        goto exit;
#else
    status = EC_getCurveIdFromKey(pECCKey, &curveId);
    if (OK != status)
        goto exit;
#endif

    if (NULL == (pCurveDescr = SSH_ECDSA_findByCurveId(curveId)))
    {
        status = ERR_SSH_UNSUPPORTED_CURVE;
        goto exit;
    }
 #ifdef __ENABLE_DIGICERT_SSH_SERVER__
    switch (pCurveDescr->curveLength)
    {
      case 192: ssh_ecdsa_signature = &ssh_ecdsa_signature_p192;
                break;
      case 224: ssh_ecdsa_signature = &ssh_ecdsa_signature_p224;
                break;
      case 256: ssh_ecdsa_signature = &ssh_ecdsa_signature_p256;
                break;
      case 384: ssh_ecdsa_signature = &ssh_ecdsa_signature_p384;
                break;
      case 521: ssh_ecdsa_signature = &ssh_ecdsa_signature_p521;
                break;
      default : status = ERR_SSH_UNSUPPORTED_CURVE;
                goto exit;
    }
 #endif
 #ifdef __ENABLE_DIGICERT_SSH_CLIENT__
    switch (pCurveDescr->curveLength)
    {
      case 192: ssh_ecdsa_signature = &sshc_ecdsa_signature_p192;
                break;
      case 224: ssh_ecdsa_signature = &sshc_ecdsa_signature_p224;
                break;
      case 256: ssh_ecdsa_signature = &sshc_ecdsa_signature_p256;
                break;
      case 384: ssh_ecdsa_signature = &sshc_ecdsa_signature_p384;
                break;
      case 521: ssh_ecdsa_signature = &sshc_ecdsa_signature_p521;
                break;
      default : status = ERR_SSH_UNSUPPORTED_CURVE;
                goto exit;
    }
 #endif

    /* fetch signature type */
    if (OK > (status = SSH_STR_copyStringFromPayload(pSignature->pString, pSignature->stringLen, &index, &tempString)))
        goto exit;

    DEBUG_RELABEL_MEMORY(tempString);
    DEBUG_RELABEL_MEMORY(tempString->pString);

    /* check signature type */
    if (isServer)
    {
#ifdef __ENABLE_DIGICERT_SSH_SERVER__
        if (OK > (status = DIGI_MEMCMP(tempString->pString, ssh_ecdsa_signature->pString, ssh_ecdsa_signature->stringLen, &result)))
            goto exit;
#else
        status = ERR_SSH_CONFIG;
        goto exit;
#endif
    } else {
#ifdef __ENABLE_DIGICERT_SSH_CLIENT__
        if (OK > (status = DIGI_MEMCMP(tempString->pString, ssh_ecdsa_signature->pString, ssh_ecdsa_signature->stringLen, &result)))
            goto exit;
#else
        status = ERR_SSH_CONFIG;
        goto exit;
#endif
    }

    if (0 != result)
    {
        status = ERR_SSH_MALFORMED_SIGNATURE;
        goto exit;
    }

    /* fetch r & s */
    if (OK > (status = SSH_STR_copyStringFromPayload(pSignature->pString, pSignature->stringLen, &index, &rsString)))
        goto exit;

    DEBUG_RELABEL_MEMORY(rsString);
    DEBUG_RELABEL_MEMORY(rsString->pString);

    status = SSH_ECDSA_verifyRSValue(MOC_ECC(hwAccelCtx) pPublicKey->key.pECC,
        hash, hashLen, rsString, pIsGoodSignature, ppVlongQueue);
    if (OK != status)
        goto exit;

exit:
    SSH_STR_freeStringBuffer(&tempString);
    SSH_STR_freeStringBuffer(&rsString);
    
    return status;

} /* SSH_ECDSA_verifyEcdsaSignature */

#endif /* ((defined(__ENABLE_DIGICERT_ECC__)) && (defined(__ENABLE_DIGICERT_SSH_SERVER__) || defined(__ENABLE_DIGICERT_SSH_CLIENT__))) */
