/**
 * @file tpm2_server_helpers.c
 * @brief This file includes helpers required on the server side of the
 * privacy CA protocol. A CA may use these helper functions to perform
 * wrapping of credentials etc without the need for a TPM.
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 */

#include "../../../../common/moptions.h"

#ifdef __ENABLE_DIGICERT_SMP_PKCS11__
#define __ENABLE_DIGICERT_TPM2__
#endif

#include "../../../../common/mtypes.h"
#include "../../../../common/merrors.h"
#include "../../../../common/mocana.h"
#include "../../../../common/mdefs.h"
#include "../../../../common/mstdlib.h"
#include "../../../../common/mprintf.h"
#include "../../../../common/debug_console.h"
#include "../../../../crypto/hw_accel.h"
#include "../../../../crypto/crypto.h"
#include "../../../../crypto/pubcrypto.h"
#include "../../../../crypto/pkcs1.h"
#include "../../../../crypto/md5.h"
#include "../../../../crypto/sha1.h"
#include "../../../../crypto/sha256.h"
#include "../../../../crypto/sha512.h"
#include "../../../../crypto/hmac.h"
#include "../../../../crypto/aes.h"
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../../../../crypto_interface/cryptointerface.h"
#include "../../../../crypto_interface/crypto_interface_aes.h"
#endif
#include "../tap_serialize_tpm2.h"
#include "../sapi2/sapi2_utils.h"
#include "tpm2_server_helpers.h"

typedef struct {
    /*
     * key algorithm of the encryption key(EK). This must be
     * either TPM2_ALG_RSA or TPM2_ALG_ECC.
     */
    TPMI_ALG_PUBLIC keyAlg;

    /*
     * Name algorithm of the encryption key (EK). This must be
     * one of the hash algorithms TPM2_ALG_SHA1, TPM2_ALG_SHA256,
     * TPM2_ALG_SHA384, TPM2_ALG_SHA512.
     */
    TPM2_ALG_ID ekNameAlg;

    union {
        /*
         * RSA Public key for the EK.
         */
        RSAKey *pRsaPublicKey;
#ifdef __ENABLE_DIGICERT_ECC__
        /*
         * ECC Public key for the EK.
         */
        ECCKey *pPublicEccKey;
#endif
    } publicKeyInfo;

    /*
     * Credential or secret that neeeds to be wrapped using the privacy
     * CA protocol.
     */
    TPM2B_DIGEST *pCredential;

    /*
     * Name of the key for which the credential/secret is being provided
     * for.
     */
    TPM2B_NAME *pObjectName;
} TPM2_MakeCredentialSwIn;

typedef TPM2_MAKE_CREDENTIAL_RSP_PARAMS TPM2_MakeCredentialSwOut;

void dumpHexByteBuffer(ubyte *pBuffer, ubyte4 size, const char *label)
{
#if defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
    int i;

    DB_PRINT("\n%s: ", label);
    for (i = 0; i < size; i++)
    {
        DB_PRINT("0x%x ", pBuffer[i]);
    }
    DB_PRINT("\n");
#else
    return;
#endif
}

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__

static ubyte4 TPM2_RSA_getBitLength(
    RSAKey *pRsaKey
    )
{
    ubyte4 modLenBits = 0;
    MRsaKeyTemplate template = { 0 };
    MSTATUS status;
    ubyte *pMod = NULL;

    status = CRYPTO_INTERFACE_RSA_getKeyParametersAllocAux(
        pRsaKey, &template, MOC_GET_PUBLIC_KEY_DATA);
    if (OK != status)
        goto exit;

    pMod = template.pN;

    /* Calculate the modulus length in bits.
     */
    modLenBits = (template.nLen * 8) - 8 + BITLENGTH(*pMod);

exit:

    CRYPTO_INTERFACE_RSA_freeKeyTemplateAux(pRsaKey, &template);

    return modLenBits;
}

#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */

static MSTATUS TPM2_makeCredentialSw(
        TPM2_MakeCredentialSwIn *pIn,
        TPM2_MakeCredentialSwOut *pOut
)
{
    MSTATUS status = ERR_GENERAL;
    const BulkHashAlgo *pHashAlg = NULL;
    ubyte oaepHashOid = 0;
    ubyte4 serializedOffset = 0;
    ubyte4 curveId = 0;

    /*
     * Create a structure for local variables required, that are of significant size.
     * Putting them in a structure so that they can all be malloced once and free'd
     * once.
     */
    typedef struct {
        BulkCtx aesCfbCtx;
        hwAccelDescr    hwAccelCtx;
        ubyte4 roundedSize;
        ubyte4 updateLen;
        ubyte ivEncrypt[16];
        TPM2B_DATA seed;
        TPM2B_DIGEST symKey;
        TPM2B_DIGEST hmacKey;
        TPMS_ID_OBJECT idObject;
    } local_struct_t;

    local_struct_t *pLocalVars = NULL;

    if (!pIn->pCredential || !pIn->pObjectName || !pOut)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid inputs\n", __FUNCTION__,
                        __LINE__);
        goto exit;
    }

    if ((TPM2_ALG_RSA != pIn->keyAlg)
#ifdef __ENABLE_DIGICERT_ECC__
            && (TPM2_ALG_ECC != pIn->keyAlg)
#endif
            )
    {
        status = ERR_INVALID_INPUT;
        DB_PRINT("%s.%d Invalid keyAlg\n", __FUNCTION__,
                        __LINE__);
        goto exit;
    }

    if ((TPM2_ALG_SHA1 != pIn->ekNameAlg) && (TPM2_ALG_SHA256 != pIn->ekNameAlg) &&
            (TPM2_ALG_SHA384 != pIn->ekNameAlg) && (TPM2_ALG_SHA512 != pIn->ekNameAlg))
    {
        status = ERR_INVALID_INPUT;
        DB_PRINT("%s.%d Invalid ek name alg\n", __FUNCTION__,
                __LINE__);
        goto exit;
    }

    if ((pIn->pCredential->size > sizeof(pIn->pCredential->buffer)) ||
            (pIn->pObjectName->size) > sizeof(pIn->pObjectName->name))
    {
        status = ERR_UNSUPPORTED_SIZE;
        DB_PRINT("%s.%d Invalid size for credential or object name\n", __FUNCTION__,
                __LINE__);
        goto exit;
    }

    if ((TPM2_ALG_RSA == pIn->keyAlg) && (NULL == pIn->publicKeyInfo.pRsaPublicKey))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid rsa public key\n", __FUNCTION__,
                        __LINE__);
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_ECC__
    if ((TPM2_ALG_ECC == pIn->keyAlg))
    {
        if (NULL == pIn->publicKeyInfo.pPublicEccKey)
        {
            status = ERR_NULL_POINTER;
            DB_PRINT("%s.%d Invalid rsa public key\n", __FUNCTION__,
                    __LINE__);
            goto exit;
        }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(
            pIn->publicKeyInfo.pPublicEccKey, &curveId);
        if (OK != status)
        {
            DB_PRINT("%s.%d Invalid curve specified\n", __FUNCTION__,
                    __LINE__);
            goto exit;
        }

        switch (curveId)
        {
            case cid_EC_P224:
            case cid_EC_P256:
            case cid_EC_P384:
            case cid_EC_P521:
                break;
            
            default:
                status = ERR_EC_UNSUPPORTED_CURVE;
                DB_PRINT("%s.%d Invalid curve specified\n", __FUNCTION__,
                    __LINE__);
                goto exit;
        }
#else
        if ((EC_P224 != pIn->publicKeyInfo.pPublicEccKey->pCurve) &&
                (EC_P256 != pIn->publicKeyInfo.pPublicEccKey->pCurve) &&
                (EC_P384 != pIn->publicKeyInfo.pPublicEccKey->pCurve) &&
                (EC_P521 != pIn->publicKeyInfo.pPublicEccKey->pCurve))
        {
            status = ERR_EC_UNSUPPORTED_CURVE;
            DB_PRINT("%s.%d Invalid curve specified\n", __FUNCTION__,
                    __LINE__);
            goto exit;
        }
#endif
    }
#endif

    if (OK != (status = SAPI2_UTILS_getHashAlgFromAlgId(pIn->ekNameAlg, &pHashAlg, &oaepHashOid)))
    {
        DB_PRINT("%s.%d Unable to get hash algorithm information\n", __FUNCTION__,
                __LINE__);
        goto exit;
    }

    if (OK != (status = DIGI_CALLOC((void **)&pLocalVars, 1, sizeof(*pLocalVars))))
    {
        DB_PRINT("%s.%d Failed to allocate memory\n", __FUNCTION__,
                __LINE__);
        goto exit;
    }

    /*
     * seed size is the size of the name algorithm of the encryption key.
     */
    pLocalVars->seed.size = pHashAlg->digestSize;

    /*
     * Size of hmac key is the same as size of hash algorithm digest.
     */
    pLocalVars->hmacKey.size = pHashAlg->digestSize;

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &(pLocalVars->hwAccelCtx));
    if (OK != status)
        goto exit;
#endif
    
    /*
     * Create seed and encrypted secret.
     */
    switch (pIn->keyAlg)
    {
    case TPM2_ALG_RSA:
        if (TSS2_RC_SUCCESS != SAPI2_UTILS_generateRsaSeed(
                MOC_RSA(pLocalVars->hwAccelCtx)
                pIn->publicKeyInfo.pRsaPublicKey,
                oaepHashOid,
                (const ubyte *)"IDENTITY",
                sizeof("IDENTITY"),
                pLocalVars->seed.buffer,
                pLocalVars->seed.size,
                &(pOut->secret))
        )
        {
            status = ERR_INTERNAL_ERROR;
            DB_PRINT("%s.%d Failed to generate rsa seed\n", __FUNCTION__,
            __LINE__);
            goto exit;
        }

        pLocalVars->symKey.size = 16;
        /*
         *  By default use AES 128. Use 256 if RSA key is > 2048 bits,
         *  or bit strength of EC Curve is > 256.
         */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        if (TPM2_RSA_getBitLength(pIn->publicKeyInfo.pRsaPublicKey) > 2048)
            pLocalVars->symKey.size = 32;
#else
        if (RSA_KEYSIZE(pIn->publicKeyInfo.pRsaPublicKey) > 2048)
            pLocalVars->symKey.size = 32;
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
        break;
#ifdef __ENABLE_DIGICERT_ECC__
    case TPM2_ALG_ECC:
        if (TSS2_RC_SUCCESS !=
                SAPI2_UTILS_generateECCSeed(MOC_ECC(pLocalVars->hwAccelCtx) pIn->publicKeyInfo.pPublicEccKey,
                        (const ubyte *)"IDENTITY",
                        sizeof("IDENTITY"),
                        pIn->ekNameAlg,
                        pLocalVars->seed.buffer,
                        pLocalVars->seed.size,
                        &(pOut->secret)))
        {
            status = ERR_INTERNAL_ERROR;
            DB_PRINT("%s.%d Failed to generate ecc seed\n", __FUNCTION__,
            __LINE__);
            goto exit;
        }
        pLocalVars->symKey.size = 16;
        /*
         *  By default use AES 128. Use 256 if RSA key is > 2048 bits,
         *  or bit strength of EC Curve is > 256.
         */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        if ((curveId == cid_EC_P384) || (curveId == cid_EC_P521))
#else
        if ((pIn->publicKeyInfo.pPublicEccKey->pCurve == EC_P384) ||
                (pIn->publicKeyInfo.pPublicEccKey->pCurve == EC_P521))
#endif
            pLocalVars->symKey.size = 32;

        break;
#endif
    default:
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d Unexpected error\n", __FUNCTION__,
                            __LINE__);
        goto exit;
    }

    dumpHexByteBuffer(pLocalVars->seed.buffer, pLocalVars->seed.size, "Seed");
    dumpHexByteBuffer(pOut->secret.secret, pOut->secret.size, "Encrypted Seed");
    dumpHexByteBuffer(pIn->pObjectName->name, pIn->pObjectName->size, "Name");

    /*
     * Use seed to generate symKey and HMAC key.
     */
    if (TSS2_RC_SUCCESS != SAPI2_UTILS_TPM2_KDFA(pIn->ekNameAlg,
            pLocalVars->seed.buffer, pLocalVars->seed.size,
            "STORAGE", pIn->pObjectName->name, pIn->pObjectName->size,
            NULL, 0,
            pLocalVars->symKey.buffer, pLocalVars->symKey.size))
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d Failed KDFA for encryption key\n", __FUNCTION__,
                            __LINE__);
        goto exit;
    }

    dumpHexByteBuffer(pLocalVars->symKey.buffer, pLocalVars->symKey.size, "SymKey");

    if (TSS2_RC_SUCCESS != SAPI2_UTILS_TPM2_KDFA(pIn->ekNameAlg,
            pLocalVars->seed.buffer, pLocalVars->seed.size,
            "INTEGRITY", NULL, 0, NULL, 0,
            pLocalVars->hmacKey.buffer, pLocalVars->hmacKey.size))
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d Failed KDFA for hmac key\n", __FUNCTION__,
                            __LINE__);
        goto exit;
    }

    dumpHexByteBuffer(pLocalVars->hmacKey.buffer, pLocalVars->hmacKey.size, "HmacKey");

    /*
     * Use symmetric key derived to encrypt the credential given as input.
     * AES CFB(symKey, 0, credentialValue)
     */
    serializedOffset = 0;
    status = TAP_SERIALIZE_serialize(&TPM2_SHADOW_TPM2B_DIGEST, TAP_SD_IN,
            (ubyte*)pIn->pCredential, sizeof(*(pIn->pCredential)),
            pLocalVars->idObject.encIdentity.buffer, sizeof(pLocalVars->idObject.encIdentity.buffer),
            &serializedOffset);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to serialize credential\n", __FUNCTION__,
        __LINE__);
        goto exit;
    }
    pLocalVars->idObject.encIdentity.size = serializedOffset;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (NULL == (pLocalVars->aesCfbCtx = CRYPTO_INTERFACE_CreateAESCFBCtx(
            MOC_SYM(pLocalVars->hwAccelCtx) pLocalVars->symKey.buffer,
            pLocalVars->symKey.size, TRUE)))
#else
    if (NULL == (pLocalVars->aesCfbCtx = CreateAESCFBCtx(MOC_SYM(pLocalVars->hwAccelCtx)
            pLocalVars->symKey.buffer, pLocalVars->symKey.size, TRUE)))
#endif
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d Failed to create AES context\n", __FUNCTION__,
                        __LINE__);
        goto exit;
    }

    /*
     * if size not multiple of AES_BLOCK_SIZE, round up the size.
     * The block should already be padded with 0's during DIGI_CALLOC of pLocalVars.
     */
    pLocalVars->roundedSize =
            (pLocalVars->idObject.encIdentity.size + AES_BLOCK_SIZE - 1) & ~(AES_BLOCK_SIZE - 1);

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK != (status = CRYPTO_INTERFACE_DoAES(
            MOC_SYM(pLocalVars->hwAccelCtx) pLocalVars->aesCfbCtx,
            (ubyte *)pLocalVars->idObject.encIdentity.buffer,
            pLocalVars->roundedSize, TRUE,
            pLocalVars->ivEncrypt)))
#else
    if (OK != (status = DoAES(MOC_SYM(pLocalVars->hwAccelCtx) pLocalVars->aesCfbCtx,
            (ubyte *)pLocalVars->idObject.encIdentity.buffer,
            pLocalVars->roundedSize, TRUE,
            pLocalVars->ivEncrypt)))
#endif
    {
        DB_PRINT("%s.%d Failed to CFB encrypt\n", __FUNCTION__,
                        __LINE__);
        goto exit;
    }

    dumpHexByteBuffer(pLocalVars->idObject.encIdentity.buffer,
            pLocalVars->idObject.encIdentity.size, "EncCredential");

    /*
     * Use HMAC key to integrity protect the credential blob.
     */

    if (OK != (status = HmacQuickEx(MOC_HASH(pLocalVars->hwAccelCtx)
            pLocalVars->hmacKey.buffer,pLocalVars->hmacKey.size,
            pLocalVars->idObject.encIdentity.buffer, pLocalVars->idObject.encIdentity.size,
            pIn->pObjectName->name, pIn->pObjectName->size,
            pLocalVars->idObject.integrityHMAC.buffer, pHashAlg)))
    {
        DB_PRINT("%s.%d Failed to hmac credential blob\n", __FUNCTION__,
                __LINE__);
        goto exit;
    }
    pLocalVars->idObject.integrityHMAC.size = pHashAlg->digestSize;

    dumpHexByteBuffer(pLocalVars->idObject.integrityHMAC.buffer,
            pLocalVars->idObject.integrityHMAC.size, "HMAC");

    /*
     * Manually serialize the idObject into the credential buffer. Per the spec, the
     * id object contains two TPM2B_DIGEST structures, which means upon serialization,
     * the buffer will contain:
     * (size of integrity)(integrity)(size of encrypted data)( encrypted data).
     *
     * However, when the TPM creates the TPM2B_ID_OBJECT, it produces
     * (size of integrity)(integrity)( encrypted data)
     * If we use our serialization framework, we will get a serialized buffer corresponding to
     * TPMS_ID_OBJECT and not like the TPM produces. This causes failures with hmac verification
     * on the TPM2 when trying to activate a software made credential.
     * Example: Suppose we have a credential of 32 bytes, a HMAC sha256, which is 32 bytes,
     * our serialization code would produce a TPM2B_ID_OBJECT of size 2 bytes(size of integrity buffer)
     * + 32 bytes (size of the HMAC itself) + 2 bytes(size of encrypted data) + 34 bytes(since the 32 byte
     * credential is a TPM2B itself, we would encrypt 34 bytes, 2 bytes for the plaintext size
     * and 32 bytes of plaintext data) and produce a serialized blob of 70 bytes.
     * However, the TPM will produce a 68 byte sized TPM2B_ID_OBJECT, since it leaves out the 2 bytes
     * for size of encrypted data(understandably so, since the encrypted data itself contains the size).
     */
    pOut->credentialBlob.size = 0;

    /*
     * Serialize the HMAC into the credential buffer normally.
     */
    serializedOffset = 0;
    status = TAP_SERIALIZE_serialize(&TPM2_SHADOW_TPM2B_DIGEST, TAP_SD_IN,
            (ubyte*)&(pLocalVars->idObject.integrityHMAC), sizeof(pLocalVars->idObject.integrityHMAC),
            pOut->credentialBlob.credential, sizeof(pOut->credentialBlob.credential),
            &serializedOffset);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to serialize HMAC into credential\n", __FUNCTION__,
        __LINE__);
        goto exit;
    }
    pOut->credentialBlob.size = serializedOffset;

    /*
     * Add size of encrypted data and copy it.
     */
    pOut->credentialBlob.size +=
            pLocalVars->idObject.encIdentity.size;

    if (OK != DIGI_MEMCPY((void *)(pOut->credentialBlob.credential + serializedOffset),
            pLocalVars->idObject.encIdentity.buffer,
            pLocalVars->idObject.encIdentity.size))
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d Failed memcpy\n", __FUNCTION__,
        __LINE__);
        goto exit;
    }

    status = OK;
exit:
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (pLocalVars && pLocalVars->aesCfbCtx)
        CRYPTO_INTERFACE_DeleteAESCtx(MOC_SYM(pLocalVars->hwAccelCtx) &(pLocalVars->aesCfbCtx));
#else
    if (pLocalVars && pLocalVars->aesCfbCtx)
        DeleteAESCtx(MOC_SYM(pLocalVars->hwAccelCtx) &(pLocalVars->aesCfbCtx));
#endif
    
    if (pLocalVars)
    {
#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
        (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &(pLocalVars->hwAccelCtx));
#endif
        DIGI_FREE((void **)&pLocalVars);
    }

    return status;
}

MOC_EXTERN MSTATUS SMP_TPM2_wrapCredentialSecret(
        AsymmetricKey *pAkPublicKey,
        AsymmetricKey *pRoTPublicKey,
        ubyte *pBase64Blob,
        ubyte4 blobLen,
        ubyte *pDecryptKey,
        ubyte4 decryptKeyLen,
        ubyte **ppEncryptedDecryptKey,
        ubyte4 *pEncryptedDecryptKeyLen
)
{
    MSTATUS status = ERR_GENERAL;
    typedef struct {
        ubyte *pCsrInfo;
        ubyte4 csrInfoLen;
        TPM2_AK_CSR_INFO csrInfoStruct;
        ubyte4 serializationOffset;
        TPM2B_PUBLIC_KEY_RSA akPublicKeyBuffer;
        TPMS_ECC_POINT encryptKeyTpm2Form;
        TPM2B_DIGEST credential;
        TPM2_MakeCredentialSwIn makeCredentialIn;
        TPM2_MakeCredentialSwOut makeCredentialOut;
        ubyte serializedCredential[sizeof(TPM2_MakeCredentialSwOut)];
        TPM2B_NAME akName;
    } local_vars_t;

    TPMA_OBJECT akAttributes = 0;
    TPMA_OBJECT ekAttributes = 0;

    sbyte4 cmpResult = 0;
    local_vars_t *pLocalVars = NULL;
    
#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    hwAccelDescr hwAccelCtx = 0;
#endif

    if (!pAkPublicKey || !pRoTPublicKey || !pBase64Blob ||
            (0 == blobLen) || !pDecryptKey || (0 == decryptKeyLen) ||
            (*ppEncryptedDecryptKey != NULL) || !pEncryptedDecryptKeyLen)
    {
        status = ERR_INVALID_INPUT;
        DB_PRINT("%s.%d Invalid inputs\n", __FUNCTION__,
                        __LINE__);
        goto exit;
    }

    if ((pAkPublicKey->type != akt_rsa)
#ifdef __ENABLE_DIGICERT_ECC__
            && (pAkPublicKey->type != akt_ecc)
#endif
            )
    {
        status = ERR_INVALID_INPUT;
        DB_PRINT("%s.%d Invalid AK\n", __FUNCTION__,
                        __LINE__);
        goto exit;
    }

    if ((pAkPublicKey->type == akt_rsa) && (NULL == pAkPublicKey->key.pRSA))
    {
        status = ERR_INVALID_INPUT;
        DB_PRINT("%s.%d Invalid RSA AK\n", __FUNCTION__,
                        __LINE__);
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_ECC__
    if ((pAkPublicKey->type == akt_ecc) && (NULL == pAkPublicKey->key.pECC))
    {
        status = ERR_INVALID_INPUT;
        DB_PRINT("%s.%d Invalid ECC AK\n", __FUNCTION__,
                __LINE__);
        goto exit;
    }
#endif
    if ((pRoTPublicKey->type != akt_rsa)
#ifdef __ENABLE_DIGICERT_ECC__
            && (pRoTPublicKey->type != akt_ecc)
#endif
            )
    {
        status = ERR_INVALID_INPUT;
        DB_PRINT("%s.%d Invalid AK\n", __FUNCTION__,
                        __LINE__);
        goto exit;
    }

    if ((pRoTPublicKey->type == akt_rsa) && (NULL == pRoTPublicKey->key.pRSA))
    {
        status = ERR_INVALID_INPUT;
        DB_PRINT("%s.%d Invalid RSA AK\n", __FUNCTION__,
                        __LINE__);
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_ECC__
    if ((pRoTPublicKey->type == akt_ecc) && (NULL == pRoTPublicKey->key.pECC))
    {
        status = ERR_INVALID_INPUT;
        DB_PRINT("%s.%d Invalid ECC AK\n", __FUNCTION__,
                __LINE__);
        goto exit;
    }
#endif

    status = DIGI_CALLOC((void **)&pLocalVars, 1, sizeof(*pLocalVars));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory for Csr attribute struct\n", __FUNCTION__,
                __LINE__);
        goto exit;
    }

    status = BASE64_decodeMessage(pBase64Blob, blobLen,
            &(pLocalVars->pCsrInfo), &(pLocalVars->csrInfoLen));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to decode base 64 csr attributes\n", __FUNCTION__,
                __LINE__);
        goto exit;
    }

    status = TAP_SERIALIZE_serialize(&TPM2_SHADOW_TPM2_AK_CSR_INFO,
            TAP_SD_OUT,
            (ubyte *)pLocalVars->pCsrInfo, pLocalVars->csrInfoLen,
            (ubyte *)&pLocalVars->csrInfoStruct, sizeof(pLocalVars->csrInfoStruct),
            &(pLocalVars->serializationOffset));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to deserialize csr attributes\n", __FUNCTION__,
                __LINE__);
        goto exit;
    }

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    if (OK != status)
        goto exit;
#endif
    
    /*
     * Match AK public key to the one in CsrInfoStruct
     */
    if (pAkPublicKey->type == akt_rsa)
    {
        if (TSS2_RC_SUCCESS !=
                SAPI2_UTILS_convertRSAPublicToTpm2RsaPublic(MOC_RSA(hwAccelCtx) pAkPublicKey->key.pRSA,
                        &(pLocalVars->akPublicKeyBuffer))
                )
        {
            status = ERR_INVALID_ARG;
            DB_PRINT("%s.%d Failed to get public key\n", __FUNCTION__,
                    __LINE__);
            goto exit;
        }

        cmpResult = 0;
        status = DIGI_MEMCMP((const ubyte *)pLocalVars->akPublicKeyBuffer.buffer,
                pLocalVars->csrInfoStruct.akPublicArea.unique.rsa.buffer,
                pLocalVars->csrInfoStruct.akPublicArea.unique.rsa.size, &cmpResult);
        if ((OK != status) || (0 != cmpResult))
        {
            status = ERR_INVALID_INPUT;
            DB_PRINT("%s.%d Public RSA AK provided does not match with the base64 blob"
                    " provided.\n", __FUNCTION__,
                    __LINE__);
            goto exit;
        }
    }
#ifdef __ENABLE_DIGICERT_ECC__
    else if (pAkPublicKey->type == akt_ecc)
    {
        if (TSS2_RC_SUCCESS !=
                SAPI2_UTILS_convertEccPointToTpm2Point(MOC_ECC(hwAccelCtx) pAkPublicKey->key.pECC,
                        &(pLocalVars->encryptKeyTpm2Form))
                )
        {
            status = ERR_INVALID_ARG;
            DB_PRINT("%s.%d Failed to convert ECC public key\n", __FUNCTION__,
                    __LINE__);
            goto exit;
        }

        cmpResult = 0;
        status = DIGI_MEMCMP((const ubyte *)&(pLocalVars->encryptKeyTpm2Form),
                (const ubyte *)&(pLocalVars->csrInfoStruct.akPublicArea.unique.ecc),
                sizeof(pLocalVars->csrInfoStruct.akPublicArea.unique.ecc), &cmpResult);
        if ((OK != status) || (0 != cmpResult))
        {
            status = ERR_INVALID_INPUT;
            DB_PRINT("%s.%d Public ECC AK provided does not match with the base64 blob"
                    " provided.\n", __FUNCTION__,
                    __LINE__);
            goto exit;
        }
    }
#endif
    /*
     * Verify AK object properties. Must be restricted signing key, fixed to a TPM,
     * whose sensitive data was created by the TPM.
     */
    akAttributes = pLocalVars->csrInfoStruct.akPublicArea.objectAttributes;
    if (!(akAttributes & TPMA_OBJECT_FIXEDTPM) ||
            !(akAttributes & TPMA_OBJECT_RESTRICTED) ||
            !(akAttributes & TPMA_OBJECT_SENSITIVEDATAORIGIN) ||
            !(akAttributes & TPMA_OBJECT_SIGN_ENCRYPT))
    {
        status = ERR_INVALID_INPUT;
        DB_PRINT("%s.%d AK not a restricted, signing, fixedTPM key.\n", __FUNCTION__,
                __LINE__);
        goto exit;
    }

    /*
     * Verify EK object properties. Must be a restricted decryption key, fixed to a TPM,
     * whose sensitive data was created by the TPM.
     */
    ekAttributes = pLocalVars->csrInfoStruct.ekObjectAttributes;
    if (!(ekAttributes & TPMA_OBJECT_FIXEDTPM) ||
            !(ekAttributes & TPMA_OBJECT_RESTRICTED) ||
            !(ekAttributes & TPMA_OBJECT_SENSITIVEDATAORIGIN) ||
            !(ekAttributes & TPMA_OBJECT_DECRYPT))
    {
        status = ERR_INVALID_INPUT;
        DB_PRINT("%s.%d AK not a restricted, signing, fixedTPM key.\n", __FUNCTION__,
                __LINE__);
        goto exit;
    }

    /*
     * Verify key length not greater than max size of TPM2B_DIGEST
     */
    if (decryptKeyLen > sizeof(pLocalVars->credential.buffer))
    {
        status = ERR_BAD_LENGTH;
        DB_PRINT("%s.%d Credential Key too long.\n", __FUNCTION__,
                __LINE__);
        goto exit;
    }

    status = DIGI_MEMCPY((void *)(pLocalVars->credential.buffer),
            (const void *)pDecryptKey, decryptKeyLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy memory.\n", __FUNCTION__,
                __LINE__);
        goto exit;
    }

    pLocalVars->credential.size = decryptKeyLen;

    /*
     * Use dummy transient handle for getting object name.
     */
    if (TSS2_RC_SUCCESS != SAPI2_UTILS_getObjectName(TPM2_TRANSIENT_FIRST,
            &(pLocalVars->csrInfoStruct.akPublicArea), &(pLocalVars->akName)))
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d Failed to get AK name.\n", __FUNCTION__,
                __LINE__);
        goto exit;
    }

    /*
     * Make Credential
     */
    pLocalVars->makeCredentialIn.ekNameAlg = pLocalVars->csrInfoStruct.ekNameAlg;
    pLocalVars->makeCredentialIn.pCredential = &(pLocalVars->credential);
    pLocalVars->makeCredentialIn.pObjectName = &(pLocalVars->akName);
    if (pRoTPublicKey->type == akt_rsa)
    {
        pLocalVars->makeCredentialIn.keyAlg = TPM2_ALG_RSA;
        pLocalVars->makeCredentialIn.publicKeyInfo.pRsaPublicKey =
                pRoTPublicKey->key.pRSA;
    }
#ifdef __ENABLE_DIGICERT_ECC__
    else if (pRoTPublicKey->type == akt_ecc)
    {
        pLocalVars->makeCredentialIn.keyAlg = TPM2_ALG_ECC;
        pLocalVars->makeCredentialIn.publicKeyInfo.pPublicEccKey =
                pRoTPublicKey->key.pECC;
    }
#endif
    status = TPM2_makeCredentialSw(&(pLocalVars->makeCredentialIn),
            &(pLocalVars->makeCredentialOut));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to make credential.\n", __FUNCTION__,
                __LINE__);
        goto exit;
    }

    /*
     * Serialize makeCredentialOut buffer
     */
    pLocalVars->serializationOffset = 0;
    status = TAP_SERIALIZE_serialize(&TPM2_SHADOW_TPM2_MAKE_CREDENTIAL_RSP_PARAMS,
            TAP_SD_IN,
            (ubyte *)&(pLocalVars->makeCredentialOut),
            sizeof(pLocalVars->makeCredentialOut),
            pLocalVars->serializedCredential, sizeof(pLocalVars->serializedCredential),
            &(pLocalVars->serializationOffset));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to deserialize csr attributes\n", __FUNCTION__,
                __LINE__);
        goto exit;
    }

    /*
     * Wrap in base64 blob
     */
    status = BASE64_encodeMessage((const ubyte *)pLocalVars->serializedCredential,
            pLocalVars->serializationOffset,
            ppEncryptedDecryptKey,
            pEncryptedDecryptKeyLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to base 64 encode credential blob\n", __FUNCTION__,
                __LINE__);
        goto exit;
    }

    status = OK;
exit:
    
#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
#endif
    
    if (pLocalVars)
    {
        if (pLocalVars->pCsrInfo && (pLocalVars->csrInfoLen != 0))
            DIGI_FREE((void **)&pLocalVars->pCsrInfo);

        DIGI_FREE((void **)&pLocalVars);
    }
    return status;
}
