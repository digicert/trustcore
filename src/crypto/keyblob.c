/*
 * keyblob.c
 *
 * Functions for serializing key blobs
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

/**
@file       keyblob.c
@brief      Mocana SoT Platform key blob management code.
@details    This file contains SoT Platform key blob management functions.

@since 1.41
@version 6.4 and later
@todo_version   (revised post-6.4, commit [3c61741], April 14, 2016.)

@flags
Whether the following flags are defined determines which functions are enabled:
+ \c \__ENABLE_DIGICERT_DSA__
+ \c \__ENABLE_DIGICERT_ECC__

@filedoc    keyblob.c
*/

#include "../common/moptions.h"

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/secmod.h"
#include "../common/mrtos.h"
#include "../common/tree.h"
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../common/mstdlib.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../common/memory_debug.h"
#include "../common/base64.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto/crypto.h"
#ifdef __ENABLE_DIGICERT_DSA__
#include "../crypto/dsa.h"
#endif
#include "../crypto/rsa.h"
#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto/primefld.h"
#include "../crypto/ecc.h"
#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__
#include "../crypto/ecc_edwards_keys.h"
#endif
#endif /* __ENABLE_DIGICERT_ECC__ */

#include "../crypto/pubcrypto.h"
#include "../crypto/keyblob.h"
#include "../harness/harness.h"
#include "../asn1/oiddefs.h"
#include "../crypto/malgo_id.h"
#include "../common/utils.h"
#if defined(__ENABLE_DIGICERT_HW_SECURITY_MODULE__)
#include "../smp/smp_tpm12/tpm12_lib/hsmrsainfo.h"
#endif
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/cryptointerface.h"
#endif

/*------------------------------------------------------------------*/

/* Key Blob format
Version 0: supports only RSA keys
            p,q,n,e stored with 4-byte length prefix
Version 0: supports only DSA keys
            two files: 1) p,q,g,y stored with 4-byte length prefix and 2) x (private key) with 4-byte length prefix
Version 1:

4 bytes: all zero
4 bytes: version number 0x00000001
4 bytes: key type       (see keyblob_type_* enum types)
                        0x00000001 : RSA
                        0x00000002 : ECC
                        0x00000003 : DSA
                        0x00010001 : HSM RSA
                        0x00010002 : HSM ECC

switch (keytype)
    case RSA:
        4 bytes length of e string
        n bytes length of e byte string
        4 bytes length of n string
        n bytes length of n byte string
        4 bytes length of p string
        n bytes length of p byte string
        4 bytes length of q string
        n bytes length of q byte string
        4 bytes length of private string #1
        n bytes length of private byte string #1
        4 bytes length of private string #2
        n bytes length of private byte string #2
        4 bytes length of private string #3
        n bytes length of private byte string #3
        4 bytes length of private string #4
        n bytes length of private byte string #4
        4 bytes length of private string #5
        n bytes length of private byte string #5

    case ECC:
        1 byte OID suffix identifying the curve
        4 bytes length of Point string
        n bytes length of Point byte string (uncompressed X9-62 format)
        4 bytes length of Scalar string
        n bytes length of Scalar byte string

    case DSA:
        4 bytes length of p string
        n bytes length of p byte string
        4 bytes length of q string
        n bytes length of q byte string
        4 bytes length of g string
        n bytes length of g byte string
        4 bytes length of y string
        n bytes length of y byte string
        4 bytes length of x string
        n bytes length of x byte string

    case HSM RSA:  (see hsmrsainfo.c for detailed info)TPM12RSAKey, defined in tpm12_rsa.h)
        4 bytes SECMOD_TYPE [extra 4-bytes in header to determine HSM/key type ]
        <variable format, based on SECMOD_TYPE - currently, only TPM 1.2 RSA Keys supported with following format>
        TPM12RSAKeyInfo:
          2 byte tag
          2 byte fill
          2 byte key usage
          4 byte key flags
          1 byte authDataUsage
          4 byte algorithm ID
          2 byte encryption scheme
          2 byte signature scheme
          4 byte parameter size
          n byte parameters
          4 byte PCRInfo size
          n byte PCRInfo
          4 byte pub key size
          n byte pub key
          4 byte encryted data size
          n byte encryted data
        4 bytes key handle
        4 bytes parent key handle

    case HSM ECC:
        (not yet implemented)

Version 2:

    Version 2 keys are created to handle PKCS#8 keys. The version 2 format is
    outlined below.

        4 bytes         - all zeros
        4 bytes         - version number which must be 0x00000002
        4 bytes         - key type which must be one of the KEYBLOB_TYPE enums
        4 bytes         - OID type which must be one of the MAlgoOid enums
        n bytes         - ASN.1 encoded algorithm identifier
        4 bytes         - reserved
        n bytes         - reserved
        4 bytes         - key data length (keylen) 
        keylen bytes    - key data (key data formats are mentioned above)

*/

/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
MSTATUS KEYBLOB_arrayToUbyte4(const ubyte *in, ubyte4 *out)
{
    if ((NULL == out) || (NULL == in))
    {
        return ERR_NULL_POINTER;
    }

    *out = ((in[0] & 0xFF) << 24)  |
            ((in[1] & 0xFF) << 16) |
            ((in[2] & 0xFF) << 8) |
            (in[3] & 0xFF);

    return OK;
}

/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
MSTATUS KEYBLOB_ubyte4ToArray(ubyte4 i, ubyte *out)
{
    if (NULL == out)
    {
        return ERR_NULL_POINTER;
    }

    out[0] = (ubyte) ((i >> 24) & 0xFF);
    out[1] = (ubyte) ((i >> 16) & 0xFF);
    out[2] = (ubyte) ((i >> 8) & 0xFF);
    out[3] = (ubyte) (i & 0xFF);

    return OK;
}


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
MSTATUS KEYBLOB_parseHeader(
    const ubyte *pKeyBlob,
    ubyte4 keyBlobLen,
    ubyte4 *pKeyType,
    ubyte4 *pVersion
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 header, keyType, version;

    if ( (NULL == pKeyBlob) || (NULL == pKeyType) || (NULL == pVersion) )
    {
        goto exit;
    }

    /* set defaults to undefined */
    *pKeyType = akt_undefined;
    *pVersion = 0;

    /* 4 bytes  - all zeroes
     * 4 bytes  - version number, 0x00000002 or 0x00000001
     * 4 bytes  - key type, must be KEYBLOB_TYPE enum
     **/
    status = ERR_BAD_KEY_BLOB;
    if (12 > keyBlobLen)
    {
        goto exit;
    }

    status = KEYBLOB_arrayToUbyte4(pKeyBlob, &header);
    if (OK != status)
    {
        goto exit;
    }

    /* header is expected to be all zeroes */
    status = ERR_BAD_KEY_BLOB;
    if (0 != header)
    {
        goto exit;
    }

    status = KEYBLOB_arrayToUbyte4(pKeyBlob + 4, &version);
    if (OK != status)
    {
        goto exit;
    }

    /* only version one and two are valid */
    status = ERR_BAD_KEY_BLOB;
    if ( (1 != version) && (2 != version) )
    {
        goto exit;
    }

    status = KEYBLOB_arrayToUbyte4(pKeyBlob + 8, &keyType);
    if (OK != status)
    {
        goto exit;
    }

    /* check to see the key type is a recognized enum value
     */
    status = ERR_BAD_KEY_BLOB;
    switch(keyType)
    {
        case keyblob_type_rsa:
        case keyblob_type_ecc:
        case keyblob_type_ecc_ed:
#ifdef __ENABLE_DIGICERT_PQC__
        case keyblob_type_hybrid:
        case keyblob_type_qs:
#endif
        case keyblob_type_dsa:
        case keyblob_type_rsa_pss:
        case keyblob_type_custom:
        case keyblob_type_moc:
        case keyblob_type_hsm_rsa:
        case keyblob_type_hsm_ecc:
        case keyblob_tap_rsa:
        case keyblob_tap_ecc:

            status = OK;
            break;
    };
    if (OK != status)
        goto exit;

    *pVersion = version;
    *pKeyType = keyType;

exit:
    return status;
}


/*------------------------------------------------------------------*/


static MSTATUS KEYBLOB_parseHeaderV2(
    const ubyte **ppKeyBlob,
    ubyte4 *pKeyBlobLen,
    MAlgoId **ppAlgoId
    )
{
    MSTATUS status;
    ubyte4 oidFlag, tag, totalLen;
    sbyte4 tagLen;

    status = ERR_NULL_POINTER;
    if ( (NULL == ppKeyBlob) || (NULL == pKeyBlobLen) || (NULL == ppAlgoId) )
    {
        goto exit;
    }

    /* Must be at least 4 bytes to read the length of the OID type.
     */
    if (4 > *pKeyBlobLen)
    {
        status = ERR_BAD_KEY_BLOB;
        goto exit;
    }

    /* Get the OID flag.
     */
    status = KEYBLOB_arrayToUbyte4(*ppKeyBlob, &oidFlag);
    if (OK != status)
    {
        goto exit;
    }

    /* Move the buffer ahead past the 4 OID bytes.
     */
    *ppKeyBlob = *ppKeyBlob + 4;
    *pKeyBlobLen = *pKeyBlobLen - 4;

    /* Buffer should now point to the ASN.1 encoded algorithm identifier.
     * Extract the length from the ASN.1 encoding.
     */
    status = ASN1_readTagAndLen(
        (ubyte *) *ppKeyBlob, *pKeyBlobLen, &tag, &tagLen, &totalLen);
    if (OK != status)
    {
        goto exit;
    }

    /* Total length of the buffer is the tag + length + data
     */
    totalLen += tagLen;

    /* Deserialize the algorithm identifier
     */
    status = ALG_ID_deserializeBuffer(
        (MAlgoOid) oidFlag, (ubyte *) *ppKeyBlob, totalLen, ppAlgoId);
    if (OK != status)
    {
        goto exit;
    }

    /* Move the blob buffer past the algorithm identifier bytes
     */
    *ppKeyBlob = *ppKeyBlob + totalLen;
    *pKeyBlobLen = *pKeyBlobLen - totalLen;

    /* Ensure there are at least 4 bytes
     */
    if (4 > *pKeyBlobLen)
    {
        status = ERR_BAD_KEY_BLOB;
        goto exit;
    }

    status = KEYBLOB_arrayToUbyte4(*ppKeyBlob, &totalLen);
    if (OK != status)
    {
        goto exit;
    }

    /* This value is currently reserved. Must be 0.
     */
    if (0 != totalLen)
    {
        status = ERR_BAD_KEY_BLOB;
        goto exit;
    }

    /* Move the blob buffer past the 4 bytes.
     */
    *ppKeyBlob = *ppKeyBlob + 4;
    *pKeyBlobLen = *pKeyBlobLen - 4;

    /* Ensure there are at least 4 bytes
     */
    if (4 > *pKeyBlobLen)
    {
        status = ERR_BAD_KEY_BLOB;
        goto exit;
    }

    status = KEYBLOB_arrayToUbyte4(*ppKeyBlob, &totalLen);
    if (OK != status)
    {
        goto exit;
    }

    /* Move the blob buffer past the 4 bytes.
     */
    *ppKeyBlob = *ppKeyBlob + 4;
    *pKeyBlobLen = *pKeyBlobLen - 4;

    /* Ensure the key data is the last set of the data in the blob.
     */
    if (totalLen != *pKeyBlobLen)
    {
        status = ERR_BAD_KEY_BLOB;
        goto exit;
    }

exit:

    return status;
}

/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RSA__
MSTATUS
KEYBLOB_makeRSAKeyBlob(MOC_RSA(hwAccelDescr hwAccelCtx)
                       RSAKey *pRSAContext, ubyte **ppRetKeyBlob,
                       ubyte4 *pRetKeyLength)
{
    MSTATUS status;
    ubyte4 bufferLength;
    ubyte* buffer = NULL;

    if (!pRSAContext || !ppRetKeyBlob || !pRetKeyLength)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > ( status = RSA_byteStringFromKey(MOC_RSA(hwAccelCtx)
                                pRSAContext, 0, &bufferLength)))
        goto exit;

    buffer =(ubyte*) MALLOC(bufferLength+12);
    if (!buffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    /* headers */
    DIGI_MEMSET( buffer, 0x00, 12);
    buffer[7] = 1; /* version */
    buffer[11] = keyblob_type_rsa;  /* key type */

    if (OK > (status = RSA_byteStringFromKey(MOC_RSA(hwAccelCtx)
                                pRSAContext, buffer+12, &bufferLength)))
        goto exit;

    *ppRetKeyBlob = buffer;
    buffer = NULL;
    *pRetKeyLength = bufferLength + 12;

exit:

    if (NULL != buffer)
        FREE(buffer);

    return status;

} /* KEYBLOB_makeRSAKeyBlob */
#endif

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_DSA__))
MSTATUS
KEYBLOB_makeDSAKeyBlob(MOC_DSA(hwAccelDescr hwAccelCtx)
                       DSAKey *pDSAContext, ubyte **ppRetKeyBlob,
                       ubyte4 *pRetKeyLength)
{
    ubyte4  bufferLength;
    ubyte*  buffer = NULL;
    MSTATUS status;

    if (!pDSAContext || !ppRetKeyBlob || !pRetKeyLength)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = DSA_makeKeyBlob(MOC_DSA(hwAccelCtx) pDSAContext, NULL, &bufferLength)))
        goto exit;

    buffer = MALLOC(bufferLength+12);
    if (!buffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* headers */
    DIGI_MEMSET( buffer, 0x00, 12);
    buffer[7] = 1; /* version */
    buffer[11] = keyblob_type_dsa;  /* key type */

    if (OK > (status = DSA_makeKeyBlob( MOC_DSA(hwAccelCtx) pDSAContext, buffer+12, &bufferLength)))
        goto exit;

    *ppRetKeyBlob = buffer;
    buffer = NULL;
    *pRetKeyLength = bufferLength + 12;

exit:
    if (NULL != buffer)
        FREE(buffer);

    return status;

} /* KEYBLOB_makeDSAKeyBlob */
#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_ECC__))
MSTATUS KEYBLOB_makeECCKeyBlob(
    MOC_ECC(hwAccelDescr hwAccelCtx)
    ECCKey *pECCKey,
    ubyte4 curveId,
    ubyte **ppRetKeyBlob,
    ubyte4 *pRetKeyLength
    )
{
    MSTATUS status;
    MEccKeyTemplate eccData = { 0 };
    ubyte *pKeyBlob = NULL;
    ubyte4 blobSize, index;
    intBoolean isPriv = FALSE;
    
    status = ERR_NULL_POINTER;
    if ( (NULL == pECCKey) || (NULL == ppRetKeyBlob) ||
         (NULL == pRetKeyLength) )
        goto exit;
    
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_isKeyPrivate(pECCKey, &isPriv);
#else
    status = EC_isKeyPrivate(pECCKey, &isPriv);
#endif
    if (OK != status)
        goto exit;

    if (TRUE == isPriv)
    {
        status = EC_getKeyParametersAlloc( MOC_ECC(hwAccelCtx)
            pECCKey, &eccData, MOC_GET_PRIVATE_KEY_DATA);
        if (OK != status)
            goto exit;
        blobSize = 12 + 4 + 4 + eccData.publicKeyLen + 4 + eccData.privateKeyLen;
    }
    else
    {
        status = EC_getKeyParametersAlloc( MOC_ECC(hwAccelCtx)
            pECCKey, &eccData, MOC_GET_PUBLIC_KEY_DATA);
        if (OK != status)
            goto exit;
        blobSize = 12 + 4 + 4 + eccData.publicKeyLen;
    }

    status = DIGI_MALLOC((void **) &pKeyBlob, blobSize);
    if (OK != status)
        goto exit;

    /* Header
     */
    status = DIGI_MEMSET(pKeyBlob, 0x00, 12);
    if (OK != status)
        goto exit;

    /* Version
     */
    pKeyBlob[7] = 1;

    /* Key Type
     */
#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__
    if (cid_EC_X25519 == curveId || cid_EC_X448 == curveId || cid_EC_Ed25519 == curveId || cid_EC_Ed448 == curveId)
    {
        pKeyBlob[11] = keyblob_type_ecc_ed;
    }
    else
#endif
    {
        pKeyBlob[11] = keyblob_type_ecc;
    }
    
    index = 12;
    BIGEND32(pKeyBlob + index, curveId);
    index += 4;

    BIGEND32(pKeyBlob + index, eccData.publicKeyLen);
    index += 4;

    status = DIGI_MEMCPY(
        pKeyBlob + index, eccData.pPublicKey, eccData.publicKeyLen);
    if (OK != status)
        goto exit;

    index += eccData.publicKeyLen;

    if (0 != eccData.privateKeyLen)
    {
        BIGEND32(pKeyBlob + index, eccData.privateKeyLen);
        index += 4;

        status = DIGI_MEMCPY(
            pKeyBlob + index, eccData.pPrivateKey, eccData.privateKeyLen);
        if (OK != status)
            goto exit;
    }

    *ppRetKeyBlob = pKeyBlob;
    *pRetKeyLength = blobSize;
    pKeyBlob = NULL;

exit:

    if (NULL != pKeyBlob)
        DIGI_FREE((void **) &pKeyBlob);

    EC_freeKeyTemplate(pECCKey, &eccData);

    return status;

} /* KEYBLOB_makeECCKeyBlob */

#ifdef __ENABLE_DIGICERT_PQC__
MSTATUS KEYBLOB_makeHybridBlob(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    AsymmetricKey *pKey,
    ubyte **ppRetKeyBlob,
    ubyte4 *pRetKeyLength
    )
{
	MSTATUS status = ERR_NULL_POINTER;
	ubyte *pKeyBlob = NULL;
    ubyte4 keyBlobLen = 0;
	ubyte *pQsBlob = NULL;
	ubyte4 qsBlobLen = 0;
    ubyte *pClBlob = NULL;
    ubyte4 clBlobLen = 0;

	status = ERR_NULL_POINTER;
	if (NULL == pKey || NULL == ppRetKeyBlob || NULL == pRetKeyLength)
		goto exit;

    /* new blob is header and concatenation of the qs blob with the classical alg blob */
    status = KEYBLOB_makeQsBlob(MOC_ASYM(hwAccelCtx) pKey->pQsCtx, &pQsBlob, &qsBlobLen);
    if (OK != status)
        goto exit;

    if (pKey->clAlg < cid_RSA_2048_PKCS15) /* ECC */
    {
        status = KEYBLOB_makeECCKeyBlob(MOC_ECC(hwAccelCtx) pKey->key.pECC, CRYPTO_getECCurveId(pKey), &pClBlob, &clBlobLen);
    }
    else /* RSA */
    {
        status = KEYBLOB_makeRSAKeyBlob(MOC_RSA(hwAccelCtx) pKey->key.pRSA, &pClBlob, &clBlobLen);
    }
    if (OK != status)
        goto exit;
      
    keyBlobLen = 20 + qsBlobLen + clBlobLen; /* 12 bytes for header, 4 for clAlgId, 4 for qsBlobLen */
    status = DIGI_MALLOC((void **) &pKeyBlob, keyBlobLen);
    if (OK != status)
        goto exit;
        
    /* Header */
    status = DIGI_MEMSET(pKeyBlob, 0x00, 12);
    if (OK != status)
        goto exit;
    
    /* Version */
    pKeyBlob[7] = 1;
    
    /* Key Type */
    pKeyBlob[11] = keyblob_type_hybrid;

    BIGEND32(pKeyBlob + 12, pKey->clAlg);
    BIGEND32(pKeyBlob + 16, qsBlobLen);
    
    (void) DIGI_MEMCPY(pKeyBlob + 20, pQsBlob, qsBlobLen);
    (void) DIGI_MEMCPY(pKeyBlob + 20 + qsBlobLen, pClBlob, clBlobLen);

	*ppRetKeyBlob = pKeyBlob; pKeyBlob = NULL;
	*pRetKeyLength = keyBlobLen;
	
exit:

	if (NULL != pKeyBlob)
    {
        DIGI_MEMSET_FREE(&pKeyBlob, keyBlobLen);
    }
	if (NULL != pQsBlob)
    {
		DIGI_MEMSET_FREE(&pQsBlob, qsBlobLen);  /* don't change status, no need to check return values */
    }
	if (NULL != pClBlob)
    {
		DIGI_MEMSET_FREE(&pClBlob, clBlobLen);
    }

	return status;
	
} /* KEYBLOB_makeHybridBlob */
#endif
#endif /* __ENABLE_DIGICERT_ECC__ */

#ifdef __ENABLE_DIGICERT_PQC__
MSTATUS KEYBLOB_makeQsBlob(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    QS_CTX *pCtx,
    ubyte **ppRetKeyBlob,
    ubyte4 *pRetKeyLength
    )
{
	MSTATUS status = ERR_NULL_POINTER;
	ubyte *pKeyBlob = NULL;
	ubyte4 blobSize, index;
	ubyte *pQSBuffer = NULL;
	ubyte4 qsBufLen = 0;
	ubyte4 qsAlg = 0;

	if (NULL == pCtx || NULL == ppRetKeyBlob || NULL == pRetKeyLength)
		goto exit;

    status = CRYPTO_INTERFACE_QS_serializeKeyAlloc(pCtx, pCtx->isPrivate ? MOC_ASYM_KEY_TYPE_PRIVATE : MOC_ASYM_KEY_TYPE_PUBLIC, 
                                                   &pQSBuffer, &qsBufLen);
	if (OK != status)
		goto exit;
	

    blobSize = 12 + 4 + 1 + qsBufLen; /* header, qsAlg, isPriv, serLen */
	
	status = DIGI_MALLOC((void **) &pKeyBlob, blobSize);
	if (OK != status)
		goto exit;
	
	/* Header
	 */
	status = DIGI_MEMSET(pKeyBlob, 0x00, 12);
	if (OK != status)
		goto exit;
	
	/* Version
	 */
	pKeyBlob[7] = 1;
	
	/* Key Type
	 */
	pKeyBlob[11] = keyblob_type_qs;
	
	index = 12;

    /* First put the post-quantum alg identifier */
    status = CRYPTO_INTERFACE_QS_getAlg(pCtx, &qsAlg);
    if (OK != status)
        goto exit;

    BIGEND32(pKeyBlob + index, qsAlg);
    index += 4;

    /* set the next byte to 0x01 for private keys, 0x00 for public keys */
	if (pCtx->isPrivate)
	{
        pKeyBlob[index++] = 0x01;
	}
    else
    {
        pKeyBlob[index++] = 0x00;
    }

	/* Then copy the QS blob at the end */
	status = DIGI_MEMCPY(pKeyBlob + index, pQSBuffer, qsBufLen);
	if (OK != status)
		goto exit;
	
	*ppRetKeyBlob = pKeyBlob;
	*pRetKeyLength = blobSize;
	pKeyBlob = NULL;
	
exit:
	
	if (NULL != pQSBuffer)
		DIGI_MEMSET_FREE(&pQSBuffer, qsBufLen);  /* don't change status, no need to check return values */
	
	if (NULL != pKeyBlob)
		DIGI_MEMSET_FREE(&pKeyBlob, blobSize);
	
	return status;
	
} /* KEYBLOB_makeHybridBlob */
#endif

/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_HW_SECURITY_MODULE__)

MSTATUS
KEYBLOB_makeHSMRSAKeyBlob(RSAKey *pRSAKey, ubyte **ppRetKeyBlob,
                       ubyte4 *pRetKeyLength)
{
    MSTATUS status;
    ubyte4 bufferLength;
    ubyte4 keyType = keyblob_type_hsm_rsa;
    ubyte* buffer = NULL;

    if (!pRSAKey || !ppRetKeyBlob || !pRetKeyLength)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if(OK > (status = HSMRSAINFO_getSerializedSize(pRSAKey->hsmInfo, &bufferLength)))
    {
        goto exit;
    }

    buffer =(ubyte *)MALLOC(bufferLength+12+4);
    if (!buffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* headers */
    DIGI_MEMSET( buffer, 0x00, bufferLength + 12 + 4);
    buffer[7] = 1; /* version */
    status = KEYBLOB_ubyte4ToArray(keyType, &(buffer[8]));
    if (OK != status)
    {
        goto exit;
    }

    if( OK > (status = HSMRSAINFO_byteStringFromKey(pRSAKey->hsmInfo, buffer+12, &bufferLength)))
    {
        goto exit;
    }

    *ppRetKeyBlob = buffer;
    buffer = NULL;
    *pRetKeyLength = bufferLength + 12;

exit:

    if (NULL != buffer)
        FREE(buffer);

    return status;

} /* KEYBLOB_makeHSMRSAKeyBlob */

#endif


/*------------------------------------------------------------------*/


MSTATUS KEYBLOB_convertV1toV2(
    const AsymmetricKey *pKey,
    ubyte **ppKeyBlob,
    ubyte4 *pKeyBlobLen
    )
{
    MSTATUS status = OK;
    ubyte *pAlgId = NULL, *pNewKeyBlob = NULL, *pIndex;
    ubyte4 algIdLen;

    if ((NULL == pKey) ||  (NULL == pKey->pAlgoId))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = ALG_ID_serializeAlloc(pKey->pAlgoId, &pAlgId, &algIdLen);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_MALLOC((void **) &pNewKeyBlob, (*pKeyBlobLen) + algIdLen + 12);
    if (OK != status)
    {
        goto exit;
    }

    pIndex = pNewKeyBlob;

    status = DIGI_MEMCPY(pIndex, *ppKeyBlob, 12);
    if (OK != status)
    {
        goto exit;
    }

    /* Version 2 Mocana key blob
    */
    pIndex[4] = 0;
    pIndex[5] = 0;
    pIndex[6] = 0;
    pIndex[7] = 2;

    pIndex += 12;

    status = KEYBLOB_ubyte4ToArray(
        (ubyte4) pKey->pAlgoId->oidFlag, pIndex);
    if (OK != status)
    {
        goto exit;
    }

    pIndex += 4;

    status = DIGI_MEMCPY(pIndex, pAlgId, algIdLen);
    if (OK != status)
    {
        goto exit;
    }

    pIndex += algIdLen;

    *pIndex++ = 0x00;
    *pIndex++ = 0x00;
    *pIndex++ = 0x00;
    *pIndex++ = 0x00;

    status = KEYBLOB_ubyte4ToArray((*pKeyBlobLen) - 12, pIndex);
    if (OK != status)
    {
        goto exit;
    }

    pIndex += 4;

    status = DIGI_MEMCPY(pIndex, (*ppKeyBlob) + 12, (*pKeyBlobLen) - 12);
    if (OK != status)
    {
        goto exit;
    }

exit:


    DIGI_MEMSET(*ppKeyBlob, 0x00, *pKeyBlobLen);
    DIGI_FREE((void **) ppKeyBlob);

    if (OK == status)
    {
        *ppKeyBlob = pNewKeyBlob;
        *pKeyBlobLen = *pKeyBlobLen + algIdLen + 12;
        pNewKeyBlob = NULL;
    }

    if (NULL != pNewKeyBlob)
    {
        DIGI_FREE((void **) &pNewKeyBlob);
    }

    if (NULL != pAlgId)
    {
        DIGI_FREE((void **) &pAlgId);
    }

    return status;
}

/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern MSTATUS
KEYBLOB_makeKeyBlobEx(const AsymmetricKey *pKey,
                      ubyte **ppRetKeyBlob, ubyte4 *pRetKeyLength)
{
    MSTATUS         status;
    hwAccelDescr    hwAccelCtx;

    if (!pKey || !ppRetKeyBlob || !pRetKeyLength)
        return ERR_NULL_POINTER;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
        goto exit;

    switch (pKey->type)
    {
#if (defined(__ENABLE_DIGICERT_ECC__))
        case keyblob_type_ecc:
        case keyblob_type_ecc_ed:
        {
            status = KEYBLOB_makeECCKeyBlob(MOC_ECC(hwAccelCtx) pKey->key.pECC, CRYPTO_getECCurveId(pKey), ppRetKeyBlob, pRetKeyLength);
            break;
        }
#endif
#if (defined(__ENABLE_DIGICERT_DSA__))
        case keyblob_type_dsa:
        {
            status = KEYBLOB_makeDSAKeyBlob(MOC_DSA(hwAccelCtx) pKey->key.pDSA, ppRetKeyBlob, pRetKeyLength);
            break;
        }
#endif
#ifndef __DISABLE_DIGICERT_RSA__
        case keyblob_type_rsa:
        case keyblob_type_hsm_rsa:
        {
#if defined(__ENABLE_DIGICERT_HW_SECURITY_MODULE__)
            if (NULL != pKey->key.pRSA->hsmInfo)
            {
                status = KEYBLOB_makeHSMRSAKeyBlob(MOC_RSA(hwAccelCtx) pKey->key.pRSA, ppRetKeyBlob, pRetKeyLength);
            }
            else
            {
#endif
                status = KEYBLOB_makeRSAKeyBlob(MOC_RSA(hwAccelCtx) pKey->key.pRSA, ppRetKeyBlob, pRetKeyLength);
#if defined(__ENABLE_DIGICERT_HW_SECURITY_MODULE__)
            }
#endif
            break;
        }
#endif /* __DISABLE_DIGICERT_RSA__ */
#ifdef __ENABLE_DIGICERT_PQC__
        case keyblob_type_hybrid:
        {
            status = KEYBLOB_makeHybridBlob(MOC_ASYM(hwAccelCtx) (AsymmetricKey *) pKey, ppRetKeyBlob, pRetKeyLength);
            break;
        }
        case keyblob_type_qs:
        {
            status = KEYBLOB_makeQsBlob(MOC_ASYM(hwAccelCtx) pKey->pQsCtx, ppRetKeyBlob, pRetKeyLength);
            break;
        }
#endif
#if (defined(__ENABLE_DIGICERT_ASYM_KEY__))
        case keyblob_type_moc:
        case keyblob_type_custom:
        {
          MocAsymKey pMocAsymKey = (MocAsymKey )(pKey->key.pMocAsymKey);
          serializedKeyFormat serialFormat;
          MKeyOperatorDataReturn dataReturn;

          serialFormat = mocanaBlobVersion2;
          dataReturn.ppData = ppRetKeyBlob;
          dataReturn.pLength = pRetKeyLength;
          status = ERR_INVALID_INPUT;
          if (NULL != pMocAsymKey->KeyOperator)
          {
            status = pMocAsymKey->KeyOperator (
              pMocAsymKey, NULL, MOC_ASYM_OP_SERIALIZE, &serialFormat,
              (void *)&dataReturn, NULL);
          }
          break;
        }
#endif
        default:
        {
            status = ERR_BAD_KEY_TYPE;
            break;
        }
    }

    if(OK != status)
        goto exit;

    if (NULL != pKey->pAlgoId)
    {
        switch (pKey->type)
        {
#ifdef __ENABLE_DIGICERT_ECC__
            case keyblob_type_ecc:
            case keyblob_type_ecc_ed:
#endif
#ifdef __ENABLE_DIGICERT_DSA__
            case keyblob_type_dsa:
#endif
#ifndef __DISABLE_DIGICERT_RSA__
            case keyblob_type_rsa:
#endif
                status = KEYBLOB_convertV1toV2(
                    pKey, ppRetKeyBlob, pRetKeyLength);
        }
    }

exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

    return status;
}



/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RSA__
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
static MSTATUS ParseOldMocanaBlob(
    ubyte **ppKeyBlob,
    ubyte4 *pKeyBlobLen,
    ubyte **ppRetValue,
    ubyte4 *pRetValueLen
    )
{
    MSTATUS status;
    ubyte4 length;
    ubyte *pIter;

    status = ERR_NULL_POINTER;
    if ( (NULL == ppKeyBlob) || (NULL == *ppKeyBlob) || (NULL == pKeyBlobLen) ||
         (NULL == ppRetValue) || (NULL == pRetValueLen) )
        goto exit;

    /* The first four bytes will be the length of the data so ensure that there
     * are atleast 4 bytes.
     */
    status = ERR_BAD_LENGTH;
    if (4 > *pKeyBlobLen)
        goto exit;
    
    pIter = *ppKeyBlob;

    /* Read the length from the buffer.
     */
    length = ((ubyte4) (pIter[3]));
    length |= ((ubyte4) (pIter[2])) << 8;
    length |= ((ubyte4) (pIter[1])) << 16;
    length |= ((ubyte4) (pIter[0])) << 24;

    /* If the length exceeds the remaining data in the buffer then return an
     * error.
     */
    if (((*pKeyBlobLen) - 4) < length)
        goto exit;

    /* If the data was successfully parsed then advance the key blob pointer and
     * decrement the key blob length accordingly. Also set the return pointer
     * to the actual data.
     */
    *ppRetValue = pIter + 4;
    *pRetValueLen = length;
    *ppKeyBlob += (4 + length);
    *pKeyBlobLen -= (4 + length);
    status = OK;

exit:

    return status;
}

MOC_EXTERN MSTATUS KEYBLOB_extractOldRSAKeyBlob(
    MOC_RSA(hwAccelDescr hwAccelCtx)
    const ubyte *pKeyBlob,
    ubyte4 keyBlobLength,
    RSAKey *pRsaKey
    )
{
    MSTATUS status;
    ubyte *pPrime, *pSubPrime, *pMod, *pExp;
    ubyte4 primeLen, subPrimeLen, modLen, expLen;

    if (0 == keyBlobLength)
    {
        status = ERR_BAD_KEY_BLOB;
        goto exit;
    }

    /* Read the prime data.
     */
    status = ParseOldMocanaBlob(
        (ubyte **) &pKeyBlob, &keyBlobLength, &pPrime, &primeLen);
    if (OK != status)
        goto exit;
    
    /* Read the subprime data.
     */
    status = ParseOldMocanaBlob(
        (ubyte **) &pKeyBlob, &keyBlobLength, &pSubPrime, &subPrimeLen);
    if (OK != status)
        goto exit;
    
    /* Read the modulus data.
     */
    status = ParseOldMocanaBlob(
        (ubyte **) &pKeyBlob, &keyBlobLength, &pMod, &modLen);
    if (OK != status)
        goto exit;
    
    /* Read the exponent data.
     */
    status = ParseOldMocanaBlob(
        (ubyte **) &pKeyBlob, &keyBlobLength, &pExp, &expLen);
    if (OK != status)
        goto exit;
    
    /* Set the key data in the RSA key. This will also prepare the RSA key
     * itself (calculate the values for CRT) if the underlying implementation
     * can do so.
     */
    status = CRYPTO_INTERFACE_RSA_setAllKeyData(
        MOC_RSA(hwAccelCtx) pRsaKey, pExp, expLen, pMod, modLen, pPrime,
        primeLen, pSubPrime, subPrimeLen, NULL, akt_rsa);
    if (OK != status)
        goto exit;

exit:

    return status;
}
#else
MSTATUS
KEYBLOB_extractOldRSAKeyBlob(MOC_RSA(hwAccelDescr hwAccelCtx)
                             const ubyte *pKeyBlob, ubyte4 keyBlobLength,
                             RSAKey *p_rsaContext)
{
    ubyte4  index;
    MSTATUS status;

    if (0 == keyBlobLength)
    {
        status = ERR_BAD_KEY_BLOB;
        goto exit;
    }

    /* p */
    index = 0;
    if (OK > (status = VLONG_newFromMpintBytes(pKeyBlob, keyBlobLength, &RSA_P(p_rsaContext), &index, NULL)))
        goto exit;

    pKeyBlob += index;
    if (0 >= (sbyte4)(keyBlobLength = (keyBlobLength - index)))
    {
        status = ERR_BAD_KEY_BLOB;
        goto exit;
    }

    /* q */
    if (OK > (status = VLONG_newFromMpintBytes(pKeyBlob, keyBlobLength, &RSA_Q(p_rsaContext), &index, NULL)))
        goto exit;

    pKeyBlob += index;
    if (0 >= (sbyte4)(keyBlobLength = (keyBlobLength - index)))
    {
        status = ERR_BAD_KEY_BLOB;
        goto exit;
    }

    /* n */
    if (OK > (status = VLONG_newFromMpintBytes(pKeyBlob, keyBlobLength, &RSA_N(p_rsaContext), &index, NULL)))
        goto exit;

    pKeyBlob += index;
    if (0 >= (sbyte4)(keyBlobLength = (keyBlobLength - index)))
    {
        status = ERR_BAD_KEY_BLOB;
        goto exit;
    }

    /* e */
    if (OK > (status = VLONG_newFromMpintBytes(pKeyBlob, keyBlobLength, &RSA_E(p_rsaContext), &index, NULL)))
        goto exit;

    if (0 != keyBlobLength - index)
    {
        status = ERR_BAD_KEY_BLOB;
        goto exit;
    }

    p_rsaContext->privateKey = TRUE;

    status = RSA_prepareKey(MOC_RSA(hwAccelCtx) p_rsaContext, 0);


exit:
    return status;

} /* KEYBLOB_extractOldRSAKeyBlob */
#endif
#endif

/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RSA__
MSTATUS
KEYBLOB_readOldRSAKeyBlob(MOC_RSA(hwAccelDescr hwAccelCtx)
                         const ubyte *pKeyBlob, ubyte4 keyBlobLength,
                         AsymmetricKey* pKey)
{
    MSTATUS status;

    if ( OK > ( status = RSA_createKey( &pKey->key.pRSA)))
        return status;
    pKey->type = keyblob_type_rsa;

    return KEYBLOB_extractOldRSAKeyBlob(MOC_RSA(hwAccelCtx) pKeyBlob, keyBlobLength, pKey->key.pRSA);
}
#endif

/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RSA__
MSTATUS
KEYBLOB_readRSAKeyPart(MOC_RSA(hwAccelDescr hwAccelCtx)
                       const ubyte *pKeyBlob, ubyte4 keyBlobLength,
                       AsymmetricKey* pKey)
{
    MSTATUS status;

    status = RSA_keyFromByteString(MOC_RSA(hwAccelCtx) &pKey->key.pRSA, pKeyBlob, keyBlobLength, 0);
    if (OK <= status)
    {
        pKey->type = keyblob_type_rsa;
    }
    return status;
}


/*------------------------------------------------------------------*/

MSTATUS
KEYBLOB_readRSAKeyPartV2(
    MOC_RSA(hwAccelDescr hwAccelCtx)
    const ubyte *pKeyBlob,
    ubyte4 keyBlobLength,
    AsymmetricKey *pKey
    )
{
    MSTATUS status;
    MAlgoId *pAlgoId = NULL;

    status = ERR_NULL_POINTER;
    if (NULL == pKey)
        goto exit;

    status = KEYBLOB_parseHeaderV2(&pKeyBlob, &keyBlobLength, &pAlgoId);
    if (OK != status)
    {
        goto exit;
    }

    status = KEYBLOB_readRSAKeyPart(
        MOC_RSA(hwAccelCtx) pKeyBlob, keyBlobLength, pKey);
    if (OK != status)
    {
        goto exit;
    }

    status = CRYPTO_loadAlgoId(pKey, (void**)&pAlgoId);
    if (OK != status)
    {
        goto exit;
    }

    pKey = NULL;

exit:

    if (NULL != pAlgoId)
    {
        ALG_ID_free(&pAlgoId);
    }

    CRYPTO_uninitAsymmetricKey(pKey, NULL);

    return status;
}
#endif

/*------------------------------------------------------------------*/
#if (!defined(__DISABLE_DIGICERT_RSA__) && defined(__ENABLE_DIGICERT_HW_SECURITY_MODULE__))
MSTATUS
KEYBLOB_readHSMRSAKeyPart(const ubyte *pKeyBlob, ubyte4 keyBlobLength,
                            AsymmetricKey* pKey)
{
    MSTATUS status;

    status = HSMRSAINFO_keyFromByteString(&pKey->key.pRSA, pKeyBlob, keyBlobLength);
    if(OK <= status)
    {
        /* HSM key types are only for writing keyblobs to disk - use generic RSA key type when passing out to rest of code */
        pKey->type = keyblob_type_rsa;
        pKey->key.pRSA->privateKey = TRUE;
    }
    return status;
}
#endif

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_DSA__))
MSTATUS
KEYBLOB_readDSAKeyPart(MOC_DSA(hwAccelDescr hwAccelCtx) const ubyte *pKeyBlob, ubyte4 keyBlobLength,
                       AsymmetricKey* pKey)
{
    MSTATUS status;

    status = DSA_extractKeyBlob(MOC_DSA(hwAccelCtx) &pKey->key.pDSA, pKeyBlob, keyBlobLength);

    if (OK <= status)
        pKey->type = keyblob_type_dsa;

    return status;
}


/*------------------------------------------------------------------*/

MSTATUS
KEYBLOB_readDSAKeyPartV2( MOC_DSA(hwAccelDescr hwAccelCtx)
    const ubyte *pKeyBlob,
    ubyte4 keyBlobLength,
    AsymmetricKey *pKey
    )
{
    MSTATUS status;
    MAlgoId *pAlgoId = NULL;

    status = ERR_NULL_POINTER;
    if (NULL == pKey)
    {
        goto exit;
    }

    status = KEYBLOB_parseHeaderV2(&pKeyBlob, &keyBlobLength, &pAlgoId);
    if (OK != status)
    {
        goto exit;
    }

    status = KEYBLOB_readDSAKeyPart(MOC_DSA(hwAccelCtx) pKeyBlob, keyBlobLength, pKey);
    if (OK != status)
    {
        goto exit;
    }

    status = CRYPTO_loadAlgoId(pKey, (void**)&pAlgoId);
    if (OK != status)
    {
        goto exit;
    }

    pKey = NULL;

exit:

    if (NULL != pAlgoId)
    {
        ALG_ID_free(&pAlgoId);
    }

    CRYPTO_uninitAsymmetricKey(pKey, NULL);

    return status;
}
#endif


/*------------------------------------------------------------------*/
#if (defined(__ENABLE_DIGICERT_ECC__))
MSTATUS
KEYBLOB_readECCKeyPart(MOC_ECC(hwAccelDescr hwAccelCtx) const ubyte *pKeyBlob, ubyte4 keyBlobLength,
                         AsymmetricKey* pKey)
{
    ubyte4 curveId;
    ubyte4 pointLen, scalarLen;
    const ubyte* pPoint;
    const ubyte* pScalar;

    if ( keyBlobLength < 8)
    {
        return ERR_BAD_KEY_BLOB;
    }

    /* read curve id */
    curveId =  ((ubyte4)(*pKeyBlob++) << 24);
    curveId |= ((ubyte4)(*pKeyBlob++) << 16);
    curveId |= ((ubyte4)(*pKeyBlob++) << 8);
    curveId |= ((ubyte4)(*pKeyBlob++) );

    /* read point len */
    pointLen =  ((ubyte4)(*pKeyBlob++) << 24);
    pointLen |= ((ubyte4)(*pKeyBlob++) << 16);
    pointLen |= ((ubyte4)(*pKeyBlob++) << 8);
    pointLen |= ((ubyte4)(*pKeyBlob++) );
    keyBlobLength-=8;

    if ( keyBlobLength < pointLen)
    {
        return ERR_BAD_KEY_BLOB;
    }
    pPoint = pKeyBlob;
    keyBlobLength -= pointLen;
    pKeyBlob += pointLen;

    if ( keyBlobLength > 4)
    {
        scalarLen =  ((ubyte4)(*pKeyBlob++) << 24);
        scalarLen |= ((ubyte4)(*pKeyBlob++) << 16);
        scalarLen |= ((ubyte4)(*pKeyBlob++) << 8);
        scalarLen |= ((ubyte4)(*pKeyBlob++) );
        keyBlobLength -= 4;

        if ( keyBlobLength < scalarLen)
        {
            return ERR_BAD_KEY_BLOB;
        }

        pScalar = pKeyBlob;
    }
    else
    {
        pScalar = 0;
        scalarLen = 0;
    }

    return CRYPTO_setECCParameters( MOC_ECC(hwAccelCtx) pKey, curveId, pPoint, pointLen,
                                    pScalar, scalarLen);
}

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PQC__
MSTATUS KEYBLOB_readQsKeyPart(MOC_ASYM(hwAccelDescr hwAccelCtx) const ubyte *pKeyBlob, ubyte4 keyBlobLength, AsymmetricKey* pKey)
{
    MSTATUS status = ERR_BAD_KEY_BLOB;
    ubyte4 qsAlg = 0;
    
    if ( keyBlobLength < 5)
        goto exit;

    /* read qs Alg id */
    qsAlg =  ((ubyte4)(*pKeyBlob++) << 24);
    qsAlg |= ((ubyte4)(*pKeyBlob++) << 16);
    qsAlg |= ((ubyte4)(*pKeyBlob++) << 8);
    qsAlg |= ((ubyte4)(*pKeyBlob++) );
    
    status = CRYPTO_INTERFACE_QS_newCtx(MOC_HASH(hwAccelCtx) &(pKey->pQsCtx), qsAlg);
    if (OK != status)
        goto exit;
    
    pKey->type = akt_qs;
    pKey->pQsCtx->isPrivate = *pKeyBlob++;
    keyBlobLength -= 5;
    
    status = CRYPTO_INTERFACE_QS_deserializeKey(pKey->pQsCtx, pKey->pQsCtx->isPrivate ? MOC_ASYM_KEY_TYPE_PRIVATE : MOC_ASYM_KEY_TYPE_PUBLIC,
                                                (ubyte *) pKeyBlob, keyBlobLength);
    if (OK != status)
        goto exit;

    /* all is good, set pKey to null so it won't be cleaned up */
    pKey = NULL;
    
exit:
    
    (void) CRYPTO_uninitAsymmetricKey(pKey, NULL); /* don't change status, ignore return code */
    
    return status;
}

/*------------------------------------------------------------------*/

MSTATUS KEYBLOB_readHybridKeyPart(MOC_ASYM(hwAccelDescr hwAccelCtx) const ubyte *pKeyBlob, ubyte4 keyBlobLength, AsymmetricKey* pKey)
{
    MSTATUS status = ERR_BAD_KEY_BLOB;
    ubyte4 clAlg = 0;
    AsymmetricKey temp = {0};
    ubyte4 qsBlobLen = 0;
    
    if ( keyBlobLength < 8)
        goto exit;
    
    /* read the clAlgId first */
    clAlg =  ((ubyte4)(*pKeyBlob++) << 24);
    clAlg |= ((ubyte4)(*pKeyBlob++) << 16);
    clAlg |= ((ubyte4)(*pKeyBlob++) << 8);
    clAlg |= ((ubyte4)(*pKeyBlob++) );

    /* now the qsBlobLen */
    qsBlobLen =  ((ubyte4)(*pKeyBlob++) << 24);
    qsBlobLen |= ((ubyte4)(*pKeyBlob++) << 16);
    qsBlobLen |= ((ubyte4)(*pKeyBlob++) << 8);
    qsBlobLen |= ((ubyte4)(*pKeyBlob++) );
    keyBlobLength -= 8;

    if (keyBlobLength < qsBlobLen)
        goto exit;

    /* qsBlob has its own 12 byte header again, skip */
    pKeyBlob += 12;
    qsBlobLen -= 12;
    keyBlobLength -= 12;
    status = KEYBLOB_readQsKeyPart(MOC_ASYM(hwAccelCtx) pKeyBlob, qsBlobLen, &temp);
    if (OK != status)
        goto exit;

    /* skip to the cl portion, again after the 12 byte header */
    pKeyBlob += (qsBlobLen + 12);
    keyBlobLength -= (qsBlobLen + 12);

    if (clAlg < cid_RSA_2048_PKCS15) /* ECC */
    {
        status = KEYBLOB_readECCKeyPart(MOC_ECC(hwAccelCtx) pKeyBlob, keyBlobLength, pKey);
    }
    else /* RSA */
    {
        status = KEYBLOB_readRSAKeyPart(MOC_RSA(hwAccelCtx) pKeyBlob, keyBlobLength, pKey);
    }
    if (OK != status)
        goto exit;

    /* switch type to hyrbid and get pQsCtx from temp */
    pKey->type = akt_hybrid;
    pKey->clAlg = clAlg;
    pKey->pQsCtx = temp.pQsCtx; temp.pQsCtx = NULL;
    
exit:

    /* pKey last thing to be set on error, no need to free ECC or RSA key */
    if (NULL != temp.pQsCtx)
    {
        (void) CRYPTO_INTERFACE_QS_deleteCtx(&temp.pQsCtx);
    }
    
    return status;
}
#endif /* __ENABLE_DIGICERT_PQC__ */

/*------------------------------------------------------------------*/

MSTATUS
KEYBLOB_readECCKeyPartV2(
    MOC_ECC(hwAccelDescr hwAccelCtx)
    const ubyte *pKeyBlob,
    ubyte4 keyBlobLength,
    AsymmetricKey *pKey
    )
{
    MSTATUS status;
    MAlgoId *pAlgoId = NULL;

    status = ERR_NULL_POINTER;
    if (NULL == pKey)
    {
        goto exit;
    }

    status = KEYBLOB_parseHeaderV2(&pKeyBlob, &keyBlobLength, &pAlgoId);
    if (OK != status)
    {
        goto exit;
    }

    status = KEYBLOB_readECCKeyPart(MOC_ECC(hwAccelCtx) pKeyBlob, keyBlobLength, pKey);
    if (OK != status)
    {
        goto exit;
    }

    status = CRYPTO_loadAlgoId(pKey, (void**)&pAlgoId);
    if (OK != status)
    {
        goto exit;
    }

    pKey = NULL;

exit:

    if (NULL != pAlgoId)
    {
        ALG_ID_free(&pAlgoId);
    }

    CRYPTO_uninitAsymmetricKey(pKey, NULL);

    return status;
}
#endif /* __ENABLE_DIGICERT_ECC__ */

/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern MSTATUS
KEYBLOB_extractKeyBlobTypeEx(const ubyte *pKeyBlob, ubyte4 keyBlobLength, ubyte4 *pRetKeyType)
{
    MSTATUS status = OK;
    sbyte4  i;
    KEYBLOB_TYPE keyBlobType;

    if ((NULL == pKeyBlob) || (NULL == pRetKeyType))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* look at the first 4 bytes - should all be 0 */
    for (i = 0; i < 4; ++i)
    {
        if (pKeyBlob[i])
        {
            /* if not all 0 -> old format */
            *pRetKeyType = keyblob_type_rsa;
            goto exit;
        }
    }

    /* jump over the first 4 bytes */
    pKeyBlob += 4;
    if (4 > (sbyte4)(keyBlobLength = (keyBlobLength - 4)))
    {
        status = ERR_BAD_KEY_BLOB;
        goto exit;
    }

    /* version */
    for (i = 0; i < 3; ++i)
    {
        if (pKeyBlob[i])
        {
            status = ERR_BAD_KEY_BLOB_VERSION;
            goto exit;
        }
    }

    if (pKeyBlob[i] != 1)
    {
        status = ERR_BAD_KEY_BLOB_VERSION;
        goto exit;
    }
    /* jump over the next 4 bytes */
    pKeyBlob += 4;
    if (4 > (sbyte4)(keyBlobLength - 4))
    {
        status = ERR_BAD_KEY_BLOB;
        goto exit;
    }

    /* key type */
    status = KEYBLOB_arrayToUbyte4(pKeyBlob, (ubyte4 *)&keyBlobType);
    if (OK != status)
    {
        goto exit;
    }

    switch (keyBlobType)
    {
        case keyblob_type_rsa: /* RSA key */
        case keyblob_type_ecc: /* ECC key */
        case keyblob_type_ecc_ed: /* Edward's ECC key */
        case keyblob_type_dsa: /* DSA key */
        case keyblob_type_hsm_rsa: /* HSM RSA key */
        case keyblob_type_hsm_ecc: /* HSM ECC key */
        {
            *pRetKeyType = keyBlobType;
            break;
        }

        default:
        {
            status = ERR_BAD_KEY_BLOB;
            break;
        }
    }

exit:
    return status;

} /* KEYBLOB_extractKeyBlobTypeEx */


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern MSTATUS
KEYBLOB_extractKeyBlobEx(const ubyte *pKeyBlob, ubyte4 keyBlobLength,
                         AsymmetricKey* pKey)
{
    sbyte4          i;
    ubyte4          version;
    KEYBLOB_TYPE    keyBlobType;
    MSTATUS         status;
    hwAccelDescr    hwAccelCtx;

    if ((NULL == pKeyBlob) || (NULL == pKey))
        return ERR_NULL_POINTER;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
        goto exit;

    /* If this is not a mocasym key, make sure it is clear. But if it is a mocasym
     * key, we can't clear it because we need the KeyOperator. If this is a
     * mocasym key, because we don't clear it, if it is already set, trying to set
     * it with the key blob will cause an error.
     */
    if (keyblob_type_moc != pKey->type && keyblob_type_custom != pKey->type)
    {
      CRYPTO_uninitAsymmetricKey (pKey, NULL);
    }

    /* look at the first 4 bytes */
    for ( i = 0; i < 4; ++i)
    {
        if (pKeyBlob[i])
        {
#ifndef __DISABLE_DIGICERT_RSA__
            /* if not all 0 -> old format */
            status = KEYBLOB_readOldRSAKeyBlob(MOC_RSA(hwAccelCtx) pKeyBlob, keyBlobLength, pKey);
            goto exit;
#else
            status = ERR_RSA_DISABLED;
            goto exit;
#endif
        }
    }

    /* jump over the first 4 bytes */
    pKeyBlob += 4;
    if (4 > (sbyte4)(keyBlobLength = (keyBlobLength - 4)))
    {
        status = ERR_BAD_KEY_BLOB;
        goto exit;
    }
    /* version */
    for ( i = 0; i < 3; ++i)
    {
        if (pKeyBlob[i])
        {
            status = ERR_BAD_KEY_BLOB_VERSION;
            goto exit;
        }
    }

    version = pKeyBlob[i];
    if ( (pKeyBlob[i] != 1) && (pKeyBlob[i] != 2) )
    {
        status = ERR_BAD_KEY_BLOB_VERSION;
        goto exit;
    }
    /* jump over the next 4 bytes */
    pKeyBlob += 4;
    if (4 > (sbyte4)(keyBlobLength = (keyBlobLength - 4)))
    {
        status = ERR_BAD_KEY_BLOB;
        goto exit;
    }

    /* key type */
    status = KEYBLOB_arrayToUbyte4(pKeyBlob, (ubyte4 *)&keyBlobType);
    if (OK != status)
    {
        goto exit;
    }
    /* jump over keyBlobType 4 bytes */
    pKeyBlob += 4;
    keyBlobLength -= 4;
    switch (keyBlobType)
    {
#ifndef __DISABLE_DIGICERT_RSA__
        case keyblob_type_rsa: /* a RSA key */
        {
            if (2 == version)
            {
                status = KEYBLOB_readRSAKeyPartV2(MOC_RSA(hwAccelCtx) pKeyBlob, keyBlobLength, pKey);
            }
            else
            {
                status = KEYBLOB_readRSAKeyPart(MOC_RSA(hwAccelCtx) pKeyBlob, keyBlobLength, pKey);
            }
            break;
        }
#endif
#if (defined(__ENABLE_DIGICERT_ECC__))
        case keyblob_type_ecc: /* an ECC key */
        case keyblob_type_ecc_ed: /* an Edward's ECC key */
        {
            if (2 == version)
            {
                status = KEYBLOB_readECCKeyPartV2(MOC_ECC(hwAccelCtx) pKeyBlob, keyBlobLength, pKey);
            }
            else
            {
                status = KEYBLOB_readECCKeyPart(MOC_ECC(hwAccelCtx) pKeyBlob, keyBlobLength, pKey);
            }
            break;
        }
#ifdef __ENABLE_DIGICERT_PQC__
        case keyblob_type_hybrid:
        {
            status = KEYBLOB_readHybridKeyPart(MOC_ASYM(hwAccelCtx) pKeyBlob, keyBlobLength, pKey);
            break;
        }
#endif
#endif /* __ENABLE_DIGICERT_ECC__ */
#ifdef __ENABLE_DIGICERT_PQC__
        case keyblob_type_qs:
        {
            status = KEYBLOB_readQsKeyPart(MOC_ASYM(hwAccelCtx) pKeyBlob, keyBlobLength, pKey);
            break;
        }
#endif
#if (defined(__ENABLE_DIGICERT_DSA__))
        case keyblob_type_dsa: /* an DSA key */
        {
            if (2 == version)
            {
                status = KEYBLOB_readDSAKeyPartV2( MOC_DSA(hwAccelCtx) pKeyBlob, keyBlobLength, pKey);
            }
            else
            {
                status = KEYBLOB_readDSAKeyPart( MOC_DSA(hwAccelCtx) pKeyBlob, keyBlobLength, pKey);
            }
            break;
        }
#endif
#if defined(__ENABLE_DIGICERT_HW_SECURITY_MODULE__)
        case keyblob_type_hsm_rsa:
        {
            status = KEYBLOB_readHSMRSAKeyPart(pKeyBlob, keyBlobLength, pKey);
            break;
        }
#endif
#if (defined(__ENABLE_DIGICERT_ASYM_KEY__))
        case keyblob_type_custom:
        case keyblob_type_moc:
        {
          MocAsymKey pMocAsymKey = (MocAsymKey )(pKey->key.pMocAsymKey);
          MKeyOperatorData theBlob;

          /* We can only extract for a custom or mocasymkey.
           */
          status = ERR_BAD_KEY_BLOB;
          if (keyblob_type_moc != pKey->type && keyblob_type_custom != pKey->type)
            break;

          if (NULL != pMocAsymKey->KeyOperator)
          {
            theBlob.pData = (ubyte *)pKeyBlob;
            theBlob.length = keyBlobLength;
            status = pMocAsymKey->KeyOperator (
              pMocAsymKey, NULL, MOC_ASYM_OP_DESERIALIZE, (void *)&theBlob,
              NULL, NULL);
          }
          break;
        }
#endif
        default:
        {
            status = ERR_BAD_KEY_BLOB;
            break;
        }
    }

exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

    return status;
}


/*------------------------------------------------------------------*/

#if (!defined(__DISABLE_DIGICERT_KEY_GENERATION__))
/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern MSTATUS
KEYBLOB_extractPublicKey(const ubyte *pKeyBlob, ubyte4 keyBlobLength,
                         ubyte **ppRetPublicKeyBlob, ubyte4 *pRetPublicKeyBlobLength,
                         ubyte4 *pRetKeyType)
{
    AsymmetricKey       key;
    MSTATUS             status;

    if ((NULL == ppRetPublicKeyBlob) || (NULL == pRetPublicKeyBlobLength) || (NULL == pRetKeyType))
        return ERR_NULL_POINTER;

    *pRetKeyType = keyblob_type_undefined;

    CRYPTO_initAsymmetricKey(&key);

    if (OK > (status = KEYBLOB_extractKeyBlobEx(pKeyBlob, keyBlobLength, &key)))
        goto exit;

    if (keyblob_type_ecc == key.type)
    {
#if (defined(__ENABLE_DIGICERT_ECC__))
        key.key.pECC->privateKey = 0;

#else
        status = ERR_CRYPTO_ECC_DISABLED;
        goto exit;
#endif
    }
#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__
    else if (keyblob_type_ecc_ed == key.type)
    {
        ((edECCKey *)(key.key.pECC->pEdECCKey))->isPrivate = FALSE;
    }
#endif
    else if (keyblob_type_rsa == key.type)
    {
        key.key.pRSA->privateKey = FALSE;
    }
    else if (keyblob_type_dsa == key.type)
    {
#if (defined(__ENABLE_DIGICERT_DSA__))
        VLONG_freeVlong( &DSA_X(key.key.pDSA), NULL); /* clear the X (private value) */
#else
        status = ERR_CRYPTO_DSA_DISABLED;
        goto exit;
#endif
    }
    else
    {
        status = ERR_CRYPTO_BAD_KEY_TYPE;
        goto exit;
    }

    if (OK > ( status = KEYBLOB_makeKeyBlobEx(&key, ppRetPublicKeyBlob, pRetPublicKeyBlobLength)))
        goto exit;

    *pRetKeyType = key.type;

exit:
    CRYPTO_uninitAsymmetricKey(&key, NULL);

    return status;
}


#endif
