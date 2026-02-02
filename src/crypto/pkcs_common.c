/*
 * pkcs_common.c
 *
 * Routines useful for PKCS
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

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/secmod.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/tree.h"
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../common/vlong.h"
#include "../common/random.h"
#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#endif
#include "../asn1/parseasn1.h"
#include "../asn1/derencoder.h"
#include "../crypto/crypto.h"
#include "../crypto/pubcrypto.h"
#ifdef __ENABLE_ARC2_CIPHERS__
#include "../crypto/arc2.h"
#endif
#ifdef __ENABLE_DIGICERT_PKCS5__
#include "../crypto/pkcs5.h"
#endif
#include "../crypto/pkcs_common.h"
#if defined( __ENABLE_DIGICERT_PKCS7__) || defined(__ENABLE_DIGICERT_PKCS12__)
#include "../crypto/pkcs7.h"
#endif
#ifdef __ENABLE_DIGICERT_PKCS12__
#include "../crypto/pkcs12.h"
#endif
#include "../harness/harness.h"



/*---------------------------------------------------------------------------*/
#ifndef __DISABLE_DIGICERT_CERTIFICATE_PARSING__
extern MSTATUS
PKCS_BulkDecrypt(MOC_SYM(hwAccelDescr hwAccelCtx)
                 ASN1_ITEM* pEncryptedContent,
                 CStream s,
                 BulkCtx bulkCtx,
                 const BulkEncryptionAlgo* pBulkAlgo,
                 ubyte* iv,
                 ubyte** decryptedInfo,
                 sbyte4* decryptedInfoLen)
{
    return PKCS_BulkDecryptEx(MOC_SYM(hwAccelCtx) NORMAL, pEncryptedContent,
                              s, bulkCtx, pBulkAlgo, iv,
                              decryptedInfo, decryptedInfoLen);
}


/*---------------------------------------------------------------------------*/

extern MSTATUS
PKCS_BulkDecryptEx(MOC_SYM(hwAccelDescr hwAccelCtx)
                    encryptedContentType type,
                    ASN1_ITEM* pEncryptedContent,
                    CStream s,
                    BulkCtx bulkCtx,
                    const BulkEncryptionAlgo* pBulkAlgo,
                    ubyte* iv,
                    ubyte** decryptedInfo,
                    sbyte4* decryptedInfoLen)
{
    ubyte* encrypted = 0;
    ubyte* decrypted = 0;
    ubyte lastByte;
    MSTATUS status;
    ubyte4 decryptedLen = 0;
    ubyte* decryptedCopy = 0;
    ubyte* pCryptoIv = 0;

    if ((NULL == pEncryptedContent) || (NULL == pBulkAlgo) || (NULL == bulkCtx) || (NULL == decryptedInfo) || (NULL == decryptedInfoLen))
    {
        return ERR_NULL_POINTER;
    }

    if (type == NORMAL)
    {
        if (pEncryptedContent->length > 0)
        {
            /* access to encrypted data -> make a copy (decrypt in place) */
            encrypted = (ubyte*) CS_memaccess( s, pEncryptedContent->dataOffset, pEncryptedContent->length);
            if ( 0 == encrypted) {  status = ERR_MEM_ALLOC_FAIL; goto exit; }
            decryptedLen = pEncryptedContent->length;
            if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, decryptedLen, TRUE, &decrypted)))
                goto exit;
            if ( 0 == decrypted) {  status = ERR_MEM_ALLOC_FAIL; goto exit; }

            DIGI_MEMCPY( decrypted, encrypted, pEncryptedContent->length);

            CS_stopaccess( s, encrypted);
        }
        else /* BER ENCODING OCTET STRING */
        {
            ubyte4 offset;
            ASN1_ITEMPTR pOS = ASN1_FIRST_CHILD(pEncryptedContent);
            while (OK == ASN1_VerifyType(pOS, OCTETSTRING))
            {
                decryptedLen += pOS->length;
                pOS = ASN1_NEXT_SIBLING(pOS);
            }
            if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, decryptedLen, TRUE, &decrypted)))
                goto exit;
            if ( 0 == decrypted) {  status = ERR_MEM_ALLOC_FAIL; goto exit; }

            pOS = ASN1_FIRST_CHILD(pEncryptedContent);
            offset = 0;
            while(offset < decryptedLen)
            {
                encrypted = (ubyte*) CS_memaccess( s, pOS->dataOffset, pOS->length);
                if ( 0 == encrypted) {  status = ERR_MEM_ALLOC_FAIL; goto exit; }

                DIGI_MEMCPY( decrypted+offset, encrypted, pOS->length);
                CS_stopaccess( s, encrypted);
                offset += pOS->length;
                pOS = ASN1_NEXT_SIBLING(pOS);
            }
        }
    }
    else if (type == SCEP)
    {
        ASN1_ITEMPTR pTemp;
        ubyte4 offset = 0;
        /* from SCEP draft:
         * NOTE:The PKCS#7 EncryptedContent is specified as an octet string, but
         * SCEP entities must also accept a sequence of octet strings as a valid
         * alternate encoding.*/
        pTemp = pEncryptedContent;
        while (pTemp->length > 0)
        {
            decryptedLen += pTemp->length;
            pTemp = ASN1_NEXT_SIBLING(pTemp);
        }

        if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, decryptedLen, TRUE, &decrypted)))
            goto exit;
        if ( 0 == decrypted) {  status = ERR_MEM_ALLOC_FAIL; goto exit; }

        pTemp = pEncryptedContent;
        while (pTemp->length > 0)
        {
            encrypted = (ubyte*) CS_memaccess( s, pTemp->dataOffset, pTemp->length);
            if ( 0 == encrypted) {  status = ERR_MEM_ALLOC_FAIL; goto exit; }

            DIGI_MEMCPY( decrypted+offset, encrypted, pTemp->length);
            offset += pTemp->length;
            CS_stopaccess( s, encrypted);
            pTemp = ASN1_NEXT_SIBLING(pTemp);
        }
    }
    encrypted = 0;

#ifdef __DISABLE_DIGICERT_HARDWARE_ACCEL__
    pCryptoIv = iv;
#else
    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, 16, TRUE, &pCryptoIv)))
            goto exit;
    DIGI_MEMCPY(pCryptoIv, iv, 16);
#endif

    status = (pBulkAlgo->cipherFunc)(MOC_SYM(hwAccelCtx) bulkCtx, decrypted,
                    decryptedLen, 0, pCryptoIv);
    if ( OK > status) { goto exit; }

    if ( pBulkAlgo->blockSize > 0)
    {
        /* look at last byte for padding */
        lastByte = decrypted[ decryptedLen - 1];
        if ( lastByte < 1 || lastByte > pBulkAlgo->blockSize)
        {
            status = ERR_CRYPTO_BAD_PAD;
            goto exit;
        }
    }
    else
    {
        lastByte = 0;
    }
    *decryptedInfoLen = decryptedLen - (sbyte) lastByte;

#ifdef __DISABLE_DIGICERT_HARDWARE_ACCEL__
    *decryptedInfo = decrypted;
    decrypted = 0;
    pCryptoIv = 0;
#else
    if (NULL == ( decryptedCopy = (ubyte*)MALLOC(*decryptedInfoLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    DIGI_MEMCPY(decryptedCopy, decrypted, *decryptedInfoLen);
    *decryptedInfo = decryptedCopy; /*ownership transfered to caller */
    decryptedCopy = 0;
#endif

exit:

    if ( encrypted)
    {
        CS_stopaccess( s, encrypted);
        encrypted = 0;
    }
    if (decrypted)
        CRYPTO_FREE(hwAccelCtx, TRUE, &decrypted);
#ifdef __DISABLE_DIGICERT_HARDWARE_ACCEL__
    /* nothing to do */
#else
    if (pCryptoIv)
        CRYPTO_FREE(hwAccelCtx, TRUE, &pCryptoIv);
#endif

    return status;
}

#endif

#if defined(__ENABLE_DIGICERT_PKCS5__) || defined(__ENABLE_DIGICERT_PKCS12__)

/*---------------------------------------------------------------------*/

extern MSTATUS
PKCS_DecryptPKCS8Key( MOC_SYM(hwAccelDescr hwAccelCtx)
                            ASN1_ITEMPTR pEncryptedKeyInfo,
                            CStream cs, const ubyte* password,
                            sbyte4 passwordLen, ubyte** privateKeyInfo,
                            sbyte4* privateKeyInfoLen)
{
    MSTATUS status;
    ASN1_ITEMPTR  pAlgoIdentifier, pEncryptedData, pOID;
    ubyte subType;

    if ( !password || !pEncryptedKeyInfo || !privateKeyInfo || !privateKeyInfoLen)
    {
        return ERR_NULL_POINTER;
    }

    /* verify type is SEQUENCE */
    status = ASN1_VerifyType( pEncryptedKeyInfo, SEQUENCE);
    if (status < OK) return status;

    /* first child is the AlgorithmIdentifier */
    pAlgoIdentifier = ASN1_FIRST_CHILD( pEncryptedKeyInfo);
    if (!pAlgoIdentifier) return ERR_RSA_INVALID_PKCS8;
    status = ASN1_VerifyType( pAlgoIdentifier, SEQUENCE);
    if (status < OK) return status;

    /* second child is the encrypted key that we need to decrypt */
    pEncryptedData = ASN1_NEXT_SIBLING( pAlgoIdentifier);
    if (!pEncryptedData) return ERR_RSA_INVALID_PKCS8;
    status = ASN1_VerifyType( pEncryptedData, OCTETSTRING);
    if (status < OK) return status;

   /* figure out whether PKCS5 or PKCS12 password encryption */
    pOID = ASN1_FIRST_CHILD( pAlgoIdentifier);
#ifdef __ENABLE_DIGICERT_PKCS5__
    if (OK <= ASN1_VerifyOIDRoot( pOID, cs, pkcs5_root_OID, &subType))
    {
        ASN1_ITEMPTR pPBEParam = ASN1_NEXT_SIBLING( pOID);

        status = PKCS5_decrypt( MOC_SYM(hwAccelCtx) subType, cs,
                                   pPBEParam, pEncryptedData, password,
                                   passwordLen, privateKeyInfo,
                                   privateKeyInfoLen);
    }
    else
#endif
#ifdef __ENABLE_DIGICERT_PKCS12__
    if ( OK <= ASN1_VerifyOIDRoot( pOID, cs, pkcs12_Pbe_root_OID,
                                        &subType))
    {
        /* PKCS12 */
        status = PKCS12_decrypt(MOC_SYM(hwAccelCtx)
               pEncryptedData, pAlgoIdentifier, cs, password,
               passwordLen, privateKeyInfo, privateKeyInfoLen);
    }
    else
#endif
    {
        status = ERR_RSA_UNKNOWN_PKCS8_ALGOID;
        goto exit;
    }

exit:

    return status;
}
#endif

/*--------------------------------------------------------------------------*/
#ifndef __DISABLE_DIGICERT_CERTIFICATE_PARSING__
extern MSTATUS
PKCS_GetCBCParams( ASN1_ITEM* pAlgoOID, CStream s, ubyte blockSize, ubyte iv[16])
{
    MSTATUS status;
    ubyte* temp;
    ASN1_ITEMPTR pIV;

    if ( 0 == pAlgoOID || 0 == iv)
    {
        return ERR_NULL_POINTER;
    }

    pIV = ASN1_NEXT_SIBLING( pAlgoOID);
    /* routine allows null argument */
    status = ASN1_VerifyType( pIV, OCTETSTRING);
    if ( OK > status || pIV->length != blockSize)
    {
        return ERR_PKCS7_INVALID_STRUCT;
    }

    /* copy the IV to the arg */
    temp = (ubyte*) CS_memaccess( s, pIV->dataOffset, blockSize);
    if ( 0 == temp)
    {
        return ERR_MEM_ALLOC_FAIL;
    }
    status = DIGI_MEMCPY( iv, temp, blockSize);
    CS_stopaccess( s, temp);

    return status;
}
#endif

/*-------------------------------------------------------------------------*/

#ifdef __ENABLE_ARC2_CIPHERS__
extern MSTATUS
PKCS_GetRC2CBCParams( ASN1_ITEM* pAlgoOID,
                   CStream s,
                   sbyte4* pEffectiveKeyBits,
                   ubyte iv[RC2_BLOCK_SIZE])
{
    MSTATUS status;
    ubyte* temp;
    ASN1_ITEMPTR pParam, pVersion, pIV;

    if ( 0 == pAlgoOID || 0 == pEffectiveKeyBits || 0 == iv)
    {
        return ERR_NULL_POINTER;
    }

/*RC2-CBC-Parameter ::= SEQUENCE {
        rc2ParameterVersion INTEGER OPTIONAL,
        iv OCTET STRING (SIZE(8)) } */

    *pEffectiveKeyBits = 32; /* default */
    pParam = ASN1_NEXT_SIBLING( pAlgoOID);

    /*OK to send NULL pParam to the routine */
    status = ASN1_VerifyType( pParam, SEQUENCE);
    if ( OK > status)
    {
        return ERR_PKCS7_INVALID_STRUCT;
    }

    pVersion = ASN1_FIRST_CHILD( pParam);

    status = ASN1_VerifyType( pVersion, INTEGER);
    if ( OK == status)
    {
        sbyte4 encoding = pVersion->data.m_intVal;
        /* weird encoding by RSA of the effective key bits */
        switch (encoding)
        {
            case 160:
                *pEffectiveKeyBits = 40;
                break;
            case 120:
                *pEffectiveKeyBits = 64;
                break;
            case 58:
                *pEffectiveKeyBits = 128;
                break;
            default:
                if ( encoding >= 256)
                {
                    *pEffectiveKeyBits = encoding;
                }
                /* else -> error or default ? */
                break;
        }

        pIV = ASN1_NEXT_SIBLING( pVersion);
    }
    else if (ERR_FALSE == status) /*not a match but not null */
    {
        pIV = pVersion; /* version optional -> IV */
    }
    else
    {
        return ERR_PKCS7_INVALID_STRUCT;
    }

    status = ASN1_VerifyType( pIV, OCTETSTRING);
    if ( OK > status || pIV->length != RC2_BLOCK_SIZE)
    {
        return ERR_PKCS7_INVALID_STRUCT;
    }

    /* copy the IV to the arg */
    temp = (ubyte*) CS_memaccess( s, pIV->dataOffset, RC2_BLOCK_SIZE);
    if ( 0 == temp)
    {
        return ERR_MEM_ALLOC_FAIL;
    }
    status = DIGI_MEMCPY( iv, temp, RC2_BLOCK_SIZE);
    CS_stopaccess( s, temp);

    return status;
}
#endif
