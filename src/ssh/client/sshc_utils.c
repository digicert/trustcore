/*
 * sshc_utils.c
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
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include "../../common/moptions.h"

#ifdef __ENABLE_MOCANA_SSH_CLIENT__

#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"
#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../crypto/secmod.h"
#include "../../common/mrtos.h"
#include "../../common/mtcp.h"
#include "../../common/mstdlib.h"
#include "../../common/random.h"
#include "../../common/vlong.h"
#include "../../common/debug_console.h"
#include "../../common/memory_debug.h"
#include "../../common/tree.h"
#include "../../common/absstream.h"
#include "../../common/memfile.h"
#include "../../asn1/parseasn1.h"
#include "../../asn1/ASN1TreeWalker.h"
#ifdef __ENABLE_MOCANA_DSA__
#include "../../crypto/dsa.h"
#endif
#include "../../crypto/rsa.h"
#include "../../crypto/dh.h"
#include "../../crypto/crypto.h"
#ifdef __ENABLE_MOCANA_ECC__
#include "../../crypto/primefld.h"
#include "../../crypto/primeec.h"
#endif
#include "../../crypto/pubcrypto.h"
#include "../../crypto/ca_mgmt.h"
#include "../../common/base64.h"
#include "../../ssh/client/sshc.h"
#include "../../ssh/ssh_str.h"
#include "../../ssh/ssh_mpint.h"
#include "../../ssh/ssh_key.h"
#include "../../ssh/client/sshc_str_house.h"
#include "../../ssh/client/sshc_utils.h"

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_rsa.h"
#include "../crypto_interface/crypto_interface_ecc.h"
#endif

/*------------------------------------------------------------------*/

extern MSTATUS
SSHC_UTILS_sshParseAuthPublicKey(sbyte* pKeyBlob, ubyte4 keyBlobLength,
                                     AsymmetricKey *p_keyDescr)
{
    return SSH_KEY_sshParseAuthPublicKey(pKeyBlob, keyBlobLength, p_keyDescr);
}

extern MSTATUS
SSHC_UTILS_sshParseAuthPublicKeyFile(sbyte* pKeyFile, ubyte4 fileSize,
                                     AsymmetricKey *p_keyDescr)
{
    return SSH_KEY_sshParseAuthPublicKeyFile(pKeyFile, fileSize, p_keyDescr);
} /* SSHC_UTILS_sshParseAuthPublicKeyFile */


/*------------------------------------------------------------------*/

extern MSTATUS
SSHC_UTILS_getByte(ubyte *pBuffer, ubyte4 bufSize, ubyte4 *pBufIndex, ubyte *pRetByte)
{
    MSTATUS status = OK;

    if (bufSize < (*pBufIndex + 1))
    {
        /* not enough bytes to get one byte */
        status = ERR_SFTP_BAD_PAYLOAD_LENGTH;
        goto exit;
    }

    pBuffer += (*pBufIndex);

    *pRetByte   = *pBuffer;
    *pBufIndex += 1;

exit:
#ifdef __DEBUG_SSH__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_COMMON, "getByte: status = ", status);
#endif

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
SSHC_UTILS_getInteger(ubyte *pBuffer, ubyte4 bufSize, ubyte4 *pBufIndex, ubyte4 *pRetInteger)
{
    MSTATUS status = OK;

    status = SSH_KEY_getInteger(pBuffer, bufSize, pBufIndex, pRetInteger);

#ifdef __DEBUG_SSH__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_COMMON, "SSHC_UTILS_getInteger: status = ", status);
#endif

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
SSHC_UTILS_getInteger64(ubyte *pBuffer, ubyte4 bufSize, ubyte4 *pBufIndex, ubyte8 *pRetInteger64)
{
#if  __MOCANA_MAX_INT__ < 64
    ubyte4  retInteger;
#endif
    MSTATUS status = OK;

    if (bufSize < (*pBufIndex + 8))
    {
        /* not enough bytes to get */
        status = ERR_SFTP_BAD_PAYLOAD_LENGTH;
        goto exit;
    }

    pBuffer += (*pBufIndex);

#if __MOCANA_MAX_INT__ == 64
    *pRetInteger64 = (((ubyte8)(pBuffer[0])) << 56) |
        (((ubyte8)(pBuffer[1])) << 48) |
        (((ubyte8)(pBuffer[2])) << 40) |
        (((ubyte8)(pBuffer[3])) << 32) |
        (((ubyte8)(pBuffer[4])) << 24) |
        (((ubyte8)(pBuffer[5])) << 16) |
        (((ubyte8)(pBuffer[6])) << 8) |
         (ubyte8)(pBuffer[7]);

#else
    retInteger  = ((ubyte4)pBuffer[3]);
    retInteger |= ((ubyte4)pBuffer[2]) << 8;
    retInteger |= ((ubyte4)pBuffer[1]) << 16;
    retInteger |= ((ubyte4)pBuffer[0]) << 24;

    pRetInteger64->upper32 = retInteger;

    retInteger  = ((ubyte4)pBuffer[7]);
    retInteger |= ((ubyte4)pBuffer[6]) << 8;
    retInteger |= ((ubyte4)pBuffer[5]) << 16;
    retInteger |= ((ubyte4)pBuffer[4]) << 24;

    pRetInteger64->lower32 = retInteger;
#endif

    *pBufIndex  += 8;

exit:
#ifdef __DEBUG_SSH__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_COMMON, "SSHC_UTILS_getInteger64: status = ", status);
#endif

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
SSHC_UTILS_setByte(ubyte *pPayload, ubyte4 payloadLength, ubyte4 *pBufIndex, ubyte byteValue)
{
    MSTATUS status = OK;

    if (payloadLength < (*pBufIndex + 1))
    {
        /* not enough room to set byte */
        status = ERR_SFTP_PAYLOAD_TOO_SMALL;
        goto exit;
    }

    pPayload += (*pBufIndex);
    *pPayload   = (ubyte)(byteValue);
    *pBufIndex += 1;

exit:
#ifdef __DEBUG_SSH__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_COMMON, "SSHC_UTILS_setByte: status = ", status);
#endif

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
SSHC_UTILS_setInteger(ubyte *pPayload, ubyte4 payloadLength, ubyte4 *pBufIndex, ubyte4 integerValue)
{

    MSTATUS status = SSH_KEY_setInteger(pPayload, payloadLength, pBufIndex, integerValue);

#ifdef __DEBUG_SSH__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_COMMON, "SSHC_UTILS_setInteger: status = ", status);
#endif

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSHC_UTILS_setInteger64(ubyte *pPayload, ubyte4 payloadLength, ubyte4 *pBufIndex, ubyte8 *pIntegerValue64)
{
    MSTATUS status = OK;

    if (payloadLength < (*pBufIndex + 8))
    {
        /* not enough room to set integer */
        status = ERR_SFTP_PAYLOAD_TOO_SMALL;
        goto exit;
    }

    pPayload += (*pBufIndex);

#if __MOCANA_MAX_INT__ == 64
    pPayload[0] = (ubyte)((*pIntegerValue64) >> 56);
    pPayload[1] = (ubyte)((*pIntegerValue64) >> 48);
    pPayload[2] = (ubyte)((*pIntegerValue64) >> 40);
    pPayload[3] = (ubyte)((*pIntegerValue64) >> 32);
    pPayload[4] = (ubyte)((*pIntegerValue64) >> 24);
    pPayload[5] = (ubyte)((*pIntegerValue64) >> 16);
    pPayload[6] = (ubyte)((*pIntegerValue64) >> 8);
    pPayload[7] = (ubyte)((*pIntegerValue64));

#else
    pPayload[0] = (ubyte)(pIntegerValue64->upper32 >> 24);
    pPayload[1] = (ubyte)(pIntegerValue64->upper32 >> 16);
    pPayload[2] = (ubyte)(pIntegerValue64->upper32 >> 8);
    pPayload[3] = (ubyte)(pIntegerValue64->upper32);

    pPayload[4] = (ubyte)(pIntegerValue64->lower32 >> 24);
    pPayload[5] = (ubyte)(pIntegerValue64->lower32 >> 16);
    pPayload[6] = (ubyte)(pIntegerValue64->lower32 >> 8);
    pPayload[7] = (ubyte)(pIntegerValue64->lower32);
#endif

    *pBufIndex += 8;

exit:
#ifdef __DEBUG_SSH__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_COMMON, "SSHC_UTILS_setInteger64: status = ", status);
#endif

    return status;
}


/*------------------------------------------------------------------*/

#if !defined(__DISABLE_MOCANA_KEY_GENERATION__)

extern MSTATUS
SSHC_UTILS_generateHostKeyFile(ubyte *pKeyBlob, ubyte4 keyBlobLength, ubyte **ppRetHostFile, ubyte4 *pRetHostFileLen)
{
    return SSH_KEY_generateHostKeyFile(pKeyBlob, keyBlobLength, ppRetHostFile, pRetHostFileLen);
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSHC_UTILS_generateServerAuthKeyFile(ubyte *pKeyBlob, ubyte4 keyBlobLength,
                                     ubyte **ppRetEncodedAuthKey, ubyte4 *pRetEncodedAuthKeyLen)
{
    return SSH_KEY_generateServerAuthKeyFile(pKeyBlob, keyBlobLength, ppRetEncodedAuthKey,
        pRetEncodedAuthKeyLen);
}
#endif /* !defined(__DISABLE_MOCANA_KEY_GENERATION__) */


/*------------------------------------------------------------------*/

extern MSTATUS
SSHC_UTILS_freeGenerateServerAuthKeyFile(ubyte **ppFreeEncodedAuthKey)
{
    MSTATUS status = ERR_NULL_POINTER;

    if ((NULL != ppFreeEncodedAuthKey) && (NULL != *ppFreeEncodedAuthKey))
    {
        MOC_FREE((void **) ppFreeEncodedAuthKey);
        status = OK;
    }

    return status;
}


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_DSA__))

#ifdef __ENABLE_MOCANA_DER_CONVERSION__
static MSTATUS
SSHC_UTILS_getDSAKey(MOC_DSA(hwAccelDescr hwAccelCtx) const ubyte *pData, ubyte4 pDataLength, AsymmetricKey *pKey)
{
    MSTATUS         status;
    CStream         cs;
    MemFile         mf;
    DSAKey*         pDsaKey;
    sbyte4          i = 0;
    ASN1_ITEMPTR    pRoot = NULL;
    ASN1_ITEMPTR    pSequence = NULL;
    ASN1_ITEMPTR    pDummy = NULL;
    ASN1_ITEMPTR    pKeyComponent;

    static WalkerStep DsaDerWalkInstructions[] =
    {
        { GoFirstChild, 0, 0},
        { VerifyType, SEQUENCE, 0},
        { GoFirstChild, 0, 0},          /* version */
        { VerifyInteger, 0, 0},         /* verify version is 0 */
        { GoNextSibling, 0, 0 },        /* p */
        { GoNextSibling, 0, 0 },        /* q */
        { GoNextSibling, 0, 0 },        /* g */
        { GoNextSibling, 0, 0 },        /* public key: y */
        /* { GoNextSibling, 0, 0 }, */  /* private key: x */
        { Complete, 0, 0}
    };


    /* parse DER file */
    if (OK > (status = MF_attach( &mf, pDataLength, (ubyte*) pData)))
        goto exit;

    CS_AttachMemFile( &cs, &mf);

    if ( OK > (status = ASN1_Parse(cs, &pRoot)))
        goto exit;

    status = ERR_ASN_INVALID_DATA;

    /* verify DSA DER infomation */
    if ( OK >  ASN1_WalkTree( pRoot, cs, DsaDerWalkInstructions, &pDummy))
        goto exit;

    if (NULL == pDummy)
        goto exit;

    if (OK > CRYPTO_createDSAKey (pKey, NULL))
        goto exit;

    pDsaKey = pKey->key.pDSA;

    pSequence = ASN1_FIRST_CHILD( pRoot);

    /* skip version */
    pKeyComponent = ASN1_FIRST_CHILD( pSequence);

    /* set DSA parameters */
    while ( (i < NUM_DSA_VLONG) && (NULL != (pKeyComponent = ASN1_NEXT_SIBLING( pKeyComponent))) )
    {
        if (OK > (status = VLONG_vlongFromByteString( pData + pKeyComponent->dataOffset,
                                                      pKeyComponent->length,
                                                     &(pDsaKey->dsaVlong[i++]), NULL)) )
        {
            goto exit;
        }
    }

exit:

    if ( pRoot)
    {
        TREE_DeleteTreeItem((TreeItem*) pRoot);
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSHC_UTILS_convertDsaKeyDER(MOC_ASYM(hwAccelDescr hwAccelCtx) ubyte *pDerDsaKey, ubyte4 derDsaKeyLength,
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

    status = SSHC_UTILS_getDSAKey(MOC_DSA(hwAccelCtx) pDerDsaKey, derDsaKeyLength, &key);

    if (OK > status)
        goto exit;

    status = CA_MGMT_makeKeyBlobEx(&key, ppRetKeyBlob, pRetKeyBlobLength);

exit:
    CRYPTO_uninitAsymmetricKey(&key, NULL);

    return (sbyte4)status;

}
#endif /* __ENABLE_MOCANA_DER_CONVERSION__ */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_PEM_CONVERSION__
extern MSTATUS
SSHC_UTILS_convertDsaKeyPEM(MOC_ASYM(hwAccelDescr hwAccelCtx) ubyte *pPemRsaKey, ubyte4 pemRsaKeyLength,
                         ubyte **ppRetKeyBlob, ubyte4 *pRetKeyBlobLength )
{
    ubyte*      pDerRsaKey = 0;
    ubyte4      derRsaKeyLength;
    MSTATUS     status;

    /* check input */
    if ((NULL == pPemRsaKey) || (NULL == ppRetKeyBlob) || (NULL == pRetKeyBlobLength))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* decode the base64 encoded message */
    if (OK > (status = CA_MGMT_decodeCertificate(pPemRsaKey, pemRsaKeyLength, &pDerRsaKey, &derRsaKeyLength)))
        goto exit;

    status = SSHC_UTILS_convertDsaKeyDER(MOC_ASYM(hwAccelCtx) pDerRsaKey, derRsaKeyLength, ppRetKeyBlob, pRetKeyBlobLength);

exit:
    if (NULL != pDerRsaKey)
        FREE(pDerRsaKey);

    return (sbyte4)status;
}
#endif /* __ENABLE_MOCANA_PEM_CONVERSION__ */

#endif /* (defined(__ENABLE_MOCANA_DSA__)) */

#endif /* __ENABLE_MOCANA_SSH_CLIENT__ */
