/*
 * ssh_out_mesg.c
 *
 * SSH Outbound Message Handler
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

#define __ENABLE_OUTBOUND_SSH_DEFINITIONS__

#include "../common/moptions.h"

#ifdef __ENABLE_MOCANA_SSH_SERVER__

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/secmod.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../common/mem_pool.h"
#include "../common/moc_stream.h"
#include "../common/debug_console.h"
#include "../common/int64.h"
#include "../crypto/crypto.h"
#include "../crypto/dsa.h"
#include "../crypto/dh.h"
#ifdef __ENABLE_MOCANA_ECC__
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#endif
#include "../crypto/pubcrypto.h"
#include "../common/sizedbuffer.h"
#include "../crypto/cert_store.h"
#include "../crypto/ca_mgmt.h"
#include "../ssh/ssh_str.h"
#include "../ssh/ssh_context.h"
#include "../ssh/ssh_out_mesg.h"
#include "../ssh/dump_mesg.h"
#include "../harness/harness.h"


/*------------------------------------------------------------------*/

static MSTATUS UTILS_ubyte8ToArray(ubyte8 i, ubyte *out)
{
    if (NULL == out)
    {
        return ERR_NULL_POINTER;
    }

    out[0] = (ubyte) ((i >> 56) & 0xFF);
    out[1] = (ubyte) ((i >> 48) & 0xFF);
    out[2] = (ubyte) ((i >> 40) & 0xFF);
    out[3] = (ubyte) ((i >> 32) & 0xFF);
    out[4] = (ubyte) ((i >> 24) & 0xFF);
    out[5] = (ubyte) ((i >> 16) & 0xFF);
    out[6] = (ubyte) ((i >> 8) & 0xFF);
    out[7] = (ubyte) (i & 0xFF);

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_OUT_MESG_sendMessageSize(sshContext *pContextSSH,
                             ubyte4 payloadLength,
                             ubyte4 *pRetPayloadMax)
{
    ubyte4  packetLen;
    ubyte4  padLen;
    ubyte4  payloadBytesTransferred;
    ubyte4  totalMessageSize;
    MSTATUS status = OK;

    if ((NULL == pContextSSH) || (NULL == (OUTBOUND_BUFFER(pContextSSH))) ||
        (NULL == pRetPayloadMax))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == payloadLength)
    {
        status = ERR_PAYLOAD_EMPTY;
        goto exit;
    }

    packetLen  = payloadLength + 1 + 4;
    padLen     = 4 + (OUTBOUND_CIPHER_SIZE(pContextSSH) -
                         ((packetLen + 4) % OUTBOUND_CIPHER_SIZE(pContextSSH)));
    packetLen += padLen;

    totalMessageSize = packetLen;

    if (NULL != OUTBOUND_MAC_ALGORITHM(pContextSSH))
        totalMessageSize += OUTBOUND_MAC_SIZE(pContextSSH);

    payloadBytesTransferred = payloadLength;

    if (OUTBOUND_MAX_MESSAGE_SIZE(pContextSSH) < (totalMessageSize + 16))
        payloadBytesTransferred -= (16 + totalMessageSize - OUTBOUND_MAX_MESSAGE_SIZE(pContextSSH));

    *pRetPayloadMax = payloadBytesTransferred;

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
SSH_OUT_MESG_sendMessage(sshContext *pContextSSH,
                         ubyte *pPayload, ubyte4 payloadLength,
                         ubyte4 *pRetPayloadTransferred)
{
#ifdef SSH_OUT_CUSTOM_MUTEX
    intBoolean  isLocked = FALSE;
#endif
    ubyte4      packetLen;
    ubyte4      padLen;
    ubyte4      payloadBytesTransferred;
    ubyte4      totalMessageSize;
    ubyte4      numBytesWritten;
    MSTATUS     status;
    ubyte       pSequenceNumOut[8];
    ubyte4      aadLen;

    if ((NULL == pContextSSH) || (NULL == pPayload) ||
        (NULL == (OUTBOUND_BUFFER(pContextSSH))) || (NULL == pRetPayloadTransferred))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == payloadLength)
    {
        status = ERR_PAYLOAD_EMPTY;
        goto exit;
    }

#ifdef __ENABLE_ALL_DEBUGGING__
    /*if (kSftpOpenState != SSH_SESSION_STATE(pContextSSH))*/
        DUMP_MESG_sshMessage(pPayload, payloadLength, TRUE, pContextSSH->authContext.authMethod);
#endif

#ifdef SSH_OUT_CUSTOM_MUTEX
    if (status = (0 > SSH_OUT_CUSTOM_MUTEX(pContextSSH->connectionInstance, 1)))    /* 1 == lock, 0 == unlock */
        goto exit;

    isLocked = TRUE;
#endif

    packetLen  = payloadLength + 1 + 4;

    if (NULL != pContextSSH->pEncryptSuiteInfoOut->pAeadSuiteInfo || TRUE == OUTBOUND_MAC_IS_ETM(pContextSSH))
    {
    /*
      AES-GCM RFC 5647 -
      PT (Plain Text)
        byte      padding_length; // 4 <= padding_length < 256
        byte[n1]  payload;        // n1 = packet_length-padding_length-1
        byte[n2]  random_padding; // n2 = padding_length
     AAD (Additional Authenticated Data)
        uint32    packet_length;  // 0 <= packet_length < 2^32
     IV (Initialization Vector)
        As described in section 7.1.
     BK (Block Cipher Key)
        The appropriate Encryption Key formed during the Key Exchange.
       The total length of the PT MUST be a multiple of 16 octets
       (the block size of AES).  The binary packet is the concatenation
       of the 4-octet packet_length, the cipher text (CT), and the 16-octet
       authentication tag (AT)
   */
      padLen = (OUTBOUND_CIPHER_SIZE(pContextSSH) -
                         ((packetLen - 4) % OUTBOUND_CIPHER_SIZE(pContextSSH)));
      if(4 > padLen) /* Padding must be atleast 4 bytes */
         padLen += (OUTBOUND_CIPHER_SIZE(pContextSSH));

    }
    else
    { /* Other flows - based on RFC 4253 */
      padLen     = 4 + (OUTBOUND_CIPHER_SIZE(pContextSSH) -
                         ((packetLen + 4) % OUTBOUND_CIPHER_SIZE(pContextSSH)));
    }
    packetLen += padLen;

    totalMessageSize = packetLen;

    if ((NULL != OUTBOUND_MAC_ALGORITHM(pContextSSH)) || (NULL != pContextSSH->pHmacSuiteInfoOut->pAeadSuiteInfo))
        totalMessageSize += OUTBOUND_MAC_SIZE(pContextSSH);

    payloadBytesTransferred = payloadLength;

    if (OUTBOUND_MAX_MESSAGE_SIZE(pContextSSH) < totalMessageSize)
    {
        ubyte4 bytesToRemove = totalMessageSize - OUTBOUND_MAX_MESSAGE_SIZE(pContextSSH);
        payloadBytesTransferred -= bytesToRemove;
        totalMessageSize        -= bytesToRemove;
        packetLen               -= bytesToRemove;
        payloadLength           -= bytesToRemove;
    }

    *pRetPayloadTransferred = payloadBytesTransferred;

/*
    uint32      packet_length
    byte        padding_length
    byte[n1]    payload; n1 = packet_length - padding_length - 1
    byte[n2]    random padding; n2 = padding_length
    byte[m]     mac (message authentication code); m = mac_length
*/

    /* write packet_length length */
    (OUTBOUND_BUFFER(pContextSSH))[0] = (ubyte)(((packetLen - 4) >> 24) & 0xff);
    (OUTBOUND_BUFFER(pContextSSH))[1] = (ubyte)(((packetLen - 4) >> 16) & 0xff);
    (OUTBOUND_BUFFER(pContextSSH))[2] = (ubyte)(((packetLen - 4) >>  8) & 0xff);
    (OUTBOUND_BUFFER(pContextSSH))[3] = (ubyte)(((packetLen - 4)      ) & 0xff);

    /* write pad length */
    (OUTBOUND_BUFFER(pContextSSH))[4] = (ubyte)padLen;

    /* copy payload to message */
    MOC_MEMCPY(&((OUTBOUND_BUFFER(pContextSSH))[5]), pPayload, payloadLength);

    /* fill pad with random garbage */
    if (OK > (status = RANDOM_numberGenerator(g_pRandomContext, &((OUTBOUND_BUFFER(pContextSSH))[packetLen - padLen]), (sbyte4)padLen)))
        goto exit;

    if (OUTBOUND_MAC_IS_ETM(pContextSSH) == FALSE)
    {
        /* fill in the MAC */
        if (NULL != OUTBOUND_MAC_ALGORITHM(pContextSSH))
        {
            ubyte*  sequenceBuf = NULL;
            ubyte4  sequenceNum = OUTBOUND_SEQUENCE_NUM(pContextSSH);

            if (OK > (status = MEM_POOL_getPoolObject(&pContextSSH->smallPool, (void **)&(sequenceBuf))))
                goto exit;

            sequenceBuf[0] = (ubyte)(sequenceNum >> 24);
            sequenceBuf[1] = (ubyte)(sequenceNum >> 16);
            sequenceBuf[2] = (ubyte)(sequenceNum >>  8);
            sequenceBuf[3] = (ubyte)(sequenceNum);

            status = (OUTBOUND_MAC_ALGORITHM(pContextSSH))
                        (MOC_HASH(pContextSSH->hwAccelCookie) OUTBOUND_KEY_DATA(pContextSSH), OUTBOUND_KEY_DATA_LEN(pContextSSH),
                            sequenceBuf, 4,
                            (OUTBOUND_BUFFER(pContextSSH)), packetLen,
                            &(OUTBOUND_BUFFER(pContextSSH)[packetLen]));

            MEM_POOL_putPoolObject(&pContextSSH->smallPool, (void **)(&sequenceBuf));

            if (OK > status)
                goto exit;
        }

    #if (defined(__ENABLE_MOCANA_CHACHA20__) && defined(__ENABLE_MOCANA_POLY1305__))
    #ifdef __ENABLE_MOCANA_SSH_WEAK_CIPHERS__
        if (CHACHA20_POLY1305_OPENSSH == OUTBOUND_CIPHER_TYPE(pContextSSH))
        {
            status = UTILS_ubyte8ToArray((ubyte8)OUTBOUND_SEQUENCE_NUM(pContextSSH), pSequenceNumOut);
            if (OK != status)
                goto exit;
        }
    #endif
    #endif /* (defined(__ENABLE_MOCANA_CHACHA20__) && defined(__ENABLE_MOCANA_POLY1305__)) */

        OUTBOUND_INC_SEQUENCE_NUM(pContextSSH);
        u8_Incr32(&pContextSSH->bytesTransmitted, packetLen);

        /* encrypt the message */
        if (NULL != OUTBOUND_CIPHER_ALGORITHM(pContextSSH))
        {
    #if (defined(__ENABLE_MOCANA_CHACHA20__) && defined(__ENABLE_MOCANA_POLY1305__))
    #ifdef __ENABLE_MOCANA_SSH_WEAK_CIPHERS__
            if (CHACHA20_POLY1305_OPENSSH == OUTBOUND_CIPHER_TYPE(pContextSSH))
            {
                /* OUTBOUND_CIPHER_CONTEXT2 has context ofr encrypting/decrypting header byte */
                status = (OUTBOUND_CIPHER_ALGORITHM(pContextSSH))(
                    MOC_SYM(pContextSSH->hwAccelCookie) OUTBOUND_CIPHER_CONTEXT2(pContextSSH),
                    OUTBOUND_BUFFER(pContextSSH), 4 /* only encrypt length bytes with this context */, 1, pSequenceNumOut);
            }
            else
    #endif
    #endif /* (defined(__ENABLE_MOCANA_CHACHA20__) && defined(__ENABLE_MOCANA_POLY1305__)) */
            {
                status = (OUTBOUND_CIPHER_ALGORITHM(pContextSSH))(MOC_SYM(pContextSSH->hwAccelCookie) OUTBOUND_CIPHER_CONTEXT(pContextSSH),
                                                                (OUTBOUND_BUFFER(pContextSSH)),
                                                                packetLen, 1, OUTBOUND_CIPHER_IV(pContextSSH));
            }
        }
    }

    if (NULL != pContextSSH->pEncryptSuiteInfoOut->pAeadSuiteInfo)
    {
        sbyte4       index;
        sshAeadAlgo* pAeadSuite = pContextSSH->pEncryptSuiteInfoOut->pAeadSuiteInfo;

        /* cipher */
#if (defined(__ENABLE_MOCANA_CHACHA20__) && defined(__ENABLE_MOCANA_POLY1305__))
#ifdef __ENABLE_MOCANA_SSH_WEAK_CIPHERS__
        if (CHACHA20_POLY1305_OPENSSH == OUTBOUND_CIPHER_TYPE(pContextSSH))
        {
            status = pAeadSuite->funcCipher(MOC_SYM(pContextSSH->hwAccelCookie) OUTBOUND_CIPHER_CONTEXT(pContextSSH),
                                            pSequenceNumOut, 8,
                                            NULL, 0,
                                            OUTBOUND_BUFFER(pContextSSH), packetLen,
                                            pAeadSuite->authenticationTagLength, TRUE);
        }
        else
#endif
#endif /* (defined(__ENABLE_MOCANA_CHACHA20__) && defined(__ENABLE_MOCANA_POLY1305__)) */
        {
            status = pAeadSuite->funcCipher(MOC_SYM(pContextSSH->hwAccelCookie) OUTBOUND_CIPHER_CONTEXT(pContextSSH),
                                            OUTBOUND_CIPHER_IV(pContextSSH), pAeadSuite->nonceFixedLength + pAeadSuite->nonceInvocationCounter,
                                            OUTBOUND_BUFFER(pContextSSH), 4 /* message length */,
                                            (4 + OUTBOUND_BUFFER(pContextSSH)), packetLen - 4,
                                            pAeadSuite->authenticationTagLength, TRUE);

            index = pAeadSuite->nonceInvocationCounter - 1;

            /* increment invocation counter */
            while ((0 == (++(*(OUTBOUND_CIPHER_IV(pContextSSH) + pAeadSuite->nonceFixedLength + index)))) && (index > 0))
                index--;
        }
    }
    else if (TRUE == OUTBOUND_MAC_IS_ETM(pContextSSH))
    {
        /* Exclude packet length from encryption for EtM modes */
        aadLen = 4;
        packetLen -= aadLen;

        if (NULL != OUTBOUND_CIPHER_ALGORITHM(pContextSSH))
        {
            status = (OUTBOUND_CIPHER_ALGORITHM(pContextSSH))(MOC_SYM(pContextSSH->hwAccelCookie) OUTBOUND_CIPHER_CONTEXT(pContextSSH),
                                                              (OUTBOUND_BUFFER(pContextSSH)) + aadLen,
                                                              packetLen, 1, OUTBOUND_CIPHER_IV(pContextSSH));
            if (OK > status)
                goto exit;
        }

        /* Calculate MAC on the aadLen + encrypted data */
        if (NULL != OUTBOUND_MAC_ALGORITHM(pContextSSH))
        {
            ubyte* sequenceBuf = NULL;
            ubyte4 sequenceNum = OUTBOUND_SEQUENCE_NUM(pContextSSH);

            if (OK > (status = MEM_POOL_getPoolObject(&pContextSSH->smallPool, (void **)&(sequenceBuf))))
                goto exit;

            sequenceBuf[0] = (ubyte)(sequenceNum >> 24);
            sequenceBuf[1] = (ubyte)(sequenceNum >> 16);
            sequenceBuf[2] = (ubyte)(sequenceNum >> 8);
            sequenceBuf[3] = (ubyte)(sequenceNum);

            status = (OUTBOUND_MAC_ALGORITHM(pContextSSH))
                       (MOC_HASH(pContextSSH->hwAccelCookie) OUTBOUND_KEY_DATA(pContextSSH), OUTBOUND_KEY_DATA_LEN(pContextSSH),
                        sequenceBuf, 4,
                        (OUTBOUND_BUFFER(pContextSSH)), packetLen + aadLen,
                        &(OUTBOUND_BUFFER(pContextSSH)[packetLen + aadLen]));

            MEM_POOL_putPoolObject(&pContextSSH->smallPool, (void **)(&sequenceBuf));

            if (OK > status)
                goto exit;
        }
        OUTBOUND_INC_SEQUENCE_NUM(pContextSSH);
        u8_Incr32(&pContextSSH->bytesTransmitted, packetLen);
    }

    if (OK <= status)
    {
#ifndef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
        status = TCP_WRITE(SOCKET(pContextSSH), (sbyte *)OUTBOUND_BUFFER(pContextSSH),
                           totalMessageSize, &numBytesWritten);
#else
        status = MOC_STREAM_write(pContextSSH->pSocketOutStreamDescr, OUTBOUND_BUFFER(pContextSSH),
                                  totalMessageSize, &numBytesWritten);
#endif

        if ((OK <= status) && (numBytesWritten != totalMessageSize))
            status = ERR_TCP_WRITE_BLOCK_FAIL;
    }

exit:
#ifdef SSH_OUT_CUSTOM_MUTEX
    if (TRUE == isLocked)
        status = SSH_OUT_CUSTOM_MUTEX(pContextSSH->connectionInstance, 0);    /* 1 == lock, 0 == unlock */
#endif

    return status;

} /* SSH_OUT_MESG_sendMessage */


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_OUT_MESG_allocStructures(sshContext *pContextSSH)
{
    MSTATUS status = OK;

    if (NULL == pContextSSH)
        status = ERR_NULL_POINTER;
    else if ( OK > (status = CRYPTO_ALLOC ( pContextSSH->hwAccelCookie, OUTBOUND_BUFFER_SIZE(pContextSSH) , TRUE, &OUTBOUND_BUFFER(pContextSSH) ) ) )
        goto exit;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_OUT_MESG_deallocStructures(sshContext *pContextSSH)
{
    MSTATUS status = OK;

    if ((NULL == pContextSSH) || (NULL == OUTBOUND_BUFFER(pContextSSH)))
        status = ERR_NULL_POINTER;
    else
    {
        CRYPTO_FREE ( pContextSSH->hwAccelCookie, TRUE, &OUTBOUND_BUFFER(pContextSSH) );
        OUTBOUND_BUFFER(pContextSSH) = NULL;
    }

    return status;
}


#endif /* __ENABLE_MOCANA_SSH_SERVER__ */


