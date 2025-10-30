/*
 * sshc_in_mesg.c
 *
 * SSH Inbound Message Handler
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

#define __ENABLE_OUTBOUND_SSH_DEFINITIONS__
#define __ENABLE_INBOUND_SSH_DEFINITIONS__


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
#include "../../common/mem_pool.h"
#include "../../common/circ_buf.h"
#include "../../common/int64.h"
#include "../../crypto/dsa.h"
#include "../../crypto/dh.h"
#include "../../crypto/sha1.h"
#include "../../crypto/crypto.h"
#ifdef __ENABLE_MOCANA_ECC__
#include "../../crypto/primefld.h"
#include "../../crypto/primeec.h"
#endif
#include "../../crypto/pubcrypto.h"
#include "../../common/sizedbuffer.h"
#include "../../crypto/cert_store.h"
#include "../../crypto/ca_mgmt.h"
#include "../../ssh/dump_mesg.h"
#include "../../ssh/ssh_defs.h"
#include "../../ssh/client/sshc.h"
#include "../../ssh/ssh_str.h"
#include "../../ssh/client/sshc_context.h"
#include "../../ssh/client/sshc_in_mesg.h"
#include "../../ssh/client/sshc_out_mesg.h"
#include "../../ssh/client/sshc_client.h"
#include "../../ssh/client/sshc_session.h"
#include "../../ssh/client/sshc_filesys.h"
#include "../../ssh/client/sshc_ftp.h"
#include "../../ssh/client/sshc_trans.h"
#include "../../harness/harness.h"


/*------------------------------------------------------------------*/

static MSTATUS UTILS_arrayToUbyte4(const ubyte *in, ubyte4 *out)
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

#if (defined(__ENABLE_MOCANA_CHACHA20__) && defined(__ENABLE_MOCANA_POLY1305__))
#ifdef __ENABLE_MOCANA_SSH_WEAK_CIPHERS__
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
#endif
#endif /* (defined(__ENABLE_MOCANA_CHACHA20__) && defined(__ENABLE_MOCANA_POLY1305__)) */

/*------------------------------------------------------------------*/

extern MSTATUS
SSHC_IN_MESG_resetInboundState(sshClientContext *pContextSSH)
{
    INBOUND_STATE(pContextSSH) = kReceiveInit;

    return OK;
}


/*------------------------------------------------------------------*/

static MSTATUS
receiveInitVersionString(sshClientContext *pContextSSH)
{
    INBOUND_STATE(pContextSSH)          = kReceiveClientHelloListen;
    INBOUND_BYTES_READ(pContextSSH)     = 0;
    INBOUND_PACKET_LENGTH(pContextSSH)  = 0;
    INBOUND_PADDING_LENGTH(pContextSSH) = 0;
    INBOUND_PAYLOAD_LENGTH(pContextSSH) = 0;
    INBOUND_BYTES_TO_READ(pContextSSH)  = 0;

    return SSHC_TRANS_setMessageTimer(pContextSSH, SSHC_sshClientSettings()->sshTimeOutOpen);
}


/*------------------------------------------------------------------*/

#define EXPECTED_CLIENT_STRING      "SSH-2."
#define EXPECTED_CLIENT_STRING1     "SSH-1.99"
#define EXPECTED_SSH_VERSION_STRING    "SSH-2."
#define EXPECTED_SSH_VERSION_STRING1   "SSH-1.99"


/*------------------------------------------------------------------*/

static MSTATUS
receiveInit(sshClientContext *pContextSSH)
{
    INBOUND_STATE(pContextSSH)          = kReceiveFirstBlock;
    INBOUND_BYTES_READ(pContextSSH)     = 0;
    INBOUND_PACKET_LENGTH(pContextSSH)  = 0;
    INBOUND_PADDING_LENGTH(pContextSSH) = 0;
    INBOUND_PAYLOAD_LENGTH(pContextSSH) = 0;
    INBOUND_BYTES_TO_READ(pContextSSH)  = 0;

    return OK;
}


/*------------------------------------------------------------------*/

static MSTATUS
receiveFirstBlock(sshClientContext *pContextSSH, ubyte **ppPacketPayload, ubyte4 *pPacketLength)
{
    MSTATUS status = OK;
    ubyte4  bytesRead;

    /* determine number of bytes we can digest */
    if ((*pPacketLength) > (INBOUND_CIPHER_SIZE(pContextSSH) - INBOUND_BYTES_READ(pContextSSH)))
        bytesRead = INBOUND_CIPHER_SIZE(pContextSSH) - INBOUND_BYTES_READ(pContextSSH);
    else
        bytesRead = *pPacketLength;

    /* copy digested bytes from packet to buffer, update indices and counters */
    if (bytesRead)
    {
        /* Following check is very important, without this check fabricated input string may cause
         * heap overflow and in turn possibly remote code execution
         */
        if ( ( SSHC_MAX_BUFFER_SIZE - INBOUND_BYTES_READ(pContextSSH) ) < bytesRead )
        {
            status = ERR_SSH_CIRCULAR_BUFFER_OVERFLOW;
            goto exit;
        }

        MOC_MEMCPY(INBOUND_BUFFER(pContextSSH) + INBOUND_BYTES_READ(pContextSSH),
               *ppPacketPayload, bytesRead);

        INBOUND_BYTES_READ(pContextSSH) += bytesRead;

        if ((ubyte4)INBOUND_CIPHER_SIZE(pContextSSH) == INBOUND_BYTES_READ(pContextSSH))
        {
            INBOUND_STATE(pContextSSH)      = kDecryptFirstBlock;
            INBOUND_BYTES_READ(pContextSSH) = 0;
        }

        /* digest bytes from packet */
        *ppPacketPayload += bytesRead;
        *pPacketLength   -= bytesRead;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_CHACHA20__) && defined(__ENABLE_MOCANA_POLY1305__))
#ifdef __ENABLE_MOCANA_SSH_WEAK_CIPHERS__
static MSTATUS
getPacketLength(sshClientContext *pContextSSH, ubyte *pPacketLength)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte pSequenceNumIn[8];

    if ( (NULL == pContextSSH) || (NULL == INBOUND_CIPHER_SUITE_INFO(pContextSSH)) ||
        (NULL == INBOUND_CIPHER_ALGORITHM(pContextSSH)) ||
        (NULL == INBOUND_CIPHER_CONTEXT2(pContextSSH)) )
    {
        goto exit;
    }

    /* convert ubyte8 to an array */
    status = UTILS_ubyte8ToArray((ubyte8)INBOUND_SEQUENCE_NUM(pContextSSH), pSequenceNumIn);
    if (OK != status)
        goto exit;

    /* If context is chacha/poly, we have to decrypt packetLength bytes */
    if (NULL != INBOUND_CIPHER_ALGORITHM(pContextSSH))
    {
        status = (INBOUND_CIPHER_ALGORITHM(pContextSSH))(MOC_SYM(pContextSSH->hwAccelCookie) INBOUND_CIPHER_CONTEXT2(pContextSSH), pPacketLength, 4, 0, pSequenceNumIn);
        if (OK != status)
            goto exit;
    }

exit:
    return status;
}
#endif
#endif /* (defined(__ENABLE_MOCANA_CHACHA20__) && defined(__ENABLE_MOCANA_POLY1305__)) */

/*------------------------------------------------------------------*/

static MSTATUS
decryptFirstBlock(sshClientContext *pContextSSH)
{
    sshAeadAlgo*    pAeadSuite;
    MSTATUS         status = OK;
#if (defined(__ENABLE_MOCANA_CHACHA20__) && defined(__ENABLE_MOCANA_POLY1305__))
#ifdef __ENABLE_MOCANA_SSH_WEAK_CIPHERS__
    ubyte           pPacketLength[4];
#endif
#endif

    if (NULL != INBOUND_CIPHER_ALGORITHM(pContextSSH))
    {
        /* see if we are using chacha20 with poly1305 cipher suite */
#if (defined(__ENABLE_MOCANA_CHACHA20__) && defined(__ENABLE_MOCANA_POLY1305__))
#ifdef __ENABLE_MOCANA_SSH_WEAK_CIPHERS__
        if (CHACHA20_POLY1305_OPENSSH == INBOUND_CIPHER_TYPE(pContextSSH))
        {
            status = MOC_MEMCPY(pPacketLength, INBOUND_BUFFER(pContextSSH), 4);
            if (OK != status)
            {
                goto exit;
            }

            status = getPacketLength(pContextSSH, pPacketLength);
            if (OK != status)
            {
                goto exit;
            }

            status = UTILS_arrayToUbyte4(pPacketLength, &(INBOUND_PACKET_LENGTH(pContextSSH)));
            if (OK != status)
                goto exit;
        }
        else
#endif
#endif /* (defined(__ENABLE_MOCANA_CHACHA20__) && defined(__ENABLE_MOCANA_POLY1305__)) */
        {
            status = (INBOUND_CIPHER_ALGORITHM(pContextSSH))(MOC_SYM(pContextSSH->hwAccelCookie) INBOUND_CIPHER_CONTEXT(pContextSSH),
                                                             INBOUND_BUFFER(pContextSSH),
                                                             INBOUND_CIPHER_SIZE(pContextSSH),
                                                             0, INBOUND_CIPHER_IV(pContextSSH));

            if (OK > status)
                goto exit;
        }
    }

    /* translate packet length from network byte order */
#if (defined(__ENABLE_MOCANA_CHACHA20__) && defined(__ENABLE_MOCANA_POLY1305__))
#ifdef __ENABLE_MOCANA_SSH_WEAK_CIPHERS__
    if (CHACHA20_POLY1305_OPENSSH != INBOUND_CIPHER_TYPE(pContextSSH))
#endif
#endif
    {
        status = UTILS_arrayToUbyte4(INBOUND_BUFFER(pContextSSH), &(INBOUND_PACKET_LENGTH(pContextSSH)));
        if (OK != status)
            goto exit;
    }

    /* Check if we have more than ZERO bytes */
    if (0 >= INBOUND_PACKET_LENGTH(pContextSSH))
    {
        status = ERR_PAYLOAD_EMPTY;
        goto exit;
    }

    if (NULL == (pAeadSuite = pContextSSH->pDecryptSuiteInfoIn->pAeadSuiteInfo))
    {
        /* retrieve pad length */
        INBOUND_PADDING_LENGTH(pContextSSH) = (((INBOUND_BUFFER(pContextSSH))[4]) & 0xff);

        /* store payload length */
        INBOUND_PAYLOAD_LENGTH(pContextSSH) = (INBOUND_PACKET_LENGTH(pContextSSH)-1)-INBOUND_PADDING_LENGTH(pContextSSH);

        if ((INBOUND_PACKET_LENGTH(pContextSSH)-1) < INBOUND_PADDING_LENGTH(pContextSSH))
        {
            status = ERR_PAYLOAD_EMPTY;
            goto exit;
        }

        /* calculate bytes to read */
        INBOUND_BYTES_TO_READ(pContextSSH)  = (INBOUND_PACKET_LENGTH(pContextSSH) + sizeof(ubyte4))
                                              - INBOUND_CIPHER_SIZE(pContextSSH);

        if ( (INBOUND_PACKET_LENGTH(pContextSSH) + sizeof(ubyte4)) < INBOUND_CIPHER_SIZE(pContextSSH) )
        {
            status = ERR_PAYLOAD_EMPTY;
            goto exit;
        }

        /* go to next state */
        if (0 < INBOUND_BYTES_TO_READ(pContextSSH))
            INBOUND_STATE(pContextSSH)      = kReceiveBlocks;
        else
            INBOUND_STATE(pContextSSH)      = kReceiveMAC;
    }
    else
    {
        /* calculate bytes to read */
        INBOUND_BYTES_TO_READ(pContextSSH) = (4 + INBOUND_PACKET_LENGTH(pContextSSH) + pAeadSuite->authenticationTagLength - INBOUND_CIPHER_SIZE(pContextSSH));

        /* go to next state */
        INBOUND_STATE(pContextSSH) = kReceiveBlocks;
    }

    if (INBOUND_PACKET_LENGTH(pContextSSH) > INBOUND_MAX_MESSAGE_SIZE(pContextSSH)) /*!!!! add growing buffer support here */
    {
        status = ERR_PAYLOAD_TOO_LARGE;
        goto exit;
    }

    u8_Incr32(&pContextSSH->bytesTransmitted, INBOUND_PACKET_LENGTH(pContextSSH));

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
receiveBlocks(sshClientContext *pContextSSH, ubyte **ppPacketPayload, ubyte4 *pPacketLength)
{
    MSTATUS status = OK;
    ubyte4  bytesRead;

    /* determine number of bytes we can digest */
    if ((*pPacketLength) > INBOUND_BYTES_TO_READ(pContextSSH) - INBOUND_BYTES_READ(pContextSSH))
        bytesRead = INBOUND_BYTES_TO_READ(pContextSSH) - INBOUND_BYTES_READ(pContextSSH);
    else
        bytesRead = *pPacketLength;

    /* copy digested bytes from packet to buffer, update indices and counters */
    if (bytesRead)
    {
        /* Following check is very important, without this check fabricated input string may cause
         * heap overflow and in turn possibly remote code execution
         */
        if ( ( SSHC_MAX_BUFFER_SIZE - INBOUND_CIPHER_SIZE(pContextSSH) - INBOUND_BYTES_READ(pContextSSH) ) < bytesRead )
        {
            status = ERR_SSH_CIRCULAR_BUFFER_OVERFLOW;
            goto exit;
        }

        MOC_MEMCPY(INBOUND_BUFFER(pContextSSH) + INBOUND_CIPHER_SIZE(pContextSSH) + INBOUND_BYTES_READ(pContextSSH),
               *ppPacketPayload, bytesRead);

        INBOUND_BYTES_READ(pContextSSH) += bytesRead;

        if (INBOUND_BYTES_TO_READ(pContextSSH) == INBOUND_BYTES_READ(pContextSSH))
        {
            if (NULL == pContextSSH->pDecryptSuiteInfoIn->pAeadSuiteInfo)
                INBOUND_STATE(pContextSSH) = kDecryptBlocks;
            else
                INBOUND_STATE(pContextSSH) = kDecryptAeadBlocks;
        }

        /* digest bytes from packet */
        *ppPacketPayload += bytesRead;
        *pPacketLength   -= bytesRead;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_CHACHA20__) && defined(__ENABLE_MOCANA_POLY1305__))
#ifdef __ENABLE_MOCANA_SSH_WEAK_CIPHERS__
static MSTATUS
decryptAeadBlocksEx(sshClientContext *pContextSSH)
{
    sshAeadAlgo*    pAeadSuite;
    ubyte4          length;
    MSTATUS         status = ERR_NULL_POINTER;
    ubyte           pSequenceNumIn[8];

    pAeadSuite = INBOUND_CIPHER_SUITE_INFO (pContextSSH)->pAeadSuiteInfo;

    if (NULL == pAeadSuite)
    {
        goto exit;
    }

    status = UTILS_ubyte8ToArray(INBOUND_SEQUENCE_NUM(pContextSSH), pSequenceNumIn);
    if (OK != status)
        goto exit;

    status = pAeadSuite->funcCipher(MOC_SYM(pContextSSH->hwAccelCookie) INBOUND_CIPHER_CONTEXT(pContextSSH),
                                    pSequenceNumIn, 8 /* sequence number as uint64 */,
                                    NULL, 0,
                                    INBOUND_BUFFER(pContextSSH), 4 + INBOUND_PACKET_LENGTH(pContextSSH),
                                    pAeadSuite->authenticationTagLength, FALSE);
    if (OK != status)
        goto exit;

    INBOUND_PADDING_LENGTH(pContextSSH) = (((INBOUND_BUFFER(pContextSSH))[4]) & 0xff);

    if (INBOUND_PACKET_LENGTH(pContextSSH) <= 1)
        status = ERR_PAYLOAD_EMPTY;

    length = INBOUND_PACKET_LENGTH(pContextSSH) - 1;

    if (length <= INBOUND_PADDING_LENGTH(pContextSSH))
        status = ERR_PAYLOAD_EMPTY;

    INBOUND_PAYLOAD_LENGTH(pContextSSH) = length - INBOUND_PADDING_LENGTH(pContextSSH);

    INBOUND_STATE(pContextSSH) = kProcessMessage;
    
exit:
    INBOUND_INC_SEQUENCE_NUM(pContextSSH);
    return status;
}
#endif
#endif /* (defined(__ENABLE_MOCANA_CHACHA20__) && defined(__ENABLE_MOCANA_POLY1305__)) */

/*------------------------------------------------------------------*/

static MSTATUS
decryptAeadBlocks(sshClientContext *pContextSSH)
{
    sshAeadAlgo*    pAeadSuite;
    sbyte4          index;
    ubyte4          length;
    MSTATUS         status;

    pAeadSuite = INBOUND_CIPHER_SUITE_INFO (pContextSSH)->pAeadSuiteInfo;
	if ( !pAeadSuite )  return ( ERR_NULL_POINTER );

    status = pAeadSuite->funcCipher(MOC_SYM(pContextSSH->hwAccelCookie) INBOUND_CIPHER_CONTEXT(pContextSSH),
                                    INBOUND_CIPHER_IV(pContextSSH), pAeadSuite->nonceFixedLength + pAeadSuite->nonceInvocationCounter,
                                    INBOUND_BUFFER(pContextSSH), 4 /* message length*/,
                                    (4 + INBOUND_BUFFER(pContextSSH)), INBOUND_BYTES_TO_READ(pContextSSH) - 4,
                                    pAeadSuite->authenticationTagLength, FALSE);

    if (OK <= status)
    {
        /* retrieve pad length */
        INBOUND_PADDING_LENGTH(pContextSSH) = (((INBOUND_BUFFER(pContextSSH))[4]) & 0xff);

        /* we need to do the checks to ensure decrypted data is properly formed */
        if (INBOUND_PACKET_LENGTH(pContextSSH) <= 1)
            status = ERR_PAYLOAD_EMPTY;

        length = INBOUND_PACKET_LENGTH(pContextSSH) - 1;

        if (length <= INBOUND_PADDING_LENGTH(pContextSSH))
            status = ERR_PAYLOAD_EMPTY;

        /* store payload length */
        INBOUND_PAYLOAD_LENGTH(pContextSSH) = length - INBOUND_PADDING_LENGTH(pContextSSH);
    }

    if (OK <= status)
    {
        /* go to next state */
        INBOUND_STATE(pContextSSH) = kProcessMessage;
    }

    index = pAeadSuite->nonceInvocationCounter - 1;

    /* increment invocation counter for next message */
    while ((0 == (++(*(INBOUND_CIPHER_IV(pContextSSH) + pAeadSuite->nonceFixedLength + index)))) && (index > 0))
        index--;

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
decryptBlocks(sshClientContext *pContextSSH)
{
    MSTATUS status = OK;

    if (NULL != INBOUND_CIPHER_ALGORITHM(pContextSSH))
    {
        status = (INBOUND_CIPHER_ALGORITHM(pContextSSH))(MOC_SYM(pContextSSH->hwAccelCookie) INBOUND_CIPHER_CONTEXT(pContextSSH),
                                                         INBOUND_BUFFER(pContextSSH) + INBOUND_CIPHER_SIZE(pContextSSH),
                                                         INBOUND_BYTES_TO_READ(pContextSSH),
                                                         0, INBOUND_CIPHER_IV(pContextSSH));
    }

    if (OK <= status)
    {
        /* go to next state */
        INBOUND_STATE(pContextSSH)      = kReceiveMAC;
        INBOUND_BYTES_READ(pContextSSH) = 0;
    }

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
receiveMAC(sshClientContext *pContextSSH, ubyte **ppPacketPayload, ubyte4 *pPacketLength)
{
    ubyte4  bytesRead = 0;
    ubyte*  sequenceBuf = NULL;
    ubyte*  tempMac = NULL;
    MSTATUS status = OK;

    if (OK > (status = MEM_POOL_getPoolObject(&pContextSSH->mediumPool, (void **)&(tempMac))))
        goto exit;

    if ((NULL == INBOUND_MAC_ALGORITHM(pContextSSH)) && (NULL == pContextSSH->pDecryptSuiteInfoIn->pAeadSuiteInfo))
    {
        /* mac is none */
        INBOUND_STATE(pContextSSH) = kProcessMessage;
        INBOUND_INC_SEQUENCE_NUM(pContextSSH);
        status = OK;

        goto exit;
    }

    /* determine number of bytes we can digest */
    if ((*pPacketLength) > INBOUND_MAC_SIZE(pContextSSH) - INBOUND_BYTES_READ(pContextSSH))
        bytesRead = INBOUND_MAC_SIZE(pContextSSH) - INBOUND_BYTES_READ(pContextSSH);
    else
        bytesRead = *pPacketLength;

    /* copy digested bytes from packet to buffer, update indices and counters */
    if (bytesRead)
    {
        MOC_MEMCPY(INBOUND_MAC_BUFFER(pContextSSH) + INBOUND_BYTES_READ(pContextSSH),
               *ppPacketPayload, bytesRead);

        INBOUND_BYTES_READ(pContextSSH) += bytesRead;

        if ((ubyte4)INBOUND_MAC_SIZE(pContextSSH) == INBOUND_BYTES_READ(pContextSSH))
        {
            if (NULL == pContextSSH->pDecryptSuiteInfoIn->pAeadSuiteInfo)
            {
                ubyte4  sequenceNum = INBOUND_SEQUENCE_NUM(pContextSSH);

                if (OK > (status = MEM_POOL_getPoolObject(&pContextSSH->smallPool, (void **)&(sequenceBuf))))
                    goto exit;

                sequenceBuf[0] = (ubyte)(sequenceNum >> 24);
                sequenceBuf[1] = (ubyte)(sequenceNum >> 16);
                sequenceBuf[2] = (ubyte)(sequenceNum >>  8);
                sequenceBuf[3] = (ubyte)(sequenceNum);

                status = (INBOUND_MAC_ALGORITHM(pContextSSH))
                           (MOC_HASH(pContextSSH->hwAccelCookie) INBOUND_KEY_DATA(pContextSSH), INBOUND_KEY_DATA_LEN(pContextSSH),
                            sequenceBuf, 4,
                            INBOUND_BUFFER(pContextSSH), INBOUND_PACKET_LENGTH(pContextSSH) + sizeof(ubyte4),
                            tempMac);
            }

            if (OK <= status)
            {
                intBoolean result;

                /* verify the MAC sent is correct */
                if (OK == (status = MOC_CTIME_MATCH(tempMac, INBOUND_MAC_BUFFER(pContextSSH),
                                                    INBOUND_MAC_SIZE(pContextSSH), &result)))
                {
                    if (0 != result)
                    {
                        status = ERR_SSH_TRANSPORT_BAD_MAC;
                        goto exit;
                    }
                }
            }

            INBOUND_STATE(pContextSSH) = kProcessMessage;
            INBOUND_INC_SEQUENCE_NUM(pContextSSH);
        }
    }

exit:
    /* digest bytes from packet */
    *ppPacketPayload += bytesRead;
    *pPacketLength   -= bytesRead;

    if (NULL != sequenceBuf)
    {
        MEM_POOL_putPoolObject(&pContextSSH->smallPool, (void **)(&sequenceBuf));
    }

    if (NULL != tempMac)
    {
        MEM_POOL_putPoolObject(&pContextSSH->mediumPool, (void **)(&tempMac));
    }

    return status;

} /* receiveMAC */


/*------------------------------------------------------------------*/

static MSTATUS
receiveVersionStringCommon(sshClientContext *pContextSSH, ubyte **ppPacketPayload, ubyte4 *pPacketLength, intBoolean *boolCompleteHello)
{
    ubyte4      bytesRead = 0;
    sbyte4      cmpResult;
    MSTATUS     status = OK;

    *boolCompleteHello = FALSE;
    /* determine number of bytes we can digest */
    while ((FALSE == *boolCompleteHello) && (0 < ((*pPacketLength) - bytesRead)))
    {
        if (LF == *(bytesRead + *ppPacketPayload))
        {
            *boolCompleteHello = TRUE;
        }

        if (MAX_SSH_VERSION_STRING < (INBOUND_BYTES_READ(pContextSSH) + bytesRead))
        {
            status = ERR_SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED;
            goto exit;
        }

        bytesRead++;
    }

    /* copy digested bytes from packet to buffer, update indices and counters */
    if (bytesRead)
    {
        /* Following check is very important, without this check fabricated input string may cause
         * heap overflow and in turn possibly remote code execution
         */
        if ( ( SSHC_MAX_BUFFER_SIZE - INBOUND_BYTES_READ(pContextSSH) ) < bytesRead )
        {
            status = ERR_SSH_CIRCULAR_BUFFER_OVERFLOW;
            goto exit;
        }

        MOC_MEMCPY(INBOUND_BUFFER(pContextSSH) + INBOUND_BYTES_READ(pContextSSH),
               *ppPacketPayload, bytesRead);

        INBOUND_BYTES_READ(pContextSSH) += bytesRead;

        /* digest bytes from packet */
        *ppPacketPayload += bytesRead;
        *pPacketLength   -= bytesRead;
    }

    if (TRUE == *boolCompleteHello)
    {
#ifdef __ENABLE_ALL_DEBUGGING__
        DEBUG_PRINTNL(DEBUG_SSHC, (sbyte *)"\nreceiveVersionStringCommon:");
        DEBUG_HEXDUMP(DEBUG_SSHC, INBOUND_BUFFER(pContextSSH), bytesRead);
#endif

        if ((sizeof(EXPECTED_SSH_VERSION_STRING) - 1) > INBOUND_BYTES_READ(pContextSSH))
        {
            status = ERR_SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED;
            goto exit;
        }

        /* check version string "SSH-2." */
        if (OK > (status = MOC_MEMCMP(INBOUND_BUFFER(pContextSSH), (ubyte *)EXPECTED_SSH_VERSION_STRING, sizeof(EXPECTED_SSH_VERSION_STRING) - 1, &cmpResult)))
            goto exit;

        if (0 != cmpResult)
        {
            if ((sizeof(EXPECTED_SSH_VERSION_STRING1) - 1) > INBOUND_BYTES_READ(pContextSSH))
            {
                status = ERR_SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED;
                goto exit;
            }

            /* Look for "SSH-1.99" == 8 bytes */
            if (OK > (status = MOC_MEMCMP(INBOUND_BUFFER(pContextSSH), (ubyte *)EXPECTED_SSH_VERSION_STRING1, sizeof(EXPECTED_SSH_VERSION_STRING1) - 1, &cmpResult)))
                goto exit;

            if (0 != cmpResult)
            {
                status = ERR_SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED;
                goto exit;
            }
        }
    }

exit:
    return status;
} /* receiveVersionStringCommon */


/*------------------------------------------------------------------*/

static MSTATUS
clientSaveRxdVersionString(sshClientContext *pContextSSH)
{
    MSTATUS     status = OK;

    if (OK > (status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, INBOUND_BYTES_READ(pContextSSH), TRUE, &(SERVER_HELLO_COMMENT(pContextSSH)))))
        goto exit;

    SERVER_HELLO_COMMENT_LEN(pContextSSH) = 0;

    /* copy out client hello string */
    while ((MOC_CR != (INBOUND_BUFFER(pContextSSH))[SERVER_HELLO_COMMENT_LEN(pContextSSH)]) &&
           (LF != (INBOUND_BUFFER(pContextSSH))[SERVER_HELLO_COMMENT_LEN(pContextSSH)]))
    {
        (SERVER_HELLO_COMMENT(pContextSSH))[SERVER_HELLO_COMMENT_LEN(pContextSSH)] =
            (INBOUND_BUFFER(pContextSSH))[SERVER_HELLO_COMMENT_LEN(pContextSSH)];

        SERVER_HELLO_COMMENT_LEN(pContextSSH)++;
    }

exit:
    return status;
} /* clientSaveRxdVersionString */


/*------------------------------------------------------------------*/

static MSTATUS
clientReceiveVersionString(sshClientContext *pContextSSH, ubyte **ppPacketPayload, ubyte4 *pPacketLength)
{
    MSTATUS status  = OK;
    intBoolean completeHello;

    if (OK > (status = receiveVersionStringCommon(pContextSSH, ppPacketPayload, pPacketLength, &completeHello)))
        goto exit;

    if (!completeHello)     /*!!!! need to read more (it's coming through in multiple reads, which
                             * I guess means multiple TCP packets!) */
        goto exit;

    if (OK > (status = clientSaveRxdVersionString(pContextSSH)))
        goto exit;

    status = SSHC_TRANS_sendAlgorithms(pContextSSH);

exit:
    return status;
} /* clientReceiveVersionString */


/*------------------------------------------------------------------*/


extern MSTATUS
SSHC_IN_MESG_processMessage(sshClientContext *pContextSSH,
                           ubyte **ppPacketPayload, ubyte4 *pPacketLength)
{
    ubyte*  pNewMessage;
    ubyte4  newMessageLength;
    ubyte4  lastState;
    MSTATUS status;

    if ((NULL == pContextSSH)      || (NULL == ppPacketPayload) ||
        (NULL == *ppPacketPayload) || (NULL == pPacketLength))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == *pPacketLength)
    {
        /* nothing to do... */
        status = OK;
        goto exit;
    }

    do
    {
        lastState = INBOUND_STATE(pContextSSH);

#ifdef __DEBUG_DETAILED_SSHC_TRANSPORT__
        DEBUG_ERROR(DEBUG_SSHC_TRANSPORT, "SSH_IN_MESG_processMessage: lastState = ", lastState);
#endif

        switch (lastState)
        {
            case kReceiveInitHelloListen:
                status = receiveInitVersionString(pContextSSH);
                break;

            case kReceiveHelloListen:
                status = clientReceiveVersionString(pContextSSH, ppPacketPayload, pPacketLength);
                break;

            case kReceiveInit:
                status = receiveInit(pContextSSH);
                break;

            case kReceiveFirstBlock:
                status = receiveFirstBlock(pContextSSH, ppPacketPayload, pPacketLength);
                break;

            case kDecryptFirstBlock:
                status = decryptFirstBlock(pContextSSH);
                break;

            case kReceiveBlocks:
                status = receiveBlocks(pContextSSH, ppPacketPayload, pPacketLength);
                break;

            case kDecryptAeadBlocks:
#if (defined(__ENABLE_MOCANA_CHACHA20__) && defined(__ENABLE_MOCANA_POLY1305__))
#ifdef __ENABLE_MOCANA_SSH_WEAK_CIPHERS__
                if (CHACHA20_POLY1305_OPENSSH == INBOUND_CIPHER_TYPE(pContextSSH))
                {
                    status = decryptAeadBlocksEx(pContextSSH);
                }
                else
#endif
#endif /* (defined(__ENABLE_MOCANA_CHACHA20__) && defined(__ENABLE_MOCANA_POLY1305__)) */
                {
                    status = decryptAeadBlocks(pContextSSH);
                }
                break;

            case kDecryptBlocks:
                status = decryptBlocks(pContextSSH);
                break;

            case kReceiveMAC:
                status = receiveMAC(pContextSSH, ppPacketPayload, pPacketLength);
                break;

            case kProcessMessage:
                if (OK > (status = SSHC_IN_MESG_resetInboundState(pContextSSH)))
                    break;

                pNewMessage      = INBOUND_BUFFER(pContextSSH) + SSH_SIZEOF_MESSAGE_HEADER;
                newMessageLength = INBOUND_PAYLOAD_LENGTH(pContextSSH);

#ifdef __ENABLE_ALL_DEBUGGING__
                /*if (kSftpOpenState != SSH_SESSION_STATE(pContextSSH))*/
                    DUMP_MESG_sshMessage(pNewMessage, newMessageLength, FALSE, pContextSSH->authContext.authMethod);
#endif

                /* do upper layer upcall */
                status = SSHC_TRANS_doProtocol(pContextSSH, pNewMessage, newMessageLength);
                break;

            default:
                status = ERR_SSH_BAD_RECEIVE_STATE;
                break;
        }
    }
    while ((OK <= status) && (lastState != INBOUND_STATE(pContextSSH)) &&
           (kReceiveInit != INBOUND_STATE(pContextSSH)));

#ifdef __DEBUG_DETAILED_SSHC_TRANSPORT__
    DEBUG_ERROR(DEBUG_SSHC_TRANSPORT, "SSH_IN_MESG_processMessage: INBOUND_STATE(pContextSSH) = ", INBOUND_STATE(pContextSSH));
#endif

exit:
    return status;

} /* SSHC_IN_MESG_processMessage */

/*------------------------------------------------------------------*/

extern MSTATUS
SSHC_IN_MESG_allocStructures(sshClientContext *pContextSSH)
{
    MSTATUS status = OK;

    if (NULL == pContextSSH)
        status = ERR_NULL_POINTER;
    else if ( OK > (status = CRYPTO_ALLOC ( pContextSSH->hwAccelCookie, INBOUND_BUFFER_SIZE(pContextSSH) , TRUE, &(INBOUND_BUFFER(pContextSSH)) ) ) )
        goto exit;
    else
    {
        INBOUND_STATE(pContextSSH) = kReceiveInitHelloListen;
    }

exit:
    return status;
} /* SSHC_IN_MESG_allocStructures */


/*------------------------------------------------------------------*/

extern MSTATUS
SSHC_IN_MESG_deallocStructures(sshClientContext *pContextSSH)
{
    MSTATUS status = OK;

    if ((NULL == pContextSSH) || (NULL == INBOUND_BUFFER(pContextSSH)))
        status = ERR_NULL_POINTER;
    else
    {
        CRYPTO_FREE ( pContextSSH->hwAccelCookie, TRUE, &(INBOUND_BUFFER(pContextSSH)));
        INBOUND_BUFFER(pContextSSH) = NULL;
    }

    return status;
}

#endif /* __ENABLE_MOCANA_SSH_CLIENT__ */

