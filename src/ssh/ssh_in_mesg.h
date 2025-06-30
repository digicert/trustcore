/*
 * ssh_in_mesg.h
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
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */


/*------------------------------------------------------------------*/

#ifndef __SSH_IN_MESG_HEADER__
#define __SSH_IN_MESG_HEADER__

#define kReceiveInitClientHelloListen   0
#define kReceiveClientHelloListen       1
#define kReceiveInit                    2
#define kReceiveFirstBlock              3
#define kDecryptFirstBlock              4
#define kReceiveBlocks                  5
#define kDecryptAeadBlocks              6
#define kDecryptBlocks                  7
#define kReceiveMAC                     8
#define kProcessMessage                 9


/*------------------------------------------------------------------*/

#ifdef    __ENABLE_INBOUND_SSH_DEFINITIONS__
#define INBOUND_BUFFER(X)               (X)->pReceiveBuffer
#define INBOUND_BUFFER_SIZE(X)          (X)->maxBufferSizeIn
#define INBOUND_BYTES_READ(X)           (X)->bytesRead
#define INBOUND_BYTES_TO_READ(X)        (X)->bytesToRead
#define INBOUND_PACKET_LENGTH(X)        (X)->packetLengthIn
#define INBOUND_PADDING_LENGTH(X)       (X)->paddingLengthIn
#define INBOUND_PAYLOAD_LENGTH(X)       (X)->payloadLengthIn
#define INBOUND_MAX_MESSAGE_SIZE(X)     (X)->maxMessageSizeIn
#define INBOUND_INC_SEQUENCE_NUM(X)     ((X)->sequenceNumIn)++

#endif /* __ENABLE_INBOUND_SSH_DEFINITIONS__ */

#define INBOUND_STATE(X)                (X)->receiveState
#define INBOUND_MAC_INFO(X)             (X)->pHmacSuiteInfoIn

#define INBOUND_MAC_SIZE(X)             (ubyte4)((X)->pHmacSuiteInfoIn->hmacDigestLength)
#define INBOUND_MAC_BUFFER(X)           ((X)->macDescrIn.pMacBuffer)
#define INBOUND_MAC_ALGORITHM(X)        (X)->pHmacSuiteInfoIn->hmacFunc
#define INBOUND_MAC_NAME(X)             (X)->pHmacSuiteInfoIn->pHmacName
#define INBOUND_MAC_IS_ETM(X)           (X)->pHmacSuiteInfoIn->isEtm

#define INBOUND_CIPHER_SUITE_INFO(X)    (X)->pDecryptSuiteInfoIn
#define INBOUND_CIPHER_SUITE(X)         (ubyte4)((X)->pDecryptSuiteInfoIn->pBEAlgo)
#define INBOUND_CIPHER_SIZE(X)          (ubyte4)((X)->pDecryptSuiteInfoIn->ivSize)
#define INBOUND_CIPHER_CREATE(X)        (X)->pDecryptSuiteInfoIn->pBEAlgo->createFunc
#define INBOUND_CIPHER_ALGORITHM(X)     (X)->pDecryptSuiteInfoIn->pBEAlgo->cipherFunc
#define INBOUND_CIPHER_TYPE(X)          ((X)->cryptTypeIn)
#define INBOUND_CIPHER_CONTEXT(X)       ((X)->cryptDescrIn)
#define INBOUND_CIPHER_CONTEXT2(X)      ((X)->cryptDescrIn2)
#define INBOUND_CIPHER_CONTEXT_FREE(X)  (X)->pDecryptSuiteInfoIn->pBEAlgo->deleteFunc
#define INBOUND_CIPHER_IV(X)            (X)->decryptIV

#define INBOUND_KEY_DATA(X)             (X)->pIntegrityKeyIn
#define INBOUND_KEY_DATA_LEN(X)         (X)->integrityKeyLengthIn


/*------------------------------------------------------------------*/
/**
 * @brief Allocates inbound SSH message processing structures.
 *
 * @details Allocates the buffer required for inbound SSH message handling and
 *          initializes the inbound state. Returns an error if allocation fails
 *          or if the context pointer is NULL.
 *
 * @param pContextSSH Pointer to the SSH context.
 * 
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h. To retrieve a string containing an
 *          English text error identifier corresponding to the function's
 *          returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_IN_MESG_allocStructures(sshContext *pContextSSH);

/**
 * @brief Deallocates inbound SSH message processing structures.
 *
 * @details Frees the buffer used for inbound SSH message handling and sets the
 *          buffer pointer to NULL. Returns an error if the context or buffer pointer is NULL.
 * 
 * @param pContextSSH Pointer to the SSH context.
 * 
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h. To retrieve a string containing an
 *          English text error identifier corresponding to the function's
 *          returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_IN_MESG_deallocStructures(sshContext *pContextSSH);

/**
 * @brief Processes inbound SSH transport messages.
 *
 * @details This function implements the SSH inbound message state machine. It parses and processes
 *          incoming SSH packets, handling version negotiation, decryption, MAC verification,
 *          and advances the session state as each stage of the SSH packet is processed.
 *
 * @param pContextSSH         Pointer to the SSH context.
 * @param ppPacketPayload     Pointer to the pointer to the incoming packet payload buffer.
 *                            This pointer is advanced as bytes are consumed.
 * @param pPacketLength       Pointer to the length of the remaining packet payload.
 *                            This value is decremented as bytes are consumed from the payload.
 *
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *           definition from merrors.h. To retrieve a string containing an
 *           English text error identifier corresponding to the function's
 *           returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_IN_MESG_processMessage(sshContext *pContextSSH, ubyte **ppPacketPayload, ubyte4 *pPacketLength);

#endif /* __SSH_IN_MESG_HEADER__ */
