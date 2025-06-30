/*
 * ssh_out_mesg.h
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


/*------------------------------------------------------------------*/

#ifndef __SSH_OUT_MESG_HEADER__
#define __SSH_OUT_MESG_HEADER__

#ifdef    __ENABLE_OUTBOUND_SSH_DEFINITIONS__
#define OUTBOUND_BUFFER(X)              (X)->pTransmitBuffer
#define OUTBOUND_BUFFER_SIZE(X)         (X)->maxBufferSizeOut
#define OUTBOUND_INC_SEQUENCE_NUM(X)    ((X)->sequenceNumOut)++
#define OUTBOUND_MAX_MESSAGE_SIZE(X)    (X)->maxMessageSizeOut

#endif /* __ENABLE_OUTBOUND_SSH_DEFINITIONS__ */

#define OUTBOUND_MAC_INFO(X)            (X)->pHmacSuiteInfoOut
#define OUTBOUND_MAC_SIZE(X)            (ubyte4)((X)->pHmacSuiteInfoOut->hmacDigestLength)
#define OUTBOUND_MAC_ALGORITHM(X)       (X)->pHmacSuiteInfoOut->hmacFunc
#define OUTBOUND_MAC_NAME(X)            (X)->pHmacSuiteInfoOut->pHmacName
#define OUTBOUND_MAC_IS_ETM(X)          (X)->pHmacSuiteInfoOut->isEtm

#define OUTBOUND_CIPHER_SUITE_INFO(X)   (X)->pEncryptSuiteInfoOut
#define OUTBOUND_CIPHER_SUITE(X)        (ubyte4)((X)->pEncryptSuiteInfoOut->pBEAlgo)
#define OUTBOUND_CIPHER_SIZE(X)         (ubyte4)((X)->pEncryptSuiteInfoOut->ivSize)
#define OUTBOUND_CIPHER_CREATE(X)       (X)->pEncryptSuiteInfoOut->pBEAlgo->createFunc
#define OUTBOUND_CIPHER_ALGORITHM(X)    (X)->pEncryptSuiteInfoOut->pBEAlgo->cipherFunc
#define OUTBOUND_CIPHER_TYPE(X)         ((X)->cryptTypeOut)
#define OUTBOUND_CIPHER_CONTEXT(X)      ((X)->cryptDescrOut)
#define OUTBOUND_CIPHER_CONTEXT2(X)     ((X)->cryptDescrOut2)
#define OUTBOUND_CIPHER_CONTEXT_FREE(X) (X)->pEncryptSuiteInfoOut->pBEAlgo->deleteFunc
#define OUTBOUND_CIPHER_IV(X)           (X)->encryptIV

#define OUTBOUND_KEY_DATA(X)            (X)->pIntegrityKeyOut
#define OUTBOUND_KEY_DATA_LEN(X)        (X)->integrityKeyLengthOut


/*------------------------------------------------------------------*/

/**
 * @brief Allocates outbound SSH message processing structures.
 *
 * @details Allocates the buffer required for outbound SSH message handling.
 *          Returns an error if allocation fails or if the context pointer is NULL.
 *
 * @param pContextSSH Pointer to the SSH context.
 * 
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h. To retrieve a string containing an
 *          English text error identifier corresponding to the function's
 *          returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_OUT_MESG_allocStructures(sshContext *pContextSSH);

/**
 * @brief Frees outbound SSH message processing structures.
 *
 * @details Frees the buffer used for outbound SSH message handling and sets the
 *          buffer pointer to NULL. Returns an error if the context or buffer pointer is NULL.
 *
 * @param pContextSSH Pointer to the SSH context.
 * 
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h. To retrieve a string containing an
 *          English text error identifier corresponding to the function's
 *          returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_OUT_MESG_deallocStructures(sshContext *pContextSSH);

/**
 * @brief Constructs and sends an outbound SSH message.
 *
 * @details Formats the SSH packet with appropriate padding, computes and appends the MAC,
 *          encrypts the message as required, and writes the final message to the outbound buffer.
 *          Handles sequence number increment and updates bytes transmitted.
 *
 * @param pContextSSH               Pointer to the SSH context.
 * @param pPayload                  Pointer to the payload to send.
 * @param payloadLength             Length of the payload in bytes.
 * @param pRetPayloadTransferred    Output: actual number of payload bytes sent.
 *
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h. To retrieve a string containing an
 *          English text error identifier corresponding to the function's
 *          returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_OUT_MESG_sendMessage(sshContext *pContextSSH, ubyte *pPayload,
                                        ubyte4 payloadLength, ubyte4 *pRetPayloadTransferred);

/**
 * @brief Calculates the maximum payload size for an outbound SSH message.
 *
 * @details Calculates the maximum payload size that can be sent in an outbound SSH message.
 *
 * @param pContextSSH      Pointer to the SSH context.
 * @param payloadLength    Payload length in bytes.
 * @param pRetPayloadMax   Output: maximum payload bytes that can be sent.
 *
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h. To retrieve a string containing an
 *          English text error identifier corresponding to the function's
 *          returned error status, use the \c DISPLAY_ERROR macro.
 */                                      
MOC_EXTERN MSTATUS SSH_OUT_MESG_sendMessageSize(sshContext *pContextSSH, ubyte4 payloadLength, ubyte4 *pRetPayloadMax);

#endif /* __SSH_OUT_MESG_HEADER__ */
