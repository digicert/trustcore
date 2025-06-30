/*
 * sshc_out_mesg.h
 *
 * SSHC Outbound Message Handler
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


/*------------------------------------------------------------------*/

#ifndef __SSHC_OUT_MESG_HEADER__
#define __SSHC_OUT_MESG_HEADER__

#ifdef    __ENABLE_OUTBOUND_SSH_DEFINITIONS__
#define OUTBOUND_BUFFER(X)              (X)->pTransmitBuffer
#define OUTBOUND_BUFFER_SIZE(X)         (X)->maxBufferSizeOut
#define OUTBOUND_INC_SEQUENCE_NUM(X)    ((X)->sequenceNumOut)++
#define OUTBOUND_MAX_MESSAGE_SIZE(X)    (X)->maxMessageSizeOut

#endif /* __ENABLE_OUTBOUND_SSH_DEFINITIONS__ */

#define OUTBOUND_MAC_INFO(X)            (X)->pHmacSuiteInfoOut
#define OUTBOUND_MAC_SIZE(X)            (ubyte4)((X)->pHmacSuiteInfoOut->hmacDigestLength)
#define OUTBOUND_MAC_ALGORITHM(X)       (X)->pHmacSuiteInfoOut->hmacFunc

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
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSHC_OUT_MESG_allocStructures(sshClientContext *pContextSSH);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSHC_OUT_MESG_deallocStructures(sshClientContext *pContextSSH);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSHC_OUT_MESG_sendMessage(sshClientContext *pContextSSH, ubyte *pPayload,
                                        ubyte4 payloadLength, ubyte4 *pRetPayloadTransferred);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSHC_OUT_MESG_sendMessageSize(sshClientContext *pContextSSH, ubyte4 payloadLength, ubyte4 *pRetPayloadMax);

#endif /* __SSHC_OUT_MESG_HEADER__ */
