/*
 * sshc_trans.h
 *
 * SSH Developer API
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

#ifndef __SSHC_TRANS_HEADER__
#define __SSHC_TRANS_HEADER__

#define MAX_SSH_VERSION_STRING          255
#define MAX_CLIENT_VERSION_STRING       255

#define SSH_MAJOR_VERSION               2
#define SSH_MINOR_VERSION               0

#define SSH_IMPLEMENTATION              Mocana SSH

#define STR(X)                          #X
#define HELLO_STRING_FORM(x,y,z)        "SSH-" STR(x) "." STR(y) "-" STR(z)
#define CLIENT_HELLO_STRING             HELLO_STRING_FORM(SSH_MAJOR_VERSION,SSH_MINOR_VERSION,SSH_IMPLEMENTATION)

#define SSH_SIZEOF_MESSAGE_HEADER       5

enum sshAlgorithmIndex
{
    SSH_ALG_INDEX_KEX   = 0,
    SSH_ALG_INDEX_HOST_KEY,
    SSH_ALG_INDEX_ENCRYPT_C2S,
    SSH_ALG_INDEX_ENCRYPT_S2C,
    SSH_ALG_INDEX_MAC_C2S,
    SSH_ALG_INDEX_MAC_S2C,
    SSH_ALG_INDEX_COMPRESS_C2S,
    SSH_ALG_INDEX_COMPRESS_S2C,
    SSH_ALG_INDEX_LANG_C2S,
    SSH_ALG_INDEX_LANG_S2C
};


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSHC_TRANS_sendHello(sshClientContext *pContextSSH);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSHC_TRANS_sendClientAlgorithms(sshClientContext *pContextSSH);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSHC_TRANS_versionExchange(sshClientContext *pContextSSH);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSHC_TRANS_doProtocol(sshClientContext *pContextSSH, ubyte *pNewMesg, ubyte4 newMesgLen);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN void    SSHC_TRANS_sendDisconnectMesg(sshClientContext *pContextSSH, ubyte4 sshError);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSHC_TRANS_setMessageTimer(sshClientContext *pContextSSH, ubyte4 msTimeToExpire);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSHC_TRANS_sendAlgorithms(sshClientContext *pContextSSH);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSHC_TRANS_cipherVerify(ubyte *pCipher, intBoolean *pIsAvailable);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSHC_TRANS_hmacVerify(ubyte *pHmac, intBoolean *pIsAvailable);

typedef intBoolean (*SSHC_FuncPtrProtocolTest)(sshcConnectDescr *pDescr, void *cookie);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSHC_doProtocolCommon(sbyte4 connectionInstance, intBoolean useTimeout, ubyte4 timeout, SSHC_FuncPtrProtocolTest testFunc, void *cookie);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN sshcConnectDescr *SSHC_getConnectionFromInstance(sbyte4 connectionInstance);

#if (defined(__ENABLE_MOCANA_SSH_CLIENT__) && defined(__ENABLE_MOCANA_SSH_X509V3_RFC_6187_SUPPORT__))
/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_CERT_buildClientCertRSA(sshClientContext *pContextSSH,SizedBuffer *pCertificates, ubyte4 numCertificates, ubyte **ppRetHostBlob, ubyte4 *pRetHostBlobLen);
#if (defined(__ENABLE_MOCANA_ECC__))
/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_TRANS_buildRawEcdsaCert(sshClientContext *pContextSSH, ubyte *pCertificate, ubyte4 certificateLength);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_CERT_buildCertECDSAP256(sshClientContext *pContextSSH, SizedBuffer *pCertificates, ubyte4 numCertificates);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_CERT_buildCertECDSAP384(sshClientContext *pContextSSH, SizedBuffer *pCertificates, ubyte4 numCertificates);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_CERT_buildCertECDSAP521(sshClientContext *pContextSSH, SizedBuffer *pCertificates, ubyte4 numCertificates);
#endif
#endif

#endif /* __SSHC_TRANS_HEADER__ */

