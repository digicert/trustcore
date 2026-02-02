/*
 * ssh_trans.h
 *
 * SSH Transport Protocol
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

#ifndef __SSH_TRANS_HEADER__
#define __SSH_TRANS_HEADER__

#define MAX_CLIENT_VERSION_STRING       255
#define MAX_SERVER_VERSION_STRING       255

/* do not include quotation marks on the next line */
#define SSH_IMPLEMENTATION              Mocana SSH

#ifndef __ENABLE_SSH_VERSION1_SUPPORT__
#define SSH_MAJOR_VERSION               2
#define SSH_MINOR_VERSION               0
#else
#define SSH_MAJOR_VERSION               1
#define SSH_MINOR_VERSION               99
#endif

#define STR(X)                          #X
#define SERVER_HELLO_STRING_FORM(x,y,z)     "SSH-" STR(x) "." STR(y) "-" STR(z)
#define SERVER_HELLO_STRING             SERVER_HELLO_STRING_FORM(SSH_MAJOR_VERSION,SSH_MINOR_VERSION,SSH_IMPLEMENTATION)
#define SERVER_HELLO_STRING_CUSTOM(x,y)     "SSH-" STR(x) "." STR(y) "-"
#define SERVER_HELLO_VERSION_STRING     SERVER_HELLO_STRING_CUSTOM(SSH_MAJOR_VERSION,SSH_MINOR_VERSION)

#define SSH_SIZEOF_MESSAGE_HEADER       5

#define PHASE_SSH_KEX                   1
#define PHASE_SSH_AUTH                  2
#define PHASE_SSH_CONNECT               3


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_TRANS_setMessageTimer(sshContext *pContextSSH, ubyte4 msTimeToExpire);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_TRANS_sendServerHello(sshContext *pContextSSH);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_TRANS_versionExchange(sshContext *pContextSSH);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_TRANS_sendServerAlgorithms(sshContext *pContextSSH);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_TRANS_doProtocol(sshContext *pContextSSH, ubyte *pMesg, ubyte4 mesgLen);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_TRANS_receiveMessage(sshContext *pContextSSH, ubyte **ppRetPayload, ubyte4 *pRetPayloadLength, ubyte4 phase, ubyte4 msTimeout);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN void    SSH_TRANS_sendDisconnectMesg(sshContext *pContextSSH, ubyte4 sshError);

#if (defined(__ENABLE_DIGICERT_DHG_KEY_EXCHANGE__))
/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_TRANS_initSafePrimesDHG(hwAccelDescr hwAccelCtx);
#endif

#if (defined(__ENABLE_DIGICERT_SSH_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSH_RSA_PKCS1_SUPPORT__) && defined(__ENABLE_DIGICERT_PKCS1__))
/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_TRANS_initRsaKeyExchange(hwAccelDescr hwAccelCtx);
#endif

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_TRANS_releaseStaticKeys(void);

#endif /* __SSH_TRANS_HEADER__ */
