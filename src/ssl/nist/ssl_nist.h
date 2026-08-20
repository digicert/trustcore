/*
 * ssl_nist.h
 *
 * Function prototypes for testing TLS 1.2 against SP 800-135
 *
 */

#ifndef __SSL_NIST_H__
#define __SSL_NIST_H__

#ifdef __ENABLE_DIGICERT_SP800_135_ACVP__

enum {
    sslClientRandom = 1,
    sslServerRandom = 2,
    sslMasterSecret = 3,
    sslKeyBlock = 4
};

/* Set a session resume type as specified in sslsock.h */
MSTATUS setSSLSessionResume(SSLSocket *pSSLSock, E_SessionResumeType resumeType);

/* Set the hash algo to be used in the key derivation function, one of the ht_* values
 * from crypto.h */
MSTATUS setSSLPRFHashAlgo(SSLSocket *pSSLSock, ubyte hashAlgo);

/* Set the desired key block length in bytes */
MSTATUS setSSLKeyBlockLen(SSLSocket *pSSLSock, ubyte4 keyBlockLen);

/* Set a value in the SSL Socket. Type must be one of {sslClientRandom, sslServerRandom} */
MSTATUS setSSLValue(SSLSocket *pSSLSock, ubyte type, ubyte *pValue, ubyte4 valueLen);

/* Get a value from the SSL Socket. Type must be one of {sslMasterSecret, sslKeyBlock}.
 * Values are allocated by this function, caller responsible for freeing newly allocated bufffer */
MSTATUS getSSLValue(SSLSocket *pSSLSock, ubyte type, ubyte **ppValue, ubyte4 *pValueLen);

/* Wrapper function to call PRF function is sslsock */
MSTATUS generateMasterSecret(SSLSocket *pSSLSock,
                             const ubyte* pSecret, ubyte4 secretLen,
                             const ubyte* pLabelSeed, sbyte4 labelSeedLen,
                             ubyte* pResult, sbyte4 resultLen);

/* SSL function that performs the key derivation */
extern MSTATUS SSL_SOCK_generateKeyMaterial(SSLSocket* pSSLSock, ubyte* preMasterSecret, ubyte4 preMasterSecretLength);

#endif
#endif
