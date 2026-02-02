/*
  ssl_priv.h
  ssl


*/

#ifndef __SSL_PRIV_HEADER__
#define __SSL_PRIV_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

struct SSLSocket;

MOC_EXTERN sbyte4  SSL_findConnectionInstance(struct SSLSocket *pSSLSock);
MOC_EXTERN MSTATUS verifyClientHelloCookie(MOC_IP_ADDRESS peerAddr, ubyte *pReceived, ubyte4 length, ubyte *pToSend, ubyte4 *pToSendLen);
MOC_EXTERN sbyte4  SSL_checkHandshakeTimer(sbyte4 connectionInstance);
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
MOC_EXTERN sbyte4  SSL_getConnectionInstance(MOC_IP_ADDRESS srcAddr, ubyte2 srcPort, MOC_IP_ADDRESS peerAddr, ubyte2 peerPort);
MOC_EXTERN sbyte4  SSL_removeConnectTimedWait(MOC_IP_ADDRESS srcAddr, ubyte2 srcPort, MOC_IP_ADDRESS peerAddr, ubyte2 peerPort);
MOC_EXTERN sbyte4  SSL_getNextConnectionInstance(ubyte4 *pCookie, sbyte4 *pConnectionInstance, const peerDescr **ppRetPeerDescr);
MOC_EXTERN MSTATUS SSL_acceptConnectionCommon(intBoolean isDTLS, TCP_SOCKET tempSocket,
                                              peerDescr *pPeerDescr,
                                              struct certStore* pCertStore,
                                              ubyte4 initialInternalFlag);
#endif
#if (defined (__ENABLE_DIGICERT_DTLS_SRTP__) && defined (__ENABLE_DIGICERT_SRTP_PROFILES_SELECT__))
MOC_EXTERN sbyte4  SSL_enableSrtpProfiles(sbyte4 connectionInstance, ubyte2 *pSrtpProfileList, ubyte4 listLength);
#endif
MOC_EXTERN MSTATUS SSL_ASYNC_connectCommon(intBoolean isDTLS, TCP_SOCKET tempSocket,
                                           peerDescr *pPeerDescr,
                                           ubyte sessionIdLen, ubyte * sessionId,
                                           ubyte * masterSecret, const sbyte* dnsName,
                                           struct certStore* certStore);

#ifdef __cplusplus
}
#endif


#endif
