/**
 * @file  eap_tls.c
 * @brief EAP-TLS method implementation
 *
 * @details    EAP Transport Layer Security
 * @since      1.41
 * @version    2.45 and later
 *
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flag must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_TLS__
 *     Additionally, at least one flag in each of the following flag pairs must be defined in moptions.h:
 *     +   Enable EAP peer/authenticator (\c \__ENABLE_DIGICERT_EAP_PEER__, \c \__ENABLE_DIGICERT_EAP_AUTH__)
 *     +   Enable asynchronous SSL client/server (\c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__, \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)
 *     Whether the following flags are defined determines which functions are enabled:
 *     +   \c \__ENABLE_DIGICERT_SSL_CLIENT__
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
 *
 */


/* Add to your makefile */
#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#if ((defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)) && (defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) || defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)))

#if (defined(__ENABLE_DIGICERT_EAP_TLS__))

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/vlong.h"
#include "../common/debug_console.h"
#include "../common/sizedbuffer.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/cert_store.h"
#include "../ssl/ssl.h"
#include "../eap/eap.h"
#ifdef __ENABLE_DIGICERT_EAP_FAST__
#include "../eap/eap_fast.h"
#endif
#include "../eap/eap_proto.h"
#include "../eap/eap_tls.h"


/*------------------------------------------------------------------*/

typedef enum eap_tls_frag_flag
{

    EAP_TLS_FRAG_FLAG_RECV = 1,
    EAP_TLS_FRAG_FLAG_SEND

} eap_tls_frag_flag_e;


/*------------------------------------------------------------------*/

typedef  struct eap_tls_cb
{
    sbyte4  tls_connection;
    ubyte * tls_data_recv;
    ubyte4  tls_data_recv_total_len;
    ubyte4  tls_data_recv_len;
    ubyte * tls_data_send;
    ubyte4  tls_data_send_total_len;
    ubyte4  tls_data_send_remaining;
    eap_tls_connection  tls_connection_type;
    eap_tls_frag_flag_e tls_frag_flag;
#if (defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_CLIENT__))
    certStorePtr ssl_cert_store_ptr;
#endif
    ubyte   tlsVersion;
    ubyte   methodType;
    ubyte   pad1[2];
    ubyte   *authId;
    ubyte2  authIdLen;
    ubyte   pad2[2];
    ubyte4  eapMTU; /*P: To hold the eapMTU value */
    ubyte   isVerNegotiated; /*P: Flag to ensure version negotiation is done just once */

} eap_tlsCB;

/*------------------------------------------------------------------*/

#define TLS_KEYING_PHRASE                "client EAP encryption"
#define TLS_KEYING_PHRASE_LEN            (21)

/*------------------------------------------------------------------*/

static  MSTATUS
eap_TLSsendPendingBytes(ubyte *appSessionHdl,ubyte *tls_connection,
                        ubyte **eapRespData, ubyte4 *eapRespLen);


/*------------------------------------------------------------------*/

/*P:SSL Record Header type */
#define SSL_CHANGE_CIPHER_SPEC              (20)
#define SSL_ALERT                           (21)
#define SSL_HANDSHAKE                       (22)
#define SSL_APPLICATION_DATA                (23)
#define SSL_INNER_APPLICATION               (24)

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_EAP_PEER__
/*! Build a %client $Hello$ message and add it to the send buffer.
This function builds a client $Hello$ response, returns the message through
the $eapRespData$ parameter, and adds the message to the asynchronous send buffer.

This function is used by the peer after it receives an EAP-TLS
$Start$ message from the authenticator. Version negotiation is performed using
the specified authenticator and peer versions. This function can be called by
any method that runs over TLS, such as TTLS, PEAP, and FAST.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_TLS__$
- $__ENABLE_DIGICERT_EAP_PEER__$

#Include %file:#&nbsp;&nbsp;eap_tls.h

\param appSessionHdl    Cookie given by the application to identify the session.
\param tls_connection   EAP-TLS session handle returned from EAP_TLSCreateSession.
\param methodType       Any of the $eapMethodType$ enumerated values (see eap_proto.h).
\param pkt              $Start$ message packet.
\param pktLen           Number of bytes in the $Start$ message packet ($pkt$).
\param eapRespData      On return, pointer to generated $Hello$ response.
\param eapRespLen       On return, pointer to length of generated $Hello$ response ($eapRespData$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\note For EAP-FAST authentication, the authenticator ID can be extracted by
calling EAP_FASTgetAuthId.

\note Although any $eapMethodType$ enumerated value can be specified for the $methodType$
parameter, only the following values are specifically addressed by this function:
- EAP_TYPE_TLS
- EAP_TYPE_TTLS
- EAP_TYPE_PEAP
- EAP_TYPE_FAST

*/
extern  MSTATUS
EAP_TLSPeerStart(ubyte *appSessionHdl,ubyte *tls_connection,
                 ubyte methodType,
                 ubyte *pkt,ubyte4 pktLen,
                 ubyte **eapRespData, ubyte4 *eapRespLen)
{
    MSTATUS status = ERR_MEM_ALLOC_FAIL;
    ubyte *eapResponse = NULL;
    eap_tlsCB * tlscon = (eap_tlsCB *)tls_connection;
    sbyte4 connectionInstance = 0;
    ubyte4 length;
    ubyte * tlsFlag;
    ubyte authVersion;
    ubyte4  sendLen;
#if defined(__ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__)
    ubyte2 cipherList[] = { 0x05 };
#endif

    MOC_UNUSED(appSessionHdl);
#if (defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__))

    if (!tls_connection)
    {
        status = ERR_EAP_TLS_SESSION_NOT_FOUND;
        goto exit;
    }
    if (2 > pktLen)
    {
        status = ERR_EAP_TLS_INVALID_LEN;
        goto exit;
    }

    tlsFlag = pkt+1;

    if (((*tlsFlag & EAP_TLS_START_FLAG) != EAP_TLS_START_FLAG))
    {
        status = ERR_EAP_TLS_INVALID_FLAG;
        goto exit;
    }

    authVersion  = *tlsFlag & EAP_TLS_VERSION_MASK;

    if (EAP_TYPE_FAST == methodType)
    {
         if (EAP_FAST_VERSION != authVersion)
         {
             status = ERR_EAP_FAST_INVALID_VERSION;
             goto exit;
         }
#if defined(__ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__)
         /*SSL_enableCiphers (tlscon->tls_connection, cipherList, 1);*/
#endif
    }
    connectionInstance = tlscon->tls_connection;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TLSPeerStart: Connection Instance ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, connectionInstance);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Auth Version ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4)authVersion);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

    /* send SSL client hello */
    if (OK > (status = SSL_ASYNC_start(connectionInstance)))
        goto exit;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Client Hello Length returned ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4)status);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

    /* Status Returns the number of Bytes Available to send */
    /* Get the Buffer out of pSockSSL and pass it through to EAP */
    if ((sbyte4) tlscon->eapMTU >= (sbyte4) status + 5)
    {
        *eapRespLen = (ubyte4) (status + 5);
        eapResponse = (ubyte *) MALLOC(*eapRespLen);
        if (NULL == eapResponse)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        *eapResponse = EAP_TLS_LENGTH_FLAG | tlscon->tlsVersion;
        DIGI_HTONL((ubyte *)&length,status);
        DIGI_MEMCPY(eapResponse +1,(ubyte *)&length,4);
        tlscon->tls_data_send_remaining = 0;
    }
    else
    {
       /* Will need fragmentation */
        *eapRespLen = tlscon->eapMTU + 5;
        eapResponse = (ubyte *) MALLOC(*eapRespLen);

        if (NULL == eapResponse)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        *eapResponse = EAP_TLS_LENGTH_FLAG | EAP_TLS_MORE_FLAG | tlscon->tlsVersion;
        DIGI_HTONL((ubyte *)&length,status);
        DIGI_MEMCPY(eapResponse +1,(ubyte *)&length,4);
        tlscon->tls_data_send_remaining = status - tlscon->eapMTU;
        tlscon->tls_frag_flag = EAP_TLS_FRAG_FLAG_SEND;
    }

    sendLen = *eapRespLen -5;
    status = SSL_ASYNC_getSendBuffer(connectionInstance,(eapResponse+5),&sendLen);

    *eapRespData = eapResponse;
#endif

exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TLSPeerStart: Error Starting TLS Connection, status = ", (sbyte4)status);

        if (eapResponse)
            FREE(eapResponse);

    }
    return status;
} /* EAP_TLSPeerStart */

#endif /*__ENABLE_DIGICERT_EAP_PEER__*/


/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
/*! Set any parameter of any method to a specified value.
This function sets the specified parameter's value for the specified method; for
example, setting the $pacKey$ value for EAP-FAST.

The two method-parameter combinations handled by this function are:
- $EAP_TYPE_FAST$-$EAP_TLS_PARAM_PAC_KEY$ (Requires that the $__ENABLE_DIGICERT_EAP_FAST__$ flag be defined)
- $EAP_TYPE_TTLS$-$EAP_TLS_PARAM_INNER_APP$ (Requires that the $__ENABLE_DIGICERT_INNER_APP__$ flag be defined)

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_TLS__$
- $__ENABLE_DIGICERT_SSL_CLIENT__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

\note A repeated call to this function overwrites the decrypted data. Therefore
your application should immediately process the data or explicitly save it for
later processing.

#Include %file:#&nbsp;&nbsp;eap_tls.h

\param appSessionHdl    Cookie given by the application to identify the session.
\param tls_connection   EAP-TLS session handle returned from EAP_TLSCreateSession.
\param methodType       $eapMethodType$ enumerated value (see eap_proto.h)
\param paramType        $eap_tls_param$ enumerated value (see eap_tls.h).\n
\n
 There are four parameter settings you can use. Two of them are desribed here:\n
\n
&bull; EAP_TLS_PARAM_MAX_MTU : This is used to set the max MTU. The group of EAP-TLS messages sent in a single round may thus be larger than the MTU size or the  maximum Remote Authentication Dail-In User Service (RADIUS) packet size of 4096 octets.  As a result, an EAP-TLS implementation must provide its own support for fragmentation and reassembly. NanoEAP takes this value from use by providing API EAP_TLSsetParams, and uses for fragmentation and reassembly.\n

&bull; EAP_TLS_SSL_CERT_STORE_PTR: This parameter is used to pass instance of certificate store to the EAP-TLS stack, so that it can find the client certificates and its private keys during mutual authentication.\n

\param param            Pointer to value to assign to specified method-parameter.
\param paramLen         Number of bytes in value to assign ($param$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_TLSstartRequest
\sa EAP_TLSPeerStart
\sa EAP_TLSRecvData
\sa EAP_TLSgetKey

*/
extern MSTATUS
EAP_TLSsetParams(ubyte *appSessionHdl,ubyte *tls_connection,
                 ubyte methodType, eap_tls_param paramType,ubyte *param,ubyte4 paramLen)
{
    eap_tlsCB   *tlscon = (eap_tlsCB *)tls_connection;
    sbyte4      connectionInstance = 0;
    MSTATUS     status = OK;

    if (!tls_connection)
    {
        status = ERR_EAP_TLS_SESSION_NOT_FOUND;
        goto exit;
    }

    connectionInstance = tlscon->tls_connection;

#ifdef __ENABLE_DIGICERT_EAP_FAST__
    /* In case of EAP_FAST, the param has to be pacKey */
    if (EAP_TYPE_FAST == methodType)
    {
        if (EAP_TLS_PARAM_PAC_KEY == paramType)
        {
            if (OK > (status = SSL_setEAPFASTParams(connectionInstance, (ubyte *)"", paramLen, param)))
                goto exit;
        }

        goto exit;
    }
#endif

#ifdef __ENABLE_DIGICERT_INNER_APP__
    if (EAP_TYPE_TTLS == methodType)
    {
        if (EAP_TLS_PARAM_INNER_APP == paramType)
        {
            if (OK > (status = SSL_setInnerApplicationExt(connectionInstance, (ubyte4) *param)))
                goto exit;
        }

        goto exit;
    }
#endif

   /*P: Setting the user-defined MTU in the control block */
   if(EAP_TLS_PARAM_MAX_MTU == paramType)
   {
        DIGI_MEMCPY((ubyte *)&tlscon->eapMTU, param,4);
        DEBUG_PRINT(DEBUG_EAP_MESSAGE,(sbyte*)"EAP MTU changed to: ");
        DEBUG_INT(DEBUG_EAP_MESSAGE,tlscon->eapMTU);
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE,(sbyte*)"");
    goto exit;
   }

#if (defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_CLIENT__))
   if((EAP_TLS_SSL_CERT_STORE_PTR == paramType) && (paramLen == sizeof(certStorePtr)))
   {
        tlscon->ssl_cert_store_ptr = (certStorePtr)param;
        goto exit;
   }
#endif

exit:
    return status;
}
#endif


/*------------------------------------------------------------------*/

/*! Get the authentication version of an EAP-TLS packet.
This function extracts the authentication version from an EAP-TLS packet.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_TLS__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_tls.h

\param appSessionHdl    Cookie given by the application to identify the session.
\param authVersion      On return, authenticator method version.
\param pkt              EAP-TLS packet containing the authentication version.
\param pktLen           Number of bytes in the EAP-TLS packet ($pkt$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_TLSPeerGetAuthVersion(ubyte *appSessionHdl, ubyte *authVersion, ubyte *pkt,
                      ubyte pktLen)
{
    MSTATUS status = OK;
    ubyte   *tlsFlag;

    MOC_UNUSED(appSessionHdl);
#if (defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__))

    if (2 > pktLen)
    {
        status = ERR_EAP_TLS_INVALID_LEN;
        goto exit;
    }

    tlsFlag = pkt+1;

    if (((*tlsFlag & EAP_TLS_START_FLAG) != EAP_TLS_START_FLAG))
    {
        status = ERR_EAP_TLS_INVALID_FLAG;
                goto exit;
    }

    *authVersion  = *tlsFlag & EAP_TLS_VERSION_MASK;
#endif

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Get the negotiated version of an EAP-TLS packet.
This function returns the negotiated version to be used for second stage.

\since 2.45
\version 2.45 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_TLS__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_tls.h

\note This function is applicable to EAP peers and authenticators.

\param tls_connection   EAP-TLS session handle returned from EAP_TLSCreateSession.
\param version          Pointer to allocated $ubyte$ that on return contains the negotiated version.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_TLSGetNegotiatedVersion(ubyte *tls_connection, ubyte *version)
{

    eap_tlsCB* tlscon = (eap_tlsCB *)tls_connection;
    MSTATUS status = OK;

    /*P: The version number cannot be more that 2 */
    if(2 < tlscon->tlsVersion)
    {
        status = ERR_EAP_TLS_INVALID_VERSION;
        goto exit;
    }

    /*P: The function would return an error in case it is invoked before the negotiation takes place*/
    if(!(tlscon->isVerNegotiated))
    {
        /*P: New Error Flag */
        status = ERR_EAP_TLS_VERSION_NOT_NEGOTIATED;
        goto exit;
    }

    DIGI_MEMCPY(version,(ubyte *)&tlscon->tlsVersion,1);

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Create an EAP-TLS session.
This function creates an EAP-TLS session using the specified parameters. The TLS
connection handle is returned through the $tls_connection$ parameter, and should
be passed in all subsequent function calls for the TLS session. This function
can be called by any method that runs over TLS, for example, TTLS, PEAP, and
FAST.

Both clients and servers can call this function. If called by a server, the
function calls SSL_ASYNC_acceptConnection. If called by a %client, the function
calls SSL_ASYNC_connect.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_TLS__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

\note The $peerVersion$ and $authVersion$ parameter values must match and must
correspond to TLS v1.0 and later.

#Include %file:#&nbsp;&nbsp;eap_tls.h

\param appSessionHdl    Cookie given by the application to identify the session.
\param tls_connection   On return, EAP-TLS session handle.
\param connectionType   Any of the $eap_tls_connection$ enumerated values (see eap_tls.h).
\param sessionIdLen     Pointer to number of bytes in EAP-TLS session ID ($sessionId$).
\param sessionId        Pointer to EAP-TLS session ID.
\param masterSecret     Pointer to master secret for this session.
\param dnsName          Pointer to DNS common name in the certificate.
\param methodType       Any of the $eapMethodType$ enumerated values (see eap_proto.h).
\param peerVersion      Peer method version.
\param authVersion      Authenticator method version.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern  MSTATUS
EAP_TLSCreateSession(ubyte *appSessionHdl,ubyte **tls_connection,
                     eap_tls_connection connectionType,
                     ubyte4 *sessionIdLen, ubyte *sessionId,
                     ubyte *masterSecret, ubyte *dnsName,
                     ubyte methodType,ubyte peerVersion, ubyte authVersion,
                     certStorePtr pCertStore)
{
    MSTATUS     status = OK;
    eap_tlsCB   *tlscon;
    sbyte4      connectionInstance = 0;

    MOC_UNUSED(appSessionHdl);

    tlscon = (eap_tlsCB *) MALLOC(sizeof(eap_tlsCB));

    if (NULL == tlscon)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)tlscon,0,sizeof(eap_tlsCB));
    tlscon->isVerNegotiated = 0; /*P: Initially setting the value as 0 */
#if (defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__))
    if (EAP_TLS_CONNECTION_CLIENT == connectionType)
    {
        if (peerVersion < authVersion)
        {
            tlscon->tlsVersion = peerVersion & EAP_TLS_VERSION_MASK;
        }
        else
        {
            tlscon->tlsVersion = authVersion;
        }

        tlscon->isVerNegotiated = 1; /*P: The Flag is set here after negotiation on the peer side */

        if (OK > (connectionInstance = SSL_ASYNC_connect((ubyte4)((uintptr)tlscon), *sessionIdLen, sessionId,
                                                         masterSecret, (sbyte *)dnsName, pCertStore)))
        {
            DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TLSCreateSession: SSL_ASYNC_connect failed, status = ", connectionInstance);
            status = connectionInstance;
            goto exit;
        }
    }
#endif

#if (defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__))
    if (EAP_TLS_CONNECTION_SERVER == connectionType)
    {
        tlscon->tlsVersion = authVersion;
        if (0 > (connectionInstance = SSL_ASYNC_acceptConnection((ubyte4)((uintptr)tlscon), pCertStore)))
        {
            DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TLSCreateSession: SSL_ASYNC_acceptConnection failed, status = ", connectionInstance);
            status = connectionInstance;
            goto exit;
        }
    }
#endif

    tlscon->methodType = methodType;
    /*P: Initializing the eapMTU to default value */
    tlscon->eapMTU = MAX_EAP_TLS_MTU;
    /* mark the session as a block buffering session */
    if (OK > (status = SSL_setSessionFlags(connectionInstance, SSL_FLAG_ENABLE_SEND_BUFFER | SSL_FLAG_ENABLE_RECV_BUFFER)))
        goto exit;

    tlscon->tls_connection = connectionInstance;
    tlscon->tls_connection_type = connectionType;
    *tls_connection = (ubyte *)tlscon;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TLSCreateSession: Connection Instance ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, tlscon->tls_connection);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Version ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, tlscon->tlsVersion);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Method Type ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, tlscon->methodType);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Connection Type ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, tlscon->tls_connection_type);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Session Id \"");
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)sessionId);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"\" DNS Name \"");
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)dnsName);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"\" MTU size "); /* P: Debug Message */
    DEBUG_INT(DEBUG_EAP_MESSAGE, tlscon->eapMTU);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TLSCreateSession: Error Starting TLS Connection, status = ", (sbyte4)status);

        if (tlscon)
            FREE(tlscon);

    }
    return status;
} /* EAP_TLSCreateSession */


/*------------------------------------------------------------------*/

/*! Set EAP-FAST authenticator ID.
This function sets an EAP-FAST authenticator's ID (which is sent to a peer in an
EAP-TLS $Start$ message) to the specified value.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_TLS__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

\note A repeated call to this function overwrites the decrypted data. Therefore
your application should immediately process the data or explicitly save it for
later processing.

#Include %file:#&nbsp;&nbsp;eap_tls.h

\param appSessionHdl    Cookie given by the application to identify the session.
\param tls_connection   EAP-TLS session handle returned from EAP_TLSCreateSession.
\param authId           Value to assign to the authenticator ID.
\param authIdLen        Number of bytes in authenticator ID value ($authId$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_TLSstartRequest
\sa EAP_TLSPeerStart
\sa EAP_TLSRecvData
\sa EAP_TLSgetKey

*/
extern MSTATUS
EAP_TLSSetAuthId(ubyte *appSessionHdl, ubyte *tls_connection,
                 ubyte *authId, ubyte2 authIdLen)
{
    MSTATUS    status = OK;
    eap_tlsCB  *tlscon = (eap_tlsCB *)tls_connection;

    if (!tlscon)
    {
        status = ERR_EAP_TLS_SESSION_NOT_FOUND;
        goto exit;
    }

    if (0 == authIdLen)
        goto exit;

    tlscon->authId = (ubyte *) MALLOC(authIdLen);

    if (NULL == tlscon->authId)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    DIGI_MEMCPY(tlscon->authId, authId, authIdLen);
    tlscon->authIdLen = authIdLen;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TLSSetAuthId: Connection Instance ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, tlscon->tls_connection);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Auth ID \"");
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)tlscon->authId);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"\"");

exit:
    if (OK > status)
    {
        if (tlscon)
            DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TLSSetAuthId: Connection Instance ", (sbyte4)tlscon->tls_connection);
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TLSSetAuthId: Error Setting Auth Id, status = ", (sbyte4)status);
    }

    return status;

}


/*------------------------------------------------------------------*/

/*! Get an EAP-TLS session's session status.
This function retrieves TLS session's session status ($SSL_CONNECTION_OPEN$ or
$SSL_CONNECTION_NEGOTIATE$). This is usually used after a call to
EAP_TLSProcessMsg to verify the TLS channel status.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_TLS__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_tls.h

\param appSessionHdl    Cookie given by the application to identify the session.
\param tls_connection   EAP-TLS session handle returned from EAP_TLSCreateSession.
\param sessionStatus    On return, pointer to the session's status.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_TLSstartRequest
\sa EAP_TLSProcessMsg
\sa EAP_TLSgetClientSessionInfo
\sa EAP_TLSgetSSLInstance

*/
extern  MSTATUS
EAP_TLSgetSessionStatus(ubyte *appSessionHdl,ubyte * tls_connection,
                              ubyte4 *sessionStatus)
{
    MSTATUS status;
    eap_tlsCB * tlscon = (eap_tlsCB *)tls_connection;
    MOC_UNUSED(appSessionHdl);

    if (!tlscon)
    {
        status = ERR_EAP_TLS_SESSION_NOT_FOUND;
        goto exit;
    }

    status = SSL_getSessionStatus(tlscon->tls_connection, sessionStatus);

exit:
    if (OK > status)
    {
        if (tlscon)
            DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TLSgetSessionStatus: Connection Instance ", (sbyte4)tlscon->tls_connection);
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TLSgetSessionStatus: Error, status = ", (sbyte4)status);
    }
    return status;
}


/*------------------------------------------------------------------*/

/*! Get an EAP-TLS connection's SSL connection instance.
This function retrieves an EAP-TLS connection's SSL connection instance.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_TLS__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_tls.h

\param appSessionHdl        Cookie given by the application to identify the session.
\param tls_connection       EAP-TLS session handle returned from EAP_TLSCreateSession.
\param connectionInstance   On return, pointer to the SSL connection instance.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_TLSstartRequest
\sa EAP_TLSProcessMsg
\sa EAP_TLSgetSessionStatus
\sa EAP_TLSgetClientSessionInfo

*/
extern  MSTATUS
EAP_TLSgetSSLInstance(ubyte *appSessionHdl,ubyte * tls_connection,
                              sbyte4 *connectionInstance)
{
    MSTATUS status  = OK;
    eap_tlsCB * tlscon = (eap_tlsCB *)tls_connection;
    MOC_UNUSED(appSessionHdl);

    if (!tlscon)
    {
        status = ERR_EAP_TLS_SESSION_NOT_FOUND;
        goto exit;
    }

    *connectionInstance = tlscon->tls_connection;

exit:
    if (OK > status)
    {
        if (tlscon)
            DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TLSgetSSLInstance: Connection Instance ", (sbyte4)tlscon->tls_connection);
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TLSgetSSLInstance: Error, status = ", (sbyte4)status);
    }

    return status;
}


/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
/*! Get EAP-TLS session's session ID and master secret.
This function retrieves the specified TLS session's session ID and master secret.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_TLS__$
- $__ENABLE_DIGICERT_SSL_CLIENT__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_tls.h

\param appSessionHdl    Cookie given by the application to identify the session.
\param tls_connection   EAP-TLS session handle returned from EAP_TLSCreateSession.
\param sessionIdLen     On return, pointer to number of bytes in EAP-TLS session ID ($sessionId$).
\param sessionId        On return, pointer to session's session ID.
\param masterSecret     On return, pointer to session's master secret.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_TLSstartRequest
\sa EAP_TLSProcessMsg
\sa EAP_TLSgetSessionStatus
\sa EAP_TLSgetSSLInstance

*/
extern  MSTATUS
EAP_TLSgetClientSessionInfo(ubyte *appSessionHdl,ubyte * tls_connection,
                            ubyte4 *sessionIdLen,
                            ubyte *sessionId, ubyte *masterSecret)
{
    MSTATUS status;
    eap_tlsCB * tlscon = (eap_tlsCB *)tls_connection;
    ubyte sid_len = (ubyte)*sessionIdLen;

    MOC_UNUSED(appSessionHdl);

    if (!tlscon)
    {
        status = ERR_EAP_TLS_SESSION_NOT_FOUND;
        goto exit;
    }

    status = SSL_getClientSessionInfo(tlscon->tls_connection, &sid_len, sessionId, masterSecret);

    *sessionIdLen = sid_len;

exit:
    if (OK > status)
    {
        if (tlscon)
            DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TLSgetClientSessionInfo: Connection Instance ", (sbyte4)tlscon->tls_connection);
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TLSgetClientSessionInfo: Error Getting Client Session Info, status = ", (sbyte4)status);
    }
    return status;
}
#endif


/*------------------------------------------------------------------*/

/*! Close an EAP-TLS connection.
This function closes an EAP-TLS connection.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_TLS__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_tls.h

\param appSessionHdl    Cookie given by the application to identify the session.
\param tls_connection   EAP-TLS session handle returned from EAP_TLSCreateSession.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_TLSstartRequest
\sa EAP_TLSProcessMsg
\sa EAP_TLSgetClientSessionInfo

*/
extern  MSTATUS
EAP_TLScloseConnection (ubyte *appSessionHdl,ubyte *tls_connection)
{
    MSTATUS status = OK;
    eap_tlsCB *tlscon = (eap_tlsCB *)tls_connection;
    MOC_UNUSED(appSessionHdl);

    if (NULL == tls_connection)
        goto exit;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TLScloseConnection: Connection Instance ", (sbyte4)tlscon->tls_connection);

    status = SSL_ASYNC_closeConnection(tlscon->tls_connection);
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TLScloseConnection: Error Closing TLS COnnection, status = ", (sbyte4)status);
    }

    if(tlscon->tls_data_recv)
    {
        FREE(tlscon->tls_data_recv);
        tlscon->tls_data_recv = NULL;
    }

    FREE (tlscon);

exit:
    return status;
}


/*------------------------------------------------------------------*/

static  MSTATUS
eap_TLSsendPendingBytes(ubyte *appSessionHdl,ubyte *tls_connection,
                        ubyte **eapRespData, ubyte4 *eapRespLen)
{
    MSTATUS status = OK;
    ubyte *eapResponse = NULL;
    eap_tlsCB * tlscon;
    ubyte4    sendLen;
    MOC_UNUSED(appSessionHdl);

    tlscon = (eap_tlsCB *)tls_connection;

    if (tlscon->eapMTU >= tlscon->tls_data_send_remaining)
    {
        /* Add 1 Byte for the Flag */
        *eapRespLen = tlscon->tls_data_send_remaining+1;
        eapResponse = (ubyte *) MALLOC(*eapRespLen);

        if(NULL == eapResponse)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        *eapResponse =  tlscon->tlsVersion;
        tlscon->tls_data_send_remaining  = 0;
        tlscon->tls_frag_flag = 0;
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"eap_TLSsendPendingBytes: Connection Instance ");
        DEBUG_INT(DEBUG_EAP_MESSAGE, tlscon->tls_connection);
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Sending Last Fragment of Length ");
        DEBUG_INT(DEBUG_EAP_MESSAGE, *eapRespLen);
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");
    }
    else
    {
       /* Will need fragmentation  Add 1 Byte for Flag*/
        *eapRespLen = tlscon->eapMTU +1;
        eapResponse = (ubyte *) MALLOC(*eapRespLen);

        if(NULL == eapResponse)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        *eapResponse = EAP_TLS_MORE_FLAG | tlscon->tlsVersion;
        tlscon->tls_data_send_remaining -=tlscon->eapMTU;
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"eap_TLSsendPendingBytes: Connection Instance ");
        DEBUG_INT(DEBUG_EAP_MESSAGE, tlscon->tls_connection);
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Sending Fragment of Length ");
        DEBUG_INT(DEBUG_EAP_MESSAGE, *eapRespLen);
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");
    }

    sendLen = *eapRespLen -1;
    status = SSL_ASYNC_getSendBuffer(tlscon->tls_connection,(eapResponse+1),&sendLen);

    *eapRespData = eapResponse;
exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"eap_TLSsendPendingBytes: Connection Instance ", (sbyte4)tlscon->tls_connection);
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"eap_TLSsendPendingBytes: Error Sending Pending Bytes, status = ", (sbyte4)status);

        if (eapResponse)
            FREE(eapResponse);
    }
    return status;
}


/*------------------------------------------------------------------*/

/*! Send an EAP-TLS $Start$ message.
This function sends an EAP-TLS $Start$ message, which is used by the
authenticator to start an EAP conversation using TLS, TTLS, PEAP, or FAST
methods. For EAP-FAST conversations, the authenticator can include
its ID to send to the peer.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_TLS__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_tls.h

\param appSessionHdl    Cookie given by the application to identify the session.
\param tls_connection   EAP-TLS session handle returned from EAP_TLSCreateSession.
\param sslCert          SSL certificate for this server.
\param methodType       Any of the $eapMethodType$ enumerated values (see eap_proto.h).
\param eapReqData       On return, pointer to returned data (the TLS encrypted payload).
\param eapReqLen        On return, pointer to length of returned data ($eapReqData$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern  MSTATUS
EAP_TLSstartRequest(ubyte *appSessionHdl,ubyte *tls_connection,
                    certDescriptor* sslCert,
                    ubyte methodType,
                    ubyte **eapReqData, ubyte4 *eapReqLen)
{
    ubyte*      eapRequest = NULL;
    MSTATUS     status = OK;
    eap_tlsCB * tlscon;
#if (defined(__ENABLE_DIGICERT_EAP_FAST__))
    ubyte       flags;
#endif
#if defined(__ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__)
    ubyte2 cipherList[] = { 0x05 };
#endif

    MOC_UNUSED(appSessionHdl);
    MOC_UNUSED(sslCert);

    tlscon = (eap_tlsCB *)tls_connection;

    if (!tlscon)
    {
        status = ERR_EAP_TLS_SESSION_NOT_FOUND;
        goto exit;
    }

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TLSstartRequest: Connection Instance ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, tlscon->tls_connection);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)" Sending Start Request");

#if (defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__))
    if (methodType == EAP_TYPE_FAST)
    {
#if defined(__ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__)
        /*SSL_enableCiphers (tlscon->tls_connection, cipherList, 1);*/
#endif
#if (defined(__ENABLE_DIGICERT_EAP_FAST__))
        /*Can Send Auth ID Too */
        if (tlscon->authIdLen != 0 && tlscon->authId)
        {
            flags = EAP_TLS_START_FLAG | tlscon->tlsVersion;
            status = EAP_FASTbuildAuthId(flags, tlscon->authId,
                                         tlscon->authIdLen,
                                         eapReqData, eapReqLen);
            goto exit;
        }
        else
        {
            *eapReqLen = 1;
        }

#endif
    }
    else
    {
        *eapReqLen = 1;
    }

    eapRequest = (ubyte *) MALLOC(*eapReqLen);

    if(NULL == eapRequest)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    *eapRequest = EAP_TLS_START_FLAG | tlscon->tlsVersion;

    *eapReqData = eapRequest;
#endif

exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TLSstartRequest: Error Sending Start Request, status = ", (sbyte4)status);
    }
    return status;
}


/*------------------------------------------------------------------*/

/*! Process a received EAP-TLS message and build a response.
This function processes an EAP-TLS message received by an authenticator or peer,
performing any necessary fragmentation and reassembly of records, as well as
wrapping the TLS response as an EAP payload.

If the $ERR_EAP_TLS_DATA_ARRIVED$ error code is returned, the decrypted data is
returned through the $eapRespData$ parameter, thereby managing cases where two SSL
frames are grouped within a single TLS packet. A typical example is the
Handshake Record for PEAP and FAST, where the Identity Request is frequently
piggybacked to the TLS $Finished$ message.

If $OK$ is returned, the data is decrypted for local processing; otherwise the
$eapRespData$ parameter contains the decrypted data to be transmitted to the
peer or authenticator (according to whether this function was called by the
authenticator or peer, respectively).

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_TLS__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_tls.h

\param appSessionHdl    Cookie given by the application to identify the session.
\param tls_connection   EAP-TLS session handle returned from EAP_TLSCreateSession.
\param data             EAP-TLS message payload.
\param len              Number of bytes in EAP-TLS message payload ($data$).
\param eapRespData      On return, pointer to decrypted data (regardless of the functin's return stauts).
\param eapRespLen       On return, pointer to length of decrypted data ($eapRespData$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_TLSstartRequest
\sa EAP_TLSPeerStart
\sa EAP_TLSSendData
\sa EAP_TLSRecvData

*/
extern MSTATUS
EAP_TLSProcessMsg(ubyte *appSessionHdl, ubyte *tls_connection,
                   ubyte *data, ubyte4 len,
                   ubyte **eapRespData, ubyte4 *eapRespLen)
{

    eap_tlsCB*  tlscon = (eap_tlsCB *)tls_connection;
    ubyte*      eapResponse= NULL;
    ubyte4      length;
    ubyte       version;
    /* 1st Byte is Method, 2nd Byte is Flag */
    ubyte       tlsFlags  = 0;
    /* Depending on Length Flag, this could vary */
    ubyte *     tlsData  = NULL;
    ubyte4      recvLen;
    ubyte4      tlsLength = 0;
    MSTATUS     status = OK;
    ubyte4      respLen;
    ubyte4      retProtocol;
    ubyte       tlsType=0;

    if (!tlscon)
    {
        status = ERR_EAP_TLS_SESSION_NOT_FOUND;
        goto exit;
    }

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TLSProcessMsg: Connection Instance ", (sbyte4)tlscon->tls_connection);

    *eapRespLen = 0;

    if ((NULL == data) || (0 == len))
    {
        status = ERR_EAP_TLS_INVALID_LEN;
        goto exit;
    }

    if (len > 1) /* flags data arrived */
    {
        tlsFlags  = *(data + 1);
    }

    if (len > 2)
    {
        tlsData  = data + 2;
        tlsLength = len - 2;
    }

    version = tlsFlags & EAP_TLS_VERSION_MASK;

    if (version != tlscon->tlsVersion)
    {
        /*P Downgrading the version to negotiate with the peer version*/
        if((EAP_TLS_CONNECTION_SERVER == tlscon->tls_connection_type) && (version < tlscon->tlsVersion) && !(tlscon->isVerNegotiated))
        {
            DEBUG_PRINT(DEBUG_EAP_MESSAGE,(sbyte*)" Downgrading version from ");
            DEBUG_INT(DEBUG_EAP_MESSAGE,tlscon->tlsVersion);
            DEBUG_PRINT(DEBUG_EAP_MESSAGE,(sbyte*)" to ");
            DEBUG_INT(DEBUG_EAP_MESSAGE,version);
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE,(sbyte*)".");

            tlscon->tlsVersion = version;
        }
        else
        {
            status = ERR_EAP_TLS_INVALID_VERSION;
            goto exit;
        }
    }
#if(defined(__ENABLE_DIGICERT_EAP_AUTH__))
    tlscon->isVerNegotiated = 1; /*P: Version negotiation flags gets set here for the auth*/
#endif

    /* We can recv 4 kinds of messages */
    /* Start Message with S Flag Len  == 2 To be called by APP when the first pkt arrives.. to check for S flag */
    /* Regular Message with L Flag */
    /* Frag Message with L & M Flag */
    /* Frag Message with  M Flag */
    /* Last Frag Message with  0 Flag */
    /* Frag ACK Message Len ==1  */

    if (0 == tlscon->tls_frag_flag)
    {
        if (1 == len || 2 == len) /*its an ACK.. */
        {
           *eapRespLen = 1;

           eapResponse = (ubyte *) MALLOC(*eapRespLen);
           if(NULL == eapResponse)
           {
               status = ERR_MEM_ALLOC_FAIL;
               goto exit;
           }
           *eapResponse = tlscon->tlsVersion;
           *eapRespData = eapResponse;

           status =  OK;
           DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)" Sending Ack");
           goto exit;
        }

        /* Length Flag Should be Present in the First  pkt */
        if ((tlsFlags & EAP_TLS_LENGTH_FLAG))
        {
        /* Check the Length */

            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Received TLS Packet L Bit Set, Length ");
            DEBUG_INT(DEBUG_EAP_MESSAGE, tlsLength);
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)" Processing");

            if (tlsLength <= EAP_TLS_LENGTH_BYTES)
            {
                status = ERR_EAP_TLS_INVALID_LEN;
                goto exit;
            }

        /* Copy The length Over */

            DIGI_MEMCPY((ubyte *) &tlscon->tls_data_recv_total_len  ,tlsData,EAP_TLS_LENGTH_BYTES);
            tlsData  += EAP_TLS_LENGTH_BYTES;
            tlsLength-= EAP_TLS_LENGTH_BYTES;

            tlscon->tls_data_recv_total_len   = DIGI_NTOHL((ubyte *)&tlscon->tls_data_recv_total_len);

            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Total Length of TLS Packet: ");
            DEBUG_INT(DEBUG_EAP_MESSAGE, tlscon->tls_data_recv_total_len);
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

            if ((tlsFlags & EAP_TLS_MORE_FLAG))
            {
               /* Move it to the buffer */
               DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)" Received Fragment, Sending ACK");
               tlscon->tls_data_recv = MALLOC(tlscon->tls_data_recv_total_len);

               if (NULL == tlscon->tls_data_recv)
               {
                    status = ERR_MEM_ALLOC_FAIL;
                    goto exit;
               }

               DIGI_MEMCPY(tlscon->tls_data_recv,tlsData,tlsLength);

               tlscon->tls_data_recv_len = tlsLength;
               DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Received Length of TLS Packet: ");
               DEBUG_INT(DEBUG_EAP_MESSAGE, tlscon->tls_data_recv_len);
               DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

               tlscon->tls_frag_flag =  EAP_TLS_FRAG_FLAG_RECV;

               /* Send ACK with the EAPTLS Flag Byte == version */
               *eapRespLen = 1;

               eapResponse = (ubyte *) MALLOC(*eapRespLen);
               if(NULL == eapResponse)
               {
                   status = ERR_MEM_ALLOC_FAIL;
                   goto exit;
               }
               *eapResponse =  tlscon->tlsVersion;
               *eapRespData = eapResponse;

               status =  OK;
               goto exit;
            }
        }
    }
    else
    {
        if (1 == len || 2 == len) /*its an ACK.. Send Pending Bytes */
        {
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)" Received Ack, Sending Pending Bytes");
            if (EAP_TLS_FRAG_FLAG_SEND == tlscon->tls_frag_flag)
            {
                status = eap_TLSsendPendingBytes (appSessionHdl,tls_connection,
                  eapRespData, eapRespLen);
                goto exit;
            }
            else
            {
                /* getting an ACK when we've already sent all the data.? */
                 status = ERR_EAP_TLS_NO_DATA_TO_SEND;
                 goto exit;
            }
        }
        else
        {
            if (tlscon->tls_frag_flag ==  EAP_TLS_FRAG_FLAG_RECV)
            { /* coallese packets..  */
                if (tlsLength + tlscon->tls_data_recv_len >= tlscon->tls_data_recv_total_len)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)" Received Last Fragment, Sending Ack");
                    /*Should be the last Fragment */
                    if ((tlsFlags & EAP_TLS_MORE_FLAG))
                    {
                        /* We seem to be overshootingt the total length */
                        status = ERR_EAP_TLS_INVALID_LEN;
                        goto exit;
                    }

                    if ((tlsFlags & EAP_TLS_LENGTH_FLAG))
                    {
                        tlsData  += EAP_TLS_LENGTH_BYTES;
                        tlsLength-= EAP_TLS_LENGTH_BYTES;
                    }

                    /* Check For Total Length */
                    if (tlsLength + tlscon->tls_data_recv_len > tlscon->tls_data_recv_total_len)
                    {

                        status = ERR_EAP_TLS_INVALID_LEN;
                        goto exit;
                    }

                    DIGI_MEMCPY(tlscon->tls_data_recv+tlscon->tls_data_recv_len,
                           tlsData,tlsLength);
                    tlscon->tls_data_recv_len += tlsLength;
                    tlscon->tls_frag_flag =  0;
                    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Received Length of TLS Packet: ");
                    DEBUG_INT(DEBUG_EAP_MESSAGE, tlscon->tls_data_recv_len);
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");
                }
                else
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)" Received Fragment, Sending Ack");
                    /* Should have the more flag set */
                    if (!(tlsFlags & EAP_TLS_MORE_FLAG))
                    {
                        status = ERR_EAP_TLS_INVALID_FLAG;
                        goto exit;
                    }

                    if ((tlsFlags & EAP_TLS_LENGTH_FLAG))
                    {
                        tlsData  += EAP_TLS_LENGTH_BYTES;
                        tlsLength-= EAP_TLS_LENGTH_BYTES;
                    }

                    DIGI_MEMCPY(tlscon->tls_data_recv+tlscon->tls_data_recv_len,
                               tlsData,tlsLength);
                    tlscon->tls_data_recv_len += tlsLength;

               /* Send ACK with the EAPTLS Flag Byte == version */
                    *eapRespLen = 1;

                    eapResponse = (ubyte *) MALLOC(*eapRespLen);
                    if(NULL == eapResponse)
                    {
                        status = ERR_MEM_ALLOC_FAIL;
                        goto exit;
                    }
                    *eapResponse =  tlscon->tlsVersion;
                    *eapRespData = eapResponse;
                     status = OK;
                     goto exit;
                }
            }
        }
    }

    /* Process the completed packet */
    if (tlscon->tls_data_recv)
    {
        /* Status returns Number of Bytes to be Harvested fom the Send Buffer*/
        tlsType = *(ubyte *)tlscon->tls_data_recv;
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Processing tlsType ");
        DEBUG_INT(DEBUG_EAP_MESSAGE,tlsType);
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE,(sbyte*)"");
        status =SSL_ASYNC_recvMessage(tlscon->tls_connection, tlscon->tls_data_recv,tlscon->tls_data_recv_total_len);
        FREE(tlscon->tls_data_recv);
        tlscon->tls_data_recv = NULL;
    }
    else
    {
        tlsType = *(ubyte *)tlsData;
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Received TLS Packet, Length ");
        DEBUG_INT(DEBUG_EAP_MESSAGE, tlsLength);
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" tlsType ");
        DEBUG_INT(DEBUG_EAP_MESSAGE,tlsType);
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)" Processing");
        /* Status returns Number of Bytes to be Harvested fom the Send Buffer*/
        status = SSL_ASYNC_recvMessage(tlscon->tls_connection, tlsData, tlsLength);
    }

    /*P: Handling SSL Alert*/
    if((SSL_ALERT == tlsType))
    {
        DEBUG_PRINT(DEBUG_EAP_MESSAGE,(sbyte*)" Received TLS Alert");
        if (EAP_TLS_CONNECTION_CLIENT == tlscon->tls_connection_type)
        {
           /* Send ACK with the EAPTLS Flag Byte == version */
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE,(sbyte*)" Sending ACK");
            *eapRespLen = 1;

            eapResponse = (ubyte *) MALLOC(*eapRespLen);
            if(NULL == eapResponse)
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }
            *eapResponse =  tlscon->tlsVersion;
            *eapRespData = eapResponse;
            status = OK;
            goto exit;
        }

        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE,(sbyte*)"");
        status = ERR_SSL_FATAL_ALERT;
        goto exit;
    }

    /* If the Status == 0, then there is Data to be sent from the TLS Stack */
    if (OK >= status)
        goto exit;

    /* Only read length of data in send buffer */
    recvLen = 0;
    if (OK > (status = SSL_ASYNC_getSendBuffer(tlscon->tls_connection, NULL, &recvLen)))
    {
        /* Mostly App Data Arrived with Handshake Record and is now sitting
           in the Recv Buffer */
        if (ERR_SSL_NO_DATA_TO_SEND == status)
        {
            FREE(eapResponse);
            eapResponse = NULL;
            if (OK > (status = SSL_ASYNC_getRecvBuffer(tlscon->tls_connection, &(eapResponse),eapRespLen,&retProtocol)))
            {
                goto exit;
            }
            *eapRespData = eapResponse;
            /* This means that the Data is for Local processing and not to be sent across */
            status = ERR_EAP_TLS_DATA_ARRIVED;
            return status;
        }
	/* A different error code was returned */
        goto exit;
    }

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Returning ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, recvLen);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)" Bytes");

    /* Send data in send buffer, in fragment if needed */
    if (tlscon->eapMTU >= recvLen+5)
    {
        /* 5 Bytes 1 Byte Flag, 4 Bytes Length */
        *eapRespLen = recvLen + 5;
        eapResponse = (ubyte *) MALLOC(*eapRespLen);
        if(NULL == eapResponse)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        *eapResponse = EAP_TLS_LENGTH_FLAG | tlscon->tlsVersion;
        DIGI_HTONL((ubyte *)&length, recvLen);
        DIGI_MEMCPY((ubyte *)(eapResponse +1),(ubyte *)&length,4);
        tlscon->tls_data_send_remaining = 0;
    }
    else
    {
       /* Will need fragmentation */
        *eapRespLen = tlscon->eapMTU + 5;
        eapResponse = (ubyte *) MALLOC(*eapRespLen);
        if(NULL == eapResponse)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        *eapResponse = EAP_TLS_LENGTH_FLAG | EAP_TLS_MORE_FLAG| tlscon->tlsVersion;
        DIGI_HTONL((ubyte *)&length, recvLen);
        DIGI_MEMCPY(eapResponse +1,(ubyte *)&length,4);
        tlscon->tls_data_send_remaining = recvLen - tlscon->eapMTU;
        tlscon->tls_frag_flag = EAP_TLS_FRAG_FLAG_SEND;
    }
    respLen = *eapRespLen - 5;
    if (OK > (status = SSL_ASYNC_getSendBuffer(tlscon->tls_connection,(eapResponse+5), &respLen)))
    {
        goto exit;
    }

    *eapRespData = eapResponse;

exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TLSProcessMsg: Error Processing Message, status = ", (sbyte4)status);
        if (eapResponse)
            FREE(eapResponse);
    }

    return status;
}


/*------------------------------------------------------------------*/

/*! Decrypt EAP message payload.
This function decrypts application data from an EAP payload. If the EAP payload
contains multiple packets, this function decrypts the initial packet and returns
the next packet through the $eapRemData$ parameter, which must be used as input
(via the $data$ parameter) to a repeated call to this function. This function
must be repeatedly called until $eapRemData$ is $NULL$.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_TLS__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

\note A repeated call to this function overwrites the decrypted data. Therefore
your application should immediately process the data or explicitly save it for
later processing.

#Include %file:#&nbsp;&nbsp;eap_tls.h

\param appSessionHdl    Cookie given by the application to identify the session.
\param tls_connection   EAP-TLS session handle returned from EAP_TLSCreateSession.
\param data             EAP-TLS message payload.
\param len              Number of bytes in EAP-TLS message payload ($data$).
\param eapRespData      On return, pointer to decrypted data.
\param eapRespLen       On return, pointer to length of decrypted data ($eapRespData$).
\param eapRemData       On return, pointer to remaining EAP payload (unprocessed data).
\param eapRemLen        On return, pointer to number of bytes in remaining EAP payload ($eapRemData$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_TLSstartRequest
\sa EAP_TLSPeerStart
\sa EAP_TLSSendData
\sa EAP_TLSgetKey

*/
extern MSTATUS
EAP_TLSRecvData(ubyte *appSessionHdl, ubyte *tls_connection,
                ubyte *data, ubyte4 len,
                ubyte **eapRespData, ubyte4 *eapRespLen,
                ubyte **eapRemData, ubyte4 *eapRemLen)
{
    /* Once the Connection is open call SSL_SOCK_recv/send
       to decrypt/encrypt data */
    eap_tlsCB*  tlscon = (eap_tlsCB *)tls_connection;
    MSTATUS     status = OK;
    ubyte4      retProtocol;
    MOC_UNUSED(appSessionHdl);

    if (!tlscon)
    {
        status = ERR_EAP_TLS_SESSION_NOT_FOUND;
        goto exit;
    }

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TLSRecvData: Connection Instance ", (sbyte4)tlscon->tls_connection);

    *eapRespLen = 0;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Decrypting data Length ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4)len);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "");

    /* Status Returns Number of Decrypted Bytes Received */
    status = SSL_ASYNC_recvMessage2(tlscon->tls_connection, data, len,
                                    eapRemData, eapRemLen);
    if (OK > status)
        goto exit;

    *eapRespLen = status;

    if (OK > (status = SSL_ASYNC_getRecvBuffer(tlscon->tls_connection,
                                       eapRespData,eapRespLen,&retProtocol)))
    {
        goto exit;
    }

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Decrypted data Length ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4)*eapRespLen);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TLSRecvData: Error, status = ", (sbyte4)status);
    }

    return status;
}


/*------------------------------------------------------------------*/

/*! Encrypt EAP (clear text) data.
This function encrypts EAP payload (clear text) data for sending in either
direction. You can use this function to }harvest} or process packets that have
already been added to the send buffer.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_TLS__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

\note A repeated call to this function overwrites the decrypted data. Therefore
your application should immediately process the data or explicitly save it for
later processing.

#Include %file:#&nbsp;&nbsp;eap_tls.h

\param appSessionHdl    Cookie given by the application to identify the session.
\param tls_connection   EAP-TLS session handle returned from EAP_TLSCreateSession.
\param data             EAP payload (clear text %data) to encrypt.
\param len              Number of bytes in EAP payload ($data$).
\param eapRespData      On return, pointer to encrypted data.
\param eapRespLen       On return, pointer to number of types in encrypted data ($eapRespData$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_TLSstartRequest
\sa EAP_TLSPeerStart
\sa EAP_TLSRecvData
\sa EAP_TLSgetKey

*/
extern MSTATUS
EAP_TLSSendData(ubyte *appSessionHdl, ubyte *tls_connection,
                ubyte *data, ubyte4 len,
                ubyte **eapRespData, ubyte4 *eapRespLen)
{

    MSTATUS status = OK;
    eap_tlsCB *tlscon = (eap_tlsCB *)tls_connection;
    ubyte * eapResponse= NULL;
    sbyte4 length;
    MOC_UNUSED(appSessionHdl);

    if (!tlscon)
    {
        status = ERR_EAP_TLS_SESSION_NOT_FOUND;
        goto exit;
    }
    DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TLSSendData: Connection Instance ", (sbyte4)tlscon->tls_connection);

    *eapRespLen = 0;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Encrypting data Length ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4)len);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

    status = SSL_ASYNC_sendMessage(tlscon->tls_connection, (sbyte *)data, len,&length);

    /* If Error is ERR_SSL_SEND_BUFFER_NOT_EMPTY  then the app should retry
     * sending this buffer as the pending data was what is presented
     * to the app currently
     */
    if (((OK > status) && (ERR_SSL_SEND_BUFFER_NOT_EMPTY != status)) || (0 == length))
        goto exit;

    /* Get actual number in buffer using special use case */
    length = 0;
    if (OK > (status = SSL_ASYNC_getSendBuffer(tlscon->tls_connection, NULL, (ubyte4 *) &length)))
    {
        goto exit;
    }

    *eapRespLen = length;
    eapResponse = (ubyte *) MALLOC(*eapRespLen);
    if(NULL == eapResponse)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = SSL_ASYNC_getSendBuffer(tlscon->tls_connection,(eapResponse), eapRespLen)))
    {
        goto exit;
    }

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Encrypted data Length ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4)*eapRespLen);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

    *eapRespData = eapResponse;

exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TLSSendData: Error, status = ", (sbyte4)status);
        if (eapResponse)
            FREE(eapResponse);
    }

    return status;
}


/*------------------------------------------------------------------*/

/*! Get a new EAP-TLS session key.
This function generates an EAP-TLS session key and returns it (or $NULL$ if there's
no key) through the $key$ parameter.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_TLS__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_tls.h

\param tls_connection   EAP-TLS session handle returned from EAP_TLSCreateSession.
\param key              On return, pointer to the newly generated key.
\param keyLen           Length (number of bytes) of key to generate.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_TLSstartRequest
\sa EAP_TLSPeerStart
\sa EAP_TLSRecvData

*/
extern MSTATUS
EAP_TLSgetKey(ubyte *tls_connection ,ubyte *key,ubyte2 keyLen)
{
    eap_tlsCB *tlscon = (eap_tlsCB *)tls_connection;
    MSTATUS status;

    if (!tlscon)
    {
        status = ERR_EAP_TLS_SESSION_NOT_FOUND;
        goto exit;
    }


    status = SSL_generateTLSExpansionKey(tlscon->tls_connection,
                                      key,keyLen,(ubyte *)TLS_KEYING_PHRASE,
                                      TLS_KEYING_PHRASE_LEN);

exit:
    if (OK > status)
    {
        if (tlscon)
            DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TLSgetKey: Connection Instance ", (sbyte4)tlscon->tls_connection);
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TLSgetKey: Error, status = ", (sbyte4)status);
    }
    return status;
}

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSL_ALERTS__

/*! Build a TLS $Alert Messsage$ to be sent over EAP.
This function builds an EAP-TLS $Alert Message$ for the peer to send whenever
there is a TLS error.

\since 2.45
\version 2.45 and later

! Flags
To enable this function, the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_TLS__$
- $__ENABLE_DIGICERT_SSL_ALERTS__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_tls.h

\param tls_connection   EAP-TLS session handle returned from EAP_TLSCreateSession.
\param alertClass       Alert class ($SSLALERTLEVEL_WARNING$ or $SSLALERTLEVEL_FATAL$)
\param alertId          Alert ID.
\param length           Number of bytes in EAP-TLS message payload ($data$)
\param eapRespData      On return, pointer to EAP-TLS Alert Payload.
\param eapRespLen       On return, pointer to length of the Payload ($eapRespData$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_TLSstartRequest
\sa EAP_TLSPeerStart
\sa EAP_TLSSendData
\sa EAP_TLSRecvData

*/

extern MSTATUS
EAP_TLSformAlert(ubyte *tls_connection,sbyte4 alertClass,sbyte4 alertId,ubyte4 length, ubyte **eapRespData, ubyte4 *eapRespLen)
{
    ubyte4 alertLen;
    ubyte *eapResponse = NULL;
    eap_tlsCB* tlscon = (eap_tlsCB *)tls_connection;
    MSTATUS status = OK;

    if (!tlscon)
    {
        status = ERR_EAP_TLS_SESSION_NOT_FOUND;
        return status;
    }

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TLSformAlert: alertClass= ", alertClass);
    DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TLSformAlert: alertId= ", alertId);

    status = SSL_sendAlert(tlscon->tls_connection,
                           alertId,
                           alertClass);

    if(OK < status)
    {
        /* 5 Bytes 1 Byte Flag, 4 Bytes Length */
        *eapRespLen = status + 5;
        eapResponse = (ubyte *) MALLOC(*eapRespLen);

        if(NULL == eapResponse)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        *eapResponse = EAP_TLS_LENGTH_FLAG | tlscon->tlsVersion;
        DIGI_HTONL((ubyte *)&length,status);
        DIGI_MEMCPY((ubyte *)(eapResponse +1),(ubyte *)&length,4);
        tlscon->tls_data_send_remaining = 0;

        alertLen = *eapRespLen - 5;
        if (OK > (status = SSL_ASYNC_getSendBuffer(tlscon->tls_connection,(eapResponse+5),&alertLen)))
        {
            goto exit;
        }

        *eapRespData = eapResponse;
     }

exit:
    if (OK > status)
    {
        if (tlscon)
            DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TLSformAlert: Connection Instance ", (sbyte4)tlscon->tls_connection);
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TLSformAlert: Error forming Message, status = ", (sbyte4)status);
        if (eapResponse)
            FREE(eapResponse);
    }

    return status;

}

#endif

/*------------------------------------------------------------------*/
/*! Get the MTU (maximum transmission unit) value from the TLS control block.
This function retrieves the MTU (maximum transmission unit) value of an
EAP-TLS session.

\since 2.45
\version 2.45 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_TLS__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_tls.h

\param tls_connection   EAP-TLS session handle returned from EAP_TLSCreateSession.
\param setMTU           Pointer to allocated $ubyte$ that on return contains the MTU.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_TLSgetMTU(ubyte *tls_connection, ubyte *setMTU)
{
    eap_tlsCB* tlscon = (eap_tlsCB *)tls_connection;
    MSTATUS status = OK;

    if (!tlscon)
    {
        status = ERR_EAP_TLS_SESSION_NOT_FOUND;
        goto exit;
    }

    DIGI_MEMCPY(setMTU,(ubyte *)&tlscon->eapMTU,4);

exit:
   return status;
}
/*------------------------------------------------------------------*/

#endif /*(defined(__ENABLE_DIGICERT_EAP_TLS__)) */
#endif /* ((defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)) */
