/**
 * @file  radius.h
 * @brief RADIUS client core API
 *
 * @details    RADIUS client interface core definitions and functions
 * @since      1.41
 * @version    3.2 and later
 *
 * @flags      Whether the following flags are defined determines which definitions are enabled:
 *             + \c \__ENABLE_DIGICERT_RADIUS_CLIENT__
 *             + \c \__ENABLE_RFC3576__
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


/*------------------------------------------------------------------*/

#ifndef __RADIUS_HEADER__
#define __RADIUS_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#include "../common/mrtos.h"
#include "../crypto/hw_accel.h"

/*
 * freeradius by default splits auth from accounting servers into
 * separate UDP ports, so supporting multiple servers is probably
 * mandated.
 */

#ifndef RADIUS_CLEANUP_TIME_MS
#define RADIUS_CLEANUP_TIME_MS                  (60 * 1000)
#endif

#ifndef RADIUS_RETRY_INTERVAL_MS
#define RADIUS_RETRY_INTERVAL_MS                (2  * 1000)
#endif

#ifndef RADIUS_RETRY_COUNT
#define RADIUS_RETRY_COUNT                      3
#endif

#ifndef RADIUS_FAILOVER_COUNT
#define RADIUS_FAILOVER_COUNT                   3
#endif



#ifndef RADIUS_MAX_CONNECTIONS
#define RADIUS_MAX_CONNECTIONS                  16
#endif

/* If the Radius Server Does not respond for these many requests skip it */
#ifndef RADIUS_MAX_TIMES_SKIP
#define RADIUS_MAX_TIMES_SKIP                   256
#endif

/*
 * RADIUS_REQUEST_ALLOCATION can legally be between RADIUS_MIN_PKT_LEN (20)
 * and RADIUS_MAX_PKT_LEN (4096)
 */
#ifndef RADIUS_REQUEST_ALLOCATION
#define RADIUS_REQUEST_ALLOCATION               2000
#endif

#if ((4096 < RADIUS_REQUEST_ALLOCATION) || (20 > RADIUS_REQUEST_ALLOCATION))
#error RADIUS_REQUEST_ALLOCATION is out of bounds (20..4096)
#endif

/* User-modifiable defines are all above this point.*/

#define RADIUS_INVALID_SERVER_ID                (-1)

#define RADIUS_STANDARD_PORT                    1812

#define RADIUS_MIN_LEN                          3
#define RADIUS_MAX_LEN                          255
#define RADIUS_MIN_PKT_LEN                      20
#define RADIUS_MAX_PKT_LEN                      4096

#define RADIUS_CODE_FIELD_SIZE                  1
#define RADIUS_IDENTIFIER_FIELD_SIZE            1
#define RADIUS_LENGTH_FIELD_SIZE                2
#define RADIUS_AUTHENTICATOR_SIZE               16
#define RADIUS_CHAP_DIGESTSIZE                  (16)
#define RADIUS_MAX_PASSWORD_CHARS               128
#define RADIUS_CODE_OFFSET                      0
#define RADIUS_IDENTIFIER_OFFSET                (RADIUS_CODE_FIELD_SIZE)
#define RADIUS_LENGTH_OFFSET                    (RADIUS_CODE_FIELD_SIZE + RADIUS_IDENTIFIER_FIELD_SIZE)
#define RADIUS_AUTHENTICATOR_OFFSET             (RADIUS_CODE_FIELD_SIZE + RADIUS_IDENTIFIER_FIELD_SIZE + RADIUS_LENGTH_FIELD_SIZE)
#define RADIUS_ATTRIBUTES_OFFSET                (RADIUS_CODE_FIELD_SIZE + RADIUS_IDENTIFIER_FIELD_SIZE + RADIUS_LENGTH_FIELD_SIZE + RADIUS_AUTHENTICATOR_SIZE)

#define RADIUS_ATTRIBUTE_TYPE_SIZE              1
#define RADIUS_ATTRIBUTE_LENGTH_SIZE            1
#define RADIUS_ATTRIBUTE_TYPE_PLUS_LEN_SIZE     (RADIUS_ATTRIBUTE_TYPE_SIZE + RADIUS_ATTRIBUTE_LENGTH_SIZE)

#define RADIUS_ATTRIBUTE_TYPE_OFFSET            0
#define RADIUS_ATTRIBUTE_LENGTH_OFFSET          1
#define RADIUS_ATTRIBUTE_DATA_OFFSET            2

#define RADIUS_IS_ACCOUNTING_REQUEST_CODE(x) (RADIUS_CODE_ACCOUNTING_REQUEST == *((ubyte*)(x)))
#define RADIUS_IS_AUTH_REQUEST_CODE(x) (RADIUS_CODE_ACCESS_REQUEST == *((ubyte*)(x)))

/* RADIUS PACKET CODES */
#define RADIUS_CODE_ACCESS_REQUEST              1
#define RADIUS_CODE_ACCESS_ACCEPT               2
#define RADIUS_CODE_ACCESS_REJECT               3
#define RADIUS_CODE_ACCOUNTING_REQUEST          4
#define RADIUS_CODE_ACCOUNTING_RESPONSE         5
#define RADIUS_CODE_ACCESS_CHALLENGE            11

#define RADIUS_CODE_DISCONNECT_REQUEST          40
#define RADIUS_CODE_DISCONNECT_ACK              41
#define RADIUS_CODE_DISCONNECT_NAK              42
#define RADIUS_CODE_COA_REQUEST                 43
#define RADIUS_CODE_COA_ACK                     44
#define RADIUS_CODE_COA_NAK                     45

/* etc, as needed */
#define RADIUS_ATTR_USER_NAME                   1
#define RADIUS_ATTR_USER_PASSWORD               2
#define RADIUS_ATTR_CHAP_PASSWORD               3
#define RADIUS_ATTR_NAS_IP_ADDRESS              4
#define RADIUS_ATTR_NAS_PORT                    5
#define RADIUS_ATTR_SERVICE_TYPE                6
#define RADIUS_ATTR_FRAMED_PROTOCOL             7
#define RADIUS_ATTR_FRAMED_IP_ADDRESS           8
#define RADIUS_ATTR_FRAMED_IP_NETMASK           9
#define RADIUS_ATTR_FRAMED_ROUTING              10
#define RADIUS_ATTR_FILTER_ID                   11
#define RADIUS_ATTR_FRAMED_MTU                  12
#define RADIUS_ATTR_FRAMED_COMPRESSION          13
#define RADIUS_ATTR_LOGIN_IP_HOST               14
#define RADIUS_ATTR_LOGIN_SERVICE               15
#define RADIUS_ATTR_LOGIN_TCP_PORT              16
#define RADIUS_ATTR_REPLY_MESSAGE               18
#define RADIUS_ATTR_CALLBACK_NUMBER             19
#define RADIUS_ATTR_CALLBACK_ID                 20
#define RADIUS_ATTR_FRAMED_ROUTE                22
#define RADIUS_ATTR_FRAMED_IPX_NETWORK          23
#define RADIUS_ATTR_STATE                       24
#define RADIUS_ATTR_CLASS                       25
#define RADIUS_ATTR_VENDOR_SPECIFIC             26
#define RADIUS_ATTR_SESSION_TIMEOUT             27
#define RADIUS_ATTR_IDLE_TIMEOUT                28
#define RADIUS_ATTR_TERMINATION_ACTION          29
#define RADIUS_ATTR_CALLED_STATION_ID           30
#define RADIUS_ATTR_CALLING_STATION_ID          31
#define RADIUS_ATTR_NAS_IDENTIFIER              32
#define RADIUS_ATTR_PROXY_STATE                 33
#define RADIUS_ATTR_LOGIN_LAT_SERVICE           34
#define RADIUS_ATTR_LOGIN_LAT_NODE              35
#define RADIUS_ATTR_LOGIN_LAT_GROUP             36
#define RADIUS_ATTR_FRAMED_APPLETALK_LINK       37
#define RADIUS_ATTR_FRAMED_APPLETALK_NETWORK    38
#define RADIUS_ATTR_FRAMED_APPLETALK_ZONE       39

#define RADIUS_ATTR_ACCT_STATUS_TYPE            40
#define RADIUS_ATTR_ACCT_DELAY_TIME             41
#define RADIUS_ATTR_ACCT_INPUT_OCTETS           42
#define RADIUS_ATTR_ACCT_OUTPUT_OCTETS          43
#define RADIUS_ATTR_ACCT_SESSION_ID             44
#define RADIUS_ATTR_ACCT_ACCT_AUTHENTIC         45
#define RADIUS_ATTR_ACCT_SESSION_TIME           46
#define RADIUS_ATTR_ACCT_INPUT_PACKETS          47
#define RADIUS_ATTR_ACCT_OUTPUT_PACKETS         48
#define RADIUS_ATTR_ACCT_TERMINATE_CAUSE        49
#define RADIUS_ATTR_ACCT_MULTI_SESSION_ID       50
#define RADIUS_ATTR_ACCT_LINK_COUNT             51
#define RADIUS_ATTR_ACCT_INPUT_GIGAWORDS        52
#define RADIUS_ATTR_ACCT_OUTPUT_GIGAWORDS       53
#define RADIUS_ATTR_ACCT_EVENT_TIMESTAMP        55

#define RADIUS_ATTR_CHAP_CHALLENGE              60
#define RADIUS_ATTR_NAS_PORT_TYPE               61
#define RADIUS_ATTR_PORT_LIMIT                  62
#define RADIUS_ATTR_LOGIN_LAT_PORT              63

#define RADIUS_ATTR_TUNNEL_PASSWORD             69

#define RADIUS_ATTR_EAP_MESSAGE                 79
#define RADIUS_ATTR_MESSAGE_AUTHENTICATOR       80

#define RADIUS_ATTR_NAS_IP_ADDRESS_LENGTH       4
#define RADIUS_ATTR_NAS_PORT_LENGTH             4
#define RADIUS_ATTR_ACCT_STATUS_TYPE_LENGTH     4

#define RADIUS_ACCT_STATUS_TYPE_START           1
#define RADIUS_ACCT_STATUS_TYPE_STOP            2
#define RADIUS_ACCT_STATUS_TYPE_INTERIM_UPDATE  3
#define RADIUS_ACCT_STATUS_TYPE_ACCOUNTING_ON   7
#define RADIUS_ACCT_STATUS_TYPE_ACCOUNTING_OFF  8

/* etc, as needed */
#define RADIUS_ATTR_VENDOR_ID_FIELD_LENGTH      4
#define VENDOR_SPECIFIC_ATTR_MEM_SIZE           255

#ifdef __ENABLE_DIGICERT_DIAMETER_PEER__

#define DIAMETER_AVP_HOST_IP_ADDRESS            257
#define DIAMETER_AVP_AUTH_APPLICATION_ID        258
#define DIAMETER_AVP_ACCT_APPLICATION_ID        259
#define DIAMETER_AVP_VENDOR_APPLICATION_ID      260
#define DIAMETER_AVP_REDIRECT_HOST_USAGE        261
#define DIAMETER_AVP_REDIRECT_MAX_CACHE_TIME    262
#define DIAMETER_AVP_SESSION_ID                 263
#define DIAMETER_AVP_ORIGIN_HOST                264
#define DIAMETER_AVP_SUPPORTED_VENDOR_ID        265
#define DIAMETER_AVP_VENDOR_ID                  266
#define DIAMETER_AVP_FIRMWARE_VERSION           267
#define DIAMETER_AVP_RESULT_CODE                268
#define DIAMETER_AVP_PRODUCT_NAME               269
#define DIAMETER_AVP_SESSION_BINDING            270
#define DIAMETER_AVP_SESSION_SERVER_FAILOVER    271
#define DIAMETER_AVP_MULTI_ROUND_TIME_OUT       272
#define DIAMETER_AVP_DISCONNECT_CAUSE           273
#define DIAMETER_AVP_AUTH_REQUEST_TYPE          274

#define DIAMETER_AVP_AUTH_GRACE_PERIOD          276
#define DIAMETER_AVP_AUTH_SESSION_STATE         277
#define DIAMETER_AVP_ORIGIN_STATE_ID            278
#define DIAMETER_AVP_FAILED_AVP                 279
#define DIAMETER_AVP_PROXY_HOST                 280
#define DIAMETER_AVP_ERROR_MESSAGE              281
#define DIAMETER_AVP_ROUTE_RECORD               282
#define DIAMETER_AVP_DESTINATION_REALM          283
#define DIAMETER_AVP_PROXY_INFO                 284
#define DIAMETER_AVP_RE_AUTH_REQUEST_TYPE       285


#define DIAMETER_AVP_AUTHORIZATION_LIFETIME     291
#define DIAMETER_AVP_REDIRECT_HOST              292
#define DIAMETER_AVP_DESTINATION_HOST           293
#define DIAMETER_AVP_ERROR_REPORTING_HOST       294
#define DIAMETER_AVP_TERMINATION_CAUSE          295
#define DIAMETER_AVP_ORIGIN_REALM               296
#define DIAMETER_AVP_EXPERIMENTAL_RESULT        297
#define DIAMETER_AVP_EXPERIMENTAL_RESULT_CODE   298
#define DIAMETER_AVP_INBAND_SECURITY_ID         299
#define DIAMETER_AVP_E2E_SEQUENCE               300


#endif /* __ENABLE_DIGICERT_DIAMETER_PEER__ */

/* For extended attributes, which use the vendor-specific
 * attribute. It does not appear that there is a current
 * internet draft for extended atributes so this may
 * need to change. */
#define RADIUS_EXTENDED_ATTR_VENDOR_ID          0

/* RFC 2548 */
#define RADIUS_VENDOR_ID_MS                     311
#define RADIUS_ATTR_MSCHAP_RESPONSE             1
#define RADIUS_ATTR_MSCHAP_ERROR                2
#define RADIUS_ATTR_MSCHAP_NT_ENC_PW            6
#define RADIUS_ATTR_MSCHAP_CHALLENGE            11
#define RADIUS_ATTR_MSCHAPV2_RESPONSE           25
#define RADIUS_ATTR_MSCHAPV2_SUCCESS            26
#define RADIUS_ATTR_MSCHAPV2_MPPE_SEND_KEY      16
#define RADIUS_ATTR_MSCHAPV2_MPPE_RECV_KEY      17

#define RADIUS_INSTANCE_ID_START    1
#define RADIUS_INSTANCE_ID_END      64
#define RADIUS_SERVER_ID_START    101
#define RADIUS_SERVER_ID_END      164


#define RADIUS_SERVER_DOWN    0
#define RADIUS_SERVER_UP      1


/*------------------------------------------------------------------*/

/** @private @internal */
typedef enum RADIUS_RESULT
{
    RADIUS_FOUND                = 0,
    RADIUS_NOT_FOUND            = 1,
    RADIUS_RETRIES_EXCEEDED     = 2,
    RADIUS_FAILOVER             = 3,
    RADIUS_MAX_SKIP_EXCEEDED    = 4,
    RADIUS_ERROR                = -1

} RADIUS_RESULT;

/** @private @internal */
typedef enum
{
    RADIUS_STATE_UNINITIALIZED  = 0,
    RADIUS_STATE_INITIALIZED

} RADIUS_STATE;

/** @private @internal */
typedef enum
{
    RADIUS_LB_NONE  = 0,
    RADIUS_LB_ROUNDROBIN,
    RADIUS_LB_FIRST_AVAILABLE,
    RADIUS_LB_PRIMARY_SECOND

} RADIUS_LB_ALGO;

/** @private @internal */
typedef struct
{
    ubyte4  txPacket;
    ubyte4  txFails;
    ubyte4  txRetries;
    ubyte4  txSkips;

    ubyte4  rxGoodPacket;
    ubyte4  rxBadCode;
    ubyte4  rxBadLength;
    ubyte4  rxBadAttributes;
    ubyte4  rxBadAuthenticator;

} RADIUS_Counters;

/** @private @internal */
typedef struct RADIUS_Attribute
{
    ubyte           id;
    ubyte           length;
    ubyte*          value; /* maybe this should be [] */

} RADIUS_Attribute;


/** @private @internal */
typedef struct RADIUS_RqstRecord
{
    intBoolean  inUse;

    sbyte4      serverID;
    sbyte4      serverSrcPortNum;
    ubyte2      rqstLength;
    ubyte*      rqstData;
    ubyte2      rspLength;
    ubyte*      rspData;
    sbyte4      sentCount;
    intBoolean  rspAuthenticated;
    intBoolean  retriesExceeded;
#if (defined( __ENABLE_RFC3576__) || defined(__ENABLE_RADIUS_SERVER__))
    ubyte2      recvPort;    /* if != 0, indicates the request was received */
    ubyte2      interfaceNum;
#endif
    void*       userCookie;
    ubyte4      requestId;
    /* related to Multiserver Support */
    sbyte4      timesChangedServer;

} RADIUS_RqstRecord;


/**
@brief      Configuration settings and callback function pointers for RADIUS
            %clients.
@details    This structure is used for RADIUS %Client configuration. Each
            callback function should be customized for your application and then
            registered by assigning it to the appropriate structure function
            pointer(s).

@since 1.41
@version 3.06 and later

@flags
No flag definitions are required to use this structure.

*/
typedef struct RADIUS_Config
{
/**
@brief      Initialize a UDP connection.
@details    This callback initializes a UDP connection to the specified
            RADIUSserver, and returns a unique cookie (through the \p ppUDPCookie
            parameter) containing the platform-specific data necessary to
            communicate with the %server. This function should be called once
            for each RADIUS %server to which your RADIUS Client will connect.

@ingroup    radius_callback_functions

@since 1.41
@version 1.41 and later

@flags
No flag definitions are required to use this callback.

@param srcAddress           IP address to use as the source identifier when
                            sending a UDP datagram.
@param pServerIPAdress      String representation of the RADIUS server's IP
                            address.
@param serverPort           Listen port of the RADIUS %server.
@param ppUDPCookie          On return, pointer to cookie containing the
                            platform-specific data necessary to communicate
                            with the RADIUS %server.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
static sbyte4
radius_EXAMPLE_UDPInit(MOC_IP_ADDRESS srcAddress,
                       sbyte *serverIPAdress, ubyte2 serverPort,
                       void **ppUDPCookie)
{
    MOC_IP_ADDRESS dstAddress;
    MSTATUS        status;

    if (OK > (status = UDP_getAddrOfHost(serverIPAdress, &dstAddress)))
        goto exit;

    status = UDP_connect(ppUDPCookie,
                      srcAddress, MOC_UDP_ANY_PORT,
                      dstAddress, serverPort, 1);
exit:
    return status;
}
@endcode

@callbackdoc    radius.h
*/
    sbyte4 (*funcPtrBindUDP)(MOC_IP_ADDRESS srcAddress, sbyte *pServerIPAdress, ubyte2 serverPort, void **ppUDPCookie);

/**
@brief      Send data.
@details    This callback sends the data to the %server associated with the
            specified cookie (\p pUDPCookie).

@ingroup    radius_callback_functions

@since 1.41
@version 1.41 and later

@flags
No flag definitions are required to use this callback.

@param pUDPCookie   Cookie containing the desired server's connection
                    information.
@param pData        Pointer to data to send.
@param dataLength   Number of bytes of data to send (\p pData).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
static MSTATUS radius_EXAMPLE_UDPSend(void *pUDPCookie,
                       ubyte *pData, ubyte4 dataLength)
{
    // for the example code, we simply call the UDP abstraction layer code
    return UDP_send(pUDPCookie, pData, dataLength);
}
@endcode

@callbackdoc    radius.h
*/
    sbyte4 (*funcPtrSendUDP)(void *pUDPCookie, ubyte *pData, ubyte4 dataLength);

/**
@brief      Read pending data.
@details    This callback reads any pending data from the %server associated
            with the specified cookie (\p pUDPCookie).

@ingroup    radius_callback_functions

@since 1.41
@version 1.41 and later

@flags
No flag definitions are required to use this callback.

@param pUDPCookie       Cookie containing the desired server's connection
                        information.
@param pData            Read buffer into which this function should store the
                        data it reads.
@param dataLength       Number of bytes in read buffer (\p pData).
@param pRetDataLength   On return, Number of bytes of received UDP datagram.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
static MSTATUS radius_EXAMPLE_UDPPoll(void *pUDPCookie,
                       ubyte *pData, ubyte4 dataLength,
                       ubyte4 *pRetDataLength)
{
    // for the example code, we simply call the UDP abstraction layer code
    return UDP_recv(pUDPCookie, pData, dataLength, pRetDataLength);
}
@endcode

@callbackdoc    radius.h
*/
    sbyte4 (*funcPtrPollUDP)(void *pUDPCookie, ubyte *pData, ubyte4 dataLength, ubyte4 *pRetDataLength);

/**
@brief      Close the server connection and free memory.
@details    This callback closes the connection to the %server associated with
            the specified cookie (\p pUDPCookie) and then free any memory
            allocated for the original bind. It should be called once for each
            RADIUS %server.

@ingroup    radius_callback_functions

@since 1.41
@version 1.41 and later

@flags
No flag definitions are required to use this callback.

@param ppUDPCookie      Pointer to the address of the cookie containing the
                        desired %server's connection information.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
static MSTATUS radius_EXAMPLE_UnbindUDP(void **ppUDPCookie)
{
    return UDP_unbind(ppUDPCookie);
}
@endcode

@callbackdoc    radius.h
*/
    sbyte4 (*funcPtrUnBindUDP)(void **ppUDPCookie);

/**
@brief      Alert the user to failed retransmission.
@details    This callback alerts the user to a failed retransmission. Typical
            usage is to inform an application that a RADIUS send request has
            timed out.

@ingroup    radius_callback_functions

@since 2.02
@version 2.02 and later

@flags
No flag definitions are required to use this callback.

@param pUserCookie  User-specific cookie data; set by calling
                    RADIUS_setRequestUserCookie.
@param result       Reason for the failure: one of the \c RADIUS_RESULT
                    enumerated values (defined in radius.h).
@param pRqst        Pointer to RADIUS request for which this callback has been
                    invoked.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    radius.h
*/
    sbyte4 (*funcPtrRadiusInd)(ubyte *pUserCookie, RADIUS_RESULT result,RADIUS_RqstRecord *pRqst);

/**
@brief      Failover to a backup %server.
@details    This callback function is invoked to failover to a backup %server if
            the number of retries to send a RADIUS request exceeds the \c
            radiusFailoverCount value. Once called, this callback function
            should set the RADIUS server record's \c calledFailoverInd field
            value to \c TRUE, preventing the callback from being invoked again
            until the \c calledFailoverInd is reset to \c FALSE.

@ingroup    radius_callback_functions

@since 2.02
@version 2.02 and later

@flags
No flag definitions are required to use this callback.

@param pUserCookie  Pointer to user-provided cookie.
@param result       \c RADIUS_FAILOVER (one of the \c RADIUS_RESULT enumerated
                    values, defined in radius.h).
@param serverId     ID of the server that failed.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     You should define and customize this callback function if you want
            the ability to failover to a backup server.

@callbackdoc    radius.h
*/
    sbyte4 (*funcPtrRadiusFailoverInd)(ubyte *pUserCookie, RADIUS_RESULT result,sbyte4 serverId);

/**
@brief      Rebuild a RADIUS request.
@details    This callback rebuilds a RADIUS request in response to a failover to
            a backup RADIUS server that has a different shared secret from the
            primary server. This callback should update the request data's
            server ID and port values as specified in the passed-in \p pRqst
            header, per the new shared secret.

@ingroup    radius_callback_functions

@since 2.02
@version 2.02 and later

@flags
No flag definitions are required to use this callback.

@param pRqst        Pointer to the original failed request, with the ID and port
                    number updated to reflect the new server (originally the
                    backup server).
@param serverId     ID of the new (formerly backup) server to which the request
                    will be sent.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    radius.h
*/
    sbyte4 (*funcPtrRadiusRebuildReq)(RADIUS_RqstRecord *pRqst,sbyte4 serverId);

/**
@brief      Number of milliseconds between retries.
@details    Number of milliseconds between retries (default = \c
            RADIUS_RETRY_INTERVAL_MS).
*/
    ubyte4 radiusRetryIntervalMS;       /* default RADIUS_RETRY_INTERVAL_MS */
/**
@brief      Number of times to retry before before setting the status to failed.
@details    Number of times to retry before before setting the status to failed
            (default = \c RADIUS_RETRY_COUNT).
*/
    ubyte4 radiusRetryCount;            /* default RADIUS_RETRY_COUNT */
/**
@brief      Number of request retries before switching to any configured backup
            RADIUS server.
@details    Number of request retries (default = \c RADIUS_FAILOVER_COUNT) before
            switching to any configured backup RADIUS server. You can provide a
            callback to handle transactions with additional RADIUS servers when
            a transaction fails more than \c RADIUS_FAILOVER_COUNT times. For
            more information, refer to {Support for Multiple AAA Servers and
            Failure Recovery}, described in RFC&nbsp;3169:
            http://www.faqs.org/rfcs/rfc3169.html.
*/
    ubyte4 radiusFailoverCount;         /* default RADIUS_FAILOVER_COUNT */

/**
@brief      Hardware acceleration context to initialize.
@details    Hardware acceleration context to initialize. (Applicable only with
            Mocana hardware acceleration)
*/
    hwAccelDescr    hwAccelCtx;

/**
@brief      Number of addresses specified in the interfaceArrayPtr array.
@details    Number of addresses specified in the interfaceArrayPtr array.
*/
    ubyte4            numInterfaces;
/**
@brief      Array of network interfaces (IP addresses or host names).
@details    Array of network interfaces (IP addresses or host names) that the
            RADIUS %client should bind to while listening for
            RFC&nbsp;3576-specific requests (such as COA). You can specify
            0.0.0.0 or provide an array of interface addresses (such as
            192.x.x.x, 10.x.x.x, eth0).
*/
    MOC_IP_ADDRESS    *interfaceArrayPtr;

/* Related to Load Balancing Schemes for  Multiserver Environment */
/**
@brief      Load balancing algorithm to use for this instance.
@details    Load balancing Algorithm to use for this instance.
*/
    RADIUS_LB_ALGO    loadBalAlgo;

/**
@brief      Number of times a server can fail to reply before it is marked to be
            skipped.
@details    Number of times a server can fail to reply before it is declared to
            be non-functional, and therefore marked to be skipped. (Skipped
            servers are not returned by the RADIUS_getNextServer function.)
*/
    ubyte4            maxSkipCounter;

} RADIUS_Config;

/** @private @internal */
typedef struct RADIUS_ServerSrcPortRec
{
  struct RADIUS_ServerSrcPortRec *next;
  sbyte4 srcPortNum;
  ubyte2 srcPort;
  void* udpInfo;/* set by funcPtrBindUDP code (should be called pUDPCookie) */
  void* idMap;
} RADIUS_ServerSrcPortRec;

struct redBlackTreeDescr;

/** @private @internal */
typedef struct RADIUS_ServerRecord
{
    sbyte4                   serverId;
    MOC_IP_ADDRESS_S         srcAddr;
    sbyte*                   pServerName;
    MOC_IP_ADDRESS_S         serverAddress;
    sbyte4                   port;
    ubyte*                   sharedSecret;
    ubyte4                   sharedSecretLength;
    RADIUS_Counters          counters;
    sbyte4*                  backupServerIdPtr;
    ubyte4                   numBackupServers;
    ubyte4                   backupServerIndex;
    sbyte4                   serverStatus;
    ubyte                    calledFailoverInd;
    ubyte                    sendToBackup;
    ubyte4                   numSrcPorts;
    ubyte4                   whichServerSrcPort;
    RADIUS_ServerSrcPortRec  *srcPortListHead;
    const RADIUS_Config      *cfgPtr;
    sbyte4                   radiusInstanceId;
    /*allocated requests are in this tree till released. */
    struct redBlackTreeDescr *requestTree;
    /* Related to Load Balancing Schemes for  Multiserver Environment */
    ubyte4                   skipCounter;

} RADIUS_ServerRecord;

/** @private @internal */
typedef struct RADIUS_Instance
{
    sbyte4           instanceId;
    ubyte4           instRef;
    RADIUS_Config    config;
    ubyte*           retryTimer;
    struct redBlackTreeDescr* serverTree;
    sbyte4           *lastUsedServerID;
    sbyte4           totalServers;
    sbyte4           availableServers;
#ifdef __ENABLE_RFC3576__
    void**           pUDPRecv; /* RFC3576 -> to receive/send CoA and DM messages from serverS */
#endif
#ifdef __ENABLE_RADIUS_SERVER__
    void**           pUDPServerRecv; /* to receive/send Messages from Clients */
#endif

} RADIUS_Instance;


/** @private @internal */
typedef struct RADIUS_Globals
{
    struct redBlackTreeDescr*   instanceTree;
    ubyte*                      instanceIdMap;
    RTOS_MUTEX                  instanceTreeMutex;
    ubyte4                      numInstances;
    struct redBlackTreeDescr*   serverTree;
    ubyte*                      serverIdMap;
    RTOS_MUTEX                  serverTreeMutex;
    ubyte4                      numServers;
    hwAccelDescr                hwAccelCtx;

} RADIUS_Globals;

/*------------------------------------------------------------------*/

/*
 * clients must set
 * funcPtrUDPListen, funcPtrSendUDP, funcPtrPollUDP, funcPtrUDPClose
 * in gRADIUS_globals before calling RADIUS_init().
 */
/** @private @internal */
MOC_EXTERN RADIUS_Globals gRADIUS_globals;

/*------------------------------------------------------------------*/
/*
 * It is unlikely you will need to use these routines, but you may do
 * so in order to retrieve the raw data of the request/response.
 */

/**
@brief      Get a pointer to a response's raw data.
@details    This function returns a pointer to a request/response record's
            response data (exclusive of the corresponding request and all header
            data). Typically your application will not need to use this
            function, but it is provided to enable retrieval of message's raw
            data.

@ingroup    radius_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@param pRequest     Pointer to request/response record containing desired data.

@return     Pointer to the response record's \c rspData field; \c NULL if
            specified request is \c NULL.

@funcdoc    radius.h
*/
MOC_EXTERN ubyte* RADIUS_getRequestResponseBuffer(RADIUS_RqstRecord *pRequest);

/**
@brief      Get the length of a response's raw data.
@details    This function returns the length of a request/response record's
            response data (exclusive of the corresponding request and all header
            data). Typically your application will not need to use this
            function, but it is provided to enable retrieval of message's raw
            data.

@ingroup    radius_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@param pRequest     Pointer to request/response record containing desired data.

@return     Pointer to the response record's \c rspLength field; 0 if specified
            request is \c NULL.

@funcdoc    radius.h
*/
MOC_EXTERN ubyte2 RADIUS_getRequestResponseBufferLength(RADIUS_RqstRecord *pRequest);

/**
@brief      Get a pointer to a requests's raw data.
@details    This function returns a pointer to a request/response record's
            request data (exclusive of the corresponding response and all header
            data). Typically your application will not need to use this
            function, but it is provided to enable retrieval of message's raw
            data.

@ingroup    radius_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@param pRequest     Pointer to request/response record containing desired data.

@return     Pointer to the request record's \c rqstData field; \c NULL if
            specified request is \c NULL.

@funcdoc    radius.h
*/
MOC_EXTERN ubyte* RADIUS_getRequestRequestBuffer(RADIUS_RqstRecord *pRequest);

/**
@brief      Get the length of a request's raw data.
@details    This function returns the length of a request/response record's
            request data (exclusive of the corresponding response and all header
            data). Typically your application will not need to use this
            function, but it is provided to enable retrieval of message's raw
            data.

@ingroup    radius_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@param pRequest     Pointer to request/response record containing desired data.

@return     Pointer to the request record's \c rqstLength field; 0 if specified
            request is \c NULL.

@funcdoc    radius.h
*/
MOC_EXTERN ubyte2 RADIUS_getRequestRequestBufferLength(RADIUS_RqstRecord *pRequest);

/* Timer Tasks  to be called every 200-300 ms*/
/**
@brief      Check a RADIUS client's timer to provide time to the RADIUS stack.
@details    This function checks a RADIUS client's timer. Your application
            should call this function on every clock tick (every 300 to 500
            milliseconds) to provide time to the RADIUS stack.

@ingroup    radius_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@param instanceId   Virtual instance ID previously returned by
                    RADIUS_addInstance.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    radius.h
*/
MOC_EXTERN sbyte4 RADIUS_periodic(sbyte4 instanceId);

/* Use this to store data you want to retrieve later that's associated
 * with the request.
 */

/**
@brief      Save and associate data with a specific request.
@details    This function saves any data you want to associate with a specific
            request so that it can be retrieved at any time (by calling
            RADIUS_getRequestUserCookie).

@ingroup    radius_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@note       If you allocate memory in which to store the cookie, be sure to
            prevent memory leak by freeing the memory before releasing the
            request.

@inc_file radius.h

@param pRequest     Descriptor for a RADIUS authentication/accounting request.
@param pCookie      Pointer to the data to save as the cookie associated with
                    the specified request.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
static int radius_EXAMPLE_sendOne(int serverID, MOC_IP_ADDRESS addr, int cookie)
{
    int                 status = -1;
    RADIUS_RqstRecord*  pRqst;
    static const ubyte  papUserName[] = "johndoe", papPassword[] = "abcdwxyz";

    if (OK > (status = RADIUS_requestNew(&pRqst, serverID, RADIUS_CODE_ACCESS_REQUEST)))
        goto exit;

    RADIUS_setRequestUserCookie(pRqst, (void*)cookie);

    if (OK > (status = RADIUS_requestAppendStringAttribute(pRqst, RADIUS_ATTR_USER_NAME, (ubyte *)papUserName)))
        goto exit;
    if (OK > (status = RADIUS_requestAppendUserPassword(pRqst, (ubyte *)papPassword, sizeof(papPassword) - 1)))
        goto exit;
    if (addr)
    {
        if (OK > (status = RADIUS_requestAppendUByte4Attribute(pRqst, RADIUS_ATTR_NAS_IP_ADDRESS, addr)))
            goto exit;
    }
    if (OK > (status = RADIUS_requestSend(pRqst)))
        goto exit;

    status = OK;
exit:
    return status;
}
@endcode

@funcdoc    radius.h
*/
MOC_EXTERN sbyte4 RADIUS_setRequestUserCookie(RADIUS_RqstRecord *pRequest, void *pCookie);

/**
@brief      Get data saved from a previous request.
@details    This function retrieves data that was saved from a previous request
            (by a call to RADIUS_setRequestUserCookie).

@ingroup    radius_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@param pRequest     Descriptor for a RADIUS authentication/accounting request.

@return     Pointer to the request record's user cookie; 0 if specified request
            is \c NULL.

@code
    case RADIUS_FOUND:
        printf("Got a response\n");
        printf("Response %s authentication\n",
        RADIUS_responseIsAuthenticated(pRqst) ? "passed" : "failed");
        cookie = (unsigned long)RADIUS_getRequestUserCookie(pRqst);
        printf("Response Cookie: %lx\n", cookie);
        RADIUS_responseGetCode(pRqst, &code);
        printf("Response Code: %d\n", (int)code);

        RADIUS_requestRelease(pRqst);

        // fall through
@endcode

@funcdoc    radius.h
*/
MOC_EXTERN void *RADIUS_getRequestUserCookie(RADIUS_RqstRecord *pRequest);

/**
@brief      Retrieve the ID of the RADIUS server that sent a specific packet.
@details    This function retrieves the ID of the RADIUS server that sent a
            specific packet. First the UDP source port and address is extracted,
            and then the configured server ID is determined.

@ingroup    radius_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@param instanceId       Virtual instance ID to which this interface belongs;
                        previously returned from RADIUS_addInstance.
@param serverAddress    IP address of the RADIUS server from which the response
                        arrived.
@param serverPort       UDP source port on which the response arrived.
@param srcAddr          Local interface address on which the packet was
                        received.
@param serverID         On return, pointer to desired RADIUS server ID.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    radius.h
*/
MOC_EXTERN sbyte4
RADIUS_getServerIDFromAddrPort(sbyte4 instanceId,MOC_IP_ADDRESS serverAddress, ubyte2 serverPort,MOC_IP_ADDRESS srcAddr, sbyte4 *serverID);

/*
 * RADIUS_getAttributeByType
 *
 * Unlikely-to-be-used routine, mostly because
 * RADIUS_getResponseAttribute and RADIUS_requestGetAttributeByType
 * are more convenient.
 */
/**
@brief      Get the first attribute of the specified type from a data packet.
@details    This function evaluates the specified \p pPkt parameter's data and
            returns the first attribute it finds that matches the specified
            type.

@ingroup    radius_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@param pPkt         Pointer to packet data containing desired attribute.
@param pktLen       Number of bytes in \p pPkt.
@param type         Desired attribute's type (see @ref radius_attribute_types).
@param ppValue      On return, pointer to address of desired attribute's data.
@param pLength      On return, pointer to length of desired attribute's data.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
    if (NULL == (p = RADIUS_getRequestResponseBuffer(pRequest)))
    {
        status = ERR_RADIUS_NO_RESPONSE;
        goto exit;
    }

    length = RADIUS_getRequestResponseBufferLength(pRequest);

    status = RADIUS_getAttributeByType(p, length, type, ppValue, pLength);
@endcode

@funcdoc    radius.h
*/
MOC_EXTERN sbyte4 RADIUS_getAttributeByType(ubyte *pPkt, ubyte2 pktLen, ubyte type, ubyte **ppValue, ubyte *pLength);

/*
 * RADIUS_getAttributeByIndex
 *
 * Unlikely-to-be-used routine, mostly because
 * RADIUS_getResponseAttribute and RADIUS_requestGetAttributeByType
 * are more convenient.
 */
/**
@brief      Get the specified attribute from a data packet.
@details    This function evaluates the specified \p pPkt parameter's data and
            returns the zero-based index attribute through the \p ppValue
            parameter, along with its length (through the \p pLength parameter)
            and type (through the \p pType parameter).

@ingroup    radius_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@param pPkt         Pointer to packet data containing desired attribute.
@param pktLen       Number of bytes in \p pPkt.
@param index        Zero-based index of desired attribute.
@param pType        On return, pointer to desired attribute's type (see
                    @ref radius_attribute_types).
@param ppValue      On return, pointer to address of desired attribute's data.
@param pLength      On return, pointer to length of desired attribute's data.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
    while (!done)
    {
        status = RADIUS_getAttributeByIndex(pData, pLength, i, &type, &pVal, &len);

        switch (status)
        {
            case ERR_INDEX_OOB:
                done = TRUE;
                break;

            case OK:
                if (RADIUS_ATTR_USER_PASSWORD != type)
                    if (OK > (status = RADIUS_requestAppendAttribute(pNewRequest, type, pVal, len)))
                        goto exit;
                break;

            default:
                goto exit;
        }

        i++;
    }
@endcode

@funcdoc    radius.h
*/
MOC_EXTERN sbyte4 RADIUS_getAttributeByIndex(ubyte *pPkt, ubyte2 pktLen, sbyte4 index, ubyte *pType, ubyte **ppValue, ubyte *pLength);

/*
 * RADIUS_getSubAttributeByIndex
 *
 * Call this ONLY on a Vendor-Specific attribute, and then only if you know the
 * attribute has subfields.
 */
/**
@brief      Get the specified subattribute from a data packet.
@details    This function evaluates the specified \p pAttr parameter's data and
            returns the zero-based index attribute through the \p ppSubValue
            parameter, along with its length (through the \p pSubLength
            parameter) and type (through the \p pSubType parameter).

@ingroup    radius_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@note       You should call this function only for vendor-specific attributes,
            and only if you know that the attribute has subfields (as determined
            by a call to RADIUS_attributeHasSubAttributes).
@note       If an invalid \p index is specified, \c ERR_INDEX_OOB is returned.

@inc_file radius.h

@param pAttr        Pointer to buffer containing desired subattribute.
@param attrLen      Number of bytes in \p pAttr.
@param index        Zero-based index of desired subattribute.
@param pSubType     On return, pointer to desired subattribute's type (see
                    @ref radius_attribute_types).
@param ppSubValue   On return, pointer to address of subattribute's data.
@param pSubLength   On return, pointer to length of subattribute's data.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
    if (RADIUS_attributeHasSubAttributes(pAttr, attrLength))
    {
        printf("Attribute has sub-attributes\n");
        done = FALSE;
        j = 0;

        while (!done)
        {
            if (OK == RADIUS_getSubAttributeByIndex(pAttr, attrLength, j, &subType, &pSubData, &subLength))
            {
                printf("    Sub-Attribute: #%d\n", j);
                printf("             Type: %d\n", (int)subType);
                printf("            Value: ");
                radius_printChars(pSubData, subLength);
                printf("\n");
                j++;
            }
            else
            {
                done = TRUE;
            }
        }
    }
@endcode

@funcdoc    radius.h
*/
MOC_EXTERN sbyte4 RADIUS_getSubAttributeByIndex(ubyte *pAttr, ubyte attrLen, sbyte4 index, ubyte *pSubType, ubyte **ppSubValue, ubyte *pSubLength);

/*
 * RADIUS_attributeHasSubAttributes
 *
 * Call this ONLY on a Vendor-Specific attribute.
 */
/**
@brief      Determine whether a vendor-specific attribute has any subattributes.
@details    This function determines whether a vendor-specific attribute has any
            subattributes.

@ingroup    radius_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@note       You should call this function only for vendor-specific attributes.

@inc_file radius.h

@param pAttr        Pointer to buffer containing attributes to evaluate.
@param attrLen      Number of bytes in \p pAttr.

@return     \c TRUE (1) if the vendor-specific attribute has any subattributes;
            otherwise \c FALSE (0).

@code
    if (OK == RADIUS_responseGetAttributeByIndexAsVendorSpecific(pRadiusReq, i, &vendorID, &pAttr, &attrLength))
    {
        printf("Vendor-Specific attribute\n");
        printf("Vendor ID: %d\n", vendorID);

        if (RADIUS_attributeHasSubAttributes(pAttr, attrLength))
        {
            printf("Attribute has sub-attributes\n");
            done = FALSE;
            j = 0;

            while (!done)
            {
                if (OK == RADIUS_getSubAttributeByIndex(pAttr, attrLength, j, &subType, &pSubData, &subLength))
                {
                    printf("    Sub-Attribute: #%d\n", j);
                    printf("             Type: %d\n", (int)subType);
                    printf("            Value: ");
                    radius_printChars(pSubData, subLength);
                    printf("\n");
                    j++;
                }
                else
                {
                    done = TRUE;
                }
            }
        }
        else
        {
            printf("Attribute has no sub-attributes\n");
        }
    }
@endcode

@funcdoc    radius.h
*/
MOC_EXTERN intBoolean RADIUS_attributeHasSubAttributes(ubyte *pAttr, ubyte2 attrLen);

/*
 * RADIUS_init
 *
 * Call this before you have invoked RADIUS_addServer() for the server(s)
 * to which  you want to communicate to initialize states and open the
 * communication channel(s).
 */
/**
@brief      Initialize RADIUS %client and open channels with all registered
            RADIUS servers.
@details    This function initializes NanoRADIUS %client states and opens
            communication channel(s) with all registered RADIUS servers (those
            added by calls to RADIUS_addServer).

@ingroup    radius_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@note       Be sure to call this function before any other RADIUS functions.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
    ++gMocanaAppsRunning;

    if ( OK == UDP_getIfAddr( sServerAddr, &addr))
    {
        if ( addr != ( 127 << 24) + 1) // localhost ?
        {
            if (OK > UDP_getIfAddr(NULL, &addr))
                addr = MOC_UDP_ANY_ADDR;  // not critical, but you may wish to customize
        }
        // otherwise also use localhost for the source address
    }

    RADIUS_EXAMPLE_InstallUpcalls();

    if (OK > (status = RADIUS_init()))
        goto exit;

    if ((OK > (status = RADIUS_addServer(addr, sServerAddr, portAuth, sharedSecret, sizeof(sharedSecret) - 1, &authServerID))) ||
        (OK > (status = RADIUS_addServer(addr, sServerAddr, portAcct, sharedSecret, sizeof(sharedSecret) - 1, &acctServerID))))
    {
        goto exit;
    }
@endcode

@funcdoc    radius.h
*/
MOC_EXTERN sbyte4 RADIUS_init(void);

/*
 * Call this when you are finished using the RADIUS client.
 */
/**
@brief      Shut down the RADIUS stack, release RADIUS servers, and release
            memory associated with the RADIUS Client.
@details    This function shuts down the RADIUS stack, calls
            RADIUS_releaseServer for each open server ID, and releases all
            memory associated with the RADIUS Client.

@ingroup    radius_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@return     None.

@code
    RADIUS_shutdown();
    --gMocanaAppsRunning;
@endcode

@funcdoc    radius.h
*/
MOC_EXTERN void RADIUS_shutdown(void);

/*
 * RADIUS_addInstance
 *
 * Add a radius client instance
 * Has to be passed a valid RADIUS_Config.
 * The instnaceId variable will have the instance id of the newly
 * created instance.
 * On error instanceId is undefined.
 */
/**
@brief      Add a RADIUS %client virtual instance.
@details    This function adds a RADIUS %client virtual instance, using the
            specified configuration settings.

@ingroup    radius_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@note       RADIUS server IDs are created for a particular virtual instance and
            cannot be shared by multiple virtual %client instances.

@param instanceId   On return, pointer to virtual instance ID.
@param config       Pointer to desired %client configuration settings and
                    callback function pointers.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa RADIUS_deleteInstance

@funcdoc    radius.h
*/
MOC_EXTERN sbyte4 RADIUS_addInstance(sbyte4 *instanceId, const RADIUS_Config *config);

/*
 * RADIUS_deleteInstance
 * Delete a radius client instance that was added using RADIUS_addInstance
 * method.
 */
/**
@brief      Delete a virtual RADIUS %client instance.
@details    This function deletes a virtual RADIUS %client instance (an instance
            previously created by RADIUS_addInstance), including freeing all its
            resources.

@ingroup    radius_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@param instanceId   Virtual instance ID previously returned by
                    RADIUS_addInstance.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa RADIUS_addInstance

@funcdoc    radius.h
*/
MOC_EXTERN sbyte4 RADIUS_deleteInstance(sbyte4 instanceId);

/*
 * RADIUS_addServer
 *
 * Use this routine BEFORE calling RADIUS_init in order to establish
 * to what RADIUS servers you will be communicating.
 */
/**
@brief      Register a server for the RADIUS %client to query or to send
            accounting data to.
@details    This function registers a server for the RADIUS %client to query or
            to send accounting data to. This function should be called for every
            server before using it in a call to the RADIUS_addBackupToServer
            function.

@ingroup    radius_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@param instanceId           Instance ID returned from an _initInstance call.
@param srcAddr              IP address to use as the source identifier when
                            sending a UDP datagram.
@param serverIPAddress      String representation of the RADIUS server's IP
                            address.
@param port                 UDP listen port of the RADIUS %server.
@param pSharedSecret        Shared secret required for authenticated RADIUS
                            server-client communication.
@param sharedSecretLength   Number of bytes in \p pSharedSecret.
@param retID                On return, ID of the RADIUS %server.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
    ++gMocanaAppsRunning;

    if ( OK == UDP_getIfAddr( sServerAddr, &addr))
    {
        if ( addr != ( 127 << 24) + 1) // localhost ?
        {
            if (OK > UDP_getIfAddr(NULL, &addr))
                addr = MOC_UDP_ANY_ADDR;  // not critical, but you may wish to customize
        }
        // otherwise also use localhost for the source address
    }

    RADIUS_EXAMPLE_InstallUpcalls();

    if (OK > (status = RADIUS_init()))
        goto exit;

    if ((OK > (status = RADIUS_addServer(addr, sServerAddr, portAuth, sharedSecret, sizeof(sharedSecret) - 1, &authServerID))) ||
        (OK > (status = RADIUS_addServer(addr, sServerAddr, portAcct, sharedSecret, sizeof(sharedSecret) - 1, &acctServerID))))
    {
        goto exit;
    }
@endcode

@funcdoc    radius.h
*/
MOC_EXTERN sbyte4 RADIUS_addServer(sbyte4 instanceId, MOC_IP_ADDRESS srcAddr, sbyte *serverIPAddress, sbyte4 port, ubyte* pSharedSecret, ubyte4 sharedSecretLength, sbyte4 *retID);

/*
 * RADIUS_updateServerSharedSecret
 *
 * Use this routine to change the Shared Secret of the Radius Server ID added
 * using RADIUS_addServer
 */
/**
@brief      Update (change) the shared secret used between a RADIUS %client and
            server.
@details    This function updates (changes) the shared secret used between a
            RADIUS %client and server.

@ingroup    radius_functions

@since 2.45
@version 2.45 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@param serverID             ID of the RADIUS server (returned by
                            RADIUS_addServer) of interest.
@param pSharedSecret        Pointer to new shared secret.
@param sharedSecretLength   Number of bytes in \p pSharedSecret.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    radius.h
*/
MOC_EXTERN sbyte4
RADIUS_updateServerSharedSecret( sbyte4 serverID,
                                 ubyte* pSharedSecret,
                                 ubyte4 sharedSecretLength);

/* RADIUS_addSrcPortForServer
 *
 *
 * This routine is used to add instances to an existing server added using
 * RADIUS_addServer.
 */
/**
@brief      Add a source port to a RADIUS server, effectively creating multiple
            server connections.
@details    This function adds a source port to a RADIUS server, effectively
            creating multiple server connections. By using this function, you
            can exceed the RADIUS protocol's 255 maximum for pending requests
            from a single %client.

@ingroup    radius_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@param serverId     ID of RADIUS server (returned by RADIUS_addServer) to
                    add a source port to.
@param pUDPCookie   On return, pointer to UDP connection cookie (containing a
                    file descriptor).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    radius.h
*/
MOC_EXTERN sbyte4 RADIUS_addSrcPortForServer(sbyte4 serverId, void **pUDPCookie);

/*
 * RADIUS_releaseServer
 *
 * Unlikely you will need to use this, but you may, to discontinue communicating
 * with a particular RADIUS server. If you need to reestablish contact with this
 * server you will have to call RADIUS_shutdown() and then RADIUS_addServer()
 * and RADIUS_init();
 */
/**
@brief      Discontinue communication with a RADIUS server.
@details    This function discontinues communication with the specified RADIUS
            server by removing it from the RADIUS Client's list of registered
            servers.

@ingroup    radius_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@param serverID     ID of the RADIUS server (returned by RADIUS_addServer) to
                    remove from server-%client communication.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
    returned error status, use the \c DISPLAY_ERROR macro.

@code
extern void RADIUS_shutdown(void)
{
    sbyte4                     i;
    RADIUS_RqstRecord*      pRqst;
    RADIUS_ServerRecord*    pServer;

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_RADIUS, &gRADIUS_globals.hwAccelCtx);

    for (i = RADIUS_MAX_CONNECTIONS, pRqst = gRqstRecords; i--; pRqst++)
        RADIUS_releaseRequest(pRqst);

    for (i = RADIUS_MAX_SERVERS, pServer = gRADIUS_globals.servers; i--; pServer++)
    {
        if (NULL == pServer->udpInfo)
            continue;

        (gRADIUS_globals.funcPtrUnBindUDP)(&pServer->udpInfo);
        RADIUS_releaseServer(SERVER_PTR_TO_ID(pServer));
    }
}
@endcode

@funcdoc    radius.h
*/
MOC_EXTERN sbyte4 RADIUS_releaseServer(sbyte4 serverID);

/*
 * RADIUS_addBackupToServer
 *
 * To add backup to a server. Both primary server and backup servers
 * must have been added using RADIUS_addServer() method.If adding more
 * than one backup server, backupId is the ptr to an array of backup
 * server ids.
 */
/**
@brief      Add one or more backup RADIUS servers to use in case the primary
            RADIUS server stops responding.
@details    This function adds one or more backup RADIUS servers to use in case
            the primary RADIUS server goes down (stops responding to queries).
            The primary and all backup servers must already have been added by a
            call to RADIUS_addServer. When it's necessary to make a switch to a
            backup server, the backup servers are tried in the order specified
            by the \p backupId parameter.

@ingroup    radius_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@param serverId     ID of primary RADIUS server (returned by RADIUS_addServer)
                    to add backup servers to.
@param backupId     Pointer to array of backup server IDs.
@param numBackup    Number of backup servers to add.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa RADIUS_modifyBackupToServer
@sa RADIUS_sendToBackup

@funcdoc    radius.h
*/
MOC_EXTERN sbyte4 RADIUS_addBackupToServer(sbyte4 serverId, sbyte4 *backupId, ubyte4 numBackup);


/*
 * RADIUS_modifyBackupToServer
 * Use this to change, delete and existing backup or add a new backup
 */
/**
@brief      Modify the list of backup RADIUS servers to use in case the primary
            RADIUS server stops responding.
@details    This function modifies the list of backup RADIUS servers to use in
            case the primary RADIUS server goes down (stops responding to
            queries). The primary and all backup servers must already have been
            added by a call to RADIUS_addServer.

@ingroup    radius_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@note       You can delete all entries from the backup list by specifying 0 for
            the \p numBackup parameter and \c NULL for the \p backupId.
@note       You can use this function even if the primary RADIUS server does not
            have any backup servers already configured.

@param serverId     ID of primary RADIUS server (returned by RADIUS_addServer)
                    to add backup servers to.
@param backupId     Pointer to array of backup server IDs.
@param numBackup    Number of backup servers to add.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa RADIUS_addBackupToServer
@sa RADIUS_sendToBackup

@funcdoc    radius.h
*/
MOC_EXTERN sbyte4 RADIUS_modifyBackupToServer(sbyte4 serverId, sbyte4 *backupId, ubyte4 numBackup);

/*
 * In some cases you will need to retrieve information about a server using the
 * server ID.
 */

/**
@brief      Get a server's information record.
@details    This function retrieves information about the specified server from
            its server record.

@ingroup    radius_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@param serverID     ID of the RADIUS server (returned by RADIUS_addServer) of
                    interest.
@param ppServer     On return, pointer to address of server's associated server
                    record.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    radius.h
*/
MOC_EXTERN sbyte4 RADIUS_getServerRecordFromID(sbyte4 serverID, RADIUS_ServerRecord **ppServer);

/**
@brief      Get a server's UDP cookie.
@details    This function retrieves information about the specified server from
            its server record UDP cookie.

@ingroup    radius_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@note       Most RADIUS Client implementations don't need to access this data
            outside of the UDP abstraction layer code.

@param serverID     ID of the RADIUS server (returned by RADIUS_addServer) of
                    interest.
@param ppUDPCookie  On return, pointer to the server record's UDP cookie, which
                    was created by the funcPtrBindUDP upcall.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    radius.h
*/
MOC_EXTERN sbyte4 RADIUS_getUDPCookieFromServerID(sbyte4 serverID, void **ppUDPCookie);


/*
 * RADIUS_NewVendorSpecificAttributeBuffer()
 */
/**
@brief      Create a custom subattribute buffer.
@details    This function creates a custom attribute buffer which can be
            appended as a subattribute to a request/response buffer's attribute
            data.

@ingroup    radius_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@note       To avoid memory leaks, be sure to free the resultant buffer by
            calling RADIUS_releaseVendorSpecificAttributeBuffer.

@param ppAttr   On return, pointer to address of buffer containing a copy of the
                attribute's data.
@param vendorID Application-specific ID that indicates the desired vendor.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
    // create/bind a custom attribute to the request
    if (OK > (status = RADIUS_newVendorSpecificAttributeBuffer(&pVSAttr, ciscoVendorID)))
        goto exit;

    if (OK > (status = RADIUS_appendSubAttributeToAttributeBuffer(pVSAttr,
                            1, subAttr1Str, (ubyte)DIGI_STRLEN((sbyte *)subAttr1Str))))
    {
        goto exit;
    }

    if (OK > (status = RADIUS_appendSubAttributeToAttributeBuffer(pVSAttr,
                            2, subAttr2Str, (ubyte)DIGI_STRLEN((sbyte *)subAttr2Str))))
    {
        goto exit;
    }

    if (OK > (status = RADIUS_requestAppendVendorSpecificAttributeBuffer(pRadiusReq, pVSAttr)))
        goto exit;

    // send the request
    status = RADIUS_requestSend(pRadiusReq);
@endcode

@funcdoc    radius.h
*/
MOC_EXTERN sbyte4 RADIUS_newVendorSpecificAttributeBuffer(ubyte **ppAttr, ubyte4 vendorID);

/*
 * RADIUS_AppendSubAttributeToAttributeBuffer()
 */
/**
@brief      Append a subattribute to a buffer.
@details    This function appends the specified subattribute to an attribute
            buffer that will be used in a RADIUS request record.

@ingroup    radius_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@param pAttr        On return, pointer to buffer containing appended
                    subattribute.
@param type         Value representing type of subattribute to add (see
                    @ref radius_attribute_types).
@param pData        Pointer to the buffer containing the subattribute data to
                    add.
@param dataLength   Number of bytes in \p pData (not the length of the
                    subattribute itself).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
    // create/bind a custom attribute to the request
    if (OK > (status = RADIUS_newVendorSpecificAttributeBuffer(&pVSAttr, ciscoVendorID)))
        goto exit;

    if (OK > (status = RADIUS_appendSubAttributeToAttributeBuffer(pVSAttr,
                            1, subAttr1Str, (ubyte)DIGI_STRLEN((sbyte *)subAttr1Str))))
    {
        goto exit;
    }

    if (OK > (status = RADIUS_appendSubAttributeToAttributeBuffer(pVSAttr,
                            2, subAttr2Str, (ubyte)DIGI_STRLEN((sbyte *)subAttr2Str))))
    {
        goto exit;
    }

    if (OK > (status = RADIUS_requestAppendVendorSpecificAttributeBuffer(pRadiusReq, pVSAttr)))
        goto exit;

    // send the request
    status = RADIUS_requestSend(pRadiusReq);
@endcode

@funcdoc    radius.h
*/
MOC_EXTERN sbyte4 RADIUS_appendSubAttributeToAttributeBuffer(ubyte *pAttr, ubyte type, ubyte *pData, ubyte dataLength);

/*
 * RADIUS_ReleaseVendorSpecificAttributeBuffer()
 */
/**
@brief      Free memory allocated for vendor-specific attribute management.
@details    This function frees memory allocated for vendor-specific attribute
            management (see RADIUS_newVendorSpecificAttributeBuffer).

@ingroup    radius_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@param pAttr    Pointer to buffer to free.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
    // create/bind a custom attribute to the request
    if (OK > (status = RADIUS_newVendorSpecificAttributeBuffer(&pVSAttr, ciscoVendorID)))
    goto exit;

    if (OK > (status = RADIUS_appendSubAttributeToAttributeBuffer(pVSAttr,
                            1, subAttr1Str, (ubyte)DIGI_STRLEN((sbyte *)subAttr1Str))))
    {
        goto exit;
    }

    if (OK > (status = RADIUS_appendSubAttributeToAttributeBuffer(pVSAttr,
                            2, subAttr2Str, (ubyte)DIGI_STRLEN((sbyte *)subAttr2Str))))
    {
        goto exit;
    }

    if (OK > (status = RADIUS_requestAppendVendorSpecificAttributeBuffer(pRadiusReq, pVSAttr)))
        goto exit;

    // send the request
    status = RADIUS_requestSend(pRadiusReq);

exit:
    if (NULL != pVSAttr)
        RADIUS_releaseVendorSpecificAttributeBuffer(pVSAttr);
@endcode

@funcdoc    radius.h
*/
MOC_EXTERN void RADIUS_releaseVendorSpecificAttributeBuffer(ubyte *pAttr);

/*
 * RADIUS_pollForResponse()
 *
 * You may call this routine with NULL or with a real pRequest.
 */
/**
@brief      Read response data for any request or a specific request.
@details    This function reads (receives) data corresponding to a specified
            request or for any requests, depending on the value you specify for
            the \p pRequest pointer:\n

- Valid, non-\c NULL &mdash;The value returned through \p pResult indicates
whether there is data available corresponding to the specified request.
- \c NULL &mdash;The function enables your RADIUS %client to read (receive) any
data (in which case \c RADIUS_FOUND is returned through \p pResult), and/or
retransmit unacknowledged requests (in which case \c RADIUS_FOUND or \c
RADIUS_NOT_FOUND is returned through \p pResult).

@ingroup    radius_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@param instanceId   Instance ID returned from an _initInstance call.
@param pRequest     \c NULL or descriptor for a RADIUS authentication/accounting
                    request.
@param pResult      On return, pointer to one of the following \c RADIUS_RESULT
                    values: \c RADIUS_NOT_FOUND, \c RADIUS_FOUND, \c
                    RADIUS_ERROR, or \c RADIUS_RETRIES_EXCEEDED. (None of the
                    other \c RADIUS_RESULT values will be returned.)

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
    while (pending)
    {
        RTOS_sleepMS(500);  // a select() or some other mechanism would be preferable to catch
                            // UDP packets for portability the example code does a simple sleep

        // give RADIUS time. Do not rely on "result" to determine if
        // data is available, because multiple packets might have been
        // read in previously, and result == RADIUS_FOUND only if
        // NEW data is read in.

        if (OK > (status = RADIUS_pollForResponse(NULL, &result)))
        {
            goto exit;
        }

        if (OK > (result = RADIUS_getAResponse(&pRadiusReq)))
        {
            status = ERR_RADIUS;
            goto exit;
        }

        switch (result)
        {
            ...
            default:
                goto exit;  // too odd to continue
        }

    } // while (pending)
@endcode

@funcdoc    radius.h
*/
MOC_EXTERN sbyte4 RADIUS_pollForResponse(sbyte4 instanceId, RADIUS_RqstRecord *pRequest, RADIUS_RESULT *pResult);

/* Retreive the Request based upon incoming Packet */
/**
@brief      Validate a response's authenticator and return the corresponding
            original request.
@details    This function validates a response's authenticator and returns the
            response's corresponding original request.

@ingroup    radius_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@param serverID ID of RADIUS server (returned by RADIUS_addServer).
@param srcPort  Response's UDP listen port field value.
@param pBuffer  Pointer to response data.
@param buflen   Number of bytes of response data (\p pBuffer).
@param pRqst    On return, pointer to response record containing the original
                request and the validated response.
@param pResult  On return, pointer to one of the following \c RADIUS_RESULT
                values: \c RADIUS_NOT_FOUND, \c RADIUS_FOUND, \c RADIUS_ERROR,
                or \c RADIUS_RETRIES_EXCEEDED. (None of the other \c
                RADIUS_RESULT values will be returned.)

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    radius.h
*/
MOC_EXTERN sbyte4 RADIUS_responseCallback(sbyte4 serverID ,ubyte2 srcPort, ubyte *pBuffer ,ubyte4 buflen ,RADIUS_RqstRecord **pRqst, RADIUS_RESULT* pResult );

/*
 * RADIUS_getResponseStatus()
 *
 * Returns whether or not a response has been received for the
 * request corresponding to pRequest. You MUST give time to
 * RADIUS by calling RADIUS_pollForResponse() if you ever hope to
 * get this routine to return RADIUS_FOUND (which means there is
 * a response to process).
 */
/**
@brief      Determine whether a response has been received for a request.
@details    This function determines whether a response has been received for
            the specified request, and returns the result as a \c RADIUS_RESULT
            value (see @ref radius_result_codes).

@ingroup    radius_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@param pRequest Descriptor for a RADIUS authentication/accounting request.

@return     One of the following \c RADIUS_RESULT values: \c RADIUS_NOT_FOUND,
            \c RADIUS_FOUND, or \c RADIUS_ERROR. (None of the other \c
            RADIUS_RESULT values will be returned.)

@note       Unless your %client code allocates time to the RADIUS processing by
            calling RADIUS_pollForResponse, no responses will ever be received,
            and the \c RADIUS_RESULT return value will never be \c RADIUS_FOUND.

@funcdoc    radius.h
*/
MOC_EXTERN RADIUS_RESULT RADIUS_getResponseStatus(RADIUS_RqstRecord *pRequest);

/*
 * RADIUS_getAResponse()
 *
 * Returns a Rqst ptr corresponding to a request for which a
 * response has been received. Notes for RADIUS_getResponseStatus about
 * supplying time to the RADIUS client using RADIUS_pollForResponse
 * apply to this routine as well.
 */
/**
@brief      Get a request pointer that corresponds to a request for which a
            response has been received.
@details    This function retrieves a request pointer that corresponds to a
            request for which a response has been received.

@ingroup    radius_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@param instanceId   Instance ID returned from an _initInstance call.
@param ppRequest    Pointer into which this function returns a RADIUS request
                    descriptor corresponding to a request for which a response
                    has been received.

@return     One of the following \c RADIUS_RESULT values: \c RADIUS_NOT_FOUND,
            \c RADIUS_FOUND, or \c RADIUS_ERROR. (None of the other \c
            RADIUS_RESULT values will be returned.)

@note       Unless your client code allocates time to the RADIUS processing by
            calling RADIUS_pollForResponse, no responses will ever be received,
            and the \c RADIUS_RESULT return value will never be \c RADIUS_FOUND.

@code
    while (pending)
    {
        RTOS_sleepMS(1);

        // give RADIUS time. Do not rely on "result" to determine if data is available
        // because multiple packets might have been read i npreviously, and
        // result == RADIUS_FOUND only if NEW data is read in.
        if (OK > (status = RADIUS_pollForResponse(NULL, &result)))
        {
            goto exit;
        }
        if (OK > (result = RADIUS_getAResponse(&pRadiusReq)))
        {
            status = ERR_RADIUS;
            goto exit;
        }

        switch (result)
        {
            case RADIUS_RETRIES_EXCEEDED:
                printf("Retries Exceeded.\n");
                if (OK == RADIUS_requestGetUsername(pRadiusReq, &nm, &nmLen))
                {
                    printf("request username: ");
                    radius_printChars(nm, nmLen);
                    printf("\n");
                }
                RADIUS_requestRelease(&pRadiusReq);
                pending--;
                break;
            case RADIUS_NOT_FOUND:
                continue;
        }
    }
@endcode

@funcdoc    radius.h
*/
MOC_EXTERN RADIUS_RESULT RADIUS_getAResponse(sbyte4 instanceId, RADIUS_RqstRecord **ppRequest);


/*
 * RADIUS_respondToAccessChallenge()
 *
 * pOriginalRequest is initial request that generated the challenge. A new
 * request will be generated by this routine, and a reference to it will
 * be contained in *ppNewRequest. On SUCCESSFUL return ppNewRequest is like any
 * other RADIUS request. On return pOriginalRequest is still valid. Most likely
 * you will want to immediately call RADIUS_requestRelease on it.
 */
/**
@brief      Generate a new request in response to a RADIUS server challenge.
@details    This function generates a new request in response to a RADIUS server
            challenge, which is itself a response to an initial request by the
            RADIUS Client (\p pOriginalRequest).\n
\n
On return, the \p ppNewRequest value points to a reference to the new request,
which in the case of a \c SUCCESSFUL return is typically another RADIUS request.
(The \p pOriginalRequest value is still valid, and typically you should
immediately call RADIUS_requestRelease for that request.)

@ingroup    radius_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@param pOriginalRequest Pointer to original %client request record.
@param ppNewRequest     On return, pointer to address of new request.
@param pResponse        Pointer to response buffer containing information to
                        complete the authentication.
@param responseLength   Number of bytes in response buffer (\p pResponse).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
static int radius_EXAMPLE_doChallenge(RADIUS_RqstRecord *pRequest)
{
    sbyte*              defaultPrompt = "Enter Response: ", prompt;
    char                pResponse[RADIUS_EXAMPLE_RESPONSE_MAX+1], *q;
    RADIUS_RqstRecord*  pNewRequest;

    if (OK != RADIUS_responseGetAttributeAsCString(pRequest, RADIUS_ATTR_REPLY_MESSAGE, &prompt))
        prompt = defaultPrompt;

    printf("%s\nType in your response: ", prompt);
    fgets(pResponse, RADIUS_EXAMPLE_RESPONSE_MAX, stdin);

    if (prompt != defaultPrompt)
        RADIUS_responseFreeString(&prompt);

    // get rid newline char(s) at end of response
    for (q = pResponse + DIGI_STRLEN(pResponse) - 1; q >= pResponse; q--)
    {
        if (*q <= ' ')    // kill trailing wsp and ctl chars too while at it
        {
            *q = 0;
        }
        else break;
    }

    return RADIUS_respondToAccessChallenge(pRequest, &pNewRequest, (ubyte*)pResponse, DIGI_STRLEN(pResponse));
}
@endcode

@funcdoc    radius.h
*/
MOC_EXTERN sbyte4 RADIUS_respondToAccessChallenge(RADIUS_RqstRecord *pOriginalRequest, RADIUS_RqstRecord **ppNewRequest, ubyte* pResponse, ubyte4 responseLength);

/*
 * RADIUS_pktValidate()
 *
 * This is actually done for you in RADIUS_pollForResponse(), before the
 * response gets attached to the request cookie, so there's probably
 * no reason to call it. Incidentally, it does NOT verify the
 * authenticator. This would require knowing what request it's a response
 * for.
 */
/**
@brief      Verify that a packet contains a properly formatted RADIUS request.
@details    This function verifies that a packet contains a properly formatted
            RADIUS request, as specified by RFC&nbsp;2865.

@ingroup    radius_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@note       Typically you will not need to call this function because response
            packets are automatically validated by RADIUS_pollForResponse before
            the response is attached to the request cookie.
@note       This function does not verify the authenticator because doing so
            would require knowing this response's corresponding request.

@param pPkt     Pointer to packet to verify.
@param pktLen   Number of bytes in \p pPkt.
@param serverID ID of the RADIUS server (returned by RADIUS_addServer) for which
                the request was intended.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    radius.h
*/
MOC_EXTERN sbyte4 RADIUS_pktValidate(ubyte *pPkt, ubyte4 pktLen, sbyte4 serverID);

/*
 * RADIUS_getRequestRecordFromName()
 *
 * Returns the request cookie, if it matches one in our database, else
 * NULL.
 */
/**
@brief      Get a request matching the specified \c User-Name attribute.
@details    This function evaluates the requests/responses array and returns the
            first request it finds that contains an attribute matching the
            specified \c User-Name attribute. If no match is found, \c NULL is
            returned.

@ingroup    radius_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@note       The first match found is returned, regardless of whether there are
            additional matches in the requests/responses array.

@param pName    Desired name to match against the requests' \c User-Name
                attribute.
@param namelen  Number of bytes in \p pName.
@param serverID ID of the RADIUS server (returned by RADIUS_addServer) for which
                the request was intended.

@return     Pointer to the request record; \c NULL if no match found.

@funcdoc    radius.h
*/
MOC_EXTERN RADIUS_RqstRecord *RADIUS_getRequestRecordFromName(ubyte *pName, ubyte4 namelen, sbyte4 serverID);

/*
 * RADIUS_getCounters()
 *
 * Returns the stats counters to/from a particular server.
 */
/**
@brief      Get the statistics (counters) between the RADIUS Client and a server.
@details    This function retrieves the statistics (counters) for communication
            between the RADIUS Client and the specified server.

@ingroup    radius_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@param serverID     ID of the RADIUS server (returned by RADIUS_addServer for
                    which the statistics are requested.
@param pCounters    Pointer to valid, allocated memory into which this function
                    returns the counter results.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
    if (OK == RADIUS_getCounters(authServerID, &counters))
    {
        printf("Counters for auth server:\n");
        radius_EXAMPLE_printCounters(&counters);
    }

    if (OK == RADIUS_getAllCounters(&counters))
    {
        printf("Counters for all servers:\n");
        radius_EXAMPLE_printCounters(&counters);
    }
@endcode

@funcdoc    radius.h
*/
MOC_EXTERN sbyte4 RADIUS_getCounters(sbyte4 serverID, RADIUS_Counters *pCounters);

/*
 * RADIUS_getAllCounters()
 *
 * Returns the sum of all stats counters to/from all current RADIUS servers.
 */
/**
@brief      Get the sum of the statistics (counters) between the RADIUS Client
            and its registered servers.
@details    This function retrieves the sum of the statistics (counters) of
            communication between the RADIUS Client and all its currently
            registered servers.

@ingroup    radius_functions

@since 1.41
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@param instanceId   Instance ID returned from an _initInstance call.
@param pCounters    Pointer to valid, allocated memory into which this function
                    returns the counter results. (See RADIUS_Counters.)

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
    if (OK == RADIUS_getCounters(authServerID, &counters))
    {
        printf("Counters for auth server:\n");
        radius_EXAMPLE_printCounters(&counters);
    }

    if (OK == RADIUS_getAllCounters(&counters))
    {
        printf("Counters for all servers:\n");
        radius_EXAMPLE_printCounters(&counters);
    }
@endcode

@funcdoc    radius.h
*/
MOC_EXTERN sbyte4 RADIUS_getAllCounters(sbyte4 instanceId,RADIUS_Counters *pCounters);

/** @private @internal */
MOC_EXTERN void RADIUS_releaseRequest(RADIUS_RqstRecord *pRqst);

#if (defined( __ENABLE_RFC3576__) || defined(__ENABLE_RADIUS_SERVER__))

/*
 * RADIUS_pollForRequest()
 *
 * Returns the next Request received from the server
 */
/**
@brief      Get the next request received on any configured interface.
@details    This function retrieves the next request received on any of the
            interfaces configured to receive RFC&nbsp;3576 CoA
            (Change-of-Authorization) messages on port&nbsp;3799.

@ingroup    radius_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__
+ \c \__ENABLE_RFC3576__

@inc_file radius.h

@note       Be sure to call this function before registering the RADIUS servers.

@param instanceId   Instance ID returned from an _initInstance call.
@param ppRequest    On return, pointer to address of request record received.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
    if (OK > (status = RADIUS_pollForRequest(&pServerRequest)))
        goto exit;

    if  (pServerRequest )
    {
        ubyte responseCode;

        gotOne = 1;
        // process it and send a response
        // first step is to see if there is a forced response code
        if (OK > (status = RADIUS_responseForcedCode( pServerRequest, &responseCode)))
            goto exit;

        if (0 == responseCode)
        {
            // no forced response so we will sent ACK always in this example
            ...
        }

        // send a response with the response code
        if (OK > (status = RADIUS_responsePrepare( pServerRequest, responseCode)))
            goto exit;

        if (OK > (status = RADIUS_responseSend( pServerRequest)))
            goto exit;
    }

exit:
    if (pServerRequest)
    {
        RADIUS_requestRelease( &pServerRequest);
    }
@endcode

@funcdoc    radius.h
*/
MOC_EXTERN MSTATUS RADIUS_pollForRequest(sbyte4 instanceId,RADIUS_RqstRecord** ppRequest);

/*
 * RADIUS_responseForcedCode()
 *
 * For some messages, the response code MUST have a certain
 * code.
 */
/**
@brief      Get a response record's response code.
@details    This function extracts the response code from the specified response
            record and returns the response code through the \p
            forcedResponseCode parameter.

@ingroup    radius_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__
+ \c \__ENABLE_RFC3576__

@inc_file radius.h

@param pRqst                Pointer to response record.
@param forcedResponseCode   On return, pointer to response code.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
    if (OK > (status = RADIUS_responseForcedCode( pServerRequest, &responseCode)))
        goto exit;

    if (0 == responseCode)
    {
        // no forced response so we will sent ACK always in this example
        ubyte requestCode;
        if ( OK > (status = RADIUS_requestGetCode( pServerRequest, &requestCode)))
            goto exit;
        if (RADIUS_CODE_DISCONNECT_REQUEST == requestCode)
        {
            responseCode = RADIUS_CODE_DISCONNECT_ACK;
        }
        else if (RADIUS_CODE_COA_REQUEST  == requestCode)
        {
            responseCode = RADIUS_CODE_COA_ACK;
        }
        else
        {
            status = ERR_RADIUS_BAD_REQUEST;
            goto exit;
        }
    }

    // send a response with the response code
    if (OK > (status = RADIUS_responsePrepare( pServerRequest, responseCode)))
        goto exit;

    if (OK > (status = RADIUS_responseSend( pServerRequest)))
        goto exit;

exit:
    if (pServerRequest)
    {
        RADIUS_requestRelease( &pServerRequest);
    }
@endcode

@funcdoc    radius.h
*/
MOC_EXTERN MSTATUS RADIUS_responseForcedCode(RADIUS_RqstRecord* pRqst, ubyte* forcedResponseCode);

/*
 * RADIUS_responsePrepare()
 *
 * Prepares the RADIUS_RqstRecord with a response. Attributes
 * can be added after that.
 */
/**
@brief      Build a response record.
@details    This function builds a response record and returns it through the
            \p pRqst parameter. After this function is called, attributes can be
            added by calling additional functions.

@ingroup    radius_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__
+ \c \__ENABLE_RFC3576__

@inc_file radius.h

@param pRqst        On return, pointer to response record.
@param responseCode Response code to use in the response record.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
    if (OK > (status = RADIUS_responseForcedCode( pServerRequest, &responseCode)))
        goto exit;

    if (0 == responseCode)
    {
        // no forced response so we will sent ACK always in this example
        ubyte requestCode;
        if ( OK > (status = RADIUS_requestGetCode( pServerRequest, &requestCode)))
            goto exit;
        if (RADIUS_CODE_DISCONNECT_REQUEST == requestCode)
        {
            responseCode = RADIUS_CODE_DISCONNECT_ACK;
        }
        else if (RADIUS_CODE_COA_REQUEST  == requestCode)
        {
            responseCode = RADIUS_CODE_COA_ACK;
        }
        else
        {
            status = ERR_RADIUS_BAD_REQUEST;
            goto exit;
        }
    }

    // send a response with the response code
    if (OK > (status = RADIUS_responsePrepare( pServerRequest, responseCode)))
        goto exit;

    if (OK > (status = RADIUS_responseSend( pServerRequest)))
        goto exit;
@endcode

@funcdoc    radius.h
*/
MOC_EXTERN MSTATUS RADIUS_responsePrepare(RADIUS_RqstRecord* pRqst, ubyte responseCode);

/*
 * RADIUS_responseSend()
 *
 * Prepares the RADIUS_RqstRecord with a response. Attributes
 * can be added after that.
 */
/**
@brief      Send a prepared response.
@details    This function sends a prepared response record as specified by its
            headers.

@ingroup    radius_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__
+ \c \__ENABLE_RFC3576__

@inc_file radius.h

@param instanceId   Instance ID returned from an _initInstance call.
@param pRqst        Pointer to response record to send.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
    // send a response with the response code
    if (OK > (status = RADIUS_responsePrepare( pServerRequest, responseCode)))
        goto exit;

    if (OK > (status = RADIUS_responseSend( pServerRequest)))
        goto exit;
@endcode

@funcdoc    radius.h
*/
MOC_EXTERN MSTATUS RADIUS_responseSend(sbyte4 instanceId, RADIUS_RqstRecord* pRqst);

#endif  /* __ENABLE_RFC3576__ || RADIUS SERVER */

/* MultiServer Support */

/**
@brief      Get the next RADIUS server in the list.
@details    This function returns the next serverID in in the list (relative to
            the current server's ID). If the current server's ID is 0, the first
            available server is returned. A server's skipCounter determines
            whether that server will be returned: if the skipCounter exceeds a
            preconfigured maximum, the server will not be returned as the next
            server.

@ingroup    radius_functions

@since 3.2
@version 3.2 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@param instanceId       Instance ID returned from an _initInstance call.
@param currentServerID  Current server's Id, or 0 to return the first available
                        server.
@param retID            On return, the next server's id (or \c NULL if the next
                        active server is not found).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa RADIUS_resetServerSkipCounter
@sa RADIUS_getSkippedServerList

@funcdoc    radius.h
*/
MOC_EXTERN MSTATUS RADIUS_getNextServer(sbyte4 instanceId, sbyte4 currentServerID, sbyte4 *retID);

/**
@brief      Reset a server's skip counter.
@details    This function resets a server's skip counter so it can be used when
            allocating RADIUS servers.

@ingroup    radius_functions

@since 3.2
@version 3.2 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@param serverId     Desired server's instance ID (returned from an _initInstance
                    call).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa RADIUS_getNextServer
@sa RADIUS_getSkippedServerList

@funcdoc    radius.h
*/
MOC_EXTERN MSTATUS RADIUS_resetServerSkipCounter(sbyte4 serverId);

/**
@brief      Get the list of RADIUS servers that have exceeded the maxSkipCount.
@details    This function returns the list of serverIDs that have exceeded the
            maxSkipCount. To reset a server's skip counter, call
            RADIUS_resetServerSkipCounter.

@note       The maximum number of servers that can be returned is defined by
            \c RADIUS_INSTANCE_ID_END in radius.h.

@ingroup    radius_functions

@since 3.2
@version 3.2 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@param instanceId       Instance ID returned from an _initInstance call.
@param retServerList    On return, pointer to the returned list of servers.
@param listCount        On return, pointer to the number of servers in the
                        returned list (\p retServerList).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa RADIUS_getNextServer
@sa RADIUS_resetServerSkipCounter

@funcdoc    radius.h
*/
MOC_EXTERN MSTATUS RADIUS_getSkippedServerList(sbyte4 instanceId, sbyte4 **retServerList, sbyte4 *listCount);

/**
@brief      Specify which RADIUS server is the primary (UP) server to which all
            transactions are sent.
@details    This function specifies which RADIUS server is the primary (UP)
            server to which all transactions are sent.

Your application can use this function to mark the current server (the
\p serverId parameter value) either UP or DOWN. If it's marked UP (by specifying
\c FALSE for the \p isTrue parameter), the current server continues as the
primary server. However, if the current server is marked DOWN (by specifying \c
TRUE for the \p isTrue parameter), the specified backup server (the \p index
parameter) is selected as the new primary server, and is marked UP.

@ingroup    radius_functions

@since 5.4
@version 5.4 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
 + \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@param serverId ID of RADIUS server (returned by RADIUS_addServer).
@param isTrue   \c TRUE to switch the primary from the current server to the
                specified backup server; \c FALSE for no changes to the primary
                and backup servers.
@param index    Backup server to mark as the new primary server, specified as a
                0-based index into the current server's \c backupId array
                (previously set by RADIUS_addBackupToServer or
                RADIUS_modifyBackupToServer).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa RADIUS_addBackupToServer
@sa RADIUS_modifyBackupToServer
@sa RADIUS_setServerStatus

@funcdoc    radius.h
*/
MOC_EXTERN MSTATUS RADIUS_sendToBackup(sbyte4 serverId, ubyte isTrue, ubyte4 index);

/**
@brief      Enable or disable a RADIUS server.
@details    This function enables or disables a RADIUS server.
            If you disable an enabled primary server, transactions are
            automatically sent to that server's backup server. If you disable a
            primary server's backup server, the backup server remains in the
            primary server's backup list, but will not be used as long as it
            remains disabled.

@ingroup    radius_functions

@since 5.4
@version 5.4 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@param serverId     ID of the RADIUS server (returned by RADIUS_addServer).
@param status       One of the following definitions (see radius.h):\n
                    \n
                    &bull; \c RADIUS_SERVER_UP &mdash;Enables the server.\n
                    &bull; \c RADIUS_SERVER_DOWN &mdash;Disables the server.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    radius.h
*/
MOC_EXTERN void RADIUS_setServerStatus(sbyte4 serverId, sbyte4 status);

/**
@brief      Insert Accouting Authentication.
@details    If the shared secret of the new RADIUS server is different than the
            previous shared secret using which the transactions occured, then
            the request needs to be reconstructed using the new shared secret.
            In this case NanoRADIUS calls the callback funcPtrRadiusRebuildReq()
            to allow the application to reconstruct the request. If the request
            is of an accounting type, then RADIUS_insertAccountingAuthenticator()
            must be called, and should be accessible to the application.

@ingroup    radius_functions

@since 5.4
@version 5.4 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius.h

@param pServer  ID of the RADIUS server returned by RADIUS_addServer(). You can
                typecast the sbyte4 to RADIUS_ServerRecord to satisfy the
                compiler.
@param pPkt     Pointer to request packet that needs insertion of accounting
                authenticator.
@param pktLen   Number of bytes in \p pPkt.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa RADIUS_addBackupToServer
@sa RADIUS_sendToBackup
@sa RADIUS_setServerStatus

@funcdoc    radius.h
*/
MOC_EXTERN MSTATUS RADIUS_insertAccountingAuthenticator(RADIUS_ServerRecord *pServer, ubyte *pPkt, ubyte2 pktLen);

#ifdef __cplusplus
}
#endif

#endif /* __RADIUS_HEADER__ */

