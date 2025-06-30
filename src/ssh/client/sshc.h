/*
 * sshc.h
 *
 * SSH Client Developer API
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 *
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 */

/**
@file       sshc.h
@brief      NanoSSH Client developer API header.
@details    This header file contains definitions, structures, and function
            declarations used by NanoSSH %client.

@since 1.41
@version 5.4 and later

@todo_version (file sizes have changed...)

@flags
Whether the following flags are defined determines which enumerations,
structures, and function declarations are enabled:
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__
+ \c \__ENABLE_MOCANA_SSH_PORT_FORWARDING__
+ \c \__ENABLE_MOCANA_SSH_AUTH_BANNER__

@filedoc    sshc.h
*/


#ifndef __SSHC_HEADER__
#define __SSHC_HEADER__

#include "../../common/mtcp.h"
#include "../../crypto/pubcrypto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SSHC_SFTP_MAX_READ_BYTES                (MAX_SESSION_WINDOW_SIZE - (4 + 4 + 1 + 4))
#define SSHC_BUFFER_SIZE                        (SSHC_MAX_BUFFER_SIZE)

#define CONNECT_CLOSING                         -1
#define CONNECT_DISABLED                        0
#define CONNECT_CLOSED                          1
#define CONNECT_NEGOTIATE                       2
#define CONNECT_OPEN                            3

#define SSH_BYTE_SIZE                           1
#define SSH_UINT64_FIELD_SIZE                   8


/*------------------------------------------------------------------*/

/* timeouts in milliseconds (zero indicates no timeout) */
#if 1
 #define TIMEOUT_SSHC_OPEN                       (2000)
 #ifdef __ENABLE_MOCANA_PQC__
    #define TIMEOUT_SSHC_KEX                     (120000)
 #elif defined(__FSL_MSS_FIX_ENABLED__)
    #define TIMEOUT_SSHC_KEX                     (40000)
 #else
    #define TIMEOUT_SSHC_KEX                     (10000)
 #endif

 #define TIMEOUT_SSHC_NEWKEYS                    (15000)
#ifdef __ENABLE_MOCANA_PQC__
 #define TIMEOUT_SSHC_SERVICE_REQUEST            (120000)
#else
 #define TIMEOUT_SSHC_SERVICE_REQUEST            (30000)
#endif
 #define TIMEOUT_SSHC_OPEN_STATE                 (30000)
 #define TIMEOUT_SSHC_UPPER_LAYER                (15000)
 #define TIMEOUT_SSHC_PORTFWD_MESG               (500)
 #define TIMEOUT_SSHC_PORTFWD_START              (1000)
#else
#define TIMEOUT_SSHC_OPEN                       (0)
#define TIMEOUT_SSHC_KEX                        (0)
#define TIMEOUT_SSHC_NEWKEYS                    (0)
#define TIMEOUT_SSHC_SERVICE_REQUEST            (0)
#define TIMEOUT_SSHC_OPEN_STATE                 (0)
#define TIMEOUT_SSHC_UPPER_LAYER                (0)
#endif


/* the most interesting of these values, the amount of time we allow the user to authenticate */
#ifdef __ENABLE_MOCANA_PQC__
 #define TIMEOUT_SSHC_AUTH_LOGON                 (1000 * 60 * 200)
#else
 #define TIMEOUT_SSHC_AUTH_LOGON                 (1000 * 60 * 10)
#endif

/* suggested by SSHv2 standard, max number of authentication attempts */
#define MAX_SSHC_AUTH_ATTEMPTS                  (20)

/* sizes */
#if 1
  #ifndef SSHC_MAX_BUFFER_SIZE
    #ifdef __ENABLE_MOCANA_PQC__
        #define SSHC_MAX_BUFFER_SIZE            (2097152)
    #elif defined(__FSL_MSS_FIX_ENABLED__)
        #define SSHC_MAX_BUFFER_SIZE            (2200)
    #else
        #define SSHC_MAX_BUFFER_SIZE            (1024*4)
    #endif
  #endif

  #ifdef __FSL_MSS_FIX_ENABLED__
    #define MAX_SESSION_WINDOW_SIZE             (2500)
  #else
    #define MAX_SESSION_WINDOW_SIZE             (1024*2)
  #endif

  #define SSHC_SYNC_BUFFER_SIZE                 (1000)
  #define SSHC_SFTP_GetMaxBytesToRead()         (SSHC_SYNC_BUFFER_SIZE)
#else
/* fast sizes */
  #ifndef SSHC_MAX_BUFFER_SIZE
    #define SSHC_MAX_BUFFER_SIZE                (16000)
  #endif

  #define MAX_SESSION_WINDOW_SIZE               (15000)
  #define SSHC_SYNC_BUFFER_SIZE                 (8192)
  #define SSHC_SFTP_GetMaxBytesToRead()           (SSHC_SYNC_BUFFER_SIZE)
#endif

/* SSH Key Blob Types */
#define SSH_PUBLIC_KEY_BLOB                     1
#define SSH_PRIVATE_KEY_BLOB                    2

/* SSH Advertised Authentication Methods (OR for multiple types) */
#define MOCANA_SSH_AUTH_PUBLIC_KEY              0x80
#define MOCANA_SSH_AUTH_PASSWORD                0x40
#define MOCANA_SSH_AUTH_NONE                    0x10
#define MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE    0x20
#define MOCANA_SSH_AUTH_CERT                    0x100

/* OCSP responders */
#define MAX_OCSP_TRUSTED_RESPONDERS             3

#define SSH_MAX_RPF_HOSTS                       16
#define SSH_MAX_REMOTE_PORT_FWD_CHANNEL         64

/* authentication keyboard interactive */
#define AUTH_ECHO                               (1)
#define AUTH_NO_ECHO                            (0)

#ifndef AUTH_MAX_NUM_PROMPTS
#define AUTH_MAX_NUM_PROMPTS                    3
#endif

#ifndef MAX_SSH_DH_SIZE
#define MAX_SSH_DH_SIZE                         (8192)
#endif

/*------------------------------------------------------------------*/

/* message types */
enum sshcSessionTypes
{
    SSH_SESSION_NOTHING,
    SSH_SESSION_OPEN,
    SSH_SESSION_PTY_REQUEST,
    SSH_SESSION_OPEN_SHELL,
    SSH_SESSION_OPEN_SFTP,
    SSH_SESSION_OPEN_PTY,
    SSH_SESSION_WINDOW_CHANGE,
    SSH_SESSION_DATA,
    SSH_SESSION_STDERR,
    SSH_SESSION_EOF,
    SSH_SESSION_CLOSED,
    SSH_SESSION_BREAK_OP
};

enum pfType
{
    SSH_LOCAL_PORT_FORWARDING,
    SSH_REMOTE_PORT_FORWARDING
};

/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 */
typedef struct
{
    ubyte4          width;
    ubyte4          height;
    ubyte4          pixelWidth;
    ubyte4          pixelHeight;

    sbyte*          pTerminalEnvironment;
    ubyte4          terminalEnvironmentLength;

    sbyte*          pEncodedTerminalModes;
    ubyte4          encodedTerminalModes;

    ubyte4          breakLength;

} clientTerminalState;


/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_SSH_FTP_CLIENT__
/**
@brief      NanoSSH Client SFTP file handle descriptor.
@details    NanoSSH Client SFTP file handle descriptor.

@todo_techpubs (add documentation for all fields in sftpcFileHandleDescr)
*/
typedef struct
{
    intBoolean              isFileHandleInUse;
    void*                   pHandleName;
    void*                   cookie;                 /* not used for directories */

    sbyte4                  readLocation;           /* current position / total bytes read */
    sbyte*                  pReadBuffer;
    sbyte4                  readBufferSize;

    sbyte4                  writeLocation;          /* current position / total bytes written */
    sbyte*                  pWriteBuffer;
    sbyte4                  writeBufferSize;

    sbyte4                  clientWrtLoc;           /* internal use */
    ubyte4                  requestID;              /* current pending request id */
    ubyte                   request;                /* not sure if needed */
    ubyte4                  requestStatusResponse;  /* the status response for the request */
    sbyte4                  response;               /* response message type for our request */

    /* for realpath */
    struct ATTRClient*      pATTR;                  /* used by SSH_FXP_NAME */
    void*                   pFilename;              /* used by SSH_FXP_NAME */

    /* for file listings */
    ubyte*                  pFileListingPayload;    /* used by SSH_FXP_NAME */
    ubyte4                  fileListingCount;
    ubyte4                  fileListingPosition;
    ubyte4                  fileListingBufIndex;
    ubyte4                  fileListingPayloadLen;

} sftpcFileHandleDescr;
#endif /* __ENABLE_MOCANA_SSH_FTP_CLIENT__ */

/**
 * @dont_show
 * @internal
 */
typedef struct
{
    sbyte*          pPrompt;
    ubyte4          promptLen;
    ubyte4          echo;

} keyIntPrompt;

/**
 * @dont_show
 * @internal
 */
typedef struct keyIntInfoReq
{
    sbyte4          cookie;                             /* for flexiblity, useful for marking things as static or dynamic, etc */

    sbyte*          pName;
    ubyte4          nameLen;
    sbyte*          pInstruction;
    ubyte4          instructionLen;

    ubyte4          numPrompts;
    keyIntPrompt*   prompts[AUTH_MAX_NUM_PROMPTS];

} keyIntInfoReq;

/**
 * @dont_show
 * @internal
 */
typedef struct
{
    ubyte*          pResponse;
    ubyte4          responseLen;

} keyIntResp;

/**
 * @dont_show
 * @internal
 */
typedef struct
{
    ubyte4          numResponses;
    keyIntResp*     responses[AUTH_MAX_NUM_PROMPTS];    /* contains responses to prompts */

} keyIntInfoResp;
struct certChain;
typedef struct certChain* certChainPtr;

/*------------------------------------------------------------------*/

/**
@brief      Configuration settings and callback function pointers for SSH
            clients.

@details    This structure is used for NanoSSH Client configuration. Which
            products and features you've included (by defining the appropriate
            flags in moptions.h) determine which callback functions are
            present in this structure. Each included callback function should
            be customized for your application and then registered by
            assigning it to the appropriate structure function pointer(s).

@since 1.41
@version 3.06 and later

@todo_version (ocsp trusted responder fields added...)

@flags
Whether the following flag is defined determines which callback functions
are enabled:
+ \c \__ENABLE_MOCANA_SSH_PORT_FORWARDING__

*/
typedef struct
{
/**
@brief      Maximum number of connections to this %client.
@details    Maximum number of connections to this %client.
*/
    sbyte4          sshMaxConnections;

/**
@brief      Number of authentication tries allowed before the connection is
              said to have failed.
@details    Number of authentication tries allowed before the connection is
              said to have failed.
*/
    ubyte4          sshMaxAuthAttempts;

/**
@brief      Number of milliseconds the %client waits for an open session
              response before timing out.
@details    Number of milliseconds the %client waits for an open session
              response before timing out.
*/
    ubyte4          sshTimeOutOpen;

/**
@brief      Number of milliseconds the %client waits for a key exchange before
              timing out.
@details    Number of milliseconds the %client waits for a key exchange before
              timing out.
*/
    ubyte4          sshTimeOutKeyExchange;

/**
@brief      Number of milliseconds the %client waits for new keys before
              timing out.
@details    Number of milliseconds the %client waits for new keys before
              timing out.
*/
    ubyte4          sshTimeOutNewKeys;

/**
@brief      Number of milliseconds the %client waits for a service request
              response before timing out.
@details    Number of milliseconds the %client waits for a service request
              response before timing out.
*/
    ubyte4          sshTimeOutServiceRequest;

/**
@brief      Number of milliseconds the %client waits for an authentication
              response before timing out.
@details    Number of milliseconds the %client waits for an authentication
              response before timing out.
*/
    ubyte4          sshTimeOutAuthentication;

/**
@brief      Number of milliseconds before timing out for the %client to make a
              request (such as open a shell) after authentication.
@details    Number of milliseconds before timing out for the %client to make a
              request (such as open a shell) after authentication.
*/
    ubyte4          sshTimeOutDefaultOpenState;

#if ((defined(__ENABLE_MOCANA_SSH_OCSP_SUPPORT__)) && (defined(__ENABLE_MOCANA_OCSP_CLIENT__)))
/**
 * @todo_eng_review (field added after 5.3.1...)
 */
    ubyte4          trustedResponderCount;
/**
 * @todo_eng_review (field added after 5.3.1...)
 */
    certDescriptor  ocspTrustedResponderCerts[MAX_OCSP_TRUSTED_RESPONDERS];
#endif

/**
@brief      Protocol-specific upcall (callback).
@details    This protocol-specific upcall (callback) pointer's value is set to
              \c sshcProtocolUpcall, which should not be modified.
*/
    MSTATUS (*funcPtrSessionOpen)    (sbyte4 connectionInstance, enum sshcSessionTypes sessionEvent, ubyte *pMesg, ubyte4 mesgLen);

/**
@brief      Protocol-specific upcall (callback).
@details    This protocol-specific upcall (callback) pointer's value is set to
              \c sshcProtocolUpcall, which should not be modified.
*/
    MSTATUS (*funcPtrPtyRequest)     (sbyte4 connectionInstance, enum sshcSessionTypes sessionEvent, ubyte *pMesg, ubyte4 mesgLen);

/**
@brief      Protocol-specific upcall (callback).
@details    This protocol-specific upcall (callback) pointer's value is set to
              \c sshcProtocolUpcall, which should not be modified.
*/
    MSTATUS (*funcPtrOpenShell)      (sbyte4 connectionInstance, enum sshcSessionTypes sessionEvent, ubyte *pMesg, ubyte4 mesgLen);

/**
@brief      Protocol-specific upcall (callback).
@details    This protocol-specific upcall (callback) pointer's value is set to
              \c sshcProtocolUpcall, which should not be modified.
*/
    MSTATUS (*funcPtrOpenSftp)       (sbyte4 connectionInstance, enum sshcSessionTypes sessionEvent, ubyte *pMesg, ubyte4 mesgLen);

/**
@brief      Protocol-specific upcall (callback).
@details    This protocol-specific upcall (callback) pointer's value is set to
              \c sshcProtocolUpcall, which should not be modified.
*/
    MSTATUS (*funcPtrWindowChange)   (sbyte4 connectionInstance, enum sshcSessionTypes sessionEvent, ubyte *pMesg, ubyte4 mesgLen);

/**
@brief      Protocol-specific upcall (callback).
@details    This protocol-specific upcall (callback) pointer's value is set to
              \c sshcProtocolUpcall, which should not be modified.
*/
    MSTATUS (*funcPtrReceivedData)   (sbyte4 connectionInstance, enum sshcSessionTypes sessionEvent, ubyte *pMesg, ubyte4 mesgLen);

/**
@brief      Protocol-specific upcall (callback).
@details    This protocol-specific upcall (callback) pointer's value is set to
              \c sshcProtocolUpcall, which should not be modified.
*/
    MSTATUS (*funcPtrStdErr)         (sbyte4 connectionInstance, enum sshcSessionTypes sessionEvent, ubyte *pMesg, ubyte4 mesgLen);

/**
@brief      Protocol-specific upcall (callback).
@details    This protocol-specific upcall (callback) pointer's value is set to
              \c sshcProtocolUpcall, which should not be modified.
*/
    MSTATUS (*funcPtrEof)            (sbyte4 connectionInstance, enum sshcSessionTypes sessionEvent, ubyte *pMesg, ubyte4 mesgLen);

/**
@brief      Protocol-specific upcall (callback).
@details    This protocol-specific upcall (callback) pointer's value is set to
              \c sshcProtocolUpcall, which should not be modified.
*/
    MSTATUS (*funcPtrClosed)         (sbyte4 connectionInstance, enum sshcSessionTypes sessionEvent, ubyte *pMesg, ubyte4 mesgLen);

/**
@brief      Protocol-specific upcall (callback).
@details    This protocol-specific upcall (callback) pointer's value is set to
              \c sshcProtocolUpcall, which should not be modified.
*/
    MSTATUS (*funcPtrBreakOp)        (sbyte4 connectionInstance, enum sshcSessionTypes sessionEvent, ubyte *pMesg, ubyte4 mesgLen);

    /* general purpose upcalls */

/**
@brief      Start a timer to use for timeout notifications.

@details    This callback starts a timer to use for timeout notifications.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    cb_sshc_general_purpose

@since 2.02
@version 2.02 and later

@flags
There are no flag dependencies to enable this callback.

@param connectionInstance       Connection instance returned from
                                  SSL_ASYNC_acceptconnection().
@param msTimerExpire            Number of milliseconds until timer expires.
@param boolUserAuthenticated    (Reserved for future use.)

@return     None.

@callbackdoc    sshc.h
*/
    void(*funcPtrStartTimer)     (sbyte4 connectionInstance, ubyte4 msTimerExpire, sbyte4 boolUserAuthenticated);


/**
@brief      Get a public/private key pair (naked key blob).

@details    This callback function is invoked when NanoSSH %client needs to
            authenticate itself to the SSH server using public key
            authentication; it should return the key blob containing the
            public and private keys from the public and private authorization
            key files, respectively. (Therefore, NanoSSH %client must have
            access to the client's unique key.)

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    cb_sshc_protocol_specific

@since 2.02
@version 2.02 and later

@flags
There are no flag dependencies to enable this callback.

@param connectionInstance   Connection instance returned from SSHC_connect().
@param ppRetKeyBlob         On return, pointer to address of key blob
                              (containing public/private key pair).
@param pRetKeyBlobLength    On return, pointer to number of bytes in returned
                              key blob (\p ppRetKeyBlob).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    sshc.h
*/
    sbyte4(*funcPtrRetrieveNakedAuthKeys)(sbyte4 connectionInstance, ubyte **ppRetKeyBlob,  ubyte4 *pRetKeyBlobLength);

/**
@brief      Release (free) memory allocated for authentication keys.

@details    This callback function is invoked after a call to
            sshClientSettings::funcPtrRetrieveNakedKeys. It should release (free) the memory allocated for the public and private keys that
            were retrieved by the sshClientSettings::funcPtrRetrieveNakedKeys
            call.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    cb_sshc_protocol_specific

@since 2.02
@version 2.02 and later

@flags
There are no flag dependencies to enable this callback.

@param connectionInstance   Connection instance returned from SSHC_connect().
@param ppFreeKeyBlob        Pointer to key blob (containing public/private
                              key pair) to release (free).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    sshc.h
*/
    sbyte4(*funcPtrReleaseNakedAuthKeys) (sbyte4 connectionInstance, ubyte **ppFreeKeyBlob);

    /* for SSH_MSG_USERAUTH_REQUEST (50). pMethod can be one of MOCANA_SSH_AUTH_PUBLIC_KEY or MOCANA_SSH_AUTH_PASSWORD. */

/**
@brief      Validate a public key.

@details    This callback function is invoked during connection establishment;
            it should verify that the provided public key is on record,
            compare the provided and on-file keys, and return TRUE or FALSE to
            indicate whether the keys match. (If they match, the key is valid.)

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    cb_sshc_protocol_specific

@since 1.41
@version 1.41 and later

@flags
There are no flag dependencies to enable this callback.

@param connectionInstance   Connection instance returned from SSHC_connect().
@param pPubKey              Pointer to public key to validate.\n
\n
The public key (\p pubKeyLength) is a byte string representation of the
keyblob, both version 1 and version 2 are supported:
+ Version 1, begins with a 12-byte header, with all bytes set to zero except
the following:\n
+ header[7] contains the Mocana SoT Platform keyblob version (1)\n
+ header[11] contains the key type (any of the \c akt_* enumerated values
defined in ca_mgmt.h)\n
\n
For DSA keys, the data following the header is:\n
+ 4 bytes length of p string\n
+ n bytes length of p byte string\n
+ 4 bytes length of q string\n
+ n bytes length of q byte string\n
+ 4 bytes length of g string\n
+ n bytes length of g byte string\n
+ 4 bytes length of y string\n
+ n bytes length of y byte string\n
+ 4 bytes length of x string\n
+ n bytes length of x byte string\n
\n
For RSA keys, the data following the header is:\n
+ 4 bytes length of e string\n
+ n bytes length of e byte string\n
+ 4 bytes length of n string\n
+ n bytes length of n byte string\n
+ 4 bytes length of p string\n
+ n bytes length of p byte string\n
+ 4 bytes length of q string\n
+ n bytes length of q byte string\n
+ 4 bytes length of private string \#1\n
+ n bytes length of private byte string \#1\n
+ 4 bytes length of private string \#2\n
+ n bytes length of private byte string \#2\n
+ 4 bytes length of private string \#3\n
+ n bytes length of private byte string \#3\n
+ 4 bytes length of private string \#4\n
+ n bytes length of private byte string \#4\n
+ 4 bytes length of private string \#5\n
+ n bytes length of private byte string \#5\n
\n
For ECC keys, the data following the header is:\n
+ 1 byte OID suffix identifying the curve\n
+ 4 bytes length of Point string\n
+ n bytes length of Point byte string (uncompressed X9-62 format)\n
+ 4 bytes length of Scalar string\n
+ n bytes length of Scalar byte string
\n
Version 2:\n
+ 4 bytes:      all zeroes\n
+ 4 bytes:      version number which must be 0x00000002\n
+ 4 bytes:      key type which must be one of the KEYBLOB_TYPE enums\n
+ 4 bytes:      OID type which must be one of the MAlgoOid enums\n
+ n bytes:      ASN.1 encoded algorithm identifier\n
+ 4 bytes:      reserved\n
+ n bytes:      reserved\n
+ 4 bytes:      key data length (keylen)\n
+ keylen bytes: key data (key data formats are mentioned above)

@param pubKeyLength     Number of bytes in the public key (\p pPubKey).

@return     \c TRUE (1) if the provided key matches the key on file;
            otherwise \c FALSE (0).

@callbackdoc    sshc.h
*/
    sbyte4(*funcPtrServerPubKeyAuth)           (sbyte4 connectionInstance, const ubyte *pPubKey,   ubyte4 pubKeyLength);

/**
@brief      Select which authentication methods can be used with the server.

@details    This callback function is invoked when the SSH server requests
            that NanoSSH %client authenticate itself; it should select which
            authentication methods can be used with the server.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    cb_sshc_general_purpose

@since 1.41
@version 1.41 and later

@flags
There are no flag dependencies to enable this callback.

@param connectionInstance   Connection instance returned from SSHC_connect().
@param pAuthNameList        Pointer to a comma-separated name-list of
                              authentication 'method name' values.
@param authNameListLen      Number of characters (bytes) in the name-list
                              (\p pAuthNameList).
@param ppUserName           On return, pointer to address of user name buffer.
@param pUserNameLength      On return, pointer to number of characters
                              (bytes) in the user name (\p ppUserName).
@param pMethod              On return, pointer to bit mask of selected
                              authentication method:\n
\n
+ \c MOCANA_SSH_AUTH_PUBLIC_KEY \n
+ \c MOCANA_SSH_AUTH_PASSWORD \n
+ \c MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE \n
+ \c MOCANA_SSH_AUTH_NONE \n
+ \c MOCANA_SSH_AUTH_CERT

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    sshc.h
*/
    sbyte4(*funcPtrRetrieveUserAuthRequestInfo)(sbyte4 connectionInstance, ubyte *pAuthNameList, ubyte4 authNameListLen, ubyte **ppUserName, ubyte4 *pUserNameLength, ubyte4 *pMethod);


#ifdef __ENABLE_MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE__
    sbyte4(*funcPtrKeyIntAuthResp)(sbyte4 connectionInstance, keyIntInfoReq* pRequestInfo, keyIntInfoResp* pResponseInfo);

    sbyte4(*funcPtrReleaseKeyIntAuthResp)(sbyte4 connectionInstance, keyIntInfoResp *pResponse);
#endif

/**
@brief      Select which authentication methods can be used with the server,
            and decide whether to query if server supports authentication method
            first.

@details    This callback function is invoked when the SSH server requests
            that NanoSSH %client authenticate itself; it should select which
            authentication methods that can be used with the server.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    cb_sshc_general_purpose

@since 1.41
@version 1.41 and later

@flags
There are no flag dependencies to enable this callback.

@param connectionInstance   Connection instance returned from SSHC_connect().
@param messageCode          The message code recieved by client. The message
                            codes supported are the following:\n
                            \n
                            + \c SSH_MSG_SERVICE_ACCEPT \n
                            + \c SSH_MSG_USERAUTH_FAILURE \n
                            + \c SSH_MSG_USERAUTH_PK_OK
@param methodType           The authentication method value associated with the
                            messageCode recieved. If the value of messageCode is
                            SSH_MSG_SERVICE_ACCEPT, this value hasn't been defined yet.
@param pAuthNameList        Pointer to a comma-separated name-list of
                              authentication 'method name' values.
@param authNameListLen      Number of characters (bytes) in the name-list
                              (\p pAuthNameList).
@param ppUserName           On return, pointer to address of user name buffer.
@param pUserNameLength      On return, pointer to number of characters
                              (bytes) in the user name (\p ppUserName).
@param pMethod              On return, pointer to bit mask of selected
                              authentication method:\n
\n
+ \c MOCANA_SSH_AUTH_PUBLIC_KEY \n
+ \c MOCANA_SSH_AUTH_PASSWORD \n
+ \c MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE \n
+ \c MOCANA_SSH_AUTH_NONE \n
+ \c MOCANA_SSH_AUTH_CERT
@param pSendSignature       On return, pointer to intBoolean used to determine whether
                            signature is sent in authentication message. If TRUE,
                            signature is sent.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    sshc.h
*/
    sbyte4(*funcPtrRetrieveUserAuthRequestInfoEx)(sbyte4 connectionInstance, ubyte messageCode, ubyte4 methodType, ubyte *pAuthNameList, ubyte4 authNameListLen, ubyte **ppUserName, ubyte4 *pUserNameLength, ubyte4 *pMethod, intBoolean *pSendSignature);

/**
@brief      Verify a client's certificate.

@details    This callback function is invoked during authentication to verify a
            client's certificate

@ingroup    cb_sshs_general_purpose

@since 6.5
@version 6.5 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_SERVER__
+ \c \__ENABLE_MOCANA_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param cert_status          cert verification status done by the stack
@param pCertificate         certificate of the peer
@param certLen              length of the certificate buffer 
@param pCertChain           certificate chain leading the to anchor 
@param pAnchorCert          Anchor CA certificate if not present in pCertChain
@param anchorCertLen        anchor cert length if present\n
\n
@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc ssh.h
*/

    sbyte4(*funcPtrCertStatus)      (sbyte4 connectionInstance,
                         sbyte4 cert_status, ubyte *pCertificate, ubyte4 certLen,
                         certChainPtr pCertChain, const ubyte *pAnchorCert, ubyte4 anchorCertLen);

/**
@brief      Return user's password and its length.

@details    This callback function is invoked when the SSH server requests
            authentication; it should return the user's password and its length.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    cb_sshc_general_purpose

@since 1.41
@version 1.41 and later

@flags
There are no flag dependencies to enable this callback.

@param connectionInstance   Connection instance returned from SSHC_connect().
@param pUserName            Pointer to user name buffer.
@param userNameLength       Number of characters (bytes) in the user name
                              (\p userName).
@param ppUserPassword       On return, pointer to address of user password
                              buffer.
@param pUserPasswordLength  On return, pointer to number of characters
                              in user password (\p ppUserPassword).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    sshc.h
*/
    sbyte4(*funcPtrRetrieveUserPassword)       (sbyte4 connectionInstance, ubyte *pUserName, ubyte4 userNameLength, ubyte **ppUserPassword, ubyte4 *pUserPasswordLength);

/**
@brief      Inform the calling application that authentication has been
            successful.

@details    This callback function is invoked after successful authentication;
            it should inform the calling application that authentication has
            been successful.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    cb_sshc_general_purpose

@since 1.41
@version 1.41 and later

@flags
There are no flag dependencies to enable this callback.

@param connectionInstance   Connection instance returned from SSHC_connect().

@return     None.

@callbackdoc    sshc.h
*/
    void(*funcPtrAuthOpen)                     (sbyte4 connectionInstance);

/**
@brief      Respond to a failed session open request.

@details    This callback function is invoked when the SSH Client attempts to
            open a service, but fails because the service is not available on
            the server. This callback function should try a different service
            or return an error code.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    cb_sshc_general_purpose

@since 1.41
@version 1.41 and later

@flags
There are no flag dependencies to enable this callback.

@param connectionInstance   Connection instance returned from SSHC_connect().
@param pInfo                Pointer to text explaining why the session was
                              closed.
@param infoLength           Number of bytes in text explanation (\p pInfo).
@param pLanguage            Pointer to language tag as defined in
                              RFC&nbsp;1766, <em>Tags for the Identification
                              of Languages</em>; includes the ISO&nbsp;639
                              2-letter language code.
@param languageLength       Number of bytes in language tag (\p pLanguage).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    sshc.h
*/
    sbyte4(*funcPtrSessionOpenFail) (sbyte4 connectionInstance, ubyte *pInfo, ubyte4 infoLength, ubyte *pLanguage, ubyte4 languageLength);

#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
/**
@brief      Respond to a successful session open request.

@details    This callback function is invoked when the SSH Client successfully
            opens a service. This callback function is used only for a local
            port forwarding session open request.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    cb_sshc_port_forwarding

@since 3.06
@version 3.06 and later

@todo_version (function name changed...)

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_PORT_FORWARDING__

@param connectionInstance   Connection instance returned from SSHC_connect().
@param sessionEvent         Any of the \c sshcSessionTypes enumerated values
                              (see sshc.h).
@param pMesg                Pointer to message to forward.
@param mesgLen              Number of bytes in the message (\p pMesg).
@param channel              Channel number returned from
                              SSHC_lpfRegisterConnection().

@return     None.

@callbackdoc    sshc.h
*/
    void(*funcPtrPortFwdSessionOpen) (sbyte4 connectionInstance, enum sshcSessionTypes sessionEvent, ubyte *pMesg, ubyte4 mesgLen, ubyte4 channel);

/**
@brief      Respond to a failed session open request.

@details    This callback function is invoked when the SSH Client attempts to
            open a service, but fails because the service is not available on
            the server. This callback function (which is used only for a local
            port forwarding session open request) should try a different
            service or return an error code.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    cb_sshc_port_forwarding

@since 3.06
@version 3.06 and later

@todo_version (function name changed...)

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_PORT_FORWARDING__

@param connectionInstance   Connection instance returned from SSHC_connect().
@param pInfo                Pointer to text explaining why the session was
                              closed.
@param infoLength           Number of bytes in text explanation (\p pInfo).
@param pLanguage            Pointer to language tag as defined in
                              RFC&nbsp;1766, <em>Tags for the Identification
                              of Languages</em>; includes the ISO&nbsp;639
                              2-letter language code.
@param languageLength       Number of bytes in language tag (\p pLanguage).
@param channel              Channel number returned from
                              SSHC_lpfRegisterConnection().

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    sshc.h
*/
    sbyte4(*funcPtrPortFwdSessionOpenFail) (sbyte4 connectionInstance, ubyte *pInfo, ubyte4 infoLength, ubyte *pLanguage, ubyte4 languageLength, sbyte4 channel);

/**
@brief      Respond to a session close request.

@details    This callback function is invoked when the SSH Client receives a
            session close message from the SSH server. This callback function
            is used only for a local port forwarding session close request.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    cb_sshc_port_forwarding

@since 3.06
@version 3.06 and later

@todo_version (function name changed...)

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_PORT_FORWARDING__

@param connectionInstance   Connection instance returned from SSHC_connect().
@param sessionEvent         Any of the \c sshcSessionTypes enumerated values
                              (see sshc.h).
@param pMesg                Pointer to message to forward.
@param mesgLen              Number of bytes in the message (\p pMesg).
@param channel              Channel number returned from
                              SSHC_lpfRegisterConnection().

@return     None.

@callbackdoc    sshc.h
*/
    void(*funcPtrPortForwardClosed) (sbyte4 connectionInstance, enum sshcSessionTypes sessionEvent, ubyte *pMesg, ubyte4 mesgLen, ubyte4 channel);

/**
@brief      Respond to a session EOF request.

@details    This callback function is invoked when the SSH Client receives a
            session EOF request from the SSH server. This callback function is
            used only for a local port forwarding session EOF request.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    cb_sshc_port_forwarding

@since 3.06
@version 3.06 and later

@todo_version (function name changed...)

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_PORT_FORWARDING__

@param connectionInstance   Connection instance returned from SSHC_connect().
@param sessionEvent         Any of the \c sshcSessionTypes enumerated values
                              (see sshc.h).
@param pMesg                Pointer to message to forward.
@param mesgLen              Number of bytes in the message (\p pMesg).
@param channel              Channel number returned from
                              SSHC_lpfRegisterConnection().

@return     None.

@callbackdoc    sshc.h
*/
    void(*funcPtrPortForwardEof) (sbyte4 connectionInstance, enum sshcSessionTypes sessionEvent, ubyte *pMesg, ubyte4 mesgLen, ubyte4 channel);

/**
@brief      Respond to a session message.

@details    This callback function is invoked when the SSH Client receives a
            session data message from the SSH server. This callback function
            is used only for a local port forwarding session open request.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    cb_sshc_port_forwarding

@since 3.06
@version 3.06 and later

@todo_version (function name changed...)

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_PORT_FORWARDING__

@param connectionInstance   Connection instance returned from SSHC_connect().
@param sessionEvent         Any of the \c sshcSessionTypes enumerated values
                              (see sshc.h).
@param pMesg                Pointer to message to forward.
@param mesgLen              Number of bytes in the message (\p pMesg).
@param channel              Channel number returned from
                              SSHC_lpfRegisterConnection().

@return     None.

@callbackdoc    sshc.h
*/
    void(*funcPtrPortFwdReceivedData) (sbyte4 connectionInstance, enum sshcSessionTypes sessionEvent, ubyte *pMesg, ubyte4 mesgLen, ubyte4 channel );

/**
@coming_soon
@ingroup    cb_sshc_port_forwarding
*/
    sbyte4(*funcPtrPortForwardConnect) (sbyte4 connectionInstance, enum pfType, sbyte *pHostAddr, ubyte4 hostPort, ubyte *pIgnoreRequest, ubyte4 channel );

/**
@coming_soon
@ingroup    cb_sshc_port_forwarding
*/
    void(*funcPtrRemotePortReqStatus) (sbyte4 status, ubyte4 port );

#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */

#ifdef __ENABLE_MOCANA_SSH_AUTH_BANNER__
/**
@brief      Display a warning message from the %server.

@details    This callback function is invoked during authentication to
            display a warning message from the server.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    cb_sshc_general_purpose

@since 5.4
@version 5.4 and later

@param connectionInstance   Pointer to the SSH %client instance.
@param pBanner              Pointer to the banner string to display.
@param length               Number of bytes in the banner string (\p pBanner).
@param pMsgLanguageTag      Pointer to the banner string language tag to be
                              displayed on the screen.

@flags
To enable this callback, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_AUTH_BANNER__

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     You should define and customize this hookup function for your
            application if SSH is configured to use digital certificates for
            authentication.

@callbackdoc    sshc.h
*/
    sbyte4(* funcPtrDisplayBanner)(sbyte4 connectionInstance, ubyte *pBanner, ubyte4 length, ubyte *pMsgLanguageTag);
#endif

/**
@brief      Display disconnetion message from %server.

@details    This callback function is invoked when server sends a disconnection
            message.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@since 5.4
@version 5.4 and later

@flags
There are no flag dependencies to enable this callback.

@param connectionInstance   Connection instance returned from SSHC_connect().
@param reasonCode           Reason code for disconnection.
@param pMsg                 Pointer to the disconnection message description.
@param msgLength            Number of bytes in the message (\p pMsg).
@param pMsgLanguageTag      Pointer to the description string language tag.

@return     None.

@callbackdoc    sshc.h
*/
    void(* funcPtrDisconnectMsg)(sbyte4 connectionInstance, ubyte4 reasonCode, ubyte *pMsg, ubyte4 msgLength, ubyte *pMsgLanguageTag);

/**
@brief      Inform the calling application that Session Rekey has been initiated.

@details    This callback function is invoked on rekey negotiation start (initiated
            locally or by remote) - allowing the application to take update session
            context.

@ingroup    cb_sshc_general_purpose

@since 3.06
@version 3.06 and later

@flags
There are no flag dependencies to enable this callback.

@param connectionInstance   Connection instance returned from SSHC_connect.
@param initiatedByRemote    True if the rekey was initiated by remote.

@return $OK$ (0) if successful; otherwise a negative number
error code definition from merrors.h. To retrieve a string containing an
English text error identifier corresponding to the function's returned error
status, use the $DISPLAY_ERROR$ macro.

*/

  MSTATUS (*funcPtrSessionReKey)   (sbyte4 connectionInstance, intBoolean initiatedByRemote);

} sshClientSettings;

/*
 * SSHC_FuncPtrProtocolTest functions should return true iff the doProtocolXXX() loop
 * should exit/unwind.
 */


/*------------------------------------------------------------------*/

struct certStore;

/**
@brief      Get a pointer to the session's NanoSSH Client settings.

@details    This function returns a pointer to the session's NanoSSH client
            settings.

@ingroup    func_ssh_core_client

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__

@inc_file sshc.h

@return     Pointer to NanoSSH %client settings.

@remark     This function is applicable to synchronous NanoSSH clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sshClientSettings *SSHC_sshClientSettings(void);

/**
@brief      Initialize NanoSSH %client internal structures.

@details    This function initializes NanoSSH %client internal structures.

@ingroup    func_ssh_core_client

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__

@inc_file sshc.h

@param numClientConnections     Maximum number of NanoSSH %client connections
                                  to allow.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous NanoSSH clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_init(sbyte4 numClientConnections);

/**
@brief      Release memory initialized by SSHC_init().

@details    This function releases memory that was initialized by SSHC_init().

@ingroup    func_ssh_core_client

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__

@inc_file sshc.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous NanoSSH clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_shutdown(void);

/**
@brief      Create a secure SSH connection with a remote server.

@details    This function creates a connection context for a secure SSH
            connection with a remote server.

@ingroup    func_ssh_core_client

@since 1.41
@version 3.2 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__

@inc_file sshc.h

@param tempSocket           Socket returned by OS-specific TCP connection call.
@param pConnectionInstance  On return, pointer to new connection context.
@param pCommonName          Expected common name of target server's certificate.
@param pCertStore           Pointer to SoT Platform certificate store that
                              contains the SSH connection's certificate (as a
                              trust point or identify).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous NanoSSH clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_connect(TCP_SOCKET tempSocket, sbyte4 *pConnectionInstance, sbyte *pCommonName, struct certStore *pCertStore);

/**
@brief      Set an SSH connection's cipher.

@details    This function explicitly sets the cipher used by the specified SSH
            connection (instead of enabling automatic cipher selection).
            Because this function requires a valid connection instance, the
            function cannot be called until after a call to SSHC_connect().

@ingroup    func_ssh_core_client

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__

@inc_file sshc.h

@param connectionInstance   Connection instance returned from SSHC_connect().
@param pCipher              Pointer to string containing the desired cipher
                              name (see @ref sshc.hipher_suites).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous NanoSSH clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_useThisCipher(sbyte4 connectionInstance, ubyte *pCipher);

/**
@brief      Set an SSH connection's HMAC.

@details    This function explicitly sets the HMAC used by the specified SSH
            connection (instead of enabling automatic HMAC selection). Because
            this function requires a valid connection instance, the function
            cannot be called until after a call to SSHC_connect().

@ingroup    func_ssh_core_client

@since 5.1
@version 5.1 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__

@inc_file sshc.h

@param connectionInstance   Connection instance returned from SSHC_connect().
@param pHmac                Pointer to string containing the desired HMAC name
                              (an entry in the \c mHmacSuites array, declared
                              in sshc_trans.c).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous NanoSSH clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_useThisHmac(sbyte4 connectionInstance, ubyte *pHmac);

/**
@brief      Authenticate a server (which establishes a secure connection).

@details    This function authenticates a server, establishing a secure
            connection.

@ingroup    func_ssh_core_client

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__

@inc_file sshc.h

@param connectionInstance  Connection instance returned from SSHC_connect().

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous NanoSSH clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_negotiateConnection(sbyte4 connectionInstance);

/**
@brief      Negotiate a connection (the %client is authenticated by the %server).

@details    This function negotiates a connection (the %client is
            authenticated by the %server), after which the SSH %server can
            provide services requested by NanoSSH %client.

@ingroup    func_ssh_core_client

@since 3.2
@version 3.2 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__

@inc_file sshc.h

@param connectionInstance   Connection instance returned from SSHC_connect().

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous NanoSSH clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_negotiateSession(sbyte4 connectionInstance);

/**
@brief      Negotiate closing of a channel.

@details    This function negotiates the closing of the channel associated
            with channelNumber.

@ingroup    func_ssh_core_client

@since 3.2
@version 3.2 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__

@inc_file sshc.h

@param connectionInstance   Connection instance returned from SSHC_connect().
@param channelNumber        Channel number of the channel we want to close.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous NanoSSH clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_negotiateCloseChannel(sbyte4 connectionInstance, sbyte4 channelNumber);

/**
@brief      Send an SSH <tt>exec&nbsp;sftp</tt> command on the specified
            connection.

@details    This function sends an SSH <tt>exec&nbsp;sftp</tt> command on the
            specified connection.

@ingroup    func_ssh_core_client

@since 3.2
@version 3.2 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__

@inc_file sshc.h

@param connectionInstance   Connection instance returned from SSHC_connect().

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous NanoSSH clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_negotiateSubsystemSFTPChannelRequest(sbyte4 connectionInstance);

/**
@brief      Start a NanoSSH client SFTP session.

@details    This function starts a NanoSsH client SFTP session by negotiating
            an SFTP protocol version.

@ingroup    func_ssh_core_client

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

@inc_file sshc.h

@param connectionInstance   Connection instance returned from SSHC_connect().

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous SFTP clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_negotiateSFTPHello(sbyte4 connectionInstance);

/**
@brief      Send an SSH \c PTY command on the specified connection.

@details    This function sends an SSH \c PTY command on the specified
            connection. To start an interactive or scripted shell with a
            server, this function must be invoked during negotiation on the
            specified connection.

@ingroup    func_sshc.hli_shell_command

@since 3.2
@version 3.2 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__
@inc_file sshc.h

@param connectionInstance   Connection instance returned from SSHC_connect().

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous NanoSSH clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_negotiatePtyTerminalChannelRequest(sbyte4 connectionInstance);

/**
@brief      Send an SSH shell command on the specified connection.

@details    This function sends an SSH shell command on the specified
            connection. To start an interactive or scripted shell with a
            server, this function must be invoked during negotiation on the
            specified connection.

@ingroup    func_sshc.hli_shell_command

@since 3.2
@version 3.2 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__

@inc_file sshc.h

@param connectionInstance   Connection instance returned from SSHC_connect().

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous NanoSSH clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_negotiateShellChannelRequest(sbyte4 connectionInstance);

/**
@brief      Send data to a server.

@details    This function sends data to a server.

@note       This function should not be called until an SSH %client-server
            connection is established.

@ingroup    func_sshc.hli_shell_command

@since 3.2
@version 3.2 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__

@inc_file ssh.h

@param connectionInstance   Connection instance returned from SSHC_connect().
@param pBuffer              Pointer to the buffer containing the data to send.
@param bufferSize           Number of bytes in the send data buffer (\p
                              pBuffer).
@param pBytesSent           On return, pointer to number of bytes successfully
                              sent.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous NanoSSH clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_sendMessage(sbyte4 connectionInstance, ubyte *pBuffer, ubyte4 bufferSize, ubyte4 *pBytesSent);

/**
@brief      Get data from a connected server/client.

@details    This function retrieves data from a connected server/client. It
            should not be called until an SSH connection is established
            between the %client and %server.

@ingroup    func_sshc.hli_shell_command

@since 3.2
@version 3.2 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__

@inc_file sshc.h

@param connectionInstance   Connection instance returned from SSHC_connect().
@param pMessageType         Pointer to \c sshcSessionTypes enum buffer (see
                              sshc.h) in which to write the message type,
                              according to the message read operation.
@param pRetMessage          Pointer to the buffer in which to write the
                              received data.
@param pNumBytesReceived    On return, pointer to the number of bytes received.
@param timeout              Number of milliseconds the %client will wait
                              to receive the message. To specify no timeout
                              (an infinite wait), set this parameter to 0.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous NanoSSH clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_recvMessage(sbyte4 connectionInstance, sbyte4 *pMessageType, sbyte *pRetMessage, sbyte4 *pNumBytesReceived, ubyte4 timeout);

/**
@brief      Set a terminal window's dimensions.

@details    This function sets (resizes from the default size of 80 x 24) a
            %client terminal window's dimensions. This function is necessary
            when using the SSH client as an interactive shell. (For automated
            SSH client applications, this function is unnecessary.)

@ingroup    func_sshc.hli_shell_command

@since 3.2
@version 3.2 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__

@inc_file sshc.h

@param connectionInstance   Connection instance returned from SSHC_connect().
@param width                Terminal window's width, in characters.
@param height               Terminal window's height in characters.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous NanoSSH clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_setTerminalTextWindowSize(sbyte4 connectionInstance, ubyte4 width, ubyte4 height);

/**
@brief      Close an SSH session and releases all its resources.

@details    This function closes an SSH session and releases all resources
            that are managed by the NanoSSH %client.

@ingroup    func_ssh_core_client

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__

@inc_file sshc.h

@param connectionInstance  Connection instance returned from SSHC_connect().

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous NanoSSH clients.

@funcdoc    sshc.h
*/
MOC_EXTERN void SSHC_close(sbyte4 connectionInstance);

/**
@brief      Initiate an SSH re-key operation.

@details    This function initiates an SSH re-key operation. NanoSSH
            automatically processes re-key requests from an SSH %client.

@ingroup    func_ssh_core_client

@since 4.2
@version 4.2 and later

To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__

@param connectionInstance   Connection instance returned from SSHC_connect().
@param msAllowToComply      Number of milliseconds to wait for an SSH %client to
                              respond before closing the session. Zero (0)
                              indicates that the request is not being
                              strictly enforced.

@inc_file sshc.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous clients.
@remark     Many SSH implementations do not support re-keying.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_initiateReKey(sbyte4 connectionInstance, ubyte4 msAllowToComply);

/**
@brief      Get the number of bytes sent and received through a given
            connectionInstance.

@details    This function returns (through the \p pRetNumBytes parameter) the
            number of bytes sent and received through a given
            connectionInstance. Typical usage for this function is to
            determine when it's appropriate to initiate a re-key exchange
            operation.

@ingroup    func_ssh_core_client

@since 4.2
@version 4.2 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__

@param connectionInstance   Connection instance returned from SSHC_connect().
@param pRetNumBytes         On return, the number of bytes received and
                              transmitted.

@inc_file sshc.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_numBytesTransmitted(sbyte4 connectionInstance, ubyte8 *pRetNumBytes);

/**
@brief      Get a connection's cookie containing custom
            (application-specific) information.

@details    This function retrieves custom (application-specific) information
            stored in the connection instance's context. Your application
            should not call this function until after it calls SSHC_setCookie().

@ingroup    func_ssh_core_client

@since 1.41
@version 1.41 and later

@todo_version (pRetCookie changed type)

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__

@inc_file sshc.h

@param connectionInstance   Connection instance returned from SSHC_connect().
@param pRetCookie           On return, pointer to cookie containing custom
                              information.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous NanoSSH clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_getCookie(sbyte4 connectionInstance, void **pRetCookie);

/**
@brief      Save a cookie containing custom information.

@details    This function saves a cookie containing custom
            (application-specific) information about the context connection.
            Your application should not call this function until after it
            calls SSHC_connect().

@ingroup    func_ssh_core_client

@since 1.41
@version 1.41 and later

@todo_version (pRetCookie changed type)

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__

@inc_file sshc.h

@param connectionInstance   Connection instance returned from SSHC_connect().
@param cookie               Custom information (the cookie).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous NanoSSH clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_setCookie(sbyte4 connectionInstance, void* cookie);

/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
/**
@brief      Register the port number on which to listen for port forwarding
            messages from the SSH server.

@details    This function registers the port number on which to listen for
            port forwarding messages from the SSH server.

@ingroup    func_sshc_port_forwarding

@since 3.06
@version 3.06 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__
+ \c \__ENABLE_MOCANA_SSH_PORT_FORWARDING__

@inc_file sshc.h

@param connectionInstance   Connection instance returned from SSHC_connect().
@param pChannel             Pointer to port forwarding channel number
                              through which to send the message.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_lpfRegisterConnection( sbyte4 connectionInstance, ubyte4* pChannel);

/**
@brief      Start a port forwarding session.

@details    This function starts a port forwarding session by sending the
            required SSH message from SSH %client to the SSH server.

@ingroup    func_sshc_port_forwarding

@since 3.06
@version 3.06 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__
+ \c \__ENABLE_MOCANA_SSH_PORT_FORWARDING__

@inc_file sshc.h

@param connectionInstance   Connection instance returned from SSHC_connect().
@param channel              Port forwarding channel number through
                              which to send the message.
@param pConnectHost         Pointer to string representation of SSH server host
                              computer IP address.
@param connectPort          Port number through which to connect to the SSH
                              server host.
@param pSrcHost             Pointer to string representation of
                              originating computer IP address.
@param srcPort              Port number of originating computer's forwarding
                              connection.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_lpfStartConnection( sbyte4 connectionInstance, ubyte4 channel,
                                       ubyte* pConnectHost, ubyte4 connectPort,
                                       ubyte* pSrcHost, ubyte4 srcPort);

/**
@brief      Stop port forwarding through the specified SSH connection.

@details    This function stops port forwarding (terminates the connection)
            by sending an SSH \c CLOSE message to the SSH server.

@ingroup    func_sshc_port_forwarding

@since 3.06
@version 3.06 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__
+ \c \__ENABLE_MOCANA_SSH_PORT_FORWARDING__

@inc_file sshc.h

@param connectionInstance   Connection instance returned from SSHC_connect().
@param channel              Port forwarding channel number through
                              which to send the message.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_lpfStopConnection( sbyte4 connectionInstance, ubyte4 channel);

/**
@brief      Send local port forwarding connection data from SSH %client to
            SSH server.

@details    This function sends local port forwarding connection data from
            SSH %client to SSH server.

@ingroup    func_sshc_port_forwarding

@since 3.06
@version 3.06 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__
+ \c \__ENABLE_MOCANA_SSH_PORT_FORWARDING__

@inc_file sshc.h

@param connectionInstance   Connection instance returned from SSHC_connect().
@param channel              Port forwarding channel number through
                              which to send the message.
@param pBuffer              Pointer to message to forward.
@param bufferSize           Number of bytes in message to forward (\p pBuffer).
@param pBytesSent           On return, pointer to number of bytes forwarded.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_lpfSendMessage(sbyte4 connectionInstance, ubyte4 channel, sbyte *pBuffer, sbyte4 bufferSize, sbyte4 *pBytesSent);

/*! Forward port forwarding messages from an SSH server to local ports.
This function forwards port forwarding messages from an SSH server to local ports.

@ingroup    func_sshc_port_forwarding

@since 3.06
@version 3.06 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__
+ \c \__ENABLE_MOCANA_SSH_PORT_FORWARDING__

@inc_file sshc.h

@param connectionInstance   Connection instance returned from SSHC_connect().
@param useTimeout           TRUE to use the <em>dead man timer</em> specified
                              by the timeout parameter; FALSE otherwise.
@param timeout              Number of milliseconds to wait for the forwarding
                              result.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_doProtocolProcessPortForwardSession(sbyte4 connectionInstance, intBoolean useTimeout, ubyte4 timeout);
extern MSTATUS
SSHC_startRemotePortForwarding(sbyte4 connectionInstance, sbyte *pBindAddr, ubyte4 bindPort, sbyte *pHostAddr, ubyte4 hostPort);
extern MSTATUS
SSHC_cancelRemotePortForwarding(sbyte4 connectionInstance, sbyte *pHostAddr, ubyte4 hostPort);
#endif /*__ENABLE_MOCANA_SSH_PORT_FORWARDING__*/
/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_SSH_FTP_CLIENT__
/**
@brief      Open a file on an SFTP server.

@details    This function sends a request to the connected SSH/SFTP server to
            open an existing file for read and/or write operations.

@ingroup    func_ssh_sftp_io

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

@inc_file sshc.h

@param connectionInstance           Connection instance returned from
                                      SSHC_connect().
@param pFName                       Pointer to buffer containing directory name.
@param fileNameLen                  Number of bytes (characters) in the
                                      directory name (\p pFName).
@param readOrWrite                  ORed bitmask of the following flags:\n
                                    + \c SFTP_OPEN_FILE_READ_BINARY \n
                                    + \c SFTP_OPEN_FILE_WRITE_BINARY
@param pp_retSftpFileHandleDescr    Pointer to address of handle descriptor
                                      structure, which on return contains
                                      opened file's information.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous SFTP clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_openFile(sbyte4 connectionInstance, ubyte* pFName, ubyte4 pFNameLen, sbyte4 readOrWrite, sftpcFileHandleDescr **pp_retSftpFileHandleDescr);

/**
@brief      Read a file on an SFTP server.

@details    This function sends a request to the connected SSH/SFTP server to
            read the specified file and return its contents and the SFTP
            operation status through the function parameters. If the entire
            file was read successfully, \c SSH_FTP_EOF is returned as the
            SFTP operation status (obtained by calling
            SSHC_sftpRequestStatusCode()).

@ingroup    func_ssh_sftp_io

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

@inc_file sshc.h

@param connectionInstance       Connection instance returned from
                                  SSHC_connect().
@param p_sftpFileHandleDescr    Pointer to handle descriptor structure
                                  containing the desired file's information.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous SFTP clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_readFile(sbyte4 connectionInstance, sftpcFileHandleDescr *p_sftpFileHandleDescr);

/**
@brief      Write a file to an SFTP server.

@details    This function sends a write file request to the connected
            SSH/SFTP server and returns the SFTP operation status through the
            \p p_sftpFileHandleDescr parameter. \c SSH_FTP_EOF indicates
            success. (To obtain the SFTP operation status, call
            SSHC_sftpRequestStatusCode().)

@ingroup    func_ssh_sftp_io

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

@inc_file sshc.h

@param connectionInstance       Connection instance returned from
                                  SSHC_connect().
@param p_sftpFileHandleDescr    File handle descriptor returned from
                                  SSHC_openFile().

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous SFTP clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_writeFile(sbyte4 connectionInstance, sftpcFileHandleDescr *p_sftpFileHandleDescr);

/**
@brief      Close a file on an SFTP server.

@details    This function sends a close file request to the connected
            SSH/SFTP server, disabling the file from further access until it
            is reopened.

@ingroup    func_ssh_sftp_io

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

@inc_file sshc.h

@param connectionInstance       Connection instance returned from
                                  SSHC_connect().
@param p_sftpFileHandleDescr    File handle descriptor returned from
                                  SSHC_openFile().

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous SFTP clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_closeFile(sbyte4 connectionInstance, sftpcFileHandleDescr *p_sftpFileHandleDescr);

/*! Open a directory.
This function sends an open directory request to the connected SSH/SFTP server.

@since 1.41
@version 1.41 and later

@ingroup    func_ssh_sftp_dir_listing

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

@inc_file sshc.h

@param connectionInstance       Connection instance returned from
                                  SSHC_connect().
@param pPath                    Pointer to buffer containing directory name.
@param pathLen                  Number of bytes (characters) in the directory
                                  name (\p pPath).
@param pp_sftpFileHandleDescr   Pointer to address of handle descriptor
                                  structure, which on return contains the
                                  opened directory's information.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@note       A directory must be open before it can be read.

@remark     This function is applicable to synchronous SFTP clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_openDirectory(sbyte4 connectionInstance, ubyte *pPath, ubyte4 pathLen, sftpcFileHandleDescr** pp_sftpFileHandleDescr);

/**
@brief      Get a directory's list of files (using a read directory request).

@details    This function sends a read directory request to the connected
            SSH/SFTP server to return the specified directory's list of files
            (through the \p ppRetFilename parameter).

@ingroup    func_ssh_sftp_dir_listing

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

@inc_file sshc.h

@param connectionInstance       Connection instance returned from
                                  SSHC_connect().
@param p_sftpFileHandleDescr    Pointer to handle descriptor structure
                                  containing the desired directory's information.
@param ppRetFilename            Pointer to address of \c ubyte buffer, which
                                  on return contains the directory's
                                  filenames as strings.
@param pRetFilenameLen          Pointer to \c ubyte4, which on return contains
                                  the number of bytes in the \p ppRetFilename
                                  buffer.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous SFTP clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_readDirectory(sbyte4 connectionInstance, sftpcFileHandleDescr* p_sftpFileHandleDescr, ubyte **ppRetFilename, ubyte4 *pRetFilenameLen);

/**
@brief      Close a directory on an SFTP server.

@details    This function sends a close directory request to the connected
            SSH/SFTP server to close an open directory, disabling it from
            further access.

@ingroup    func_ssh_sftp_dir_listing

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

@inc_file sshc.h

@param connectionInstance       Connection instance returned from
                                  SSHC_connect().
@param p_sftpFileHandleDescr    File handle returned from SSHC_openDirectory().

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous SFTP clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_closeDirectory(sbyte4 connectionInstance, sftpcFileHandleDescr* p_sftpFileHandleDescr);

/**
@brief      Get a directory's size (number of bytes).

@details    This function determines whether the specified directory's
            attributes are set. If so, \c TRUE is returned through the
            \p pRetIsPresent parameter, and the directory attribute's
            \c SSH_FILEXFER_ATTR_SIZE bit flag is checked. If the bit
            flag is set, the \p RetFileSize parameter value is set to the
            number of bytes used by the directory; otherwise the
            \p RetFileSize value is set to 0.

For a list of handle descriptor attribute flags, see @ref sshc_hnd_desc_flags.

@ingroup    func_ssh_sftp_dir_listing

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

@inc_file sshc.h

@param connectionInstance       Connection instance returned from
                                  SSHC_connect().
@param p_sftpFileHandleDescr    Pointer to file handle descriptor.
@param pRetFileSize             (Valid only if \p pRetIsPresent value is \c
                                  TRUE) On return, pointer to number of bytes
                                  used by the directory (if the attribute's 
                                  \c SSH_FILEXFER_ATTR_SIZE bit flag is set)
                                  or 0.
@param pRetIsPresent            On return, pointer to \c TRUE (if the handle
                                  descriptor's directory attributes are set)
                                  or \c FALSE.

@return     None.

@remark     This function is applicable to synchronous SFTP clients.

@funcdoc    sshc.h
*/
MOC_EXTERN void   SSHC_sftpGetDirEntryFileSize(sbyte4 connectionInstance, sftpcFileHandleDescr *p_sftpFileHandleDescr, ubyte4 *pRetFileSize, intBoolean *pRetIsPresent);

/**
@brief      Get a directory's type.

@details    This function determines whether the specified directory's
            attributes are set. If so, \c TRUE is returned through the
            \p pRetIsPresent parameter, and the directory attribute's type is
            returned through the \p pRetFileType parameter.

@note       The directory type is available only for SFTP version 4 and
            later. If this function is called for SFTP versions 3 and
            earlier, \c FALSE is returned through the \p pRetIsPresent
            parameter.

@ingroup    func_ssh_sftp_dir_listing

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

@inc_file sshc.h

@param connectionInstance       Connection instance returned from
                                  SSHC_connect().
@param p_sftpFileHandleDescr    Pointer to file handle descriptor.
@param pRetFileType             (Valid only if \p pRetIsPresent value is
                                  \c TRUE) On return, pointer to value
                                  indicating directory type (definitions in
                                  ssh_defs.h):\n
+ \c SSH_FILEXFER_TYPE_REGULAR \n
+ \c SSH_FILEXFER_TYPE_DIRECTORY \n
+ \c SSH_FILEXFER_TYPE_SYMLINK \n
+ \c SSH_FILEXFER_TYPE_SPECIAL \n
+ \c SSH_FILEXFER_TYPE_UNKNOWN

@param pRetIsPresent            On return, pointer to \c TRUE (if the handle
                                  descriptor's directory attributes are set)
                                  or \c FALSE.

@return     None.

@remark     This function is applicable to synchronous SFTP clients.

@funcdoc    sshc.h
*/
MOC_EXTERN void   SSHC_sftpGetDirEntryFileType(sbyte4 connectionInstance, sftpcFileHandleDescr *p_sftpFileHandleDescr, ubyte4 *pRetFileType, intBoolean *pRetIsPresent);

/**
@brief      Determine whether a directory's file permission flag is set.

@details    This function determines the specified directory's attributes are
            set. If so, \c TRUE is returned through the \p pRetIsPresent
            parameter, and the \p pRetFilePermission parameter value is set to
            \c TRUE or \c FALSE to indicate whether the
            \c SSH_FILEXFER_ATTR_PERMISSIONS bit flag is set or clear in the
            directory attribute's bitmask. If the attributes are not set, 
            \c FALSE is returned trough the \p pRetFilePermission parameter.

For a list of handle descriptor attribute flags, see @ref sshc_hnd_desc_flags.

@ingroup    func_ssh_sftp_dir_listing

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

@inc_file sshc.h

@param connectionInstance       Connection instance returned from
                                  SSHC_connect().
@param p_sftpFileHandleDescr    Pointer to file handle descriptor.
@param pRetFilePermission       (Valid only if pRetIsPresent value is \c TRUE)
                                  On return, pointer to \c TRUE (if the
                                  attribute's \c
                                  SSH_FILEXFER_ATTR_PERMISSIONS bit flag is
                                  set) or \c FALSE.
@param pRetIsPresent            On return, pointer to \c TRUE (if the handle
                                  descriptor's directory attributes are set)
                                  or \c FALSE.

@return     None.

@remark     This function is applicable to synchronous SFTP clients.

@funcdoc    sshc.h
*/
MOC_EXTERN void   SSHC_sftpGetDirEntryFilePermission(sbyte4 connectionInstance, sftpcFileHandleDescr *p_sftpFileHandleDescr, ubyte4 *pRetFilePermission, intBoolean *pRetIsPresent);

/**
@brief      Set a file's cookie value (custom information).

@details    This function assigns the specified cookie value (custom
            information) to the specified file handle descriptor's cookie field.

@ingroup    func_ssh_sftp_client_general

@since 1.41
@version 1.41 and later

@todo_version (changes to sftpCookie arg type)

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

@inc_file sshc.h

@param p_sftpFileHandleDescr  Pointer to file handle descriptor.
@param sftpCookie             Value to assign to the cookie.

@return     None.

@sa SSHC_sftpGetCookie

@remark     This function is applicable to synchronous SFTP clients.

@funcdoc    sshc.h
*/
MOC_EXTERN void   SSHC_sftpSetCookie(sftpcFileHandleDescr *p_sftpFileHandleDescr, void* sftpCookie);

/**
@brief      Get a file's cookie value.

@details    This function returns the cookie value of the specified file
            handle descriptor.

@ingroup    func_ssh_sftp_client_general

@since 1.41
@version 1.41 and later

@todo_version (changes to return type)

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

@inc_file sshc.h

@param p_sftpFileHandleDescr    Pointer to file handle descriptor.

@return     Cookie's value.

@sa SSHC_sftpSetCookie

@remark     This function is applicable to synchronous SFTP clients.

@funcdoc    sshc.h
*/
MOC_EXTERN void*  SSHC_sftpGetCookie(sftpcFileHandleDescr *p_sftpFileHandleDescr);

/**
@brief      Get a file's SFTP operation status.

@details    This function returns the specified file's SFTP operation status
            (see @ref sshc_ftp_status_codes).

@ingroup    func_ssh_sftp_client_general

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

@inc_file sshc.h

@param p_sftpFileHandleDescr    Pointer to file handle descriptor.

@return     File's SFTP operation status (see @ref sshc_ftp_status_codes).

@remark     This function is applicable to synchronous SFTP clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_sftpRequestStatusCode(sftpcFileHandleDescr *p_sftpFileHandleDescr);

/**
@brief      Release (free) memory used to store a file/directory descriptor
            handle.

@details    This function releases (frees) memory used to store the specified
            file/directory descriptor handle.

@ingroup    func_ssh_sftp_client_memory_mgmt

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

@inc_file sshc.h

@param connectionInstance       Connection instance returned from
                                  SSHC_connect().
@param pp_sftpFileHandleDescr   Pointer to address of handle descriptor
                                  structure.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_freeHandle(sbyte4 connectionInstance, sftpcFileHandleDescr** pp_sftpFileHandleDescr);

/**
@brief      Release memory used to store a filename.

@details    This function releases the memory used to store the specified
            filename.

@ingroup    func_ssh_sftp_client_memory_mgmt

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

@inc_file sshc.h

@param connectionInstance   Connection instance returned from SSHC_connect().
@param ppFreeFilename       Pointer to address of buffer containing the
                              NULL-terminated filename string.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous SFTP clients.

@funcdoc    sshc_ftp.c
*/
MOC_EXTERN sbyte4 SSHC_freeFilename(sbyte4 connectionInstance, ubyte **ppFreeFilename);

/**
@brief      Get a file's current read location.

@details    This function returns the specified file descriptor's current
            read location. The read file upcall typically calls this function
            to track read progress.

@ingroup    func_ssh_sftp_get

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

@inc_file sshc.h

@param p_sftpFileHandleDescr    Pointer to file handle descriptor.

@return 0-based byte index of file's current read location.

@remark     This function is applicable to synchronous SFTP clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_sftpReadLocation(sftpcFileHandleDescr *p_sftpFileHandleDescr);

/**
@brief      Get a pointer to a file's read data buffer.

@details    This function returns a pointer to a buffer in which data read
            from a file is stored.

@ingroup    func_ssh_sftp_get

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

@inc_file sshc.h

@param p_sftpFileHandleDescr    Pointer to file handle descriptor.

@return     Pointer to a buffer containing a file's read data.

@remark     This function is applicable to synchronous SFTP clients.

@sa SSHC_sftpReadBufferSize

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte* SSHC_sftpReadBuffer(sftpcFileHandleDescr *p_sftpFileHandleDescr);

/**
@brief      Get the number of bytes in a file's read buffer.

@details    This function returns the number of bytes in the specified file
            descriptor's read buffer.

@ingroup    func_ssh_sftp_get

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

@inc_file sshc.h

@param p_sftpFileHandleDescr    Pointer to file handle descriptor.

@return     Number of bytes in the file's read buffer.

@remark     This function is applicable to synchronous SFTP clients.

@sa SSHC_sftpReadBuffer

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_sftpReadBufferSize(sftpcFileHandleDescr *p_sftpFileHandleDescr);

/**
@brief      Get the number of bytes read from an open file.

@details    This function returns the number of bytes already read from the
            specified open file. Typically an application first calls
            SSHC_openFile() and then calls this function to keep track of
            download (read) progress.

@ingroup    func_ssh_sftp_io

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

@inc_file sshc.h

@param p_sftpFileHandleDescr    Pointer to file handle descriptor.

@return     Number of bytes already read from the file.

@remark     This function is applicable to synchronous SFTP clients.

@note       After the file download (read) is complete, the file should be
            closed by calling SSHC_closeFile().

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_sftpNumBytesRead(sftpcFileHandleDescr *p_sftpFileHandleDescr);

/**
@brief      Get a file's current write location.

@details    This function returns the specified file descriptor's current
            write location. The read file upcall typically calls this
            function to track write progress.

@ingroup    func_ssh_sftp_put

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

@inc_file sshc.h

@param p_sftpFileHandleDescr    Pointer to file handle descriptor.

@return     0-based byte index of file's current write location.

@remark     This function is applicable to synchronous SFTP clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_sftpWriteLocation(sftpcFileHandleDescr *p_sftpFileHandleDescr);

/**
@brief      Get a pointer to a file's write data buffer.

@details    This function returns a pointer to a buffer in which data written
            to a file is stored.

@ingroup    func_ssh_sftp_put

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

@inc_file sshc.h

@param p_sftpFileHandleDescr    Pointer to file handle descriptor.

@return     Pointer to a buffer containing a file's write data.

@remark     This function is applicable to synchronous SFTP clients.

@sa SSHC_sftpWriteBufferSize

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte* SSHC_sftpWriteBuffer(sftpcFileHandleDescr *p_sftpFileHandleDescr);

/**
@brief      Get the number of bytes in a file's write buffer.

@details    This function returns the number of bytes in the specified file
            descriptor's write buffer.

@ingroup    func_ssh_sftp_put

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

@inc_file sshc.h

@param p_sftpFileHandleDescr    Pointer to file handle descriptor.

@return     Number of bytes in the file's write buffer.

@remark     This function is applicable to synchronous SFTP clients.

@sa SSHC_sftpReadBuffer

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_sftpWriteBufferSize(sftpcFileHandleDescr *p_sftpFileHandleDescr);

/**
@brief      Get the number of bytes written to an open file.

@details    This function returns the number of bytes already written to the
            specified open file. Typically an application first calls
            SSHC_openFile() and then calls this function to keep track of
            upload (write) progress.

@ingroup    func_ssh_sftp_put

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

@inc_file sshc.h

@param p_sftpFileHandleDescr    Pointer to file handle descriptor.

@return     Number of bytes already written to the file.

@remark     This function is applicable to synchronous SFTP clients.

@note       After the file download (read) is complete, the file should be
            closed by calling SSHC_closeFile().

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_sftpNumBytesWritten(sftpcFileHandleDescr *p_sftpFileHandleDescr);

/**
@brief      Get a file's statistics from an SFTP server.

@details    This function sends a request to the connected SSH/SFTP server to
            return the specified file's statistics, such as file size and type.

@ingroup    func_ssh_sftp_file_dir_mgmt

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

@inc_file sshc.h

@param connectionInstance       Connection instance returned from
                                  SSHC_connect().
@param pGetStatFile             Pointer to buffer containing name of file to
                                  evaluate.
@param getStatFileLen           Number of bytes (characters) in the filename
                                  (\p getStatFileLen).
@param pp_sftpFileHandleDescr   Pointer to address of handle descriptor
                                  structure, which on return contains file's
                                  statistics.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous SFTP clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_getFileStat(sbyte4 connectionInstance, ubyte *pGetStatFile, ubyte4 getStatFileLen, sftpcFileHandleDescr** pp_sftpFileHandleDescr);

/**
@brief      Get the fully-qualified directory path of an an SSH Client's
            virtual directory.

@details    This function retrieves (from the connected SSH/SFTP server) the
            fully-qualified directory path corresponding to the specified SSH
            Client's virtual directory. This is useful for converting path
            names containing <tt>".."</tt> components, or relative pathnames
            without a leading slash, into absolute paths.

@ingroup    func_ssh_sftp_file_dir_mgmt

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

@inc_file sshc.h

@param connectionInstance       Connection instance returned from
                                  SSHC_connect().
@param pRealpath                Pointer to buffer containing SSH Client's
                                  virtual directory name.
@param realpathLen              Number of bytes (characters) in the virtual
                                  directory name (\p pRealpath).
@param pp_sftpFileHandleDescr   Pointer to address of handle descriptor
                                  structure, which on return contains real
                                  directory's information.
@param ppRetRealpath            Pointer to address of \c ubyte buffer, which
                                  on return contains the real directory's
                                  name as a string.
@param pRetRealpathLen          Pointer to \c ubyte4, which on return contains
                                  the number of bytes in the real directory's
                                  name (\p ppRetRealpath).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous SFTP clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_realpath(sbyte4 connectionInstance, ubyte *pRealpath, ubyte4 realpathLen, sftpcFileHandleDescr** pp_sftpFileHandleDescr, ubyte **ppRetRealpath, ubyte4 *pRetRealpathLen);

/**
@brief      Delete a file from an SFTP server.

@details    This function sends a delete file request to the connected
            SSH/SFTP server.

@ingroup    func_ssh_sftp_file_dir_mgmt

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

@inc_file sshc.h

@param connectionInstance       Connection instance returned from
                                  SSHC_connect().
@param pRemoveFileName          Pointer to buffer containing name of file to
                                  delete.
@param removeFileNameLen        Number of bytes (characters) in the filename
                                  (\p pRemoveFileName).
@param pp_sftpFileHandleDescr   Pointer to address of file's handle
                                  descriptor structure; on return it will be
                                  NULL.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous SFTP clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_removeFile(sbyte4 connectionInstance, ubyte *pRemoveFileName, ubyte4 removeFileNameLen, sftpcFileHandleDescr** pp_sftpFileHandleDescr);

/**
@brief      Create a directory on an SFTP server.

@details    This function sends create directory request to the connected
            SSH/SFTP server to create a directory as specified by the
            function parameter values.

@ingroup    func_ssh_sftp_file_dir_mgmt

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

@inc_file sshc.h

@param connectionInstance       Connection instance returned from
                                  SSHC_connect().
@param pNewDirName              Pointer to buffer containing desired
                                  directory name.
@param newDirNameLen            Number of bytes (characters) in the desired
                                  directory name (\p pNewDirName).
@param pp_sftpFileHandleDescr   Pointer to address of handle descriptor
                                  structure, which on return contains the
                                  created directory's information.
@param pFuture                  (Reserved for future use.)

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous SFTP clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_mkdir(sbyte4 connectionInstance, ubyte *pNewDirName, ubyte4 newDirNameLen, sftpcFileHandleDescr** pp_sftpFileHandleDescr, void *pFuture);

/**
@brief      Delete a directory from an SFTP server.

@details    This function sends a delete direcotyr request to the connected
            SSH/SFTP server.

@ingroup    func_ssh_sftp_file_dir_mgmt

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

@inc_file sshc.h

@param connectionInstance       Connection instance returned from
                                  SSHC_connect().
@param pRemoveDirName           Pointer to buffer containing name of directory
                                  to delete.
@param removeDirNameLen         Number of bytes (characters) in the directory
                                  name (\p pRemoveDirName).
@param pp_sftpFileHandleDescr   Pointer to address of directory's handle
                                  descriptor structure; on return it will be
                                  \c NULL.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous SFTP clients.

@funcdoc    sshc.h
*/
MOC_EXTERN sbyte4 SSHC_rmdir(sbyte4 connectionInstance, ubyte *pRemoveDirName, ubyte4 removeDirNameLen, sftpcFileHandleDescr** pp_sftpFileHandleDescr);

/**
@brief      Generate an exportable public key from an internal public key BLOB.

@details    This function generates an exportable public key from the
            specified internal public key BLOB. For exportable public key
            format, see the IETF Internet-Draft for <em>SSH Public Key File
            Format</em>:
            http://tools.ietf.org/html/draft-ietf-secsh-publickeyfile-13.

@ingroup    func_ssh_sftp_client_auth_key

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__

@inc_file sshc.h

@param pKeyBlob                 Pointer to key blob.
@param keyBlobLen               Number of bytes in the key blob (\p pKeyBlob).
@param ppRetEncodedAuthKey      Pointer to address of encoded authentication
                                  key, which on return contains the user's
                                  public key.
@param pRetEncodedAuthKeyLen    Pointer to ubyte4, which on return contains
                                  the number of bytes in the user's public
                                  key (\p ppRetEncodedAuthKey).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous NanoSSH clients.

@funcdoc    sshc.h
*/
MOC_EXTERN MSTATUS SSHC_generateServerAuthKeyFile(ubyte *pKeyBlob, ubyte4 keyBlobLen, ubyte **ppRetEncodedAuthKey, ubyte4 *pRetEncodedAuthKeyLen);

/**
@brief      Parses an exportable public key and generates an AsymmetricKey
            object.

@details    This function takes a exportable public key file and generates
            a AsymmetricKey object. Format of file is algorithm identifier,
            followed by a white space, followed by the base64 encoded public key.

@ingroup    func_ssh_sftp_client_auth_key

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__

@inc_file sshc.h

@param pKeyFile                 Pointer to buffer containing an SSH key file.
@param keyFileLen               Number of bytes in key file buffer (\p pKeyFile).
@param pAsymKey                 Pointer to an AsymmetricKey object into which the
                                  key will be placed.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous NanoSSH clients.

@funcdoc    sshc.h
*/
MOC_EXTERN MSTATUS SSHC_parseServerAuthKeyFile(ubyte* pKeyFile, ubyte4 keyFileLen,
    AsymmetricKey *pAsymKey);

/**
@brief      Parses an public key and generates an AsymmetricKey object.

@details    This function takes a public key and generates
            a AsymmetricKey object. For public key formats, see:
              https://tools.ietf.org/html/rfc4253#section-6.6 for rsa and dsa.
              https://tools.ietf.org/html/rfc5656#section-3.1 for ecdsa
              https://tools.ietf.org/html/draft-ietf-curdle-ssh-ed25519-02 for ed25519

@ingroup    func_ssh_sftp_client_auth_key

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__

@inc_file sshc.h

@param pKeyBlob                 Pointer to buffer containing public key.
@param keyBlobLen               Number of bytes in key buffer (\p pKeyBlob).
@param pAsymKey                 Pointer to an AsymmetricKey object into which the
                                  key will be placed.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous NanoSSH clients.

@funcdoc    sshc.h
*/
MOC_EXTERN MSTATUS SSHC_parsePublicKeyBuffer(ubyte* pKeyFile, ubyte4 keyFileLen,
    AsymmetricKey *pAsymKey);

/**
@brief      Release an authentication key's memory.

@details    This function releases the memory used to store the specified
            authentication key.

@ingroup    func_ssh_sftp_client_auth_key

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__

@inc_file sshc.h

@param ppFreeEncodedAuthKey     Pointer to address of buffer containing the
                                  NULL-terminated authentication key string.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous NanoSSH clients.

@funcdoc    sshc.h
*/
MOC_EXTERN MSTATUS SSHC_freeGenerateServerAuthKeyFile(ubyte **ppFreeEncodedAuthKey);

#endif

#ifdef __cplusplus
}
#endif

#endif /* __SSHC_HEADER__ */
