/*
 * ssh.h
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

/**
@file       ssh.h
@brief      NanoSSH server developer API header.
@details    This header file contains definitions, enumerations, structures, and
            function declarations used by NanoSSH server.

@since 1.41
@version 4.0 and later

@flags
To build products using this header file, at least one of the following flags
must be defined (in a file included before %ssh.h is included):
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

Whether the following flags are defined determine which enumerations, structures,
and function declarations are enabled:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__
+ \c \__USE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_PORT_FORWARDING__

@filedoc    ssh.h
*/


/*------------------------------------------------------------------*/

#ifndef __SSH_HEADER__
#define __SSH_HEADER__

#include "../common/mtcp.h"
#ifdef __cplusplus
extern "C" {
#endif

#if !defined( __ENABLE_DIGICERT_SSH_SERVER__ ) && defined( __ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__ )
#define __ENABLE_DIGICERT_SSH_SERVER__
#endif


/*------------------------------------------------------------------*/

/* message types */
enum sshSessionTypes
{
    SSH_SESSION_NOTHING,
    SSH_SESSION_OPEN,
    SSH_SESSION_OPEN_PF,
    SSH_SESSION_PTY_REQUEST,
    SSH_SESSION_OPEN_SHELL,
    SSH_SESSION_OPEN_SFTP,
    SSH_SESSION_OPEN_EXEC,
    SSH_SESSION_WINDOW_CHANGE,
    SSH_SESSION_DATA,
    SSH_SESSION_STDERR,
    SSH_SESSION_EOF,
    SSH_SESSION_CLOSED,
    SSH_SESSION_CHANNEL_CLOSED,
    SSH_PF_CLOSED,
    SSH_PF_EOF,
    SSH_SESSION_BREAK_OP,
    SSH_SESSION_PING_REPLY,
    SSH_PF_DATA
};


/*------------------------------------------------------------------*/

enum asyncWaitEvents
{
    kNotWaiting = 0,
    kWaitingForAuth,
    kWaitingForHwOffload
};


/*------------------------------------------------------------------*/

/* timeouts in milliseconds (zero indicates no timeout) */
#ifndef TIMEOUT_SSH_OPEN
#define TIMEOUT_SSH_OPEN                        (2000)
#endif

#ifndef TIMEOUT_SSH_KEX
#ifdef __ENABLE_DIGICERT_PQC__
 #define TIMEOUT_SSH_KEX                         (120000)
#else
 #define TIMEOUT_SSH_KEX                         (10000)
#endif
#endif

#ifndef TIMEOUT_SSH_NEWKEYS
#ifdef __ENABLE_DIGICERT_PQC__
 #define TIMEOUT_SSH_NEWKEYS                     (120000)
#else
 #define TIMEOUT_SSH_NEWKEYS                     (15000)
#endif
#endif

#ifndef TIMEOUT_SSH_SERVICE_REQUEST
#ifdef __ENABLE_DIGICERT_PQC__
 #define TIMEOUT_SSH_SERVICE_REQUEST             (120000)
#else
 #define TIMEOUT_SSH_SERVICE_REQUEST             (4000)
#endif
#endif

#ifndef TIMEOUT_SSH_OPEN_STATE
#define TIMEOUT_SSH_OPEN_STATE                  (0)
#endif

/* the most interesting of these values, the amount of time we allow the user to authenticate */
#ifndef TIMEOUT_SSH_AUTH_LOGON
#ifdef __ENABLE_DIGICERT_PQC__
 #define TIMEOUT_SSH_AUTH_LOGON                  (1000 * 60 * 200)
#else
 #define TIMEOUT_SSH_AUTH_LOGON                  (1000 * 60 * 10)
#endif
#endif

/* suggested by SSHv2 standard, max number of authentication attempts */
#ifndef MAX_SSH_AUTH_ATTEMPTS
#define MAX_SSH_AUTH_ATTEMPTS                   (20)
#endif

/* sizes */
#ifndef SSH_MAX_BUFFER_SIZE
#ifdef __ENABLE_DIGICERT_PQC__
#define SSH_MAX_BUFFER_SIZE                     (2097152)
#else
#define SSH_MAX_BUFFER_SIZE                     (1024*4)
#endif
#endif

#ifndef MAX_SESSION_WINDOW_SIZE
#define MAX_SESSION_WINDOW_SIZE                 (1024*2)
#endif

#ifndef SSH_SYNC_BUFFER_SIZE
#define SSH_SYNC_BUFFER_SIZE                    (512)
#endif

#ifndef MOCANA_SSH_SOCKET_STREAM_SIZE
#define MOCANA_SSH_SOCKET_STREAM_SIZE           (4096)
#endif

#if (MAX_SESSION_WINDOW_SIZE > SSH_MAX_BUFFER_SIZE)
#error ssh.h: SSH_MAX_BUFFER_SIZE must be greater than MAX_SESSION_WINDOW_SIZE
#endif

/* SSH Key Blob Types */
#define SSH_PUBLIC_KEY_BLOB                     1
#define SSH_PRIVATE_KEY_BLOB                    2

/* SSH Advertised Authentication Methods (OR for multiple types) */
#define MOCANA_SSH_AUTH_NONE                    0x10
#define MOCANA_SSH_AUTH_PUBLIC_KEY              0x80
#define MOCANA_SSH_AUTH_PASSWORD                0x40
#define MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE    0x20

#define SSH_DEFAULT_TCPIP_PORT                  (22)

/* authentication results */
#define AUTH_FAIL                               (0)
#define AUTH_PASS                               (1)
#define AUTH_MORE                               (2)
#define AUTH_WAIT                               (3)
#define AUTH_FAIL_MORE                          (4)

/* authentication keyboard interactive */
#define AUTH_ECHO                               (1)
#define AUTH_NO_ECHO                            (0)

#ifndef AUTH_MAX_NUM_PROMPTS
#define AUTH_MAX_NUM_PROMPTS                    3
#endif

/* stream buffer sizes */
#ifndef SFTP_SERVER_STREAM_BUF_SIZE
#define SFTP_SERVER_STREAM_BUF_SIZE             (4096)
#endif

#ifdef __ENABLE_DIGICERT_SSH_PORT_FORWARDING__
#define MOCANA_SSH_ALLOW_DIRECT_TCPIP             (0x00010000)
#define MOCANA_SSH_ALLOW_FORWARDED_TCPIP          (0x00020000)
#define MOCANA_SSH_ALLOW_PRIVILEGED_DIRECT_TCPIP  (0x00040000)
#define MOCANA_SSH_ALLOW_PRIVILEGED_FORWARD_TCPIP (0x00080000)
#define MOCANA_SSH_REVERSE_PORT_FWD_PORT_VALUE    (25000)
#endif

/* SSH ioctls */
#define SET_SSH_MAX_SESSION_TIME_LIMIT           (1)


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

} terminalState;

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

struct certStore;
typedef struct certStore* certStorePtr;

/**
@brief      Configuration settings and callback function pointers for NanoSSH
            servers.

@details    This structure is used for NanoSSH server configuration. Which
            products and features you've included (by defining the appropriate
            flags in moptions.h) determine which callback functions are present
            in this structure. Each included callback function should be
            customized for your application and then registered by assigning it
            to the appropriate structure function pointer(s).

@since 1.41
@version 1.41 and later

@flags
To use this structure, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

*/
typedef struct
{
/**
@brief      Maximum number of connections to this server.
@details    Maximum number of connections to this server.
*/
    sbyte4          sshMaxConnections;

/**
@brief      Port number for the connection context.
@details    Port number for the connection context.
*/
    ubyte4          sshListenPort;

/**
@brief      Number of authentication tries allowed before the connection is said
              to have failed.
@details    Number of authentication tries allowed before the connection is said
              to have failed.
*/
    ubyte4          sshMaxAuthAttempts;

/**
@brief      Number of milliseconds the server waits for an open session response
              before timing out.
@details    Number of milliseconds the server waits for an open session response
              before timing out.
*/
    ubyte4          sshTimeOutOpen;

/**
@brief      Number of milliseconds the server waits for a key exchange before
              timing out.
@details    Number of milliseconds the server waits for a key exchange before
              timing out.
*/
    ubyte4          sshTimeOutKeyExchange;

/**
@brief      Number of milliseconds the server waits for new keys before timing
              out.
@details    Number of milliseconds the server waits for new keys before timing
              out.
*/
    ubyte4          sshTimeOutNewKeys;

/**
@brief      Number of milliseconds the server waits for a service request
              response before timing out.
@details    Number of milliseconds the server waits for a service request
              response before timing out.
*/
    ubyte4          sshTimeOutServiceRequest;

/**
@brief      Number of milliseconds the server waits for an authentication
              response before timing out.
@details    Number of milliseconds the server waits for an authentication
              response before timing out.
*/
    ubyte4          sshTimeOutAuthentication;

/**
@brief      Number of milliseconds the server waits after authentication for a
              %client to make a request (such as open a shell).
@details    Number of milliseconds the server waits after authentication for a
              %client to make a request (such as open a shell).
*/
    ubyte4          sshTimeOutDefaultOpenState;

#if ((defined(__ENABLE_DIGICERT_SSH_OCSP_SUPPORT__)) && (defined(__ENABLE_DIGICERT_OCSP_CLIENT__)))
    sbyte *         pOcspResponderUrl;
#if (defined(__ENABLE_DIGICERT_OCSP_TIMEOUT_CONFIG__))
    ubyte4          ocspTimeout;
#endif
#endif

    /* protocol specific upcalls */

/**
@brief      Respond to a %client session request.

@details    This callback function is invoked when a %client requests a session
            with the NanoSSH server, after the %client is successfully
            authenticated (message type \c SSH_SESSION_OPEN). Your application
            can do anything when it receives this call, but no particular action
            is required.

@ingroup    cb_sshs_protocol_specific

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param sessionEvent         Any of the \c sshSessionTypes enumerated values (see
                              ssh.h).
@param pMesg                Not used for this upcall.
@param mesgLen              Not used for this upcall.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc ssh.h
*/
    sbyte4(*funcPtrSessionOpen)   (sbyte4 connectionInstance, enum sshSessionTypes sessionEvent, ubyte *pMesg, ubyte4 mesgLen);

/**
@brief      Respond to receipt of a %client's terminal emulation settings.

@details    This callback function is invoked when a %client sends terminal
            emulation settings to the NanoSSH Server (message type
            \c SSH_SESSION_PTY_REQUEST).

@ingroup    cb_sshs_protocol_specific

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstanc    Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param sessionEvent         Any of the \c sshSessionTypes enumerated values (see ssh.h).
@param pMesg                Not used for this upcall.
@param mesgLen              Not used for this upcall.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc ssh.h
*/
    sbyte4(*funcPtrPtyRequest)    (sbyte4 connectionInstance, enum sshSessionTypes sessionEvent, ubyte *pMesg, ubyte4 mesgLen);

/**
@brief      Respond to the establishment of a secure session.

@details    This callback function is invoked when a secure session is
            established after authentication (message type
            \c SSH_SESSION_OPEN_SHELL).

@ingroup    cb_sshs_protocol_specific

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param sessionEvent         Any of the \c sshSessionTypes enumerated values (see
                              ssh.h).
@param pMesg                Not used for this upcall.
@param mesgLen              Not used for this upcall.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc ssh.h
*/
    sbyte4(*funcPtrOpenShell)     (sbyte4 connectionInstance, enum sshSessionTypes sessionEvent, ubyte *pMesg, ubyte4 mesgLen);

/**
@brief      Respond to the opening of a %client SFTP session.

@details    This callback function is invoked when a %client opens an SFTP
            session to the NanoSSH server (message type
            \c SSH_SESSION_OPEN_SFTP).

@ingroup    cb_sshs_protocol_specific

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param sessionEvent         Any of the \c sshSessionTypes enumerated values (see
                              ssh.h).
@param pMesg                Not used for this upcall.
@param mesgLen              Not used for this upcall.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc ssh.h
*/
    sbyte4(*funcPtrOpenSftp)      (sbyte4 connectionInstance, enum sshSessionTypes sessionEvent, ubyte *pMesg, ubyte4 mesgLen);

/**
@brief      Respond to a change in a client's terminal window size.

@details    This callback function is invoked when a client's terminal window
            changes size. Your application can do anything when it receives this
            call, but no particular action is required.

@ingroup    cb_sshs_protocol_specific

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param sessionEvent         Any of the \c sshSessionTypes enumerated values (see
                              ssh.h).
@param pMesg                Not used for this upcall.
@param mesgLen              Not used for this upcall.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc ssh.h
*/
    sbyte4(*funcPtrWindowChange)  (sbyte4 connectionInstance, enum sshSessionTypes sessionEvent, ubyte *pMesg, ubyte4 mesgLen);

/**
@brief      (Optional) Custom receive data handler.

@details    This callback function is invoked when the server receives text data
            from a %client. Your application can do anything when it receives
            this call, but no particular action is required.

@ingroup    cb_sshs_protocol_specific

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param sessionEvent         Any of the \c sshSessionTypes enumerated values (see
                              ssh.h).
@param pMesg                Pointer to received message.
@param mesgLen              Number of bytes in received message (\p pMesg).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc ssh.h
*/
    sbyte4(*funcPtrReceivedData)  (sbyte4 connectionInstance, enum sshSessionTypes sessionEvent, ubyte *pMesg, ubyte4 mesgLen);

/**
@brief      Process text data sent to \c stderr.

@details    This callback function is invoked when a %client sends text data to
            \c stderr. Unless you've built a special application on top of SSH to
            use this text data, you can ignore this event (message type
            \c SSH_SESSION_STDERR).

@ingroup    cb_sshs_protocol_specific

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from SSH_acceptConnection() or SSH_ASYNC_acceptConnection().
@param sessionEvent         Any of the \c sshSessionTypes enumerated values (see ssh.h).
@param pMesg                Pointer to message buffer.
@param mesgLen              Number of bytes in the message buffer (\p pMesg).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc ssh.h
*/
    sbyte4(*funcPtrStdErr)        (sbyte4 connectionInstance, enum sshSessionTypes sessionEvent, ubyte *pMesg, ubyte4 mesgLen);

/**
@brief      Respond to a connection close request.

@details    This function is invoked when a %client requests that its connection
            to the NanoSSH server be closed (message type \c SSH_SESSION_EOF).
            Upon receiving this event, your application should perform cleanup
            and shutdown operations.

@ingroup    cb_sshs_protocol_specific

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param sessionEvent         Any of the \c sshSessionTypes enumerated values (see
                              ssh.h).
@param pMesg                Not used for this upcall.
@param mesgLen              Not used for this upcall.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc ssh.h
*/
    sbyte4(*funcPtrEof)           (sbyte4 connectionInstance, enum sshSessionTypes sessionEvent, ubyte *pMesg, ubyte4 mesgLen);

/**
@brief      Respond to a %client's close connection request.

@details    This function is invoked when a %client's connection with the
            NanoSSH server is closed (message type \c SSH_SESSION_CLOSED).

@ingroup    cb_sshs_protocol_specific

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param sessionEvent         Any of the \c sshSessionTypes enumerated values (see
                              ssh.h).
@param pMesg                Not used for this upcall.
@param mesgLen              Not used for this upcall.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc ssh.h
*/
    sbyte4(*funcPtrClosed)        (sbyte4 connectionInstance, enum sshSessionTypes sessionEvent, ubyte *pMesg, ubyte4 mesgLen);

/**
@brief      Respond to a %client's close channel request.

@details    This function is invoked when a %client requests for the channel
            with the NanoSSH server be closed (message type \c SSH_SESSION_CHANNEL_CLOSED).

@ingroup    cb_sshs_protocol_specific

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param sessionEvent         Any of the \c sshSessionTypes enumerated values (see
                              ssh.h).
@param pMesg                Not used for this upcall.
@param mesgLen              Not used for this upcall.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc ssh.h
*/
    sbyte4(*funcPtrCloseChannel)        (sbyte4 connectionInstance, enum sshSessionTypes sessionEvent, ubyte *pMesg, ubyte4 mesgLen);

/**
@brief      Respond to a %client's break message.

@details    This function is invoked when a %client sends a break message
            (message type \c SSH_SESSION_BREAK_OP). Not all applications will
            send this message.

@ingroup    cb_sshs_protocol_specific

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param sessionEvent         Any of the \c sshSessionTypes enumerated values (see
                              ssh.h).
@param pMesg                Not used for this upcall.
@param mesgLen              Not used for this upcall.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc ssh.h
*/
    sbyte4(*funcPtrBreakOp)       (sbyte4 connectionInstance, enum sshSessionTypes sessionEvent, ubyte *pMesg, ubyte4 mesgLen);

/**
@brief      Notify the NanoSSH server when a %client issues a command.

@details    This function notifies the NanoSSH server that an SSH %client is
            requesting an open channel for command execution. The function is
            invoked when a %client sends a break message (message type
            \c SSH_SESSION_OPEN_EXEC), as described in RFC&nbsp;4254, <em>Secure
            Shell (SSH) Connection Protocol</em>, section 6.5.

@ingroup    cb_sshs_protocol_specific

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param sessionEvent         Any of the \c sshSessionTypes enumerated values (see
                              ssh.h).
@param pMesg                Not used for this upcall.
@param mesgLen              Not used for this upcall.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc ssh.h
*/
    sbyte4(*funcPtrExec)          (sbyte4 connectionInstance, enum sshSessionTypes sessionEvent, ubyte *pMesg, ubyte4 mesgLen);

/**
@brief      (Optional) Respond to a \c Ping message.

@details    (Optional) This callback function is invoked when a \c Ping message
            is received. Your application can do anything when it receives this
            call, but no particular action is required.

@ingroup    cb_sshs_protocol_specific

@since 2.02
@version 2.02 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param sessionEvent         Any of the \c sshSessionTypes enumerated values (see
                              ssh.h).
@param pMesg                Not used for this upcall.
@param mesgLen              Not used for this upcall.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc ssh.h
*/
    sbyte4(*funcPtrReplyPing)     (sbyte4 connectionInstance, enum sshSessionTypes sessionEvent, ubyte *pMesg, ubyte4 mesgLen);

    /* general purpose upcalls */
#ifndef __ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

/**
@brief      Initialize session data.

@details    This function, which is invoked after a connection is accepted by
            the NanoSSH synchronous server, initializes session data.

@ingroup    cb_sshs_sync_server

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__

Additionally, the following flag must \b not be defined:
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection().
@param tcpAcceptSocket      Client socket to store in a cookie for later use.

@return     None.

@callbackdoc ssh.h
*/
    void(*funcPtrPostAccept)     (sbyte4 connectionInstance, TCP_SOCKET tcpAcceptSocket);

/**
@brief      Respond to a synchronous channel opening.

@details    This function is invoked when a connection channel is opened.

@ingroup    cb_sshs_sync_server

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__

Additionally, the following flag must \b not be defined:
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection().

@return     None.

@callbackdoc ssh.h
*/
    void(*funcPtrConnection)     (sbyte4 connectionInstance);
#else

/**
@brief      Start the timeout notification timer.

@details    This callback function is used to start a timeout notification
            timer.

@ingroup    cb_sshs_async_server

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance       Connection instance returned from
                                  SSH_ASYNC_acceptConnection().
@param msTimerExpire            Length of timer (in milliseconds).
@param boolUserAuthenticated    \c TRUE (1) to specify that authentication is
                                  complete; otherwise \c FALSE.

@return     None.

@callbackdoc ssh.h
*/
    void(*funcPtrStartTimer)     (sbyte4 connectionInstance, ubyte4 msTimerExpire, sbyte4 boolUserAuthenticated);
#endif /* __ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__ */

/**
@brief      Validate the provided password to complete authentication.

@details    This callback function is invoked as the final authentication step
            to validate the provided password.

@ingroup    cb_sshs_general_purpose

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param pUser                Pointer to user name.
@param userLength           Number of bytes in user name (\p pUser).
@param pPassword            Pointer to password.
@param passwordLength       Number of bytes in password (\p pPassword).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc ssh.h
*/
    sbyte4(*funcPtrPasswordAuth)    (sbyte4 connectionInstance, const ubyte *pUser, ubyte4 userLength, const ubyte *pPassword, ubyte4 passwordLength);

/**
@dont_show
@internal
*/
    sbyte4(*funcPtrNoneAuth)    (sbyte4 connectionInstance, const ubyte *pUser, ubyte4 userLength);

/**
@coming_soon
*/
    sbyte*  pBannerString;

/**
@brief      Verify a client's public key.

@details    This callback function is invoked during authentication to verify a
            client's public key.

@ingroup    cb_sshs_general_purpose

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param pUser                Pointer to user name.
@param userLength           Number of bytes in user name (\p pUser).
@param pPubKey              Pointer to public key.\n
\n
The public key (\p pubKeyLength) is a byte string representation of the
keyblob, both version 1 and version 2 are supported:
+ Version 1, begins with a 12-byte header, with all bytes set to zero except
the following:\n
+ header[7] contains the Mocana keyblob version (1)\n
+ header[11] contains the key type (any of the akt_* enumerated values
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
+ n bytes length of Scalar byte string\n
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

@param pubKeyLength         Number of bytes in public key (\p pPubKey).
@param keyType              Type of public key (\p pPubKey).\n
\n
The following enumerated values (defined in ca_mgmt.h) are supported:\n
\n
+ \c akt_rsa\n
+ \c akt_ecc\n
+ \c akt_ecc_ed\n
+ \c akt_dsa

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc ssh.h
*/
    sbyte4(*funcPtrPubKeyAuth)      (sbyte4 connectionInstance, const ubyte *pUser, ubyte4 userLength, const ubyte *pPubKey, ubyte4 pubKeyLength, ubyte4 keyType);

/**
@brief      Verify a client's certificate.

@details    This callback function is invoked during authentication to verify a
            client's certificate

@ingroup    cb_sshs_general_purpose

@since 6.5
@version 6.5 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param pUser                Pointer to user name.
@param userLength           Number of bytes in user name (\p pUser).
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
                         const ubyte *pUser,   ubyte4 userLength,
                         sbyte4 cert_status, ubyte *pCertificate, ubyte4 certLen,
                         certChainPtr pCertChain, const ubyte *pAnchorCert, ubyte4 anchorCertLen);

/**
@brief      Authorize a user for an interactive keyboard session.

@details    This callback function is invoked during interactive keyboard
            authentication to authorize a user.

@ingroup    cb_sshs_general_purpose

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param pUser                Pointer to user name.
@param userLength           Number of bytes in user name (\p pUser).
@param pResponseInfo        Pointer to previous response buffer (or \c NULL if
                              this is the first request).
@param pRequestInfo         On return, pointer to request data.
@param pAuthState           On return, pointer to state of authentication. Supported states:
                                AUTH_FAIL - Authentication failed.
                                AUTH_PASS - Authentication succeeded.
                                AUTH_MORE - Additional info requests are necessary.
                                AUTH_FAIL_MORE - Authentication failed, additional info
                                                 requests are necessary.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc ssh.h
*/
    sbyte4(*funcPtrKeyIntAuthReq)   (sbyte4 connectionInstance, const ubyte* pUser, ubyte4 userLength, keyIntInfoResp* pResponseInfo, keyIntInfoReq* pRequestInfo, sbyte4 *pAuthState);

/**
@brief      Release (free) memory used by an unneeded request data buffer.

@details    This callback function is invoked during interactive keyboard
            authentication to release (free) unneeded request data.

@ingroup    cb_sshs_general_purpose

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param request              Pointer to request to free.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc ssh.h
*/
    sbyte4(*funcPtrReleaseKeyIntReq)(sbyte4 connectionInstance, keyIntInfoReq* request);

/**
@brief      (Optional) Custom authorization methods handler.

@details    This callback function is invoked at the start of authentication,
            when the 32-bit bitmask representing the selected authorization
            methods is returned. You can restrict authorization methods based
            on the incoming request characteristics, such as IP address.

@ingroup    cb_sshs_general_purpose

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc ssh.h
*/
    sbyte4(*funcPtrGetAuthAdvertizedMethods)  (sbyte4 connectionInstance);

#ifdef __ENABLE_DIGICERT_SSH_PORT_FORWARDING__
/**
@brief      (Optional) Custom connection handler.

@details    (Optional) If port forwarding is enabled, this callback function is
            invoked when a connection channel is opened. You can use this
            handler to block, redirect, or use a non-socket interface for an
            incoming channel open request. You can also change the connect
            address and/or port.

@ingroup    cb_sshs_general_purpose

@since 1.41
@version 3.06 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_PORT_FORWARDING__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param sessionNum           (Reserved for future use.)
@param pConnectHost         IP Address of the host to be connected with NanoSSH
                              server.
@param port                 Port number through which to connect to the NanoSSH
                              server host.
@param pIgnoreRequest       (Reserved for future use.)
@param channel              Local port forwarded channel number.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc ssh.h
*/
    sbyte4(*funcPtrConnect)      (sbyte4 connectionInstance, sbyte4 sessionNum, ubyte *pConnectHost, ubyte2 port, sbyte4 *pIgnoreRequest, sbyte4 channel);

/**
@brief      (Optional) Receive SSH port forwarding session data.

@details    This callback function is invoked when the server receives text
            data from a %client in a port forwarding session. Your application
            can do anything when it receives this call, but no particular
            action is required. This callback is applicable only to port
            forwarding.

@ingroup    cb_sshs_port_forwarding

@since 3.06
@version 3.06 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_PORT_FORWARDING__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param sessionEvent         Any of the \c sshSessionTypes enumerated values
                              (see ssh.h).
@param pMesg                Pointer to received message.
@param mesgLen              Number of bytes in received message (\p pMesg).
@param channel              Associated channel number on the %client side.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc ssh.h
*/
    sbyte4(*funcPortFwdReceivedData)  (sbyte4 connectionInstance, enum sshSessionTypes sessionEvent, ubyte *pMesg, ubyte4 mesgLen, ubyte4 channel);



/**
@brief      Respond to a %client's close connection request.

@details    This function is invoked when a %client's connection with the
            NanoSSH server is closed for a port forwarding session (message
            type \c SSH_SESSION_CLOSED). This callback is applicable only to port forwarding.

@ingroup    cb_sshs_port_forwarding

@since 3.06
@version 3.06 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_PORT_FORWARDING__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or SSH_ASYNC_acceptConnection().
@param sessionEvent         Any of the \c sshSessionTypes enumerated values
                              (see ssh.h).
@param pMesg                Not used for this upcall.
@param mesgLen              Not used for this upcall.
@param channel              Associated channel number on the %client side.

@inc_file ssh.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc ssh.h
*/
    sbyte4(*funcPortFwdPtrClosed)        (sbyte4 connectionInstance, enum sshSessionTypes sessionEvent, ubyte *pMesg, ubyte4 mesgLen, ubyte4 channel);

/**
@brief      Respond to a %client's EOF request.

@details    This function is invoked when a %client's connection with the
            NanoSSH server sends an EOF for a port forwarding session (message
            type \c SSH_SESSION_CLOSED). This callback is applicable only to
            port forwarding.

@ingroup    cb_sshs_port_forwarding

@since 3.06
@version 3.06 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_PORT_FORWARDING__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param sessionEvent         Any of the \c sshSessionTypes enumerated values
                              (see ssh.h).
@param pMesg                Not used for this upcall.
@param mesgLen              Not used for this upcall.
@param channel              Associated channel number on the %client side.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc ssh.h
*/
    sbyte4 (*funcPortFwdPtrEof)       (sbyte4 connectionInstance, enum sshSessionTypes sessionEvent, ubyte *pMesg, ubyte4 mesgLen, ubyte4 channel);

/**
@todo_eng_review
@coming_soon
@ingroup    cb_sshs_port_forwarding
*/
    sbyte4 (*funcCheckPort)           (ubyte4 dstPort);

/**
@todo_eng_review
@coming_soon
@ingroup    cb_sshs_port_forwarding
*/
    sbyte4 (*funcStartTcpIpForward)   (sbyte4 connectionInstance,ubyte* pSrc, ubyte4 dstport, ubyte4 orgPort);

/**
@todo_eng_review
@coming_soon
@ingroup    cb_sshs_port_forwarding
*/
    sbyte4 (*funcCancelTcpIpForward)  (sbyte4 connectionInstance, ubyte4 dstPort);

/**
@todo_eng_review
@coming_soon
@ingroup    cb_sshs_port_forwarding
*/
    sbyte4 (*funcPtrRemotePortFwdSessionOpen) (sbyte4 connectionInstance, ubyte4 channel, ubyte4 myChannel);
#endif /* __ENABLE_DIGICERT_SSH_PORT_FORWARDING__ */

/**
@brief      Inform the calling application that Session Rekey has been initiated.

@details    This callback function is invoked on rekey negotiation start (initiated
            locally or by remote) - allowing the application to take update session
            context.

@ingroup    cb_sshs_general_purpose

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
  sbyte4(*funcPtrSessionReKey)   (sbyte4 connectionInstance, intBoolean initiatedByRemote);

} sshSettings;


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSH_SERVER__
/**
@brief      Associate host keys with a connection.

@details    This function associates host keys with a specific connection.
            Based on the certificate store contents, the NanoSSH server can
            determine the authentication type to negotiate with the %client.
            This function should only be called after SSH_acceptConnection() and before SSH_negotiateConnection().

@ingroup    func_ssh_core_server_connection_mgmt

@since 2.02
@version 2.02 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@inc_file ssh.h

For an example of how to call this function, refer to @ref ssh_example.c in the
sample code (examples directory).

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param pCertStore           Pointer to host keys.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_assignCertificateStore(sbyte4 connectionInstance, certStorePtr pCertStore);

#ifndef __ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__
/**
@brief      Initialize NanoSSH server internal structures.

@details    This function initializes NanoSSH server internal structures. Your
            application should call this function before starting the HTTPS
            and application servers.

@ingroup    func_ssh_sync_server_connection_mgmt

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__

Additionally, the following flag must \b not be defined:
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param sshMaxConnections    Maximum number of SSH server connections to allow.
                            (Each connection requires only a few bytes of
                            memory.)

@inc_file ssh.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous servers.

@code
if (0 > SSH_init(MAX_SSH_CONNECTIONS_ALLOWED))
    goto exit;
@endcode

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_init(sbyte4 sshMaxConnections);

/**
@brief      Register an SSH %client-server connection and get its connection
            instance.

@details    This function registers a connection between SSH %server and
            %client and returns the session's connection instance.

@note       This function must be called from within the HTTPS daemon context.
            If you are using multiple HTTPS daemons, you must use a semaphore
            (mutex) around this function call.

@note       If your web server and application server run as separate tasks, you
            should protect your call to SSH_acceptConnection with a semaphore
            to prevent race conditions.

@ingroup    func_ssh_sync_server_connection_mgmt

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__

Additionally, the following flag must \b not be defined:
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param tempSocket   Socket or TCB identifier returned by a call to \c accept().

@inc_file ssh.h

@return     Value > 0 is the connection instance; otherwise a negative number
            error code definition from merrors.h. To retrieve a string
            containing an English text error identifier corresponding to the
            function's returned error %status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous servers.

@code
intBoolean isBreakSignalRequest = FALSE
sbyte4 connectionInstance;

TCP_SOCKET socketClient;
status = TCP_ACCEPT_SOCKET(&socketClient, mListenSocket, &isBreakSignalRequest);

connectionInstance = SSH_acceptConnection(socketClient);
@endcode

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_acceptConnection(TCP_SOCKET socket);

/**
@brief      Exchange keys and establishe a secure SSHv2 %client-server
            connection.

@details    This function exchanges keys and establishes a secure SSHv2
            %client-server connection.

@note       You should not call this function until a connection instance is
            available from a previous call to SSH_acceptConnection().

@note       Key exchange is a complex process, and may take a few seconds to
            perform on older (slower) platforms. However, the key exchange
            typically is performed only once during a session's lifetime (at
            startup), so there is no effect on regular communication.

@ingroup    func_ssh_sync_server_connection_mgmt

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__

Additionally, the following flag must \b not be defined:
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection().

@inc_file ssh.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous servers.

@code
sbyte4 status = 0;sbyte4 connectionInstance;

status = SSH_negotiateConnection(connectionInstance);
@endcode

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_negotiateConnection(sbyte4 connectionInstance);

#ifndef __ENABLE_DIGICERT_SSH_STREAM_API__
/**
@brief      Get an entire message from a %server and decrypt the data.

@details    This function retrieves an entire message from a %server,
            decrypts the data, and stores it in the provided buffer.

In contrast to SSH_recv(), which reads just part of a message, this function
reads an entire message at once.

@ingroup    func_ssh_sync_server_msg

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__

Additionally, the following flags must \b not be defined:
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__
+ \c \__ENABLE_DIGICERT_SSH_STREAM_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection().
@param pMessageType         On return, pointer to type of message received
                              (an \c sshSessionTypes enumerated value,
                              defined in ssh.h).
@param pRetMessage          Pointer to receive message buffer.
@param pNumBytesReceived    On return, pointer to the number of bytes received.
@param timeout              Number of milliseconds for the %client to wait to
                              receive the message; 0 specifies no timeout (an
                              infinite wait).

@inc_file ssh.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@note       This function must not be called until an SSH connection is
            established between the %client and %server; otherwise an error
            is returned.

@remark     This function is applicable to synchronous servers.

@code
static void SSH_EXAMPLE_simpleCLI(sbyte4 connectionInstance)
{
    ubyte*     pInBuffer = NULL;         // incoming data
    sbyte4     numBytesReceived;
    sbyte4     mesgType = 0;
    sbyte4     bytesSent, status;

    if (0 > (status = SSH_negotiateConnection(connInstance)))    // key xchange
        goto exit;

    if (NULL == (pInBuffer = malloc(MAX_SESSION_WINDOW_SIZE)))  // alloc rx buffer
        goto exit;

    while ((0 <= status) && ((sbyte4)SSH_SESSION_EOF > mesgType))
    {   // echo msg
        status = SSH_recvMessage(connectionInstance, &mesgType,
                                 pInBuffer, &numBytesReceived, 0);
    if ((0 <= status) && (SSH_SESSION_DATA == mesgType))
            status = SSH_sendMessage(connectionInstance, pInBuffer,
                                     numBytesReceived, &bytesSent)))
    }
exit: // cleanup
    return;
}
@endcode

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_recvMessage(sbyte4 connectionInstance, sbyte4 *pMessageType, sbyte *pRetMessage, sbyte4 *pNumBytesReceived, ubyte4 timeout);
#else
/**
@brief      Get data from a %server and decrypt the data.

@details    This function retrieves data from a %server, decrypts the data,
            and stores it in the provided buffer. The retrieved data may be
            the full message or only part of the message.

In contrast to SSH_recvMessage(), which reads an entire message, this function
enables streaming data reads of just part of a message.

@ingroup    func_ssh_sync_server_msg

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_STREAM_API__

Additionally, the following flag must \b not be defined:
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection().
@param pMessageType         On return, pointer to type of message received (an
                              \c sshSessionTypes enumerated value, defined in
                              ssh.h).
@param pRetBuffer           Pointer to receive message buffer.
@param bufferSize           Number of bytes in receive message buffer
                              (\p pRetBuffer).
@param pNumBytesReceived    On return, pointer to the number of bytes received.
@param timeout              Number of milliseconds for the %client to wait to
                              receive the message; 0 specifies no timeout (an
                              infinite wait).

@inc_file ssh.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@note This function should not be called until an SSH connection is established
between the %client and %server; otherwise an error is returned.

@remark     This function is applicable to synchronous servers.

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_recv(sbyte4 connectionInstance, sbyte4 *pMessageType, ubyte *pRetBuffer, ubyte4 bufferSize, sbyte4 *pNumBytesReceived, ubyte4 timeout);

/**
@brief      Determine whether there is data in a connection instance's SSH
            receive buffer.

@details    This function determines whether there is data in a connection
            instance's SSH receive buffer, and returns the result (\c TRUE or
            \c FALSE) through the \p pRetBooleanIsPending parameter.

@ingroup    func_ssh_sync_server_msg

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_STREAM_API__

Additionally, the following flag must \b not be defined:
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance       Connection instance returned from
                                  SSH_acceptConnection().
@param pRetBooleanIsPending     On return, pointer to \c TRUE if there is data
                                  to be received; otherwise pointer to \c FALSE.

@remark     This function is applicable to synchronous servers.

@inc_file ssh.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_recvPending(sbyte4 connectionInstance, sbyte4 *pRetBooleanIsPending);
#endif

/**
@brief      Send data to a client.

@details    This function sends data to a server unless deadlock prevention is
            enabled by the \c __ENABLE_DIGICERT_SSH_SENDER_RECV__ flag and the
            SSH transport window size indicates insufficient %client
            acknowledgement of previously sent data.

@note       This function should not be called until an SSH %client-server
            connection is established.

@ingroup    func_ssh_sync_server_msg

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__

Additionally, the following flag must \b not be defined:
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from SSH_acceptConnection().
@param pBuffer              Pointer to the buffer containing the data to send.
@param bufferSize           Number of bytes in the send data buffer (\p pBuffer).
@param pBytesSent           On return, pointer to number of bytes successfully
                              sent.

@inc_file ssh.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous servers.

@code
static void SSH_EXAMPLE_simpleCLI(sbyte4 connectionInstance)
{
    // incoming data
    ubyte*   pInBuffer = NULL;
    sbyte4     numBytesReceived;
    sbyte4     mesgType = 0;
    sbyte4     bytesSent;
    sbyte4     status;

    if (0 > (status = SSH_negotiateConnection(connInstance)))   // do key xchange
        goto exit;

    if (NULL == (pInBuffer = malloc(MAX_SESSION_WINDOW_SIZE)))   // alloc rx buffer
        goto exit;

    // echo message back to client
    while ((0 <= status) && ((sbyte4)SSH_SESSION_EOF > mesgType))
    {
        status = SSH_recvMessage(connectionInstance, &mesgType,
                                 pInBuffer, &numBytesReceived, 0);

        if ((0 <= status) && (SSH_SESSION_DATA == mesgType))
            status = SSH_sendMessage(connectionInstance, pInBuffer,
                                     numBytesReceived, &bytesSent)))
    }

exit:
    // cleanup
    return;
}
@endcode

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_sendMessage(sbyte4 connectionInstance, sbyte *pBuffer, sbyte4 bufferSize, sbyte4 *pBytesSent);

/**
@brief      Send \c stderr error message output data over SSH.

@details    This function sends \c stderr error message output data over SSH.

@ingroup    func_ssh_sync_server_msg

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection().
@param pBuffer              Pointer to buffer containing the \c stderr error
                              message data to send.
@param bufferSize           Number of bytes in the error message (\p bBuffer).
@param pBytesSent           On return, pointer to number of bytes successfully
                              sent.

@inc_file ssh.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous servers.

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_sendErrMessage(sbyte4 connectionInstance, sbyte *pBuffer, sbyte4 bufferSize, sbyte4 *pBytesSent);

/**
@brief      Close an NanoSSH server session and releases its resources.

@details    This function closes an NanoSSH server session and releases all its
            resources.

@ingroup    func_ssh_sync_server_connection_mgmt

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__

Additionally, the following flag must \b not be defined:
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance     Connection instance returned from SSH_acceptConnection().
@param errorCode              Error code to identify the error status of the
                              connection. If the connection is closed normally,
                              this parameter should be set to \c OK (0).
@inc_file ssh.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous servers.

@code
sbyte4 status = 0;sbyte4 connectionInstance;

status = SSH_closeConnection(connectionInstance, errorCode);
@endcode

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_closeConnection(sbyte4 connectionInstance, MSTATUS errorCode);

#ifdef __ENABLE_DIGICERT_SSH_PING__
/**
@brief      Determine which connections are alive by pinging each open
            connection.

@details    This function determines which connections are alive by pinging
            (sending an message with no data) each open connection.

@ingroup    func_ssh_sync_server_connection_mgmt

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_PING__

Additionally, the following flag must \b not be defined:
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                            SSH_acceptConnection().

@inc_file ssh.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous servers.

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_sendPing(sbyte4 connectionInstance);
#endif
#endif /* __ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__ */

#if (defined(__ENABLE_DIGICERT_SSH_OLD_DSA_CONVERSION__) && defined(__ENABLE_DIGICERT_DSA__))
/**
@brief      Convert a key blob from NanoSSH version 1.41 and earlier formats to
            version 2.02 format.

@details    This function converts a key blob from NanoSSH version 1.41 and
            earlier formats to version 2.02 format. The 2.02 format adds RSA
            and ECC keys, providing greater flexibility and making development easier.

@ingroup    func_ssh_core_server_security

@since 2.02
@version 2.02 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

Additionally, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_OLD_DSA_CONVERSION__
+ \c \__ENABLE_DIGICERT_DSA__

@inc_file ssh.h

@note       The public key is always the longer of the public/private key pair,
            and the private key is typically 24 or 25 bytes. Inadvertently
            swapping them in this function call causes an error to be returned.

@param pOldDsaPublicKeyBlob         Pointer to original (pre-2.02 format)
                                      public key blob.
@param oldDsaPublicKeyBlobLength    Number of bytes in original public key blob
                                      (\p pOldDsaPublicKeyBlob).
@param pOldDsaPrivateKeyBlob        Pointer to original (pre-2.02 format)
                                      private key blob.
@param oldDsaPrivateKeyBlobLength   Number of bytes in original private key blob
                                      (\p pOldDsaPrivateKeyBlob).
@param ppRetNewKeyBlob              On return, pointer to new 2.02-formatted key
                                      blob, which contains both public and
                                      private keys.
@param pRetNewKeyBlobLength         On return, pointer to number of bytes in new
                                      key blob (\p ppRetNewKeyBlob).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@code
{
    ubyte*  pPubKeyBlob = NULL;
    ubyte4  pubKeyBlobLength;
    ubyte*  pPrivKeyBlob = NULL;
    ubyte4  privKeyBlobLength;
    ubyte*  pKeyBlob;
    ubyte4  keyBlobLength;

    // read old dsa key blob, filenames may be different
    status = DIGICERT_readFile("sshkeys.pub", &pPubKeyBlob, &pubKeyBlobLength);
    status = DIGICERT_readFile("sshkeys.prv", &pPrivKeyBlob, &privKeyBlobLength);

    // convert to new format
    status = SSH_convertOldKeyBlobToNew(pPubKeyBlob, pubKeyBlobLength, pPrivKeyBlob, privKeyBlobLength, &pKeyBlob, &keyBlobLength);

    // save new key blob
    status = DIGICERT_writeFile("ssh_dss.key", pKeyBlob, keyBlobLength);

    // it may be a good idea to delete the old key blob at this time

    DIGICERT_freeReadFile(&pPubKeyBlob);
    DIGICERT_freeReadFile(&pPrivKeyBlob);
    CA_MGMT_freeNakedKey(&pKeyBlob);
}
@endcode

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_convertOldKeyBlobToNew(ubyte *pOldDsaPublicKeyBlob, ubyte4 oldDsaPublicKeyBlobLength, ubyte *pOldDsaPrivateKeyBlob, ubyte4 oldDsaPrivateKeyBlobLength, ubyte **ppRetNewKeyBlob, ubyte4 *pRetNewKeyBlobLength);
#endif

/**
@brief      Get a pointer to a connection instance's negotiated terminal
            settings.

@details    This function retrieves a pointer to the specified connection
            instance's negotiated terminal settings.

@ingroup    func_ssh_core_server_mgmt

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param ppTerminalSettings   On return, pointer to the client's terminal
                              settings.

@inc_file ssh.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@note       This function should not be called until after the shell session
            has been established.

@remark     This function is applicable to synchronous and asynchronous servers.

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_getTerminalSettingDescr(sbyte4 connectionInstance, terminalState **ppTerminalSettings);

/**
@brief      Get a connection context's custom information.

@details    This function retrieves custom information stored in the
            connection instance's context. Your application should call this
            function after calls to SSH_setCookie() or to make custom SSH
            upcalls (callbacks).

@ingroup    func_ssh_core_server_connection_mgmt

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance  Connection instance returned from SSH_acceptConnection().
@param pCookie             On return, pointer to cookie containing custom information.

@inc_file ssh.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@sa SSH_setCookie()

@code
mySessionInfo *myCookie = NULL;

SSH_getCookie(connectionInstance, (int *)(&myCookie));
@endcode

@remark     This function is applicable to synchronous and asynchronous servers.

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_getCookie(sbyte4 connectionInstance, sbyte4 *pCookie);

/**
@brief      Store custom information (a cookie) about the context connection.

@details    This function stores custom information about the context
            connection. Your application should call this function after calling SSH_acceptConnection().

@ingroup    func_ssh_core_server_connection_mgmt

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from SSH_acceptConnection().
@param cookie               Custom data (the cookie).

@inc_file ssh.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@sa SSH_setCookie()

@code
mySessionInfo *mySession = malloc(sizeof(mySessionInfo));

// setup my session info
SSH_setCookie(connectionInstance, (int)(mySession));
@endcode

@remark     This function is applicable to synchronous and asynchronous servers.

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_setCookie(sbyte4 connectionInstance, sbyte4 cookie);

/**
@brief      Get a socket's connection instance.

@details    This function retrieves a socket's connection instance.

@ingroup    func_ssh_core_server_security

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param socket   TCP/IP socket whose connection instance you want.

@inc_file ssh.h

@return         Socket instance identifier if successful; otherwise a negative
                number error code definition from merrors.h. To retrieve a
                string containing an English text error identifier
                corresponding to the function's returned error %status, use the
                \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous servers.

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_getInstanceFromSocket(TCP_SOCKET socket);

/**
@brief      Get a NanoSSH session's cipher names.

@details    This function retrieves the cipher names (strings) used for the
            specified NanoSSH session (connection instance).

@ingroup    func_ssh_core_server_security

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection(), SSH_ASYNC_acceptConnection(), or SSH_getNextConnectionInstance.()
@param ppInCipherName       On return, pointer to string containing the inbound
                              cipher name (for example, "AES-256-CBC" or
                              "BLOWFISH-CBC").
@param ppInMacName          On return, pointer to string containing the inbound
                              MAC name (for example, "HMAC-MD5-96" or
                              "HMAC-SHA1").
@param ppOutCipherName      On return, pointer to string containing the outbound
                              cipher name (for example, "3DES-CBC").
@param ppOutMacName         On return, pointer to string containing the outbound
                              MAC name (for example, "HMAC-SHA1-96" or "HMAC-MD5").

@inc_file ssh.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@code
static void
exampleUsage(void)
{
  sbyte4 temp = 0;

  while ((temp = SSH_getNextConnectionInstance(temp)) &&
         (0 != temp))
  {
    ubyte *pInCipher;

    if (0 <= SSH_getSessionCryptInfo(temp, &pInCipher, 0, 0, 0))
      printf("session %d, using %s cipher\n", temp, pInCipher);
  }
}
@endcode

@remark     This function is applicable to synchronous and asynchronous servers.

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_getSessionCryptoInfo(sbyte4 connectionInstance, sbyte **ppInCipherName,  sbyte **ppInMacName, sbyte **ppOutCipherName, sbyte **ppOutMacName);

/**
@brief      Get the next connection instance from the active NanoSSH connection
            instance table.

@details    This function traverses the active NanoSSH connection instance
            table, and returns the }next} connection instance. Your application
            can use this connection instance in a call to
            SSH_getSessionCryptoInfo().

@ingroup    func_ssh_core_server_security

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().

@inc_file ssh.h

@return A pointer to the }next} connection instance; 0 if there are no more
active connections.

@remark     This function is applicable to synchronous and asynchronous servers.

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_getNextConnectionInstance(sbyte4 connectionInstance);

/**
@brief      Get a connection's socket identifier.

@details    This function retrieves a connection instance's socket identifier.

@ingroup    func_ssh_core_server_security

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param pRetSocket           On return, pointer to the socket corresponding to
                              the connection instance.

@inc_file ssh.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous servers.

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_getSocketId(sbyte4 connectionInstance, TCP_SOCKET *pRetSocket);

MOC_EXTERN sbyte4 SSH_setErrorCode(sbyte4 connectionInstance, sbyte4 errorCode);

/**
@brief      Set a server's cipher list.

@details    This function dynamically updates cipher support selection.

@ingroup    func_ssh_core_server_security

@since 2.02
@version 2.02 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param pCipherList          Pointer to a C&nbsp;string (NULL-terminated)
                              cipher list to advertise. (See ssh_trans.c for
                              the list of available ciphers.)

@inc_file ssh.h

@note       This function is applicable only when the connection state is
            \c CONNECT_NEGOTIATE.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@code
if (OK > (ci = SSH_acceptConnection(socketClient)))
{
    DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, "SSH_EXAMPLE_startServer: Too many open connections.");
    TCP_CLOSE_SOCKET(socketClient);
    continue;
}

SSH_useThisCipherList(ci, "3des-cbc");

if (OK > (status = RTOS_createThread(SSH_EXAMPLE_simpleDemo, (void*)ci, SSH_SESSION, &tid)))
{
    DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, "SSH_EXAMPLE_startServer: Too many open connections.");
    TCP_CLOSE_SOCKET(socketClient);
    goto exit;
}
@endcode

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_useThisCipherList(sbyte4 connectionInstance, ubyte *pCipherList);

/**
@brief      Set a server's HMAC list.

@details    This function dynamically updates HMAC support selelction.

@ingroup    func_ssh_core_server_security

@since 2.02
@version 2.02 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param pHmacList            Pointer to a C&nbsp;string (NULL-terminated) HMAC
                              list to advertise. (See ssh_trans.c for the list
                              of available HMACs.)

@inc_file ssh.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@code
if (OK > (ci = SSH_acceptConnection(socketClient)))
{
    DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, "SSH_EXAMPLE_startServer: Too many open connections.");
    TCP_CLOSE_SOCKET(socketClient);
    continue;
}

SSH_useThisHmacList(ci, "hmac-md5-96,hmac-md5");

if (OK > (status = RTOS_createThread(SSH_EXAMPLE_simpleDemo, (void*)ci, SSH_SESSION, &tid)))
{
    DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, "SSH_EXAMPLE_startServer: Too many open connections.");
    TCP_CLOSE_SOCKET(socketClient);
    goto exit;
}
@endcode

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_useThisHmacList(sbyte4 connectionInstance, ubyte *pHmacList);

/**
@brief      Change a NanoSSH server setting value.

@details    This function dynamically updates a selected NanoSSH server setting.

@ingroup    func_ssh_core_server_mgmt

@since 2.02
@version 2.02 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param ioctlSelector        Setting to change, specified as an "SSH ioctls"
                              definition from ssh.h; current option is limited
                              to \c SET_SSH_MAX_SESSION_TIME_LIMIT.
@param ioctlValue           Value to assign to the setting.

@inc_file ssh.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@code
if (OK > (ci = SSH_acceptConnection(socketClient)))
    {
        DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, "SSH_EXAMPLE_startServer: Too many open connections.");
        TCP_CLOSE_SOCKET(socketClient);
        continue;
    }

    DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, "SSH_EXAMPLE_startServer: Set max session time limit to 40 minutes.");
    SSH_ioctl(ci, SET_SSH_MAX_SESSION_TIME_LIMIT, 40 * 60 * 1000);

    if (OK > (status = RTOS_createThread(SSH_EXAMPLE_simpleDemo, (void*)ci, SSH_SESSION, &tid)))
    {
        DEBUG_PRINTNL(DEBUG_SSH_EXAMPLE, "SSH_EXAMPLE_startServer: Too many open connections.");
        TCP_CLOSE_SOCKET(socketClient);
        goto exit;
    }
@endcode

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_ioctl(sbyte4 connectionInstance, ubyte4 ioctlSelector, ubyte4 ioctlValue);

/**
@brief      Initiate an SSH re-key operation.

@details    This function initiates an SSH re-key operation. NanoSSH automatically
processes re-key requests from SSH %clients.

@ingroup    func_ssh_core_server_security

@since 4.2
@version 4.2 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param msAllowToComply      Number of milliseconds to wait for an SSH %client to
                              respond before closing the session. Zero (0)
                              indicates that the request is not being strictly
                              enforced.

@inc_file ssh.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous servers.

@remark     Many SSH implementations do not support re-keying.

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_initiateReKey(sbyte4 connectionInstance, ubyte4 msAllowToComply);

/**
@brief      Get the number of bytes sent and received through a given
            connectionInstance.

@details    This function returns (through the \p pRetNumBytes parameter) the
            number of bytes sent and received through a given
            connectionInstance. Typical usage for this function is to determine
            when it's appropriate to initiate a re-key exchange operation.

@ingroup    func_ssh_core_server_security

@since 4.2
@version 4.2 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param pRetNumBytes         On return, the number of bytes received and
                              transmitted.

@inc_file ssh.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous servers.

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_numBytesTransmitted(sbyte4 connectionInstance, ubyte8 *pRetNumBytes);

#ifndef __ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__
#ifdef __USE_DIGICERT_SSH_SERVER__
/**
@brief      Start the NanoSSH server.

@details    This function starts the NanoSSH server.

You can use the NanoSSH SSH daemon or your own CLI daemon to listen for and
accept connections. To run multiple SSH Server instances, you can use your
existing code or adapt the @ref ssh_server.c sample code.

@ingroup    func_ssh_sync_server_mgmt

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__USE_DIGICERT_SSH_SERVER__

Additionally, the following flag must \b not be defined:
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@inc_file ssh.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous servers.

@note       By default, the NanoSSH server is multi-threaded. To change the
            NanoSSH server to single-threaded, define the
            \c __SINGLE_THREAD_SSH_SERVER__ flag in moptions.h.

@code
void SSH_EXAMPLE_main(void)
{
#ifdef __ENABLE_ALL_DEBUGGING__
    printf("SSH_EXAMPLE_main: Starting up SSH Server\n");
#endif

    // initialize the SSH tables and structures
    if (0 > SSH_init(MAX_SSH_CONNECTIONS_ALLOWED))
        goto exit;

    // if necessary, create host keys
    if (0 > SSH_EXAMPLE_computeHostKeys())
        goto exit;

#ifdef __ENABLE_DIGICERT_SSH_FTP_SERVER__
    SFTP_EXAMPLE_init();
#endif

    // startup the SSH Server
    SSH_startServer();

exit:
    SSH_shutdown();
}
@endcode

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4  SSH_startServer(void);

/**
@brief      Stop NanoSSH server from accepting any new %client connections.

@details    This function stops the NanoSSH server from accepting any new
            %client connections. (Existing active connection sessions remain
            active.)

@ingroup    func_ssh_sync_server_mgmt

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__USE_DIGICERT_SSH_SERVER__

Additionally, the following flag must \b not be defined:
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@inc_file ssh.h

@return None.

@remark     This function is applicable to synchronous servers.

@code
extern void SSH_stopServer (void);
@endcode

@funcdoc ssh.h
*/
MOC_EXTERN void SSH_stopServer (void);

/**
@brief      Disconnect all NanoSSH server clients.

@details    This function disconnects all the NanoSSH server's clients.

@warning    To avoid race conditions that could occur if code is actively
            serving a session, be cautious about using this function to
            forcefully terminate sessions. Better alternatives are using the
            upper-layer CLI to terminate sessions or calling SSH_stopServer().

@ingroup    func_ssh_sync_server_mgmt

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__USE_DIGICERT_SSH_SERVER__

Additionally, the following flag must \b not be defined:
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@inc_file ssh.h

@return None.

@remark     This function is applicable to synchronous servers.

@funcdoc ssh.h
*/
MOC_EXTERN void SSH_disconnectAllClients(void);
#endif /* __USE_DIGICERT_SSH_SERVER__ */
#endif /* __ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__ */

/**
@brief      Authenticate a %client by public key authentication.

@details    This function (which should be called from the public key
            authentication callback method sshSettings::funcPtrPubKeyAuth)
            authenticates a %client by public key authentication.

The key file may be any host key generated by any SSH-compliant %client.

@ingroup    func_ssh_core_server_security

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param pPubKey          Pointer to public key provided by the client.
@param pubKeyLength     Number of bytes in public key (\p pPubKey).
@param pFileKey         Pointer to the key on file to which the client's key
                          will be compared.
@param fileKeyLength    Number of bytes in the key on file (\p pFileKey).
@param pRetIsMatch      On return, pointer to \c TRUE if the client's public key
                          matches the key on file; otherwise pointer to \c
                          FALSE.

@inc_file ssh.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous servers.

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4  SSH_compareAuthKeys(const ubyte *pPubKey,  ubyte4 pubKeyLength,
                                const ubyte *pFileKey, ubyte4 fileKeyLength,
                                sbyte4 *pRetIsMatch);

/**
@brief      Verify that an RSA or DSS/DSA or ECC or EDDSA public key file format is valid.

@details    This function verifies that the specified SSH RSA or DSS/DSA or ECC
            or EDDSA public key file format is valid, thereby proving a client's identity.
            You should call this function to verify every key file that is uploaded 
            to the NanoSSH server or your device.

@ingroup    func_ssh_core_server_security

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be 
defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param pKeyFileData     Pointer to authentication key to be verified.
@param fileSize         Number of bytes in the public key (\p pKeyFileData).

@inc_file ssh.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@code
ubyte*  pStoredPublicKey = NULL;
ubyte4  storedPublicKeyLength;
sbyte4  result;

    // a pub key on file
    if (0 > DIGICERT_readFile(AUTH_KEYFILE_NAME,
                            &pStoredPublicKey,
                            &storedPublicKeyLength))
    {
        goto exit;
    }

    // verify key here
    result = SSH_verifyPublicKeyFile(pStoredPublicKey,
                                storedPublicKeyLength)

// if result == zero (0), the key is valid, otherwise contains error code for reason key is not valid

exit:
// do something here

@endcode

@remark     This function is applicable to synchronous and asynchronous servers.

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4  SSH_verifyPublicKeyFile(sbyte *pKeyFileData, ubyte4 fileSize);

/**
@brief      Disconnect all clients and shut down the NanoSSH server stack.

@details    This function disconnects all clients and shuts down the NanoSSH
            server stack.

In rare instances, for example changing the port number to which an embedded
device listens, you many need to completely stop the NanoSSH server and all its
resources. However, in most circumstances this is unnecessary because the
NanoSSH server is threadless.

@ingroup    func_ssh_core_server_connection_mgmt

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@inc_file ssh.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@code
sbyte4 status = 0;

status = SSH_shutdown();
@endcode

@remark     This function is applicable to synchronous and asynchronous servers.

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_shutdown(void);

/**
@brief      Release NanoSSH server's internal memory tables.

@details    This function releases the NanoSSH server's internal memory
            tables. It should be called only after a call to SSH_shutdown().
            To resume communication with a device after calling this
            function, you must create a new connection and register
            encryption keys.

@ingroup    func_ssh_core_server_connection_mgmt

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@inc_file ssh.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@code
sbyte4 status = 0;

status = SSH_releaseTables():
@endcode

@remark     This function is applicable to synchronous and asynchronous servers.

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_releaseTables(void);

/**
@brief      Get a pointer to NanoSSH server settings.

@details    This function returns a pointer to NanoSSH server settings that
            can be dynamically adjusted during initialization or runtime.

The default values for the following basic settings are suitable for most systems:

<tt>
SSH_sshSettings()->sshListenPort                = 22;
SSH_sshSettings()->sshMaxAuthAttempts           = 20;
SSH_sshSettings()->sshTimeOutOpen               = 2000;
SSH_sshSettings()->sshTimeOutKeyExchange        = 10000;
SSH_sshSettings()->sshTimeOutNewKeys            = 15000;
SSH_sshSettings()->sshTimeOutServiceRequest     = 4000;
SSH_sshSettings()->sshTimeOutAuthentication     = 1000 * 60 * 10;
SSH_sshSettings()->sshTimeOutDefaultOpenState   = 0;    // no timeout
SSH_sshSettings()->sshMaxConnections            = 4;
</tt>

@ingroup    func_ssh_core_server_mgmt

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__

@inc_file ssh.h

@return     Pointer to NanoSSH Server settings.

@remark     This function is applicable to synchronous servers.

@funcdoc ssh.h
*/
MOC_EXTERN sshSettings* SSH_sshSettings(void);

#ifdef __ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__
/**
@brief      Initialize NanoSSH server internal structures.

@details    This function initializes NanoSSH server internal structures. It
            should be called before starting your SSH daemon.

@ingroup    func_ssh_async_server_connection_mgmt

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param sshMaxConnections    Maximum number of SSH asynchronous server
                            connections to allow. (Each connection requires
                            only a few bytes of memory.)

@inc_file ssh.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous servers.

@code
if (0 > SSH_ASYNC_init(MAX_SSH_CONNECTIONS_ALLOWED))
        goto exit;
@endcode

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_ASYNC_init(sbyte4 sshMaxConnections);

/**
@brief      Set NanoSSH server listening port.

@details    This function resets the NanoSSH server's listening port from its
            default (port 22) to any desired port. To reset the port, you
            must call this function immediately after calling SSH_ASYNC_init().

@ingroup    func_ssh_async_server_connection_mgmt

@since 3.06
@version 3.06 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param listeningPort    Listening port number.

@inc_file ssh.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous servers.

@code
if (0 > SSH_ASYNC_setListeningPort(18000))
        goto exit;
@endcode

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_ASYNC_setListeningPort(ubyte4 listeningPort);

/**
@brief      Register a secure SSH asynchronous connection and exchange
            public/private encryption keys.

@details    This function registers a secure SSH asynchronous connection,
            exchanges public/private encryption keys, and returns the
            connection's instance.

@ingroup    func_ssh_async_server_connection_mgmt

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param tempSocket               Socket or TCB identifier returned by a call
                                  to \c accept().
@param pClientHelloString       (Optional) Pointer to \c hello string
                                  received from %client.
@param clientHelloStringLength  (Optional) Number of bytes in \c hello string
                                  received from %client (\p pClientHelloString).
@param pServerHelloString       (Optional) Pointer to \c hello string sent to
                                  %client.
@param serverHelloStringLength  (Optional) Number of bytes in \c hello string
                                  sent to %client (\p pServerHelloString).

@inc_file ssh.h

@return         Value > 0 is the connection instance; otherwise a negative
                number error code definition from merrors.h. To retrieve a
                string containing an English text error identifier
                corresponding to the function's returned error %status, use the
                \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous servers.

@code
intBoolean  isBreakSignalRequest = FALSE
sbyte4      connectionInstance;

TCP_SOCKET socketClient;
status = TCP_ACCEPT_SOCKET(&socketClient, mListenSocket, &isBreakSignalRequest);

connectionInstance = SSH_ASNYC_acceptConnection(socketClient, 0,0,0,0);
@endcode

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_ASYNC_acceptConnection(TCP_SOCKET tempSocket, ubyte *pClientHelloString, ubyte4 clientHelloStringLength, ubyte *pServerHelloString, ubyte4 serverHelloStringLength);

/**
@brief      Initiate sending a \c hello message.

@details    This function initiates sending a \c hello message, contrary to
            the typical sequence of sending a \c hello in response to
            receiving a %client hello. Use this function only in the rare
            instance that you are using two SSH stacks on the same port.

@ingroup    func_ssh_async_server_connection_mgmt

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from SSH_ASYNC_acceptConnection.

@inc_file ssh.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous servers.

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_ASYNC_startProtocolV2(sbyte4 connectionInstance);

/**
@brief      Get data from a %client.

@details    This function retrieves data from a %client. It should be called
            from your TCP/IP receive upcall handler, or from your application
            after reading a packet of data. The engine decrypts and processes
            the packet, and then calls the sshSettings::funcPtrReceivedData
            upcall to handle the decrypted data.

@ingroup    func_ssh_async_server_msg

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_ASYNC_acceptConnection().
@param pBytesReceived       Pointer to the packet or message received from
                              the TCP/IP stack.
@param numBytesReceived     Number of bytes in packet or message received
                              (\p pBytesReceived).

@inc_file ssh.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous servers.

@code
// ...

    while ((OK == status) && (TRUE != mBreakServer))
    {
        if (OK <= (status = TCP_READ_AVL(socketClient,
                                         pInBuffer,
                                         SSH_SYNC_BUFFER_SIZE,
                                         &numBytesRead,
                                         20000)))
        {
            if (0 != numBytesRead)
                status = SSH_ASYNC_recvMessage(connInstance,
                                               pInBuffer,
                                               numBytesRead);
        }

        if (ERR_TCP_READ_TIMEOUT == status)
            status = OK;
    }

// ...
@endcode

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_ASYNC_recvMessage(sbyte4 connectionInstance, ubyte *pBytesReceived, ubyte4 numBytesReceived);

/**
@brief      Send an acknowledgement that data was received by the %server.

@details    This function sends an acknowledgement that data was received by
            the %server on the specified connection. Your application must
            explicitly call this function; there is no automatic
            acknowledgement.

\b Important
Mocana NanoSSH server versions earlier than 1.41 automatically acknowledged
received data. Therefore, if you're porting your application from an earlier
NanoSSH server version, be sure to add calls to this function.

@ingroup    func_ssh_async_server_msg

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_ASYNC_acceptConnection().
@param sessionEvent         Type of message for which data was received (an
                              \c sshSessionTypes enumerated value, defined in
                              ssh.h).
@param numBytesAck          Number of bytes received.

@inc_file ssh.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous servers.

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_ASYNC_ackReceivedMessageBytes(sbyte4 connectionInstance, enum sshSessionTypes sessionEvent, ubyte4 numBytesAck);

/**
@brief      Resume (continue) an authentication process that was waiting for
            a result.

@details    This function resumes (continues) an authentication process that
            was waiting for a result from an authentication server.

@ingroup    func_ssh_async_server_msg

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@inc_file ssh.h

@param connectionInstance   Connection instance returned from
                              SSH_ASYNC_acceptConnection().
@param result               Result of previous authentication attempt; see
                              @ref ssh_auth_result_codes.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous servers.

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_ASYNC_recvContinueMessage(sbyte4 connectionInstance, sbyte4 result);

/**
@brief      Send data to a %client.

@details    This function sends data to a %client. It should not be called
            until an open shell upcall notification
            (sshSettings::funcPtrOpenShell).

@ingroup    func_ssh_async_server_msg

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_ASYNC_acceptConnection().
@param pBuffer              Pointer to the send data buffer.
@param bufferSize           Number of bytes in send data buffer (\p pBuffer).
@param pBytesSent           On return, pointer to the number of bytes
                              successfully sent.

@inc_file ssh.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous servers.

@code
static void SSH_EXAMPLE_helloWorld(int connectionInstance)
{
    sbyte4 bytesSent = 0;
    sbyte4 status;

    status = SSH_ASYNC_sendMessage(connInstance,
                                   "hello world!", 12,
                                   &bytesSent);
}
@endcode

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_ASYNC_sendMessage(sbyte4 connectionInstance, sbyte *pBuffer, sbyte4 bufferSize, sbyte4 *pBytesSent);

/**
@brief      Determine whether there is data in a connection instance's SSH
            send buffer.

@details    This function determines whether there is data in a connection
            instance's SSH send buffer. If the send buffer is empty, zero (0)
            is returned through the \p pRetNumBytesPending parameter. If send
            data is pending, an attempt is made to send the data, and the
            subsequent number of bytes remaining to be sent is returned
            through the \p pRetNumBytesPending parameter.

@ingroup    func_ssh_async_server_msg

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_ASYNC_acceptConnection().
@param pRetNumBytesPending  On return, pointer to number of bytes remaining
                              in the send buffer.

@inc_file ssh.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@note       This function should not be called until after
            SSH_ASYNC_acceptConnection().

@remark     This function is applicable to asynchronous servers.

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_ASYNC_sendMessagePending(sbyte4 connectionInstance, ubyte4 *pRetNumBytesPending);

/**
@brief      Close a NanoSSH server session and releases all its resources.

@details    This function closes a NanoSSH server session and releases all the
            resources that are managed by the NanoSSH server.

@note       This function does not close sockets or TCBs (transmission
            control blocks). Therefore, your integration code should
            explicitly close all TCP/IP sockets and TCBs.

@ingroup    func_ssh_async_server_connection_mgmt

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_ASYNC_acceptConnection().
@param errorCode            Error code to identify the error status of the
                            connection. If the connection is closed normally,
                            this parameter should be set to \c OK (0).

@inc_file ssh.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous servers.

@code
sbyte4 status = 0;sbyte4 connectionInstance;

status = SSH_closeConnection(connectionInstance, errorCode);
@endcode

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_ASYNC_closeConnection(sbyte4 connectionInstance, MSTATUS errorCode);
#endif /* __ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__ */

#ifdef __ENABLE_DIGICERT_SSH_PORT_FORWARDING__
/**
@brief      Set a connection's port forwarding access permission.

@details    This function sets a connection's port forwarding access permission
            to the specified combination of the following bit flag constants:
+ \c MOCANA_SSH_ALLOW_DIRECT_TCPIP
+ \c MOCANA_SSH_ALLOW_FORWARDED_TCPIP
+ \c MOCANA_SSH_ALLOW_PRIVILEGED_DIRECT_TCPIP

@ingroup    func_ssh_core_server_security

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_PORT_FORWARDING__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param memberGroups         Combination of bit flag constant(s) specifying the
                              desired port forwarding access permission.

@inc_file ssh.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous servers.

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_setUserPortForwardingPermissions(sbyte4 connectionInstance, ubyte4 memberGroups);

/**
@brief      Send a message to a %client over a secure SSH connection.

@details    This function sends a message (typically unencrypted text) to a
            %client over a secure SSH connection unless deadlock prevention
            is enabled by the \c __ENABLE_DIGICERT_SSH_SENDER_RECV__ flag and
            the SSH transport window size indicates insufficient %client acknowledgement of previously sent data.

@ingroup    func_ssh_core_server_connection_mgmt

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_PORT_FORWARDING__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection().
@param channel              Port forwarding channel through which to send the
                              message (for example, \c SSH_PF_DATA).
@param pBuffer              Pointer to the data buffer to send.
@param bufferSize           Number of bytes in data buffer to send (\p pBuffer).
@param pBytesSent           On return, pointer to number of bytes
                              successfully sent.

@inc_file ssh.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@code
        // received data from pfSock, move bytes from server side to client side
        if ((pCookieStructure->pfSockActive) &&
            (0 != FD_ISSET(pCookieStructure->pfSock, pSocketList)))
        {
            // read bytes from pfSock
            if (0 > TCP_READ_AVL(pCookieStructure->pfSock, pInBuffer, MAX_SESSION_WINDOW_SIZE, &numBytesReceived, 1))
            {
                goto exit;
            }

            // forward data to socket
            if (0 < numBytesReceived)
            {
                if (0 > (SSH_sendPortForwardMessage(connInstance, SSH_PF_DATA, pInBuffer, numBytesReceived, &bytesSent)))
                    goto exit;
            }
        }
@endcode

@remark     This function is applicable to synchronous and asynchronous servers.

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_sendPortForwardMessage(sbyte4 connectionInstance, sbyte4 channel, sbyte *pBuffer, sbyte4 bufferSize, sbyte4 *pBytesSent);

MOC_EXTERN sbyte4 SSH_sendPortFwdOpen(sbyte4 connectionInstance, ubyte* pConnectHost,ubyte4 connectPort,ubyte* pSrc, ubyte4 srcPort,ubyte4 *myChannel);

/**
@brief      Send an SSH CLOSE message to an SSH %client whose local port
            forwarding socket is inactive.

@details    This function sends an SSH CLOSE message to an SSH %client whose
            local port forwarding socket is inactive. (The port may be
            inactive due to an error or due to the forwarded server
            deliberately dropping the connection.)

@note       This function should be called only for clients whose local port
            forwarding socket is inactive. Results are undefined if the local
            port forwarding socket is active.

@ingroup    func_ssh_core_server_connection_mgmt

@since 3.06
@version 3.06 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_PORT_FORWARDING__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection().
@param channel              Port forwarding channel through which to send the
                              message (for example, \c SSH_PF_DATA).

@inc_file ssh.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous servers.

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_sendPortForwardClose(sbyte4 connectionInstance, sbyte4 channel);

/**
@brief      Send an acknowledgement that data was received by the %server.

@details    This function sends an acknowledgement that data was received by
            the %server on the specified connection. Your application must
            explicitly call this function; there is no automatic
            acknowledgement. This function is similar to SSH_ASYNC_ackReceivedMessageBytes(), but is applicable only for
            port forwarding, where it must be used.

@ingroup    func_ssh_core_server_connection_mgmt

@since 3.06
@version 4.0 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_PORT_FORWARDING__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or SSH_ASYNC_acceptConnection().
@param sessionEvent         Type of message for which data was received (an
                              \c sshSessionTypes enumerated value, defined in ssh.h).
@param numBytesAck          Number of bytes received.
@param channel              Channel number from the SSH %client side; used for
                              local multiport forwarding.

@inc_file ssh.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous servers.

@funcdoc ssh.h
*/
MOC_EXTERN sbyte4 SSH_ackPortFwdReceivedMessageBytes(sbyte4 connectionInstance, enum sshSessionTypes sessionEvent, ubyte4 numBytesAck, ubyte4 channel);
#endif /* __ENABLE_DIGICERT_SSH_PORT_FORWARDING__ */

#else

/* stub functions */
#define SSH_init(X)                     (-1)
#define SSH_acceptConnection(X)         (-1)
#define SSH_negotiateConnection(X)      (-1)
#define SSH_recvMessage(X)              (-1)
#define SSH_sendMessage(X)              (-1)
#define SSH_closeConnection(X)          (-1)
#define SSH_getTerminalSettingDescr(X)  (-1)
#define SSH_getCookie(X)                (-1)
#define SSH_setCookie(X)                (-1)
#define SSH_startServer(X)              (-1)
#define SSH_stopServer(X)
#define SSH_disconnectAllClients(X)
#define SSH_compareAuthKeys(X)          (-1)
#define SSH_shutdown(X)                 (-1)
#define SSH_releaseTables(X)            (-1)
#define SSH_verifyPublicKeyFile(X)      (-1)
#define SSH_sshSettings(X)              (0)
#define SSH_sftpSettings(X)             (0)

#endif /* __ENABLE_DIGICERT_SSH_SERVER__ */

#ifdef __cplusplus
}
#endif

#endif /* __SSH_HEADER__ */
