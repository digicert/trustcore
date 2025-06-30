/*
 * ssh_defs.h
 *
 * SSH Protocol Definitions
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

#ifndef __SSH_DEFS_HEADER__
#define __SSH_DEFS_HEADER__

/* from SSH Transport Layer Protocol Internet Draft */
#define SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT      1
#define SSH_DISCONNECT_PROTOCOL_ERROR                   2
#define SSH_DISCONNECT_KEY_EXCHANGE_FAILED              3
#define SSH_DISCONNECT_RESERVED                         4
#define SSH_DISCONNECT_MAC_ERROR                        5
#define SSH_DISCONNECT_COMPRESSION_ERROR                6
#define SSH_DISCONNECT_SERVICE_NOT_AVAILABLE            7
#define SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED   8
#define SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE          9
#define SSH_DISCONNECT_CONNECTION_LOST                  10
#define SSH_DISCONNECT_BY_APPLICATION                   11
#define SSH_DISCONNECT_TOO_MANY_CONNECTIONS             12
#define SSH_DISCONNECT_AUTH_CANCELLED_BY_USER           13
#define SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE   14
#define SSH_DISCONNECT_ILLEGAL_USER_NAME                15

#define SSH_MSG_DISCONNECT                              1
#define SSH_MSG_IGNORE                                  2
#define SSH_MSG_UNIMPLEMENTED                           3
#define SSH_MSG_DEBUG                                   4
#define SSH_MSG_SERVICE_REQUEST                         5
#define SSH_MSG_SERVICE_ACCEPT                          6
#define SSH_MSG_EXT_INFO                                7 /* RFC 8308 */

#define SSH_MSG_KEXINIT                                 20
#define SSH_MSG_NEWKEYS                                 21

/* Numbers 30-49 used for kex packets.
Different kex methods may reuse message numbers in
this range. */

#define SSH_MSG_KEXDH_INIT                              30
#define SSH_MSG_KEXDH_REPLY                             31

#define SSH_MSG_KEX_DH_GEX_REQUEST_OLD                  30
#define SSH_MSG_KEY_DH_GEX_REQUEST                      34
#define SSH_MSG_KEX_DH_GEX_GROUP                        31
#define SSH_MSG_KEX_DH_GEX_INIT                         32
#define SSH_MSG_KEX_DH_GEX_REPLY                        33

#define SSH_MSG_KEXRSA_PUBKEY                           30
#define SSH_MSG_KEXRSA_SECRET                           31
#define SSH_MSG_KEXRSA_DONE                             32

#define SSH_MSG_KEX_ECDH_INIT                           30
#define SSH_MSG_KEX_ECDH_REPLY                          31

#define SSH_MSG_KEX_HYBRID_INIT                         30
#define SSH_MSG_KEX_HYBRID_REPLY                        31

/*------------------------------------------------------------------*/

/* from SSH Authentication Protocol Internet Draft */
/* These are the general authentication message codes: */

#define SSH_MSG_USERAUTH_REQUEST                        50
#define SSH_MSG_USERAUTH_FAILURE                        51
#define SSH_MSG_USERAUTH_SUCCESS                        52
#define SSH_MSG_USERAUTH_BANNER                         53
/* Key-based */
#define SSH_MSG_USERAUTH_PK_OK                          60

/* The following method-specific message numbers are used by the
password authentication method. */

#define SSH_MSG_USERAUTH_PASSWD_CHANGEREQ               60


/*------------------------------------------------------------------*/

/* from SSH Connection Protocol Internet Draft */
/* The following reason codes are defined: */

#define SSH_OPEN_ADMINISTRATIVELY_PROHIBITED            1
#define SSH_OPEN_CONNECT_FAILED                         2
#define SSH_OPEN_UNKNOWN_CHANNEL_TYPE                   3
#define SSH_OPEN_RESOURCE_SHORTAGE                      4

/* Data sent with these messages consumes the same window as ordinary
data.

Currently, only the following type is defined. */

#define SSH_EXTENDED_DATA_STDERR                        1


/* Summary of Message Numbers */
#define SSH_MSG_GLOBAL_REQUEST                          80
#define SSH_MSG_REQUEST_SUCCESS                         81
#define SSH_MSG_REQUEST_FAILURE                         82
#define SSH_MSG_CHANNEL_OPEN                            90
#define SSH_MSG_CHANNEL_OPEN_CONFIRMATION               91
#define SSH_MSG_CHANNEL_OPEN_FAILURE                    92
#define SSH_MSG_CHANNEL_WINDOW_ADJUST                   93
#define SSH_MSG_CHANNEL_DATA                            94
#define SSH_MSG_CHANNEL_EXTENDED_DATA                   95
#define SSH_MSG_CHANNEL_EOF                             96
#define SSH_MSG_CHANNEL_CLOSE                           97
#define SSH_MSG_CHANNEL_REQUEST                         98
#define SSH_MSG_CHANNEL_SUCCESS                         99
#define SSH_MSG_CHANNEL_FAILURE                         100


/*------------------------------------------------------------------*/

/* from RFC 4256: Generic Message Exchange Authentication for SSH */
#define SSH_MSG_USERAUTH_INFO_REQUEST                   60
#define SSH_MSG_USERAUTH_INFO_RESPONSE                  61


/*------------------------------------------------------------------*/

/* from SSH File Transfer Protocol Internet Draft */

/* The following values are defined for packet types. */
#define SSH_FXP_INIT                                    1
#define SSH_FXP_VERSION                                 2
#define SSH_FXP_OPEN                                    3
#define SSH_FXP_CLOSE                                   4
#define SSH_FXP_READ                                    5
#define SSH_FXP_WRITE                                   6
#define SSH_FXP_LSTAT                                   7
#define SSH_FXP_FSTAT                                   8
#define SSH_FXP_SETSTAT                                 9
#define SSH_FXP_FSETSTAT                                10
#define SSH_FXP_OPENDIR                                 11
#define SSH_FXP_READDIR                                 12
#define SSH_FXP_REMOVE                                  13
#define SSH_FXP_MKDIR                                   14
#define SSH_FXP_RMDIR                                   15
#define SSH_FXP_REALPATH                                16
#define SSH_FXP_STAT                                    17
#define SSH_FXP_RENAME                                  18
#define SSH_FXP_READLINK                                19
#define SSH_FXP_SYMLINK                                 20

#define SSH_FXP_STATUS                                  101
#define SSH_FXP_HANDLE                                  102
#define SSH_FXP_DATA                                    103
#define SSH_FXP_NAME                                    104
#define SSH_FXP_ATTRS                                   105

#define SSH_FXP_EXTENDED                                200
#define SSH_FXP_EXTENDED_REPLY                          201

/* RESERVED_FOR_EXTENSIONS                              210-255 */


/* The flags bits are defined to have the following values: */
#define SSH_FILEXFER_ATTR_SIZE                          0x00000001
#define SSH_FILEXFER_ATTR_UIDGID                        0x00000002
#define SSH_FILEXFER_ATTR_PERMISSIONS                   0x00000004
#define SSH_FILEXFER_ATTR_ACCESSTIME                    0x00000008
#define SSH_FILEXFER_ATTR_CREATETIME                    0x00000010
#define SSH_FILEXFER_ATTR_MODIFYTIME                    0x00000020
#define SSH_FILEXFER_ATTR_ACL                           0x00000040
#define SSH_FILEXFER_ATTR_OWNERGROUP                    0x00000080
#define SSH_FILEXFER_ATTR_SUBSECOND_TIMES               0x00000100
#define SSH_FILEXFER_ATTR_EXTENDED                      0x80000000

/* In previous versions of this protocol flags value 0x00000002 was
SSH_FILEXFER_ATTR_UIDGID.  This value is now unused, and OWNERGROUP
was given a new value in order to ease implementation burden.
0x00000002 MUST NOT appear in the mask.  Some future version of this
protocol may reuse flag 0x00000002. */

/* The type field is always present.  The following types are defined: */

#define SSH_FILEXFER_TYPE_REGULAR                       1
#define SSH_FILEXFER_TYPE_DIRECTORY                     2
#define SSH_FILEXFER_TYPE_SYMLINK                       3
#define SSH_FILEXFER_TYPE_SPECIAL                       4
#define SSH_FILEXFER_TYPE_UNKNOWN                       5

#define SSH_FXF_READ                                    0x00000001
#define SSH_FXF_WRITE                                   0x00000002
#define SSH_FXF_APPEND                                  0x00000004
#define SSH_FXF_CREAT                                   0x00000008
#define SSH_FXF_TRUNC                                   0x00000010
#define SSH_FXF_EXCL                                    0x00000020
#define SSH_FXF_TEXT                                    0x00000040


/*------------------------------------------------------------------*/

/* from GSSAPI Authentication and Key Exchange for the SSH Internet Draft */
#define SSH_MSG_KEXGSS_INIT                             30
#define SSH_MSG_KEXGSS_CONTINUE                         31
#define SSH_MSG_KEXGSS_COMPLETE                         32
#define SSH_MSG_KEXGSS_HOSTKEY                          33
#define SSH_MSG_KEXGSS_ERROR                            34

/* The numbers 30-49 are specific to key exchange and may be redefined
by other kex methods.

The following message numbers have been defined for use with the
'gssapi' user authentication method: */

#define SSH_MSG_USERAUTH_GSSAPI_RESPONSE                60
#define SSH_MSG_USERAUTH_GSSAPI_TOKEN                   61
#define SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE       63
#define SSH_MSG_USERAUTH_GSSAPI_ERROR                   64


/*------------------------------------------------------------------*/

/* from Diffie-Hellman Group Exchange for the SSH Transport Layer Protocol Internet Draft */
/* The following message numbers have been defined in this document. */

#define SSH_MSG_KEX_DH_GEX_REQUEST_OLD                  30
#define SSH_MSG_KEX_DH_GEX_REQUEST                      34
#define SSH_MSG_KEX_DH_GEX_GROUP                        31
#define SSH_MSG_KEX_DH_GEX_INIT                         32
#define SSH_MSG_KEX_DH_GEX_REPLY                        33


/*------------------------------------------------------------------*/

/* from Secure Shell Authentication Agent Protocol */
/* Messages sent by the client. */
#define SSH_AGENT_REQUEST_VERSION                       1
#define SSH_AGENT_ADD_KEY                               202
#define SSH_AGENT_DELETE_ALL_KEYS                       203
#define SSH_AGENT_LIST_KEYS                             204
#define SSH_AGENT_PRIVATE_KEY_OP                        205
#define SSH_AGENT_FORWARDING_NOTICE                     206
#define SSH_AGENT_DELETE_KEY                            207
#define SSH_AGENT_LOCK                                  208
#define SSH_AGENT_UNLOCK                                209
#define SSH_AGENT_PING                                  212
#define SSH_AGENT_RANDOM                                213

/* Messages sent by the agent. */
#define SSH_AGENT_SUCCESS                               101
#define SSH_AGENT_FAILURE                               102
#define SSH_AGENT_VERSION_RESPONSE                      103
#define SSH_AGENT_KEY_LIST                              104
#define SSH_AGENT_OPERATION_COMPLETE                    105
#define SSH_AGENT_RANDOM_DATA                           106
#define SSH_AGENT_ALIVE                                 150


/* Constraints 50-99 have a uint32 argument */

/* Argument is uint32 defining key expiration time-out in
seconds. After this timeout expires, the key can't be used.
0 == no timeout */
#define SSH_AGENT_CONSTRAINT_TIMEOUT                    50

/* Argument is uint32 defining the number of operations that can
be performed with this key.  0xffffffff == no limit */
#define SSH_AGENT_CONSTRAINT_USE_LIMIT                  51

/* Argument is uint32 defining the number of forwarding steps that
this key can be forwarded.  0xffffffff == no limit */
#define SSH_AGENT_CONSTRAINT_FORWARDING_STEPS           52

/* Constraints 100-149 have a string argument */

/* Argument is string defining the allowed forwarding steps for
this key. XXX define this. */
#define SSH_AGENT_CONSTRAINT_FORWARDING_PATH            100

/* Constraints 150-199 have a boolean argument */

/* Argument is a boolean telling whether the key can be used
in Secure Shell 1.x compatibility operations. */

#define SSH_AGENT_CONSTRAINT_SSH1_COMPAT                150

/* Argument is a boolean telling whether operations performed
with this key should  be confirmed interactively by the user
or not. */
#define SSH_AGENT_CONSTRAINT_NEED_USER_VERIFICATION     151

/* The error code is one of the following: */
#define SSH_AGENT_ERROR_TIMEOUT                         1
#define SSH_AGENT_ERROR_KEY_NOT_FOUND                   2
#define SSH_AGENT_ERROR_DECRYPT_FAILED                  3
#define SSH_AGENT_ERROR_SIZE_ERROR                      4
#define SSH_AGENT_ERROR_KEY_NOT_SUITABLE                5
#define SSH_AGENT_ERROR_DENIED                          6
#define SSH_AGENT_ERROR_FAILURE                         7
#define SSH_AGENT_ERROR_UNSUPPORTED_OP                  8

#endif /* __SSH_DEFS_HEADER__ */
