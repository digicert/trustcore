/**
 * @file tap_remote.h
 *
 * @ingroup nanotap_tree
 *
 * @brief Trust Anchor Platform (TAP) Definitions and Types for Client-Server communication.
 * @details This file contains definitions and functions needed by both Mocana Trust Anchor Platform (TAP) client and server modules.
 *
 * @flags
 * This file requires that the following flags be defined:
 *    + \c \__ENABLE_MOCANA_TAP__
 *
 * @flags
 * Whether the following flags are defined determines whether or not support is enabled for a particular security module:
 *    + \c \__ENABLE_MOCANA_TPM2__
 *
 * Copyright (c) Mocana Corp 2018. All Rights Reserved.
 * Proprietary and Confidential Material.
 * 
 */


/*------------------------------------------------------------------*/

#ifndef __TAP_REMOTE_HEADER__
#define __TAP_REMOTE_HEADER__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mtcp.h"
#include "../common/random.h"
#include "../crypto/hw_accel.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/sha256.h"
#include "tap.h"
#include "tap_smp.h"

#ifdef __cplusplus
extern "C" {
#endif

/*! @cond */
#if (defined (__ENABLE_MOCANA_TAP__) && defined (__ENABLE_TAP_REMOTE__))
/*! @endcond */

/***************************************************************
   Constant Definitions
****************************************************************/


/***************************************************************
   Command Code definitions TAP client and server communication
****************************************************************/

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details TAP command code
 * @details The TAP command codes handled by the TAP server.  Commands that map one-to-one to a single SMP command
 *          will use the SMP_CC.  The range from 0x8000 to 0x8FFF is reserved for TAP_CMD codes, used for commands
 *          handled by the TAP server or for commands mapping a single TAP command to more than one SMP command.
 *          This is useful in a client-server model to prevent sending
 *          multiple command requests and response over the client-server connection.
 */
typedef ubyte2 TAP_CMD;
/*! TAP_CMD_UNDEFINED */
#define  TAP_CMD_UNDEFINED                         ((ubyte2)0)
/*! TAP_CMD_GET_PROVIDER_LIST - TAP command to get the list of available providers (TAP_PROVIDER) */
#define  TAP_CMD_GET_PROVIDER_LIST                 ((ubyte2)0x8001)
/*! TAP_CMD_IS_PROVIDER_PRESENT - TAP command to check if a TAP_PROVIDER is present */
#define  TAP_CMD_IS_PROVIDER_PRESENT               ((ubyte2)0x8002)
/*! TAP_CMD_INIT_CONTEXT - TAP command to initialize the TAP and module context for the underlying module.
 *                         This command will result in a call to SMP_<NAME>_initModule for the underlying module.
 */
#define  TAP_CMD_INIT_CONTEXT                      ((ubyte2)0x8003)
/*! TAP_CMD_UNINIT_CONTEXT - TAP command to uninitialize the TAP and module context for the underlying module.
 *                           This command will result in a call to SMP_<NAME>_uninitModule for the underlying module.
 */
#define  TAP_CMD_UNINIT_CONTEXT                    ((ubyte2)0x8004)

/***************************************************************
   "enum" Definitions - use #defines for compiler compatibility
****************************************************************/



/**
 * @ingroup tap_definitions
 * @brief Value to indicate the direction of the command; a request or a response.
 * @details Value to indicate the destination of the command; a request or a response.
 *     <p> This value will tell the modules what data structure to expect.
 *     <p> TAP_CMD_DIRECTION must be one of the following values:
 *     - #TAP_CMD_DIRECTION_REQ
 *     - #TAP_CMD_DIRECTION_RSP
 */
typedef ubyte TAP_CMD_DIRECTION;
/*! TAP_CMD_DIRECTION_UNDEFINED - Undefined destination */
#define  TAP_CMD_DIRECTION_UNDEFINED  ((ubyte)0)
/*! TAP_CMD_DIRECTION_REQ - Command is sent to specified module daemon to handle. */
#define  TAP_CMD_DIRECTION_REQ        ((ubyte)1)
/*! TAP_CMD_DIRECTION_RSP - Command is handle by the TAP server. */
#define  TAP_CMD_DIRECTION_RSP        ((ubyte)2)

/**
 * @ingroup tap_definitions
 * @brief Value to indicate the destination of the command; the specific module daemon or server.
 * @details Value to indicate the destination of the command; the specific module daemon or server.
 *     <p> Some commands, such as discovery, are handled by the server and not the individual module daemons.
 *     <p> TAP_CMD_DEST must be one of the following values:
 *     - #TAP_CMD_DEST_MODULE
 *     - #TAP_CMD_DEST_SERVER
 */
typedef ubyte TAP_CMD_DEST;
/*! TAP_CMD_DEST_UNDEFINED - Undefined destination */
#define  TAP_CMD_DEST_UNDEFINED  ((ubyte)0)
/*! TAP_CMD_DEST_MODULE - Command is sent to specified module daemon to handle. */
#define  TAP_CMD_DEST_MODULE     ((ubyte)1)
/*! TAP_CMD_DEST_SERVER - Command is handle by the TAP server. */
#define  TAP_CMD_DEST_SERVER     ((ubyte)2)

/**
 * @ingroup tap_definitions
 * @brief Value to indicate the underlying command structure; SMP_CmdReq or TAP_CmdReq.
 * @details Value to indicate the underlying command structure; SMP_CmdReq or TAP_CmdReq.
 *     <p> Some commands are handled by the TAP server only and thus have a TAP_CmdReq structure.
 *     <p> Commands handle by in SMP will have a SMP_CmdReq structure.
 *     <p> Commands requiring action by both the TAP server and the SMP may have a either command structure.  If a TAP_CmdReq
 *         structure is passed in this case, the TAP server must translate the request into an SMP_CmdReq.
 *     <p> TAP_CMD_TYPE must be one of the following values:
 *     - #TAP_CMD_TYPE_SMP
 *     - #TAP_CMD_TYPE_TAP
 */
typedef ubyte TAP_CMD_TYPE;
/*! TAP_CMD_TYPE_UNDEFINED - Undefined command structure */
#define  TAP_CMD_TYPE_UNDEFINED  ((ubyte)0)
/*! TAP_CMD_TYPE_SMP - The underlying command structure is SMP_CmdReq. */
#define  TAP_CMD_TYPE_SMP        ((ubyte)1)
/*! TAP_CMD_TYPE_TAP - The underlying command structure is TAP_CmdReq. */
#define  TAP_CMD_TYPE_TAP        ((ubyte)2)

/***************************************************************
   General Structure Definitions
****************************************************************/




/***************************************************************
   Context Structure Definitions
****************************************************************/

#if 0

/** @private
 *  @internal
 */
typedef struct  _TAPS_Context
{
    TAP_PROVIDER           providerType;
    TAP_ModuleId           moduleId;
#if 0
    TAP_Buffer             pathName;  /*  TAP_Buffer with length to support Unicode in future releases */
    ubyte2 port;
#endif
    void                  *pModuleConfInfo;
    struct _TAPS_Context  *pNext;
} TAPS_Context;

#endif



/***************************************************************
   Command Request-Response Structure Definitions
****************************************************************/


/**
 * @private
 * @internal
 *
 * @ingroup tap_definitions
 * @details Command request structure for TAP_getProviderList
 */
typedef struct
{
    /*! for compilers that do not allow an empty structure */
    ubyte nullChar;
} TAP_GetProviderList_ReqParams;

/**
 * @private
 * @internal
 *
 * @ingroup tap_definitions
 * @details Response structure for TAP_getProviderList
 */
typedef struct
{
    /*! The list of providers available on the specified host */
    TAP_ProviderList     providerList;
} TAP_GetProviderList_RspParams;

/****************************************/

/**
 * @private
 * @internal
 *
 * @ingroup tap_definitions
 * @details Command request structure for TAP_isProviderPresent
 */
typedef struct
{
    /*! TAP_PROVIDER to check if present */
    TAP_PROVIDER  providerType;
} TAP_IsProviderPresent_ReqParams;

/**
 * @private
 * @internal
 *
 * @ingroup tap_definitions
 * @details Response structure for TAP_getProviderList
 */
typedef struct
{
    /*! Boolean indicating whether or not the TAP_PROVIDER is present. */
    ubyte     isPresent;
} TAP_IsProviderPresent_RspParams;

/****************************************/
/**
 * @private
 * @internal
 *
 * @ingroup tap_definitions
 * @details Command request structure for TAP_initContext
 */
typedef struct
{
    /*! Module ID for which to create a context. */
    TAP_ModuleId       moduleId;
    /*! Optional Credentials needed by a SMP to initialize a context.  This may contain 0 or more credentials.
        Refer to the SMP documentation for the types of credentials supported and/or required. */
    TAP_CredentialList *pCredentials;
} TAP_InitContext_ReqParams;

/**
 * @private
 * @internal
 *
 * @ingroup tap_definitions
 * @details Command response structure for TAP_initContext
 */
typedef struct
{
    /*! The module handle returned. */
    TAP_ModuleHandle moduleHandle;
} TAP_InitContext_RspParams;

/****************************************/

/**
 * @private
 * @internal
 *
 * @ingroup tap_definitions
 * @details Command request structure for TAP_uninitContext
 */
typedef struct
{
    /*! Serialized module handle. */
    TAP_ModuleHandle moduleHandle;
} TAP_UninitContext_ReqParams;

/**
 * @private
 * @internal
 *
 * @ingroup tap_definitions
 * @details Command response structure for TAP_uninitContext
 */
typedef struct
{
    /*! for compilers that do not allow an empty structure */
    ubyte nullChar;
} TAP_UninitContext_RspParams;


/***************************************************************
  Command request/response unions
****************************************************************/

typedef union
{
    TAP_GetProviderList_ReqParams           getProviderList;           /* NULL */
    TAP_IsProviderPresent_ReqParams         isProviderPresent;
    TAP_InitContext_ReqParams               initContext;
    TAP_UninitContext_ReqParams             uninitContext;
} TAP_CmdReqParams;

typedef union
{
    TAP_GetProviderList_RspParams           getProviderList;
    TAP_IsProviderPresent_RspParams         isProviderPresent;
    TAP_InitContext_RspParams               initContext;
    TAP_UninitContext_RspParams             uninitContext;
} TAP_CmdRspParams;

/****************************************/


/**
 * @ingroup tap_definitions
 * @details Structure containing all information needed to process a TAP command.
 */
typedef struct
{
    /*! command code */
    TAP_CMD             cmdCode;
    /*! The command request parameters.  The cmdCode determines the structure within the union. */
    TAP_CmdReqParams    reqParams;
} TAP_CmdReq;

/**
 * @ingroup tap_definitions
 * @details Structure containing all information needed to process a TAP command.
 */
typedef struct
{
    /*! command code */
    TAP_CMD             cmdCode;
    /*! Command response code. */
    MSTATUS             cmdStatus;
    /*! The command response parameters.  The cmdCode determines the structure within the union. */
    TAP_CmdRspParams    rspParams;
} TAP_CmdRsp;

/****************************************/

/**
 * @ingroup tap_definitions
 * @details Structure containing TAP client-server request header information
 */
typedef struct
{
    /*! Identifies whether this command gets processed by the server or an individual SMP.
        If TAP_CMD_TYPE = TAP_CMD_DEST_SERVER, the commmand gets processed by the TAP server.
        If TAP_CMD_TYPE = TAP_CMD_DEST_MODULE, the commmand gets processed by an individual SMP.
     */
    TAP_CMD_DEST    cmdDest;
    /*! Identifies the underlying command request type.
        If TAP_CMD_TYPE = TAP_CMD_TYPE_TAP, the underlying command is a TAP_CmdReq structure.
        If TAP_CMD_TYPE = TAP_CMD_TYPE_SMP, the underlying command is an SMP_CmdReq structure.
     */
    TAP_CMD_TYPE    cmdType;
    /*! The security module to which the command is being issued or for which discovery is requested. */
    TAP_PROVIDER    providerType;
    /*! Total number of bytes in command buffer, including the header(s) */
    ubyte4          totalBytes;
} TAP_CmdReqHdr;

/**
 * @ingroup tap_definitions
 * @details Structure containing TAP client-server response header information
 */
typedef struct
{
    /*! Server response code. */
    MSTATUS        cmdStatus;
    /*! Identified the underlying command response type.
        If TAP_CMD_TYPE = TAP_CMD_TYPE_TAP, the underlying command is a TAP_CmdRsp structure.
        If TAP_CMD_TYPE = TAP_CMD_TYPE_SMP, the underlying command is an SMP_CmdRsp structure.
     */
    TAP_CMD_TYPE   cmdType;
    /*! Total number of bytes in response buffer, including the header(s) */
    ubyte4         totalBytes;
} TAP_CmdRspHdr;



/***************************************************************
   Function Definitions
****************************************************************/

MSTATUS TAP_updateAttributeList(TAP_AttributeList *pSrc, TAP_AttributeList *pDest,
        ubyte4 *pAttributeListLen);



/*! @cond */
#endif /* __ENABLE_MOCANA_TAP__ && __ENABLE_TAP_REMOTE__ */
/*! @endcond */

#ifdef __cplusplus
}
#endif

#endif /* __TAP_REMOTE_HEADER__ */
