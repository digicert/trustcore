/*
 * ssh_auth.h
 *
 * SSH Authentication Header
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
@file       ssh_auth.h
@brief      SSH authentication functions header.
@details    This header file contains definitions and function declarations used
            by for SSH authentication.

@since 1.41
@version 2.02 and later

@flags
Whether the following flag is defined determines which function declarations are
enabled:
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

*/


/*------------------------------------------------------------------*/

#ifndef __SSH_AUTH_HEADER__
#define __SSH_AUTH_HEADER__

#define AUTH_FAILURE_BUFFER(X)              (X)->authContext.pAuthFailueBuffer
#define AUTH_ADVERTISED(X)                  (X)->authAdvertised
#define AUTH_ADVERTISED_METHODS(X)          (X)->advertisedMethods
#define AUTH_FAILURE_ATTEMPTS(X)            (X)->authAttempts
#define AUTH_KEYINT_CONTEXT(X)              (X)->authContext.kbdInteractiveAuthContext

/* SSH2 authentication range */
#define SSH2_MSG_USERAUTH_LOW               (50)
#define SSH2_MSG_USERAUTH_HIGH              (79)


/*------------------------------------------------------------------*/

/**
@brief      Initialize SSH authentication structure.

@details    This function initializes authDescr structure in sshContext. It initializes
keyInitAuthContext with NULL values, and allocates pAuthFailueBuffer with default values.

@ingroup    func_ssh_core_server_security

@since 4.2
@version 4.2 and later

@flags
To enable this function, at least one of the following flags must be defined:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__

@param pContextSSH          SSH context whose authDescr field authContext will be populated.

@inc_file ssh_auth.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     To initialize a SSH context, use SSH_CONTEXT_allocStructures, which itself
calls this function.

@funcdoc ssh_auth.h
*/
MOC_EXTERN MSTATUS SSH_AUTH_allocStructures(sshContext *pContextSSH);

/**
@brief      Release SSH authentication structure.

@details    Free data in authDescr structure of sshContext.

@ingroup    func_ssh_core_server_security

@since 4.2
@version 4.2 and later

@flags
To enable this function, at least one of the following flags must be defined:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__

@param pContextSSH          SSH context containing authDescr to release.

@inc_file ssh_auth.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function should not be called directly, instead call
SSH_CONTEXT_deallocStructures.

@funcdoc ssh_auth.h
*/
MOC_EXTERN MSTATUS SSH_AUTH_deallocStructures(sshContext *pContextSSH);

/**
@brief      Does the Authentication Protocol for SSH.

@details    Does the Authentication Protocol for SSH. Defined in RFC 4252.
Receives service request and processes authentication message from %client.

@ingroup    func_ssh_core_server_security

@since 4.2
@version 4.2 and later

@flags
To enable this function, at least one of the following flags must be defined:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__

@param pContextSSH          SSH context for authentication request
@param pNewMesg             SSH binary packet containing message
@param newMesgLen           Length in bytes of pNewMesg

@inc_file ssh_auth.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc ssh_auth.h
*/
MOC_EXTERN MSTATUS SSH_AUTH_doProtocol(sshContext *pContextSSH, ubyte *pNewMesg, ubyte4 newMesgLen);

#ifdef __ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__
/**
@brief      Continue authentication from wait state.

@details    This function is used to continue the authentication process from a wait state.

@param pContextSSH          SSH context for authentication request
@param authResult           Result of the authentication attempt

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.
*/
MOC_EXTERN MSTATUS SSH_AUTH_continueAuthFromWait(sshContext *pContextSSH, sbyte4 authResult);
#endif

#endif /* __SSH_AUTH_HEADER__ */
