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
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */


/*------------------------------------------------------------------*/

#ifndef __SSHC_AUTH_HEADER__
#define __SSHC_AUTH_HEADER__

#define AUTH_FAILURE_BUFFER(X)              (X)->authContext.pAuthFailueBuffer
#define AUTH_KEYINT_CONTEXT(X)              (X)->authContext.kbdInteractiveAuthContext

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSHC_AUTH_SendUserAuthServiceRequest(sshClientContext *pContextSSH);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSHC_AUTH_doProtocol(sshClientContext *pContextSSH, ubyte *pNewMesg, ubyte4 newMesgLen);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSHC_AUTH_allocStructures(sshClientContext *pContextSSH);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSHC_AUTH_deallocStructures(sshClientContext *pContextSSH);

#endif /* __SSHC_AUTH_HEADER__ */
