/*
 * ssh_auth.h
 *
 * SSH Authentication Header
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
