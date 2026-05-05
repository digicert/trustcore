/*
 * trustedge_agent.h
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

#ifndef __TRUSTEDGE_AGENT_HEADER__
#define __TRUSTEDGE_AGENT_HEADER__

#include "../../common/moptions.h"
#include "../../common/mdefs.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/msg_logger.h"
#include "../../common/hash_table.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef METRIC_HASH_TABLE_SIZE
#define METRIC_HASH_TABLE_SIZE      (127)
#endif

#ifndef METRIC_HASH_VALUE_BASE
#define METRIC_HASH_VALUE_BASE      (0x255179c9)
#endif

#define TRUSTEDGE_AGENT_BOOTSTRAP_SIGNATURE_ENV   "TE_VERIFY_BOOTSTRAP_SIGNATURE"

typedef struct
{
    sbyte *pBootstrapConfig;
    sbyte *pWorkspaceDir;
    sbyte *pDebugDir;
} TrustEdgeAgentSettings;

typedef void TrustEdgeAgentContext;

typedef int (*funcPtrSafeToExitCallback)(sbyte4);

typedef struct
{
    MSTATUS statusCode;
} TrustEdgeAgentResult;

byteBoolean TRUSTEDGE_isServiceRunning();

/**
 * Create TrustEdge agent context
 *
 * @param ppCtx         Location where context is stored
 * @param pSettings     Settings for agent mode to run with
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS TRUSTEDGE_agentContextAcquire(
    TrustEdgeAgentContext **ppCtx,
    TrustEdgeConfig **ppConfig);

/**
 * Perform TrustEdge agent operation
 *
 * @param pCtx          TrustEdge agent context
 * @param ppResult      Result of TrustEdge agent operation
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS TRUSTEDGE_agentContextProcess(
    TrustEdgeAgentContext *pCtx,
    TrustEdgeAgentResult **ppResult);

/**
 * Release TrustEdge agent context
 *
 * @param ppCtx         TrustEdge agent context to release
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS TRUSTEDGE_agentContextRelease(
    TrustEdgeAgentContext **ppCtx);

/**
 * Launch TrustEdge agent in service mode
 *
 * @param pSettings     Settings for agent mode to run with
 * @param cb            Function pointer to callback to register
 * @param ppResult      Result of TrustEdge agent operation
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS TRUSTEDGE_agentContextService(
    TrustEdgeConfig **ppConfig,
    TrustEdgeAgentResult **ppResult);

/**
 * Register a callback that is lets Trustedge know
 * when if it is safe to exit.
 *
 * @param cb            Function pointer to callback to register
 */
MOC_EXTERN void TRUSTEDGE_registerStatusCallback(
    funcPtrSafeToExitCallback cb
);

/**
 * @private
 * @internal
 */
MOC_EXTERN MSTATUS TRUSTEDGE_agentMetricAlloc(
    void *pHashCookie,
    hashTablePtrElement **ppNewElement);

/**
 * @private
 * @internal
 */
MOC_EXTERN MSTATUS TRUSTEDGE_agentMetricFree(
    void *pHashCookie,
    hashTablePtrElement *pDeleteElement);

#ifdef __cplusplus
}
#endif

#endif /* __TRUSTEDGE_AGENT_HEADER__ */
