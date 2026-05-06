/*
 * trustedge_main.h
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

#ifndef __TRUSTEDGE_MAIN_HEADER__
#define __TRUSTEDGE_MAIN_HEADER__

#ifndef __DISABLE_TRUSTEDGE_REST_API__
#include "../common/hash_table.h"
#endif

#include "../trustedge/agent/trustedge_agent_policy_data_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__)
typedef enum TrustedgeStatus {
    PREINSTALL = 1,
    INSTALLED,
    PROVISIONED
} TrustedgeStatus;

typedef enum TrustedgeState {
    UNKNOWN = 0,
    CONNECTED,
    PROCESSING_POLICY,
    DISCONNECTED,
} TrustedgeState;

typedef enum TrustedgeMode {
    PROVISION = 1,
    LAUNCH,
    LAUNCH_AND_EXIT
} TrustedgeMode;

enum TrustedgeState TRUSTEDGE_getState();

enum TrustedgeStatus TRUSTEDGE_getStatus();

/**
 * Register a callback that handles DNS lookups
 *
 * @param cb            Function pointer to callback to register
 */
void TRUSTEDGE_registerDNSLookupCallback(
    funcPtrDNSLookupCallback cb
);

/**
 * Register a callback for handling action handlers
 *
 * @param pCtx          TrustEdge agent context to release
 * @param cb            Function pointer to callback to register
 */
void TRUSTEDGE_registerUpdateActionHandlerCallback(
    funcPtrActionHandlerCallback cb
);

int TRUSTEDGE_launch(enum TrustedgeMode mode);

int TRUSTEDGE_extractBootStrap(char *pPath);

int TRUSTEDGE_install(char *pZipPath);

int TRUSTEDGE_installEx(char *pZipPath, char *pDst);

/**
 * This function sets the mount point using mount path and starting
 * directory path.
 *
 * @param pNewMountPath     NULL terminating string with path to mount point.
 * @param pNewDirectoryPath NULL terminating string with path to current working
 *                          directory from mount point.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
int TRUSTEDGE_setMountPoint(unsigned char *pNewMountPath);

int TRUSTEDGE_init(void);
int TRUSTEDGE_deinit(void);
int TRUSTEDGE_reset(void);
#ifdef __ENABLE_DIGICERT_CUSTOM_MALLOC__
int TRUSTEDGE_initCustomHeap(void *pHeap, int heapSize);
#endif

#endif /* __ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__ */

#ifndef __DISABLE_TRUSTEDGE_REST_API__
#define TRUSTEDGE_REST_API_HASH_TABLE_SIZE(N)  ((N) <= 0x7F ? 0x7F : \
                                                (N) <= 0xFF ? 0xFF : \
                                                (N) <= 0x1FF ? 0x1FF : \
                                                (N) <= 0x3FF ? 0x3FF : \
                                                (N) <= 0x7FF ? 0x7FF : \
                                                (N) <= 0xFFF ? 0xFFF : \
                                                (N) <= 0x1FFF ? 0x1FFF : \
                                                (N) <= 0x3FFF ? 0x3FFF : \
                                                (N) <= 0x7FFF ? 0x7FFF : \
                                                (N) <= 0xFFFF ? 0xFFFF : 0xFFFFFFFF)

#define TRUSTEDGE_REST_API_HASH_VALUE_BASE      (0x255179c9)

typedef struct _TrustEdgeResource
{
    ubyte *pResourcePath;
    byteBoolean isUpdated;
} TrustEdgeResource;

typedef struct _TrustEdgeResourceCtx
{
    TrustEdgeResource *resourceCtx;
    ubyte2 numResources;
    ubyte2 numUpdatedResources;
} TrustEdgeResourceCtx;

typedef struct _TrustEdgePidCtx
{
    ubyte **pPidVal;
    ubyte2 numPids;
} TrustEdgePidCtx;

typedef struct _TrustEdgeRestApiCtx
{
    hashTableOfPtrs *pHashTableDesiredAttrs;
    sbyte *pJsonBuf;
    ubyte *pKeyBuf;
    ubyte4 privLen;
    sbyte *pOutputMode;
    sbyte *pPid;
    hashTableOfPtrs *pHashTablePidKey;
    hashTableOfPtrs *pHashTableResourceKey;
    ubyte2 numProcesses;
} TrustEdgeRestApiCtx;
#endif

#ifdef __cplusplus
}
#endif

#endif /* __TRUSTEDGE_MAIN_HEADER__ */
