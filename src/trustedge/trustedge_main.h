/**
 * @file trustedge_main.h
 * @brief TrustEdge main entry points and runtime state definitions.
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
/**
 * @brief Installation and provisioning status of TrustEdge.
 */
typedef enum TrustedgeStatus {
    PREINSTALL = 1, /**< TrustEdge configuration is not present on the device. */
    INSTALLED,      /**< TrustEdge is installed but not bootstrapped. */
    PROVISIONED     /**< TrustEdge is installed and the bootstrap is extracted. */
} TrustedgeStatus;

/**
 * @brief Runtime connection state of the TrustEdge agent.
 */
typedef enum TrustedgeState {
    UNKNOWN = 0,       /**< State is not tracked on this platform. */
    CONNECTED,         /**< Agent is connected to the server. */
    PROCESSING_POLICY, /**< Agent is processing a policy. */
    DISCONNECTED,      /**< Agent is disconnected from the server. */
} TrustedgeState;

/**
 * @brief Mode in which TRUSTEDGE_launch() runs.
 */
typedef enum TrustedgeMode {
    PROVISION = 1,  /**< Install and bootstrap only; do not start the agent. */
    LAUNCH,         /**< Provision if needed, then run the agent until stopped. */
    LAUNCH_AND_EXIT /**< Provision if needed, run the agent and exit once policies are processed. */
} TrustedgeMode;

/**
 * @brief Get the current agent runtime state.
 *
 * @details State is only tracked on Zephyr; all other platforms return
 *          \c UNKNOWN.
 *
 * @return Current \c TrustedgeState value.
 */
enum TrustedgeState TRUSTEDGE_getState();

/**
 * @brief Determine the installation status of TrustEdge.
 *
 * @details Returns \c PREINSTALL if the TrustEdge configuration file does not
 *          exist, \c INSTALLED if it exists, and \c PROVISIONED if the
 *          bootstrap file is also present in the configuration directory.
 *
 * @return Current \c TrustedgeStatus value.
 */
enum TrustedgeStatus TRUSTEDGE_getStatus();

/**
 * @brief Register a callback that handles DNS lookups.
 *
 * @param cb            Function pointer to callback to register
 */
void TRUSTEDGE_registerDNSLookupCallback(
    funcPtrDNSLookupCallback cb
);

/**
 * @brief Register a callback for handling action handlers.
 *
 * @param cb            Function pointer to callback to register
 */
void TRUSTEDGE_registerUpdateActionHandlerCallback(
    funcPtrActionHandlerCallback cb
);

/**
 * @brief Install (if needed), bootstrap and run the TrustEdge agent.
 *
 * @details Initializes the library, then based on TRUSTEDGE_getStatus()
 *          downloads and installs the file system and downloads and extracts
 *          "bootstrap.zip" from the current working directory as required.
 *          Unless \p mode is \c PROVISION, the agent is then started in
 *          daemon mode; this call blocks until the agent exits.
 *
 * @param mode      \c PROVISION, \c LAUNCH or \c LAUNCH_AND_EXIT.
 *
 * @return          \c OK (0) if successful, otherwise a negative number error
 *                  code from merrors.h
 */
int TRUSTEDGE_launch(enum TrustedgeMode mode);

/**
 * @brief Extract a bootstrap archive into the TrustEdge configuration.
 *
 * @param pPath     NULL terminated path to the bootstrap zip file; the string
 *                  is not copied or freed.
 *
 * @return          \c OK (0) if successful, otherwise a negative number error
 *                  code from merrors.h
 */
int TRUSTEDGE_extractBootStrap(char *pPath);

/**
 * @brief Extract a TrustEdge file system archive to the root directory.
 *
 * @details Equivalent to TRUSTEDGE_installEx() with destination "/".
 *
 * @param pZipPath  NULL terminated path to the zip file.
 *
 * @return          \c OK (0) if successful, otherwise a negative number error
 *                  code from merrors.h
 */
int TRUSTEDGE_install(char *pZipPath);

/**
 * @brief Extract a TrustEdge file system archive to a destination directory.
 *
 * @param pZipPath  NULL terminated path to the zip file.
 * @param pDst      NULL terminated destination directory.
 *
 * @return          \c OK (0) if successful, \c ERR_NULL_POINTER if either
 *                  argument is NULL, otherwise a negative number error code
 *                  from merrors.h
 */
int TRUSTEDGE_installEx(char *pZipPath, char *pDst);

/**
 * @brief Set the file system mount point used by TrustEdge.
 *
 * @param pNewMountPath     NULL terminating string with path to mount point.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
int TRUSTEDGE_setMountPoint(unsigned char *pNewMountPath);

/**
 * @brief Initialize the underlying TrustEdge/Digicert libraries.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
int TRUSTEDGE_init(void);

/**
 * @brief Free the resources acquired by TRUSTEDGE_init().
 *
 * @return  Always 0.
 */
int TRUSTEDGE_deinit(void);

/**
 * @brief Reset TrustEdge to its pre-provisioned state.
 *
 * @details Clears persisted keystore and agent data via the agent reset
 *          routine.
 *
 * @return  0 if successful, 1 on failure.
 */
int TRUSTEDGE_reset(void);
#ifdef __ENABLE_DIGICERT_CUSTOM_MALLOC__
/**
 * @brief Initialize the libraries using a caller supplied heap.
 *
 * @flags
 * To enable this function, the following flag must be defined:
 * + \c \__ENABLE_DIGICERT_CUSTOM_MALLOC__
 *
 * @param pHeap     Pointer to the memory block to use as heap.
 * @param heapSize  Size of the heap in bytes.
 *
 * @return          \c OK (0) if successful, otherwise a negative number error
 *                  code from merrors.h
 */
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
