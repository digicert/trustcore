/**
 * @file trustedge_agent_policy_data_types.h
 * @brief TrustEdge agent policy data types.
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

#ifndef __TRUSTEDGE_POLICY_DATA_TYPES_HEADER__
#define __TRUSTEDGE_POLICY_DATA_TYPES_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief JSON Web Signature algorithms used to sign update artifacts.
 */
typedef enum
{
    JWS_ALG_NONE,
    JWS_ALG_RS256,
    JWS_ALG_RS384,
    JWS_ALG_RS512,
    JWS_ALG_ES256,
    JWS_ALG_ES384,
    JWS_ALG_ES512,
    JWS_ALG_PS256,
    JWS_ALG_PS384,
    JWS_ALG_PS512,
    JWS_ALG_MLDSA44,
    JWS_ALG_MLDSA65,
    JWS_ALG_MLDSA87,
    JWS_ALG_SLHDSA_SHA2_128F,
    JWS_ALG_SLHDSA_SHA2_128S,
    JWS_ALG_SLHDSA_SHA2_192F,
    JWS_ALG_SLHDSA_SHA2_192S,
    JWS_ALG_SLHDSA_SHA2_256F,
    JWS_ALG_SLHDSA_SHA2_256S,
    JWS_ALG_SLHDSA_SHAKE_128F,
    JWS_ALG_SLHDSA_SHAKE_128S,
    JWS_ALG_SLHDSA_SHAKE_192F,
    JWS_ALG_SLHDSA_SHAKE_192S,
    JWS_ALG_SLHDSA_SHAKE_256F,
    JWS_ALG_SLHDSA_SHAKE_256S
} JWSAlg;

/**
 * @brief Encoding of an artifact signature.
 */
typedef enum
{
   TE_ARTIFACT_SIG_FORMAT_UNKNOWN = -1, /**< Unrecognized format. */
   TE_ARTIFACT_SIG_FORMAT_PEM,          /**< PEM encoded. */
} TrustEdgeAgentSignatureFormat;

/**
 * @brief Kind of update artifact.
 */
typedef enum 
{
   TE_ARTIFACT_TYPE_UNKNOWN = -1, /**< Unrecognized type. */
   TE_ARTIFACT_CONFIG,            /**< Configuration. */
   TE_ARTIFACT_APP,               /**< Application. */
   TE_ARTIFACT_OS,                /**< Operating system. */
   TE_ARTIFACT_FW                 /**< Firmware. */
} TrustEdgeAgentArtifactType;

/**
 * @brief Stage of artifact deployment an action applies to.
 */
typedef enum 
{
   TE_ACTION_UNKNOWN = -1,
   TE_ACTION_PREINSTALL,   /**< Run before installation. */
   TE_ACTION_INSTALL,      /**< Install the artifact. */
   TE_ACTION_POSTINSTALL,  /**< Run after installation. */
   TE_ACTION_ROLLBACK      /**< Roll back the artifact. Add any new action type after this. */
} TrustEdgeAgentActionType;

/**
 * @brief Kind of program that executes an action.
 */
typedef enum
{
   TE_ACTION_HANDLER_UNKNOWN = -1, 
   TE_ACTION_HANDLER_SCRIPT,       /**< Script run by an interpreter. */
   TE_ACTION_HANDLER_EXE,          /**< Executable. */
   TE_ACTION_HANDLER_PKG_MGR_TYPE  /**< Package manager package. */
} TrustEdgeAgentActionHandlerType;

/**
 * @brief Interpreter or package format of an action handler.
 */
typedef enum
{
   TE_ACTION_HANDLER_SUBTYPE_UNKNOWN = -1,
   TE_ACTION_HANDLER_SUBTYPE_PYTHON3,
   TE_ACTION_HANDLER_SUBTYPE_BASH,
   TE_ACTION_HANDLER_SUBTYPE_NODEJS,
   TE_ACTION_HANDLER_SUBTYPE_TEXT,
   TE_ACTION_HANDLER_SUBTYPE_RPM,
   TE_ACTION_HANDLER_SUBTYPE_DPKG,
   TE_ACTION_HANDLER_SUBTYPE_BATCH
} TrustEdgeAgentActionHandlerSubType;

/**
 * @brief Signature and signing certificate of an artifact.
 */
typedef struct
{
   JWSAlg signatureAlgorithm;                /**< Signature algorithm. */
   TrustEdgeAgentSignatureFormat signatureFormat; /**< Signature encoding. */
   ubyte *pSignature;                        /**< Signature bytes. */
   ubyte4 signatureLength;                   /**< Length of \c pSignature. */
   ubyte *pCertificate;                      /**< Signing certificate. */
   ubyte4 certificateLength;                 /**< Length of \c pCertificate. */
} TrustEdgeArtifactSignature;

/**
 * @brief Program used to execute an artifact action.
 */
typedef struct {
   TrustEdgeAgentActionHandlerType type;       /**< Handler kind. */
   TrustEdgeAgentActionHandlerSubType subtype; /**< Interpreter or package format. */
} TrustEdgeAgentActionHandler;

/**
 * @brief An action to perform when deploying an artifact.
 */
typedef struct TrustEdgeArtifactAction {
   TrustEdgeAgentActionType type;       /**< Deployment stage. */
   TrustEdgeAgentActionHandler handler; /**< Program that executes the action. */
   sbyte *pActionPath;                  /**< Path of the script/executable/package. */
   sbyte *pActionArgument;              /**< Argument string from the manifest. */
   sbyte **ppActionArgs;                /**< Argument vector for the handler. */
} TrustEdgeArtifactAction;

/**
 * @brief Application callback that executes an artifact action instead of the
 *        built-in action handler.
 *
 * @param pAction   Action to execute.
 * @param pFile     Path of the artifact directory.
 *
 * @return          \c OK (0) if successful, otherwise a negative number error
 *                  code from merrors.h
 */
typedef int (*funcPtrActionHandlerCallback)(struct TrustEdgeArtifactAction *pAction, char *pFile);

/**
 * @brief Application callback that resolves a host name.
 *
 * @details The first argument is the NULL terminated host name; the second is
 *          the buffer that receives the IP address string. Return 0 on
 *          success; return -1 to fall back to the system resolver.
 */
typedef int (*funcPtrDNSLookupCallback)(char*, char*);

#ifdef __cplusplus
}
#endif

#endif /* __TRUSTEDGE_POLICY_DATA_TYPES_HEADER__ */
