/*
 * trustedge_agent_policy_data_types.h
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

typedef enum
{
   TE_ARTIFACT_SIG_FORMAT_UNKNOWN = -1,
   TE_ARTIFACT_SIG_FORMAT_PEM,
} TrustEdgeAgentSignatureFormat;

typedef enum 
{
   TE_ARTIFACT_TYPE_UNKNOWN = -1,
   TE_ARTIFACT_CONFIG,
   TE_ARTIFACT_APP,
   TE_ARTIFACT_OS,
   TE_ARTIFACT_FW
} TrustEdgeAgentArtifactType;

typedef enum 
{
   TE_ACTION_UNKNOWN = -1,
   TE_ACTION_PREINSTALL,
   TE_ACTION_INSTALL,
   TE_ACTION_POSTINSTALL,
   TE_ACTION_ROLLBACK      /* Add any new action type after this */
} TrustEdgeAgentActionType;

typedef enum
{
   TE_ACTION_HANDLER_UNKNOWN = -1, 
   TE_ACTION_HANDLER_SCRIPT,
   TE_ACTION_HANDLER_EXE,
   TE_ACTION_HANDLER_PKG_MGR_TYPE
} TrustEdgeAgentActionHandlerType;

typedef enum
{
   TE_ACTION_HANDLER_SUBTYPE_UNKNOWN = -1,
   TE_ACTION_HANDLER_SUBTYPE_PYTHON3,
   TE_ACTION_HANDLER_SUBTYPE_BASH,
   TE_ACTION_HANDLER_SUBTYPE_NODEJS,
   TE_ACTION_HANDLER_SUBTYPE_TEXT,
   TE_ACTION_HANDLER_SUBTYPE_RPM,
   TE_ACTION_HANDLER_SUBTYPE_DPKG
} TrustEdgeAgentActionHandlerSubType;

typedef struct
{
   JWSAlg signatureAlgorithm;
   TrustEdgeAgentSignatureFormat signatureFormat;
   ubyte *pSignature;
   ubyte4 signatureLength;
   ubyte *pCertificate;
   ubyte4 certificateLength; 
} TrustEdgeArtifactSignature;

typedef struct {
   TrustEdgeAgentActionHandlerType type;
   TrustEdgeAgentActionHandlerSubType subtype;
} TrustEdgeAgentActionHandler;

typedef struct TrustEdgeArtifactAction {
   TrustEdgeAgentActionType type;
   TrustEdgeAgentActionHandler handler;
   sbyte *pActionPath;
   sbyte *pActionArgument;
   sbyte **ppActionArgs;
} TrustEdgeArtifactAction;

typedef int (*funcPtrActionHandlerCallback)(struct TrustEdgeArtifactAction *pAction, char *pFile);
typedef int (*funcPtrDNSLookupCallback)(char*, char*);

#ifdef __cplusplus
}
#endif

#endif /* __TRUSTEDGE_POLICY_DATA_TYPES_HEADER__ */
