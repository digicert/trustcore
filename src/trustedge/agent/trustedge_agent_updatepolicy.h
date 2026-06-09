/*
 * trustedge_agent_updatepolicy.h
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

/* trustedge_agent_updatepolicy.h
 * Structures related to Manifest 
 * and artifacts coming from the update policy
 */

#ifndef __TRUSTEDGE_AGENT_UPDATEPOLICY_HEADER__
#define __TRUSTEDGE_AGENT_UPDATEPOLICY_HEADER__

#include <stdio.h>
#include "../../common/moptions.h"
#include "../../common/msg_logger.h"
#include "../../common/mocana.h"
#include "../../common/mjson.h"
#include "../../common/mfmgmt.h"
#include "../../mqtt/mqtt_client.h"
#include "trustedge_agent_priv.h"


typedef struct TrustEdgeAgentArtifactComponent {
   sbyte *pName;
   sbyte *pLocation;
   sbyte *pCheckSum;
   sbyte4 checkSumLen;
   struct TrustEdgeAgentArtifactComponent *pNext;
} TrustEdgeAgentArtifactComponent;

typedef struct {
   sbyte *pKey;
   sbyte *pValue;
} TrustEdgeAgentDeviceAttributes;

typedef struct {
   TrustEdgeAgentDeviceAttributes deviceAttributes;
   ubyte4 deviceAttributeCount;
} TrustEdgeAgentArtifactRequirements;

typedef struct
{
   sbyte *pName;
   sbyte *pId;
} TrustEdgeAgentDependsOnArtifact;

typedef struct {
   TrustEdgeAgentDependsOnArtifact *pArtifact;
   ubyte4 count;
} TrustEdgeAgentDependsOn;

#define ACTION_COUNT 4
typedef struct TrustEdgeArtifactManifest
{
   sbyte *pVersion;
   sbyte *pName;
   sbyte *pDescription;
   /* The manifest json also contains artifactVersion, description etc.
    * need to check if we need them here */
   TrustEdgeAgentArtifactType artifactType;
   TrustEdgeArtifactAction *pActions[ACTION_COUNT];    /* Update this if we decide to have any more action types */
   ubyte4 actionsCount;
   TrustEdgeAgentArtifactComponent *pComponents;
   TrustEdgeAgentArtifactRequirements requirements;
   TrustEdgeArtifactSignature signature;
   TrustEdgeAgentDependsOn dependsOn;
} TrustEdgeArtifactManifest;

#define JSON_STR_TYPE            "artifactType"
#define JSON_STR_NAME            "name"
#define JSON_STR_DESCRIPTION     "description"
#define JSON_STR_VERSION         "artifactVersion"
#define JSON_STR_ACTIONS         "actions"
#define JSON_STR_ACTION          "action"
#define JSON_STR_ACTIONPATH      "actionPath"
#define JSON_STR_ACTIONARG       "actionArgument"  
#define JSON_STR_HANDLER         "handler"
#define JSON_STR_HANDLERTYPE     "handlerType"
#define JSON_STR_HANDLERSUBTYPE  "handlerSubType"

#define JSON_STR_DEPENDSON       "dependsOn"
#define JSON_STR_ID              "id"

#define JSON_STR_COMPONENT       "components"
#define JSON_STR_LOCATION        "location"
#define JSON_STR_CHECKSUM        "checksum"

#define JSON_STR_PREINSTALL      "preinstall"
#define JSON_STR_PREINSTALL_ALT  "pre_install"
#define JSON_STR_INSTALL         "install"
#define JSON_STR_POSTINSTALL     "postinstall"
#define JSON_STR_POSTINSTALL_ALT "post_install"
#define JSON_STR_ROLLBACK        "rollback"
#define JSON_STR_ROLLBACK_ALT    "roll_back"

#define JSON_STR_HTYPE_SCRIPT    "Script"
#define JSON_STR_HTYPE_EXE       "Exe"
#define JSON_STR_HTYPE_PKGMGR    "pkgmngr"

#define JSON_STR_UNKNOWN         "unknown"
#define JSON_STR_UNDEFINED       "undefined"
#define JSON_STR_PYTHON3         "python3"
#define JSON_STR_BASH            "bash"
#define JSON_STR_NODEJS          "nodejs"
#define JSON_STR_TEXT            "text"
#define JSON_STR_RPM             "rpm"
#define JSON_STR_DPKG            "dpkg"
#define JSON_STR_CMD             "cmd"

#define JSON_STR_SIGNATURE       "signature"
#define JSON_STR_SIGALG          "sigAlg"
#define JSON_STR_SIG             "sig"
#define JSON_STR_SIGFORMAT       "sigFormat"
#define JSON_STR_SIGCERT         "certificate"

#define TE_ACTION_COMMAND_BASH      "bash"
#define TE_ACTION_COMMAND_PYTHON3   "python3"
#define TE_ACTION_COMMAND_RPM       "rpm"
#define TE_ACTION_COMMAND_DPKG      "dpkg"
#define TE_ACTION_COMMAND_NODEJS    "node"

MOC_EXTERN MSTATUS TRUSTEDGE_agentParseArtifactDownload(TrustEdgeAgentCtx *pCtx, ubyte *pMimeFile, ubyte4 mimeFileLen, TrustEdgeAgentActionType action);

MOC_EXTERN MSTATUS TRUSTEDGE_agentParseArtifactDownloadChunk(TrustEdgeAgentCtx *pCtx, ubyte *pMimeFile, ubyte4 mimeFileLen, TrustEdgeAgentActionType action);

MOC_EXTERN sbyte *TRUSTEDGE_actionTypeToString(
   TrustEdgeAgentActionType type);

MOC_EXTERN sbyte *TRUSTEDGE_actionHandlerSubTypeToString(
   TrustEdgeAgentActionHandlerSubType subtype);

MOC_EXTERN sbyte *TRUSTEDGE_actionHandlerTypeToString(
   TrustEdgeAgentActionHandlerType type);

MOC_EXTERN MSTATUS TRUSTEDGE_agentComputeTotalWindowSize(TrustEdgeAgentArtifactNode *pArtifact, ubyte4 *pTotalWindowSize);

#endif /* __TRUSTEDGE_AGENT_UPDATEPOLICY_HEADER__ */
