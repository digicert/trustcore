/*
 * trustedge_cloud_service_azure.h
 *
 * TrustEdge Cloud Service Azure header
 *
 * Copyright Digicert Inc 2022. All Rights Reserved.
 * Proprietary and Confidential Material.
 *
 */

#ifndef __TRUSTEDGECLOUDSERVICEAZURE_HEADER__
#define __TRUSTEDGECLOUDSERVICEAZURE_HEADER__

#include "../../trustedge/agent/trustedge_agent_priv.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CLOUD_SERVICES_DIR                      "cloud_services"

#define CLOUD_SERVICE_JSTR                      "cloud_service"
#define SERVICE_TYPE_JSTR                       "service_type"
#define SERVICE_ATTRS_JSTR                      "service_attrs"
#define SERVICE_ATTRS_URI_JSTR                  "uri"
#define SERVICE_ATTRS_PORT_JSTR                 "port"
#define SERVICE_ATTRS_RETRY_MAX_COUNT_JSTR      "retry_max_count"
#define SERVICE_ATTRS_RETRY_DELAY_SECONDS_JSTR  "retry_delay_seconds"
#define SERVICE_ATTRS_MODE                      "mode"
#define SERVICE_ATTRS_REGISTRATION_ID           "registration_id"
#define SERVICE_ATTRS_SIG_EXPIRY_TIME           "signature_expiry_time"

#define AZURE_DPS_JSTR              "azure_dps"
#define AZURE_ID_SCOPE_JSTR         "id_scope"

#define AZURE_REG_MODE_X509         "X509"
#define AZURE_REG_MODE_TPM          "TPM"

/* TRUSTEDGE_cloudServiceAzureRegister : Register with Azure cloud service using
 *   provided JSON parameters
 *
 *   Parameters :
 *     TrustEdgeAgentCtx *pCtx :: Cloud service context
 *     ubyte *pJson :: JSON with Azure parameters
 *     ubyte4 jsonLen :: Length of JSON
 *     ubyte4 *pHttpStatusCode :: HTTP status code from Azure cloud service
 *     ubyte **ppServerRsp :: Server response from Azure cloud service
 *     ubyte4 *pServerRspLen :: Length of server response
 *     ubyte **ppProviderCredJson :: Provider credential JSON from Azure cloud service
 *     ubyte4 *pProviderCredJsonLen :: Length of provider credential JSON
 */
MOC_EXTERN MSTATUS TRUSTEDGE_cloudServiceAzureRegister(
    TrustEdgeAgentCtx *pCtx,
    ubyte *pJson,
    ubyte4 jsonLen,
    ubyte4 *pHttpStatusCode,
    ubyte **ppServerRsp,
    ubyte4 *pServerRspLen,
    ubyte **ppProviderCredJson,
    ubyte4 *pProviderCredJsonLen);

#ifdef __cplusplus
}
#endif

#endif /* __TRUSTEDGECLOUDSERVICEAZURE_HEADER__ */
