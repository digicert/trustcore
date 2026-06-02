/**
 * @file  ipsec_stats.h
 * @brief NanoSec IPsec global statistics header.
 *
 * @details    This file contains IPsec global statistics definitions.
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


#ifndef __IPSEC_STATS_HEADER__
#define __IPSEC_STATS_HEADER__


/*------------------------------------------------------------------*/

/*#include "../ipsec/ipsec_defs.h"*/

#define LOG_IPSEC_PERMIT_SUCCESS(_sp_proto, _len) \
    switch (_sp_proto) \
    { \
    case IPSEC_PROTO_AH : \
    case IPSEC_PROTO_ESP_NULL : \
        g_ipsecStats.bytesAuthenticatedReceived += _len; \
        break; \
    case IPSEC_PROTO_ESP_AUTH : \
        g_ipsecStats.bytesAuthenticatedReceived += _len; \
    case IPSEC_PROTO_ESP : \
        g_ipsecStats.bytesConfidentialReceived += _len; \
        break; \
    } \


#define LOG_IPSEC_APPLY_SUCCESS(_sp_proto, _len) \
    switch (_sp_proto) \
    { \
    case IPSEC_PROTO_AH : \
    case IPSEC_PROTO_ESP_NULL : \
        g_ipsecStats.bytesAuthenticatedSent += _len; \
        break; \
    case IPSEC_PROTO_ESP_AUTH : \
        g_ipsecStats.bytesAuthenticatedSent += _len; \
    case IPSEC_PROTO_ESP : \
        g_ipsecStats.bytesConfidentialSent += _len; \
        break; \
    } \


#define LOG_SADB_DELETE(_proto, _spi, _sa) \
    ++g_ipsecStats.numKeyDeletion;


#define LOG_IPSEC_PERMIT_FAIL(_st, _proto, _spi, _sa) \
    IPSEC_statsPermitFail(_st, _sa);


#define LOG_SADB_REKEY(_proto, _spi, _sa) \
    ++g_ipsecStats.numRekey;


/*------------------------------------------------------------------*/

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ipsecStats
{
    unsigned bytesAuthenticatedReceived;
    unsigned bytesAuthenticatedSent;
    unsigned bytesConfidentialReceived;
    unsigned bytesConfidentialSent;
    unsigned numKeyDeletion;
    unsigned numPacketBadSpi;
    unsigned numPacketNotDecrypted;
    unsigned numRekey;

} ipsecStats;

MOC_EXTERN ipsecStats g_ipsecStats;

MOC_EXTERN void IPSEC_statsPermitFail(int st, void *sa);

#ifdef __cplusplus
}
#endif

#endif /* __IPSEC_STATS_HEADER__ */

