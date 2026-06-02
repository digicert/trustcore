/**
 * @file  ipsec_stats.c
 * @brief NanoSec IPsec global statistics implementation.
 *
 * @details    This file contains IPsec global statistics implementation.
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flags must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IPSEC_SERVICE__
 *     +   \c \__NORTEL_SAMPLE_COUNTERS__
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

#include "../common/moptions.h"

#if defined(__ENABLE_DIGICERT_IPSEC_SERVICE__)

#ifdef __NORTEL_SAMPLE_COUNTERS__

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"

#include "../ipsec/ipsec.h"
#include "../ipsec/ipsec_defs.h"
#include "../ipsec/ipsec_stats.h"
#include "../ipsec/sadb.h"


/*------------------------------------------------------------------*/

ipsecStats g_ipsecStats = { 0 };

/* see "common/merrors.h" */
#define ERR_IPSEC_MISMATCH_MIN  ERR_IPSEC_MISMATCH_BUNDLE
#define ERR_IPSEC_MISMATCH_MAX  ERR_IPSEC_MISMATCH_TADDR


/*------------------------------------------------------------------*/

extern void
IPSEC_statsPermitFail(int st, void *sa)
{
    if ((int)ERR_IPSEC_DROP_FINDSA_FAIL == st)
    {
        ++g_ipsecStats.numPacketBadSpi;
    }
    else if ((st >= (int) ERR_IPSEC_MISMATCH_MIN) &&
             (st <= (int) ERR_IPSEC_MISMATCH_MAX))
    {
        /* authenticated/decrypted, but SA/Policy/Flow mismatch*/
    }
    else if (sa && ((SADB)sa)->pCipherSuite)
    {
        ++g_ipsecStats.numPacketNotDecrypted;
    }

    return;
} /* IPSEC_statsPermitFail*/

#endif /* __NORTEL_SAMPLE_COUNTERS__ */
#endif /* defined(__ENABLE_DIGICERT_IPSEC_SERVICE__) */

