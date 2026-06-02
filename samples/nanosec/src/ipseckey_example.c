/*
 * ipseckey_example.c
 *
 * Example code for integrating IKE server with IPsec stack
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
 */

#include "../common/moptions.h"

#if defined(__ENABLE_DIGICERT_EXAMPLES__) || defined(__ENABLE_DIGICERT_BIN_EXAMPLES__)
#if defined(__ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__)

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../ipsec/ipsec.h"
#include "../ipsec/ipsec_defs.h"
#include "../ipsec/ipsecconf.h"
#include "../ipsec/ipseckey.h"
#include "../ike/ike.h"
#include "../ike/ike_defs.h"
#include "../ike/ikekey.h"
#include "../pfkey/pfkey.h"
#include "../ike/ike_event.h"
#include "../ike/ike_utils.h"


/*------------------------------------------------------------------*/

#if defined(__THREADX_RTOS__)

extern sbyte4
IPSECKEY_EXAMPLE_main(void)
{
    return 0;
}


/* Exclude platform-specific interface implementations. */
#elif \
    !defined(__LINUX_RTOS__)    && \
    !defined(__ANDROID_RTOS__)    && \
    !defined(__INTEGRITY_RTOS__)&& \
    !defined(__OSE_RTOS__)      && \
    !defined(__QNX_RTOS__)      && \
    !defined(__VXWORKS_RTOS__)  && \
    !defined(__WIN32_RTOS__)    && \
    !defined(__WINCE_RTOS__)    && \
    !defined(__ENABLE_DIGICERT_PFKEY__)


#include <string.h>
#include <stdlib.h>
#include <stdio.h>


/*------------------------------------------------------------------*/

extern sbyte4
IPSECKEY_EXAMPLE_main(void)
{
    return 0;
}


/*------------------------------------------------------------------*/

extern sbyte4
IPSEC_keyAddEx(IPSECKEY_EX pxKey)
{
    MSTATUS status = OK;

    printf("%s:%s: Not implemented yet.\n", __FILE__, __FUNCTION__);

    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

extern sbyte4
IPSEC_keyDelete(IPSECKEY pxKey)
{
    MSTATUS status = OK;

    printf("%s:%s: Not implemented yet.\n", __FILE__, __FUNCTION__);

    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

extern sbyte4
IPSEC_keyReady(IPSECKEY_EX pxKey)
{
    MSTATUS status = OK;

    printf("%s:%s: Not implemented yet.\n", __FILE__, __FUNCTION__);

    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

extern sbyte4
IPSEC_confAdd1(IPSECCONF pxConf)
{
    MSTATUS status = OK;

    printf("%s:%s: Not implemented yet.\n", __FILE__, __FUNCTION__);

    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

extern sbyte4
IPSEC_confFlush(void)
{
    MSTATUS status = OK;

    printf("%s:%s: Not implemented yet.\n", __FILE__, __FUNCTION__);

    return (sbyte4)status;
}

#endif
#endif /* (defined(__ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__) && defined(__ENABLE_DIGICERT_EXAMPLES__)) */
#endif

