/*
 * trustedge_lib_sample_main.c
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

#define LOG_LEVEL CONFIG_LOG_DEFAULT_LEVEL
#include <string.h>

/* DigiCert includes */
#include "../../common/moptions.h"
#include "../../common/mdefs.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mstdlib.h"
#include "../../common/mrtos.h"
#include "../../common/mocana.h"
#include "../../trustedge/utils/trustedge_utils.h"
#include "../../trustedge/trustedge_main.h"
#include "../../trustedge/agent/trustedge_agent_updatepolicy.h"

int runTrustedge(void)
{
    MSTATUS status = ERR_GENERAL;
    RTOS_THREAD trustedgeTid = RTOS_THREAD_INVALID;
    enum TrustedgeStatus trustedgeStatus;
    
    trustedgeStatus = TRUSTEDGE_getStatus();
    if (PREINSTALL == trustedgeStatus)
    {
        printf("%s", "status: PREINSTALL");
    }
    else if(INSTALLED == trustedgeStatus)
    {
        printf("%s", "status: INSTALLED");
    }
    else if(PROVISIONED == trustedgeStatus)
    {
        printf("%s", "status: PROVISIONED");
    }

    status = TRUSTEDGE_launch((enum TrustedgeMode) LAUNCH_AND_EXIT);
    if (OK != status)
    {
        printf("TRUSTEDGE_launch failed: %d\n", status);
    }

    TRUSTEDGE_deinit();
    
    return status;
}

int main(int argc, char *ppArgv[])
{
    MSTATUS status = DIGICERT_initDigicert();
    if (OK != status)
    {
        printf("DIGICERT_initDigicert failed: %d\n", status);
        goto exit;
    }

    if (argc > 1 && 0 == DIGI_STRCMP((const sbyte *) "--reset", (const sbyte *) ppArgv[1]))
    {
        status = (MSTATUS) TRUSTEDGE_reset();       
    }
    else
    {
        status = runTrustedge();
    }
    if (OK != status)
    {
        printf("runTrustedge failed: %d\n", status);
    }

exit:

    (void) DIGICERT_freeDigicert();

    return 0;
}
