/*
 * linux_signal.c
 *
 * Linux Signal Handling Abstraction Layer
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

#if defined(__ENABLE_DIGICERT_RTOS_SIGNAL__) && defined(__RTOS_LINUX__)

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/msignal.h"

#include <signal.h>
#include <string.h>

/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_registerHandler(int sig, funcPtrSignalHandlerCallback handler)
{
  MSTATUS status = OK;
  struct sigaction sa;

  if (NULL == handler)
  {
    status = ERR_NULL_POINTER;
    goto exit;
  }

  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;

  /* Register the signal handler */
  if (sigaction(sig, &sa, NULL) == -1)
  {
    status = ERR_RTOS;
  }

exit:
  return status;
}

#endif /* __LINUX_SIGNAL__ */
