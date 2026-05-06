/**
 * @file   win32_term.c
 * @brief  Windows Terminal Functions
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

#if defined(__ENABLE_DIGICERT_RTOS_TERM__) && defined(__RTOS_WIN32__)

#include "../common/mterm.h"

#include <windows.h>
#include <conio.h>
#include <stdio.h>

/*------------------------------------------------------------------*/

extern sbyte4
WIN32_promptPassword(sbyte *pPassword, ubyte4 passwdLength, int mask)
{
  ubyte4 idx = 0;
  int c = 0;

  if (!pPassword || !passwdLength)
  {
    return -1;
  }

  /* Read characters using _getch (no echo) */
  while (idx < passwdLength - 1)
  {
    c = _getch();

    /* Enter key */
    if (c == '\r' || c == '\n')
    {
      break;
    }

    /* Backspace */
    if (c == '\b' || c == 127)
    {
      if (idx > 0)
      {
        if (31 < mask && mask < 127)
        {
          /* Erase character on screen */
          printf("\b \b");
        }
        pPassword[--idx] = 0;
      }
      continue;
    }

    /* Ignore special keys (extended key codes start with 0 or 0xE0) */
    if (c == 0 || c == 0xE0)
    {
      _getch(); /* Consume the second byte */
      continue;
    }

    /* Store character */
    if (31 < mask && mask < 127)
    {
      putchar(mask);
    }
    pPassword[idx++] = (sbyte)c;
  }
  pPassword[idx] = 0;

  return idx;
}

#endif /* __WIN32_TERM__ */
