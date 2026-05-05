/**
 * @file   linux_term.c
 * @brief  Linux/OSX Terminal Functions
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

#if defined(__ENABLE_DIGICERT_RTOS_TERM__) && defined(__RTOS_LINUX__)

#include "../common/mterm.h"

#include <stdio.h>
#include <termios.h>
#include <string.h>

/*------------------------------------------------------------------*/

extern sbyte4
LINUX_promptPassword(sbyte *pPassword, ubyte4 passwdLength, int mask)
{
  FILE *stdinFp = stdin;
  ubyte4 idx = 0;
  sbyte4 c = 0;
  struct termios oldKbdMode;
  struct termios newKbdMode;

  if (!pPassword || !passwdLength || !stdinFp)
  {
    return -1;
  }

  /* Save original terminal settings */
  if (tcgetattr(0, &oldKbdMode))
  {
    return -1;
  }

  /* Copy old settings to new */
  memcpy(&newKbdMode, &oldKbdMode, sizeof(struct termios));

  /* Disable canonical mode and echo */
  newKbdMode.c_lflag &= ~(ICANON | ECHO);
  newKbdMode.c_cc[VTIME] = 0;
  newKbdMode.c_cc[VMIN] = 1;

  if (tcsetattr(0, TCSANOW, &newKbdMode))
  {
    return -1;
  }

  /* Read characters from stdin, mask if valid char specified */
  while (((c = fgetc(stdinFp)) != '\n' && c != EOF && idx < passwdLength - 1) ||
         (idx == passwdLength - 1 && c == 127))
  {
    if (c != 127)
    {
      if (31 < mask && mask < 127)
      {
        /* Valid ASCII char - display mask */
        fputc(mask, stdout);
      }
      pPassword[idx++] = c;
    }
    else if (idx > 0)
    {
      /* Handle backspace (del) */
      if (31 < mask && mask < 127)
      {
        fputc(0x8, stdout);
        fputc(' ', stdout);
        fputc(0x8, stdout);
      }
      pPassword[--idx] = 0;
    }
  }
  pPassword[idx] = 0;

  /* Reset original terminal settings */
  if (tcsetattr(0, TCSANOW, &oldKbdMode))
  {
    return -1;
  }

  return idx;
}

#endif /* __LINUX_TERM__ */
