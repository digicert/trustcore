/*
 * devurandseed.c
 *
 * Function to seed the a PRNG implementation from /dev/urandom
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include "../common/moptions.h"
#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/utils.h"
#include "../common/mocana.h"
#include "../common/random.h"
#include "../crypto/mocsym.h"
#if (defined(__ENABLE_DIGICERT_DEV_URANDOM__))
#if defined(__RTOS_LINUX__) || defined(__RTOS_VXWORKS__) || defined(__OSX_RTOS__)
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#define LINUX_DEV_URANDOM_FILE	"/dev/urandom"
#define RAND_MAX_SEED_LEN_BYTES	64

extern MSTATUS RANDOM_seedFromDevURandom (
  randomContext *pCtx,
  ubyte4 numBytes
  )
{
  MSTATUS status;
  sbyte4 fd = -1;
  ssize_t rlen = -1;
  sbyte4 bytes_read = 0;
  ubyte seedBuffer[RAND_MAX_SEED_LEN_BYTES] = {0};

  status = ERR_RAND_SEED_TOO_LARGE;
  if (RAND_MAX_SEED_LEN_BYTES < numBytes)
    goto exit;

  status = ERR_FILE_OPEN_FAILED;
  fd = open(LINUX_DEV_URANDOM_FILE, O_RDONLY);
  if (0 > fd)
    goto exit;

  status = ERR_FILE_READ_FAILED;
  while (numBytes != bytes_read)
  {
    rlen = read (
      fd, (void *)seedBuffer + bytes_read, (ssize_t)(numBytes - bytes_read));
    if (0 >= rlen)
      goto exit;

    bytes_read += rlen;
  }

  status = CRYPTO_seedRandomContext (
    pCtx, NULL, (ubyte *)seedBuffer, numBytes);

  DIGI_MEMSET((ubyte *)seedBuffer, 0, RAND_MAX_SEED_LEN_BYTES);

exit:

  if (0 <= fd)
    close(fd);

  return status;
}

#endif /* if defined(__RTOS_LINUX__) etc. */
#endif /* if (defined(__ENABLE_DIGICERT_DEV_URANDOM__)) */
