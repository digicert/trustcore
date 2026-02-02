/*
 * poly1305.h
 *
 * Implementation of the POLY1305 MAC
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 * Adapted from the public domain implementation in
 *  <https://github.com/floodyberry/poly1305-donna>
 */

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_POLY1305_INTERNAL__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#ifndef __POLY1305_HARDWARE_ACCELERATOR__

/*
 * needed for size_t definition
 */
#if defined( __RTOS_VXWORKS__ )
#include <vxWorks.h>
#endif

#if defined(__RTOS_QNX__)
#include <stdlib.h>
#endif
#if defined(__ENABLE_DIGICERT_POLY1305__)
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"

#include "../crypto/poly1305.h"

#define POLY1305_BLOCK_SIZE 16

/* auto detect between 32bit / 64bit for GCC or MS Visual Studio  */
#if (defined(__SIZEOF_INT128__) && defined(__LP64__))
#define HAS_SIZEOF_INT128_64BIT 1
#else
#define HAS_SIZEOF_INT128_64BIT 0
#endif

#if (defined(_MSC_VER) && defined(_M_X64))
#define HAS_MSVC_64BIT 1
#else
#define HAS_MSVC_64BIT 0
#endif

#if (defined(__GNUC__) && defined(__LP64__) && ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC_MINOR__ >= 4))))
#define HAS_GCC_4_4_64BIT 1
#else
#define HAS_GCC_4_4_64BIT 0
#endif

#if (HAS_SIZEOF_INT128_64BIT || HAS_MSVC_64BIT || HAS_GCC_4_4_64BIT)
#include "poly1305-64.h"
#else
/* should be portable for all other platforms */
#include "poly1305-32.h"
#endif

/*----------------------------------------------------------------------------*/

extern MSTATUS
Poly1305Update(MOC_HASH(hwAccelDescr hwAccelCtx) Poly1305Ctx *ctx, const ubyte *m, ubyte4 bytes)
{
	MSTATUS status;
	ubyte4 i;
	poly1305_state_internal_t *st = (poly1305_state_internal_t *)ctx;

	status = ERR_CRYPTO_CTX_STATE;
	if ( (MOC_POLY1305_STATE_INIT != ctx->state) &&
		 (MOC_POLY1305_STATE_UPDATE != ctx->state) )
		goto exit;

	status = OK;

	/* handle leftover */
	if (st->leftover)
    {
		ubyte4 want = (ubyte4) (POLY1305_BLOCK_SIZE - st->leftover);
		if (want > bytes)
        {
			want = bytes;
        }
        for (i = 0; i < want; i++)
        {
            st->buffer[st->leftover + i] = m[i];
        }
        bytes -= want;
		m += want;
		st->leftover += want;
		if (st->leftover < POLY1305_BLOCK_SIZE)
        {
			return OK;
        }
        poly1305_blocks(st, st->buffer, POLY1305_BLOCK_SIZE);
		st->leftover = 0;
	}

	/* process full blocks */
	if (bytes >= POLY1305_BLOCK_SIZE)
    {
		ubyte4 want = (bytes & ~(POLY1305_BLOCK_SIZE - 1));
		poly1305_blocks(st, m, want);
		m += want;
		bytes -= want;
	}

	/* store leftover */
	if (bytes)
    {
		for (i = 0; i < bytes; i++)
        {
            st->buffer[st->leftover + i] = m[i];
        }
        st->leftover += bytes;
	}

	ctx->state = MOC_POLY1305_STATE_UPDATE;

exit:

    return status;
}


/*----------------------------------------------------------------------------*/

MSTATUS
Poly1305_completeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) ubyte mac[16], const ubyte *m, ubyte4 bytes,
                        const ubyte key[32])
{
	MSTATUS status;
	Poly1305Ctx ctx;

	status = Poly1305Init(MOC_HASH(hwAccelCtx) &ctx, key);
	if (OK != status)
	  goto exit;

	status = Poly1305Update(MOC_HASH(hwAccelCtx) &ctx, m, bytes);
	if (OK != status)
	  goto exit;

	status = Poly1305Final(MOC_HASH(hwAccelCtx) &ctx, mac);

exit:

    return status;
}

#endif /* __POLY1305_HARDWARE_ACCELERATOR__ */
#endif /* defined(__ENABLE_DIGICERT_POLY1305__)  */
