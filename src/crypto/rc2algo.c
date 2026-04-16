/*
 * rc2algo.c
 *
 * RC2 Algorithm
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
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#if (defined(__ENABLE_ARC2_CIPHERS__) && !defined(__ARC2_HARDWARE_CIPHER__))

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../crypto/rc2algo.h"
#include "../crypto/arc2.h"

/*------------------------------------------------------------------*/

extern BulkCtx
CreateRC2Ctx2(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial, sbyte4 keyLength, sbyte4 effectiveBits)
{
    ubyte2* xkey = (ubyte2*) MALLOC(64 * sizeof(ubyte2));

    if (xkey)
    {
        rc2_keyschedule( xkey, keyMaterial, (ubyte4) keyLength, effectiveBits);
    }

    return xkey;
}

/*------------------------------------------------------------------*/

extern BulkCtx
CreateRC2Ctx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    MOC_UNUSED(encrypt);
    return CreateRC2Ctx2( MOC_SYM( hwAccelCtx) keyMaterial, keyLength, keyLength * 8);
}

/*------------------------------------------------------------------*/

extern MSTATUS
DeleteRC2Ctx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ctx)
{
    if (*ctx)
    {
        FREE(*ctx);
        *ctx = NULL;
    }

    return OK;
}

/*------------------------------------------------------------------*/

extern MSTATUS
DoRC2(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data, sbyte4 dataLength,
              sbyte4 encrypt, ubyte* iv)
{
    MSTATUS status = OK;

    if (ctx)
    {
        ubyte2 *xkey = (ubyte2*) ctx;

        if (dataLength % RC2_BLOCK_SIZE)
        {
            status = ERR_RC2_BAD_LENGTH;
            goto exit;
        }

        if (encrypt)
        {
            while (dataLength > 0)
            {
                /* XOR block with iv */
                sbyte4 i;

                for (i = 0; i < RC2_BLOCK_SIZE; ++i)
                {
                    data[i] ^= iv[i];
                }

                /* encrypt */
                rc2_encrypt( xkey, data, data);

                /* save into iv */
                DIGI_MEMCPY(iv, data, RC2_BLOCK_SIZE);

                /* advance */
                dataLength -= RC2_BLOCK_SIZE;
                data += RC2_BLOCK_SIZE;
            }
        }
        else
        {
            while ( dataLength > 0)
            {
                sbyte4 i;
                ubyte nextIV[ RC2_BLOCK_SIZE];

                /* save block in next IV */
                DIGI_MEMCPY( nextIV, data, RC2_BLOCK_SIZE);

                /* decrypt */
                rc2_decrypt(xkey, data, data);

                /* XOR with iv */
                for (i = 0; i < RC2_BLOCK_SIZE; ++i)
                {
                    data[i] ^= iv[i];
                }

                /* put nextIV into iv */
                DIGI_MEMCPY(iv, nextIV, RC2_BLOCK_SIZE);

                /* advance */
                dataLength -= RC2_BLOCK_SIZE;
                data += RC2_BLOCK_SIZE;
            }
        }
    }

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
CloneRC2Ctx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, BulkCtx *ppNewCtx)
{
    MSTATUS status;
    BulkCtx pNewCtx = NULL;

    if ( (NULL == pCtx) || (NULL == ppNewCtx) )
    {
        return ERR_NULL_POINTER;
    }

    status = DIGI_MALLOC((void **)&pNewCtx, 64 * sizeof(ubyte2));
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((void *)pNewCtx, (void *)pCtx, 64 * sizeof(ubyte2));
    if (OK != status)
        goto exit;

    *ppNewCtx = pNewCtx;
    pNewCtx = NULL;

exit:
    if (NULL != pNewCtx)
    {
        DIGI_FREE((void **)&pNewCtx);
    }

    return status;
}

#endif
