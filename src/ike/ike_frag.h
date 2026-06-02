/**
 * @file  ike_frag.h
 * @brief IKE fragmentation definitions.
 *
 * @details    IKEv1 fragmentation support structures and definitions.
 * @since      5.0
 * @version    6.5.1 and later
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flag must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_IKE_FRAGMENTATION__
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


/*------------------------------------------------------------------*/

/* internal use only */

#ifndef __IKE_FRAG_HEADER__
#define __IKE_FRAG_HEADER__

#if defined(__ENABLE_IKE_FRAGMENTATION__)

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __IKE_UPDATE_TIMER__
MOC_EXTERN void IKE_fragReassemblyTimerExpiry(void *cookie, ubyte *type);
#endif
MOC_EXTERN MSTATUS IKE_fragCreate(IKESA pxSa, ubyte fragNum, ubyte2 *pFragId,
                                  struct ikeHdr *pHdr, ubyte *pFragData,
                                  intBoolean lastFrag, ubyte4 fragSize,
                                  ubyte **pPkt);
MOC_EXTERN MSTATUS IKE_fragRecv(IKE_context ctx, ubyte *pIsReassembled);
MOC_EXTERN MSTATUS IKE_flushFragReassemble(IKESA pxSa);
MOC_EXTERN MSTATUS IKE_fragCheckFragment(ubyte *pBuffer, ubyte *pIsFragment);

#ifdef __cplusplus
}
#endif

#endif /* __ENABLE_IKE_FRAGMENTATION__ */

#endif /* __IKE_FRAG_HEADER__ */

