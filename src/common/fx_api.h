/*
 * fx_api.h  —  stub for builds without Azure RTOS FileX
 *
 * mrtos.h includes this header when __AZURE_RTOS__ is defined (which
 * moptions.h sets whenever __RTOS_AZURE__ is defined).  This project uses
 * ThreadX + NetX Duo but NOT FileX.  clm_vfs.c provides all file I/O, so
 * no real FileX functions are ever called; we only need the three seek-origin
 * constants that mrtos.h maps to MSEEK_*.
 *
 * This file lives in src/common/ next to mrtos.h, so a quoted #include
 * "fx_api.h" always resolves here first. Builds that really enable FileX
 * (__ENABLE_DIGICERT_RTOS_FILEX__) must not get this incomplete stub, so we
 * fall through to the vendor SDK's real fx_api.h via #include_next instead.
 */

#ifndef FX_API_H
#define FX_API_H

#if defined(__ENABLE_DIGICERT_RTOS_FILEX__)
#include_next "fx_api.h"
#else

/* Seek origins — values match the real FileX fx_api.h */
#define FX_SEEK_BEGIN    0
#define FX_SEEK_FORWARD  1
#define FX_SEEK_END      2

#endif /* __ENABLE_DIGICERT_RTOS_FILEX__ */

#endif /* FX_API_H */
