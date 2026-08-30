/*
 * fx_api.h  —  stub for builds without Azure RTOS FileX
 *
 * mrtos.h includes this header when __AZURE_RTOS__ is defined (which
 * moptions.h sets whenever __RTOS_AZURE__ is defined).  This project uses
 * ThreadX + NetX Duo but NOT FileX.  clm_vfs.c provides all file I/O, so
 * no real FileX functions are ever called; we only need the three seek-origin
 * constants that mrtos.h maps to MSEEK_*.
 */

#ifndef FX_API_H
#define FX_API_H

/* Seek origins — values match the real FileX fx_api.h */
#define FX_SEEK_BEGIN    0
#define FX_SEEK_FORWARD  1
#define FX_SEEK_END      2

#endif /* FX_API_H */
