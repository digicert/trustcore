/*
 * mstdlib.h
 *
 * Mocana Standard Library
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


/*------------------------------------------------------------------*/

#ifndef __MSTDLIB_HEADER__
#define __MSTDLIB_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __ENABLE_MOCANA_MEM_PROFILE_LEAK_CHECK__

#define MEM_PROFILE_ADD_SUFFIX( X) X ## _TRACK
#define MEM_PROFILE_TRACK_DECL ,ubyte *pFunc ,sbyte4 line
#define MEM_PROFILE_TRACK_VARS ,pFunc, line
#define MEM_PROFILE_TRACK_VARS_ADD_REC MEM_PROFILE_TRACK_VARS
#define MOC_MALLOC( x, y) MOC_MALLOC_TRACK( x, y, (ubyte *) __func__, __LINE__)
#define MOC_CALLOC( x, y, z) MOC_CALLOC_TRACK( x, y, z, (ubyte *) __func__, __LINE__)
#define MOC_MALLOC_ALIGN( x, y, z) MOC_MALLOC_ALIGN_TRACK( x, y, z, (ubyte *) __func__, __LINE__)
#define CONVERT_MALLOC( x) CONVERT_MALLOC_TRACK( x, (ubyte *) __func__, __LINE__)
#define CONVERT_CALLOC( x, y) CONVERT_CALLOC_TRACK( x, y, (ubyte *) __func__, __LINE__)
#define MOC_MALLOC_MEMCPY( x, y, z, w) MOC_MALLOC_MEMCPY_TRACK( x, y, z, w, (ubyte *) __func__, __LINE__)

#else

#define MEM_PROFILE_ADD_SUFFIX( X) X
#define MEM_PROFILE_TRACK_DECL
#define MEM_PROFILE_TRACK_VARS
#define MEM_PROFILE_TRACK_VARS_ADD_REC ,NULL,0

#endif

#if defined(MOC_LITTLE_ENDIAN) && defined(MOC_BIG_ENDIAN)
#error Must not define both MOC_LITTLE_ENDIAN and MOC_BIG_ENDIAN
#endif

#define BIGEND32( BUFF, X)  {  ubyte* _tmp = (ubyte*) (BUFF);       \
                                   *_tmp++ = (ubyte)((X) >> 24);    \
                                   *_tmp++ = (ubyte)((X) >> 16);    \
                                   *_tmp++ = (ubyte)((X)>>  8);     \
                                   *_tmp++ = (ubyte)(X);  }

/* compute the new length so that x mod p = 0; p must be a power of 2 */
#define MOC_PAD(x,p)                ((x+p-1) & (~(p-1)))

#if defined(__ASM_386_GCC__)
#define ROTATE_LEFT(X,n)  \
    ({ ubyte4 _R = X; __asm __volatile ("rol %1, %0": "=r"(_R) : "i"(n), "0"(_R)); _R;})
#define ROTATE_RIGHT(X,n) \
({ ubyte4 _R = X; __asm __volatile ("ror %1, %0": "=r"(_R) : "i"(n), "0"(_R)); _R;})
#elif defined(__ASM_PPC__)
#if defined(__ghs__)
/* Use asm macros here for the GHS toolset */
asm ubyte4 ROTATE_LEFT(X,n) {
%reg X con n
    rotlwi r3, X, n
%error
}
asm ubyte4 ROTATE_RIGHT(X,n) {
%reg X con n
    rotrwi r3, X, n
%error
}
#else /* __ghs__ */
 /* newer versions of the gcc compiler do that optimization already! */
#define ROTATE_LEFT(X,n) \
( {ubyte4 _R; __asm __volatile("rotlwi %0, %1, %2": "=r"(_R): "r"(X), "i"(n)); _R; })
#define ROTATE_RIGHT(X,n) \
( {ubyte4 _R; __asm __volatile("rotrwi %0, %1, %2": "=r"(_R): "r"(X), "i"(n)); _R; })
#endif /* else ~__ghs__ */
#elif defined(__xxASM_ARM__)
/* don't enable this for ARM since gcc is able to wrap the rotation operation
   as part of some other instruction... like add r1, r2, r7, ror #27 */
#define ROTATE_LEFT(X,n) \
( {ubyte4 _R; __asm __volatile("mov %0, %1, ror %2": "=r"(_R): "r"(X), "i"(32-n)); _R; })
#define ROTATE_RIGHT(X,n) \
( {ubyte4 _R; __asm __volatile("mov %0, %1, ror %2": "=r"(_R): "r"(X), "i"(n)); _R; })
#else
    /* MIPS does not have rotate instructions */
/* rotate X left n bits */
#define ROTATE_LEFT(X,n)        (((ubyte4)(X) << (n)) | (((ubyte4)X) >> (32-(n))))
#define ROTATE_RIGHT(X,n)       (((ubyte4)(X) >> (n)) | (((ubyte4)(X)) << (32-(n))))
#endif

/* Valid index - 0 to max bits in X */
/* Valid value - 0 or 1 */
#define MOC_BIT_SET(X, value, bitIndex) ((X & ~(1 << bitIndex)) | (value << bitIndex)) /* First reset the value and then set to passed value */
#define MOC_BIT_GET(X, bitIndex)        ((X & (1 << bitIndex)) >> bitIndex)

/*------------------------------------------------------------------*/

MOC_EXTERN ubyte2 SWAPWORD(ubyte2 a);
MOC_EXTERN ubyte4 SWAPDWORD(ubyte4 a);

MOC_EXTERN ubyte4  MOC_NTOHL(const ubyte *v);
MOC_EXTERN ubyte2  MOC_NTOHS(const ubyte *v);
MOC_EXTERN void    MOC_HTONL(ubyte n[4], ubyte4 h);
MOC_EXTERN void    MOC_HTONS(ubyte n[2], ubyte2 h);

/* REVIEW -- prototypes should use void* */
MOC_EXTERN MSTATUS MOC_MEMMOVE(ubyte *pDest, const ubyte *pSrc, sbyte4 len);
MOC_EXTERN MSTATUS MOC_MEMCPY(void *pDest, const void *pSrc, sbyte4 len);
MOC_EXTERN MSTATUS MOC_MEMCMP(const ubyte *pSrc1, const ubyte *pSrc2, usize len, sbyte4 *pResult);
MOC_EXTERN MSTATUS MOC_MEMSET(ubyte *pDest, ubyte value, usize len);
MOC_EXTERN MSTATUS MOC_XORCPY(void *pDst, const void *pSrc, ubyte4 numBytes);
MOC_EXTERN MSTATUS MOC_CTIME_MATCH(const void *a, const void *b, ubyte4 len,
                                   intBoolean *pDiffer);

MOC_EXTERN ubyte   returnHexDigit(ubyte4 digit);
MOC_EXTERN sbyte   MTOLOWER(sbyte c);
MOC_EXTERN byteBoolean   MOC_ISSPACE( sbyte c);
MOC_EXTERN byteBoolean   MOC_ISLWS( sbyte c);
MOC_EXTERN byteBoolean   MOC_ISXDIGIT( sbyte c);
MOC_EXTERN byteBoolean   MOC_ISLOWER( sbyte c);
MOC_EXTERN byteBoolean   MOC_ISDIGIT( sbyte c);
MOC_EXTERN byteBoolean   MOC_ISASCII( sbyte c);

MOC_EXTERN sbyte4  MOC_STRCMP(const sbyte *pString1, const sbyte *pString2);
MOC_EXTERN sbyte4  MOC_STRNCMP(const sbyte *pString1, const sbyte *pString2, ubyte4 n);
MOC_EXTERN sbyte4  MOC_STRNICMP(const sbyte *pString1, const sbyte* pString2, ubyte4 n);
MOC_EXTERN ubyte4  MOC_STRLEN(const sbyte *s);
MOC_EXTERN ubyte4  MOC_STRCBCPY( sbyte* dest, ubyte4 destSize, const sbyte* src);
MOC_EXTERN sbyte*  MOC_STRCHR(sbyte *src, sbyte ch, ubyte4 len);
MOC_EXTERN ubyte4  MOC_STRCAT( sbyte* dest, const sbyte* addsrc);
MOC_EXTERN ubyte4  MOC_BITLENGTH( ubyte4 w);
MOC_EXTERN ubyte4  MOC_BITCOUNT( ubyte4 v);

struct TimeDate;
MOC_EXTERN sbyte4 MOC_cmpTimeDate(const struct TimeDate* first,
                                  const struct TimeDate* second);

/* convert a string to a integer using decimal base, the stop pointer
    can be null. If it is not, it is set to the character that can't be
    interpreted as a decimal digit */
MOC_EXTERN sbyte4  MOC_ATOL(const sbyte *s, const sbyte **stop);

/* convert a string to a hex byte arrey. pOut must have enough space */
MOC_EXTERN MSTATUS MOC_ATOH(ubyte *pHexString, ubyte4 hexStrLen, ubyte *pOut);

/* write a integer to a string using decimal base. Returns the
    position in the buffer where the value was written or NULL
    if there was not enough space in the buffer == the buffer is
    NOT NUL terminated */
MOC_EXTERN sbyte* MOC_LTOA(sbyte4 value, sbyte *buff, ubyte4 bufSize);

/* 0 = Sunday, ..... 6 = Saturday */
MOC_EXTERN sbyte4 MOC_DAYOFWEEK( sbyte4 day, sbyte4 month /*1-12*/, sbyte4 year /* 1752- */);

/* If this is not an OSX build, but is an Altivec build, we need to have a malloc
 * that guarantees results are 16-byte aligned.
 * OSX always aligns 16.
 */
#if !defined(__RTOS_OSX__) && (defined(__ALTIVEC__) || defined(__SSE2__))

#define NEED_MALLOC_ALIGN   1
#define UNITS_MALLOC(a,b)   MOC_MALLOC_ALIGN((a),(b),16)
#define UNITS_FREE(a)       MOC_FREE((a))

#else /* not __ALTIVEC__ */

#define NEED_MALLOC_ALIGN   0
#define UNITS_MALLOC(a,b)   MOC_MALLOC((a),(b))
#define UNITS_FREE(a)       MOC_FREE((a))

#endif  /* __ALTIVEC__ */

/* This malloc and free have the regular malloc and free function signatures
 * (malloc: arg of size, returns a void *, free: arg of void * returns void).
 * and cnverts them to calls to MOC_MALLOC and MOC_FREE.
 */
MOC_EXTERN void * MEM_PROFILE_ADD_SUFFIX(CONVERT_MALLOC) (ubyte4 bufSize MEM_PROFILE_TRACK_DECL);
MOC_EXTERN void * MEM_PROFILE_ADD_SUFFIX(CONVERT_CALLOC) (ubyte4 typeSize, ubyte4 bufSize MEM_PROFILE_TRACK_DECL);
MOC_EXTERN void CONVERT_FREE (void *buffer);

MOC_EXTERN MSTATUS MEM_PROFILE_ADD_SUFFIX(MOC_MALLOC)(void **ppPtr, ubyte4 bufSize MEM_PROFILE_TRACK_DECL);

/* Allocate memory and memcpy the input data into the new buffer.
 * The dataLen can be smaller than the bufSize, but it cannot be bigger.
 */
MOC_EXTERN MSTATUS MEM_PROFILE_ADD_SUFFIX(MOC_MALLOC_MEMCPY) (
  void **ppPtr,
  ubyte4 bufSize,
  void *pDataToCopy,
  ubyte4 dataLen
  MEM_PROFILE_TRACK_DECL
  );

/* MOC_MALLOC_ALIGN is the same as MOC_MALLOC, except this call will guarantee
 * that the resulting address is aligned by the amount given in alignment.
 * If the alignment is 0, the function will not guarantee any alignment. That is,
 * it is the same as MOC_MALLOC.
 * At the moment, the only supported value for alignment is 16.
 */
MOC_EXTERN MSTATUS MEM_PROFILE_ADD_SUFFIX(MOC_MALLOC_ALIGN)(void **ppPtr, ubyte4 bufSize, ubyte4 alignment MEM_PROFILE_TRACK_DECL);
/* Allocate memory and memset it to 0.
 * This will allocate count * size bytes.
 */
MOC_EXTERN MSTATUS MEM_PROFILE_ADD_SUFFIX(MOC_CALLOC)(void **ppPtr, ubyte4 count, ubyte4 size MEM_PROFILE_TRACK_DECL);
MOC_EXTERN MSTATUS MOC_FREE(void **ppPtr);

MOC_EXTERN MSTATUS shredMemory(ubyte **ppMemToShred, ubyte4 memToShredLen, byteBoolean freeMemory);

MOC_EXTERN MSTATUS MOC_Defragment(uintptr *pAllocationList, ubyte4 listLen);

/* MOC_MEMSET_FREE is a simple macro wrapper that calls shredMemory. It is
 * primarily here to ensure consistent naming */
#define MOC_MEMSET_FREE(_ppMemToShred, _memToShredLen) \
    shredMemory(_ppMemToShred, _memToShredLen, TRUE)

void moc_memset(void *pDest, ubyte value, usize len);
void moc_free(void **ppPtr);
void moc_memset_free(ubyte **ppMemToShred, ubyte4 memToShredLen);
void moc_memcpy(void *pDest1, const void *pSrc1, sbyte4 len);
sbyte4 moc_memcmp(const void *pSrc1, const void *pSrc2, usize len);

MOC_EXTERN MSTATUS MOC_UTOA(ubyte4 value, ubyte *pRetResult, ubyte4 *pRetNumDigitsLong);
MOC_EXTERN ubyte4  MOC_floorPower2(ubyte4 value);
MOC_EXTERN MSTATUS MOC_convertHexString(const char *src, ubyte *outbuf,
        ubyte4 outbuflen);

MOC_EXTERN MSTATUS MOC_removeDuplicateSlashes (char *pPath);

#ifdef __ENABLE_MOCANA_MEM_PART_DEBUG__
MOC_EXTERN MSTATUS MOC_debugMemPart(char *pOutFileName);
#endif

#ifdef __RTOS_WIN32__
#define MOC_REALLOC realloc
#endif /* __RTOS_WIN32__ */

#ifdef __cplusplus
}
#endif

#endif /* __MSTDLIB_HEADER__ */

