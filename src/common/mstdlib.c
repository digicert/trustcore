/*
 * mstdlib.c
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

#include "../common/moptions.h"

#ifdef __RTOS_WIN32__
#include <windows.h>
#endif

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/mem_part.h"
#if NEED_MALLOC_ALIGN!=0
#if !defined(__RTOS_VXWORKS__)
#include <malloc.h>
#include <stdlib.h>
#endif
#if defined(__RTOS_VXWORKS__)
#include <memLib.h>
#endif
#endif
#if defined(__RTOS_ZEPHYR__)
#include <zephyr/kernel.h>
#endif
#ifdef __ENABLE_DIGICERT_SUPPORT_FOR_NATIVE_STDLIB__
#if (defined(__KERNEL__) && (defined(__LINUX_RTOS__) || defined(__ANDROID_RTOS__)))
#include <linux/types.h>
#include <linux/string.h>
#else
#include <string.h>
#endif
#endif /*__ENABLE_DIGICERT_SUPPORT_FOR_NATIVE_STDLIB__ */

#ifdef __ENABLE_DIGICERT_MEM_PART__
memPartDescr  *gMemPartDescr = 0;
#endif

#ifdef __ENABLE_DIGICERT_MEM_PROFILE__
#include "../common/mem_profiler.h"
#endif

/*------------------------------------------------------------------*/
#if defined(__ENABLE_DIGICERT_DEBUG_PADDING__)
#define DEAD_ZONE 4
#define PREAMBLE 0xdeadbeef
#define POSTAMBLE 0x12345678
#endif

#define DIGI_MALLOC_MAX_BUF_SIZE     (0x00ffffff)

#ifndef __DISABLE_DIGICERT_MSTD_LIB_DEP__

/*------------------------------------------------------------------*/

extern ubyte2 SWAPWORD(ubyte2 a)
{
    return (ubyte2)((a << 8) | (a >> 8));
}


/*------------------------------------------------------------------*/

extern ubyte4 SWAPDWORD(ubyte4 a)
{
    return ((a << 24) |
            ((a << 8) & 0x00ff0000) |
            ((a >> 8) & 0x0000ff00) |
            (a >> 24));
}


/*------------------------------------------------------------------*/

extern ubyte4
DIGI_NTOHL(const ubyte *v)
{
    return (ubyte4)((((ubyte4)(v[0])) << 24) | (((ubyte4)(v[1])) << 16) | (((ubyte4)(v[2])) <<8 ) | ((ubyte4)(v[3])));
}


/*------------------------------------------------------------------*/

extern ubyte2
DIGI_NTOHS(const ubyte *v)
{
    return (ubyte2)((((ubyte4)(v[0])) << 8) | v[1]);
}


/*------------------------------------------------------------------*/

extern void
DIGI_HTONL(ubyte n[4], ubyte4 h)
{
    n[0] = (ubyte)((h >> 24) & 0xFF);
    n[1] = (ubyte)((h >> 16) & 0xFF);
    n[2] = (ubyte)((h >> 8)  & 0xFF);
    n[3] = (ubyte)( h        & 0xFF);
}


/*------------------------------------------------------------------*/

extern void
DIGI_HTONS(ubyte n[2], ubyte2 h)
{
    n[0] = (ubyte)((h >> 8) & 0xFF);
    n[1] = (ubyte)( h       & 0xFF);
}


/*------------------------------------------------------------------*/

extern MSTATUS
DIGI_MEMMOVE(ubyte *pDest, const ubyte *pSrc, sbyte4 len)
{
    MSTATUS status = OK;

    if ((NULL == pDest) || (NULL == pSrc))
    {
        status = ERR_NULL_POINTER;
    }
    else
    {
#ifdef __ENABLE_DIGICERT_SUPPORT_FOR_NATIVE_STDLIB__
        memmove(pDest, pSrc, len);
#else
        if ((pSrc > pDest) || (pDest >= pSrc + len))
        {
            while (0 < len)
            {
                *pDest = *pSrc;
                pDest++;
                pSrc++;
                len--;
            }
        }
        else
        {
            pSrc += len - 1;
            pDest += len - 1;

            while (0 < len)
            {
                *pDest = *pSrc;
                pDest--;
                pSrc--;
                len--;
            }
        }
#endif
    }

    return status;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
DIGI_MEMCPY(void *pDest1, const void *pSrc1, sbyte4 len)
{
    MSTATUS         status = OK;

    if ((NULL == pDest1) || (NULL == pSrc1))
        status = ERR_NULL_POINTER;
    else
    {
#ifdef __ENABLE_DIGICERT_SUPPORT_FOR_NATIVE_STDLIB__
        memcpy(pDest1, pSrc1, len);
#else
        ubyte*          pDest  = (ubyte*)pDest1;
        const ubyte*    pSrc   = (const ubyte*)pSrc1;

        while (0 < len)
        {
            *pDest = *pSrc;
            pDest++;
            pSrc++;
            len--;
        }
#endif
    }

    return status;
}


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
DIGI_MEMCMP(const ubyte *pSrc1, const ubyte *pSrc2, usize len, sbyte4 *pResult)
{
    MSTATUS status = OK;

    if ((NULL == pSrc1) || (NULL == pSrc2) || (NULL == pResult))
        status = ERR_NULL_POINTER;
    else
    {
#ifdef __ENABLE_DIGICERT_SUPPORT_FOR_NATIVE_STDLIB__
        *pResult = memcmp(pSrc1, pSrc2, len);
#else
        *pResult = 0;

        while (((ubyte4)0 < len) && ((ubyte4)0 == (*pResult = (sbyte4)(*pSrc1 - *pSrc2))))
        {
            pSrc1++;
            pSrc2++;
            len--;
        }

        *pResult = ((sbyte4)0 < *pResult) ? (sbyte4) 1 : (((sbyte4) 0 == *pResult) ? (sbyte4) 0 :(sbyte4) -1);
#endif
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DIGI_CTIME_MATCH(const void *a, const void *b, ubyte4 len,
                 intBoolean *pDiffer)
{
    const ubyte* ba = (const ubyte*) a;
    const ubyte* bb = (const ubyte*) b;
    ubyte4 i;

    if (!a || !b || !pDiffer)
    {
        return ERR_NULL_POINTER;
    }

    *pDiffer = 0;
    for (i = 0; i < len; ++i)
    {
        *pDiffer |= ba[i] ^ bb[i];
    }

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DIGI_SAFEMATCH(const ubyte *pTrustedSrc,   ubyte4 trustedSrcLen,
              const ubyte *pUntrustedSrc, ubyte4 untrustedLen,
              intBoolean *pResult)
{
    /* not to be confused with memcmp(). this code is resistant to a timing attack. */
    /* if bytes are identical match, *pResult will be TRUE */
    ubyte4  index;
    ubyte4  result;
    MSTATUS status = OK;

    if ((NULL == pTrustedSrc) || (NULL == pUntrustedSrc) || (NULL == pResult))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    result = trustedSrcLen ^ untrustedLen;

    for (index = 0; index < untrustedLen; index++)
        result = (result | (pTrustedSrc[index % trustedSrcLen] ^ pUntrustedSrc[index]));

    *pResult = (0 == result) ? TRUE : FALSE;

exit:
    return status;
}


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
DIGI_MEMSET(ubyte *pDest, ubyte value, usize len)
{
    MSTATUS status = OK;

    if (NULL == pDest)
        status = ERR_NULL_POINTER;
    else
    {
#ifdef __RTOS_WIN32__
        if (0 == value)
        {
            /* Use the secure version when filling with zero to
             * ensure the compiler does not optimize it out. */
            SecureZeroMemory(pDest, len);
        }
        else
        {
            FillMemory(pDest, len, value);
        }
#elif defined(__ENABLE_DIGICERT_SUPPORT_FOR_NATIVE_STDLIB__)
        memset(pDest, value, len);
#else
        volatile ubyte *volatile p = pDest;
        while (0 < len)
        {
            *p = value;
            p++;
            len--;
        }
#endif
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DIGI_XORCPY(void *pDst, const void *pSrc, ubyte4 numBytes)
{
    MSTATUS status = OK;

    if ((NULL == pDst) || (NULL == pSrc))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    while (numBytes)
    {
        *((ubyte *)pDst) ^= *((ubyte *)pSrc);
        pDst = (ubyte *) pDst + 1;
        pSrc = (ubyte *) pSrc + 1;
        numBytes--;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern ubyte
returnHexDigit(ubyte4 digit)
{
    digit &= 0x0f;

    if (0x0a > digit)
        return (ubyte)(digit + '0');

    return (ubyte)((digit - 10) + 'a');
}

/*------------------------------------------------------------------*/

extern sbyte
MTOLOWER(sbyte c)
{
    if (('A' <= c) && ('Z' >= c))
    {
        c += 'a' - 'A';
    }

    return c;
}


/*------------------------------------------------------------------*/

extern byteBoolean
DIGI_ISSPACE(sbyte c)
{
    return ( (0x20 == c) || (( 0x09 <= c) && (c <= 0x0D)));
}

/*------------------------------------------------------------------*/
/* LWS  = [CRLF] 1*( SP | HT ) defined in RFC 2616
*/
extern byteBoolean
DIGI_ISLWS( sbyte c)
{
    return ( (0x20 == c) || (0x09 == c) || (0x0A == c) || (0x0D == c));
}

/*------------------------------------------------------------------*/

extern byteBoolean
DIGI_ISXDIGIT( sbyte c)
{
    return ( (c>= '0' && c <= '9') ||
             (c>= 'a' && c <= 'f') ||
             (c>= 'A' && c <= 'F') );
}


/*------------------------------------------------------------------*/

extern byteBoolean
DIGI_ISASCII( sbyte c)
{
    return ( (c & ~0x7f) == 0 );
}


/*------------------------------------------------------------------*/

extern byteBoolean
DIGI_ISDIGIT( sbyte c)
{
    return ( (c>= '0' && c <= '9') );
}


/*------------------------------------------------------------------*/

extern byteBoolean
DIGI_ISLOWER( sbyte c)
{
    return ( (c>= 'a' && c <= 'z') );
}


/*------------------------------------------------------------------*/

extern ubyte4
DIGI_STRLEN(const sbyte *s)
{
    const sbyte *t = s;

	if (NULL == t)
	{
		return 0;
	}
    while (0 != *t)
        t++;

    return (ubyte4)(t - s);
}


/*------------------------------------------------------------------*/

extern sbyte4
DIGI_STRCMP(const sbyte *pString1, const sbyte *pString2)
{
    while (('\0' != *pString1) && (*pString1 == *pString2))
    {
        pString1++;
        pString2++;
    }

    return ((*pString1) - (*pString2));
}


/*------------------------------------------------------------------*/

extern sbyte4
DIGI_STRNCMP(const sbyte *pString1, const sbyte *pString2, ubyte4 n)
{
    ubyte4 i;

    for (i = 0; i < n; ++i)
    {
        sbyte c1 = *pString1++;
        sbyte c2 = *pString2++;

        if ( 0 == c1 || 0 == c2 || c1!=c2)
            return c1-c2;
    }
    return 0;
}


/*------------------------------------------------------------------*/

extern sbyte4
DIGI_STRNICMP(const sbyte *pString1, const sbyte *pString2, ubyte4 n)
{
    ubyte4 i;

    for (i = 0; i < n; ++i)
    {
        sbyte c1 = MTOLOWER(*pString1++);
        sbyte c2 = MTOLOWER(*pString2++);

        if ( 0 == c1 || 0 == c2 || c1!=c2)
            return c1-c2;
    }
    return 0;
}


/*------------------------------------------------------------------*/

extern ubyte4
DIGI_STRCBCPY( sbyte* dest, ubyte4 destSize, const sbyte* src)
{
    ubyte4 i = 0;

    if (0 == dest || 0 == destSize || 0 == src)
    {
        return 0;
    }

    while ( i < destSize && (dest[i] = *src++) )
    {
        ++i;
    }

    if ( i == destSize)
    {
        /* destSize >= 1 */
        dest[--i] = 0; /* --len && NUL terminate */
    }

    return i;
}


/*------------------------------------------------------------------*/

extern ubyte4
DIGI_STRCAT( sbyte* dest, const sbyte* addsrc)
{
	ubyte4 len = 0;

    if (NULL == dest || NULL == addsrc)
    {
        return 0;
    }

	for (; *dest; ++dest)
	{
		len++;
	}

	while ((*dest++ = *addsrc++) != 0)
	{
		len++;
	}

	return len;

}
/*------------------------------------------------------------------*/

extern sbyte*
DIGI_STRCHR(sbyte *s, sbyte c, ubyte4 len)
{
    while((0 < len) && ('\0' != *s))
    {
        if (MTOLOWER(*s) == MTOLOWER(c))
            return (s);
        s++;
        len--;
    }
    return (NULL);
}

/*------------------------------------------------------------------*/

extern sbyte4
DIGI_ATOL(const sbyte* s, const sbyte** stop)
{
    sbyte4 sign = 1;
    sbyte4 retVal = 0;

    /* white space */
    while ( (*s >= 0x9 && *s <= 0xD) || (0x20 == *s) )
    {
        ++s;
    }

    /* sign if any */
    if ('-' == *s)
    {
        sign = -1;
        ++s;
    }

    /* decimal part */
    while (*s >= '0' && *s <= '9')
    {
        retVal *= 10;
        retVal += *s - '0';
        ++s;
    }

    if ( stop)
    {
        *stop = (sbyte *)s;
    }

    return sign * retVal;
}

/*---------------------------------------------------------------------------*/

/* for non-FIPS this will be in crypto_utils.c */
#ifndef __ENABLE_DIGICERT_FIPS_MODULE__
extern MSTATUS
DIGI_ATOH(ubyte *pHexString, ubyte4 hexStrLen, ubyte *pOut)
{
    MSTATUS status = ERR_INVALID_INPUT;
    ubyte4 i = 0;
    ubyte4 j = 0;

    /* hexStrLenmust  be even */
    if (hexStrLen & 0x01)
        goto exit;

    for (i = 0; i < hexStrLen; i += 2, j++ )
    {
        if ('0' <= pHexString[i] && '9' >= pHexString[i])
        {
            pOut[j] = pHexString[i] - '0';
        }
        else if ('a' <= pHexString[i] && 'f' >= pHexString[i])
        {
            pOut[j] = pHexString[i] + 10 - 'a';
        }
        else if ('A' <= pHexString[i] && 'F' >= pHexString[i])
        {
            pOut[j] = pHexString[i] + 10 - 'A';
        }
        else
        {
            goto exit;
        }

        pOut[j] <<= 4;

        if ('0' <= pHexString[i+1] && '9' >= pHexString[i+1])
        {
            pOut[j] |= (pHexString[i+1] - '0');
        }
        else if ('a' <= pHexString[i+1] && 'f' >= pHexString[i+1])
        {
            pOut[j] |= (pHexString[i+1] + 10 - 'a');
        }
        else if ('A' <= pHexString[i+1] && 'F' >= pHexString[i+1])
        {
            pOut[j] |= (pHexString[i+1] + 10 - 'A');
        }
        else
        {
            goto exit;
        }
    }

    status = OK;

exit:

    return status;
}
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

/*------------------------------------------------------------------*/
#endif /* __DISABLE_DIGICERT_MSTD_LIB_DEP__ */

#ifdef __ENABLE_DIGICERT_MEM_PART__
extern MSTATUS DIGI_LoadPartition (
  memPartDescr *pPartition
  )
{
  /* Place the partition at the global location, DIGI_MALLOC will now have control
   * of it.
   */
  if (NULL == gMemPartDescr)
  {
    gMemPartDescr = pPartition;
    return (OK);
  }

  return (ERR_MEM_PART);
}

extern MSTATUS DIGI_UnloadPartition (
  memPartDescr **pPartition
  )
{
  if (NULL == pPartition)
    return (ERR_NULL_POINTER);

  /* Return control of the partition to the caller. Simply return the partition
   * at the address given, then NULL out the global location so that DIGI_MALLOC
   * can no longer see it.
   */
  *pPartition = NULL;
  if (NULL != gMemPartDescr)
  {
    *pPartition = gMemPartDescr;
    gMemPartDescr = NULL;
    return (OK);
  }

  return (ERR_MEM_PART);
}

/* A note on why this function was created.
 * In the process of evaluating and rewriting how memory partitions do threading,
 * there was a desire to modify the functionality such that the first MALLOC
 * call to create the partition mutex also went inside of the memory partition
 * itself. Handling it on the creation side was straightforward, however it
 * presented a new problem when cleaning up. The memory partition paradigm is
 * create, load, unload, free. This is a problem however because in the process
 * of unloading the partition, the global memory partition descriptor is set to
 * NULL. Now when the freePartition calls to freeMutex, which in turn calls to
 * FREE, the FREE implementation will see that the global memory partition
 * descriptor is NULL and thus call the normal free implementation. This of
 * course results in an error since that buffer was never malloc'd by the system.
 * The solution is to free the mutex just before unloading the partition, thus
 * ensuring the FREE call goes to the memory partition instead of normal free.
 */
extern MSTATUS DIGI_UnloadAndFreeGlobalPartition ()
{
  MSTATUS status = OK;


  memPartDescr *pPartition = NULL;

  /* First grab the global memory part descriptor if valid */
  if (NULL != gMemPartDescr)
  {
    pPartition = gMemPartDescr;

    /* Note we do not set the gMemPartDescr to NULL yet. This is because we need
     * it to point to the memory partition so that the internal FREE call on the
     * mutex frees the mutex memory inside the partition itself. With the
     * global memory descriptor still set we free the mutex */
    status = MEM_PART_freePartition(&pPartition);
    if (OK != status)
      goto exit;

    /* Now that we are all done, set the global memory descriptor to NULL.
     * If the mutex disable flag is set, this emulates the behavior of an unload
     * and free */
    gMemPartDescr = NULL;
  }

exit:
    return status;
}

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_MEM_PART_DEBUG__
MOC_EXTERN MSTATUS DIGI_debugMemPart(char *pOutFileName)
{
    return MEM_PART_printMemoryPartitions(gMemPartDescr, pOutFileName);
}
#endif /* __ENABLE_DIGICERT_MEM_PART_DEBUG__ */
#endif /*  __ENABLE_DIGICERT_MEM_PART__ */

#ifndef __DISABLE_DIGICERT_MSTD_LIB_DEP__

#if NEED_MALLOC_ALIGN!=0

#ifdef __RTOS_ZEPHYR__
/* Zephyr defines posix_memalign as part of pico libc module
 * which includes definitions for aligned_alloc, malloc, and free
 * that are not compatible with lib c equivalent defined by
 * CONFIG_COMMON_LIBC_MALLOC. To avoid duplicate definitions
 * we implement posix_memalign here. */
static int posix_memalign_ex(void **memptr, size_t align, size_t size)
{
    void *mem = aligned_alloc(align, size);

    if (!mem)
        return ENOMEM;

    *memptr = mem;
    return 0;
}
#endif /* __RTOS_ZEPHYR__ */

extern MSTATUS MEM_PROFILE_ADD_SUFFIX(DIGI_MALLOC_ALIGN) (
  void **ppPtr,
  ubyte4 bufSize,
  ubyte4 alignment
  MEM_PROFILE_TRACK_DECL
  )
{
  MSTATUS status;
  void *retVal = (void *)0;

  status = ERR_MEM_ALLOC_PTR;
  if (NULL == ppPtr)
    goto exit;

  *ppPtr = (void *)0;

  status = ERR_INVALID_ARG;
  if ( (0 != alignment) && (16 != alignment) )
    goto exit;

  /* Don't allocate memory if the requested size is too big. We can change
   * this limit and we can revisit this decision.
   */
  status = ERR_MEM_ALLOC_SIZE;
#ifdef __DISABLE_DIGICERT_MALLOC_LIMIT__
  if (0 == bufSize)
    goto exit;
#else
  if ( (0 == bufSize) || (DIGI_MALLOC_MAX_BUF_SIZE < bufSize) )
    goto exit;
#endif

#ifdef __ENABLE_DIGICERT_MEM_PART__
  if (gMemPartDescr != (memPartDescr *)0)
  {
    status = MEM_PART_alloc (gMemPartDescr, bufSize + (16 - (bufSize % 16)), ppPtr);
    goto exit;
  }
#endif

  status = ERR_MEM_ALLOC_FAIL;

#if defined(__ENABLE_DIGICERT_DEBUG_MEMORY__)
  retVal = MC_MALLOC_ALIGN(bufSize, 16);
  if (NULL == retVal)
    goto exit;
#else
#if (defined(__RTOS_CYGWIN__) || defined(__RTOS_SOLARIS__) || defined(__RTOS_ANDROID__) || defined(__RTOS_VXWORKS__))
  retVal = memalign (16, (size_t)bufSize);
  if (NULL == retVal)
#elif defined(__RTOS_ZEPHYR__)
  if (0 != posix_memalign_ex (&retVal, 16, bufSize))
#else
  if (0 != posix_memalign (&retVal, 16, bufSize))
#endif
    goto exit;
#endif

  *ppPtr = retVal;
  status = OK;

exit:

#ifdef __ENABLE_DIGICERT_MEM_PROFILE__
  if (OK == status)
    status = MEM_PROFILER_addRecord(TRUE, (uintptr) *ppPtr, bufSize + (16 - (bufSize % 16)) MEM_PROFILE_TRACK_VARS_ADD_REC);

#ifdef __ENABLE_DIGICERT_MEM_PROFILE_MAP__
  if (OK == status)
    status = MEM_PROFILER_addToMap((uintptr) ppPtr, (uintptr) *ppPtr, bufSize + (16 - (bufSize % 16)));
#endif

#endif /* __ENABLE_DIGICERT_MEM_PROFILE__ */

  return (status);
}

#endif /* NEED_MALLOC_ALIGN!=0 */

extern void * MEM_PROFILE_ADD_SUFFIX(CONVERT_MALLOC) (ubyte4 bufSize MEM_PROFILE_TRACK_DECL)
{
  MSTATUS status;
  void *pRetVal = NULL;

  status = MEM_PROFILE_ADD_SUFFIX(DIGI_MALLOC) (&pRetVal, bufSize MEM_PROFILE_TRACK_VARS);
  if (OK == status)
    return (pRetVal);

  return ((void *)0);
}

extern void * MEM_PROFILE_ADD_SUFFIX(CONVERT_CALLOC) (ubyte4 typeSize, ubyte4 bufSize MEM_PROFILE_TRACK_DECL)
{
  MSTATUS status;
  void *pRetVal = NULL;

  status = MEM_PROFILE_ADD_SUFFIX(DIGI_CALLOC) (&pRetVal, typeSize, bufSize MEM_PROFILE_TRACK_VARS);
  if (OK == status)
    return (pRetVal);

  return ((void *)0);
}

#if defined(__ENABLE_DIGICERT_CUSTOM_MALLOC__) && defined(__RTOS_ZEPHYR__)
static struct k_heap custom_heap;
MOC_EXTERN MSTATUS DIGICERT_initCustomHeap(void *pHeap, size_t heapSize)
{
    if (NULL == pHeap || 0 == heapSize)
        return ERR_INVALID_ARG;

    k_heap_init(&custom_heap, pHeap, heapSize);
    return OK;
}

MOC_EXTERN void *DIGICERT_customMalloc(size_t size)
{
    return k_heap_alloc(&custom_heap, size, K_NO_WAIT);
}

MOC_EXTERN void DIGICERT_customFree(void *memptr)
{
    if (memptr != NULL)
    {
        k_heap_free(&custom_heap, memptr);
    }
}
#endif

MOC_EXTERN MSTATUS MEM_PROFILE_ADD_SUFFIX(DIGI_MALLOC) (
  void **ppPtr,
  ubyte4 bufSize
  MEM_PROFILE_TRACK_DECL
  )
{
  MSTATUS status;
  void *retVal = (void *)0;

  status = ERR_MEM_ALLOC_PTR;
  if (NULL == ppPtr)
    goto exit;

  *ppPtr = (void *)0;

  /* Don't allocate memory if the requested size is too big, or 0. We can change
   * this limit and we can revisit this decision.
   */
  status = ERR_MEM_ALLOC_SIZE;
#ifdef __DISABLE_DIGICERT_MALLOC_LIMIT__
  if (0 == bufSize)
    goto exit;
#else
  if ( (0 == bufSize) || (DIGI_MALLOC_MAX_BUF_SIZE < bufSize) )
    goto exit;
#endif

  /* If the MEM_PART is compiled, it is possible the program is using static
   * memory. If so, call MEM_PART_alloc.
   */
#ifdef __ENABLE_DIGICERT_MEM_PART__
  if (gMemPartDescr != (memPartDescr *)0)
  {
    status = MEM_PART_alloc (gMemPartDescr, bufSize, ppPtr);
    goto exit;
  }
#endif

  status = ERR_MEM_ALLOC_FAIL;
#if defined(__ENABLE_DIGICERT_DEBUG_PADDING__)
  retVal = MC_MALLOC (bufSize+DEAD_ZONE*3);
#else
  retVal = MC_MALLOC (bufSize);
#endif
  if (NULL == retVal)
    goto exit;

#if defined(__ENABLE_DIGICERT_DEBUG_PADDING__)
  *ppPtr = ((char *)retVal) + DEAD_ZONE*2;

  *(ubyte4 *)retVal = PREAMBLE;
  *(ubyte4 *)(((char *)retVal) + DEAD_ZONE) = bufSize;
  *(ubyte4 *)(((char *)retVal) + 2*DEAD_ZONE + bufSize) = POSTAMBLE;
#else
  *ppPtr = retVal;
#endif

  status = OK;

exit:

#ifdef __ENABLE_DIGICERT_MEM_PROFILE__
  if (OK == status)
    status = MEM_PROFILER_addRecord(TRUE, (uintptr) *ppPtr, bufSize MEM_PROFILE_TRACK_VARS_ADD_REC);

#ifdef __ENABLE_DIGICERT_MEM_PROFILE_MAP__
  if (OK == status)
    status = MEM_PROFILER_addToMap((uintptr) ppPtr, (uintptr) *ppPtr, bufSize);
#endif

#endif /* __ENABLE_DIGICERT_MEM_PROFILE__ */

  return (status);
}

MOC_EXTERN MSTATUS MEM_PROFILE_ADD_SUFFIX(DIGI_MALLOC_MEMCPY) (
  void **ppPtr,
  ubyte4 bufSize,
  void *pDataToCopy,
  ubyte4 dataLen
  MEM_PROFILE_TRACK_DECL
  )
{
  MSTATUS status;

  status = ERR_INVALID_INPUT;
  if (dataLen <= bufSize)
  {
    status = MEM_PROFILE_ADD_SUFFIX(DIGI_MALLOC) (ppPtr, bufSize MEM_PROFILE_TRACK_VARS);
    if ( (OK == status) && (NULL != pDataToCopy) && (0 != dataLen) )
    {
      status = DIGI_MEMCPY (*ppPtr, pDataToCopy, dataLen);
    }
  }

  return (status);
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MEM_PROFILE_ADD_SUFFIX(DIGI_CALLOC) (
  void **ppPtr,
  ubyte4 count,
  ubyte4 size
  MEM_PROFILE_TRACK_DECL
  )
{
  MSTATUS status;
  ubyte4 len;

  /* Check for integer overflow */
  if (count > (0xffffffff / size))
  {
      return ERR_INVALID_INPUT;
  }

  len = count * size;

  /* DIGI_MALLOC will check the input args for us.
   */
  status = MEM_PROFILE_ADD_SUFFIX(DIGI_MALLOC) (ppPtr, len MEM_PROFILE_TRACK_VARS);
  if (OK == status)
  {
    status = DIGI_MEMSET ((ubyte *)(*ppPtr), 0, len);
  }

  return (status);
}

/*------------------------------------------------------------------*/

extern void CONVERT_FREE(void *pBuffer)
{
  void *pTemp = pBuffer;

  (void) DIGI_FREE (&pTemp);
}

MOC_EXTERN MSTATUS
DIGI_FREE(void **ppPtr)
{
    MSTATUS status;

#ifdef __ENABLE_DIGICERT_MEM_PROFILE__
    uintptr ptrCopy = 0;
#ifdef __ENABLE_DIGICERT_MEM_PROFILE_MAP__
    uintptr ppPtrCopy = 0;
#endif
#endif

    if ((NULL == ppPtr) || (NULL == *ppPtr))
    {
        status = ERR_MEM_FREE_PTR;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_MEM_PROFILE__
    ptrCopy = (uintptr) *ppPtr;
#ifdef __ENABLE_DIGICERT_MEM_PROFILE_MAP__
    ppPtrCopy = (uintptr) ppPtr;
#endif
#endif

#ifdef __ENABLE_DIGICERT_MEM_PART__
    if (gMemPartDescr != (memPartDescr *)0)
    {
      status = MEM_PART_free (gMemPartDescr, ppPtr);
      goto exit;
    }
#endif
#if defined(__ENABLE_DIGICERT_DEBUG_PADDING__)
    char *ptr = (char *) *ppPtr;
    ubyte4 bufSize;

    ptr -= DEAD_ZONE*2;

    if (*(ubyte4 *)ptr != PREAMBLE)
    {
    	/* Problem, don't access size */
    	printf("ERROR: Memory corruption in header\n");
    }
    else
    {
    	bufSize = *(ubyte4 *)(ptr + DEAD_ZONE);
    	if (*(ubyte4 *)(ptr + DEAD_ZONE*2 + bufSize) != POSTAMBLE)
    	{
    		printf("ERROR: Memory corruption in trailer\n");
    	}
    }

    MC_FREE(ptr);
#else
    MC_FREE(*ppPtr);
#endif
    *ppPtr = NULL;
    status = OK;

exit:

#ifdef __ENABLE_DIGICERT_MEM_PROFILE__
    if (OK == status)
      status = MEM_PROFILER_addRecord(FALSE, ptrCopy, 0, NULL, 0);

#ifdef __ENABLE_DIGICERT_MEM_PROFILE_MAP__
    if (OK == status)
      status = MEM_PROFILER_deleteFromMap((uintptr) ppPtrCopy);

    /* if the location of the ptr changed we are out of luck, continue as if ok */
    if (ERR_HASH_MAP_KEY_NOT_FOUND == status)
      status = OK;
#endif

#endif /* __ENABLE_DIGICERT_MEM_PROFILE__ */

    return status;
}

/**
 * @brief Function to zero out memory before freeing
 */
extern MSTATUS
shredMemory(ubyte **ppMemToShred, ubyte4 memToShredLen, byteBoolean freeMemory)

{
    MSTATUS status = OK;

    if ((NULL != ppMemToShred) && (NULL != *ppMemToShred))
    {
        if (0 < memToShredLen)
        {
            status = DIGI_MEMSET(*ppMemToShred, 0, memToShredLen);
            if (OK != status)
                goto exit;
        }
        if (TRUE == freeMemory)
        {
            status = DIGI_FREE((void **)ppMemToShred);
            if (OK != status)
                goto exit;

            *ppMemToShred = NULL;
        }
    }
exit:
    return status;
}

void moc_free(void **ppPtr)
{
    (void) DIGI_FREE(ppPtr);
}

void moc_memset_free(ubyte **ppMemToShred, ubyte4 memToShredLen)
{
    (void) shredMemory(ppMemToShred, memToShredLen, TRUE);
}

void moc_memset(void *pDest, ubyte value, usize len)
{
    (void) DIGI_MEMSET(pDest, value, len);
}

void moc_memcpy(void *pDest1, const void *pSrc1, sbyte4 len)
{
    (void)DIGI_MEMCPY(pDest1, pSrc1, len);
}

sbyte4 moc_memcmp(const void *pSrc1, const void *pSrc2, usize len)
{
    sbyte4 result = -1;

    MSTATUS status = DIGI_MEMCMP(pSrc1, pSrc2, len, &result);
    if (status != OK) {
        goto exit;
    }

exit:
    return result;
}

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_MEM_PART__

#ifndef MOC_DEFRAGMENT_MAX_VARS
#define MOC_DEFRAGMENT_MAX_VARS 32
#endif

extern MSTATUS DIGI_Defragment(uintptr *pAllocationList, ubyte4 listLen)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 pBlockLen[MOC_DEFRAGMENT_MAX_VARS] = {0};
    ubyte4 totalLen = 0;
    ubyte *pNewPtr = NULL;
    ubyte *pTemp = NULL;
    ubyte *pTempPtr = NULL;
    ubyte4 i = 0;

    if (NULL == pAllocationList)
    {
        goto exit;
    }

    if (listLen > MOC_DEFRAGMENT_MAX_VARS || !listLen)
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

    /* Get and total all the block lengths */
    for (; i < listLen; i++)
    {
        status = MEM_PART_getBlockLen((void *) pAllocationList[i], &pBlockLen[i]);
        if (OK != status)
            goto exit;

        totalLen += pBlockLen[i];
    }

    /* Create one temp buffer to hold all the data */
    status = DIGI_MALLOC((void **) &pTemp, totalLen);
    if (OK != status)
    {
        /* Use a different return code so the app can continue even if this fails */
        status = ERR_MEM_DEFRAGMENT_FAIL;
        goto exit;
    }

    /* copy each buffer of data to pTemp and free the old buffer */
    pTempPtr = pTemp;
    for (i = 0; i < listLen; i++)
    {
        status = DIGI_MEMCPY(pTempPtr, (ubyte *) pAllocationList[i], pBlockLen[i]);
        if (OK != status)
            goto exit;

        status = DIGI_FREE((void **) &pAllocationList[i]);
        if (OK != status)
            goto exit;

        pTempPtr += pBlockLen[i];
    }

    /* allocate new blocks and copy to them */
    pTempPtr = pTemp;
    for (i = 0; i < listLen; i++)
    {
        status = DIGI_MALLOC((void **) &pNewPtr, pBlockLen[i]);
        if (OK != status)
            goto exit; 

        /* we'll ignore return code here as we want to update the 
           ptr in the list no matter what, ie so it can be freed later */
        (void) DIGI_MEMCPY(pNewPtr, pTempPtr, pBlockLen[i]);
        pTempPtr += pBlockLen[i];

        /* set the new ptr in the list */
        pAllocationList[i] = (uintptr) pNewPtr;
    }

exit:

    if (NULL != pTemp)
    {
        MSTATUS fstatus = DIGI_FREE((void **) &pTemp);
        if (OK == status)
            status = fstatus;
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_MEM_PART__ */

/*------------------------------------------------------------------*/

extern MSTATUS
DIGI_UTOA(ubyte4 value, ubyte *pRetResult, ubyte4 *pRetNumDigitsLong)
{
    ubyte4     divisor = 1000000000UL;
    ubyte4     digit;
    intBoolean isLeadingZero = TRUE;

    *pRetResult = '0';
    *pRetNumDigitsLong = 0;

    while ((divisor > value) && (divisor))
        divisor = divisor / 10;

    while (0 < divisor)
    {
        digit = (value / divisor);

        if (0 != digit)
            isLeadingZero = FALSE;

        if ((digit) || (FALSE == isLeadingZero))
        {
            *pRetResult = (ubyte)(digit + '0');
            (*pRetNumDigitsLong)++;
            pRetResult++;
        }

        value = value - (digit * divisor);
        divisor = divisor / 10;
    }

    if (!(*pRetNumDigitsLong))
        *pRetNumDigitsLong = 1;

    return OK;
}


/*------------------------------------------------------------------*/

extern sbyte*
DIGI_LTOA(sbyte4 value, sbyte *buff, ubyte4 bufSize)
{
    sbyte* p = buff;
    sbyte* retVal;

    if (!buff) return buff;


    do
    {
        if ( !bufSize)
        {
            return NULL;
        }

        *p++ = (sbyte)('0' + (value % 10));
        value /= 10;
        --bufSize;
    } while ( value);


    retVal = p;

    /* everything is in the wrong order -> reverse bytes */
    while ( --p > buff)
    {
        sbyte c = *p;
        *p = *buff;
        *buff++ = c;
    }

    return retVal;
}


/*---------------------------------------------------------------------------*/

extern sbyte4
DIGI_DAYOFWEEK( sbyte4 d, sbyte4 m, sbyte4 y)
{
    /* C FAQ Tomohiko Sakamoto */
    static int t[] = {0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4};

    y -= m < 3;
    return (y + y/4 - y/100 + y/400 + t[m-1] + d) % 7;
}


/*------------------------------------------------------------------*/

extern ubyte4
DIGI_BITLENGTH( ubyte4 w)
{
    ubyte4 numBits = 0;

    static const ubyte lookupBits[32] =
    {
        3,4,5,5,6,6,6,6,7,7,7,7,7,7,7,7,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8
    };

    if (w & 0xff000000L)
    {
        numBits += 24;
        w >>= 24;
    }
    else if (w & 0x00ff0000L)
    {
        numBits += 16;
        w >>= 16;
    }
    else if (w & 0x0000ff00L)
    {
        numBits += 8;
        w >>= 8;
    }

    if (0 == (w & 0xf8))
    {
        numBits += lookupBits[w & 7] - 3;               /* value = 0..7 */
    }
    else
    {
        numBits += lookupBits[((w >> 3) & 0x1f)];       /* value = 8..255 */
    }
    return numBits;
}


/*------------------------------------------------------------------*/

extern ubyte4
DIGI_BITCOUNT( ubyte4 v)
{
    v = v - ((v >> 1) & 0x55555555);
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
    return (((v + (v >> 4)) & 0xF0F0F0F) * 0x1010101) >> 24;
}


/*------------------------------------------------------------------*/


extern ubyte4
DIGI_floorPower2(ubyte4 value)
{
    value = (value | (value >> 1));
    value = (value | (value >> 2));
    value = (value | (value >> 4));
    value = (value | (value >> 8));
    value = (value | (value >> 16));

    return (value - (value >> 1));
}



/*------------------------------------------------------------------*/

extern sbyte4
DIGI_cmpTimeDate( const TimeDate* first, const TimeDate* second)
{
    sbyte4 retVal;
    if (first->m_year == second->m_year)
    {
        DIGI_MEMCMP( &first->m_month, &second->m_month, sizeof(TimeDate) - 2, &retVal);
    }
    else
    {
        retVal = first->m_year - second->m_year;
    }

    return retVal;
}

/*------------------------------------------------------------------*/

extern MSTATUS
DIGI_convertHexString(const char *src, ubyte *outbuf, ubyte4 outbuflen)
{
    MSTATUS status = OK;
    ubyte4 len = 0;
    sbyte val;

    if ((NULL == src) || (NULL == outbuf) ||
        (0 == outbuflen))
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

    while (*src && (outbuflen > len))
    {
        outbuf[len] = 0;

        val = MTOLOWER(*src);

        if (((val >= '0' && val <= '9')) ||
                ((val >= 'a') && (val <= 'f')))
        {
            /* High Nibble * 16 */
            if ((val >= 'a') && (val <= 'f'))
                outbuf[len] += 16 * (10 + (val - 'a'));
            else
                outbuf[len] += 16 * (val - '0');
        }
        else
        {
            status = ERR_INVALID_ARG;
            goto exit;
        }

        src++;
        if (*src)
        {
            val = MTOLOWER(*src);

            /* Make sure source byte is valid */
            if (((val >= '0' && val <= '9')) ||
                    ((val >= 'a') && (val <= 'f')))
            {
                /* Low Nibble */
                if ((val >= 'a') && (val <= 'f'))
                    outbuf[len] += 10 + (val - 'a');
                else
                    outbuf[len] += val - '0';
            }
            else
            {
                status = ERR_INVALID_ARG;
                goto exit;
            }
        }
        else
        {
            status = ERR_INVALID_ARG;
            goto exit;
        }

        len++;
        src++;
    }

    if (len != outbuflen)
        status = ERR_INVALID_ARG;

exit:
    return status;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS DIGI_removeDuplicateSlashes (char *pPath)
{
    int i = 0, j, len;
    intBoolean slashFound = FALSE;

    if (NULL == pPath)
        return ERR_NULL_POINTER;

    len = DIGI_STRLEN ((const sbyte*)pPath);
    while (i < len)
    {
#if defined(__RTOS_WIN32__)
        if ('\\' == pPath[i])
#else
        if ('/' == pPath[i])
#endif
        {
            if (FALSE == slashFound)
            {
                slashFound = TRUE;
                i++;
            }
            else
            {
                /* shift string to the left */
                len--; /* total length is reduced by one */
                for (j = i;j < len; j++)
                {
                    pPath[j] = pPath[j+1];
                }

                /* do not reset slashFound */
                /* do not increment i */
            }
        }
        else
        {
            slashFound = FALSE; /* reset */
            i++;
        }
    }
    pPath[len] = '\0';
    return OK;
}
#endif

