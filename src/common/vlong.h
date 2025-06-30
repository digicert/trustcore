/**
 * @file  vlong.h
 * @brief Very Long Integer Library Header
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 */

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/random.h"
#include "../common/memory_debug.h"
#include "../common/asm_math.h"
#include "../crypto/hw_accel.h"

#ifdef __ENABLE_MOCANA_FIPS_MODULE__
#include "../crypto/fips.h"
#endif

#ifdef __ALTIVEC__
#include <altivec.h>
#endif

#ifndef __VLONG_HEADER__
#define __VLONG_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/* Needed for vlong struct definition */
#ifdef __ENABLE_MOCANA_64_BIT__
typedef ubyte8 vlong_unit;
#else
typedef ubyte4 vlong_unit;
#endif

/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
/* Overview */

/* Computers have 32- or 64-bit registers. Older ones had 16-bit registers, and
 * some small devices have 8-bit registers. These registers can hold integer
 * values on which operations such as add, multiply, divide, and so on are
 * performed. So if you want to multiply 14 by 86, put 14 into a register, 86
 * into another, then call the mul instruction.
 *    loadi   r0, $14
 *    loadi   r2, $86
 *    mulw    r0, r2   # r0 <- r0 * r2
 * But what if you have two 1024-bit numbers? No computer has a 1024-bit
 * register, so how can you perform a multiplication operation? The answer is
 * "multi-precision arithmetic".
 * Think of decimal multiplication on pencil and paper.
 *          86
 *        x 14
 *       ------
 *         344       4 x 6 -> 24, carry the 2, etc.
 *       + 86
 *       ------
 *        1204
 *
 * We can do pretty  much the same thing with 32-bit numbers.
 *                        -----------  -----------
 *                       | 32-bit A | | 32-bit B |
 *                       -----------  -----------
 *                        -----------  -----------
 *                     x | 32-bit C | | 32-bit D |
 *                       -----------  -----------
 *                     ----------------------------
 *                          ----------------------
 *                         |    64-bit D * B     |
 *                         ----------------------
 *                 ----------------------
 *                |    64-bit D * A     |
 *                ----------------------
 *                 ----------------------
 *                |    64-bit C * B     |
 *                ----------------------
 *        ----------------------
 *     + |    64-bit C * A     |
 *       ----------------------
 *    ---------------------------------------------
 *
 * So a multi-precision integer is simply an array of 32-bit (or 16-bit or
 * 64-bit) values.
 * That is the vlong. It is an "object" consisting of an array of 32-bit values,
 * along with information such as the number of values that make up the integer,
 * the space allocated, and the sign. The vlong uses the term "unit" for the
 * individual elements.
 * A vlong also contains a field to make a linked list of vlongs. We'll talk
 * about that under vlongQueue.
 * Then there are functions that operate on these objects.
 * Incidentally, apparently "vlong" stands for "very long".
 *
 * Canonical Format
 * ----------------
 * For the purpose of vlong, we'll define a canonical integer as a byte array
 * representation of an integer with the most significant byte at position 0 and
 * the least significant byte at position length - 1.
 * For example, look at these numbers
 *       decimal        hex      byte array
 *   -------------------------------
 *              19      0x13      13
 *             191      0xBF      BF
 *          18,947     0x4A03     4A 03
 *   1,386,823,099   0x52A93DBB   52 A9 3D BB
 *
 * Most of the time, we will need to "convert" between canonical format to vlong
 * and back. For example, an RSA public key consists of a modulus (2048 bits long
 * or longer) and an exponent. Inside a certificate, those values are represented
 * as canonical integers. When we want to load up an RSA public key from a cert,
 * we'll convert the integers to vlongs so that we can operate on them.
 *
 * vlongQueue
 * ----------
 * Many operations need temporary vlongs. You might have to create 3 or 4 vlongs
 * as intermediate values. If so, you can use the vlongQueue. This is a "pool" of
 * sorts. Just as there are memory pools and socket connection pools, there is a
 * vlong pool. If you have a vlongQueue, this can save time and possibly space.
 * Every time you need a new vlong, instead of allocating space for the vlong
 * shell and the array of units, just grab a pre-built vlong from the queue. When
 * you're done with it, instead of freeing the memory, just put it back onto the
 * queue.
 * Here's an example of using a queue.
 *
 *     MSTATUS status;
 *     RSAKey *newPair = NULL;
 *     vlong *queue = NULL;
 *
 *     status = RSA_createKey (&newPair);
 *     if (OK != status)
 *       goto exit;
 *
 *     status = RSA_generateKey (
 *       randCtx, newPair, bitLen, &queue);
 *     if (OK != status)
 *       goto exit;
 *
 *   exit:
 *
 *     RSA_freeKey (&newPair, &queue);
 *     VLONG_freeVlongQueue (&queue);
 *
 * Here's another example.
 *
 *     MSTATUS status;
 *     vlong *base = NULL;
 *     vlong *expo = NULL;
 *     vlong *mod = NULL;
 *     vlong *result = NULL;
 *     vlong *queue = NULL;
 *
 *      <set up a mod exp, load base, exponent, and modulus>
 *
 *     status = VLONG_modexp (
 *       base, expo, mod, &result, &queue);
 *     if (OK != status)
 *       goto exit;
 *
 *   exit:
 *
 *     VLONG_freeVlong (&base, &queue);
 *     VLONG_freeVlong (&expo, &queue);
 *     VLONG_freeVlong (&mod, &queue);
 *     VLONG_freeVlong (&result, &queue);
 *     VLONG_freeVlongQueue (&queue);
 *
 * Notice that you still have to call freeVlong on any vlong you yourself create.
 * And you created it if you called VLONG_allocVlong or some other routine (such
 * as VLONG_modexp or VLONG_vlongFromByteString) that creates a new vlong as the
 * result. It could very well be that the vlong you created really came from the
 * queue, but you still have to call the free.
 * If you call freeVlong and pass in a queue, the free function will simply put
 * the vlong back onto the queue. When you call freeVlongQueue, then all the
 * vlongs in that queue will be freed for real.
 * This means that if you call freeVlong and pass in a NULL queue, then the vlong
 * will be freed for real instead of placed back onto the queue.
 * Think of it this way. When a new vlong is created, the create function can get
 * one from the queue. At that point, the queue no longer knows about that vlong.
 * When a vlong is freed, it is returned to the queue. When the queue is freed,
 * all those vlongs it knows about will be freed. Hence, it is safe to get a
 * vlong from the queue, then free it without the queue. It's not likely to be
 * something you will do, but it is possible.
 * And remember, the queue most likely contains many vlongs created as
 * intermediate values, so even if you free all the vlongs you yourself created,
 * and free them without referencing the queue, you still must call
 * freeVlongQueue.
 */

/** A vlong is really an array of words. Each word might be a 32-bit or 64-bit
 * integer. In vlong, a word is called a vlong_unit. Depending on the platform, a
 * unit can be defined to be 16, 32, or 64 bits.
 * <p>The numUnitsUsed is the number of units that make up the current value of
 * the vlong. For example, to represent the number 2, one needs only one unit, so
 * the numUnitsUsed would be 1.
 * <p>The numUnitsAllocated is the number of units available for use. For
 * example, suppose you have a number where numUnitsUsed is 16. Then you add to
 * it another vlong, and suppose the result has carry and you now need 17 units
 * to represent the value. Look at numUnitsAllocated. If it is 16, you know you
 * need to reallocate the array of units. If it is, say 20, you know you have
 * enough space, just set the next unit to the carry value.
 * <p>The field negative is TRUE (nonzero) or FALSE (zero). If FALSE (0), the
 * number is positive.
 * <p>The pNextVlong field is for the vlongQueue. A queue is simply a linked list
 * of vlongs. This field is how the link list is linked.
 */
typedef struct vlong /* Provides storage allocation and index checking */
{
  vlong_unit    *pUnits;                 /* array of units */
  ubyte4         numUnitsAllocated;      /* units allocated */
  ubyte4         numUnitsUsed;           /* used units */
  intBoolean     negative;
  struct vlong  *pNextVlong;             /* used to chain vlong variables */
} vlong;

/* A vlong array of units is ordered from least significant word to most
 * significant word. For example, suppose a canonical integer is converted to
 * vlong.
 *    11 22 33 44 55 66 77 88
 *    pUnits[0] = 0x55667788
 *    pUnits[1] = 0x11223344
 * One reason to do this is operations generally start with low order words and
 * move up. For example, if you add two numbers, add the low order words first,
 * then add the carry plus the next two words, and so on. So start at index = 0
 * and increment. This also means we start both numbers at index 0 for the low
 * order word. If the numbers were in the other direction and one were shorter
 * than the other (one 6 words long, the other 11 words long), we would start one
 * at index 5 and the other at index 10.
 * Another reason is so that if there is carry (overflow), we just add another
 * word to the end of the array. For example, suppose the above vlong is A, and
 * this is a vlong called B.
 *   f0 11 11 11 00 00 00 00
 *   pUnits[0] = 0x00000000
 *   pUnits[1] = 0xf0111111
 * Now suppose we want to find A += B. The result is
 *   01 01 33 44 55 55 66 77 88
 *   pUnits[0] = 0x55667788
 *   pUnits[1] = 0x01334455
 *   pUnits[2] = 0x00000001
 */

/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
/* Preprocessor, Variable, and Type Declarations */

#ifdef __MOCANA_ENABLE_LONG_LONG__
#ifdef __MOCANA_ENABLE_64_BIT__
#error "Mocana: cannot define both __MOCANA_ENABLE_LONG_LONG__ and __MOCANA_ENABLE_64_BIT__"
#endif
#ifndef __RTOS_WIN32__
#define UBYTE8  unsigned long long
#else
#define UBYTE8  unsigned __int64
#endif
#endif

/*----------------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_SMALL_CODE_FOOTPRINT__
#ifndef __DISABLE_MOCANA_MODEXP_SLIDING_WINDOW__
#define __DISABLE_MOCANA_MODEXP_SLIDING_WINDOW__
#endif
#ifndef __DISABLE_MOCANA_BARRETT__
#define __DISABLE_MOCANA_BARRETT__
#endif
#ifndef __DISABLE_MOCANA_KARATSUBA__
#define __DISABLE_MOCANA_KARATSUBA__
#endif
#endif

/*----------------------------------------------------------------------------*/

/* Macros used to abstract operations */
#define BPU     (8 * sizeof(vlong_unit))        /* bits per unit */
#define HALF_MASK         (((vlong_unit)1) << (BPU-1))
#define LO_MASK           ((((vlong_unit)1)<<(BPU/2))-1)
#define HI_MASK           (~(LO_MASK))
#define LO_HUNIT(x)       ((x) & LO_MASK)             /* lower half */
#define HI_HUNIT(x)       ((x) >> (BPU/2))            /* upper half */
#define MAKE_HI_HUNIT(x)  (((vlong_unit)(x)) << (BPU/2))  /* make upper half */
#define MAKE_UNIT(h,l)    (MAKE_HI_HUNIT(h) | ((vlong_unit)(l)))
#define ZERO_UNIT          ((vlong_unit)0)
#define FULL_MASK         (~ZERO_UNIT)

/*----------------------------------------------------------------------------*/

#ifndef VLONG_MAX_LENGTH
#define VLONG_MAX_LENGTH    (8192)
#endif

/*----------------------------------------------------------------------------*/

#define MUL_VLONG_UNIT(a0,a1,b0,b1) \
    {                               \
      vlong_unit p0,p1,t0;        \
      \
      p0   = (b0) * (a0);         \
      p1   = (b1) * (a0);         \
      t0   = (b0) * (a1);         \
      (a1) = (b1) * (a1);         \
      p1 += t0;                   \
      if (p1 < t0)                \
        a1+=MAKE_HI_HUNIT((vlong_unit)1); \
      a1 += HI_HUNIT(p1);         \
      t0  = MAKE_HI_HUNIT(p1);    \
      (a0)=(p0+t0);               \
      if ((a0) < t0)              \
        a1++;                   \
    }

/*----------------------------------------------------------------------------*/

#ifndef MULT_ADDC
#ifndef __MOCANA_ENABLE_LONG_LONG__
#define MULT_ADDC(a,b,index0,index1,result0,result1,result2) \
    {   vlong_unit a0, a1, b0, b1;                               \
    a0=LO_HUNIT(a[index0]); a1=HI_HUNIT(a[index0]);          \
    b0=LO_HUNIT(b[index1]); b1=HI_HUNIT(b[index1]);          \
    MUL_VLONG_UNIT(a0,a1,b0,b1);                             \
    result0 += a0; if (result0 < a0) a1++;                   \
    result1 += a1; if (result1 < a1) result2++;              \
    }
#else
#define MULT_ADDC(a,b,index0,index1,result0,result1,result2) \
    { \
      UBYTE8 result; \
      ubyte4 temp_result; \
      \
      result = ((UBYTE8)a[index0]) * ((UBYTE8)b[index1]); \
      temp_result = result0; \
      result0 += (ubyte4)(result); \
      if (result0 < temp_result) \
        if (0 == (++result1)) \
          result2++; \
      temp_result = result1; \
      result1 += (ubyte4)(result >> BPU); \
      if (result1 < temp_result) \
        result2++; \
    }
#endif /* ifndef __MOCANA_ENABLE_LONG_LONG__ */
#endif /* ifndef MULT_ADDC */

/*----------------------------------------------------------------------------*/

#ifndef MULT_ADDC1
#ifndef __MOCANA_ENABLE_LONG_LONG__
#define MULT_ADDC1(a,b,index0,index1,result0,result1) \
    { vlong_unit a0,a1,b0,b1;                         \
    a0=LO_HUNIT(a[index0]); a1=HI_HUNIT(a[index0]);   \
    b0=LO_HUNIT(b[index1]); b1=HI_HUNIT(b[index1]);   \
    MUL_VLONG_UNIT(a0,a1,b0,b1);                      \
    result0 += a0; if (result0 < a0) a1++;            \
    result1 += a1;}
#else
#define MULT_ADDC1(a,b,index0,index1,result0,result1) \
    { \
      UBYTE8 result; \
      ubyte4 temp_result; \
      \
      result = ((UBYTE8)a[index0]) * ((UBYTE8)b[index1]); \
      temp_result = result0; \
      result0 += (ubyte4)(result); \
      if (result0 < temp_result) \
        ++result1; \
      result1 += (ubyte4)(result >> 32); \
    }
#endif /* ifndef __MOCANA_ENABLE_LONG_LONG__ */
#endif /* ifndef MULT_ADDC1 */

/*----------------------------------------------------------------------------*/

#ifndef ADD_DOUBLE
#define ADD_DOUBLE( result0, result1, result2, half0, half1, half2) \
    { vlong_unit carry;                                                     \
    half2 <<= 1;  half2  += (half1 & HALF_MASK) ? 1 : 0;         \
    half1 <<= 1;  half1  += (half0 & HALF_MASK) ? 1 : 0;         \
    half0 <<= 1;                                                    \
    result0 += half0;     carry  = (result0 < half0) ? 1 : 0;       \
    result1 += carry;     carry  = (result1 < carry) ? 1 : 0;       \
    result1 += half1;     carry += (result1 < half1) ? 1 : 0;       \
    result2 += (carry + half2); }
#endif /* ifndef ADD_DOUBLE */

/*----------------------------------------------------------------------------*/

#ifndef MULT_ADDCX
#define MULT_ADDCX  MULT_ADDC
#endif

/*----------------------------------------------------------------------------*/

/* Definitions for efficient division, see VLONG_DoubleDiv for more info */
#ifdef __ENABLE_MOCANA_64_BIT__
typedef ubyte4 hvlong_unit;
#else
typedef ubyte2 hvlong_unit;
#endif

#define ELEM_0(a,i)   ((i >= 0)? a[i] : 0)

/*----------------------------------------------------------------------------*/

/* multiplication is so fast with altivec we are better off
computing the whole modular inverse of N instead of only its first
word -- this way we can use Altivec Multiplication instead of
multiplying word by word */
#ifdef __ALTIVEC__
#define NUM_MONTY_VLONG (4)
#define NUM_MW_VLONG (2)
#else
#define NUM_MONTY_VLONG (3)
#define NUM_MW_VLONG (1)
#endif

/* once initialized, is const and can be shared among threads */
typedef struct MontgomeryCtx
{
#ifndef __ALTIVEC__
  vlong_unit rho;
#endif
  vlong*  v[NUM_MONTY_VLONG];
} MontgomeryCtx;

#define MONTY_R(m)          ((m)->v[0])
#define MONTY_R1(m)         ((m)->v[1])
#define MONTY_N(m)          ((m)->v[2])
#ifdef __ALTIVEC__
#define MONTY_N1(m)         ((m)->v[3])
#endif

/* one per thread */
typedef struct MontgomeryWork
{
  vlong* vw[NUM_MW_VLONG];
} MontgomeryWork;

#define MW_T(mw)            ((mw)->vw[0])
#ifdef __ALTIVEC__
#define MW_K(mw)            ((mw)->vw[1])
#endif

/*----------------------------------------------------------------------------*/

/* Modular Exponentiation Caches */
typedef const struct MontgomeryCtx* CModExpHelper;
typedef struct MontgomeryCtx* ModExpHelper;

/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
/* Common */

/** Create an "empty" vlong.
 * <p>Supply the address of a vlong pointer, the function will go to that address
 * and deposit the new vlong.
 * <p>This function will try to find an existing vlong from the queue first. If
 * there is no queue (ppVlongQueue is NULL or there are no vlongs in the queue),
 * the function will allocate space for a new vlong shell (the vlong struct), but
 * will not allocate any units.
 * <p>Whether it gets a vlong from the queue or allocates a new one, it will
 * initialize negative to FALSE and numUnitsUsed to 0. This is an empty vlong.
 * However, the value of such a vlong is considered 0. Note that if the
 * numUnitsUsed is 1 and that one unit is 0x00000000, then that also is the value
 * of zero.
 * <p>If you call allocVlong, you must call freeVlong on the created object when
 * you are done with it. Call the free function even if you had called alloc with
 * a queue.
 *
 * @param ppRetVlongValue The address where the function will deposit the empty
 * vlong.
 * @param ppVlongQueue The queue to search for a prebuilt vlong. This can be NULL.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS VLONG_allocVlong (
  vlong **ppRetVlongValue,
  vlong **ppVlongQueue
  );

/** If ppVlongQueue is NULL, this function will free any memory created during
 * the construction and use of the given vlong. If ppVlongQueue is not NULL, this
 * function will place the given vlong onto the queue.
 * <p>The function will go to the address given by ppFreeVlong. If there is a
 * NULL at this address there is nothing to free and the function will return. If
 * there is something, it will take that vlong and place it onto the queue if
 * there is one, or it will free the memory if not. To free the memory is to free
 * the array of units (the pUnits field) and the shell (the vlong struct).
 * <p>The function will then set *ppFreeVlong to NULL.
 *
 * @param ppFreeVlong The address where the function will find the vlong to free.
 * @param ppVlongQueue A potential queue, this can be NULL.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS VLONG_freeVlong (
  vlong **ppFreeVlong,
  vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS VLONG_freeVlongQueue (
  vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS VLONG_reallocVlong (
  vlong *pThis,
  ubyte4 vlongNewLength
  );

MOC_EXTERN MSTATUS expandVlong (
  vlong *pThis,
  ubyte4 vlongNewLength
  );

MOC_EXTERN vlong_unit VLONG_getVlongUnit (
  const vlong *pThis,
  ubyte4 index
  );

MOC_EXTERN MSTATUS VLONG_setVlongUnit (
  vlong *pThis,
  ubyte4 index,
  vlong_unit unitValue
  );

MOC_EXTERN MSTATUS VLONG_clearVlong (
  vlong *pThis
  );

MOC_EXTERN intBoolean VLONG_isVlongZero (
  const vlong *pThis
  );

MOC_EXTERN intBoolean VLONG_isVlongBitSet (
  const vlong *pThis,
  ubyte4 testBit
  );

MOC_EXTERN MSTATUS VLONG_setVlongBit (
  vlong *pThis,
  ubyte4 setBit
  );

MOC_EXTERN MSTATUS assignUnsignedToVlong (
  vlong *pThis,
  vlong_unit x
  );

MOC_EXTERN MSTATUS copyUnsignedValue (
  vlong *pDest,
  const vlong *pSource
  );

MOC_EXTERN MSTATUS VLONG_copySignedValue (
  vlong *pDest,
  const vlong *pSource
  );

MOC_EXTERN ubyte4 VLONG_bitLength (
  const vlong *pThis
  );

#if !defined(ASM_BIT_LENGTH) && !defined(__ENABLE_MOCANA_64_BIT__)
# define BITLENGTH(w) MOC_BITLENGTH(w)
#else
MOC_EXTERN ubyte4 BITLENGTH (
  vlong_unit w
  );
#endif

/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
/* Conversion */

MOC_EXTERN MSTATUS VLONG_makeVlongFromUnsignedValue (
  vlong_unit value,
  vlong **ppRetVlong,
  vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS VLONG_makeVlongFromVlong (
  const vlong* pValue,
  vlong **ppRetVlong,
  vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS VLONG_vlongFromByteString (
  const ubyte* byteString,
  sbyte4 len,
  vlong **ppRetVlong,
  vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS VLONG_vlongFromUByte4String (
  const ubyte4 *pU4Str,
  ubyte4 len,
  vlong **ppNewVlong
  );

MOC_EXTERN MSTATUS VLONG_byteStringFromVlong (
  const vlong* pValue,
  ubyte* pDest,
  sbyte4* pRetLen
  );

MOC_EXTERN MSTATUS VLONG_fixedByteStringFromVlong (
  vlong* pValue,
  ubyte* pDest,
  sbyte4 fixedLength
  );

MOC_EXTERN MSTATUS VLONG_mpintByteStringFromVlong (
  const vlong* pValue,
  ubyte** ppDest,
  sbyte4* pRetLen
  );

MOC_EXTERN MSTATUS VLONG_newFromMpintBytes (
  const ubyte *pArray,
  ubyte4 bytesAvailable,
  vlong **ppNewVlong,
  ubyte4 *pRetNumBytesUsed,
  vlong **ppVlongQueue
  );

/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
/* Comparison */

MOC_EXTERN MSTATUS compareUnsignedVlongs (
  const vlong *pValueX,
  const vlong *pValueY
  );

MOC_EXTERN MSTATUS VLONG_compareUnsigned (
  const vlong* pTest,
  vlong_unit immValue
  );

MOC_EXTERN MSTATUS VLONG_compareSignedVlongs (
  const vlong *pValueX,
  const vlong* pValueY
  );

/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
/* Addition */

MOC_EXTERN MSTATUS addUnsignedVlongs (
  vlong *pSumAndValue,
  const vlong *pValue
  );

MOC_EXTERN MSTATUS VLONG_addSignedVlongs (
  vlong *pSumAndValue,
  const vlong *pValue,
  vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS VLONG_addImmediate (
  vlong *pThis,
  ubyte4 immVal,
  vlong **ppVlongQueue
  );

/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
/* Subtraction */

MOC_EXTERN MSTATUS subtractUnsignedVlongs (
  vlong *pResultAndValue,
  const vlong *pValue
  );

MOC_EXTERN MSTATUS VLONG_subtractSignedVlongs (
  vlong *pSumAndValue,
  const vlong *pValue,
  vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS VLONG_subtractImmediate (
  vlong *pThis,
  ubyte4 immVal,
  vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS operatorMinusSignedVlongs (
  vlong* pValueX,
  vlong* pValueY,
  vlong **ppSum,
  vlong **ppVlongQueue
  );

/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
/* Bit Shifting */

MOC_EXTERN MSTATUS shlVlong (
  vlong *pThis
  );

MOC_EXTERN MSTATUS VLONG_shlVlong (
  vlong *pThis
  );

MOC_EXTERN void shrVlong (
  vlong *pThis
  );

MOC_EXTERN MSTATUS VLONG_shrVlong (
  vlong *pThis
  );

MOC_EXTERN MSTATUS VLONG_shrXvlong (
  vlong *pThis,
  ubyte4 numBits
  );

MOC_EXTERN MSTATUS VLONG_shlXvlong (
  vlong *pThis,
  ubyte4 numBits
  );

/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
/* Division */

MOC_EXTERN MSTATUS VLONG_unsignedDivide (
  vlong *pQuotient,
  const vlong *pDividend,
  const vlong *pDivisor,
  vlong *pRemainder,
  vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS VLONG_operatorDivideSignedVlongs (
  const vlong* pDividend,
  const vlong* pDivisor,
  vlong **ppQuotient,
  vlong **ppVlongQueue
  );

/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
/* Multiplication */

MOC_EXTERN MSTATUS VLONG_vlongSignedMultiply (
  vlong *pProduct,
  const vlong *pFactorX,
  const vlong *pFactorY
  );

MOC_EXTERN MSTATUS VLONG_unsignedMultiply (
  vlong *pProduct,
  const vlong *pFactorX,
  const vlong *pFactorY
  );

MOC_EXTERN MSTATUS VLONG_vlongSignedSquare (
  vlong *pProduct,
  const vlong *pFactor
  );

MOC_EXTERN MSTATUS fastUnsignedMultiplyVlongs (
  vlong *pProduct,
  const vlong *pFactorX,
  const vlong *pFactorY,
  ubyte4 x_limit
  );

MOC_EXTERN MSTATUS fastUnsignedSqrVlong (
  vlong *pProduct,
  const vlong *pFactorSqrX,
  ubyte4 x_limit
  );

MOC_EXTERN MSTATUS fasterUnsignedMultiplyVlongs (
  vlong *pProduct,
  const vlong *pFactorA,
  const vlong *pFactorB,
  ubyte4 numUnits
  );

MOC_EXTERN MSTATUS fasterUnsignedSqrVlong (
  vlong *pProduct,
  const vlong *pFactorA,
  ubyte4 numUnits
  );

MOC_EXTERN MSTATUS operatorMultiplySignedVlongs (
  const vlong* pFactorX,
  const vlong* pFactorY,
  vlong **ppProduct,
  vlong **ppVlongQueue
  );

/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
/* Karatsuba */

MOC_EXTERN void karatsubaMultiply (
  vlong_unit *pProduct,
  const vlong_unit *pFactorA,
  const vlong_unit *pFactorB,
  vlong_unit *pWorkspace,
  sbyte4 n
  );

MOC_EXTERN void karatsubaSqr (
  vlong_unit *pProduct,
  const vlong_unit *pFactorA,
  vlong_unit *pWorkspace,
  sbyte4 n
  );

/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
/* Barrett */

MOC_EXTERN MSTATUS VLONG_barrettMultiply (
  vlong* pResult,
  const vlong* pX,
  const vlong* pY,
  const vlong* pM,
  const vlong* pMu,
  vlong** ppVlongQueue
  );

MOC_EXTERN MSTATUS VLONG_newBarrettMu (
  vlong** ppMu,
  const vlong* m,
  vlong** ppVlongQueue
  );

MOC_EXTERN MSTATUS VLONG_modexp_barrett (
  MOC_MOD(hwAccelDescr hwAccelCtx) const vlong *x,
  const vlong *e,
  const vlong *n,
  vlong **ppRet,
  vlong **ppVlongQueue
  );

/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
/* Montgomery */

MOC_EXTERN MSTATUS VLONG_newModExpHelper (
  MOC_MOD(hwAccelDescr hwAccelCtx) ModExpHelper* pMEH,
  const vlong* m,
  vlong** ppVlongQueue
  );

MOC_EXTERN MSTATUS VLONG_deleteModExpHelper(
  ModExpHelper* pMEH,
  vlong** ppVlongQueue
  );

MOC_EXTERN MSTATUS VLONG_makeModExpHelperFromModExpHelper (
  CModExpHelper meh,
  ModExpHelper* pMEH,
  vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS VLONG_modexp_montgomery (
  MOC_MOD(hwAccelDescr hwAccelCtx) const vlong *x,
  const vlong *e,
  const vlong *n,
  vlong **ppRetModExp,
  vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS VLONG_montgomeryExp (
  MOC_MOD(hwAccelDescr hwAccelCtx) const MontgomeryCtx *pMonty,
  const vlong *x,
  const vlong *e,
  vlong **ppRetMontyExp,
  vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS VLONG_montgomeryExpBin (
  MOC_MOD(hwAccelDescr hwAccelCtx) const MontgomeryCtx *pMonty,
  const vlong *x,
  const vlong *e,
  vlong **ppRetMontyExp,
  vlong **ppVlongQueue
  );

/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
/* Modular Exponentiation */

MOC_EXTERN MSTATUS VLONG_modexp (
  MOC_MOD(hwAccelDescr hwAccelCtx) const vlong *x,
  const vlong *e,
  const vlong *n,
  vlong **ppRet,
  vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS VLONG_modExp (
  MOC_MOD(hwAccelDescr hwAccelCtx) CModExpHelper meh,
  const vlong *x,
  const vlong *e,
  vlong **ppRetModExp,
  vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS VLONG_modexp_classic (
  MOC_MOD(hwAccelDescr hwAccelCtx) const vlong *x,
  const vlong *e,
  const vlong *n,
  vlong **ppRet,
  vlong **ppVlongQueue
  );

/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
/* Modular Inverse */

MOC_EXTERN MSTATUS VLONG_modularInverse (
  MOC_MOD(hwAccelDescr hwAccelCtx) const vlong *pA,
  const vlong *pModulus,
  vlong **ppRetModularInverse,
  vlong **ppVlongQueue
  );

/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
/* GCD */

MOC_EXTERN MSTATUS VLONG_greatestCommonDenominator (
  MOC_MOD(hwAccelDescr hwAccelCtx) const vlong *pValueX,
  const vlong *pValueY,
  vlong **ppGcd,
  vlong **ppVlongQueue
  );

/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
/* Miscellaneous */

MOC_EXTERN MSTATUS VLONG_makeRandomVlong (
  void *pRandomContext,
  vlong **ppRetPrime,
  ubyte4 numBitsLong,
  vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS VLONG_N_mod_2powX (
  vlong *pThis,
  ubyte4 X
  );

MOC_EXTERN MSTATUS VLONG_operatorModSignedVlongs (
  MOC_MOD(hwAccelDescr hwAccelCtx) const vlong* pDividend,
  const vlong* pDivisor,
  vlong **ppRemainder,
  vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS VLONG_increment (
  vlong *pThis,
  vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS VLONG_decrement (
  vlong *pThis,
  vlong **ppVlongQueue
  );

#ifdef __cplusplus
}
#endif

#endif /* __VLONG_HEADER__ */
