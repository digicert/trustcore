/**
 * @file  vlong_const.c
 * @brief Very Long Integer Library Header Constant Time arithmetic
 *
 * Copyright Digicert 2023. All Rights Reserved.
 * Proprietary and Confidential Material.
 */

#if defined(__RTOS_THREADX__) && !defined(__RTOS_AZURE__)
#include "common/moptions.h"
#else
#include "../../common/moptions.h"
#endif

#ifdef __ENABLE_MOCANA_VLONG_CONST_TIME__

#if defined(__RTOS_THREADX__) && !defined(__RTOS_AZURE__)
#include "common/vlong.h"
#include "common/vlong_const.h"
#else
#include "../../common/vlong.h"
#include "../../common/vlong_const.h"
#endif

/* undefine and redefine macros tweaked here to ensure constant time ops. */
#undef MUL_VLONG_UNIT
#undef MULT_ADDCX
#undef MULT_ADDC1
#undef ADD_DOUBLE

#define MUL_VLONG_UNIT(a0,a1,b0,b1) \
    {                               \
      vlong_unit p0,p1,t0;        \
      \
      p0   = (b0) * (a0);         \
      p1   = (b1) * (a0);         \
      t0   = (b0) * (a1);         \
      (a1) = (b1) * (a1);         \
      p1 += t0;                   \
      a1 += MAKE_HI_HUNIT((vlong_unit)(p1 < t0)); \
      a1 += HI_HUNIT(p1);         \
      t0  = MAKE_HI_HUNIT(p1);    \
      (a0)=(p0+t0);               \
      a1 += ((a0) < t0);          \
    }

/*----------------------------------------------------------------------------*/

#ifndef __MOCANA_ENABLE_LONG_LONG__
#define MULT_ADDCX(a,b,index0,index1,result0,result1,result2) \
    {   vlong_unit a0, a1, b0, b1;                               \
    a0=LO_HUNIT(a[index0]); a1=HI_HUNIT(a[index0]);          \
    b0=LO_HUNIT(b[index1]); b1=HI_HUNIT(b[index1]);          \
    MUL_VLONG_UNIT(a0,a1,b0,b1);                             \
    result0 += a0; a1 += (result0 < a0);                     \
    result1 += a1; result2 += (result1 < a1);                \
    }
#else
#define MULT_ADDCX(a,b,index0,index1,result0,result1,result2) \
    { \
      UBYTE8 result; \
      ubyte4 temp_result; \
      \
      result = ((UBYTE8)a[index0]) * ((UBYTE8)b[index1]); \
      temp_result = result0; \
      result0 += (ubyte4)(result); \
      result2 += ((result0 < temp_result) && (0 == (++result1))); \
      temp_result = result1; \
      result1 += (ubyte4)(result >> BPU); \
      result2 += (result1 < temp_result); \
    }
#endif /* ifndef __MOCANA_ENABLE_LONG_LONG__ */

/*----------------------------------------------------------------------------*/

#ifndef __MOCANA_ENABLE_LONG_LONG__
#define MULT_ADDC1(a,b,index0,index1,result0,result1) \
    { vlong_unit a0,a1,b0,b1;                         \
    a0=LO_HUNIT(a[index0]); a1=HI_HUNIT(a[index0]);   \
    b0=LO_HUNIT(b[index1]); b1=HI_HUNIT(b[index1]);   \
    MUL_VLONG_UNIT(a0,a1,b0,b1);                      \
    result0 += a0; a1 += (result0 < a0);              \
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
      result1 += (result0 < temp_result); \
      result1 += (ubyte4)(result >> 32); \
    }
#endif /* ifndef __MOCANA_ENABLE_LONG_LONG__ */

/*----------------------------------------------------------------------------*/

#define ADD_DOUBLE( result0, result1, result2, half0, half1, half2) \
    { vlong_unit carry;                                                     \
    half2 <<= 1;  half2  += (0 != (half1 & HALF_MASK));     \
    half1 <<= 1;  half1  += (0 != (half0 & HALF_MASK));     \
    half0 <<= 1;                                            \
    result0 += half0;     carry  = (result0 < half0);       \
    result1 += carry;     carry  = (result1 < carry);       \
    result1 += half1;     carry += (result1 < half1);       \
    result2 += (carry + half2); }

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_allocVlongZero (
  vlong **ppNew,
  ubyte4 vlongNewLength,
  vlong **ppVlongQueue
  )
{
  MSTATUS status;
  vlong *pNew = NULL;
  vlong_unit *pNewArrayUnits;
  ubyte4 allocLen = vlongNewLength + 1;  /* we'll keep the +1 and padding as in expandVlong */
  ubyte4 i;

  /* used as an internal method, no NULL checks */

  status = VLONG_allocVlong(&pNew, ppVlongQueue);
  if (OK != status)
     goto exit;

#if defined(__ALTIVEC__) || defined(__SSE2__)
  allocLen = MOC_PAD(allocLen, 4);
#elif defined(__ARM_NEON__) || defined(__ARM_V6__)
  allocLen = MOC_PAD(allocLen, 2);
#endif

  status = UNITS_MALLOC(((void **)&pNewArrayUnits), (allocLen * sizeof(vlong_unit)));
  if (OK != status)
    goto exit;

  if (NULL != pNew->pUnits)
  {
    UNITS_FREE(((void **)&(pNew->pUnits)));
  }
  
  for (i = 0; i < allocLen; i++)
  {
    pNewArrayUnits[i] = ZERO_UNIT;
  }

  pNew->pUnits = pNewArrayUnits;
  pNew->numUnitsAllocated = allocLen;
  pNew->numUnitsUsed = vlongNewLength; /* we will "use" all the zero words in order to keep const time */

  *ppNew = pNew; pNew = NULL;

exit:

  /* UNITS_MALLOC is last goto exit condition, no cleanup needed of units */
  if (NULL != pNew)
  {
    (void) VLONG_freeVlong(&pNew, ppVlongQueue);
  }

  return status;
}

/*----------------------------------------------------------------------------*/

/* returns 1 if pA < pB and 0 otherwise */
MOC_EXTERN vlong_unit VLONG_constTimeCmp (
  vlong_unit *pA,
  vlong_unit *pB,
  ubyte4 numUnits
  )
{ 
  /* used as an internal method, no NULL checks, we assume both A, B and R have same number of units */
  vlong_unit result = ZERO_UNIT;
  vlong_unit running_cmp = (vlong_unit) 1;
  vlong_unit this_cmp;

  while (numUnits)
  {
    numUnits--;
    
    this_cmp = (pA[numUnits] < pB[numUnits]) & running_cmp;
    running_cmp &= (pA[numUnits] == pB[numUnits]);
    result |= this_cmp;
  }

  return result & FULL_MASK;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN vlong_unit VLONG_constTimeAdd (
  vlong_unit *pR,
  vlong_unit *pA,
  vlong_unit *pB, 
  ubyte4 numUnits
  )
{
  /* used as an internal method, no NULL checks, we assume both A, B and R have same number of units */
  vlong_unit temp1, temp2, carry = ZERO_UNIT;

  /* For typical RSA uses the number of units will be divisible by 8 */
#ifndef __ENABLE_MOCANA_SMALL_CODE_FOOTPRINT__
  while (numUnits & ~0x7)
  {
    temp1 = pA[0];
    temp1 = (temp1 + carry) & FULL_MASK;
    carry = (temp1 < carry);
    temp2 = (temp1 + pB[0]) & FULL_MASK;
    carry += (temp2 < temp1);
    pR[0] = temp2;

    temp1 = pA[1];
    temp1 = (temp1 + carry) & FULL_MASK;
    carry = (temp1 < carry);
    temp2 = (temp1 + pB[1]) & FULL_MASK;
    carry += (temp2 < temp1);
    pR[1] = temp2;
      
    temp1 = pA[2];
    temp1 = (temp1 + carry) & FULL_MASK;
    carry = (temp1 < carry);
    temp2 = (temp1 + pB[2]) & FULL_MASK;
    carry += (temp2 < temp1);
    pR[2] = temp2;

    temp1 = pA[3];
    temp1 = (temp1 + carry) & FULL_MASK;
    carry = (temp1 < carry);
    temp2 = (temp1 + pB[3]) & FULL_MASK;
    carry += (temp2 < temp1);
    pR[3] = temp2;

    temp1 = pA[4];
    temp1 = (temp1 + carry) & FULL_MASK;
    carry = (temp1 < carry);
    temp2 = (temp1 + pB[4]) & FULL_MASK;
    carry += (temp2 < temp1);
    pR[4] = temp2;

    temp1 = pA[5];
    temp1 = (temp1 + carry) & FULL_MASK;
    carry = (temp1 < carry);
    temp2 = (temp1 + pB[5]) & FULL_MASK;
    carry += (temp2 < temp1);
    pR[5] = temp2;
      
    temp1 = pA[6];
    temp1 = (temp1 + carry) & FULL_MASK;
    carry = (temp1 < carry);
    temp2 = (temp1 + pB[6]) & FULL_MASK;
    carry += (temp2 < temp1);
    pR[6] = temp2;

    temp1 = pA[7];
    temp1 = (temp1 + carry) & FULL_MASK;
    carry = (temp1 < carry);
    temp2 = (temp1 + pB[7]) & FULL_MASK;
    carry += (temp2 < temp1);
    pR[7] = temp2;

    pA += 8;
    pB += 8;
    pR += 8;
    numUnits -= 8;
  }
#endif

  while (numUnits) 
  {
    temp1 = pA[0];
    temp1 = (temp1 + carry) & FULL_MASK;
    carry = (temp1 < carry);
    temp2 = (temp1 + pB[0]) & FULL_MASK;
    carry += (temp2 < temp1);
    pR[0] = temp2;
    pA++;
    pB++;
    pR++;
    numUnits--;
  }

  return carry;
}

/**********************************************************************************/

MOC_EXTERN vlong_unit VLONG_constTimeSubtract (
  vlong_unit *pR,
  vlong_unit *pA,
  vlong_unit *pB, 
  ubyte4 numUnits
  )
{
  /* used as an internal method, no NULL checks, we assume both A, B and R have same number of units */
  vlong_unit temp1, temp2, borrow = ZERO_UNIT;

  /* For typical RSA uses the number of units will be divisible by 8 */
#ifndef __ENABLE_MOCANA_SMALL_CODE_FOOTPRINT__
  while (numUnits & ~0x7)
  {
    temp1 = pA[0];
    temp2 = (temp1 - borrow) & FULL_MASK;
    borrow  = (temp2 > temp1);
    temp1 = pB[0];
    temp1 = (temp2 - temp1) & FULL_MASK;
    pR[0] = temp1;
    borrow += (temp1 > temp2);

    temp1 = pA[1];
    temp2 = (temp1 - borrow) & FULL_MASK;
    borrow  = (temp2 > temp1);
    temp1 = pB[1];
    temp1 = (temp2 - temp1) & FULL_MASK;
    pR[1] = temp1;
    borrow += (temp1 > temp2);

    temp1 = pA[2];
    temp2 = (temp1 - borrow) & FULL_MASK;
    borrow  = (temp2 > temp1);
    temp1 = pB[2];
    temp1 = (temp2 - temp1) & FULL_MASK;
    pR[2] = temp1;
    borrow += (temp1 > temp2);

    temp1 = pA[3];
    temp2 = (temp1 - borrow) & FULL_MASK;
    borrow  = (temp2 > temp1);
    temp1 = pB[3];
    temp1 = (temp2 - temp1) & FULL_MASK;
    pR[3] = temp1;
    borrow += (temp1 > temp2);

    temp1 = pA[4];
    temp2 = (temp1 - borrow) & FULL_MASK;
    borrow  = (temp2 > temp1);
    temp1 = pB[4];
    temp1 = (temp2 - temp1) & FULL_MASK;
    pR[4] = temp1;
    borrow += (temp1 > temp2);

    temp1 = pA[5];
    temp2 = (temp1 - borrow) & FULL_MASK;
    borrow  = (temp2 > temp1);
    temp1 = pB[5];
    temp1 = (temp2 - temp1) & FULL_MASK;
    pR[5] = temp1;
    borrow += (temp1 > temp2);

    temp1 = pA[6];
    temp2 = (temp1 - borrow) & FULL_MASK;
    borrow  = (temp2 > temp1);
    temp1 = pB[6];
    temp1 = (temp2 - temp1) & FULL_MASK;
    pR[6] = temp1;
    borrow += (temp1 > temp2);

    temp1 = pA[7];
    temp2 = (temp1 - borrow) & FULL_MASK;
    borrow  = (temp2 > temp1);
    temp1 = pB[7];
    temp1 = (temp2 - temp1) & FULL_MASK;
    pR[7] = temp1;
    borrow += (temp1 > temp2);

    pA += 8;
    pB += 8;
    pR += 8;
    numUnits -= 8;
  }
#endif

  while (numUnits) 
  {
    temp1 = pA[0];
    temp2 = (temp1 - borrow) & FULL_MASK;
    borrow  = (temp2 > temp1);
    temp1 = pB[0];
    temp1 = (temp2 - temp1) & FULL_MASK;
    pR[0] = temp1;
    borrow += (temp1 > temp2);
    pA++;
    pB++;
    pR++;
    numUnits--;
  }

  return borrow;
}

/**********************************************************************************/

MOC_EXTERN void VLONG_constTimeMultiply (
  vlong_unit *pRes,
  ubyte4 resLen,
  vlong_unit *pX,
  ubyte4 xLen,
  vlong_unit *pY,
  ubyte4 yLen
  )
{
  /* used as an internal method, no NULL checks, we assume each input array has enough space */
  vlong_unit result0 = 0, result1 = 0, result2 = 0;
  ubyte4 i, j, x;
  ubyte4 j_upper;

  /* modify to highest index */
  xLen--;
  yLen--;

  for (x = 0; x < resLen; x++)
  {
    i = (x <= xLen) ? x : xLen;
    j = x - i;

    j_upper = ((x <= yLen) ? x : yLen);

    while (j <= j_upper)
    {
      /* result2:result1:result0 += pX[i] * pY[j]; */
      MULT_ADDCX(pX, pY, i, j, result0, result1, result2);
      i--;
      j++;
    }

    *pRes++ = result0;

    result0 = result1;
    result1 = result2;
    result2 = 0;
  }
}

/**********************************************************************************/

MOC_EXTERN void VLONG_constTimeSquare (
  vlong_unit *pRes,
  ubyte4 resLen,
  vlong_unit *pX,
  ubyte4 xLen
  )
{
  /* used as an internal method, no NULL checks, we assume each input array has enough space */
  vlong_unit result0 = 0, result1 = 0, result2 = 0;
  vlong_unit half0, half1, half2;
  ubyte4 i, j, x;

  /* modify to highest index */
  xLen--;

  for (x = 0; x < resLen; x++)
  {
    half0 = half1 = half2 = 0;

    i = (x <= xLen) ? x : xLen;
    j = x - i;

    while (j < i)
    {
      /* result2:result1:result0 += pX[i] * pX[j]; */
      MULT_ADDCX(pX, pX, i, j, half0, half1, half2);
      i--;
      j++;
    }

    ADD_DOUBLE(result0, result1, result2, half0, half1, half2);

    /* add odd-even case */
    if (i == j)
    {
      MULT_ADDCX(pX, pX, i, j, result0, result1, result2);
    }

    *pRes++ = result0;

    result0 = result1;
    result1 = result2;
    result2 = 0;
  }  
}

/**********************************************************************************/

static ubyte4 VLONG_constTimeBitlen(vlong_unit in)
{
    vlong_unit temp, mask;
    ubyte4 bits = (in != 0);

#ifdef __ENABLE_MOCANA_64_BIT__
    temp = in >> 32;
    mask = (0 - temp) & FULL_MASK;
    mask = (0 - (mask >> (BPU - 1)));
    bits += 32 & mask;
    in ^= (temp ^ in) & mask;
#endif

    temp = in >> 16;
    mask = (0 - temp) & FULL_MASK;
    mask = (0 - (mask >> (BPU - 1)));
    bits += 16 & mask;
    in ^= (temp ^ in) & mask;

    temp = in >> 8;
    mask = (0 - temp) & FULL_MASK;
    mask = (0 - (mask >> (BPU - 1)));
    bits += 8 & mask;
    in ^= (temp ^ in) & mask;

    temp = in >> 4;
    mask = (0 - temp) & FULL_MASK;
    mask = (0 - (mask >> (BPU - 1)));
    bits += 4 & mask;
    in ^= (temp ^ in) & mask;

    temp = in >> 2;
    mask = (0 - temp) & FULL_MASK;
    mask = (0 - (mask >> (BPU - 1)));
    bits += 2 & mask;
    in ^= (temp ^ in) & mask;

    temp = in >> 1;
    mask = (0 - temp) & FULL_MASK;
    mask = (0 - (mask >> (BPU - 1)));
    bits += 1 & mask;

    return bits;
}

/**********************************************************************************/

/* pIn has to have non-zero most significant word (ie index inLen - 1)*/
static ubyte4 VLONG_leftAlign(vlong_unit *pIn, ubyte4 inLen)
{
    vlong_unit temp;
    vlong_unit borrow = ZERO_UNIT;
    vlong_unit rmask;
    ubyte4 rshift, lshift, i;

    rshift = VLONG_constTimeBitlen(pIn[inLen - 1]);
    lshift = BPU - rshift;
    rshift %= BPU; /* in case rshift = BPU */
    rmask = ZERO_UNIT - rshift; 
    rmask |= rmask >> 8;

    for (i = 0; i < inLen; i++) 
    {
        temp = pIn[i];
        pIn[i] = ((temp << lshift) | borrow) & FULL_MASK;
        borrow = (temp >> rshift) & rmask;
    }

    return lshift;
}

/**********************************************************************************/

/* shift must be < BPU */
static void VLONG_constTimeRightShift(vlong_unit *pRes, vlong_unit *pA, ubyte4 aLen, ubyte4 shift)
{
    ubyte4 i, lshift;
    vlong_unit temp, borrow, lmask;

    lshift = BPU - shift;
    lshift %= BPU; /* in case shift = 0 */

    lmask = ZERO_UNIT - lshift; 
    lmask |= lmask >> 8;

    temp = pA[0];
    for (i = 0; i < aLen - 1; i++) 
    {
        borrow = pA[i + 1];
        pRes[i] = (temp >> shift) | ((borrow << lshift) & lmask);
        temp = borrow;
    }
    pRes[i] = borrow >> shift;
}

/**********************************************************************************/

/* Res must have one more byte than aLen of space, shift must be < BPU */
static void VLONG_constTimeLeftShift(vlong_unit *pRes, vlong_unit *pA, ubyte4 aLen, ubyte4 shift)
{
    ubyte4 i, rshift;
    vlong_unit temp, borrow, rmask;

    rshift = BPU - shift;
    rshift %= BPU; /* in case shift = 0 */

    rmask = ZERO_UNIT - rshift; 
    rmask |= rmask >> 8;

    temp = pA[aLen - 1];
    pRes[aLen] = (temp >> rshift) & rmask;

    for (i = aLen - 1; i > 0; i--) 
    {
        borrow = temp << shift;
        temp = pA[i - 1];
        pRes[i] = (borrow | ((temp >> rshift) & rmask)) & FULL_MASK;
    }
    pRes[0] = (temp << shift) & FULL_MASK;
}

/**********************************************************************************/

static inline vlong_unit VLONG_constTimeDoubleCmp(vlong_unit *pLHS, vlong_unit *pRHS)
{
    vlong_unit hiCmp = (vlong_unit) (pLHS[1] < pRHS[1]);
    vlong_unit loCmp1 = (vlong_unit) (pLHS[1] == pRHS[1]);
    vlong_unit loCmp2 = (vlong_unit) (pLHS[0] <= pRHS[0]);

    return (hiCmp | (loCmp1 & loCmp2)) & FULL_MASK;
}

/**********************************************************************************/

/* pDividend must be at least 1 index into the dividend as index -1 is accessed */
static vlong_unit VLONG_constTimeDiv3(vlong_unit *pDividend, vlong_unit nmsu, vlong_unit msu)
{
    vlong_unit pR[2];
    vlong_unit pD[2];
    vlong_unit mask;
    vlong_unit quotient = ZERO_UNIT;
    vlong_unit pTemp[2];
    ubyte4 i;

    pR[0] = pDividend[-1];
    pR[1] = pDividend[0];
    pD[0] = nmsu;
    pD[1] = msu;

    for (i = 0; i < BPU; i++) 
    {
        quotient <<= 1;
        mask = VLONG_constTimeDoubleCmp(pD, pR);
        quotient |= mask;

        mask = ZERO_UNIT - mask;

        pTemp[0] = pD[0] & mask;
        pTemp[1] = pD[1] & mask;

        (void) VLONG_constTimeSubtract (pR, pR, pTemp, 2);

        /* use mask again as temp var, shift D one left */
        mask = pD[1] & ((vlong_unit) 0x01);
        pD[1] >>= 1;
        pD[0] = ((pD[0] >> 1) | (mask << (BPU - 1))) & FULL_MASK;
    }

    mask = 0 - (quotient >> (BPU - 1));

    quotient <<= 1;
    quotient |= (VLONG_constTimeDoubleCmp(pD, pR));

    return (quotient | mask) & FULL_MASK;
}

/**********************************************************************************/

/* pQuotient may be NULL in which case just modular reduction is output
   Most significant word of pDivisor MUST be non-zero 
   Also dividendLen >= divisorLen must hold too */
MOC_EXTERN MSTATUS VLONG_constTimeDiv(
  vlong_unit *pQuotient,
  vlong_unit *pRemainder,
  vlong_unit *pDividend,
  ubyte4 dividendLen,
  vlong_unit *pDivisor,
  ubyte4 divisorLen
  )
{
  /* used as an internal method, no NULL checks, we assume each input array has enough space */
  MSTATUS status;
  ubyte4 shift, i, j; 

  /* left shifted divisor, left shifted dividend which has 1 more unit, and temp which has one more unit than divisorLen */
  ubyte4 scratchLen = (2 * divisorLen + dividendLen + 2);
  ubyte4 quoLen = 1 + dividendLen - divisorLen; /* shifted dividend len - shifted divisor len*/;

  vlong_unit *pScratch = NULL;
  vlong_unit *pDivisorShift;
  vlong_unit *pDividendShift;
  vlong_unit *pTemp;
  vlong_unit *pResPtr = (NULL == pQuotient) ? NULL : pQuotient + quoLen; /* We'll begin at the end */
  vlong_unit *pDividendPtr;
  vlong_unit *pDividendTopPtr;

  vlong_unit divisorMSU, divisorNMSU;

  status = MOC_MALLOC((void **) &pScratch, scratchLen * sizeof(vlong_unit));
  if (OK != status)
    goto exit;
    
  pDivisorShift = pScratch;
  pDividendShift = pScratch + divisorLen;
  pTemp = pScratch + divisorLen + dividendLen + 1;
  
  (void) MOC_MEMCPY((ubyte *) pDivisorShift, (ubyte *) pDivisor, divisorLen * sizeof(vlong_unit));

  shift = VLONG_leftAlign(pDivisorShift, divisorLen);
  VLONG_constTimeLeftShift(pDividendShift, pDividend, dividendLen, shift);

  pDividendPtr = pDividendShift + quoLen;
  pDividendTopPtr = pDividendShift + dividendLen; /* shifted dividend len, has extra unit */

  divisorMSU = pDivisorShift[divisorLen - 1];
  divisorNMSU = (1 == divisorLen) ? ZERO_UNIT : pDivisorShift[divisorLen - 2]; /* const time relative to divisorLen which is fixed */

  for (i = 0; i < quoLen; i++, pDividendTopPtr--) 
  {
    vlong_unit quotient, borrow;

    quotient = VLONG_constTimeDiv3(pDividendTopPtr, divisorNMSU, divisorMSU);
    VLONG_constTimeMultiply(pTemp, divisorLen + 1, pDivisorShift, divisorLen, &quotient, 1);

    pDividendPtr--;

    borrow = VLONG_constTimeSubtract(pDividendPtr, pDividendPtr, pTemp, divisorLen + 1);
    quotient -= borrow;
    for (borrow = ZERO_UNIT - borrow, j = 0; j < divisorLen; j++)
    {
      pTemp[j] = pDivisorShift[j] & borrow;
    }
    borrow = VLONG_constTimeAdd(pDividendPtr, pDividendPtr, pTemp, divisorLen);

    (*pDividendTopPtr) += borrow;

    if (NULL != pResPtr)
    {
      *--pResPtr = quotient;
    }
  }

  VLONG_constTimeRightShift(pRemainder, pDividendPtr, divisorLen, shift);

  /* Only goto exit is on MALLOC, ok to free before exit block */
  (void) MOC_MEMSET_FREE((ubyte **) &pScratch, scratchLen * sizeof(vlong_unit));

exit:

  return status;
}

/**********************************************************************************/

static void VLONG_constTimeMontyMultiply (
  const MontgomeryCtx *pMonty,
  vlong_unit* a, 
  vlong_unit* b,
  vlong_unit* pTUnits
  )
{
  const vlong *pModulus = MONTY_N(pMonty);
  vlong_unit rho = pMonty->rho;
  const vlong_unit *pModulusUnits = pModulus->pUnits;
  ubyte4 numModUnits;
  ubyte4 i, j;
  vlong_unit r0, r1, r2, m[1];
  vlong_unit borrow;
  ubyte4 shift;

  numModUnits = pModulus->numUnitsUsed;
  
  /* T = x*y */
  VLONG_constTimeMultiply (pTUnits, 2 * numModUnits, a, numModUnits, b, numModUnits);
  pTUnits[2 * numModUnits] = ZERO_UNIT;

  r2 = 0;
  for (i = 0; i < numModUnits; ++i)
  {
    r0 = 0;
    m[0] = pTUnits[i] * rho;
    for (j = 0; j < numModUnits; ++j)
    {
      /* r0 = t[i+j] + r0; */
      r0 += pTUnits[i + j];
      /* carry ? */
      r1 = (vlong_unit) (r0 < pTUnits[i + j]);
      /* r1:r0 +=  m * n[j] */
      MULT_ADDC1(pModulusUnits, m, j, 0, r0, r1);

      pTUnits[i + j] = r0;
      r0 = r1;
      r1 = 0;
    }
    r0 += r2;
    r2 = (vlong_unit) (r0 < r2);
    pTUnits[i + j] += r0;
    r2 += (pTUnits[i + j] < r0);
  }
  pTUnits[2 * numModUnits] += r2;

  /* always do the subtraction for protection against side channel attacks */
  borrow = 0;
  for (j = 0; j < numModUnits; ++j)
  {
    vlong_unit nunit = pModulusUnits[j];
    vlong_unit tunit = pTUnits[j + numModUnits];
    vlong_unit bbb = (vlong_unit) (tunit < borrow);

    pTUnits[j] = tunit - borrow;

    bbb += (vlong_unit) (pTUnits[j] < nunit);
    pTUnits[j] -= nunit;
    borrow = bbb;
  }

  shift = (pTUnits[2 * numModUnits] < borrow) ? numModUnits : 0;
  pTUnits += shift;

  /* we already assume A has numModUnits, we copy empty words if needbe */
  for (j = 0; j < numModUnits; ++j)
  {
    a[j] = pTUnits[j];
  }

}

/**********************************************************************************/

static void VLONG_constTimeMontySqr (
  const MontgomeryCtx *pMonty,
  vlong_unit *a, 
  vlong_unit *pTUnits
  )
{
  const vlong *pModulus = MONTY_N(pMonty);
  vlong_unit rho = pMonty->rho;
  const vlong_unit *pModulusUnits = pModulus->pUnits;
  ubyte4 numModUnits;
  ubyte4 i, j;
  vlong_unit r0, r1, r2, m[1];
  vlong_unit borrow;
  ubyte4 shift;

  numModUnits = pModulus->numUnitsUsed;

  /* T = x*x */
  VLONG_constTimeSquare (pTUnits, 2 * numModUnits, a, numModUnits);
  pTUnits[2 * numModUnits] = ZERO_UNIT;

  r2 = 0;
  for (i = 0; i < numModUnits; ++i)
  {
    r0 = 0;
    m[0] = pTUnits[i] * rho;
    for (j = 0; j < numModUnits; ++j)
    {
      /* r0 = t[i+j] + r0; */
      r0 += pTUnits[i + j];
      /* carry ? */
      r1 = (r0 < pTUnits[i + j]);
      /* r1:r0 +=  m * n[j] */
      MULT_ADDC1(pModulusUnits, m, j, 0, r0, r1);
      pTUnits[i + j] = r0;
      r0 = r1;
    }
    r0 += r2;
    r2 = (r0 < r2);
    pTUnits[i + j] += r0;
    r2 += (pTUnits[i + j] < r0);
  }
  pTUnits[2 * numModUnits] += r2;

  /* always do the subtraction for protection against side channel attacks */
  borrow = 0;
  for (j = 0; j < numModUnits; ++j)
  {
    vlong_unit nunit = pModulusUnits[j];
    vlong_unit tunit = pTUnits[j + numModUnits];
    vlong_unit bbb = (vlong_unit) (tunit < borrow);

    pTUnits[j] = tunit - borrow;

    bbb += (vlong_unit) (pTUnits[j] < nunit);
    pTUnits[j] -= nunit;
    borrow = bbb;
  }

  shift = (pTUnits[2 * numModUnits] < borrow) ? numModUnits : 0;
  pTUnits += shift;
  
  /* we already assume A has numModUnits, we copy empty words if needbe */
  for (j = 0; j < numModUnits; ++j)
  {
    a[j] = pTUnits[j];
  }
}

/**********************************************************************************/

/* pBase can be oversized. pResult is assumed to be modulus Len in units */
MOC_EXTERN MSTATUS VLONG_constTimeMontExp (
  MOC_MOD(hwAccelDescr hwAccelCtx) 
  MontgomeryCtx *pMonty,
  vlong *pBase,
  vlong *pExp, 
  vlong_unit *pResult
  )
{
  /* used as an internal method, no NULL checks, we assume each input array has enough space */
  ubyte4 bits = VLONG_bitLength(pExp);
  sbyte4 i;
  MSTATUS status;
  ubyte4 winSize; /* windowSize */
  ubyte4 tableSize;
  vlong_unit *pG = NULL; /* full table of vlongs */
  vlong_unit *pTemp;
  vlong_unit *pTUnits; /* Montgomery scratch work, 2 * modLen + 1 units */
  ubyte4 modLen;
  ubyte4 modByteLen;
  ubyte4 tmpLen;

  winSize = (bits > 671 ? 6 : bits > 239 ? 5 : bits > 79 ? 4 : bits > 23 ? 3 : 2);
  tableSize = (1 << (winSize - 1));

  modLen = MONTY_N(pMonty)->numUnitsUsed;
  modByteLen = modLen * sizeof(vlong_unit);
  tmpLen = MONTY_R(pMonty)->numUnitsUsed + pBase->numUnitsUsed;

  /* Allocate the entire table, extra temp space, and pTUnits in one-shot */
  if (OK > (status = MOC_MALLOC((void **) &pG, (unsigned long)(tableSize + 2) * modByteLen + (1 + tmpLen) * sizeof(vlong_unit))))
  {
    goto cleanup;
  }

  pTemp = pG + tableSize * modLen; /* pG is still type vlong_unit * */
  pTUnits = pTemp + tmpLen;
  
  /* result begins as an augmented 1, ie R */
  (void) MOC_MEMCPY((ubyte *) pResult, (ubyte *) (MONTY_R(pMonty)->pUnits), MONTY_R(pMonty)->numUnitsUsed * sizeof(vlong_unit));

  /* pad result if necc (almost never will be needed) */
  if (MONTY_R(pMonty)->numUnitsUsed < modLen)
  {
    (void) MOC_MEMSET((ubyte *) (pResult + MONTY_R(pMonty)->numUnitsUsed), 0x00, (modLen - MONTY_R(pMonty)->numUnitsUsed) * sizeof(vlong_unit));
  }

  /* g[0] = (x * R) % m */
  VLONG_constTimeMultiply (pTemp, tmpLen, MONTY_R(pMonty)->pUnits, MONTY_R(pMonty)->numUnitsUsed, 
                           pBase->pUnits, pBase->numUnitsUsed);

  if (OK > (status = VLONG_constTimeDiv(NULL, pG, pTemp, tmpLen, MONTY_N(pMonty)->pUnits, modLen)))
  {
    goto cleanup;
  }

  /* tmp = g[0] * g[0] */
  (void) MOC_MEMCPY((ubyte *)pTemp, (ubyte *)pG, modByteLen);

  VLONG_constTimeMontySqr(pMonty, pTemp, pTUnits);

  for (i = 1; i < (sbyte4) tableSize; i++)
  {
    /* copy g[i - 1] to g[i] */
    (void) MOC_MEMCPY((ubyte *) pG + i * modByteLen, (ubyte *) pG + (i - 1) * modByteLen, modByteLen);
    VLONG_constTimeMontyMultiply(pMonty, pG + i * modLen, pTemp, pTUnits);
  }

  i = (sbyte4) bits - 1;
  while (i >= 0)
  {
    if (!VLONG_isVlongBitSet(pExp, i))
    {

      VLONG_constTimeMontySqr(pMonty, pResult, pTUnits);
      --i;
    }
    else
    {
      /* find the longest bitstring of size <= window where last bit = 1 */
      sbyte4 j, L, index;

      index = 1; /* window value used as index for g[] */
      L = 1;     /* window length */

      if (i > 0)
      {
        sbyte4 max = (i + 1 < (sbyte4) winSize) ? i : (sbyte4) winSize;
       
        for (j = 1; j < max; ++j)
        {
          index <<= 1;
          if (VLONG_isVlongBitSet(pExp, i - j))
          {
            L = j + 1;
            index += 1;
          }
        }
        index >>= (max - L);
      }

      /* assert( index & 1); index should be odd! */

      for (j = 0; j < L; ++j)
      {
        VLONG_constTimeMontySqr(pMonty, pResult, pTUnits);
      }
      VLONG_constTimeMontyMultiply(pMonty, pResult, pG + (index >> 1) * modLen, pTUnits);

      i -= L;
    }
  }

  /* convert from Monty residue to "real" number */
  /* *ppRetMontyExp = (result * MONTY_R1(pMonty)) % MONTY_M(pMonty) */

  /* although pTemp has enough space assuming input x is sized correctly, we know for sure
     pG has at least 2 modular elements worth of space, so we re-use that as a temp */
  VLONG_constTimeMultiply (pG, modLen + MONTY_R1(pMonty)->numUnitsUsed, pResult, modLen, 
                           MONTY_R1(pMonty)->pUnits, MONTY_R1(pMonty)->numUnitsUsed);

  status = VLONG_constTimeDiv(NULL, pResult, pG, modLen + MONTY_R1(pMonty)->numUnitsUsed, MONTY_N(pMonty)->pUnits, modLen);

cleanup:

  if (NULL != pG)
  {
    (void) MOC_MEMSET_FREE((ubyte **) &pG, (unsigned long)(tableSize + 2) * modByteLen + (tmpLen + 1) * sizeof(vlong_unit));
  }

  return status;
}
#endif /* __ENABLE_MOCANA_VLONG_CONST_TIME__ */
