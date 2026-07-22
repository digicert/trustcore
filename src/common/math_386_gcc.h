/*
 * math_gcc_386.h
 *
 * Inline assembly macros for 80386+ Processor using GCC
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

/* vtype should be the same type as vlong_unit */
#ifdef __ENABLE_DIGICERT_64_BIT__
typedef ubyte8 vtype;
#else
typedef ubyte4 vtype;
#endif

/* Important note: DO NOT remove the dummy output constraint;
 "Because the way the constraints are implemented inside GCC, an input
 constraint cannot overlap with a clobber.  As input constraint can stay in
 the same register across the inline-asm so it does not make sense to have
 it as a clobber.  Use an output register that says it clobbers that
 register."
 */
#if defined(__ENABLE_DIGICERT_64_BIT__) && defined(__LP64__)

/*---------------------------------------------------------------------------*/

#define MULT_ADDC(base_a,base_b,index0,index1,result0,result1,result2)      \
{                                                                           \
    vtype dummy;                                                           \
    __asm __volatile (  "mulq   %5                          \n\t"           \
                        "addq   %4, %0                      \n\t"           \
                        "adcq   %%rdx, %1                   \n\t"           \
                        "adcq   $0x00, %2                   \n\t"           \
                        : "=r"(result0),"=r"(result1),"=r"(result2),        \
                          "=a"(dummy)                                       \
                        : "a"(base_a[index0]),"r"(base_b[index1]),          \
                          "0"(result0),"1"(result1),"2"(result2)            \
                        : "rdx", "cc" );                          \
}


#define MULT_ADDC1(base_a,base_b,index0,index1,result0,result1)             \
{                                                                           \
    vtype dummy;                                                           \
    __asm __volatile (  "mul   %4                          \n\t"            \
                        "add   %3, %0                      \n\t"            \
                        "adc   %%rdx, %1                   \n\t"            \
                        : "=r"(result0),"=r"(result1),"=a"(dummy)           \
                        : "a"(base_a[index0]),"r"(base_b[index1]),          \
                          "0"(result0),"1"(result1)                         \
                        : "rdx", "cc" );                          \
}

/*------------------------------------------------------------------*/


#define ADD_DOUBLE(result0, result1, result2, half0, half1, half2) \
{                                                                  \
__asm __volatile( "add %6, %6                          \n\t"       \
                  "adc %7, %7                          \n\t"       \
                  "adc %8, %8                          \n\t"       \
                  "add %6, %0                          \n\t"       \
                  "adc %7, %1                          \n\t"       \
                  "adc %8, %2                          \n\t"       \
                  : "=r"(result0), "=r"(result1), "=r"(result2)    \
                  : "0"(result0), "1"(result1), "2"(result2),      \
                    "r"(half0), "r"(half1), "r"(half2)             \
                  : "cc" );                               \
}


/*------------------------------------------------------------------*/

#define ASM_BIT_LENGTH( aWord, bitlen)                              \
{                                                                   \
__asm __volatile("bsr %1, %0                        \n\t"           \
                 "inc  %0                           \n\t"           \
                 : "=r"(bitlen)                                     \
                 : "r"(aWord)                                       \
                 : "cc"); }



/*------------------------------------------------------------------*/

#define MULT_ADDC32(base_a,base_b,index0,index1,result0,result1,result2) \
{                                                                        \
vtype dummy;                                                          \
__asm __volatile (  "mull  %5                          \n\t"           \
                    "addl  %%eax, %0                   \n\t"           \
                    "adcl  %%edx, %1                   \n\t"           \
                    "adcl  $0x00, %2                   \n\t"           \
                    : "=r"(result0),"=r"(result1),"=r"(result2),       \
                      "=a"(dummy)                                      \
                    : "a"(base_a[index0]),"r"(base_b[index1]),         \
                      "0"(result0),"1"(result1),"2"(result2)           \
                    : "edx", "cc" );                                   \
}



/* shift right assembly is no longer improving noticably the performance
   since the division is no longer implemented using it */

#else /*! __ENABLE_DIGICERT_64_BIT__ || ! __LP64__ */


/* 64 bit compiler but no __ENABLE_DIGICERT_64_BIT__ */
#if defined(__LP64__)


/*------------------------------------------------------------------*/

#define MULT_ADDC(base_a,base_b,index0,index1,result0,result1,result2) \
{                                                                      \
vtype dummy;                                                          \
__asm __volatile (  "mull  %5                          \n\t"           \
                    "addl  %%eax, %0                   \n\t"           \
                    "adcl  %%edx, %1                   \n\t"           \
                    "adcl  $0x00, %2                   \n\t"           \
                  : "=r"(result0),"=r"(result1),"=r"(result2),         \
                    "=a"(dummy)                                        \
                  : "a"(base_a[index0]),"r"(base_b[index1]),           \
                    "0"(result0),"1"(result1),"2"(result2)             \
                  : "edx", "cc" );                            \
}



/*------------------------------------------------------------------*/

#define ADD_DOUBLE(result0, result1, result2, half0, half1, half2) \
{                                                                  \
__asm __volatile( "addl %6, %6                          \n\t"      \
                  "adcl %7, %7                          \n\t"      \
                  "adcl %8, %8                          \n\t"      \
                  "addl %6, %0                          \n\t"      \
                  "adcl %7, %1                          \n\t"      \
                  "adcl %8, %2                          \n\t"      \
       : "=r"(result0), "=r"(result1), "=r"(result2)               \
       : "0"(result0), "1"(result1), "2"(result2),                 \
         "r"(half0), "r"(half1), "r"(half2)                        \
       : "cc");                                                    \
}


/* this does not work properly  when optimization turned to -O3 with
   GCC 4.1. Works with GCC 4.2 */

/*------------------------------------------------------------------*/

#define ASM_BIT_LENGTH( aWord, bitlen)                              \
{                                                                   \
__asm __volatile("bsrl %1, %0                        \n\t"          \
                 "incl %0                            \n\t"          \
                 : "=r"(bitlen)                                     \
                 : "r"(aWord)                                       \
                 : "cc" ); }


/*------------------------------------------------------------------*/



#else /*! __LP64__ */

/* GCC inline assembly is unstable, not to say buggy. Attempts to
report bugs to the GCC team were rebuffed. One should always
run some sanity tests to make sure the compiler works properly
*/


/*------------------------------------------------------------------*/

#define MULT_ADDC(base_a,base_b,index0,index1,result0,result1,result2) \
{                                                                      \
vtype dummy;                                                          \
__asm __volatile (  "mull   %5                          \n\t"          \
                    "addl   %4, %0                      \n\t"          \
                    "adcl   %%edx, %1                   \n\t"          \
                    "adcl   $0x00, %2                   \n\t"          \
                  : "=r"(result0),"=r"(result1),"=r"(result2),         \
                    "=a"(dummy)                                        \
                  : "a"(base_a[index0]),"r"(base_b[index1]),           \
                    "0"(result0),"1"(result1),"2"(result2)             \
                  : "edx", "cc" );                            \
}


/*------------------------------------------------------------------*/

#define MULT_ADDC1(base_a,base_b,index0,index1,result0,result1)        \
{                                                                      \
vtype dummy;                                                          \
__asm __volatile (  "mull   %4                          \n\t"          \
                    "addl   %3, %0                      \n\t"          \
                    "adcl   %%edx, %1                   \n\t"          \
                  : "=r"(result0),"=r"(result1),"=a"(dummy)            \
                  : "a"(base_a[index0]),"r"(base_b[index1]),           \
                    "0"(result0),"1"(result1)                          \
                  : "edx", "cc" );                          \
}


/*------------------------------------------------------------------*/

#define ADD_DOUBLE(result0, result1, result2, half0, half1, half2) \
{                                                                  \
__asm __volatile( "addl %6, %6                         \n\t"       \
                  "adcl %7, %7                         \n\t"       \
                  "adcl %8, %8                         \n\t"       \
                  "addl %6, %0                         \n\t"       \
                  "adcl %7, %1                         \n\t"       \
                  "adcl %8, %2                         \n\t"       \
       : "=r"(result0), "=r"(result1), "=r"(result2)               \
       : "0"(result0), "1"(result1), "2"(result2),                 \
         "r"(half0), "r"(half1), "r"(half2)                        \
       : "cc" );                                                   \
}




/*------------------------------------------------------------------*/

#define ASM_BIT_LENGTH( aWord, bitlen)                              \
{                                                                   \
__asm __volatile("bsrl %1, %0                        \n\t"          \
                 "incl  %0                           \n\t"          \
                 : "=r"(bitlen)                                     \
                 : "r"(aWord)                                       \
                 : "cc"); }

/* shift right assembly is no longer improving noticably the performance
   since the division is no longer implemented using it */

#ifdef __SSE2__

MOC_EXTERN void SSE2_multiply( ubyte4* pResult, ubyte4* pFactorA, ubyte4* pFactorB,
                           ubyte4 i_limit, ubyte4 j_limit, ubyte4 x_limit);


#define MACRO_MULTIPLICATION_LOOP(a,b,c,d,e,f) SSE2_multiply( a,b,c,d,e,f);


MOC_EXTERN void SSE2_square( ubyte4* pResult, ubyte4* pFactorA, ubyte4 i_limit,
                         ubyte4 x_limit);

#define MACRO_SQR_LOOP(a,b,c,d) SSE2_square(a,b,c,d)

#endif



#endif /* !__LP64__ */

#endif /* !__ENABLE_DIGICERT_64_BIT__ || !__LP64__ */
