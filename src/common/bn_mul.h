/*
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
/*
 *      Multiply source vector [s] with b, add result
 *       to destination vector [d] and set carry c.
 *
 *      Currently supports:
 *
 *         . IA-32 (386+)         . AMD64 / EM64T
 *         . IA-32 (SSE2)         . Motorola 68000
 *         . PowerPC, 32-bit      . MicroBlaze
 *         . PowerPC, 64-bit      . TriCore
 *         . SPARC v8             . ARM v3+
 *         . Alpha                . MIPS32
 *         . C, longlong          . C, generic
 */
#ifndef MOC_BN_MUL_H
#define MOC_BN_MUL_H

#ifndef asm
#define asm __asm
#endif

/* armcc5 --gnu defines __GNUC__ but doesn't support GNU's extended asm */
#if defined(__GNUC__) && \
    ( !defined(__ARMCC_VERSION) || __ARMCC_VERSION >= 6000000 )

/*
 * Disable use of the i386 assembly code below if option -O0, to disable all
 * compiler optimisations, is passed, detected with __OPTIMIZE__
 * This is done as the number of registers used in the assembly code doesn't
 * work with the -O0 option.
 */
#if defined(__i386__) && defined(__OPTIMIZE__)
#define

#define MOC_MULADDC_INIT                        \
    asm(                                    \
        "movl   %%ebx, %0           \n\t"   \
        "movl   %5, %%esi           \n\t"   \
        "movl   %6, %%edi           \n\t"   \
        "movl   %7, %%ecx           \n\t"   \
        "movl   %8, %%ebx           \n\t"

#define MOC_MULADDC_CORE                        \
        "lodsl                      \n\t"   \
        "mull   %%ebx               \n\t"   \
        "addl   %%ecx,   %%eax      \n\t"   \
        "adcl   $0,      %%edx      \n\t"   \
        "addl   (%%edi), %%eax      \n\t"   \
        "adcl   $0,      %%edx      \n\t"   \
        "movl   %%edx,   %%ecx      \n\t"   \
        "stosl                      \n\t"

#if defined(MOC_HAVE_SSE2)

#define MOC_MULADDC_HUIT                            \
        "movd     %%ecx,     %%mm1      \n\t"   \
        "movd     %%ebx,     %%mm0      \n\t"   \
        "movd     (%%edi),   %%mm3      \n\t"   \
        "paddq    %%mm3,     %%mm1      \n\t"   \
        "movd     (%%esi),   %%mm2      \n\t"   \
        "pmuludq  %%mm0,     %%mm2      \n\t"   \
        "movd     4(%%esi),  %%mm4      \n\t"   \
        "pmuludq  %%mm0,     %%mm4      \n\t"   \
        "movd     8(%%esi),  %%mm6      \n\t"   \
        "pmuludq  %%mm0,     %%mm6      \n\t"   \
        "movd     12(%%esi), %%mm7      \n\t"   \
        "pmuludq  %%mm0,     %%mm7      \n\t"   \
        "paddq    %%mm2,     %%mm1      \n\t"   \
        "movd     4(%%edi),  %%mm3      \n\t"   \
        "paddq    %%mm4,     %%mm3      \n\t"   \
        "movd     8(%%edi),  %%mm5      \n\t"   \
        "paddq    %%mm6,     %%mm5      \n\t"   \
        "movd     12(%%edi), %%mm4      \n\t"   \
        "paddq    %%mm4,     %%mm7      \n\t"   \
        "movd     %%mm1,     (%%edi)    \n\t"   \
        "movd     16(%%esi), %%mm2      \n\t"   \
        "pmuludq  %%mm0,     %%mm2      \n\t"   \
        "psrlq    $32,       %%mm1      \n\t"   \
        "movd     20(%%esi), %%mm4      \n\t"   \
        "pmuludq  %%mm0,     %%mm4      \n\t"   \
        "paddq    %%mm3,     %%mm1      \n\t"   \
        "movd     24(%%esi), %%mm6      \n\t"   \
        "pmuludq  %%mm0,     %%mm6      \n\t"   \
        "movd     %%mm1,     4(%%edi)   \n\t"   \
        "psrlq    $32,       %%mm1      \n\t"   \
        "movd     28(%%esi), %%mm3      \n\t"   \
        "pmuludq  %%mm0,     %%mm3      \n\t"   \
        "paddq    %%mm5,     %%mm1      \n\t"   \
        "movd     16(%%edi), %%mm5      \n\t"   \
        "paddq    %%mm5,     %%mm2      \n\t"   \
        "movd     %%mm1,     8(%%edi)   \n\t"   \
        "psrlq    $32,       %%mm1      \n\t"   \
        "paddq    %%mm7,     %%mm1      \n\t"   \
        "movd     20(%%edi), %%mm5      \n\t"   \
        "paddq    %%mm5,     %%mm4      \n\t"   \
        "movd     %%mm1,     12(%%edi)  \n\t"   \
        "psrlq    $32,       %%mm1      \n\t"   \
        "paddq    %%mm2,     %%mm1      \n\t"   \
        "movd     24(%%edi), %%mm5      \n\t"   \
        "paddq    %%mm5,     %%mm6      \n\t"   \
        "movd     %%mm1,     16(%%edi)  \n\t"   \
        "psrlq    $32,       %%mm1      \n\t"   \
        "paddq    %%mm4,     %%mm1      \n\t"   \
        "movd     28(%%edi), %%mm5      \n\t"   \
        "paddq    %%mm5,     %%mm3      \n\t"   \
        "movd     %%mm1,     20(%%edi)  \n\t"   \
        "psrlq    $32,       %%mm1      \n\t"   \
        "paddq    %%mm6,     %%mm1      \n\t"   \
        "movd     %%mm1,     24(%%edi)  \n\t"   \
        "psrlq    $32,       %%mm1      \n\t"   \
        "paddq    %%mm3,     %%mm1      \n\t"   \
        "movd     %%mm1,     28(%%edi)  \n\t"   \
        "addl     $32,       %%edi      \n\t"   \
        "addl     $32,       %%esi      \n\t"   \
        "psrlq    $32,       %%mm1      \n\t"   \
        "movd     %%mm1,     %%ecx      \n\t"

#define MOC_MULADDC_STOP                    \
        "emms                   \n\t"   \
        "movl   %4, %%ebx       \n\t"   \
        "movl   %%ecx, %1       \n\t"   \
        "movl   %%edi, %2       \n\t"   \
        "movl   %%esi, %3       \n\t"   \
        : "=m" (t), "=m" (c), "=m" (d), "=m" (s)        \
        : "m" (t), "m" (s), "m" (d), "m" (c), "m" (b)   \
        : "eax", "ebx", "ecx", "edx", "esi", "edi"      \
    );

#else

#define MOC_MULADDC_STOP                    \
        "movl   %4, %%ebx       \n\t"   \
        "movl   %%ecx, %1       \n\t"   \
        "movl   %%edi, %2       \n\t"   \
        "movl   %%esi, %3       \n\t"   \
        : "=m" (t), "=m" (c), "=m" (d), "=m" (s)        \
        : "m" (t), "m" (s), "m" (d), "m" (c), "m" (b)   \
        : "eax", "ebx", "ecx", "edx", "esi", "edi"      \
    );
#endif /* SSE2 */
#endif /* i386 */

#if defined(__amd64__) || defined (__x86_64__)

#define MOC_MULADDC_INIT                        \
    asm(                                    \
        "xorq   %%r8, %%r8\n"

#define MOC_MULADDC_CORE                        \
        "movq   (%%rsi), %%rax\n"           \
        "mulq   %%rbx\n"                    \
        "addq   $8, %%rsi\n"                \
        "addq   %%rcx, %%rax\n"             \
        "movq   %%r8, %%rcx\n"              \
        "adcq   $0, %%rdx\n"                \
        "nop    \n"                         \
        "addq   %%rax, (%%rdi)\n"           \
        "adcq   %%rdx, %%rcx\n"             \
        "addq   $8, %%rdi\n"

#define MOC_MULADDC_STOP                        \
        : "+c" (c), "+D" (d), "+S" (s)      \
        : "b" (b)                           \
        : "rax", "rdx", "r8"                \
    );

#endif /* AMD64 */

#if defined(__mc68020__) || defined(__mcpu32__)

#define MOC_MULADDC_INIT                    \
    asm(                                \
        "movl   %3, %%a2        \n\t"   \
        "movl   %4, %%a3        \n\t"   \
        "movl   %5, %%d3        \n\t"   \
        "movl   %6, %%d2        \n\t"   \
        "moveq  #0, %%d0        \n\t"

#define MOC_MULADDC_CORE                    \
        "movel  %%a2@+, %%d1    \n\t"   \
        "mulul  %%d2, %%d4:%%d1 \n\t"   \
        "addl   %%d3, %%d1      \n\t"   \
        "addxl  %%d0, %%d4      \n\t"   \
        "moveq  #0,   %%d3      \n\t"   \
        "addl   %%d1, %%a3@+    \n\t"   \
        "addxl  %%d4, %%d3      \n\t"

#define MOC_MULADDC_STOP                    \
        "movl   %%d3, %0        \n\t"   \
        "movl   %%a3, %1        \n\t"   \
        "movl   %%a2, %2        \n\t"   \
        : "=m" (c), "=m" (d), "=m" (s)              \
        : "m" (s), "m" (d), "m" (c), "m" (b)        \
        : "d0", "d1", "d2", "d3", "d4", "a2", "a3"  \
    );

#define MOC_MULADDC_HUIT                        \
        "movel  %%a2@+,  %%d1       \n\t"   \
        "mulul  %%d2,    %%d4:%%d1  \n\t"   \
        "addxl  %%d3,    %%d1       \n\t"   \
        "addxl  %%d0,    %%d4       \n\t"   \
        "addl   %%d1,    %%a3@+     \n\t"   \
        "movel  %%a2@+,  %%d1       \n\t"   \
        "mulul  %%d2,    %%d3:%%d1  \n\t"   \
        "addxl  %%d4,    %%d1       \n\t"   \
        "addxl  %%d0,    %%d3       \n\t"   \
        "addl   %%d1,    %%a3@+     \n\t"   \
        "movel  %%a2@+,  %%d1       \n\t"   \
        "mulul  %%d2,    %%d4:%%d1  \n\t"   \
        "addxl  %%d3,    %%d1       \n\t"   \
        "addxl  %%d0,    %%d4       \n\t"   \
        "addl   %%d1,    %%a3@+     \n\t"   \
        "movel  %%a2@+,  %%d1       \n\t"   \
        "mulul  %%d2,    %%d3:%%d1  \n\t"   \
        "addxl  %%d4,    %%d1       \n\t"   \
        "addxl  %%d0,    %%d3       \n\t"   \
        "addl   %%d1,    %%a3@+     \n\t"   \
        "movel  %%a2@+,  %%d1       \n\t"   \
        "mulul  %%d2,    %%d4:%%d1  \n\t"   \
        "addxl  %%d3,    %%d1       \n\t"   \
        "addxl  %%d0,    %%d4       \n\t"   \
        "addl   %%d1,    %%a3@+     \n\t"   \
        "movel  %%a2@+,  %%d1       \n\t"   \
        "mulul  %%d2,    %%d3:%%d1  \n\t"   \
        "addxl  %%d4,    %%d1       \n\t"   \
        "addxl  %%d0,    %%d3       \n\t"   \
        "addl   %%d1,    %%a3@+     \n\t"   \
        "movel  %%a2@+,  %%d1       \n\t"   \
        "mulul  %%d2,    %%d4:%%d1  \n\t"   \
        "addxl  %%d3,    %%d1       \n\t"   \
        "addxl  %%d0,    %%d4       \n\t"   \
        "addl   %%d1,    %%a3@+     \n\t"   \
        "movel  %%a2@+,  %%d1       \n\t"   \
        "mulul  %%d2,    %%d3:%%d1  \n\t"   \
        "addxl  %%d4,    %%d1       \n\t"   \
        "addxl  %%d0,    %%d3       \n\t"   \
        "addl   %%d1,    %%a3@+     \n\t"   \
        "addxl  %%d0,    %%d3       \n\t"

#endif /* MC68000 */

#if defined(__powerpc64__) || defined(__ppc64__)

#if defined(__MACH__) && defined(__APPLE__)

#define MOC_MULADDC_INIT                        \
    asm(                                    \
        "ld     r3, %3              \n\t"   \
        "ld     r4, %4              \n\t"   \
        "ld     r5, %5              \n\t"   \
        "ld     r6, %6              \n\t"   \
        "addi   r3, r3, -8          \n\t"   \
        "addi   r4, r4, -8          \n\t"   \
        "addic  r5, r5,  0          \n\t"

#define MOC_MULADDC_CORE                        \
        "ldu    r7, 8(r3)           \n\t"   \
        "mulld  r8, r7, r6          \n\t"   \
        "mulhdu r9, r7, r6          \n\t"   \
        "adde   r8, r8, r5          \n\t"   \
        "ld     r7, 8(r4)           \n\t"   \
        "addze  r5, r9              \n\t"   \
        "addc   r8, r8, r7          \n\t"   \
        "stdu   r8, 8(r4)           \n\t"

#define MOC_MULADDC_STOP                        \
        "addze  r5, r5              \n\t"   \
        "addi   r4, r4, 8           \n\t"   \
        "addi   r3, r3, 8           \n\t"   \
        "std    r5, %0              \n\t"   \
        "std    r4, %1              \n\t"   \
        "std    r3, %2              \n\t"   \
        : "=m" (c), "=m" (d), "=m" (s)              \
        : "m" (s), "m" (d), "m" (c), "m" (b)        \
        : "r3", "r4", "r5", "r6", "r7", "r8", "r9"  \
    );


#else /* __MACH__ && __APPLE__ */

#define MOC_MULADDC_INIT                        \
    asm(                                    \
        "ld     %%r3, %3            \n\t"   \
        "ld     %%r4, %4            \n\t"   \
        "ld     %%r5, %5            \n\t"   \
        "ld     %%r6, %6            \n\t"   \
        "addi   %%r3, %%r3, -8      \n\t"   \
        "addi   %%r4, %%r4, -8      \n\t"   \
        "addic  %%r5, %%r5,  0      \n\t"

#define MOC_MULADDC_CORE                        \
        "ldu    %%r7, 8(%%r3)       \n\t"   \
        "mulld  %%r8, %%r7, %%r6    \n\t"   \
        "mulhdu %%r9, %%r7, %%r6    \n\t"   \
        "adde   %%r8, %%r8, %%r5    \n\t"   \
        "ld     %%r7, 8(%%r4)       \n\t"   \
        "addze  %%r5, %%r9          \n\t"   \
        "addc   %%r8, %%r8, %%r7    \n\t"   \
        "stdu   %%r8, 8(%%r4)       \n\t"

#define MOC_MULADDC_STOP                        \
        "addze  %%r5, %%r5          \n\t"   \
        "addi   %%r4, %%r4, 8       \n\t"   \
        "addi   %%r3, %%r3, 8       \n\t"   \
        "std    %%r5, %0            \n\t"   \
        "std    %%r4, %1            \n\t"   \
        "std    %%r3, %2            \n\t"   \
        : "=m" (c), "=m" (d), "=m" (s)              \
        : "m" (s), "m" (d), "m" (c), "m" (b)        \
        : "r3", "r4", "r5", "r6", "r7", "r8", "r9"  \
    );

#endif /* __MACH__ && __APPLE__ */

#elif defined(__powerpc__) || defined(__ppc__) /* end PPC64/begin PPC32  */

#if defined(__MACH__) && defined(__APPLE__)

#define MOC_MULADDC_INIT                    \
    asm(                                \
        "lwz    r3, %3          \n\t"   \
        "lwz    r4, %4          \n\t"   \
        "lwz    r5, %5          \n\t"   \
        "lwz    r6, %6          \n\t"   \
        "addi   r3, r3, -4      \n\t"   \
        "addi   r4, r4, -4      \n\t"   \
        "addic  r5, r5,  0      \n\t"

#define MOC_MULADDC_CORE                    \
        "lwzu   r7, 4(r3)       \n\t"   \
        "mullw  r8, r7, r6      \n\t"   \
        "mulhwu r9, r7, r6      \n\t"   \
        "adde   r8, r8, r5      \n\t"   \
        "lwz    r7, 4(r4)       \n\t"   \
        "addze  r5, r9          \n\t"   \
        "addc   r8, r8, r7      \n\t"   \
        "stwu   r8, 4(r4)       \n\t"

#define MOC_MULADDC_STOP                    \
        "addze  r5, r5          \n\t"   \
        "addi   r4, r4, 4       \n\t"   \
        "addi   r3, r3, 4       \n\t"   \
        "stw    r5, %0          \n\t"   \
        "stw    r4, %1          \n\t"   \
        "stw    r3, %2          \n\t"   \
        : "=m" (c), "=m" (d), "=m" (s)              \
        : "m" (s), "m" (d), "m" (c), "m" (b)        \
        : "r3", "r4", "r5", "r6", "r7", "r8", "r9"  \
    );

#else /* __MACH__ && __APPLE__ */

#define MOC_MULADDC_INIT                        \
    asm(                                    \
        "lwz    %%r3, %3            \n\t"   \
        "lwz    %%r4, %4            \n\t"   \
        "lwz    %%r5, %5            \n\t"   \
        "lwz    %%r6, %6            \n\t"   \
        "addi   %%r3, %%r3, -4      \n\t"   \
        "addi   %%r4, %%r4, -4      \n\t"   \
        "addic  %%r5, %%r5,  0      \n\t"

#define MOC_MULADDC_CORE                        \
        "lwzu   %%r7, 4(%%r3)       \n\t"   \
        "mullw  %%r8, %%r7, %%r6    \n\t"   \
        "mulhwu %%r9, %%r7, %%r6    \n\t"   \
        "adde   %%r8, %%r8, %%r5    \n\t"   \
        "lwz    %%r7, 4(%%r4)       \n\t"   \
        "addze  %%r5, %%r9          \n\t"   \
        "addc   %%r8, %%r8, %%r7    \n\t"   \
        "stwu   %%r8, 4(%%r4)       \n\t"

#define MOC_MULADDC_STOP                        \
        "addze  %%r5, %%r5          \n\t"   \
        "addi   %%r4, %%r4, 4       \n\t"   \
        "addi   %%r3, %%r3, 4       \n\t"   \
        "stw    %%r5, %0            \n\t"   \
        "stw    %%r4, %1            \n\t"   \
        "stw    %%r3, %2            \n\t"   \
        : "=m" (c), "=m" (d), "=m" (s)              \
        : "m" (s), "m" (d), "m" (c), "m" (b)        \
        : "r3", "r4", "r5", "r6", "r7", "r8", "r9"  \
    );

#endif /* __MACH__ && __APPLE__ */

#endif /* PPC32 */

/*
 * The Sparc(64) assembly is reported to be broken.
 * Disable it for now, until we're able to fix it.
 */
#if 0 && defined(__sparc__)
#if defined(__sparc64__)

#define MOC_MULADDC_INIT                                    \
    asm(                                                \
                "ldx     %3, %%o0               \n\t"   \
                "ldx     %4, %%o1               \n\t"   \
                "ld      %5, %%o2               \n\t"   \
                "ld      %6, %%o3               \n\t"

#define MOC_MULADDC_CORE                                    \
                "ld      [%%o0], %%o4           \n\t"   \
                "inc     4, %%o0                \n\t"   \
                "ld      [%%o1], %%o5           \n\t"   \
                "umul    %%o3, %%o4, %%o4       \n\t"   \
                "addcc   %%o4, %%o2, %%o4       \n\t"   \
                "rd      %%y, %%g1              \n\t"   \
                "addx    %%g1, 0, %%g1          \n\t"   \
                "addcc   %%o4, %%o5, %%o4       \n\t"   \
                "st      %%o4, [%%o1]           \n\t"   \
                "addx    %%g1, 0, %%o2          \n\t"   \
                "inc     4, %%o1                \n\t"

        #define MOC_MULADDC_STOP                            \
                "st      %%o2, %0               \n\t"   \
                "stx     %%o1, %1               \n\t"   \
                "stx     %%o0, %2               \n\t"   \
        : "=m" (c), "=m" (d), "=m" (s)          \
        : "m" (s), "m" (d), "m" (c), "m" (b)    \
        : "g1", "o0", "o1", "o2", "o3", "o4",   \
          "o5"                                  \
        );

#else /* __sparc64__ */

#define MOC_MULADDC_INIT                                    \
    asm(                                                \
                "ld      %3, %%o0               \n\t"   \
                "ld      %4, %%o1               \n\t"   \
                "ld      %5, %%o2               \n\t"   \
                "ld      %6, %%o3               \n\t"

#define MOC_MULADDC_CORE                                    \
                "ld      [%%o0], %%o4           \n\t"   \
                "inc     4, %%o0                \n\t"   \
                "ld      [%%o1], %%o5           \n\t"   \
                "umul    %%o3, %%o4, %%o4       \n\t"   \
                "addcc   %%o4, %%o2, %%o4       \n\t"   \
                "rd      %%y, %%g1              \n\t"   \
                "addx    %%g1, 0, %%g1          \n\t"   \
                "addcc   %%o4, %%o5, %%o4       \n\t"   \
                "st      %%o4, [%%o1]           \n\t"   \
                "addx    %%g1, 0, %%o2          \n\t"   \
                "inc     4, %%o1                \n\t"

#define MOC_MULADDC_STOP                                    \
                "st      %%o2, %0               \n\t"   \
                "st      %%o1, %1               \n\t"   \
                "st      %%o0, %2               \n\t"   \
        : "=m" (c), "=m" (d), "=m" (s)          \
        : "m" (s), "m" (d), "m" (c), "m" (b)    \
        : "g1", "o0", "o1", "o2", "o3", "o4",   \
          "o5"                                  \
        );

#endif /* __sparc64__ */
#endif /* __sparc__ */

#if defined(__microblaze__) || defined(microblaze)

#define MOC_MULADDC_INIT                    \
    asm(                                \
        "lwi   r3,   %3         \n\t"   \
        "lwi   r4,   %4         \n\t"   \
        "lwi   r5,   %5         \n\t"   \
        "lwi   r6,   %6         \n\t"   \
        "andi  r7,   r6, 0xffff \n\t"   \
        "bsrli r6,   r6, 16     \n\t"

#define MOC_MULADDC_CORE                    \
        "lhui  r8,   r3,   0    \n\t"   \
        "addi  r3,   r3,   2    \n\t"   \
        "lhui  r9,   r3,   0    \n\t"   \
        "addi  r3,   r3,   2    \n\t"   \
        "mul   r10,  r9,  r6    \n\t"   \
        "mul   r11,  r8,  r7    \n\t"   \
        "mul   r12,  r9,  r7    \n\t"   \
        "mul   r13,  r8,  r6    \n\t"   \
        "bsrli  r8, r10,  16    \n\t"   \
        "bsrli  r9, r11,  16    \n\t"   \
        "add   r13, r13,  r8    \n\t"   \
        "add   r13, r13,  r9    \n\t"   \
        "bslli r10, r10,  16    \n\t"   \
        "bslli r11, r11,  16    \n\t"   \
        "add   r12, r12, r10    \n\t"   \
        "addc  r13, r13,  r0    \n\t"   \
        "add   r12, r12, r11    \n\t"   \
        "addc  r13, r13,  r0    \n\t"   \
        "lwi   r10,  r4,   0    \n\t"   \
        "add   r12, r12, r10    \n\t"   \
        "addc  r13, r13,  r0    \n\t"   \
        "add   r12, r12,  r5    \n\t"   \
        "addc   r5, r13,  r0    \n\t"   \
        "swi   r12,  r4,   0    \n\t"   \
        "addi   r4,  r4,   4    \n\t"

#define MOC_MULADDC_STOP                    \
        "swi   r5,   %0         \n\t"   \
        "swi   r4,   %1         \n\t"   \
        "swi   r3,   %2         \n\t"   \
        : "=m" (c), "=m" (d), "=m" (s)              \
        : "m" (s), "m" (d), "m" (c), "m" (b)        \
        : "r3", "r4", "r5", "r6", "r7", "r8",       \
          "r9", "r10", "r11", "r12", "r13"          \
    );

#endif /* MicroBlaze */

#if defined(__tricore__)

#define MOC_MULADDC_INIT                            \
    asm(                                        \
        "ld.a   %%a2, %3                \n\t"   \
        "ld.a   %%a3, %4                \n\t"   \
        "ld.w   %%d4, %5                \n\t"   \
        "ld.w   %%d1, %6                \n\t"   \
        "xor    %%d5, %%d5              \n\t"

#define MOC_MULADDC_CORE                            \
        "ld.w   %%d0,   [%%a2+]         \n\t"   \
        "madd.u %%e2, %%e4, %%d0, %%d1  \n\t"   \
        "ld.w   %%d0,   [%%a3]          \n\t"   \
        "addx   %%d2,    %%d2,  %%d0    \n\t"   \
        "addc   %%d3,    %%d3,    0     \n\t"   \
        "mov    %%d4,    %%d3           \n\t"   \
        "st.w  [%%a3+],  %%d2           \n\t"

#define MOC_MULADDC_STOP                            \
        "st.w   %0, %%d4                \n\t"   \
        "st.a   %1, %%a3                \n\t"   \
        "st.a   %2, %%a2                \n\t"   \
        : "=m" (c), "=m" (d), "=m" (s)          \
        : "m" (s), "m" (d), "m" (c), "m" (b)    \
        : "d0", "d1", "e2", "d4", "a2", "a3"    \
    );

#endif /* TriCore */

/*
 * Note, gcc -O0 by default uses r7 for the frame pointer, so it complains about
 * our use of r7 below, unless -fomit-frame-pointer is passed.
 *
 * On the other hand, -fomit-frame-pointer is implied by any -Ox options with
 * x !=0, which we can detect using __OPTIMIZE__ (which is also defined by
 * clang and armcc5 under the same conditions).
 *
 * So, only use the optimized assembly below for optimized build, which avoids
 * the build error and is pretty reasonable anyway.
 */
#if defined(__GNUC__) && !defined(__OPTIMIZE__)
#define MOC_MULADDC_CANNOT_USE_R7
#endif

#if defined(__arm__) && !defined(MOC_MULADDC_CANNOT_USE_R7)

#if defined(__thumb__) && !defined(__thumb2__)

#define MOC_MULADDC_INIT                                    \
    asm(                                                \
            "ldr    r0, %3                      \n\t"   \
            "ldr    r1, %4                      \n\t"   \
            "ldr    r2, %5                      \n\t"   \
            "ldr    r3, %6                      \n\t"   \
            "lsr    r7, r3, #16                 \n\t"   \
            "mov    r9, r7                      \n\t"   \
            "lsl    r7, r3, #16                 \n\t"   \
            "lsr    r7, r7, #16                 \n\t"   \
            "mov    r8, r7                      \n\t"

#define MOC_MULADDC_CORE                                    \
            "ldmia  r0!, {r6}                   \n\t"   \
            "lsr    r7, r6, #16                 \n\t"   \
            "lsl    r6, r6, #16                 \n\t"   \
            "lsr    r6, r6, #16                 \n\t"   \
            "mov    r4, r8                      \n\t"   \
            "mul    r4, r6                      \n\t"   \
            "mov    r3, r9                      \n\t"   \
            "mul    r6, r3                      \n\t"   \
            "mov    r5, r9                      \n\t"   \
            "mul    r5, r7                      \n\t"   \
            "mov    r3, r8                      \n\t"   \
            "mul    r7, r3                      \n\t"   \
            "lsr    r3, r6, #16                 \n\t"   \
            "add    r5, r5, r3                  \n\t"   \
            "lsr    r3, r7, #16                 \n\t"   \
            "add    r5, r5, r3                  \n\t"   \
            "add    r4, r4, r2                  \n\t"   \
            "mov    r2, #0                      \n\t"   \
            "adc    r5, r2                      \n\t"   \
            "lsl    r3, r6, #16                 \n\t"   \
            "add    r4, r4, r3                  \n\t"   \
            "adc    r5, r2                      \n\t"   \
            "lsl    r3, r7, #16                 \n\t"   \
            "add    r4, r4, r3                  \n\t"   \
            "adc    r5, r2                      \n\t"   \
            "ldr    r3, [r1]                    \n\t"   \
            "add    r4, r4, r3                  \n\t"   \
            "adc    r2, r5                      \n\t"   \
            "stmia  r1!, {r4}                   \n\t"

#define MOC_MULADDC_STOP                                    \
            "str    r2, %0                      \n\t"   \
            "str    r1, %1                      \n\t"   \
            "str    r0, %2                      \n\t"   \
         : "=m" (c),  "=m" (d), "=m" (s)        \
         : "m" (s), "m" (d), "m" (c), "m" (b)   \
         : "r0", "r1", "r2", "r3", "r4", "r5",  \
           "r6", "r7", "r8", "r9", "cc"         \
         );

#elif (__ARM_ARCH >= 6) && \
    defined (__ARM_FEATURE_DSP) && (__ARM_FEATURE_DSP == 1)

#define MOC_MULADDC_INIT                            \
    asm(

#define MOC_MULADDC_CORE                            \
            "ldr    r0, [%0], #4        \n\t"   \
            "ldr    r1, [%1]            \n\t"   \
            "umaal  r1, %2, %3, r0      \n\t"   \
            "str    r1, [%1], #4        \n\t"

#define MOC_MULADDC_STOP                            \
         : "=r" (s),  "=r" (d), "=r" (c)        \
         : "r" (b), "0" (s), "1" (d), "2" (c)   \
         : "r0", "r1", "memory"                 \
         );

#else

#define MOC_MULADDC_INIT                                    \
    asm(                                                \
            "ldr    r0, %3                      \n\t"   \
            "ldr    r1, %4                      \n\t"   \
            "ldr    r2, %5                      \n\t"   \
            "ldr    r3, %6                      \n\t"

#define MOC_MULADDC_CORE                                    \
            "ldr    r4, [r0], #4                \n\t"   \
            "mov    r5, #0                      \n\t"   \
            "ldr    r6, [r1]                    \n\t"   \
            "umlal  r2, r5, r3, r4              \n\t"   \
            "adds   r7, r6, r2                  \n\t"   \
            "adc    r2, r5, #0                  \n\t"   \
            "str    r7, [r1], #4                \n\t"

#define MOC_MULADDC_STOP                                    \
            "str    r2, %0                      \n\t"   \
            "str    r1, %1                      \n\t"   \
            "str    r0, %2                      \n\t"   \
         : "=m" (c),  "=m" (d), "=m" (s)        \
         : "m" (s), "m" (d), "m" (c), "m" (b)   \
         : "r0", "r1", "r2", "r3", "r4", "r5",  \
           "r6", "r7", "cc"                     \
         );

#endif /* Thumb */

#endif /* ARMv3 */

#if defined(__alpha__)

#define MOC_MULADDC_INIT                    \
    asm(                                \
        "ldq    $1, %3          \n\t"   \
        "ldq    $2, %4          \n\t"   \
        "ldq    $3, %5          \n\t"   \
        "ldq    $4, %6          \n\t"

#define MOC_MULADDC_CORE                    \
        "ldq    $6,  0($1)      \n\t"   \
        "addq   $1,  8, $1      \n\t"   \
        "mulq   $6, $4, $7      \n\t"   \
        "umulh  $6, $4, $6      \n\t"   \
        "addq   $7, $3, $7      \n\t"   \
        "cmpult $7, $3, $3      \n\t"   \
        "ldq    $5,  0($2)      \n\t"   \
        "addq   $7, $5, $7      \n\t"   \
        "cmpult $7, $5, $5      \n\t"   \
        "stq    $7,  0($2)      \n\t"   \
        "addq   $2,  8, $2      \n\t"   \
        "addq   $6, $3, $3      \n\t"   \
        "addq   $5, $3, $3      \n\t"

#define MOC_MULADDC_STOP                                    \
        "stq    $3, %0          \n\t"   \
        "stq    $2, %1          \n\t"   \
        "stq    $1, %2          \n\t"   \
        : "=m" (c), "=m" (d), "=m" (s)              \
        : "m" (s), "m" (d), "m" (c), "m" (b)        \
        : "$1", "$2", "$3", "$4", "$5", "$6", "$7"  \
    );
#endif /* Alpha */

#if defined(__mips__) && !defined(__mips64)

#define MOC_MULADDC_INIT                    \
    asm(                                \
        "lw     $10, %3         \n\t"   \
        "lw     $11, %4         \n\t"   \
        "lw     $12, %5         \n\t"   \
        "lw     $13, %6         \n\t"

#define MOC_MULADDC_CORE                    \
        "lw     $14, 0($10)     \n\t"   \
        "multu  $13, $14        \n\t"   \
        "addi   $10, $10, 4     \n\t"   \
        "mflo   $14             \n\t"   \
        "mfhi   $9              \n\t"   \
        "addu   $14, $12, $14   \n\t"   \
        "lw     $15, 0($11)     \n\t"   \
        "sltu   $12, $14, $12   \n\t"   \
        "addu   $15, $14, $15   \n\t"   \
        "sltu   $14, $15, $14   \n\t"   \
        "addu   $12, $12, $9    \n\t"   \
        "sw     $15, 0($11)     \n\t"   \
        "addu   $12, $12, $14   \n\t"   \
        "addi   $11, $11, 4     \n\t"

#define MOC_MULADDC_STOP                    \
        "sw     $12, %0         \n\t"   \
        "sw     $11, %1         \n\t"   \
        "sw     $10, %2         \n\t"   \
        : "=m" (c), "=m" (d), "=m" (s)                      \
        : "m" (s), "m" (d), "m" (c), "m" (b)                \
        : "$9", "$10", "$11", "$12", "$13", "$14", "$15", "lo", "hi" \
    );

#endif /* MIPS */
#endif /* GNUC */

#if (defined(_MSC_VER) && defined(_M_IX86)) || defined(__WATCOMC__)

#define MOC_MULADDC_INIT                            \
    __asm   mov     esi, s                      \
    __asm   mov     edi, d                      \
    __asm   mov     ecx, c                      \
    __asm   mov     ebx, b

#define MOC_MULADDC_CORE                            \
    __asm   lodsd                               \
    __asm   mul     ebx                         \
    __asm   add     eax, ecx                    \
    __asm   adc     edx, 0                      \
    __asm   add     eax, [edi]                  \
    __asm   adc     edx, 0                      \
    __asm   mov     ecx, edx                    \
    __asm   stosd

#if defined(MOC_HAVE_SSE2)

#define EMIT __asm _emit

#define MOC_MULADDC_HUIT                            \
    EMIT 0x0F  EMIT 0x6E  EMIT 0xC9             \
    EMIT 0x0F  EMIT 0x6E  EMIT 0xC3             \
    EMIT 0x0F  EMIT 0x6E  EMIT 0x1F             \
    EMIT 0x0F  EMIT 0xD4  EMIT 0xCB             \
    EMIT 0x0F  EMIT 0x6E  EMIT 0x16             \
    EMIT 0x0F  EMIT 0xF4  EMIT 0xD0             \
    EMIT 0x0F  EMIT 0x6E  EMIT 0x66  EMIT 0x04  \
    EMIT 0x0F  EMIT 0xF4  EMIT 0xE0             \
    EMIT 0x0F  EMIT 0x6E  EMIT 0x76  EMIT 0x08  \
    EMIT 0x0F  EMIT 0xF4  EMIT 0xF0             \
    EMIT 0x0F  EMIT 0x6E  EMIT 0x7E  EMIT 0x0C  \
    EMIT 0x0F  EMIT 0xF4  EMIT 0xF8             \
    EMIT 0x0F  EMIT 0xD4  EMIT 0xCA             \
    EMIT 0x0F  EMIT 0x6E  EMIT 0x5F  EMIT 0x04  \
    EMIT 0x0F  EMIT 0xD4  EMIT 0xDC             \
    EMIT 0x0F  EMIT 0x6E  EMIT 0x6F  EMIT 0x08  \
    EMIT 0x0F  EMIT 0xD4  EMIT 0xEE             \
    EMIT 0x0F  EMIT 0x6E  EMIT 0x67  EMIT 0x0C  \
    EMIT 0x0F  EMIT 0xD4  EMIT 0xFC             \
    EMIT 0x0F  EMIT 0x7E  EMIT 0x0F             \
    EMIT 0x0F  EMIT 0x6E  EMIT 0x56  EMIT 0x10  \
    EMIT 0x0F  EMIT 0xF4  EMIT 0xD0             \
    EMIT 0x0F  EMIT 0x73  EMIT 0xD1  EMIT 0x20  \
    EMIT 0x0F  EMIT 0x6E  EMIT 0x66  EMIT 0x14  \
    EMIT 0x0F  EMIT 0xF4  EMIT 0xE0             \
    EMIT 0x0F  EMIT 0xD4  EMIT 0xCB             \
    EMIT 0x0F  EMIT 0x6E  EMIT 0x76  EMIT 0x18  \
    EMIT 0x0F  EMIT 0xF4  EMIT 0xF0             \
    EMIT 0x0F  EMIT 0x7E  EMIT 0x4F  EMIT 0x04  \
    EMIT 0x0F  EMIT 0x73  EMIT 0xD1  EMIT 0x20  \
    EMIT 0x0F  EMIT 0x6E  EMIT 0x5E  EMIT 0x1C  \
    EMIT 0x0F  EMIT 0xF4  EMIT 0xD8             \
    EMIT 0x0F  EMIT 0xD4  EMIT 0xCD             \
    EMIT 0x0F  EMIT 0x6E  EMIT 0x6F  EMIT 0x10  \
    EMIT 0x0F  EMIT 0xD4  EMIT 0xD5             \
    EMIT 0x0F  EMIT 0x7E  EMIT 0x4F  EMIT 0x08  \
    EMIT 0x0F  EMIT 0x73  EMIT 0xD1  EMIT 0x20  \
    EMIT 0x0F  EMIT 0xD4  EMIT 0xCF             \
    EMIT 0x0F  EMIT 0x6E  EMIT 0x6F  EMIT 0x14  \
    EMIT 0x0F  EMIT 0xD4  EMIT 0xE5             \
    EMIT 0x0F  EMIT 0x7E  EMIT 0x4F  EMIT 0x0C  \
    EMIT 0x0F  EMIT 0x73  EMIT 0xD1  EMIT 0x20  \
    EMIT 0x0F  EMIT 0xD4  EMIT 0xCA             \
    EMIT 0x0F  EMIT 0x6E  EMIT 0x6F  EMIT 0x18  \
    EMIT 0x0F  EMIT 0xD4  EMIT 0xF5             \
    EMIT 0x0F  EMIT 0x7E  EMIT 0x4F  EMIT 0x10  \
    EMIT 0x0F  EMIT 0x73  EMIT 0xD1  EMIT 0x20  \
    EMIT 0x0F  EMIT 0xD4  EMIT 0xCC             \
    EMIT 0x0F  EMIT 0x6E  EMIT 0x6F  EMIT 0x1C  \
    EMIT 0x0F  EMIT 0xD4  EMIT 0xDD             \
    EMIT 0x0F  EMIT 0x7E  EMIT 0x4F  EMIT 0x14  \
    EMIT 0x0F  EMIT 0x73  EMIT 0xD1  EMIT 0x20  \
    EMIT 0x0F  EMIT 0xD4  EMIT 0xCE             \
    EMIT 0x0F  EMIT 0x7E  EMIT 0x4F  EMIT 0x18  \
    EMIT 0x0F  EMIT 0x73  EMIT 0xD1  EMIT 0x20  \
    EMIT 0x0F  EMIT 0xD4  EMIT 0xCB             \
    EMIT 0x0F  EMIT 0x7E  EMIT 0x4F  EMIT 0x1C  \
    EMIT 0x83  EMIT 0xC7  EMIT 0x20             \
    EMIT 0x83  EMIT 0xC6  EMIT 0x20             \
    EMIT 0x0F  EMIT 0x73  EMIT 0xD1  EMIT 0x20  \
    EMIT 0x0F  EMIT 0x7E  EMIT 0xC9

#define MOC_MULADDC_STOP                            \
    EMIT 0x0F  EMIT 0x77                        \
    __asm   mov     c, ecx                      \
    __asm   mov     d, edi                      \
    __asm   mov     s, esi                      \

#else

#define MOC_MULADDC_STOP                            \
    __asm   mov     c, ecx                      \
    __asm   mov     d, edi                      \
    __asm   mov     s, esi                      \

#endif /* SSE2 */
#endif /* MSVC */

#ifdef __ASM_COLDFIRE_MCF__

#define MOC_MULADDC_INIT \
asm( \
    move.l a2, backup_a2 \
    move.l a3, backup_a3 \
    move.l a5, backup_a5 \
    move.l d0, backup_d0 \
    move.l d1, backup_d1 \
    move.l d2, backup_d2 \
    move.l d3, backup_d3 \
    move.l d4, backup_d4 \
    move.l d5, backup_d5 \
    move.l d6, backup_d6 \
    move.l s, a2 \
    move.l d, a3 \
    move.l c, a5 \
    move.l b, d1 \
    move.l d1, d2 \
    ANDI.L #0x0000ffff, d1 \
    LSR.L #8, d2 \
    LSR.L #8, d2

#define MOC_MULADDC_CORE \
    move.l (a2)+, d3 \
    move.l d3, d4 \
    ANDI.L #0x0000ffff, d3 \
    LSR.L #8, d4 \
    LSR.L #8, d4 \
    move.l d1, d5 \
    move.l d2, d6 \
    move.l d4, d0 \
    MULU.W d3, d6 \
    MULU.W d3, d5 \
    MULU.W d1, d4 \
    MULU.W d2, d0 \
    move.l d6, d3 \
    LSR.L #8, d3 \
    LSR.L #8, d3 \
    ADD.L d3, d0 \
    move.l d4, d3 \
    LSR.L #8, d3 \
    LSR.L #8, d3 \
    ADD.L d3, d0 \
    LSL.L #8, d6 \
    LSL.L #8, d6 \
    LSL.L #8, d4 \
    LSL.L #8, d4 \
    move.l #0, d3 \
    ADD.L d6, d5 \
    ADDX.L d3, d0 \
    ADD.L d4, d5 \
    ADDX.L d3, d0 \
    ADD.L a5, d5 \
    ADDX.L d3, d0 \
    ADD.L (a3), d5 \
    ADDX.L d3, d0 \
    move.l d0, a5 \
    move.l d5, (a3)+

#define MOC_MULADDC_STOP \
    move.l a5, d0 \
    move.l d0, c \
    move.l a2, d0 \
    move.l d0, s \
    move.l a3, d0 \
    move.l d0, d \
    move.l backup_a2, a2 \
    move.l backup_a3, a3 \
    move.l backup_a5, a5 \
    move.l backup_d0, d0 \
    move.l backup_d1, d1 \
    move.l backup_d2, d2 \
    move.l backup_d3, d3 \
    move.l backup_d4, d4 \
    move.l backup_d5, d5 \
    move.l backup_d6, d6 \
    )

#define ASM_COLDFIRE_BACKUP_VARS( type) \
    type backup_a2; \
    type backup_a3; \
    type backup_a5; \
    type backup_d0; \
    type backup_d1; \
    type backup_d2; \
    type backup_d3; \
    type backup_d4; \
    type backup_d5; \
    type backup_d6;

/* The following hasn't proved to provide a speedup  
   If you find a case where enabling this may help,
   you may want to add a similar MULT_ADDC method
   and also make sure they don't get duplicately
   defined in vlong.h, and make sure backup vars
   are declared wherever used.
*/
#ifdef __ASM_COLDFIRE_MCF_MULT_ADDC__
#define MULT_ADDC1(a,b,index0,index1,result0,result1) \
asm ( \
    move.l a2, backup_a2 \
    move.l d0, backup_d0 \
    move.l d1, backup_d1 \
    move.l d2, backup_d2 \
    move.l d3, backup_d3 \
    move.l d4, backup_d4 \
    move.l d5, backup_d5 \
    move.l a, a2 \
    move.l index0, d0 \
    LSL.L #2, d0 \
    ADD.L d0, a2 \
    move.l (a2), d0 \
    move.l (b), d2 \
    move.l d0, d1 \
    move.l d2, d3 \
    ANDI.L #0x0000ffff, d0 \
    LSR.L #8, d1 \
    LSR.L #8, d1 \
    ANDI.L #0x0000ffff, d2 \
    LSR.L #8, d3 \
    LSR.L #8, d3 \
    move.l d0, d4 \
    move.l d3, d5 \
    move.l d2, d6 \
    MULU.W d2, d4 \
    MULU.W d0, d5 \
    MULU.W d1, d6 \
    MULU.W d3, d1 \
    ADD.L d6, d5 \
    move.l #0, d2 \
    ADDX.L d2, d2 \
    LSL.L #8, d2 \
    LSL.L #8, d2 \
    ADD.L d2, d1 \
    move.l d5, d2 \
    LSR.L #8, d2 \
    LSR.L #8, d2 \
    ADD.L d2, d1 \
    LSL.L #8, d5 \
    LSL.L #8, d5 \
    move.l d4, d0 \
    move.l #0, d2 \
    ADD.L d5, d0 \
    ADDX.L d2, d1 \
    ADD.L d0, result0 \
    ADDX.L d2, d1 \
    ADD.L d1, result1 \
    move.l backup_a2, a2 \
    move.l backup_d0, d0 \
    move.l backup_d1, d1 \
    move.l backup_d2, d2 \
    move.l backup_d3, d3 \
    move.l backup_d4, d4 \
    move.l backup_d5, d5 \
    )
#endif /* __ASM_COLDFIRE_MCF_MULT_ADDC__ */
#endif /* __ASM_COLDFIRE_MCF__ */

/* revert back to code defaults if none of the above assembly is enabled */

#ifndef MOC_MULADDC_INIT

#ifdef __ENABLE_MOCANA_64_BIT__

#define MOC_MULADDC_INIT                    \
{                                       \
    ubyte8 s0, s1, b0, b1;              \
    ubyte8 r0, r1, rx, ry;              \
    b0 = ( b << 32 ) >> 32;             \
    b1 = ( b >> 32 );

#define MOC_MULADDC_CORE                    \
    s0 = ( *s << 32 ) >> 32;            \
    s1 = ( *s >> 32 ); s++;             \
    rx = s0 * b1; r0 = s0 * b0;         \
    ry = s1 * b0; r1 = s1 * b1;         \
    r1 += ( rx >> 32 );                 \
    r1 += ( ry >> 32 );                 \
    rx <<= 32; ry <<= 32;               \
    r0 += rx; r1 += (r0 < rx);          \
    r0 += ry; r1 += (r0 < ry);          \
    r0 +=  c; r1 += (r0 <  c);          \
    r0 += *d; r1 += (r0 < *d);          \
    c = r1; *(d++) = r0;

#else

#define MOC_MULADDC_INIT                    \
{                                       \
    ubyte4 s0, s1, b0, b1;              \
    ubyte4 r0, r1, rx, ry;              \
    b0 = ( b << 16 ) >> 16;             \
    b1 = ( b >> 16 );

#define MOC_MULADDC_CORE                    \
    s0 = ( *s << 16 ) >> 16;            \
    s1 = ( *s >> 16 ); s++;             \
    rx = s0 * b1; r0 = s0 * b0;         \
    ry = s1 * b0; r1 = s1 * b1;         \
    r1 += ( rx >> 16 );                 \
    r1 += ( ry >> 16 );                 \
    rx <<= 16; ry <<= 16;               \
    r0 += rx; r1 += (r0 < rx);          \
    r0 += ry; r1 += (r0 < ry);          \
    r0 +=  c; r1 += (r0 <  c);          \
    r0 += *d; r1 += (r0 < *d);          \
    c = r1; *(d++) = r0;

#endif /* __ENABLE_MOCANA_64_BIT__ */

#define MOC_MULADDC_STOP                    \
}
#endif /* MOC_MULADDC_INIT */

#endif /* MOC_BN_MUL_H */
