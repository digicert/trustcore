/*
 * moc_profiling.c
 *
 * Copyright 2026 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include <stdio.h>
#include <time.h>
#include <errno.h>

#ifdef __ENABLE_DIGICERT_PROFILING__

#define TRACE_OUTPUT_FILE "mss_trace.log"
static FILE *fp_trace;
static int file_open_failed;
void trace_begin (void) __attribute__((no_instrument_function));
void trace_end (void) __attribute__((no_instrument_function));

void
__attribute__ ((constructor))
trace_begin (void)
{
    fp_trace = fopen(TRACE_OUTPUT_FILE, "w");
    if (fp_trace == NULL)
    {
        printf("Unable to open file %s | errno = %d\n", TRACE_OUTPUT_FILE, errno);
        file_open_failed = 1;
        fp_trace = stdout;
    }
}
 
void
__attribute__ ((destructor))
trace_end (void)
{
    if((fp_trace != NULL) && !file_open_failed)
    {
        fclose(fp_trace);
    }
}

void __cyg_profile_func_enter (void *func, void *caller) __attribute__((no_instrument_function));
void __cyg_profile_func_exit  (void *func, void *caller) __attribute__((no_instrument_function));

void
__cyg_profile_func_enter (void *func,  void *caller)
{
    if(fp_trace != NULL)
    {
        fprintf(fp_trace, "Enter function : %p | Caller : %p\n", func, caller);
    }
}
 
void
__cyg_profile_func_exit (void *func, void *caller)
{
}

#endif
