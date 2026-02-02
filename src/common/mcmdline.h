/* mcmdline.h
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
#ifndef __MOC_CMD_LINE_H
#define __MOC_CMD_LINE_H

#ifdef __RTOS_WIN32__

#ifdef WIN_COMMON_EXPORT
#define MOC_EXTERN_MCMDLINE_H __declspec(dllexport)
#else
#define MOC_EXTERN_MCMDLINE_H __declspec(dllimport) extern 
#endif

#ifdef WIN_STATIC
#undef MOC_EXTERN_MCMDLINE_H
#define MOC_EXTERN_MCMDLINE_H extern
#endif

#else

#define MOC_EXTERN_MCMDLINE_H extern

#endif /* RTOS_WIN32 */


#if defined(__RTOS_WIN32__) && !defined(__DISABLE_DIGICERT_GETOPT__)
MOC_EXTERN_MCMDLINE_H int  opterr;	    /* if error message should be printed */
MOC_EXTERN_MCMDLINE_H int  optind;	    /* index into parent argv vector */
MOC_EXTERN_MCMDLINE_H int  optopt;	    /* character checked for validity */
MOC_EXTERN_MCMDLINE_H char *optarg;	/* argument associated with option */

struct option
{
    const char  *name;
    int         has_arg;
    int         *flag;
    int         val;
};

/*Predefined values for "has_arg" member of struct option*/
#define no_argument             0
#define required_argument       1
#define optional_argument       2

/* getopt
 */
MOC_EXTERN int getopt(int argc, char **argv, const char *optstr);

/* getopt_long
 * accepts long options starting with "--"
 *
 * Notes
 * - Currently accepts only long options. Doesn't support optstring option. 
 *   Use getopt() for using single char options prefixed with '-'
 * - Support long format with equal character only as in "--arg=value".
 *   Needs minor modifications for supporting space in this, as in "--arg value"
 */
MOC_EXTERN int getopt_long(int argc, char * const argv[], const char *optstring,
                const struct option *longopts, int *longindex);


#endif /* __RTOS_WIN32__ */


#endif /* __MOC_CMD_LINE_H */
