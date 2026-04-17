 /*
 * ossl_sample_utils.h
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

#ifndef __OSSL_SAMPLE_UTILS_H
#define __OSSL_SAMPLE_UTILS_H


#ifdef __RTOS_WIN32__
extern int  opterr;	    /* if error message should be printed */
extern int  optind;	    /* index into parent argv vector */
extern int  optopt;	    /* character checked for validity */
extern char *optarg;	/* argument associated with option */

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
int getopt(int argc, char **argv, const char *optstr);

/* getopt_long
 * accepts long options starting with "--"
 *
 * Notes
 * - Currently accepts only long options. Doesn't support optstring option.
 *   Use getopt() for using single char options prefixed with '-'
 * - Support long format with equal character only as in "--arg=value".
 *   Needs minor modifications for supporting space in this, as in "--arg value"
 */
int getopt_long(int argc, char * const argv[], const char *optstring,
                const struct option *longopts, int *longindex);


#endif /* __RTOS_WIN32__ */


#endif /* __OSSL_SAMPLE_UTILS_H */
