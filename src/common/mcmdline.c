/* mcmdline.c
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

#include <stdlib.h>
#include <string.h>

#include "moptions.h"
#include "mtypes.h"
#include "debug_console.h"
#include "mcmdline.h"

#if defined(__RTOS_WIN32__) && !defined(__DISABLE_DIGICERT_GETOPT__)
/*Definition for static opt variables*/
MOC_EXTERN_MCMDLINE_H int optind = 1;		/* index into parent argv vector */
MOC_EXTERN_MCMDLINE_H int opterr = 1;		/* if error message should be printed. 0=No, else Yes*/
MOC_EXTERN_MCMDLINE_H int optopt = '?';	/* character checked for validity */
MOC_EXTERN_MCMDLINE_H char *optarg = NULL;

/* getopt
*/
MOC_EXTERN int getopt(int argc, char **argv, const char *optstr)
{
    char *optPtr;

    if ((NULL == optstr) || (NULL == argv) ||
        (0 == argc))
    {
        goto exit;
    }

    optopt = -1;
    optarg = NULL;
    if (optind < argc)
    {
        if ('-' == argv[optind][0])
        {
            if (argv[optind][1] && (NULL != (optPtr = strchr(optstr, argv[optind][1]))))
            {
                optopt = (int)argv[optind][1];

                /* Will this option have a parameter ? */
                if (*(optPtr + 1) && (':' == *(optPtr + 1)))
                {
                    optind++;

                    if (optind < argc)
                    {
                        if ('-' != argv[optind][0])
                        {
                            optarg = argv[optind];
                            optind++;
                        }
                    }
                }
                else
                    optind++;
            }
        }
    }

exit:

    return optopt;
}

/*** getopt_long implementation ***/

/* PRINT_ERROR_NO_ARGS macro would print an error only if opterr is set to a non-zero value.
*/
#define PRINT_ERROR_NO_ARGS(ERR_STR)	\
    if (0!=opterr) \
    {\
        DB_PRINT("%s() - %d: "ERR_STR"\n", __FUNCTION__, __LINE__);\
    }

#define PRINT_ERROR(fmt, ...) \
    if (0!=opterr) \
    {\
        DB_PRINT("%s() - %d: "fmt"\n", __FUNCTION__, __LINE__, ##__VA_ARGS__ );\
    } 


int searchLongOption(const char *optionStr, size_t optionStrLen, const struct option *longopts);

/* getopt_long
*/
MOC_EXTERN int getopt_long(int argc, char * const argv[], const char *optstring,
                const struct option *longopts, int *longindex)
{
    int retval = -1;            //-1 indicates error
    int iter = 0;               //for iteration of longopts
    char *equal_pos = NULL;     //indicates presence and position of '=' char
    char *current_opt = NULL;
    size_t current_opt_len = 0;
    int longopt_index = -1;
    const struct option *current_longopt = NULL;

    /*Initialize static opt vars with default error values*/
    optopt = '?';
    optarg = NULL;

    if ( (NULL != optstring) && (0 != *optstring) )
    {
        PRINT_ERROR_NO_ARGS("getopt_long() only support long options parsing, for short options use getopt()"); 
        goto exit;
    }

    if (NULL == longopts)
    {
        PRINT_ERROR_NO_ARGS("Invalid arguments: longopts cannot be null"); 
        goto exit;
    }

    if (argc <= optind)
    {
        //PRINT_ERROR_NO_ARGS("Finished parsing arguments"); 
        goto exit;
    }

    iter = 0;
    while ( (0 != argv[optind][iter]) && (iter<2) )
    {
        if ('-' != argv[optind][iter])
        {
            PRINT_ERROR_NO_ARGS("Error parsing, options should begin with -- prefix.");
            goto exit;
        }
        iter++;
    }

    current_opt = argv[optind] + 2;
    equal_pos = strchr(argv[optind],'=');
    current_opt_len = (NULL != equal_pos) ? (equal_pos - current_opt) : strlen(current_opt); 

    if (0 > current_opt_len)
    {
        PRINT_ERROR("Empty option encountered for %d-th argument", optind); 
        goto exit;
    }

    longopt_index = searchLongOption(current_opt, current_opt_len, longopts);
    if (0 > longopt_index)
    {
        PRINT_ERROR("Invalid argument - %s", argv[optind]); 
        goto exit;
    }

    current_longopt = longopts + longopt_index;
    if (    ( (no_argument == current_longopt->has_arg) && (NULL != equal_pos) )
       ||   ( (required_argument == current_longopt->has_arg) && (NULL == equal_pos) )
       )
    {
        PRINT_ERROR("Error parsing option argument and value", argv[optind]);
        goto exit;
    }

    switch(current_longopt->has_arg)
    {
        case optional_argument:
        case required_argument:
            {
                optarg= (NULL != equal_pos) ? equal_pos+1 : NULL;
            }
        case no_argument:
        default:    /*common processing for all types of options*/
            {
                optind++;
                optopt = (int)current_opt[0];
                if(NULL == current_longopt->flag)
                {
                    retval = current_longopt->val;
                }
                else
                {
                    *(current_longopt->flag) = current_longopt->val;
                    retval = 0;
                }
            }
            break;
    }

exit:
    return retval; 
}


/* searchLongOption
 * Searches the incoming array of option struct, to find a match for optionStr
 * Returns the index of the struct if found, else -1
 * Returns -1 for error too.
 */
int searchLongOption(const char *optionStr, size_t optionStrLen, const struct option *longopts)
{
    int matched_index = -1;
    const struct option *longopt_ptr = NULL;

    if (NULL == longopts)
    {
        PRINT_ERROR_NO_ARGS("Invalid argument: longopts cannot be null"); 
        goto exit;
    }

    for (longopt_ptr=longopts; NULL != longopt_ptr->name; longopt_ptr++)
    {
        if (0 == strncmp(longopt_ptr->name, optionStr, optionStrLen))
        {
            matched_index = (int)(longopt_ptr - longopts);
            goto exit;
        }
    }

exit:
    return matched_index;
}

#endif /* __RTOS_WIN32__ */
