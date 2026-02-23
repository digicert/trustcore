/*
 * digitest_cnf.c
 *
 * digi provider for OSSL 3.0 test configuration file utility
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

#ifdef __ENABLE_DIGICERT_OSSL_V3_TEST__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include "digitest_cnf.h"
#include "testutil.h"

#define SECT_FILTERS                "Filters"
#define KEY_FILTERS_AVAILABLEIN     "Availablein"
#define KEY_FILTERS_ALGO            "Algo"

/*
 * Parses provider filter and sets in `digiTestFilter`
 * return 1 on success else 0
 */ 
static int parseProviderFilters(CONF *conf, const char* availableinSectName,
                                DigiTestFilter *digiTestFilter)
{
    int retVal = 1;
    STACK_OF(CONF_VALUE) *providersSect = NULL;

    if (NULL == availableinSectName || NULL == digiTestFilter)
        goto err;

    providersSect = NCONF_get_section(conf, availableinSectName);
    
    if ( 0 < sk_CONF_VALUE_num(providersSect))
    {
        int provSectNameLen = strlen(availableinSectName);
        char *provSectName= calloc(provSectNameLen+1, sizeof(*provSectName));

        if(NULL == provSectName)
        {
            TEST_error("Failed to allocate memory for provider section name");
            retVal = 0;
            goto err;
        }

        if (NULL == strcpy(provSectName, availableinSectName))
        {
            TEST_error("Failed to copy provider section name");
            retVal = 0;
            goto err;
        }

        digiTestFilter->providersSect = providersSect;
        digiTestFilter->providerSectName = provSectName;
    }

err:
    return retVal;
}

/*
 * Parses the algorithm filters and set in `digiTestFilter`
 * return 1 on success else 0
 */
static int parseAlgoFilters(CONF *conf, const char *algoSectName,
                            DigiTestFilter *digiTestFilter)
{
    int retVal = 1;
    STACK_OF(CONF_VALUE) *algoSect = NULL;

    if (NULL == algoSectName || NULL == digiTestFilter)
        goto err;

    algoSect = NCONF_get_section(conf, algoSectName);
    
    if ( 0 < sk_CONF_VALUE_num(algoSect))
    {
        int algoSectLen = strlen(algoSectName);
        char *algoSectStr= calloc(algoSectLen+1, sizeof(*algoSectStr));
        if(NULL == algoSectStr)
        {
            TEST_error("Failed to allocate memory for algorithm section name");
            retVal = 0;
            goto err;
        }

        if (NULL == strcpy(algoSectStr, algoSectName))
        {
            TEST_error("Failed to copy algorithm section name");
            retVal = 0;
            goto err;
        }

        digiTestFilter->algoSect = algoSect;
        digiTestFilter->algoSectName = algoSectStr;
    }

err:
    return retVal;
}

/*
 * Loads the Configuration file and parse the filters to apply. 
 * Filter configurations are set in `digiTestFilter`
 * return 1 on success,0 is error.
 */
int loadDigiTestConf(const char *digitest_conf_file, DigiTestFilter *digiTestFilter)
{
    int retVal = 1; /* 1 is success, 0 is error */
    long eline = -1;
    int errCode = 0;
    const char *file = "digiprov_test.cnf";
    CONF *conf = NULL;
    STACK_OF(CONF_VALUE) *filterSect = NULL;
    char availableinSect[128] ={0};
    char algoSect[128] = {0};
    int availableinSectFound = 0;
    int algoSectFound = 0;

    file = (NULL == digitest_conf_file) ? file : digitest_conf_file;

    conf = NCONF_new(NULL);
    if (conf == NULL)
        goto err;

    retVal = NCONF_load(conf, file, &eline);
    if (retVal <= 0) {
        errCode = ERR_GET_REASON(ERR_peek_last_error());
        TEST_error("Failed loading configuraton file %s, error-code=%d, error-at-line=%ld",
                file, errCode, eline);
        goto err;
    }

    filterSect = NCONF_get_section(conf, SECT_FILTERS);
    if (NULL != filterSect)
    {
        int i;
        for (i = 0; i < sk_CONF_VALUE_num(filterSect); i++)
        {
            CONF_VALUE *sectconf = sk_CONF_VALUE_value(filterSect, i);

            if (NULL != sectconf)
            {
                if (0 == strcasecmp(KEY_FILTERS_AVAILABLEIN, sectconf->name))
                {
                    strncpy(availableinSect, sectconf->value, sizeof(availableinSect)-1);
                    availableinSectFound = 1;
                    retVal = parseProviderFilters(conf, availableinSect, digiTestFilter);
                    if (!retVal)
                    {
                        TEST_error("Failed parsing Availablein filters, status=%d", retVal);
                        goto err;
                    }
                }
                else if (0 == strcasecmp(KEY_FILTERS_ALGO, sectconf->name))
                {
                    strncpy(algoSect, sectconf->value, sizeof(algoSect)-1);
                    algoSectFound = 1;
                    retVal = parseAlgoFilters(conf, algoSect, digiTestFilter);
                    if (!retVal)
                    {
                        TEST_error("Failed parsing algo filters, status=%d", retVal);
                        goto err;
                    }
                }
                else
                {
                    TEST_error("Invalid key %s in section %s\n", sectconf->name, SECT_FILTERS);
                }
            }
        }
        digiTestFilter->conf = conf;
    }

err:
    return retVal;
}

/* Checks if the incoming `provName` is shortlisted in filter configuration for digi prov testing
 * returns 1 if true else 0 
 */
int checkIfProviderShortlisted(DigiTestFilter *digiTestFilter, const char *provName)
{
    int retVal = 0;
    int idx = -1;

    if ((NULL != digiTestFilter) && (NULL != digiTestFilter->providersSect) &&
        (NULL != provName))
    {
        int numVals = sk_CONF_VALUE_num(digiTestFilter->providersSect);
        for (int i = 0; i < numVals; i++)
        {
            CONF_VALUE *sectconf = sk_CONF_VALUE_value(digiTestFilter->providersSect, i);

            if (NULL != sectconf)
            {
                if ((0 == strcasecmp(provName, sectconf->name)) &&
                    (0 == strcmp("1", sectconf->value)) )
                {
                    /* found a matching algorithm */
                    idx = i;
                    break;
                }
            }
        }

        if (0 <= idx)
        {
            /* Found a match in provider filter section */
            TEST_info("Found a match for %s in provider filter section", provName);
            retVal = 1;
        }
    }
    else
    {
        /* If no filters set then allow all */
        retVal = 1;
    }

err:
    return retVal;
}

/* 
 * Checks if the incoming `algoName` is shortlisted in filter configuration for digi prov testing
 * returns 1 if true else 0 
 */
int checkIfAlgoShortlisted(DigiTestFilter *digiTestFilter, const char *algoName)
{
    int retVal = 0;
    int idx = -1;

    if ( (NULL != digiTestFilter) && (NULL != digiTestFilter->algoSect) &&
            (NULL != algoName) )
    {
        int numVals = sk_CONF_VALUE_num(digiTestFilter->algoSect);
        for (int i = 0; i < numVals; i++)
        {
            CONF_VALUE *sectconf = sk_CONF_VALUE_value(digiTestFilter->algoSect, i);

            if (NULL != sectconf)
            {
                if ((0 == strcasecmp(algoName, sectconf->name)) &&
                    (0 == strcmp("1", sectconf->value)) )
                {
                    /* found a matching algorithm */
                    idx = i;
                    break;
                }
            }
        }

        if (0 <= idx)
        {
            /* Found a match in algo filter section */
            TEST_info("Found a match for %s in algo filter section", algoName);
            retVal = 1;
        }
    }
    else
    {
        /* If no filters set then allow all */
        retVal = 1;
    }

err:
    return retVal;
}

/* Free the memory allocated to members for DigiTestFilter struct */
void free_digiTestFilter(DigiTestFilter *digiTestFilter)
{
    if((NULL != digiTestFilter))
    {
        if (NULL != digiTestFilter->algoSectName)
        {
            free(digiTestFilter->algoSectName);
            digiTestFilter->algoSectName = NULL;
        }
        if (NULL != digiTestFilter->providerSectName)
        {
            free(digiTestFilter->providerSectName);
            digiTestFilter->providerSectName = NULL;
        }

        if (NULL != digiTestFilter->conf)
        {
            NCONF_free(digiTestFilter->conf);
            digiTestFilter->conf = NULL;
        }
    }
}

#endif /*__ENABLE_DIGICERT_OSSL_V3_TEST__*/

