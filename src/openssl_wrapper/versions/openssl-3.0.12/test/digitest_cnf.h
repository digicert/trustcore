/*
 * digitest_cnf.h
 *
 * digi provider for OSSL 3.0 test configuration file utility
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

#ifndef DIGICERT_COMMON_H
#define DIGICERT_COMMON_H

#ifdef __ENABLE_DIGICERT_OSSL_V3_TEST__

#define ENV_PATH_DIGITEST_CNF   "DIGITEST_CNF"
#define DIGIPROV_PROP_STR       "provider=digi"

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct
{
    CONF *conf;

    char *providerSectName;  
    STACK_OF(CONF_VALUE) *providersSect;

    char *algoSectName;  
    STACK_OF(CONF_VALUE) *algoSect;
}DigiTestFilter;

/* Load Digi Provider test configuration file */
int loadDigiTestConf(const char *digitest_conf_file, DigiTestFilter *digiTestFilter);

/* returns 1 if true else 0 */
int checkIfAlgoShortlisted(DigiTestFilter *digiTestFilter, const char *algoName);
/* returns 1 if true else 0 */
int checkIfProviderShortlisted(DigiTestFilter *digiTestFilter, const char *provName);
/* free the memory allocated to members for DigiTestFilter struct */
void free_digiTestFilter(DigiTestFilter *digiTestFilter);

#ifdef  __cplusplus
}
#endif

#endif /*__ENABLE_DIGICERT_OSSL_V3_TEST__*/

#endif /* DIGICERT_COMMON_H */
