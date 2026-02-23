/*
 * moc_evp_fips_version_test.c
 *
 * Test program to verify FIPS module version functions
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
#include <openssl/engine.h>

/* Not part of the standard OpenSSL headers
 *
 * Only exists in the FIPS module. Assuming the FIPS header
 * will be included by the application so this won't be
 * required but since the FIPS header is not available,
 * declare the FIPS functions here
 */
unsigned long FIPS_module_version(void);
const char *FIPS_module_version_text(void);

int main()
{
#if defined(__EVP_NAMESPACE_CONFLICT__)
    ENGINE *e;
    int ret = -1;
    const char *pVersion;
    unsigned long versionNum;

    pVersion = FIPS_module_version_text();
    if (NULL == pVersion)
    {
        printf("ERROR: Failed to get FIPS version string\n");
        goto exit;
    }

    printf("FIPS version string: %s\n", pVersion);

    versionNum = FIPS_module_version();
    if (0 == versionNum)
    {
        printf("ERROR: Failed to get FIPS version number\n");
        goto exit;
    }

    printf("FIPS version number: %lx\n", versionNum);

    ret = 0;

exit:

    return ret;
#else
    printf("FIPS is not enabled...skipping test\n");
    return 0;
#endif
}