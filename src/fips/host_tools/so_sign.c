#include <stdio.h>
#include "../../common/moptions.h"

#ifdef __ENABLE_DIGICERT_FIPS_SOSIGN__

#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"
#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mrtos.h"
#include "../../common/mstdlib.h"
#include "../../crypto/crypto.h"
#include "../../crypto/fips.h"
#include "../../crypto/fips_priv.h"
#include "../../crypto/sha256.h"

#endif

#ifdef __ENABLE_DIGICERT_FIPS_SOSIGN__

#ifdef __cplusplus
extern "C" {
#endif
extern int FIPS_INTEG_TEST_hash_bin();
#ifdef _cplusplus
}
#endif

#include <stdio.h>

static char sig_file_name_const[] = FIPS_INTEG_TEST_HASH_FILENAME;

int main( int argc, char* argv[])
{
    MSTATUS status;
    ubyte hashReturn[SHA256_RESULT_SIZE];
    FILE* f;
    int i;

    char *bin_file_name = NULL;
    char *sig_file_name = NULL;

    /* Either no parms, (use #defined values, or two parms (use these) */
    if (argc == 1)
    {
    	bin_file_name = NULL;
    	sig_file_name = sig_file_name_const;
        printf("so_sign  %s  %s  \n", FIPS_INTEG_TEST_BINARY_FILENAME ,sig_file_name_const);
    }
    else if (argc == 3)
    {
    	bin_file_name = argv[1];
    	sig_file_name = argv[2];
    }
    else
    {
        printf("Usage: so_sign <so_file_name> <so_signature_file_name>\n");
        return 1;
    }

	/* FORCE OK so we can run HMAC SHA256 */
	setFIPS_Status(FIPS_ALGO_SHA256, OK);
	setFIPS_Status(FIPS_ALGO_HMAC, OK);

    if (OK > (status = FIPS_INTEG_TEST_hash_bin(hashReturn, bin_file_name)))
    {
        printf("FIPS_INTEG_TEST_hash_bin failed: %d\n", status);
        return 1;
    }

   	f = fopen(sig_file_name, "w");

    if (0 == f)
    {
        printf("Unable to open %s\n", FIPS_INTEG_TEST_HASH_FILENAME);
        return 2;
    }

    for (i = 0; i < SHA256_RESULT_SIZE; ++i)
    {
        fprintf(f, "%02x", hashReturn[i]);
    }
    fclose(f);

    return 0;

}
#else

int main( int argc, char* argv[])
{
    printf("****************************************************************************\n");
    printf("WARNING! so_sign does nothing unless __ENABLE_DIGICERT_FIPS_SOSIGN__ is defined\n");
    printf("****************************************************************************\n");
    return 0;
}


#endif


