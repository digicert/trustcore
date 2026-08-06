#include "eap_aka_file_provider.h"

#include <daemon.h>
#include <simaka_manager.h>

typedef struct private_eap_aka_file_provider_t private_eap_aka_file_provider_t;

struct private_eap_aka_file_provider_t {
	eap_aka_file_provider_t    public;
	eap_aka_file_quintuplets_t *quintuplets;
};

METHOD(simaka_provider_t, get_quintuplet, bool,
	private_eap_aka_file_provider_t *this, identification_t *id,
	char rand[AKA_RAND_LEN],
	char xres[AKA_RES_MAX], int *xres_len,
	char ck[AKA_CK_LEN], char ik[AKA_IK_LEN],
	char autn[AKA_AUTN_LEN])
{
	enumerator_t     *enumerator;
	identification_t *cand;
	char *c_rand, *c_autn, *c_xres, *c_ck, *c_ik;
	int   c_xres_len;

	enumerator = this->quintuplets->create_enumerator(this->quintuplets);
	while (enumerator->enumerate(enumerator, &cand,
				&c_rand, &c_autn, &c_xres, &c_xres_len, &c_ck, &c_ik))
	{
		if (id->matches(id, cand))
		{
			memcpy(rand,  c_rand, AKA_RAND_LEN);
			memcpy(autn,  c_autn, AKA_AUTN_LEN);
			memcpy(xres,  c_xres, c_xres_len);
			*xres_len = c_xres_len;
			memcpy(ck,    c_ck,   AKA_CK_LEN);
			memcpy(ik,    c_ik,   AKA_IK_LEN);
			enumerator->destroy(enumerator);
			return TRUE;
		}
	}
	enumerator->destroy(enumerator);
	return FALSE;
}

METHOD(eap_aka_file_provider_t, destroy, void,
	private_eap_aka_file_provider_t *this)
{
	free(this);
}

eap_aka_file_provider_t *eap_aka_file_provider_create(
				eap_aka_file_quintuplets_t *quintuplets)
{
	private_eap_aka_file_provider_t *this;

	INIT(this,
		.public = {
			.provider = {
				.get_triplet    = (void*)return_false,
				.get_quintuplet = _get_quintuplet,
				.resync         = (void*)return_false,
				.is_pseudonym   = (void*)return_null,
				.gen_pseudonym  = (void*)return_null,
				.is_reauth      = (void*)return_null,
				.gen_reauth     = (void*)return_null,
			},
			.destroy = _destroy,
		},
		.quintuplets = quintuplets,
	);
	return &this->public;
}
