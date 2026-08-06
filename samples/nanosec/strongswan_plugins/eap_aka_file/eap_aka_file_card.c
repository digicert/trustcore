#include "eap_aka_file_card.h"

#include <daemon.h>
#include <simaka_manager.h>

typedef struct private_eap_aka_file_card_t private_eap_aka_file_card_t;

struct private_eap_aka_file_card_t {
	eap_aka_file_card_t    public;
	eap_aka_file_quintuplets_t *quintuplets;
};

/*
 * Look up pre-computed (CK, IK, RES) for (id, rand).
 * AUTN is accepted as-is — this is a test card, not a real USIM.
 */
METHOD(simaka_card_t, get_quintuplet, status_t,
	private_eap_aka_file_card_t *this, identification_t *id,
	char rand[AKA_RAND_LEN], char autn[AKA_AUTN_LEN],
	char ck[AKA_CK_LEN], char ik[AKA_IK_LEN],
	char res[AKA_RES_MAX], int *res_len)
{
	enumerator_t     *enumerator;
	identification_t *cand;
	char *c_rand, *c_autn, *c_xres, *c_ck, *c_ik;
	int   c_xres_len;
	status_t ret = NOT_FOUND;

	enumerator = this->quintuplets->create_enumerator(this->quintuplets);
	while (enumerator->enumerate(enumerator, &cand,
				&c_rand, &c_autn, &c_xres, &c_xres_len, &c_ck, &c_ik))
	{
		if (id->matches(id, cand) &&
		    memeq(rand, c_rand, AKA_RAND_LEN))
		{
			memcpy(ck,  c_ck,   AKA_CK_LEN);
			memcpy(ik,  c_ik,   AKA_IK_LEN);
			memcpy(res, c_xres, c_xres_len);
			*res_len = c_xres_len;
			DBG1(DBG_IKE, "eap-aka-file card: found quintuplet for %Y", id);
			ret = SUCCESS;
			break;
		}
	}
	enumerator->destroy(enumerator);
	return ret;
}

METHOD(eap_aka_file_card_t, destroy, void,
	private_eap_aka_file_card_t *this)
{
	free(this);
}

eap_aka_file_card_t *eap_aka_file_card_create(eap_aka_file_quintuplets_t *quintuplets)
{
	private_eap_aka_file_card_t *this;

	INIT(this,
		.public = {
			.card = {
				.get_triplet    = (void*)return_false,
				.get_quintuplet = _get_quintuplet,
				.resync         = (void*)return_false,
				.set_pseudonym  = (void*)nop,
				.get_pseudonym  = (void*)return_null,
				.set_reauth     = (void*)nop,
				.get_reauth     = (void*)return_null,
			},
			.destroy = _destroy,
		},
		.quintuplets = quintuplets,
	);
	return &this->public;
}
