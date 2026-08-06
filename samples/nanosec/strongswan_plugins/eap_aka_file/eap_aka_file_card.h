#ifndef EAP_AKA_FILE_CARD_H_
#define EAP_AKA_FILE_CARD_H_

#include "eap_aka_file_quintuplets.h"
#include <simaka_card.h>

typedef struct eap_aka_file_card_t eap_aka_file_card_t;

struct eap_aka_file_card_t {
	simaka_card_t card;
	void (*destroy)(eap_aka_file_card_t *this);
};

eap_aka_file_card_t *eap_aka_file_card_create(eap_aka_file_quintuplets_t *quintuplets);

#endif
