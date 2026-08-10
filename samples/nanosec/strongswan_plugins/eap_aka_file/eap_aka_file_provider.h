#ifndef EAP_AKA_FILE_PROVIDER_H_
#define EAP_AKA_FILE_PROVIDER_H_

#include "eap_aka_file_quintuplets.h"
#include <simaka_provider.h>

typedef struct eap_aka_file_provider_t eap_aka_file_provider_t;

struct eap_aka_file_provider_t {
	simaka_provider_t provider;
	void (*destroy)(eap_aka_file_provider_t *this);
};

eap_aka_file_provider_t *eap_aka_file_provider_create(
				eap_aka_file_quintuplets_t *quintuplets);

#endif /* EAP_AKA_FILE_PROVIDER_H_ */
