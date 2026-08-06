/*
 * EAP-AKA file-based quintuplet store.
 *
 * Reads pre-computed (RAND, AUTN, XRES, CK, IK) tuples from a CSV file so
 * that StrongSwan can act as an AKA authenticator against peers whose AKA
 * responses are hardcoded (e.g. NanoSec test builds), without requiring
 * Milenage/CAVE crypto.
 *
 * File format — one entry per line, comma-separated, # for comments:
 *   identity,RAND(32 hex),AUTN(32 hex),XRES(hex),CK(32 hex),IK(32 hex)
 */

#ifndef EAP_AKA_FILE_QUINTUPLETS_H_
#define EAP_AKA_FILE_QUINTUPLETS_H_

#include <library.h>
#include <simaka_crypto.h>

typedef struct eap_aka_file_quintuplets_t eap_aka_file_quintuplets_t;

struct eap_aka_file_quintuplets_t {
	/**
	 * Enumerate (id*, rand*, autn*, xres*, xres_len*, ck*, ik*) tuples.
	 * Holds the internal mutex for its lifetime; caller must destroy().
	 */
	enumerator_t *(*create_enumerator)(eap_aka_file_quintuplets_t *this);

	void (*destroy)(eap_aka_file_quintuplets_t *this);
};

eap_aka_file_quintuplets_t *eap_aka_file_quintuplets_create(char *file);

#endif /* EAP_AKA_FILE_QUINTUPLETS_H_ */
