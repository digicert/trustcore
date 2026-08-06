#include "eap_aka_file_quintuplets.h"

#include <stdio.h>
#include <errno.h>
#include <daemon.h>
#include <collections/linked_list.h>
#include <threading/mutex.h>
#include <simaka_manager.h>

typedef struct private_eap_aka_file_quintuplets_t private_eap_aka_file_quintuplets_t;

struct private_eap_aka_file_quintuplets_t {
	eap_aka_file_quintuplets_t public;
	linked_list_t *list;
	mutex_t       *mutex;
};

typedef struct {
	identification_t *id;
	char rand[AKA_RAND_LEN];
	char autn[AKA_AUTN_LEN];
	char xres[AKA_RES_MAX];
	int  xres_len;
	char ck[AKA_CK_LEN];
	char ik[AKA_IK_LEN];
} quintuplet_t;

static void quintuplet_destroy(quintuplet_t *q)
{
	DESTROY_IF(q->id);
	free(q);
}

/* --- enumerator --- */

typedef struct {
	enumerator_t public;
	enumerator_t *inner;
	private_eap_aka_file_quintuplets_t *this;
} qenum_t;

METHOD(enumerator_t, qenum_destroy, void, qenum_t *e)
{
	e->inner->destroy(e->inner);
	e->this->mutex->unlock(e->this->mutex);
	free(e);
}

METHOD(enumerator_t, qenum_enumerate, bool, qenum_t *e, va_list args)
{
	identification_t **id;
	char **rand_p, **autn_p, **xres_p, **ck_p, **ik_p;
	int *xres_len_p;
	quintuplet_t *q;

	id         = va_arg(args, identification_t**);
	rand_p     = va_arg(args, char**);
	autn_p     = va_arg(args, char**);
	xres_p     = va_arg(args, char**);
	xres_len_p = va_arg(args, int*);
	ck_p       = va_arg(args, char**);
	ik_p       = va_arg(args, char**);

	if (e->inner->enumerate(e->inner, &q))
	{
		*id        = q->id;
		*rand_p    = q->rand;
		*autn_p    = q->autn;
		*xres_p    = q->xres;
		*xres_len_p = q->xres_len;
		*ck_p      = q->ck;
		*ik_p      = q->ik;
		return TRUE;
	}
	return FALSE;
}

METHOD(eap_aka_file_quintuplets_t, create_enumerator, enumerator_t*,
	private_eap_aka_file_quintuplets_t *this)
{
	qenum_t *e;

	this->mutex->lock(this->mutex);
	INIT(e,
		.public = {
			.enumerate  = enumerator_enumerate_default,
			.venumerate = _qenum_enumerate,
			.destroy    = _qenum_destroy,
		},
		.inner = this->list->create_enumerator(this->list),
		.this  = this,
	);
	return &e->public;
}

/*
 * Decode a hex string of at most dst_len bytes into dst (zero-padded on the left).
 */
static void parse_hex(char *dst, char *src, int dst_len)
{
	chunk_t c = chunk_create(src, min(strlen(src), (size_t)dst_len * 2));
	c = chunk_from_hex(c, NULL);
	memset(dst, 0, dst_len);
	memcpy(dst + dst_len - c.len, c.ptr, c.len);
	free(c.ptr);
}

/*
 * Decode a variable-length hex string.  Returns number of bytes decoded
 * (capped at dst_len).
 */
static int parse_hex_var(char *dst, char *src, int dst_len)
{
	size_t hex_len = strlen(src);
	int bin_len = (int)(hex_len / 2);
	if (bin_len > dst_len)
		bin_len = dst_len;
	/* parse_hex zero-pads on the left; we want left-aligned for XRES */
	chunk_t c = chunk_create(src, hex_len);
	c = chunk_from_hex(c, NULL);
	memset(dst, 0, dst_len);
	memcpy(dst, c.ptr, min((size_t)bin_len, c.len));
	free(c.ptr);
	return bin_len;
}

static bool read_quintuplets(private_eap_aka_file_quintuplets_t *this, char *path)
{
	FILE *f;
	char line[512];
	int nr = 0, loaded = 0;

	f = fopen(path, "r");
	if (!f)
	{
		DBG1(DBG_CFG, "opening AKA quintuplet file %s failed: %s",
		     path, strerror(errno));
		return FALSE;
	}

	while (fgets(line, sizeof(line), f))
	{
		enumerator_t *tok;
		char *token;
		quintuplet_t *q;
		int i = 0;

		nr++;
		switch (line[0])
		{
			case '\n': case '\r': case '#': case '\0':
				continue;
			default:
				break;
		}

		q = malloc_thing(quintuplet_t);
		memset(q, 0, sizeof(*q));

		tok = enumerator_create_token(line, ",", " \n\r");
		while (tok->enumerate(tok, &token))
		{
			switch (i++)
			{
				case 0: q->id = identification_create_from_string(token); continue;
				case 1: parse_hex(q->rand, token, AKA_RAND_LEN);          continue;
				case 2: parse_hex(q->autn, token, AKA_AUTN_LEN);          continue;
				case 3: q->xres_len = parse_hex_var(q->xres, token, AKA_RES_MAX); continue;
				case 4: parse_hex(q->ck, token, AKA_CK_LEN);              continue;
				case 5: parse_hex(q->ik, token, AKA_IK_LEN);              continue;
				default: break;
			}
			break;
		}
		tok->destroy(tok);

		if (i < 6)
		{
			DBG1(DBG_CFG, "error in AKA quintuplet file, line %d", nr);
			quintuplet_destroy(q);
			continue;
		}
		DBG2(DBG_CFG, "AKA quintuplet: id %Y rand %b autn %b xres %b ck %b ik %b",
		     q->id,
		     q->rand, AKA_RAND_LEN,
		     q->autn, AKA_AUTN_LEN,
		     q->xres, q->xres_len,
		     q->ck,   AKA_CK_LEN,
		     q->ik,   AKA_IK_LEN);
		this->list->insert_last(this->list, q);
		loaded++;
	}
	fclose(f);
	DBG1(DBG_CFG, "read %d AKA quintuplets from %s", loaded, path);
	return TRUE;
}

METHOD(eap_aka_file_quintuplets_t, destroy, void,
	private_eap_aka_file_quintuplets_t *this)
{
	this->list->destroy_function(this->list, (void*)quintuplet_destroy);
	this->mutex->destroy(this->mutex);
	free(this);
}

eap_aka_file_quintuplets_t *eap_aka_file_quintuplets_create(char *file)
{
	private_eap_aka_file_quintuplets_t *this;

	INIT(this,
		.public = {
			.create_enumerator = _create_enumerator,
			.destroy           = _destroy,
		},
		.list  = linked_list_create(),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
	);

	if (!read_quintuplets(this, file))
	{
		destroy(this);
		return NULL;
	}
	return &this->public;
}
