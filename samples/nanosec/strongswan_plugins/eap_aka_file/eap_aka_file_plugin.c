#include "eap_aka_file_plugin.h"
#include "eap_aka_file_card.h"
#include "eap_aka_file_provider.h"
#include "eap_aka_file_quintuplets.h"

#include <daemon.h>
#include <simaka_manager.h>

#ifndef IPSEC_CONFDIR
#define IPSEC_CONFDIR "/etc"
#endif

#define QUINTUPLET_FILE IPSEC_CONFDIR "/ipsec.d/aka_quintuplets.dat"

typedef struct private_eap_aka_file_plugin_t private_eap_aka_file_plugin_t;

struct private_eap_aka_file_plugin_t {
	eap_aka_file_plugin_t       public;
	eap_aka_file_card_t        *card;
	eap_aka_file_provider_t    *provider;
	eap_aka_file_quintuplets_t *quintuplets;
};

METHOD(plugin_t, get_name, char*,
	private_eap_aka_file_plugin_t *this)
{
	return "eap-aka-file";
}

static bool load_quintuplets(private_eap_aka_file_plugin_t *this,
			     plugin_feature_t *feature, bool reg, void *data)
{
	if (reg)
	{
		this->quintuplets = eap_aka_file_quintuplets_create(QUINTUPLET_FILE);
		if (!this->quintuplets)
			return FALSE;
		this->card     = eap_aka_file_card_create(this->quintuplets);
		this->provider = eap_aka_file_provider_create(this->quintuplets);
		return TRUE;
	}
	this->card->destroy(this->card);
	this->provider->destroy(this->provider);
	this->quintuplets->destroy(this->quintuplets);
	this->card        = NULL;
	this->provider    = NULL;
	this->quintuplets = NULL;
	return TRUE;
}

static simaka_card_t *get_card(private_eap_aka_file_plugin_t *this)
{
	return &this->card->card;
}

static simaka_provider_t *get_provider(private_eap_aka_file_plugin_t *this)
{
	return &this->provider->provider;
}

METHOD(plugin_t, get_features, int,
	private_eap_aka_file_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK((void*)load_quintuplets, NULL),
			PLUGIN_PROVIDE(CUSTOM, "eap-aka-file-quintuplets"),
		PLUGIN_CALLBACK(simaka_manager_register, get_card),
			PLUGIN_PROVIDE(CUSTOM, "aka-card"),
				PLUGIN_DEPENDS(CUSTOM, "aka-manager"),
				PLUGIN_DEPENDS(CUSTOM, "eap-aka-file-quintuplets"),
		PLUGIN_CALLBACK(simaka_manager_register, get_provider),
			PLUGIN_PROVIDE(CUSTOM, "aka-provider"),
				PLUGIN_DEPENDS(CUSTOM, "aka-manager"),
				PLUGIN_DEPENDS(CUSTOM, "eap-aka-file-quintuplets"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_eap_aka_file_plugin_t *this)
{
	free(this);
}

PLUGIN_DEFINE(eap_aka_file)
{
	private_eap_aka_file_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name     = _get_name,
				.get_features = _get_features,
				.destroy      = _destroy,
			},
		},
	);
	return &this->public.plugin;
}
