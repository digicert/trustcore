#
# Makefile for IPsec example integration code for Linux
#
# Copyright 2026 DigiCert Project Authors. All Rights Reserved.
#
# This is a convenience Makefile used for building the GPL and non-GPL
# portions of the Linux integration code and Mocana IPsec code, respectively.
#
#

prepare:
	ln -fs ../../../../make/Makefile.linux.cross gpl/
	cd gpl && make links

all:
	cd mocana && $(MAKE) BUILD_IPSEC_MOD=$(BUILD_IPSEC_MOD)
	cd gpl && $(MAKE) BUILD_IPSEC_MOD=$(BUILD_IPSEC_MOD) \
		KBUILD_EXTRA_SYMBOLS="$(CURDIR)/mocana/Module.symvers"

clean:
	cd mocana && $(MAKE) BUILD_IPSEC_MOD=$(BUILD_IPSEC_MOD) clean
	cd gpl && $(MAKE) BUILD_IPSEC_MOD=$(BUILD_IPSEC_MOD) clean
	-rm -f gpl/*.o_shipped
	-rm -f gpl/Makefile.linux.cross
