# Copyright 2012-2013 Luke Dashjr
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the standard MIT license.  See COPYING for more details.

lib_LTLIBRARIES = \
	libblkmaker_jansson-@LIBBLKMAKER_API_VERSION@.la \
	libblkmaker-@LIBBLKMAKER_API_VERSION@.la


libblkmaker_@LIBBLKMAKER_API_VERSION@_la_SOURCES = \
	base58.c \
	blkmaker.c \
	blktemplate.c \
	hex.c \
	private.h

libblkmaker_@LIBBLKMAKER_API_VERSION@_la_CFLAGS = \
	$(libbase58_CFLAGS)
libblkmaker_@LIBBLKMAKER_API_VERSION@_la_LDFLAGS = \
	$(libbase58_LIBS) \
	-no-undefined \
	-version-info $(LIBBLKMAKER_SO_VERSION)

libblkmaker_includedir = $(includedir)/libblkmaker-$(LIBBLKMAKER_API_VERSION)
libblkmaker_include_HEADERS = \
	blkmaker.h \
	blktemplate.h

libblkmaker_jansson_@LIBBLKMAKER_API_VERSION@_la_SOURCES = blkmaker_jansson.c
libblkmaker_jansson_@LIBBLKMAKER_API_VERSION@_la_DEPENDENCIES = libblkmaker-$(LIBBLKMAKER_API_VERSION).la
libblkmaker_jansson_@LIBBLKMAKER_API_VERSION@_la_CFLAGS = $(JANSSON_CFLAGS)
libblkmaker_jansson_@LIBBLKMAKER_API_VERSION@_la_LDFLAGS = \
	-L.libs \
	-lblkmaker-$(LIBBLKMAKER_API_VERSION) \
	$(JANSSON_LIBS) \
	-no-undefined \
	-version-info $(LIBBLKMAKER_SO_VERSION)

libblkmaker_jansson_includedir = $(includedir)/libblkmaker-$(LIBBLKMAKER_API_VERSION)
libblkmaker_jansson_include_HEADERS = \
	blkmaker_jansson.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = \
	libblkmaker_jansson-$(LIBBLKMAKER_API_VERSION).pc

dist_noinst_SCRIPTS = autogen.sh test.sh
dist_noinst_DATA = \
	AUTHORS COPYING README \
	example.c \
	testinput.c
	
if HAVE_LIBGCRYPT
check_PROGRAMS = test
test_SOURCES = test.c
test_CFLAGS = $(libbase58_CFLAGS) $(JANSSON_CFLAGS) $(LIBGCRYPT_CFLAGS)
test_LDADD = $(libbase58_LIBS) libblkmaker-@LIBBLKMAKER_API_VERSION@.la libblkmaker_jansson-@LIBBLKMAKER_API_VERSION@.la $(JANSSON_LIBS) $(LIBGCRYPT_LIBS)
TESTS = test.sh

EXTRA_PROGRAMS = example
example_SOURCES = example.c
example_CFLAGS = $(libbase58_CFLAGS) $(JANSSON_CFLAGS) $(LIBGCRYPT_CFLAGS)
example_LDADD = $(libbase58_LIBS) libblkmaker-@LIBBLKMAKER_API_VERSION@.la libblkmaker_jansson-@LIBBLKMAKER_API_VERSION@.la $(JANSSON_LIBS) $(LIBGCRYPT_LIBS)
else
example:
	@echo "libgcrypt is required to build the example, but was not found"
.PHONY: example
endif
