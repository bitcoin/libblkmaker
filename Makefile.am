lib_LTLIBRARIES = \
	libblkmaker_jansson-@LIBBLKMAKER_API_VERSION@.la \
	libblkmaker-@LIBBLKMAKER_API_VERSION@.la


libblkmaker_@LIBBLKMAKER_API_VERSION@_la_SOURCES = \
	blkmaker.c \
	blktemplate.c

libblkmaker_@LIBBLKMAKER_API_VERSION@_la_LDFLAGS = -version-info $(LIBBLKMAKER_SO_VERSION) -no-undefined

libblkmaker_includedir = $(includedir)/libblkmaker-$(LIBBLKMAKER_API_VERSION)
libblkmaker_include_HEADERS = \
	blkmaker.h \
	blktemplate.h

libblkmaker_jansson_@LIBBLKMAKER_API_VERSION@_la_SOURCES = blkmaker_jansson.c
libblkmaker_jansson_@LIBBLKMAKER_API_VERSION@_la_DEPENDENCIES = libblkmaker-$(LIBBLKMAKER_API_VERSION).la
libblkmaker_jansson_@LIBBLKMAKER_API_VERSION@_la_CFLAGS = $(JANSSON_CFLAGS)
libblkmaker_jansson_@LIBBLKMAKER_API_VERSION@_la_LDFLAGS = \
	-lblkmaker-$(LIBBLKMAKER_API_VERSION) \
	$(JANSSON_LIBS) \
	-no-undefined \
	-version-info $(LIBBLKMAKER_SO_VERSION)


pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = \
	libblkmaker_jansson-$(LIBBLKMAKER_API_VERSION).pc

dist_noinst_SCRIPTS = autogen.sh
