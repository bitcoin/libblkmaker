AC_INIT(
	[libblkmaker],
	[0.1],
	[luke_libblkmaker@dashjr.org],
	[libblkmaker],
	[http://gitorious.org/bitcoin/libblkmaker])
AC_CONFIG_AUX_DIR([.])
AC_PREREQ([2.59])
AM_INIT_AUTOMAKE([1.10 -Wall dist-bzip2])

AC_PROG_CC_C99
AM_PROG_AR
LT_INIT([disable-static])

# http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
AC_SUBST([LIBBLKMAKER_SO_VERSION], [1:0:1])
AC_SUBST([LIBBLKMAKER_API_VERSION], [0.1])

AC_CONFIG_FILES([Makefile
	libblkmaker_jansson-${LIBBLKMAKER_API_VERSION}.pc:libblkmaker_jansson.pc.in
])

AC_CHECK_LIB([ws2_32], [strchr])

AC_OUTPUT
