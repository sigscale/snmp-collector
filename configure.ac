## configure.ac
## vim: ts=3
##
## Process this file with autoconf to produce a configure script.
##
## Boilerplate:  standard boilerplate code
##
AC_INIT([snmp_collector], [1.0.0], [issues@sigscale.org])
AC_COPYRIGHT([Copyright (c) 2018 SigScale Global Inc.])
AC_PREREQ(2.63)
AC_CONFIG_SRCDIR([src/snmp_collector_app.erl])
AC_CONFIG_HEADERS([config.h])
LT_INIT([disable-static dlopen])
AM_INIT_AUTOMAKE([-Wno-portability])

##
## Options:  control options to configure, support code for the options
##
AC_ARG_ENABLE([debug],
		[AS_HELP_STRING([--enable-debug], [enable debugging (default is no)])])
AC_ARG_WITH([ssl],
		[AS_HELP_STRING([--with-ssl=PATH], [specify location of OpenSSL include and lib])])
CFLAGS="${CFLAGS} -Wall"


##
## Programs:  check for programs needed by the configure process,
##            the build process, or by one of the programs being built
##
AC_LANG_PUSH([Erlang])
AC_ERLANG_NEED_ERL
AC_ERLANG_NEED_ERLC
if test -z "${ERLCFLAGS}" ; then
	ERLCFLAGS="-W -v"
fi
if test "x$enable_debug" == xyes ; then
	ERLCFLAGS="$ERLCFLAGS +debug_info"
fi
if test "x$with_ssl" != xyes ; then
   CPPFLAGS="${CPPFLAGS} -I$with_ssl/include"
   LDFLAGS="${LDFLAGS} -L$with_ssl/lib"
fi
AC_ERLANG_SUBST_LIB_DIR
if test -z "${ERLANG_INSTALL_LIB_DIR}" ; then
	ERLANG_INSTALL_LIB_DIR=$ERLANG_LIB_DIR
fi
AC_ERLANG_SUBST_ROOT_DIR
CPPFLAGS="${CPPFLAGS} -I ${ERLANG_ROOT_DIR}/erts-${ERLANG_ERTS_VER}/include",
AC_PROG_MKDIR_P
AC_PROG_INSTALL
AC_PROG_LN_S
AC_ERLANG_SUBST_INSTALL_LIB_DIR
appdir=$ERLANG_INSTALL_LIB_DIR/$PACKAGE_NAME-$PACKAGE_VERSION
erldir=$ERLANG_INSTALL_LIB_DIR/$PACKAGE_NAME-$PACKAGE_VERSION/src
beamdir=$ERLANG_INSTALL_LIB_DIR/$PACKAGE_NAME-$PACKAGE_VERSION/ebin
eincludedir=$ERLANG_INSTALL_LIB_DIR/$PACKAGE_NAME-$PACKAGE_VERSION/include
docdir=$ERLANG_INSTALL_LIB_DIR/$PACKAGE_NAME-$PACKAGE_VERSION/doc
wwwdir=$ERLANG_INSTALL_LIB_DIR/$PACKAGE_NAME-$PACKAGE_VERSION/priv/www
libdir=$ERLANG_INSTALL_LIB_DIR/$PACKAGE_NAME-$PACKAGE_VERSION/priv/lib
reldir=$ERLANG_INSTALL_LIB_DIR/../releases
AC_SUBST(appdir)
AC_SUBST(erldir)
AC_SUBST(beamdir)
AC_SUBST(eincludedir)
AC_SUBST(privdir)
AC_SUBST(wwwdir)
AC_SUBST(reldir)
AC_LANG_POP([Erlang])


##
## Libraries:  check for libraries
##
AC_ERLANG_SUBST_ERTS_VER
AC_CHECK_LIB([crypto], [EVP_DigestInit], [],
      [AC_MSG_ERROR([openssl crypto was not found!])])
AC_LANG_PUSH([Erlang])
AC_ERLANG_CHECK_LIB([kernel], [], [AC_MSG_ERROR([kernel was not found!])])
AC_ERLANG_CHECK_LIB([stdlib], [], [AC_MSG_ERROR([stdlib was not found!])])
AC_ERLANG_CHECK_LIB([sasl], [], [AC_MSG_ERROR([sasl was not found!])])
AC_ERLANG_CHECK_LIB([mnesia], [], [AC_MSG_ERROR([mnesia was not found!])])
AC_ERLANG_CHECK_LIB([crypto], [], [AC_MSG_ERROR([crypto was not found!])])
AC_ERLANG_CHECK_LIB([asn1], [], [AC_MSG_ERROR([asn1 was not found!])])
AC_ERLANG_CHECK_LIB([compiler], [], [AC_MSG_ERROR([compiler was not found!])])
AC_ERLANG_CHECK_LIB([snmp], [], [AC_MSG_ERROR([snmp was not found!])])
AC_ERLANG_CHECK_LIB([runtime_tools], [], [AC_MSG_ERROR([runtime_tools was not found!])])
AC_ERLANG_CHECK_LIB([inets], [], [AC_MSG_ERROR([inets was not found!])])
AC_ERLANG_CHECK_LIB([public_key], [], [AC_MSG_ERROR([public_key was not found!])])
AC_ERLANG_CHECK_LIB([ssl], [], [AC_MSG_ERROR([ssl was not found!])])
AC_LANG_POP([Erlang])


##
## Headers:  check for header files
##
AC_CHECK_HEADERS([erl_nif.h], [], [AC_MSG_ERROR([Erlang NIFs not found!])])
AC_CHECK_HEADERS([openssl/evp.h], [], [AC_MSG_ERROR([openssl/evp.h not found!])])

##
## Typedefs & Structures:  check for typedefs, structures,
##                         and compiler characteristics.
##


##
## Functions:  check for library functions
##
AC_CHECK_FUNC([EVP_DigestInit], [], [AC_MSG_ERROR([EVP_Digest function not found!])])


##
## Output:  create output files
##

AC_OUTPUT([Makefile include/Makefile src/Makefile ebin/Makefile
		doc/Makefile c_src/Makefile priv/lib/Makefile priv/Makefile
		priv/www/Makefile priv/www/package.json test/Makefile
		$PACKAGE_NAME.rel sys.config])

