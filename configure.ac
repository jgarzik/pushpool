
AC_INIT([pushpool], [0.1.1])

AC_PREREQ(2.52)
AC_CONFIG_SRCDIR([server.c])
AM_INIT_AUTOMAKE([gnu])
AC_CONFIG_HEADERS([autotools-config.h])

dnl Make sure anyone changing configure.ac/Makefile.am has a clue
AM_MAINTAINER_MODE

dnl Checks for programs
AC_PROG_CC
AC_PROG_GCC_TRADITIONAL
AM_PROG_CC_C_O
AC_PROG_RANLIB

dnl Checks for header files.
AC_HEADER_STDC

case $host in
  *-*-mingw*)
    have_win32=true
    PTHREAD_FLAGS=""
    ;;
  *)
    have_win32=false
    PTHREAD_FLAGS="-pthread"
    ;;
esac

AC_CHECK_LIB(event, event_base_new, EVENT_LIBS=-levent,
  [AC_MSG_ERROR([Missing required libevent])])
AC_CHECK_LIB(pthread, pthread_create, PTHREAD_LIBS=-lpthread)
AC_CHECK_LIB(z, uncompress, Z_LIBS=-lz,
  [AC_MSG_ERROR([Missing required zlib])])
AC_CHECK_LIB(jansson, json_loads, JANSSON_LIBS=-ljansson,
  [AC_MSG_ERROR([Missing required jansson library])])
AC_CHECK_LIB(crypto, MD5_Init, CRYPTO_LIBS=-lcrypto,
  [AC_MSG_ERROR([Missing required OpenSSL library])])

PKG_PROG_PKG_CONFIG()

LIBCURL_CHECK_CONFIG(, 7.10.1, ,
  [AC_MSG_ERROR([Missing required libcurl >= 7.10.1])])

AC_SUBST(JANSSON_LIBS)
AC_SUBST(EVENT_LIBS)
AC_SUBST(PTHREAD_FLAGS)
AC_SUBST(PTHREAD_LIBS)
AC_SUBST(CRYPTO_LIBS)
AC_SUBST(Z_LIBS)

AC_CONFIG_FILES([
	Makefile
	])
AC_OUTPUT

