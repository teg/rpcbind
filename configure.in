AC_INIT(rpcbind, 0.2.0)
 
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/rpcbind.c])
AC_PREFIX_DEFAULT(/usr)
AC_PROG_CC

AC_ARG_ENABLE([libwrap],
  AS_HELP_STRING([--enable-libwrap], [Enables host name checking through tcpd @<:@default=no@:>@]))
AM_CONDITIONAL(LIBWRAP, test x$enable_libwrap = xyes)

AC_ARG_ENABLE([debug],
  AS_HELP_STRING([--enable-debug], [Turns on rpcbind debugging @<:@default=no@:>@]))
AM_CONDITIONAL(DEBUG, test x$enable_debug = xyes)

AC_ARG_ENABLE([warmstarts],
  AS_HELP_STRING([--enable-warmstarts], [Enables Warm Starts @<:@default=no@:>@]))
AM_CONDITIONAL(WARMSTART, test x$enable_warmstarts = xyes)

AC_ARG_WITH([statedir],
  AS_HELP_STRING([--with-statedir=ARG], [use ARG as state dir @<:@default=/tmp@:>@])
  ,, [with_statedir=/tmp])
AC_SUBST([statedir], [$with_statedir])

AC_ARG_WITH([rpcuser],
  AS_HELP_STRING([--with-rpcuser=ARG], [use ARG for RPC @<:@default=root@:>@]),
  ,, [with_rpcuser=root])
AC_SUBST([rpcuser], [$with_rpcuser])
 
PKG_CHECK_MODULES([TIRPC], [libtirpc])

AS_IF([test x$enable_libwrap = xyes], [
	AC_CHECK_LIB([wrap], [hosts_access], ,
		AC_MSG_ERROR([libwrap support requested but unable to find libwrap]))
])

AC_SEARCH_LIBS([pthread_create], [pthread])

AC_OUTPUT([Makefile])
