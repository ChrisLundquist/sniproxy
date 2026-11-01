#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.71])
AC_INIT([sniproxy],[0.7.0])
AM_INIT_AUTOMAKE([subdir-objects])
AM_SILENT_RULES([yes])
AC_USE_SYSTEM_EXTENSIONS

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O


# Checks for libraries.
AC_CHECK_LIB([ev], [ev_run], [],
	     [AC_MSG_ERROR([libev is required])])
AC_CHECK_LIB([pcre2-8], [pcre2_compile_8], [],
	     [AC_CHECK_LIB([pcre], [pcre_exec], [],
			   [AC_MSG_ERROR([libpcre is required])])])

AC_ARG_ENABLE([dns],
	      [AS_HELP_STRING([--enable-dns], [Enable DNS resolution (requires libudns)])])

AS_IF([test "x$enable_dns" = "xyes"],
      [AC_CHECK_LIB([udns], [dns_init], [],
                    [AC_MSG_ERROR([--enable-dns requires libudns, please install the libudns development headers])])])

AM_CONDITIONAL([DNS_ENABLED], [test "x$enable_dns" = "xyes"])

AC_ARG_ENABLE([rfc3339-timestamps],
  [AS_HELP_STRING([--enable-rfc3339-timestamps], [Enable RFC3339 timestamps])],
  [AC_DEFINE([RFC3339_TIMESTAMP], 1, [RFC3339 timestamps enabled])])

AC_CHECK_FUNCS([accept4])

# Timeouts are measured with clock_gettime(CLOCK_MONOTONIC), which older
# C libraries provide in librt
AC_SEARCH_LIBS([clock_gettime], [rt], [],
               [AC_MSG_ERROR([clock_gettime() is required])])

# Enable large file support (so we can log more than 2GB)
AC_SYS_LARGEFILE

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 man/Makefile
                 tests/Makefile])

AC_OUTPUT
