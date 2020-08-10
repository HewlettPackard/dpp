#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([Device Provisioning Protocol], [1.0.0], [dpp-bugs@lounge.org])
AC_CONFIG_SRCDIR([utils.h])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC

AM_PROG_CC_C_O

# Checks for libraries.

AC_ARG_WITH(ssl,
	AS_HELP_STRING([--with-ssl=PATH], [location of OpenSSL]),
	[ssldir="$withval" custom_ssl="yes"],
	[ssldir="/usr/local/ssl" custom_ssl="no"]
)

CFLAGS="$CFLAGS -Wall -I$ssldir/include"
LDFLAGS="$LDFLAGS -L$ssldir/lib -L$ssldir"

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netinet/in.h stddef.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([bzero gethostname gettimeofday memset select socket strstr strtol])

AC_MSG_CHECKING([enable-brainpool])
AC_ARG_ENABLE(brainpool,
	AC_HELP_STRING([--enable-brainpool],[Has Brainpool support]) [],
[ case "enableval" in
  yes)
	AC_MSG_RESULT(yes)
	CFLAGS="$CFLAGS -DHAS_BRAINPOOL"
	;;
  *)	AC_MSG_RESULT(no)
  	;;
  esac ],
       AC_MSG_RESULT(no)
)

# OS specific stuff
AC_CANONICAL_HOST
case $host in
*-linux*)
	AC_CHECK_LIB([dl], [dlopen], [],
        	   [AC_MSG_FAILURE([can't find libdl])],
		   [])
	AC_CHECK_LIB([pthread], pthread_create, [],
		   [AC_MSG_FAILURE([can't find pthread])],
		   [])
	AC_CHECK_LIB([nl-3], nl_recvmsgs, [],
		   [AC_MSG_FAILURE([can't find nl-3])],
		   [])
	AC_CHECK_LIB([nl-genl-3], genlmsg_put, [],
		   [AC_MSG_FAILURE([can't find nl-genl-3])],
		   [])
	AC_CHECK_LIB([dl], dlopen, [],
		   [AC_MSG_FAILURE([can't find dl])],
		   [])
	AC_ARG_ENABLE(static,
		AS_HELP_STRING([--enable-static], [build static]),
		LDFLAGS="$LDFLAGS -static",
		[givemsg="yes" ld_msg="LD_LIBRARY_PATH"]
	)
	CFLAGS="$CFLAGS -I/usr/include/libnl3"
	AC_CONFIG_FILES([linux/Makefile 
	])
	;;
*-darwin*)
	dnl static building is not supported on OSX
	givemsg="yes"
	ld_msg="DYLD_LIBRARY_PATH"
	AC_CONFIG_FILES([macos/Makefile 
	])
	;;
*-freebsd*)
	AC_ARG_ENABLE(static,
		AS_HELP_STRING([--enable-static], [build static]),
		LDFLAGS="$LDFLAGS -static",
		[givemsg="yes" ld_msg="LD_LIBRARY_PATH"]
	)
	AC_CONFIG_FILES([freebsd/Makefile 
	])
	;;
*)
	AC_MSG_ERROR([DPP has not been ported to your OS yet])

esac

AC_CONFIG_FILES([ecca/Makefile])

AC_CHECK_LIB([crypto], [EC_GROUP_get_order], [],
	[AC_MSG_FAILURE([can't find libcrypto])],
	[])

AC_OUTPUT

if test "x$givemsg" = 'xyes'; then
  AC_MSG_NOTICE([Be sure to set $ld_msg appropriately])
fi
