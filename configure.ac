#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([sed-tools], [3])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([subdir-objects])

# Checks for programs.
LT_INIT
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AM_PROG_CC_C_O

# Checks for libraries.
AC_CHECK_LIB([ssl], [EVP_sha1])
PKG_CHECK_MODULES([OPENSSL], [openssl], [], [AC_MSG_ERROR([Missing openssl module!])])

AC_CHECK_LIB([p11], [PKCS11_CTX_new])
PKG_CHECK_MODULES([LIBP11], [libp11], [], [AC_MSG_ERROR([Missing libp11 module!])])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h inttypes.h stdint.h stdlib.h string.h sys/ioctl.h termios.h unistd.h], [], [AC_MSG_ERROR([Missing required header!])])
AC_CHECK_HEADER([libp11.h], [], [AC_MSG_ERROR([Missing libp11-dev!])])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_UID_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([getpass memset strerror])

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
