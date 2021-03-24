#SUBDIRS=packet_tokenization invokers stdlib sed
bin_PROGRAMS = ${top_builddir}/bin/sed_tools

lib_LTLIBRARIES=libsed.la

libsed_la_SOURCES= \
    ata/ata.c \
	account/account.c \
	packet_tokenization/compacket.c \
	packet_tokenization/packet.c \
	packet_tokenization/packets.c \
	packet_tokenization/dataPayload.c \
	packet_tokenization/datasubpacket.c \
	invokers/ace.c \
	invokers/adminSP.c \
	invokers/cpin.c \
	invokers/datastore.c \
	invokers/lockingRange.c \
	invokers/lockingSP.c \
	invokers/mbr.c \
	invokers/mbrControl.c \
	invokers/sessionManager.c \
	invokers/thisSP.c \
	invokers/user.c \
	sed/sed.c \
	sed/error.c \
	crypto/crypto.c \
	password/password.c \
	password/sedAuth.c \
	menu/adminMenu.c

libsed_la_CFLAGS=-I${top_srcdir}/src/include -fPIC -Wall -Werror

__top_builddir__bin_sed_tools_SOURCES = sed_tools.c
__top_builddir__bin_sed_tools_LDADD = ${top_srcdir}/src/libsed.la
__top_builddir__bin_sed_tools_CFLAGS = -fPIC -Wall -Werror -I${top_srcdir}/src/include

#sedincludedir = $(includedir)

#sedinclude_HEADERS = \
#	sed/sed.h \
#	invokers/ace.h \
#	invokers/adminSP.h \
#	invokers/cpin.h \
#	invokers/datastore.h \
#	invokers/lockingRange.h \
#	invokers/lockingSP.h \
#	invokers/mbr.h \
#	invokers/mbrControl.h \
#	invokers/sessionManager.h \
#	invokers/thisSP.h \
#	invokers/user.h
#noinst_HEADERS = \
#	hdparm_sgio.h \
#	packet_tokenization/compacket.h \
#	packet_tokenization/packet.h \
#	packet_tokenization/packets.h \
#	packet_tokenization/datasubpacket.h \
#	packet_tokenization/dataPayload.h \
#	stdlib/stdlib.h \
#	sed/sed_columns.h \
#	sed/sed_errors.h \
#	sed/sed_uids.h \
#	sed/uids.h
