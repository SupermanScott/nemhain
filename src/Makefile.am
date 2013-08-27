lib_LTLIBRARIES = libsyslogparser.la
libsyslogparser_la_SOURCES = parser.rl dbg.c bstr/bsafe.c bstr/bstraux.c bstr/bstrlib.c

bin_PROGRAMS = main
main_SOURCES = main.c
main_LDADD = libsyslogparser.la

AM_CFLAGS = -std=c1x

SUFFIXES = .rl
RAGEL = ragel
RAGEL_CFLAGS = -G2

test: check

.rl.c:
	$(RAGEL) $(RAGEL_CFLAGS) $<
