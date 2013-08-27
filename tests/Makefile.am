TESTS = check_parser
check_PROGRAMS = check_parser
check_parser_SOURCES = check_parser.c $(top_builddir)/src/parser.h
check_parser_CFLAGS = @CHECK_CFLAGS@
check_parser_LDADD = $(top_builddir)/src/libsyslogparser.la @CHECK_LIBS@

AM_CFLAGS = -std=c1x
