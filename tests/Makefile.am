TESTS = check_parser check_json
check_PROGRAMS = check_parser check_json
check_parser_SOURCES = check_parser.c $(top_builddir)/src/parser.c $(top_builddir)/src/dbg.c $(top_builddir)/src/bstr/bsafe.c $(top_builddir)/src/bstr/bstraux.c $(top_builddir)/src/bstr/bstrlib.c $(top_builddir)/src/cJSON/cJSON.c minunit/minunit.h
check_json_SOURCES = check_json.c $(top_builddir)/src/parser.c $(top_builddir)/src/dbg.c $(top_builddir)/src/bstr/bsafe.c $(top_builddir)/src/bstr/bstraux.c $(top_builddir)/src/bstr/bstrlib.c $(top_builddir)/src/cJSON/cJSON.c minunit/minunit.h
LDADD = $(DEPS_LIBS)
