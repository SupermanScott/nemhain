bin_PROGRAMS = main
main_SOURCES = main.c parser.rl dbg.c bstr/bsafe.c bstr/bstraux.c bstr/bstrlib.c server.c

LDADD = $(DEPS_LIBS)

SUFFIXES = .rl
RAGEL = ragel
RAGEL_CFLAGS = -G2

test: check

.rl.c:
	$(RAGEL) $(RAGEL_CFLAGS) $<
