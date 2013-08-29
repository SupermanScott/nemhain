bin_PROGRAMS = main
main_SOURCES = main.c parser.rl dbg.c bstr/bsafe.c bstr/bstraux.c bstr/bstrlib.c

AM_CFLAGS = -std=c1x

SUFFIXES = .rl
RAGEL = ragel
RAGEL_CFLAGS = -G2

test: check

.rl.c:
	$(RAGEL) $(RAGEL_CFLAGS) $<
