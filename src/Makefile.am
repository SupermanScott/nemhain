bin_PROGRAMS = main send_msg
main_SOURCES = main.c parser.rl dbg.c bstr/bsafe.c bstr/bstraux.c bstr/bstrlib.c server.c adt/hash.c cJSON/cJSON.c

send_msg_SOURCES = send_msg.c

LDADD = $(DEPS_LIBS)

SUFFIXES = .rl
RAGEL = ragel
RAGEL_CFLAGS = -G2

test: check

.rl.c:
	$(RAGEL) $(RAGEL_CFLAGS) $<
