
EXTRA_DIST	= example-cfg.json

INCLUDES	= $(PTHREAD_FLAGS) -fno-strict-aliasing

bin_PROGRAMS	= pushpoold

pushpoold_SOURCES = anet.h elist.h protocol.h server.h ubbp.h		\
		    hist.c htab.c anet.c config.c msg.c server.c util.c
pushpoold_LDFLAGS = $(PTHREAD_FLAGS)
pushpoold_LDADD	= @LIBCURL@ @EVENT_LIBS@ @PTHREAD_LIBS@ @JANSSON_LIBS@ \
		  @CRYPTO_LIBS@ @Z_LIBS@

