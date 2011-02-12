
INCLUDES	= $(PTHREAD_FLAGS) -fno-strict-aliasing

bin_PROGRAMS	= pushpoold

pushpoold_SOURCES = elist.h server.h ubbp.h		\
		    config.c server.c util.c
pushpoold_LDFLAGS = $(PTHREAD_FLAGS)
pushpoold_LDADD	= @EVENT_LIBS@ @PTHREAD_LIBS@ @JANSSON_LIBS@ @Z_LIBS@

