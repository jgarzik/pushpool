
EXTRA_DIST	= example-cfg.json example-blkmon.cfg blkmond

INCLUDES	= -fno-strict-aliasing $(PTHREAD_FLAGS) @SQLITE3_CFLAGS@ \
		@MYSQL_CFLAGS@ @POSTGRESQL_CFLAGS@

sbin_SCRIPTS	= blkmond
sbin_PROGRAMS	= pushpoold

pushpoold_SOURCES = anet.h elist.h htab.h protocol.h scrypt.h server.h ubbp.h	\
		    hist.c htab.c anet.c config.c msg.c scrypt.c server.c util.c \
		    db-sqlite.c db-mysql.c db-postgresql.c
pushpoold_LDFLAGS = $(PTHREAD_FLAGS)
pushpoold_LDADD	= @LIBCURL@ @EVENT_LIBS@ @PTHREAD_LIBS@ @JANSSON_LIBS@ \
		  @CRYPTO_LIBS@ @Z_LIBS@ @LIBMEMCACHED_LIBS@ @ARGP_LIBS@ \
		  @SQLITE3_LDFLAGS@ @MYSQL_LDFLAGS@ @POSTGRESQL_LDFLAGS@
