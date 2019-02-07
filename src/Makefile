.PHONY: install

all: mod_sqliteblob

mod_sqliteblob:
	apxs -c mod_sqliteblob.c -lsqlite3

install:
	apxs -i -a -c mod_sqliteblob.c -lsqlite3