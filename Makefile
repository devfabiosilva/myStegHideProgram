
# Dec 25 2018
CC=gcc
#COMPAT_WITH_ARM= -malign-double
STRIP=strip
LIBOPENSSL= -lssl -lcrypto
FILENAME=fstg
FPATH=/usr/bin/

main:main.c
	$(CC) -o $(FILENAME) $@.c $(LIBOPENSSL)
	$(STRIP) $(FILENAME)

install:
	cp -v $(FILENAME) $(FPATH)
	chmod 755 $(FPATH)$(FILENAME)

unistall:
	rm -vi $(FPATH)$(FILENAME)

debug:
	$(CC) -D DEBUG -o $(FILENAME) main.c $(LIBOPENSSL)
	$(STRIP) $(FILENAME)

.PHONY: clean
clean:
	rm -v $(FILENAME)

