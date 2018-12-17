
CC = gcc -std=gnu99 -pthread
LIBS = -lyaml -lsqlite3
ifdef DEBUG
CFLAGS = -Wall -D_GNU_SOURCE -ggdb -pg
LDFLAGS = -ggdb -pg
else
CFLAGS = -Wall -D_GNU_SOURCE -O3 -finline
LDFLAGS = -s -O3 -finline
endif


all: ecoll
	@if [ -s ./TODO ]; then echo "====== TODO ======="; cat ./TODO; fi

ecoll.o: ecoll.c ecoll.h
	$(CC) $(CFLAGS) -c $<

ecoll: ecoll.o
	$(CC) $(LDFLAGS) $< -o ecoll $(LIBS)

clean: test-clean
	@rm -f ecoll.o ecoll gmon.out core.* vcore.*

dist:
	@tar -zcf ecoll-$(shell date +'%s').tgz \
                  ecoll.c \
                  ecoll.h \
                  ecoll.yml \
                  Makefile \
                  TODO \
                  README \
                  COPYING
