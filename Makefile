CC = gcc
CFLAGS = -g -O2 -O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -fstack-protector-strong
LIBS = -lm -lUseful-5 
INSTALL=/usr/bin/install -c
prefix=/usr/local
exec_prefix=${prefix}
bindir=${exec_prefix}/bin
mandir=${prefix}/share/man
DESTDIR=
LIBUSEFUL_BUNDLED=
FLAGS=$(CFLAGS) -DPACKAGE_NAME=\"\" -DPACKAGE_TARNAME=\"\" -DPACKAGE_VERSION=\"\" -DPACKAGE_STRING=\"\" -DPACKAGE_BUGREPORT=\"\" -DPACKAGE_URL=\"\" -DHAVE_STDIO_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_STRINGS_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_UNISTD_H=1 -DSTDC_HEADERS=1 -DHAVE_LIBUSEFUL_5_LIBUSEFUL_H=1 -DHAVE_LIBUSEFUL5=1 -DHAVE_LIBUSEFUL_5=1

OBJ=common.o net.o proc.o proc_list.o

all: main.c $(OBJ) $(LIBUSEFUL_BUNDLED)
	gcc $(FLAGS) -opssec $(OBJ) main.c $(LIBS) $(LIBUSEFUL_BUNDLED)


common.o: common.h common.c
	gcc $(FLAGS) -c common.c

net.o: net.h net.c common.h
	gcc $(FLAGS) -c net.c

proc.o: proc.h proc.c common.h
	gcc $(FLAGS) -c proc.c

proc_list.o: proc_list.h proc_list.c common.h
	gcc $(FLAGS) -c proc_list.c


$(LIBUSEFUL_BUNDLED):
	make -C libUseful-bundled



clean:
	rm *.o *.orig pssec */*.o */*.a */*.so

install:
	mkdir -p $(DESTDIR)/$(bindir)
	cp pssec -p $(DESTDIR)/$(bindir)
	mkdir -p $(DESTDIR)/$(mandir)
	cp pssec.1 -p $(DESTDIR)/$(mandir)
