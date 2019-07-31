# Makefile for INSPECTORLOG
#/********************************************************/
#/* (c) - JEDV			                             */
#/********************************************************/
#/* Makefile                                             */
#/*                                                      */
#/********************************************************/

.KEEP_STATE:

DESTDIR = /home/jedv/work/siva/bin

ICES = inspector.h
PROGS = inspectorlog

OBJS = logs.o rules.o bd.o arguments.o engine.o 
CES = $(OBJS:%.o=%.c)

#CFLAGS  =  -ggdb -I/usr/include -I/usr/local/include -I. -W -Wreturn-type -Wformat -Wchar-subscripts -Wuninitialized -Wshadow -Wpointer-arith 
CFLAGS  =  -std=c99 -ggdb -I. -w -O3 -W -Wreturn-type -Wformat -Wchar-subscripts -Wuninitialized -Wshadow -Wpointer-arith

CC      = gcc

# Opciones de compilacion

LDFLAGS =  -ldl -lpcre -lpthread -lmysqlclient
LD_RUN_PATH = /usr/local/lib

all:  $(PROGS)


#$(PROGS) : ${CES} ${OBJS} ${PROGS}.c
$(PROGS) :  ${CES} ${ICES} ${PROGS}.c
	$(CC) ${CFLAGS}  ${CES} -o $@ $@.c  ${LDFLAGS}


clean:
	rm -f core *% *.o  $(PROGS) $(PROGS:%=%.exe) ${OBJS}


install:
	cp $(PROGS) $(DESTDIR)

