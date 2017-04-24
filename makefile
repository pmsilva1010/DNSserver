FLAGS  = -D_REENTRANT -Wall -g
CC     = gcc
PROG   = dnsserver
OBJS   = dnsserver.o

all:	${PROG}

clean:
	rm ${OBJS} ${PROG}
  
${PROG}:	${OBJS}
	${CC} ${FLAGS} ${OBJS} -lpthread -o $@

.c.o:
	${CC} ${FLAGS} $< -c

##########################

dnsserver.o: dnsserver.h dnsserver.c

dnsserver: dnsserver.o