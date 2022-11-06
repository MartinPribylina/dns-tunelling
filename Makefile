CC=gcc
CFLAGS= -std=gnu99 -pedantic -Wall -Wextra
LFLAGS = $(CFLAGS) -L/usr/lib/

all: receiver sender

sender: sender.o dns.o base32.o sender/dns_sender.o
	$(CC) $(LFLAGS) sender/dns_sender.o dns.o base32.o -o dns_sender -luuid 

sender.o: sender/dns_sender_events.c
	$(CC) $(CFLAGS) -c sender/dns_sender_events.c -o sender/dns_sender.o

receiver: receiver.o dns.o base32.o receiver/dns_receiver.o
	$(CC) $(LFLAGS) receiver/dns_receiver.o dns.o base32.o -o dns_receiver -luuid 

receiver.o: receiver/dns_receiver_events.c
	$(CC) $(CFLAGS) -c receiver/dns_receiver_events.c -o receiver/dns_receiver.o

dns.o: dns.c
	$(CC) $(CFLAGS) -c dns.c -o dns.o

base32.o: base32.c
	$(CC) $(CFLAGS) -c base32.c -o base32.o

zip:
	zip xpriby19 dns.c dns.h sender/dns_sender_events.c sender/dns_sender_events.h receiver/dns_receiver_events.c receiver/dns_receiver_events.h base32.h base32.c Makefile

clean:
	rm -rf dns_receiver dns_sender sender/dns_sender.o receiver/dns_receiver.o base32.o dns.o