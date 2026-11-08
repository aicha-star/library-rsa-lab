CC      = gcc
CFLAGS  = -Wall -Wextra -Wno-unused-variable
LDFLAGS = -lcrypto

all: bn_sample rsa_lab

bn_sample: bn_sample.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

rsa_lab: rsa_lab.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

.PHONY: all clean

clean:
	rm -f bn_sample rsa_lab
