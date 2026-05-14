CC      = gcc
CFLAGS  = -Wall -O2
LDFLAGS = -L/usr/local/lib -lssl -lcrypto -lz
LDLIBS += -lpthread -lm

PKG_LIBS = $(shell pkg-config --libs openssl libpng16)

all: myapp

myapp: main.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)
