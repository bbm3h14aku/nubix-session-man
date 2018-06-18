CC = gcc
LD = gcc

GTK_VERSION = 3.0
INCS = $(shell pkg-config --cflags gtk+-$(GTK_VERSION)) -I$(PWD)/../libnubix
LIBS = $(shell pkg-config --libs gtk+-$(GTK_VERSION)) -lpam -pthread -L/usr/X11R6/lib -lX11 -lgthread-2.0

LDFLAGS = $(LIBS) -lpam
CFLAGS = $(INCS) -std=gnu11 -c

TARGET = nubix-sman
SERVICE_FILE = nubix-dman.service
BINDIR = /usr/bin/nubix/$(TARGET)

OBJ = display-manager.o pam.o

all: $(OBJ)
	$(LD) $^ $(PWD)/../libnubix/libnubix.a  -o $(TARGET) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) $< -o $@

.PHONY: clean all

clean:
	rm -f $(OBJ)
clean-all:
	rm -f $(TARGET)

install:
	sed 's/BINPATH/$(BINDIR)' $(SERVICE_FILE)

debug:
	screen -d -m Xephyr -ac -br -noreset -screen 800x600 :1
	./$(TARGET)
