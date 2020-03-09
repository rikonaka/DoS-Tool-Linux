.SUFFIXES:.c .o

CC   = gcc
SRCS = src/main.c\
	src/utils/log.c\
	src/utils/base64.c\
	src/utils/https.c\
	src/utils/str.c\
	src/utils/version.c\
	src/utils/input.c\
	src/utils/usage.c\
	src/utils/others.c\
	src/guess.c\
	src/syn_flood_dos.c\
	src/udp_flood_dos.c\
	src/ack_reflect_dos.c\
	src/dns_reflect_dos.c\
	src/router/feixun.c\
	src/router/tplink.c

OBJS = $(SRCS:.c=.o)
EXEC = dos-tool-linux
INSTALLDIR = /usr/local/bin

start: $(OBJS)
	$(CC) -o $(EXEC) $(OBJS) -g -Wall -lpthread -lcrypto -lssl
	@echo "\033[0;32mCompiled finish\033[0m"

.c.o:
	$(CC) -o $@ -c $< -g -Wall -lpthread -lcrypto -lss

clean: 
	rm -f $(OBJS)
	rm -f $(EXEC)
	@echo "\033[0;32mClean up finish\033[0m"

install:$(EXEC)
    @if [-d $(INSTALLDIR)]; \
        then \
        cp ./src/$(EXEC) $(INSTALLDIR) &&\
        chmod a+x $(INSTALLDIR)/&& \
        chmod og-w $(INSTALLDIR)/$(EXEC);\
    else \
        echo "Sorry, $(INSTDIR) does not exist";\
    fi
