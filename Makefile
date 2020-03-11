.SUFFIXES:.c .o

CC   = gcc
SRCS = src/main.c \
	src/utils/debug.c \
	src/utils/base64.c \
	src/utils/https.c \
	src/utils/str.c \
	src/utils/version.c \
	src/utils/input.c \
	src/utils/usage.c \
	src/utils/others.c \
	src/utils/router/feixun.c \
	src/utils/router/tplink.c \
	src/guess.c \
	src/syn_flood_dos.c \
	src/udp_flood_dos.c \
	src/ack_reflect_dos.c \
	src/dns_reflect_dos.c \

SRCSTEST = src/test.c \
	src/utils/debug.c \
	src/utils/base64.c \
	src/utils/https.c \
	src/utils/str.c \
	src/utils/version.c \
	src/utils/input.c \
	src/utils/usage.c \
	src/utils/others.c \
	src/utils/router/feixun.c \
	src/utils/router/tplink.c \
	src/guess.c \
	src/syn_flood_dos.c \
	src/udp_flood_dos.c \
	src/ack_reflect_dos.c \
	src/dns_reflect_dos.c \

OBJS = $(SRCS:.c=.o)
OBJSTEST = $(SRCSTEST:.c=.o)
EXEC = dos-tool-linux
EXECTEST = dos-tool-linux-test
INSTALLDIR = /usr/local/bin

all: $(EXEC) $(TEST)

$(EXEC): $(OBJS)
	$(CC) -o $(EXEC) $(OBJS) -g -Wall -lpthread -lcrypto -lssl
	@echo "\033[0;32mCompiled finish.\033[0m"

$(EXECTEST): $(OBJS)
	$(CC) -o $(EXECTEST) $(OBJSTEST) -g -Wall -lpthread -lcrypto -lssl
	@echo "\033[0;32mCompiled test file finish.\033[0m"

.c.o:
	$(CC) -o $@ -c $< -g -Wall -lpthread -lcrypto -lss

clean: 
	rm -f $(OBJS)
	rm -f ./src/$(EXEC)
	@echo "\033[0;32mClean up finish.\033[0m"

install:$(EXEC)
	@if [-d $(INSTALLDIR)]; then \
		cp ./src/$(EXEC) $(INSTALLDIR)
		chmod a+x $(INSTALLDIR)/$(EXEC)
		chmod og-w $(INSTALLDIR)/$(EXEC)
	else
		echo "\033[0;32mSorry, $(INSTDIR) does not exist.\033[0m"
	fi

uninstall:$(EXEC)
	@if [-d $(INSTALLDIR)]; then \
		rm -f $(INSTALLDIR)/$(EXEC)
		echo "\033[0;32mUninstall successful.\033[0m"
	fi
