.SUFFIXES:.c .o

CC   = gcc
SRCS = src/main.c \
	src/utils/logger.c \
	src/utils/crypto.c \
	src/utils/https.c \
	src/utils/tools.c \
	src/utils/parameter.c \
	src/utils/usage.c \
	src/dos/brute_force.c \
	src/dos/syn_flood.c \
	src/dos/udp_flood.c \
	src/dos/ack_reflect.c \
	src/dos/dns_reflect.c \

T_SRCS = src/debug.c \
	src/utils/logger.c \
	src/utils/crypto.c \
	src/utils/https.c \
	src/utils/tools.c \
	src/utils/parameter.c \
	src/utils/usage.c \

OBJS = $(SRCS:.c=.o)
T_OBJS= $(T_SRCS:.c=.o)
EXEC = dos-tool-linux
T_EXEC = debug-dos-tool-linux

all: $(EXEC) $(T_EXEC)

$(EXEC): $(OBJS)
	$(CC) -o $(EXEC) $(OBJS) -g -Wall -lpthread -lcrypto -lssl -lsodium
	@echo "\033[0;32mCompiled finish.\033[0m"

$(T_EXEC): $(T_OBJS)
	$(CC) -o $(T_EXEC) $(T_OBJS) -g -Wall -lpthread -lcrypto -lssl -lsodium
	@echo "\033[0;32mCompiled test file finish.\033[0m"

.c.o:
	$(CC) -o $@ -c $< -g -Wall -lpthread -lcrypto -lss -lsodium

clean: 
	rm -f $(OBJS)
	rm -f $(EXEC)
	rm -f $(T_EXEC)
	@echo "\033[0;32mClean up finish.\033[0m"