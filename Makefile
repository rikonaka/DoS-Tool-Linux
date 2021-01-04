.SUFFIXES:.c .o

CC   = gcc
SRCS = src/main.c \
	src/utils/logger.c \
	src/utils/tools.c \
	src/utils/usage.c \
	src/utils/version.c \
	src/dos/syn_flood.c \
	src/dos/udp_flood.c \
	src/dos/ack_reflect.c \
	src/dos/dns_reflect.c \

TEST_SRCS = src/test.c \
	src/utils/logger.c \
	src/utils/tools.c \
	src/utils/usage.c \
	src/utils/version.c \
	src/dos/syn_flood.c \
	src/dos/udp_flood.c \
	src/dos/ack_reflect.c \
	src/dos/dns_reflect.c \

OBJS = $(SRCS:.c=.o)
TEST_OBJS= $(TEST_SRCS:.c=.o)
EXEC = dos_tool_linux
TEST_EXEC = test_dos_tool_linux

all: $(EXEC) $(TEST_EXEC)

$(EXEC): $(OBJS)
	$(CC) -o $(EXEC) $(OBJS) -g -Wall -lpthread -lcrypto -lssl -lsodium
	@echo "Compiled finish."

$(TEST_EXEC): $(TEST_OBJS)
	$(CC) -o $(TEST_EXEC) $(TEST_OBJS) -g -Wall -lpthread -lcrypto -lssl -lsodium
	@echo "Compiled test file finish."

.c.o:
	$(CC) -o $@ -c $< -g -Wall -lpthread -lcrypto -lss -lsodium

clean: 
	rm -f $(OBJS)
	rm -f $(EXEC)
	rm -f $(TEST_EXEC)
	@echo "Clean up finish."