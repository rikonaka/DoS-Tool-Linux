.SUFFIXES:.c .o
.SUFFIXES:.c .do

# CC   = clang
CC   = gcc
SRCS = src/main.c \
	src/utils/logger.c \
	src/utils/tools.c \
	src/utils/usage.c \
	src/utils/version.c \
	src/dos/syn_flood.c \
	src/dos/udp_flood.c \
	src/dos/ack_flood.c \
	src/dos/syn_ack_joint_flood.c \
	src/dos/http_flood.c \

# rm all log file from test
VALGRIND_TEST = valgrind-out-a*.txt

OBJS = $(SRCS:.c=.o)
DEBUG_OBJS = $(SRCS:.c=.do)
EXEC = dos-tool-linux
DEBUG_EXEC = debug-dos-tool-linux

all: $(EXEC)

debug: $(DEBUG_EXEC)

$(EXEC): $(OBJS)
	$(CC) -o $(EXEC) $(OBJS) -Wall -lpthread -lcrypto -lssl
	@echo "> finish"

$(DEBUG_EXEC): $(DEBUG_OBJS)
	$(CC) -o $(DEBUG_EXEC) $(DEBUG_OBJS) -g -Wall -lpthread -lcrypto -lssl -DDEBUG
	@echo "> finish (debug)"

.c.o:
	$(CC) -o $@ -c $< -Wall -lpthread -lcrypto -lssl

.c.do:
	$(CC) -o $@ -c $< -g -Wall -lpthread -lcrypto -lssl -DDEBUG

clean: 
	rm -f $(OBJS)
	rm -f $(DEBUG_OBJS)
	rm -f $(EXEC)
	rm -f $(DEBUG_EXEC)
	rm -f $(VALGRIND_TEST)
	@echo "> finish"