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

OBJS = $(SRCS:.c=.o)
EXEC = dos-tool-linux

all: $(EXEC) $(TEST_EXEC)

$(EXEC): $(OBJS)
	$(CC) -o $(EXEC) $(OBJS) -g -Wall -lpthread
	@echo "Compiled finish."

.c.o:
	$(CC) -o $@ -c $< -g -Wall -lpthread

clean: 
	rm -f $(OBJS)
	rm -f $(EXEC)
	@echo "Clean up finish."