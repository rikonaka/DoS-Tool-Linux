.SUFFIXES:.c .o

CC   = gcc
SRCS = main.c         \
       tool/debug.c   \
	   tool/base64.c  \
	   tool/https.c   \
	   tool/str.c     \
	   tool/version.c \
	   attack/guess.c \
	   attack/syn_flood_dos.c 

OBJS = $(SRCS:.c=.o)
EXEC = dos-tool

start: $(OBJS)
		$(CC) -o $(EXEC) $(OBJS) -g -Wall -lpthread -lcrypto -lssl
		@echo 'complie done'

.c.o:
		$(CC) -o $@ -c $< -g -Wall -lpthread -lcrypto -lss

clean:
		rm -f $(OBJS)
		rm -f $(EXEC)
		@echo 'clean done'