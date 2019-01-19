.SUFFIXES:.c .o

CC   = gcc
SRCS = main.c         \
       tool/debug.c   \
	   tool/base64.c  \
	   tool/http.c    \
	   tool/str.c     \
	   attack/guess.c \
	   attack/syn_flood_dos.c 

OBJS = $(SRCS:.c=.o)
EXEC = dos-tool

start: $(OBJS)
		$(CC) -o $(EXEC) $(OBJS) -g -Wall -lpthread -lcrypto
		@echo 'complie done'

.c.o:
		$(CC) -o $@ -c $< -g -Wall -lpthread

clean:
		rm -f $(OBJS)
		rm -f $(EXEC)
		@echo 'clean done'