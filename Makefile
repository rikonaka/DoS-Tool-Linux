.SUFFIXES:.c .o

CC   = gcc
SRCS = main.c core/debug.c core/base64.c core/http.c core/str.c attack_module/guess.c attack_module/syn_flood_dos.c 

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