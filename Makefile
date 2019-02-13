.SUFFIXES:.c .o

CC   = gcc
SRCS = main.c\
       log.c\
	   base64.c\
	   https.c\
	   str.c\
	   version.c\
	   attack_guess.c\
	   router/feixun.c\
	   router/tplink.c\
	   attack_syn_flood_dos.c 

OBJS = $(SRCS:.c=.o)
EXEC = dos-tool

start: $(OBJS)
		$(CC) -o $(EXEC) $(OBJS) -g -Wall -lpthread -lcrypto -lssl
		@echo 'Compiled'

.c.o:
		$(CC) -o $@ -c $< -g -Wall -lpthread -lcrypto -lss

clean:
		rm -f $(OBJS)
		rm -f $(EXEC)
		@echo 'Clean up'