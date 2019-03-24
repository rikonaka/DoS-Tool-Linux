.SUFFIXES:.c .o

CC   = gcc
SRCS = main.c\
       core_module/log.c\
	   core_module/base64.c\
	   core_module/https.c\
	   core_module/str.c\
	   core_module/version.c\
	   core_module/input.c\
	   core_module/usage.c\
	   attack_module/router/feixun.c\
	   attack_module/router/tplink.c\
	   attack_module/attack_guess.c\
	   attack_module/attack_syn_flood_dos.c 

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