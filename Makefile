.SUFFIXES:.c .o

CC   = gcc
SRCS = main.c core/debug.c attack_module/guess_username_password.c attack_module/syn_flood_dos.c 

OBJS = $(SRCS:.c=.o)
EXEC = tool

start: $(OBJS)
		$(CC) -o $(EXEC) $(OBJS) -g -Wall -lpthread
		@echo '>>> Complie All File Ok'

.c.o:
		$(CC) -o $@ -c $< -g -Wall -lpthread

clean:
		rm -f $(OBJS)
		rm -f $(EXEC)
		@echo '>>> Clean All File Ok'