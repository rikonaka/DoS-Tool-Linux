.SUFFIXES:.c .o

CC   = gcc
SRCS = main.c\
	core_module/core_log.c\
	core_module/core_base64.c\
	core_module/core_https.c\
	core_module/core_str.c\
	core_module/core_version.c\
	core_module/core_input.c\
	core_module/core_usage.c\
	attack_module/attack_guess.c\
	attack_module/attack_syn_flood_dos.c\
    attack_module/attack_udp_flood_dos.c\
	attack_module/router/feixun.c\
	attack_module/router/tplink.c

OBJS = $(SRCS:.c=.o)
EXEC = dos-tool

start: $(OBJS)
	$(CC) -o $(EXEC) $(OBJS) -g -Wall -lpthread -lcrypto -lssl
	@echo "\033[0;32mCompiled finish\033[0m"

.c.o:
	$(CC) -o $@ -c $< -g -Wall -lpthread -lcrypto -lss

clean: 
	rm -f $(OBJS)
	rm -f $(EXEC)
	@echo "\033[0;32mClean up finish\033[0m"
