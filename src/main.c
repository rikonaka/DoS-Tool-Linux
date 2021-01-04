#include <stdlib.h> // for exit and atoi
#include <stdio.h>  // for printf
#include <signal.h> // for signal
#include <string.h> // for strncpy
#include <getopt.h> // for getopt_long

#include "main.h"

extern void VersionShow(void);
/* from logger.c */
extern int ShowMessage(const int message_debug_mode, const int user_debug_mode, const char *fmt, ...);
extern int InfoMessage(const char *fmt, ...);
extern int WarningMessage(const char *fmt, ...);
extern int ErrorMessage(const char *fmt, ...);
extern int MallocErrorMessage(void);
extern int InvalidParameterErrorMessage(const char *argv_s);
extern void WrongInputMessage(const char *input_parameter);

/* from tools.c */
extern int AnalysisAddress(const char *addr);
extern char *StripCopy(char *dst, const char *src);

/* from https.c */
extern int HttpMethod(const char *address, const int port, const char *request, char **response);
extern int HttpsMethod(const char *address, const int port, const char *request, char **response);

/* usage.c */
extern void ShowUsage(void);

/* attack function */
extern int StartSYNFloodAttack(pParameter parameter);
extern int StartUDPFloodAttack(pParameter parameter);
extern int StartACKReflectAttack(pParameter parameter);
extern int StartDNSReflectAttack(pParameter parameter);

void Exit(int sig)
{
    signal(sig, SIGINT);
    signal(sig, SIGSEGV);
    signal(sig, SIGTERM);
    InfoMessage("exit program now...\n");
    exit(0);
}

int main(int argc, char *argv[])
{
    /*
     * main function here, do some parameters parse work
     */

    signal(SIGINT, Exit);
    signal(SIGSEGV, Exit);
    signal(SIGTERM, Exit);

    if (argc < 2)
    {
        ErrorMessage("please specify at least one parameter!");
        ErrorMessage("exit now...");
        ShowUsage();
        return -1;
    }

    /*
     * BRUTE_FORCE_ATTACK 1 // guess the web passwd (advanced)
     * SYN_FLOOD_ATTACK 2   // syn flood attack
     * UDP_FLOOD_ATTACK 3   // udp flood attack
     * ACK_REFLECT_ATTACK 4 // ack reflect attack
     * DNS_REFLECT_ATTACK 5 // dns reflect attack
     */

    VersionShow();
    InfoMessage("running...");

    static char *option_string = "u:p:a:rt:i:h";
    int option_index = 0;
    int c;
    static struct option long_options[] = {
        {"url", required_argument, NULL, 'u'},
        {"port", required_argument, NULL, 'p'},
        {"attack-mode", required_argument, NULL, 'a'},
        {"random-source-address", no_argument, NULL, 'r'},
        {"thread", required_argument, NULL, 't'},
        {"ip-repeat-time", required_argument, NULL, 'i'},
        {"help", no_argument, NULL, 'h'},
        {0, 0, 0, 0},
    };

    char url[MAX_ADDRESS_LENGTH] = {'\0'};
    int port = HTTP_PORT_DEFAULT;
    int attack_mode = NON_ATTACK;
    int random_source_address = DISABLE;
    int thread = THREAD_NUM_DEFAULT;
    int ip_repeat_time = 0;
    while (1)
    {
        c = getopt_long(argc, argv, option_string, long_options, &option_index);
        if (c == -1)
            break;

        switch (c)
        {
        case 'r':
            random_source_address = ENABLE;
            break;
        case 't':
            if (atoi(optarg) != 0)
                thread = atoi(optarg);
            else
                WrongInputMessage("thread");
            break;
        case 'i':
            if (atoi(optarg) != 0)
                ip_repeat_time = atoi(optarg);
            else
                WrongInputMessage("ip-repeat-time");
            break;
        case 'h':
            ShowUsage();
            break;
        case 'u':
            strncpy(url, optarg, MAX_ADDRESS_LENGTH);
            break;
        case 'p':
            if (atoi(optarg) != 0)
                port = atoi(optarg);
            else
                WrongInputMessage("-p or --port"); 
            break;
        case 'a':
            if (atoi(optarg) != 0)
                attack_mode = atoi(optarg);
            else
                WrongInputMessage("-a or --attack-mode"); 
            break;
        case '?':
            WrongInputMessage(c);
        }
    }
    if (strlen(url) == 0)
    {
        WrongInputMessage("-u or --url");
    }

    if (attack_mode == NON_ATTACK)
    {
        WrongInputMessage("-a or --attck-mode");
    }

    switch (attack_mode)
    {
    case SYN_FLOOD_ATTACK:
        /* start syn flood thread */
        break;
    case UDP_FLOOD_ATTACK:
        break;
    case ACK_REFLECT_ATTACK:
        break;
    case DNS_REFLECT_ATTACK:
        break;
    default:
        break;
    }

    return 0;
}