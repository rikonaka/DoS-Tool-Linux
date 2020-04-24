#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include "main.h"

// char *version = "v0.10";
// const char *version = "0.20";
// const char *version = "0.30"; // 2019-3-25
const char *version = "1.00"; // 2020-3-23, new arch now

/* global value*/
pParameter parameter;

void ElegantExit()
{
    if (parameter->_brute_force_st)
    {
        
    }
    DesParameterSt(parameter);
    InfoMessage("exit program now");
    exit(0);
}

int main(int argc, char *argv[])
{
    /*
     * main function
     */

    if (argc < 2)
    {
        ErrorMessage("please specify at least one parameter!");
        ShowUsage();
        return -1;
    }

    signal(SIGINT, ElegantExit);
    signal(SIGSEGV, ElegantExit);
    signal(SIGTERM, ElegantExit);
    /*
     * GUESS 0              // guess the web passwd (advanced)
     * SYN_FLOOD_ATTACK 1   // syn flood attack
     * UDP_FLOOD_ATTACK 2   // udp flood attack
     * ACK_REFLECT_ATTACK 3 // ack reflect attack
     * DNS_REFLECT_ATTACK 4 // dns reflect attack
     */
    
    InfoMessage("dos-tool-linux version: %s", version);
    InfoMessage("running...");

    // processing the user input data
    if (GenParameterSt(argc, argv, &parameter) == -1)
    {

        ErrorMessage("Please check you input");
        //ShowUsage();
        return -1;
    }
    ShowMessage(DEBUG, parameter->debug_mode, "debug mode started...");

    if ((!parameter->target_address) || (strlen(parameter->target_address) == 0))
    {
        ErrorMessage("please input the target address use -i");
        return -1;
    }

    switch (parameter->attack_mode)
    {
        case BRUTE_FORCE_ATTACK:
            parameter->_brute_force_st = (pBruteForceSt)malloc(sizeof(BruteForceSt));
            parameter->_brute_force_st->brute_force_attack_mode = BruteForceMode(parameter);
            parameter->address_type = AnalysisAddress(parameter->target_address);
            if (parameter->address_type == -1)
            {
                ErrorMessage("analysis address failed");
                return -1;
            }
            /* start attack thread */
            StartBruteForceAttack(parameter);
            break;

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

    if (parameter)
    {
        free(parameter);
    }
    return 0;
}