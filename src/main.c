#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "main.h"

// char *version = "v0.10";
// const char *version = "0.20";
// const char *version = "0.30"; // 2019-3-25
const char *version = "0.40"; // 2020-3-23, new arch now

int main(int argc, char *argv[])
{
    /*
     * main function
     */

    if (argc == 1)
    {
        ErrorMessage("Please specify at least one parameter!");
        DisplayUsage();
        return -1;
    }

    size_t attack_mode = JudgeInputType(argc, argv);
    /*
     * GUESS 0              // guess the web passwd (advanced)
     * SYN_FLOOD_ATTACK 1   // syn flood attack
     * UDP_FLOOD_ATTACK 2   // udp flood attack
     * ACK_REFLECT_ATTACK 3 // ack reflect attack
     * DNS_REFLECT_ATTACK 4 // dns reflect attack
     */
    switch (attack_mode)
    {
        case 0:
            /* guess */
            pGuessAttackParameter input_parameter;
            break;

        case 1:
            /* syn */
            break;

        case 2:
            /* udp */
            break;

        case 3:
            /* ack */
            break;

        case 4:
            /* dns */
            break;
    
        default:
            break;
    }

    pInput input;
    if (InitInput(&input) == -1)
    {
        ErrorMessage("init the input failed");
        return 1;
    }

    // processing the user input data
    if (!ProcessInput(argc, argv, input))
    {

        ErrorMessage("Please check you input");
        DisplayUsage();
        return 1;
    }

    char *version;
    if (!GetCurrentVersion(&version))
    {
        ErrorMessage("GetCurrentVersion failed");
        return 1;
    }
    InfoMessage("dos-tool version: %s", version);
    FreeGetCurrentVersionBuff(version);

    InfoMessage("Running...");
    ShowMessage(INFO, input->debug_level, "Debug mode started...");

    check_input = CheckInputCompliance(input);
    if (check_input > 0)
    {
        // process user input ready, start attack now
        ErrorMessage("Check compliance failed, please check your input");
        DisplayUsage();
        return 1;
    }
    else if (check_input < 0)
    {
        // test the module here
        switch (check_input)
        {
        case TEST_TYPE_GUESS:
            if (StartGuessTest(input))
            {
                ErrorMessage("StartGuessTest failed");
                return 1;
            }
            break;

        case TEST_TYPE_SYN_FLOOD:
            if (StartSYNFloodTest(input))
            {
                ErrorMessage("StartSYNFloodTest failed");
                return 1;
            }
            break;

        case TEST_TYPE_UDP_FLOOD:
            if (StartUDPFloodTest(input))
            {
                ErrorMessage("StartUDPFloodTest failed");
                return 1;
            }
            break;

        case TEST_TYPE_ACK_REFLECT:
            if (StartACKReflectTest(input))
            {
                ErrorMessage("StartACKReflectTest failed");
                return 1;
            }
            break;

        case TEST_TYPE_ACK_IP_LIST:
            ProcessACKIPListFileTest();
            break;

        case TEST_TYPE_DNS_REFLECT:
            if (StartDNSReflectTest(input))
            {
                ErrorMessage("StartDNSReflectTest failed");
                return 1;
            }
            break;

        default:
            break;
        }
    }
    else if (check_input == 0)
    {
        // really attack funtion is here
        switch (input->attack_mode)
        {
        case GUESS:
            if (StartGuessAttack(input))
            {
                ErrorMessage("StartGuessAttack failed");
                return 1;
            }
            break;

        case SYN_FLOOD_ATTACK:
            if (StartSYNFloodAttack(input))
            {
                ErrorMessage("StartSYNFloodAttack failed");
                return 1;
            }
            break;

        case UDP_FLOOD_ATTACK:
            if (StartUDPFloodAttack(input))
            {
                ErrorMessage("StartUDPFloodAttack failed");
                return 1;
            }
            break;

        case ACK_REFLECT_ATTACK:
            if (StartACKReflectAttack(input))
            {
                ErrorMessage("StartACKReflectAttack failed");
                return 1;
            }
            break;

        case DNS_REFLECT_ATTACK:
            if (StartDNSReflectAttack(input))
            {
                ErrorMessage("StartDNSReflectAttack failed");
                return 1;
            }
            break;

        default:
            break;
        }
    }

    if (input)
    {
        free(input);
    }
    return 0;
}