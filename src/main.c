#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "main.h"

extern int DisplayDebug(const int message_debug_level, const int user_debug_level, const char *fmt, ...);
extern int DisplayInfo(const char *fmt, ...);
extern int DisplayWarning(const char *fmtsring, ...);
extern int DisplayError(const char *fmt, ...);

extern int ProcessInput(const int argc, char *argv[], pInput input);
extern int CheckInputCompliance(const pInput input);
extern int InitInput(pInput *p);

extern void DisplayUsage(void);

extern int StartSYNFloodAttack(const pInput input);
extern int StartSYNFloodTest(const pInput input);

extern int StartGuessAttack(const pInput input);
extern int StartGuessTest(const pInput input);

extern int StartUDPFloodAttack(const pInput input);
extern int StartUDPFloodTest(const pInput input);

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
        DisplayError("Need more parameter");
        DisplayUsage();
        return 1;
    }

    pInput input;
    if (!InitInput(&input))
    {
        DisplayError("Init the input failed");
        return 1;
    }

    // processing the user input data
    if (!ProcessInput(argc, argv, input))
    {

        DisplayError("Please check you input");
        DisplayUsage();
        return 1;
    }

    char *version;
    if (!GetCurrentVersion(&version))
    {
        DisplayError("GetCurrentVersion failed");
        return 1;
    }
    DisplayInfo("dos-tool version %s", version);
    FreeGetCurrentVersionBuff(version);

    DisplayInfo("Running...");
    DisplayDebug(DEBUG_LEVEL_1, input->debug_level, "Debug mode started...");

    check_input = CheckInputCompliance(input);
    if (check_input > 0)
    {
        // process user input ready, start attack now
        DisplayError("Check compliance failed, please check your input");
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
                DisplayError("StartGuessTest failed");
                return 1;
            }
            break;

        case TEST_TYPE_SYN_FLOOD:
            if (StartSYNFloodTest(input))
            {
                DisplayError("StartSYNFloodTest failed");
                return 1;
            }
            break;

        case TEST_TYPE_UDP_FLOOD:
            if (StartUDPFloodTest(input))
            {
                DisplayError("StartUDPFloodTest failed");
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
                DisplayError("StartGuess failed");
                return 1;
            }
            break;

        case SYN_FLOOD_ATTACK:
            if (StartSYNFloodAttack(input))
            {
                DisplayError("StartSYNFlood failed");
                return 1;
            }
            break;

        case UDP_FLOOD_ATTACK:
            if (StartUDPFloodAttack(input))
            {
                DisplayError("StartUDPFlood failed");
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