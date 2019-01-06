#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/time.h>

#include "main.h"
#include "core/http.h"
#include "core/debug.h"
#include "core/attack.h"
#include "method/random.h"

static int ProcessInputParameters(const int argc, char *argv[], pInput process_result)
{
    /*
        understood the user input meaning
     */
    int i;
    char *ptmp;

    for (i = 1; i < argc; i++)
    {
        ptmp = (char *)strstr(argv[i], "-");
        if (!ptmp)
        {
            printf("Illegal input\n");
            return 1;
        }

        switch (*(ptmp + 1))
        {
        case 'a':
            if (argv[++i])
            {
                switch (*argv[i])
                {
                case '0':
                    process_result->attack_mode = GUESS_USERNAME_PASSWORD;
                    break;
                case '1':
                    process_result->attack_mode = SYN_FLOOD_ATTACK;
                    break;
                default:
                    process_result->attack_mode = ATTACK_MODE_DEFAULT;
                    break;
                }
            }
            else
                return 1;
            break;

        case 'd':
            process_result->debug_mode = LOG_LEVEL_1;
            break;

        case 'D':
            process_result->debug_mode = LOG_LEVEL_2;
            break;

        case 'u':
            if (argv[++i])
            {
                strncpy(process_result->attack_mode_0_one_username, argv[i], MAX_USERNAME_LENGTH);
            }
            else
                return 1;
            break;

        case 'U':
            if (argv[++i])
            {
                strncpy(process_result->attack_mode_0_username_file_path, argv[i], MAX_USERNAME_PATH_LENGTH);
            }
            else
                return 1;
            break;

        case 'p':
            if (argv[++i])
            {
                strncpy(process_result->attack_mode_0_one_password, argv[i], MAX_PASSWORD_LENGTH);
            }
            else
                return 1;
            break;

        case 'P':
            if (argv[++i])
            {
                strncpy(process_result->attack_mode_0_password_file_path, argv[i], MAX_PASSWORD_PATH_LENGTH);
            }
            else
                return 1;
            break;

        default:
            printf("Input error, please see the usage:\n");
            ShowUsage();
            exit(1);
        }
    }

    return 0;
}

int TestProcessResult(pInput process_result)
{
    /*
        show the process result
     */
    printf("attack_mode: %d\n", process_result->attack_mode);
    printf("debug_mode: %d\n", process_result->debug_mode);
    printf("attack_mode_0_one_username: %s\n", process_result->attack_mode_0_one_username);
    printf("attack_mode_0_one_password: %s\n", process_result->attack_mode_0_one_password);
    printf("attack_mode_0_username_file_path: %s\n", process_result->attack_mode_0_username_file_path);
    printf("attack_mode_0_password_file_path: %s\n", process_result->attack_mode_0_password_file_path);
    return 0;
}

int main(int argc, char *argv[])
{
    /*
      main function
     */

    if (argc == 1)
    {
        return 0;
    }

    pInput process_result = (pInput)malloc(sizeof(Input));

    if (!ProcessInputParameters(argc, argv, process_result))
    {
        TestProcessResult(process_result);
    }
    else
    {
        printf("Please check you input");
        ShowUsage();
        exit(1);
    }

    return 0;
}