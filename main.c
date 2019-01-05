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
                process_result->attack_mode = atoi(argv[i]);
            }
            else
                return 1;
            break;
        case 'd':
            process_result->debug_mode = 1;
            break;
        case 'D':
            process_result->debug_mode = 2;
            break;
        case 'u':
            if (argv[++i])
            {
                strcpy(process_result->attack_mode_0_one_username, argv[i]);
            }
            else
                return 1;
        case 'U':
            if (argv[++i])
            {
                strcpy(process_result->attack_mode_0_username_file_path, argv[i]);
            }
            else
                return 1;
        case 'p':
            if (argv[++i])
            {
                strcpy(process_result->attack_mode_0_one_password, argv[i]);
            }
            else
                return 1;
        case 'P':
            if (argv[++i])
            {
                strcpy(process_result->attack_mode_0_password_file_path, argv[i]);
            }
            else
                return 1;
        default:
            printf("Please see the usage:\n");
            ShowUsage();
            exit(1);
        }
    }

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
    process_result->attack_mode = ATTACK_MODE_DEFAULT;
    process_result->debug_mode = DEBUG_MODE_DEFAULT;

    if (!ProcessInputParameters(argc, argv, process_result))
    {
    }
    else
    {
        printf("Please check you input");
        ShowUsage();
        exit(1);
    }

    return 0;
}