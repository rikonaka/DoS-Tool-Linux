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
#include "core/random.h"
#include "attack_module/guess_username_password.h"

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
            process_result->debug_mode = LOG_INFO;
            break;

        case 'D':
            process_result->debug_mode = LOG_DEBUG;
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

        case 't':
            if (argv[++i])
            {
                process_result->max_thread = atoi(argv[i]);
                /*
                if (process_result->max_thread >= __INT64_MAX__)
                {
                    process_result->max_process = __INT64_MAX__;
                }
                */
            }
            else
                return 1;
            break;

        case 'T':
            if (argv[++i])
            {
                process_result->max_process = atoi(argv[i]);
            }
            else
                return 1;
            break;

        default:
            printf("Input error, please see the usage:\n");
            ShowUsage();
            return 1;
        }
    }

    return 0;
}

static int TestProcessResult(const pInput process_result)
{
    /*
        show the process result
     */
    Log(LOG_DEBUG, process_result->debug_mode, "attack_mode: %d\n", process_result->attack_mode);
    Log(LOG_DEBUG, process_result->debug_mode, "debug_mode: %d\n", process_result->debug_mode);
    Log(LOG_DEBUG, process_result->debug_mode, "attack_mode_0_one_username: %s\n", process_result->attack_mode_0_one_username);
    Log(LOG_DEBUG, process_result->debug_mode, "attack_mode_0_one_password: %s\n", process_result->attack_mode_0_one_password);
    Log(LOG_DEBUG, process_result->debug_mode, "attack_mode_0_username_file_path: %s\n", process_result->attack_mode_0_username_file_path);
    Log(LOG_DEBUG, process_result->debug_mode, "attack_mode_0_password_file_path: %s\n", process_result->attack_mode_0_password_file_path);
    return 0;
}

static int StartAttackJob(const pInput process_result)
{
    pid_t job_pid;
    pthread_t job_tid;
    int pi, ti;
    int ret;
    for (pi = 0; pi < process_result->max_process; pi++)
    {
        job_pid = fork();
        if (job_pid == 0)
        {
            /* child process */
            for (ti = 0; ti < process_result->max_thread; ti++)
            {
                switch (process_result->attack_mode)
                {
                case GUESS_USERNAME_PASSWORD:
                    /* get the random seed */
                    time_t t;
                    time(&t);
                    process_result->seed = (int)t + ti + pi;
                    ret = pthread_create(&job_tid, NULL, (void *)Attack_GuessUsernamePassword, process_result);
                    break;
                }
            }
        }
    }
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
    process_result->max_process = MAX_PROCESS;
    process_result->max_thread = MAX_THREAD;

    if (!ProcessInputParameters(argc, argv, process_result))
    {
        Log(LOG_INFO, process_result->debug_mode, "Running...");
        Log(LOG_DEBUG, process_result->debug_mode, "Debug mode start...");
        TestProcessResult(process_result);

        if (process_result->debug_mode != 0)
        {
            Log(LOG_DEBUG, process_result->debug_mode, "Sleep 2s for debug...");
            sleep(2);
        }

        StartAttackJob(process_result);
    }
    else
    {
        printf("Please check you input");
        ShowUsage();
    }

    free(process_result);
    return 0;
}