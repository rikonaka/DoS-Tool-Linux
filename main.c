#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/time.h>

#include "main.h"
#include "core/debug.h"
#include "attack_module/guess_username_password.h"
#include "attack_module/syn_flood_dos.h"

static int DisplayUsage(void)
{
    /*
        show the useage info
     */
    char *usage = "\n"
                  "Usage:   dostool\n"
                  "Example: ./dostool -a 1 -i \"192.168.1.1:80\"\n"
                  "         ./dostool -a 0 -u riko -i \"http:\\\\192,168.1.1:80/login.asp\"\n"
                  "         ./dostool -a 0 -U \"/home/test/username.txt\" -P \"/home/test/password.txt\"\n"
                  "         -i \"http:\\\\192,168.1.1:80/login.asp\"\n\n"
                  "         -a    Indicate attack mode\n"
                  "               0    Guess the web password\n"
                  "               1    Syn flood attack\n\n"
                  "         -u    Indicate user-provided username (default 'admin', must use with -a 0)\n"
                  "         -U    Indicate user-provided username file (must use with -a 0 and -P)\n"
                  "         -P    Indicate user-provided password file (must use with -a 0)\n"
                  "         -r    Indicate random password generate length (default 8)\n"
                  "         -d    Indicate debug level (default 0)\n"
                  "               0    turn off the debug show\n"
                  "               1    show less debug message\n"
                  "               2    show verbose debug message\n"
                  "               3    show all debug message\n\n"
                  "         -p    Set the process number (default 4)\n"
                  "         -t    Set the thread number (default 2)\n"
                  "         -i    Indicate intent URL address (user shoud indicate the port in thr URL)\n"
                  "         -R    Use the random source IP address in dos attack (can not use in the guess password attack)\n"
                  "               0    turn off the random source ip address which can protect in the local net\n"
                  "               1    enable random source ip address (default)\n\n"
                  "         -h    Show this message\n";

    printf("%s", usage);
    return 0;
}

static int CheckInputCompliance(const pInput process_result)
{
    /*
     * check the compliance of user input
     * like -U must use with -P .etc
     * 
     * return:
     * 0 - check pass
     * 1 - error
     */

    DisplayDebug(DEBUG_LEVEL_3, process_result->debug_level, "Enter CheckInputCompliance");

    /* must have -i */
    if (strlen(process_result->address) == 0)
    {
        return 1;
    }

    /*
     * in the dos attack mode, can not appear 'http' in the address
     */
    if (process_result->attack_mode != 0)
    {

    }

    DisplayDebug(DEBUG_LEVEL_3, process_result->debug_level, "Exit CheckInputCompliance");
}

static int ProcessInputParameters(const int argc, char *argv[], pInput process_result)
{
    /*
        understood the user input meaning
     */
    DisplayDebug(DEBUG_LEVEL_3, process_result->debug_level, "Enter ProcessInputParameters");
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
                    DisplayWarning("Value of -a parameter is not allowed, use default value now");
                    process_result->attack_mode = ATTACK_MODE_DEFAULT;
                    break;
                }
            }
            else
                return 1;
            break;

        case 'd':
            if (argv[++i])
            {
                switch (*argv[i])
                {
                case '0':
                    process_result->debug_level = DEBUG_OFF;
                    break;
                case '1':
                    process_result->debug_level = DEBUG_LEVEL_1;
                    break;
                case '2':
                    process_result->debug_level = DEBUG_LEVEL_2;
                    break;
                case '3':
                    process_result->debug_level = DEBUG_LEVEL_3;
                    break;
                default:
                    DisplayWarning("Value of -t parameter is not allowed, use default value now");
                    process_result->debug_level = DEBUG_LEVEL_DEFAULT;
                    break;
                }
            }
            else
                return 1;
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
            }
            else
                return 1;
            break;

        case 'p':
            if (argv[++i])
            {
                process_result->max_process = atoi(argv[i]);
            }
            else
                return 1;
            break;

        case 'r':
            if (argv[++i])
            {
                process_result->random_password_length = atoi(argv[i]);
            }
            else
                return 1;
            break;

        case 'i':
            if (argv[++i])
            {
                strncpy(process_result->address, argv[i], MAX_URL_LENGTH);
            }
            else
                return 1;
            break;

        case 'R':
            if (argv[++i])
            {
                switch (*argv[i])
                {
                case '0':
                    process_result->random_sip_address = DISABLE_SIP;
                    break;
                case '1':
                    process_result->random_sip_address = ENABLE_SIP;
                    break;
                default:
                    DisplayWarning("Value of -R parameter is not allowed, use default value now");
                    process_result->random_sip_address = ENABLE_SIP;
                    break;
                }
            }

        case 'h':
            DispalyUsage();
            break;

        default:
            DisplayError("Please check you input");
            DispalyUsage();
            return 1;
        }
    }

    DisplayDebug(DEBUG_LEVEL_3, process_result->debug_level, "Exit ProcessInputParameters");
    return 0;
}

static int TestProcessResult(const pInput process_result)
{
    /*
        show the process result
     */
    DisplayDebug(DEBUG_LEVEL_3, process_result->debug_level, "attack_mode: %d\n", process_result->attack_mode);
    DisplayDebug(DEBUG_LEVEL_3, process_result->debug_level, "debug_level: %d\n", process_result->debug_level);
    DisplayDebug(DEBUG_LEVEL_3, process_result->debug_level, "attack_mode_0_one_username: %s\n", process_result->attack_mode_0_one_username);
    DisplayDebug(DEBUG_LEVEL_3, process_result->debug_level, "attack_mode_0_username_file_path: %s\n", process_result->attack_mode_0_username_file_path);
    DisplayDebug(DEBUG_LEVEL_3, process_result->debug_level, "attack_mode_0_password_file_path: %s\n", process_result->attack_mode_0_password_file_path);
    return 0;
}

static int StartAttackJob(const pInput process_result)
{
    DisplayDebug(DEBUG_LEVEL_3, process_result->debug_level, "Enter StartAttackJob");
    pid_t job_pid;
    pthread_t job_tid;
    int pi, ti;
    for (pi = 0; pi < process_result->max_process; pi++)
    {
        DisplayDebug(DEBUG_LEVEL_2, process_result->debug_level, "pi value: %d", pi);
        job_pid = fork();
        DisplayDebug(DEBUG_LEVEL_2, process_result->debug_level, "job_pid value: %d", job_pid);
        if (job_pid == 0)
        {
            /* child process */
            for (ti = 0; ti < process_result->max_thread; ti++)
            {
                DisplayDebug(DEBUG_LEVEL_2, process_result->debug_level, "ti value: %d", ti);
                DisplayDebug(DEBUG_LEVEL_2, process_result->debug_level, "attack_mode value: %d", process_result->attack_mode);
                switch (process_result->attack_mode)
                {
                case GUESS_USERNAME_PASSWORD:
                    /* get the random seed */
                    process_result->seed = ti + pi;
                    int ret = pthread_create(&job_tid, NULL, (void *)Attack_GuessUsernamePassword, process_result);
                    DisplayDebug(DEBUG_LEVEL_2, process_result->debug_level, "job_tid value: %d", job_tid);
                    DisplayDebug(DEBUG_LEVEL_2, process_result->debug_level, "ret value: %d", ret);
                    if (ret != 0)
                    {
                        DisplayError("Create pthread failed");
                        return 1;
                    }
                    pthread_join(job_tid, NULL);
                    break;

                case SYN_FLOOD_ATTACK:
                    /* not finish */
                    break;
                }
            }
        }
        else if (job_pid < 0)
        {
            // Error now
            DisplayError("Create process failed");
        }
        else
        {

            int wait_val;
            int child_id;
            // Father process
            child_id = wait(&wait_val);
            DisplayDebug(DEBUG_LEVEL_1, process_result->debug_level, "child exit, process id: %d", child_id);
            if (WIFEXITED(wait_val))
            {
                DisplayDebug(DEBUG_LEVEL_1, process_result->debug_level, "child exited with code %d", WEXITSTATUS(wait_val));
            }
            else
            {
                DisplayError("Child exited unnormally");
                // sleep() for test
                //sleep(1);
            }
        }
    }

    DisplayDebug(DEBUG_LEVEL_3, process_result->debug_level, "Exit StartAttackJob");
    return 0;
}

int main(int argc, char *argv[])
{
    /*
      main function
     */

    if (argc == 1)
    {
        DisplayError("Need more parameter");
        DispalyUsage();
        return 1;
    }

    pInput process_result = (pInput)malloc(sizeof(Input));
    process_result->max_process = PROCESS_NUM_DEFAULT;
    process_result->max_thread = THREAD_NUM_DEFAULT;
    process_result->debug_level = DEBUG_LEVEL_DEFAULT;
    process_result->random_password_length = RANDOM_PASSWORD_LENGTH_DEFAULT;
    process_result->random_sip_address = RANDOM_SIP_DEFAULT;

    /* processing the user input data */
    if (!ProcessInputParameters(argc, argv, process_result))
    {
        DisplayInfo("Running...");
        DisplayDebug(DEBUG_LEVEL_1, process_result->debug_level, "Debug mode");
        if (process_result->debug_level > 0)
        {
            TestProcessResult(process_result);
        }

        if (process_result->debug_level > 0)
        {
            DisplayDebug(DEBUG_LEVEL_1, process_result->debug_level, "Sleep 2s for debug...");
            sleep(2);
        }

        DisplayDebug(DEBUG_LEVEL_3, process_result->debug_level, "Run StartAttackJob now");
        if (!CheckInputCompliance(process_result))
        {
            /* process user input ready, start attack now */
            StartAttackJob(process_result);
        }
        else
            DisplayError("Check compliance failed, please check your input");
            DispalyUsage();
            return 1;
    }
    else
    {
        DisplayError("Please check you input");
        ShowUsage();
    }

    free(process_result);
    return 0;
}