#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/time.h>

#include "main.h"

extern int DisplayDebug(const int message_debug_level, const int user_debug_level, const char *fmtstring, ...);
extern int DisplayInfo(const char *fmtstring, ...);
extern int DisplayWarning(const char *fmtsring, ...);
extern int DisplayError(const char *fmtstring, ...);

static int DisplayUsage(void)
{
    /*
        show the useage info
     */
    char *usage = "\n"
                  "Usage:   dostool [option]\n"
                  "Example: ./dostool -a 0 -u \"JayChou\" -i \"http:\\\\192,168.1.1:80/login.asp\"\n"
                  "         ./dostool -a 0 -U \"/home/test/username.txt\" -P \"/home/test/password.txt\"\n"
                  "         ./dostool -a 0 -u \"JayChou\" -P \"/home/test/password.txt\"\n"
                  "         ./dostool -a 0 -P \"/home/test/password.txt\"\n"
                  "         ./dostool -a 1 -i \"192.168.1.1:80\"\n"
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
                  "         -m    Type of router\n"
                  "               Please check the README.md file for details\n\n"
                  "         -h    Show this message\n";

    printf("%s", usage);
    return 0;
}

static int CheckInputCompliance(const pInput input)
{
    /*
     * check the compliance of user input
     * like -U must use with -P .etc
     * 
     * return:
     * 0 - check pass
     * 1 - error
     */

    DisplayDebug(DEBUG_LEVEL_3, input->debug_level, "Enter CheckInputCompliance");

    // in the dos attack mode, can not appear 'http' in the address
    if (input->attack_mode != 0)
    {
        if (strstr(input->address, "http"))
        {
            DisplayError("Please check your address, this should not appear http or https");
            return -1;
        }
    }

    // -U must with -P
    if (strlen(input->attack_mode_0_username_file_path) > 0)
    {
        if (strlen(input->attack_mode_0_password_file_path) == 0)
        {
            DisplayError("Place check your -U paratemer, -U must use with -P");
            return -1;
        }
    }

    DisplayDebug(DEBUG_LEVEL_3, input->debug_level, "Exit CheckInputCompliance");
    return 0;
}

static int ProcessInput(const int argc, char *argv[], pInput input)
{
    /*
        understood the user input meaning
     */
    DisplayDebug(DEBUG_LEVEL_3, input->debug_level, "Enter ProcessInputParameters");
    int i;
    char *ptmp;

    for (i = 1; i < argc; i++)
    {
        ptmp = (char *)strstr(argv[i], "-");
        if (!ptmp)
        {
            printf("Illegal input\n");
            return -1;
        }

        switch (*(ptmp + 1))
        {
        case 'a':
            if (argv[++i])
            {
                switch (*argv[i])
                {
                case '0':
                    input->attack_mode = GUESS_USERNAME_PASSWORD;
                    break;
                case '1':
                    input->attack_mode = SYN_FLOOD_ATTACK;
                    break;
                default:
                    DisplayWarning("Value of the -a parameter is not allowed, use default value now");
                    input->attack_mode = ATTACK_MODE_DEFAULT;
                    break;
                }
            }
            else
            {
                DisplayWarning("Can not found value of -a parameter, use default value now");
                input->attack_mode = ATTACK_MODE_DEFAULT;
                //return -1;
            }
            break;

        case 'd':
            if (argv[++i])
            {
                switch (*argv[i])
                {
                case '0':
                    input->debug_level = DEBUG_OFF;
                    break;
                case '1':
                    input->debug_level = DEBUG_LEVEL_1;
                    break;
                case '2':
                    input->debug_level = DEBUG_LEVEL_2;
                    break;
                case '3':
                    input->debug_level = DEBUG_LEVEL_3;
                    break;
                default:
                    DisplayWarning("Value of -d parameter is not allowed, use default value now");
                    input->debug_level = DEBUG_LEVEL_DEFAULT;
                    break;
                }
            }
            else
            {
                DisplayWarning("Can not found value of -d parameter, use default value now");
                input->debug_level = DEBUG_LEVEL_DEFAULT;
                //return -1;
            }
            break;

        case 'u':
            if (argv[++i])
            {
                strncpy(input->attack_mode_0_one_username, argv[i], MAX_USERNAME_LENGTH);
            }
            else
            {
                DisplayError("Can not found value of -u parameter");
                return -1;
            }
            break;

        case 'U':
            if (argv[++i])
            {
                strncpy(input->attack_mode_0_username_file_path, argv[i], MAX_USERNAME_PATH_LENGTH);
            }
            else
            {
                DisplayError("Can not found value of -U parameter");
                return -1;
            }
            break;

        case 'P':
            if (argv[++i])
            {
                strncpy(input->attack_mode_0_password_file_path, argv[i], MAX_PASSWORD_PATH_LENGTH);
            }
            else
            {
                DisplayError("Can not found value of -P parameter");
                return -1;
            }
            break;

        case 't':
            if (argv[++i])
            {
                input->max_thread = atoi(argv[i]);
            }
            else
            {
                DisplayWarning("Can not found value of -t parameter, use default value now");
                input->max_thread = THREAD_NUM_DEFAULT;
                //return -1;
            }
            break;

        case 'p':
            if (argv[++i])
            {
                input->max_process = atoi(argv[i]);
            }
            else
            {
                DisplayWarning("Can not found value of -p parameter, use default value now");
                input->max_process = PROCESS_NUM_DEFAULT;
                //return -1;
            }
            break;

        case 'r':
            if (argv[++i])
            {
                input->random_password_length = atoi(argv[i]);
            }
            else
            {
                DisplayWarning("Can not found value of -r parameter, use default value now");
                input->random_password_length = RANDOM_PASSWORD_LENGTH_DEFAULT;
                //return -1;
            }
            break;

        case 'i':
            if (argv[++i])
            {
                strncpy(input->address, argv[i], MAX_URL_LENGTH);
            }
            else
            {
                DisplayError("Can not found value of -i parameter");
                return -1;
            }
            break;

        case 'R':
            if (argv[++i])
            {
                switch (*argv[i])
                {
                case '0':
                    input->random_sip_address = DISABLE_SIP;
                    break;
                case '1':
                    input->random_sip_address = ENABLE_SIP;
                    break;
                default:
                    DisplayWarning("Value of -R parameter is not allowed, use default value now");
                    input->random_sip_address = ENABLE_SIP;
                    break;
                }
            }
            else
            {
                DisplayWarning("Can not found value of -i parameter, use default value now");
                input->random_sip_address = RANDOM_SIP_DEFAULT;
            }
            break;

        case 'h':
            DispalyUsage();
            return 0;

        default:
            DisplayError("Please check you input");
            DispalyUsage();
            return -1;
        }
    }

    DisplayDebug(DEBUG_LEVEL_3, input->debug_level, "Exit ProcessInputParameters");
    return 0;
}

static int Run_Attack_GuessUsernamePassword(pInput input)
{
    // split the big function
    extern int Attack_GuessUsernamePassword(pInput input);
    pthread_t job_tid;

    int ret = pthread_create(&job_tid, NULL, (void *)Attack_GuessUsernamePassword, input);
    DisplayDebug(DEBUG_LEVEL_2, input->debug_level, "job_tid value: %d", job_tid);
    DisplayDebug(DEBUG_LEVEL_2, input->debug_level, "ret value: %d", ret);

    if (ret != 0)
    {
        DisplayError("Create pthread failed");
        return -1;
    }
    pthread_join(job_tid, NULL);
    return 0;
}

static int Run_Attack_SYNFlood(pInput input)
{
    // run function in thread
    return 0;
}

static int StartAttackJob(const pInput input)
{
    DisplayDebug(DEBUG_LEVEL_3, input->debug_level, "Enter StartAttackJob");
    pid_t job_pid;
    int pi, ti;
    for (pi = 0; pi < input->max_process; pi++)
    {
        DisplayDebug(DEBUG_LEVEL_2, input->debug_level, "pi value: %d", pi);
        job_pid = fork();
        DisplayDebug(DEBUG_LEVEL_2, input->debug_level, "job_pid value: %d", job_pid);
        if (job_pid == 0)
        {
            /* child process */
            for (ti = 0; ti < input->max_thread; ti++)
            {
                DisplayDebug(DEBUG_LEVEL_2, input->debug_level, "ti value: %d", ti);
                DisplayDebug(DEBUG_LEVEL_2, input->debug_level, "attack_mode value: %d", input->attack_mode);
                switch (input->attack_mode)
                {
                case GUESS_USERNAME_PASSWORD:
                    /* get the random seed */
                    input->seed = ti + pi;
                    Run_Attack_GuessUsernamePassword(input);
                    break;

                case SYN_FLOOD_ATTACK:
                    /* not finish */
                    Run_Attack_SYNFlood(input);
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
            // Father process
            int wait_val;
            int child_id;
            child_id = wait(&wait_val);
            DisplayDebug(DEBUG_LEVEL_1, input->debug_level, "child exit, process id: %d", child_id);
            if (WIFEXITED(wait_val))
            {
                DisplayDebug(DEBUG_LEVEL_1, input->debug_level, "child exited with code %d", WEXITSTATUS(wait_val));
            }
            else
            {
                DisplayError("Child exited unnormally");
                // sleep() for test
                //sleep(1);
            }
        }
    }

    DisplayDebug(DEBUG_LEVEL_3, input->debug_level, "Exit StartAttackJob");
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
        return -1;
    }

    pInput input = (pInput)malloc(sizeof(Input));
    // field default value
    input->attack_mode = -1;
    input->max_process = PROCESS_NUM_DEFAULT;
    input->max_thread = THREAD_NUM_DEFAULT;
    input->debug_level = DEBUG_LEVEL_DEFAULT;
    input->random_password_length = RANDOM_PASSWORD_LENGTH_DEFAULT;
    input->random_sip_address = RANDOM_SIP_DEFAULT;

    // processing the user input data
    if (!ProcessInput(argc, argv, input))
    {
        DisplayInfo("Running...");
        DisplayDebug(DEBUG_LEVEL_1, input->debug_level, "Debug mode started...");

        if (input->debug_level > 0)
        {
            DisplayDebug(DEBUG_LEVEL_1, input->debug_level, "Sleep 2s for debug...");
            sleep(2);
        }

        if (!CheckInputCompliance(input))
        {
            /* process user input ready, start attack now */
            StartAttackJob(input);
        }
        else
        {
            DisplayError("Check compliance failed, please check your input");
            DispalyUsage();
            return -1;
        }
    }
    else
    {
        DisplayError("Please check you input");
        ShowUsage();
    }

    free(input);
    return 0;
}