#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/time.h>

#include "main.h"

extern int DisplayDebug(const int message_debug_level, const int user_debug_level, const char *fmt, ...);
extern int DisplayInfo(const char *fmt, ...);
extern int DisplayWarning(const char *fmtsring, ...);
extern int DisplayError(const char *fmt, ...);

extern int ProcessInput(const int argc, char *argv[], pInput input);
extern int CheckInputCompliance(const pInput input);
extern int InitInput(pInput *p);

extern void DisplayUsage(void);

static int StartSYNFlood(pInput input)
{
    // run function in thread
    // this attack type must run as root
    extern int SYNFloodAttack_Thread(pInput input);

    pid_t pid, wpid;
    pthread_t tid[input->max_thread];
    pthread_attr_t attr;
    int i, j, ret;
    int status = 0;

    DisplayDebug(DEBUG_LEVEL_3, input->debug_level, "Enter StartSYNFlood");

    for (i = 0; i < input->max_process; i++)
    {
        pid = fork();
        DisplayDebug(DEBUG_LEVEL_2, input->debug_level, "pid: %d", pid);
        if (pid == 0)
        {
            // child process
            for (j = 0; j < input->max_thread; j++)
            {
                //input->serial_num = (i * input->max_thread) + j;
                if (pthread_attr_init(&attr))
                {
                    DisplayError("StartGuess pthread_attr_init failed");
                    return 1;
                }
                //if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED))
                if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE))
                {
                    DisplayError("StartGuess pthread_attr_setdetachstate failed");
                    return 1;
                }
                // create thread
                ret = pthread_create(&tid[j], &attr, (void *)SYNFloodAttack_Thread, input);
                //printf("j is: %d\n", j);
                DisplayDebug(DEBUG_LEVEL_2, input->debug_level, "tid: %ld", tid[j]);
                // here we make a map
                if (ret != 0)
                {
                    DisplayDebug(DEBUG_LEVEL_2, input->debug_level, "ret: %d", ret);
                    DisplayError("Create pthread failed");
                    return 1;
                }
                pthread_attr_destroy(&attr);
            }
            //pthread_detach(tid);
            // join them all
            for (j = 0; j < input->max_thread; j++)
            {
                pthread_join(tid[j], NULL);
            }
        }
        else if (pid < 0)
        {
            DisplayError("Create process failed");
        }
        // Father process
        while ((wpid = wait(&status)) > 0)
        {
            // nothing here
            // wait the child process end
        }
    }
    return 0;
}

static int StartTestSYNFlood(pInput input)
{
    // run function in thread
    // this attack type must run as root
    extern int SYNFloodAttack_Thread(pInput input);

    DisplayDebug(DEBUG_LEVEL_3, input->debug_level, "Enter StartSYNFlood");

    SYNFloodAttack_Thread(input);

    return 0;
}

static int StartGuess(const pInput input)
{
    extern void FreeProcessFileBuff(pStrHeader p);
    extern pStrHeader *ProcessFile(const char *path, pStrHeader *output, int flag);
    extern int GuessAttack_Thread(pInput input);

    pid_t pid, wpid;
    pthread_t tid[input->max_thread];
    pthread_attr_t attr;
    int i, j, ret;
    int status = 0;
    pThreadControlNode tcn;

    // store the linked list if use the path file
    pGuessAttackUse gau = (pGuessAttackUse)malloc(sizeof(GuessAttackUse));
    gau->u_header = NULL;
    gau->p_header = NULL;
    DisplayDebug(DEBUG_LEVEL_3, input->debug_level, "Enter StartAttackProcess");

    // we are not allowed the username from linked list but password from random string
    if (input->get_response_length == ENABLE)
    {
        input->guess_attack_type = GUESS_GET_RESPONSE_LENGTH;
        int length = GuessAttack_Thread(input);
        if (length == -1)
        {
            DisplayError("GuessAttack_Thread failed");
            return 1;
        }
        DisplayInfo("Response length is %d", length);
        return 0;
    }
    else if (input->watch_length > 0)
    {
        input->guess_attack_type = GUESS_LENGTH;
    }
    else if (strlen(input->password_path) > 0)
    {
        ProcessFile(input->password_path, &(gau->p_header), 1);
        if (strlen(input->username_path) > 0)
        {
            ProcessFile(input->username_path, &(gau->u_header), 0);
            input->guess_attack_type = GUESS_ULPL;
        }
        else
        {
            input->guess_attack_type = GUESS_U1PL;
        }
    }
    else
    {
        input->guess_attack_type = GUESS_U1PR;
    }

    input->gau = gau;
    input->tch = (pThreadControlHeader)malloc(sizeof(ThreadControlHeader));
    input->tch->next = NULL;
    input->tch->length = 0;
    for (i = 0; i < input->max_process; i++)
    {
        pid = fork();
        DisplayDebug(DEBUG_LEVEL_2, input->debug_level, "pid: %d", pid);
        if (pid == 0)
        {
            // child process
            for (j = 0; j < input->max_thread; j++)
            {
                //input->serial_num = (i * input->max_thread) + j;
                tcn = (pThreadControlNode)malloc(sizeof(ThreadControlNode));
                input->seed = i + j;
                if (pthread_attr_init(&attr))
                {
                    DisplayError("StartGuess pthread_attr_init failed");
                    return 1;
                }
                //if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED))
                if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE))
                {
                    DisplayError("StartGuess pthread_attr_setdetachstate failed");
                    return 1;
                }
                // create thread
                ret = pthread_create(&tid[j], &attr, (void *)GuessAttack_Thread, input);
                //printf("j is: %d\n", j);
                DisplayDebug(DEBUG_LEVEL_2, input->debug_level, "tid: %ld", tid[j]);
                // here we make a map
                tcn->tid = tid[j];
                tcn->id = j;
                if (ret != 0)
                {
                    DisplayDebug(DEBUG_LEVEL_2, input->debug_level, "ret: %d", ret);
                    DisplayError("Create pthread failed");
                    return 1;
                }
                tcn->next = input->tch->next;
                input->tch->next = tcn;
                pthread_attr_destroy(&attr);
            }
            //pthread_detach(tid);
            // join them all
            for (j = 0; j < input->max_thread; j++)
            {
                pthread_join(tid[j], NULL);
            }
        }
        else if (pid < 0)
        {
            // Error now
            DisplayError("Create process failed");
        }
        // Father process
        while ((wpid = wait(&status)) > 0)
        {
            // nothing here
            // wait the child process end
        }
    }
    // for test
    //sleep(10);
    if (gau->u_header)
    {
        FreeProcessFileBuff(gau->u_header);
    }
    if (gau->p_header)
    {
        FreeProcessFileBuff(gau->p_header);
    }
    if (gau)
    {
        free(gau);
    }
    DisplayDebug(DEBUG_LEVEL_3, input->debug_level, "Exit StartAttackProcess");
    return 0;
}

static int StartTestGuess(const pInput input)
{
    extern void FreeProcessFileBuff(pStrHeader p);
    extern pStrHeader *ProcessFile(const char *path, pStrHeader *output, int flag);
    extern int GuessAttack_Thread(pInput input);


    // store the linked list if use the path file
    pGuessAttackUse gau = (pGuessAttackUse)malloc(sizeof(GuessAttackUse));
    gau->u_header = NULL;
    gau->p_header = NULL;
    DisplayDebug(DEBUG_LEVEL_3, input->debug_level, "Enter StartAttackProcess");

    // we are not allowed the username from linked list but password from random string
    if (input->get_response_length == ENABLE)
    {
        input->guess_attack_type = GUESS_GET_RESPONSE_LENGTH;
        int length = GuessAttack_Thread(input);
        if (length == -1)
        {
            DisplayError("GuessAttack_Thread failed");
            return 1;
        }
        DisplayInfo("Response length is %d", length);
        return 0;
    }
    else if (input->watch_length > 0)
    {
        input->guess_attack_type = GUESS_LENGTH;
    }
    else if (strlen(input->password_path) > 0)
    {
        ProcessFile(input->password_path, &(gau->p_header), 1);
        if (strlen(input->username_path) > 0)
        {
            ProcessFile(input->username_path, &(gau->u_header), 0);
            input->guess_attack_type = GUESS_ULPL;
        }
        else
        {
            input->guess_attack_type = GUESS_U1PL;
        }
    }
    else
    {
        input->guess_attack_type = GUESS_U1PR;
    }

    input->gau = gau;
    input->tch = (pThreadControlHeader)malloc(sizeof(ThreadControlHeader));
    input->tch->next = NULL;
    input->tch->length = 0;

    GuessAttack_Thread(input);

    // for test
    //sleep(10);
    if (gau->u_header)
    {
        FreeProcessFileBuff(gau->u_header);
    }
    if (gau->p_header)
    {
        FreeProcessFileBuff(gau->p_header);
    }
    if (gau)
    {
        free(gau);
    }
    DisplayDebug(DEBUG_LEVEL_3, input->debug_level, "Exit StartAttackProcess");
    return 0;
}

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
        switch (check_input)
        {
        case TEST_TYPE_GUESS:
            if (StartTestGuess(input))
            {
                DisplayError("StartTestGuess failed");
                return 1;
            }
            break;

        case TEST_TYPE_SYN_FLOOD:
            if (StartTestSYNFlood(input))
            {
                DisplayError("StartTestSYNFlood failed");
                return 1;
            }
            break;

        default:
            break;
        }
    }

    switch (input->attack_mode)
    {
    case GUESS_USERNAME_PASSWORD:
        if (StartGuess(input))
        {
            DisplayError("StartGuess failed");
            return 1;
        }
        break;

    case SYN_FLOOD_ATTACK:
        if (StartSYNFlood(input))
        {
            DisplayError("StartSYNFlood failed");
            return 1;
        }
        break;

    default:
        break;
    }

    if (input)
    {
        free(input);
    }
    return 0;
}