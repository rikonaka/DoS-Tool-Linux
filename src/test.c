#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "main.h"
#include "debug.h"

/*
 * Test all function.
 */

/*
static int TestHttpServer()
{
    int listen_socket = ServerTcpCreateSocket(LOCAL_PORT);
    int client_socket = WaitClient(listen_socket);
    
    hanld_client(listen_socket, client_socket);
    close(listen_socket);
    return 0;
}

static int TestHttpClient()
{
    pUDPStruct udp_struct = (pUDPStruct)malloc(sizeof(UDPStruct));
    pSplitUrlRet split_result;
    int i;

    if (!SplitUrl(input->address, &split_result))
    {
        ErrorMessage("AttackThread SplitUrl failed");
        return 1;
    }
    ShowMessage(DEBUG, input->debug_mode, "split_reult: %s", split_result->protocol);
    ShowMessage(DEBUG, input->debug_mode, "split_reult: %s", split_result->host);
    ShowMessage(DEBUG, input->debug_mode, "split_reult: %d", split_result->port);
    ShowMessage(DEBUG, input->debug_mode, "split_reult: %s", split_result->suffix);
    if (split_result->port == 0)
    {
        if (strlen(split_result->host) == 0)
        {
            ErrorMessage("AttackThread SplitUrl not right");
            return -1;
        }
        // make the port as default
        split_result->port = UDP_FLOOD_PORT_DEFAULT;
    }
    // init the target ip and port
    udp_struct->dst_ip = (char *)malloc(IP_BUFFER_SIZE);
    if (!(udp_struct->dst_ip))
    {
        ErrorMessage("AttackThread malloc failed: %s(%d)", strerror(errno), errno);
        return -1;
    }
    if (!memset(udp_struct->dst_ip, 0, IP_BUFFER_SIZE))
    {
        ErrorMessage("AttackThread memset failed: %s(%d)", strerror(errno), errno);
        return -1;
    }
    if (!strncpy(udp_struct->dst_ip, split_result->host, strlen(split_result->host)))
    {
        ErrorMessage("AttackThread strncpy failed: %s(%d)", strerror(errno), errno);
        return -1;
    }
    udp_struct->dst_port = split_result->port;
    FreeSplitUrlBuff(split_result);
    udp_struct->each_ip_repeat = input->each_ip_repeat;

    ShowMessage(VERBOSE, input->debug_mode, "AttackThread start sending data...");
    for (;;)
    {
        if (input->random_sip_address == ENABLE_SIP)
        {
            // randome ip and port
            if (!GetRandomIP(&(udp_struct->src_ip)))
            {
                ErrorMessage("AttackThread GetRandomIP failed");
                return -1;
            }
            // this function has no failed
            GetRandomPort(&(udp_struct->src_port));
        }
        else
        {
            // use the static ip and port
            if (!strncpy(udp_struct->src_ip, DEFAULT_ADDRESS, strlen(DEFAULT_ADDRESS)))
            {
                ErrorMessage("AttackThread copy SIP_ADDRESS failed: %s(%d)", strerror(errno), errno);
                return -1;
            }
            udp_struct->src_port = (int)DEFAULT_PORT;
        }

        // rport is random source port
        for (i = 0; i < input->each_ip_repeat; i++)
        {
            if (SendUDP(udp_struct, input->debug_mode))
            {
                ErrorMessage("AttackThread Attack failed");
                //return 1;
            }
        }
        FreeRandomIPBuff(udp_struct->src_ip);
    }
    FreeUDPStrutBuff(udp_struct);
    return 0;
}

static int TestHttpSend(void)
{

    TestHttpServer();
    char *url = (char *)malloc(sizeof(2 * strlen(LOCAL_ADDRESS)));
    memset(url, 0, sizeof(url));
    sprintf(url, "%s%d", LOCAL_ADDRESS, LOCAL_PORT);
    char *request = "";
    char **response;
    size_t send_len = HttpMethod(url, request, response, VERBOSE);
    print("Send data length: %d", send_len);

    pthread_t tid;
    pthread_attr_t attr;
    int j, ret;

    ShowMessage(VERBOSE, VERBOSE, "Enter StartSYNFloodAttack");
    // only one process
    //input->serial_num = (i * input->max_thread) + j;
    if (pthread_attr_init(&attr))
    {
        ErrorMessage("StartSYNFloodAttack pthread_attr_init failed");
        return -1;
    }
    //if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED))
    if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE))
    {
        ErrorMessage("StartSYNFloodAttack pthread_attr_setdetachstate failed");
        return -1;
    }
    // create thread
    ret = pthread_create(&tid, &attr, (void *)AttackThread, input);
    //printf("j is: %d\n", j);
    ShowMessage(DEBUG, input->debug_mode, "tid: %ld", tid[j]);
    // here we make a map
    if (ret != 0)
    {
        ShowMessage(DEBUG, input->debug_mode, "ret: %d", ret);
        ErrorMessage("Create pthread failed");
        return -1;
    }
    pthread_attr_destroy(&attr);
    //pthread_detach(tid);
    pthread_join(tid, NULL);
    
    free(url);
    return 0;
}
*/

static int TestBase64(void)
{
    /*
     * Test the base64 module work in your system.
     */

    /* encode code */
    WarningMessage("TestBase64 start");

    const char *plain_text_1 = "1234567890";
    char *cipher_text_1 = Base64Encode(plain_text_1);
    InfoMessage("base64 plaintext: [%s], ciphertext: [%s]", plain_text_1, cipher_text_1);

    unsigned char *plain_text_2 = Base64Decode(cipher_text_1);
    InfoMessage("base64 ciphertext: [%s] ,plaintext: [%s]", cipher_text_1, plain_text_2);
    if (strcmp(plain_text_1, plain_text_2) != 0)
    {
        ErrorMessage("base64 result check failed");
        return -1;
    }
    else
    {
        InfoMessage("base64 result check success");
    }
    
    free(cipher_text_1);
    free(plain_text_2);

    const char *plain_text_3 = "abcdefghijklmnopqrstuvwxyz";
    char *cipher_text_3 = Base64Encode(plain_text_3);
    InfoMessage("base64 plaintext: [%s], ciphertext: [%s]", plain_text_3, cipher_text_3);
    unsigned char *plain_text_4 = Base64Decode(cipher_text_3);
    InfoMessage("base64 ciphertext: [%s], plaintext: [%s]", cipher_text_3, plain_text_4);
    if (strcmp(plain_text_3, plain_text_4) != 0)
    {
        ErrorMessage("base64 check result failed");
        return -1;
    }
    else
    {
        InfoMessage("base64 result check success");
    }
    
    free(cipher_text_3);
    free(plain_text_4);

    WarningMessage("TestBase64 end");
    return 0;
}

static int _TestProcessParameter(int argc, char *argv[])
{

    pParameter parameter;
    if (GenParameterSt(argc, argv, &parameter) == -1)
    {
        ErrorMessage("ProcessParameter return -1");
    }
    int i;
    for (i = 0; i < argc; i++)
    {
        InfoMessage("argv_%d: %s", i, argv[i]);
    }
    InfoMessage("<<<<<<<<<< LINE >>>>>>>>>>");
    /*
    typedef struct parameter
    {
        // has the defalut value
        int attack_mode;
        int random_source_address;
        int debug_mode;

        long int random_password_length;
        long int thread_num;
        lone int ip_repeat_time;

        size_t seed;

        char *target_url;
        char *target_ip;
        char *username;
        char *username_file_path;
        char *password_file_path;
        char *router_type;
    } Parameter, *pParameter;
    */
   
    InfoMessage("attack_mode: %d", parameter->attack_mode);
    InfoMessage("random_source_ip_status: %d", parameter->random_source_address);
    InfoMessage("debug_mode: %d", parameter->debug_mode);

    InfoMessage("random_password_length: %ld", parameter->passwd_len);
    InfoMessage("thread_num: %ld", parameter->thread_num);
    InfoMessage("ip_repeat_time: %ld", parameter->ip_repeat_time);

    InfoMessage("target_address: %s", parameter->target_address);
    InfoMessage("username: %s", parameter->username);
    InfoMessage("password: %s", parameter->password);
    InfoMessage("username_file_path: %s", parameter->username_file_path);
    InfoMessage("password_file_path: %s", parameter->password_file_path);
    InfoMessage("router_type: %s", parameter->router_type);

    InfoMessage("<<<<<<<<<< LINE >>>>>>>>>>");
    DesParameterSt(parameter);
    parameter = NULL;

    return 0;
}

static int _TestParameter_1(void)
{
    char *argv_0 = "/home/user/test";
    char *argv_1 = "-a";
    char *argv_2 = "1";
    char *argv_3 = "-i";
    char *argv_4 = "https://192.168.1.1:80/login.asp";
    char *argv_5 = "-u";
    char *argv_6 = "admin";
    char *argv_7 = "-P";
    char *argv_8 = "/path/password.txt";

    int argc = 9;

    char *argv[] = {argv_0, argv_1, argv_2, argv_3,
        argv_4, argv_5, argv_6, argv_7, argv_8};

    _TestProcessParameter(argc, argv);
    return 0;
}

static int _TestParameter_2(void)
{
    char *argv_0 = "/home/user/test";
    char *argv_1 = "-a";
    char *argv_2 = "2";
    char *argv_3 = "-i";
    char *argv_4 = "192.168.1.1";
    char *argv_5 = "-U";
    char *argv_6 = "/path/username.txt";
    char *argv_7 = "-P";
    char *argv_8 = "/path/password.txt";

    int argc = 9;

    char *argv[] = {argv_0, argv_1, argv_2, argv_3,
        argv_4, argv_5, argv_6, argv_7, argv_8};

    _TestProcessParameter(argc, argv);
    return 0;
}

static int _TestParameter_3(void)
{
    char *argv_0 = "/home/user/test";
    char *argv_1 = "-a";
    char *argv_2 = "syn_flood";
    char *argv_3 = "-i";
    char *argv_4 = "192.168.1.1";
    char *argv_5 = "-d";
    char *argv_6 = "1";

    int argc = 7;

    char *argv[] = {argv_0, argv_1, argv_2, argv_3, argv_4, argv_5, argv_6};

    _TestProcessParameter(argc, argv);
    return 0;
}

static int _TestParameter_4(void)
{
    char *argv_0 = "/home/user/test";
    char *argv_1 = "-a";
    char *argv_2 = "syn_flood";
    char *argv_3 = "-i";
    char *argv_4 = "192.168.1.1";
    char *argv_5 = "-d";
    char *argv_6 = "verbose";

    int argc = 7;

    char *argv[] = {argv_0, argv_1, argv_2, argv_3, argv_4, argv_5, argv_6};

    _TestProcessParameter(argc, argv);
    return 0;
}

static int TestParameter(void)
{

    WarningMessage("TestParameter start");
    WarningMessage("_TestParameter_1");
    _TestParameter_1();
    WarningMessage("_TestParameter_2");
    _TestParameter_2();
    WarningMessage("_TestParameter_3");
    _TestParameter_3();
    WarningMessage("_TestParameter_4");
    _TestParameter_4();
    WarningMessage("TestParameter end");

    return 0;

}

static int TestResponseWrite(void)
{

    WarningMessage("TestResponseWrite start");
    const char *test_str = "qwertyiop!@#$%^&*(){}:)(*&^$#@!WGHJHJJHJGJDGAJG";
    BruteForceAttackResponseWrite(test_str);

    if (remove(BRUTE_FORCE_ATTACK_RESPONSE_WRITE_PATH) == 0)
    {
        InfoMessage("delete the write test file success");
    }
    else
    {
        ErrorMessage("delete the write test file failed");
        return -1;
    }

    WarningMessage("TestResponseWrite end");
    return 0;
}

static int TestStrListTravel(const pStrHeader test_list_header)
{
    WarningMessage("TestStrListTravel start");
    if (test_list_header->length <= 0)
    {
        ErrorMessage("the test_list_header is null");
        return -1;
    }
    pStrNode test_node = test_list_header->next;

    for (int i = 0; i < test_list_header->length; i++)
    {
        if (!test_node)
        {
            ErrorMessage("[%d] test_node is null");
            return -1;
        }
        InfoMessage("%d: %s", i, test_node->str);
        test_node = test_node->next;
    }
    WarningMessage("TestStrListTravel end");
    return 0;
}

static int TestDesBruteForceList(pStrHeader password_list_header, pStrHeader username_list_header)
{
    WarningMessage("TestDesBruteForceList start");
    DesBruteForceStrList(password_list_header);
    DesBruteForceStrList(username_list_header);
    WarningMessage("TestDesBruteForceList end");
    return 0;
}


static int TestStrListDistributor(username_header, password_header)
{
    int ret;
    int thread_num = 4;

    pthread_attr_t attr;
    pthread_t tid[thread_num];

    for (int i = 0; i < thread_num; i++)
    {
        //input->serial_num = (i * input->max_thread) + j;
        parameter->seed = i;
        parameter->_brute_force_st->id = i;
        if (pthread_attr_init(&attr))
        {
            ErrorMessage("pthread_attr_init failed");
            return 1;
        }
        //if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED))
        if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE))
        {
            ErrorMessage("StartGuess pthread_attr_setdetachstate failed");
            return 1;
        }
        /* create thread */
        ret = pthread_create(&tid[i], &attr, (void *)_AttackThread, parameter);

        #ifdef DEBUG
        if (ret != 0)
        {
            ShowMessage(DEBUG, parameter->debug_mode, "ret: %d", ret);
            ErrorMessage("create pthread failed");
            return -1;
        }
        ShowMessage(DEBUG, parameter->debug_mode, "tid: %ld", tid[i]);
        #endif

        pthread_attr_destroy(&attr);
    }
    /* join them all */
    //pthread_detach(tid);
    for (int i = 0; i < parameter->thread_num; i++)
    {
        pthread_join(tid[i], NULL);
    }
}

static int TestGenBruteForceList()
{
    WarningMessage("TestGenBruteForceSt start");
    const char *test_password_path = "src/utils/txt/password.txt";
    pStrHeader password_list_header;
    if (GenBruteForcePasswordList(test_password_path, &password_list_header, 10) == -1)
    {
        ErrorMessage("test gen brute force password string list failed");
        return -1;
    }

    const char *test_username_path = "src/utils/txt/username.txt";
    pStrHeader username_list_header;
    if (GenBruteForceUsernameList(test_username_path, &username_list_header, 10))
    {
        ErrorMessage("test gen brute force username string list failed");
        return -1;
    }

    if (TestStrListTravel(password_list_header) == -1)
    {
        ErrorMessage("test travel the password string list failed");
        return -1;
    }
    if (TestStrListTravel(username_list_header) == -1)
    {
        ErrorMessage("test travel the username string list failed");
        return -1;
    }

    TestDesBruteForceList(password_list_header, username_list_header);

    WarningMessage("TestGenBruteForceSt end");
    return 0;
}

int main(int argc, char *argv[])
{
    if (TestParameter() == -1)
    {
        ErrorMessage("test parameter function failed");
        return -1;
    }

    if (TestBase64() == -1)
    {
        ErrorMessage("test base64 function failed");
        return -1;
    }

    if (TestResponseWrite() == -1)
    {
        ErrorMessage("test guess attack response write failed");
        return -1;
    }

    if (TestGenBruteForceList() == -1)
    {
        ErrorMessage("test gennerate brute force attack str list failed");
        return -1;
    }

    /* not test now
    if (TestHttp() == -1)
    {
        ErrorMessage("test http function failed");
        return -1;
    }
    */

    return 0;
}
