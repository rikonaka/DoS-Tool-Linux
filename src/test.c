#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "test.h"
#include "main.h"

/*
 * Test all function.
 */

static int TestHttps(void)
{
    const char *url = "127.0.0.1:9988";
    const char *request = "";
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
    
    return 0;

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
            return 1;
        }
        FreeBase64Buffer(encode_result);
        FreeBase64Buffer(decode_result);
    }

    free(plain_text);
    return 0;
}

int main(int argc, char *argv[])
{

    TestBase64();

    Test

    return 0;
}
