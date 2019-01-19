#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
//#include <stdint.h>

size_t CalcDecodeLength(const char *b64input)
{
    /*
     * calculates the length of a decoded string
     */
    size_t len = strlen(b64input);
    size_t padding = 0;

    if (b64input[len - 1] == '=' && b64input[len - 2] == '=')
    {
        /* last two chars are '=' */
        padding = 2;
    }
    else if (b64input[len - 1] == '=')
    {
        /* last char is '=' */
        padding = 1;
    }

    return (len * 3) / 4 - padding;
}

size_t Base64Decode(unsigned char **buffer, char *b64message)
{
    /*
     * decode the base64 encode string 
     * 
     * b64message -> buffer
     * return the decode string length
     *
     * input:
     *     b64message
     * output:
     *     buffer
     *     length
     */

    BIO *bio, *b64;
    size_t decode_len = CalcDecodeLength(b64message);

    /* store the decode result string */
    *buffer = (unsigned char *)malloc(decode_len + 1);
    (*buffer)[decode_len] = '\0';

    bio = BIO_new_mem_buf(b64message, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    /* do not use the newlines to flush buffer */
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    size_t length = BIO_read(bio, *buffer, strlen(b64message));

    if (length != decode_len)
    {
        /* something wrong now */
        return 0;
    }

    BIO_free_all(bio);

    return length;
}

size_t Base64Encode(char **b64message, const unsigned char *buffer, size_t length)
{
    /*
     * encode a binary safe base64 string 
     * 
     * buffer -> b64message
     * return 0: success
     * return -1: failed
     *
     * input:
     *     buffer
     *     length
     * output:
     *     b64message
     */

    BIO *bio, *b64;
    BUF_MEM *buffer_ptr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    /* write everything in one line */
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &buffer_ptr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    *b64message = (*buffer_ptr).data;

    return strlen(*b64message);
}

void FreeBase64(char *b64message)
{
    if (b64message)
    {
        free(b64message);
    }
}

/*
int main(void)
{

    // encode code
    char *encode_result;
    char *text = "1234567890";

    Base64Encode(&encode_result, text, strlen(text));
    printf("result: %s\n", encode_result);

    // decode code
    char *decode_result;
    size_t test;
    test = Base64Decode((unsigned char **)&decode_result, encode_result);
    printf("Decode output: %s - %ld\n", decode_result, test);

    return 0;
}
*/