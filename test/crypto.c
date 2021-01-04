#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sodium.h>

#include "../main.h"

char *Base64Encode(const char *plain_text)
{
    const size_t plain_text_len = strlen(plain_text);
    const size_t cipher_text_max_len = sodium_base64_encoded_len(plain_text_len, sodium_base64_VARIANT_ORIGINAL);
    char *cipher_text = (char *)malloc(cipher_text_max_len);
    cipher_text = sodium_bin2base64(cipher_text, cipher_text_max_len, (unsigned char *)plain_text, plain_text_len, sodium_base64_VARIANT_ORIGINAL);

    return cipher_text;
}

unsigned char *Base64Decode(const char *cipher_text)
{
    const size_t cipher_text_len = strlen(cipher_text);
    /*
    size_t i = 0;
    while (cipher_text[i] != '=' && cipher_text[i] != '\0')
    {
        ++i;
    }
    */

    /* use the cipher_text_len to avoid the memory leak */
    //const size_t plain_text_max_len =  4 * (cipher_text_len / 3);
    /* 4/5 */
    const size_t plain_text_max_len =  ((cipher_text_len * 4) / 5);
    //size_t plain_text_len = plain_text_max_len - i;
    size_t plain_text_len = plain_text_max_len;
    unsigned char *plain_text = (unsigned char *)malloc(plain_text_max_len);
    memset(plain_text, 0, plain_text_max_len);

    if (sodium_base642bin(plain_text, plain_text_max_len, cipher_text, cipher_text_len, NULL, &plain_text_len, NULL, sodium_base64_VARIANT_ORIGINAL) != 0)
    {
        return -1;
    }

    return plain_text;
}