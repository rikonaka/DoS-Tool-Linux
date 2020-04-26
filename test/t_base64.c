#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sodium.h>

int Base64Encode(const char *plain_text)
{
    /*
    if (sodium_init() == -1) {
        return 1;
    }
    */

    const size_t plain_text_len = strlen(plain_text);
    const size_t cipher_text_max_len = sodium_base64_encoded_len(plain_text_len, sodium_base64_VARIANT_ORIGINAL);
    char *cipher_text = (char *)malloc(cipher_text_max_len);
    cipher_text = sodium_bin2base64(cipher_text, cipher_text_max_len, (unsigned char *)plain_text, plain_text_len, sodium_base64_VARIANT_ORIGINAL);

    printf("%s\n", cipher_text);
    return 0;
}

int Base64Decode(const char *cipher_text)
{
    const size_t cipher_text_len = strlen(cipher_text);
    size_t i = 0;
    while (cipher_text[i] != '=' && cipher_text[i] != '\0')
    {
        ++i;
    }

    const size_t plain_text_max_len =  4 * (cipher_text_len / 3);
    size_t plain_text_len = plain_text_max_len - i;
    unsigned char *plain_text = (unsigned char *)malloc(plain_text_max_len);

    if (sodium_base642bin(plain_text, plain_text_max_len, cipher_text, cipher_text_len, NULL, &plain_text_len, NULL, sodium_base64_VARIANT_ORIGINAL) != 0)
    {
        return -1;
    }

    printf("%s\n", plain_text);
    return 0;
}

int main(void)
{
    const char *str_1 = "1234567890";
    Base64Encode(str_1);

    const char *str_2 = "MTIzMzQ1";
    Base64Decode(str_2);
}