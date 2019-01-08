#ifndef _BASE64_H
#define _BASE64_H

int Base64Encode(char **b64message, const unsigned char *buffer, size_t length);
size_t Base64Decode(unsigned char **buffer, char *b64message);

#endif