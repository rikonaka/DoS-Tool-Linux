#ifndef _GUESS_H
#define _GUESS_H
#include <stdlib.h>
#include <string.h>

#define CheckModel 0
#define CheckLength 1

#define UHEADER 0
#define PHEADER 1

typedef struct match_output
{
    char *request;
    char *request_data;
    char *success_or_not;
    struct match_output *next;
} MatchOutput, *pMatchOutput;

#endif