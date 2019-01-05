#include <stdlib.h>
#include <stdio.h>

#include "debug.h"

int ShowUsage()
{
    /*
        show the useage info
     */
    char *usage = "\nUsage:   dostool\n"
                  "Example: ./dostool -a 1\n"
                  "         ./dostool -a 0\n"
                  "         ./dostool -a 0 -u admin\n"
                  "         ./dostool -a 0 -U \"/home/test/username.txt\"\n\n"
                  "         -a   Attack mode\n"
                  "         -d   Debug mode\n"
                  "         -D   Show more debug mode\n"
                  "         -u   Use user-provided username (must use with -a 0)\n"
                  "         -U   Use user-provided username file (must use with -a 0)\n"
                  "         -p   Use user-provided password (must use with -a 0)\n"
                  "         -P   Use user-provided password file (must use with -a 0)\n";

    printf(usage);
    return 0;
}