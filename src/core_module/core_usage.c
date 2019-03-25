#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../main.h"

void DisplayUsage(void)
{
    /*
     * show the useage info
     */

    extern void FreeGetCurrentVersionBuff(char *p);
    extern char *GetCurrentVersion(char **output);

    char *version;
    GetCurrentVersion(&version);
    printf("Version: %s", version);
    FreeGetCurrentVersionBuff(version);

    char *usage = "\n"
                  "Usage: dos-tool [option]\n\n"
                  "Example:\n"
                  "./dos-tool -a 0 -i http:\\\\192.168.1.1:80/login.asp -u admin -P /path/password.txt (use username admin and password file to guess)\n"
                  "./dos-tool -a 1 -i 192.168.1.1:80 (use syn flood attack 192.168.1.1's port 80)\n"
                  "./dos-tool -a 2 -i 192.168.1.1:80 (use udp flood attack 192.168.1.1's port 80)\n"
                  "\n"
                  "-a <attack_mode>        indicate attack mode\n"
                  "                            0    guess the password (not stable)\n"
                  "                            1    syn flood attack\n"
                  "                            2    udp flood attack\n"
                  "-u <username>           indicate user-provided username (default 'admin', must use with -a 0)\n"
                  "-U <username_file>      indicate user-provided username file (must use with -a 0 and -P)\n"
                  "-P <password_file>      indicate user-provided password file (must use with -a 0)\n"
                  "-r <length>             indicate random password generate length (default 8)\n"
                  "-d <debug_level>        indicate debug level (default 0)\n"
                  "                            0    turn off the debug show\n"
                  "                            1    show less debug message\n"
                  "                            2    show verbose debug message\n"
                  "                            3    show all debug message\n"
                  "-p <number>             set the process number (default 1)\n"
                  "-t <number>             set the thread number (default 8)\n"
                  "-i <target>             indicate intent URL address (user shoud indicate the port in thr URL)\n"
                  "-m <type>               type of router\n"
                  "                            feixun_fwr_604h .etc\n"
                  "-h                      show this message\n"
                  "-R                      Use the random source IP address in dos attack (can not use in the guess password attack)\n"
                  "                            0    turn off the random source ip address which can protect you true IP in the local net\n"
                  "                            1    enable random source ip address (default)\n"
                  "\n"
                  "--get-response-length   get the response length for test\n"
                  "--set-watch-length      Indicate a length, if response's length not equal this, return\n"
                  "--ip-repeat-time        If you use the -R, indicate the each random ip repeat send times(default 10240)\n"
                  "--test-guess            Test the guess module\n"
                  "--test-syn              Test the syn flood attack module\n"
                  "--test-udp              Test the udp flood attack module\n"
                  "\n"
                  "";

    printf("%s", usage);
}