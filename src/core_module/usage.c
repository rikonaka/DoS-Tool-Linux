#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../main.h"

void DisplayUsage(void)
{
    /*
     * show the useage info
     */
    char *usage = "\n"
                  "Usage: dostool [option]\n\n"
                  "Example:\n"
                  "./dostool -a 0 -u \"admin\" -i \"http:\\\\192.168.1.1:80/login.asp\"\n"
                  "./dostool -a 0 -U \"/path/username.txt\" -P \"/path/password.txt\"\n"
                  "./dostool -a 0 -u \"admin\" -P \"/path/password.txt\"\n"
                  "./dostool -a 0 -P \"/path/password.txt\"\n"
                  "./dostool -a 1 -i \"192.168.1.1:80\"\n"
                  "\n"
                  "-a <attack_mode>        Indicate attack mode\n"
                  "                        0    Guess the web password\n"
                  "                        1    Syn flood attack\n"
                  "\n"
                  "-u <username>           Indicate user-provided username (default 'admin', must use with -a 0)\n"
                  "\n"
                  "-U <username_file>      Indicate user-provided username file (must use with -a 0 and -P)\n"
                  "\n"
                  "-P <password_file>      Indicate user-provided password file (must use with -a 0)\n"
                  "\n"
                  "-r <length>             Indicate random password generate length (default 8)\n"
                  "\n"
                  "-d <debug_level>        Indicate debug level (default 0)\n"
                  "                        0    turn off the debug show\n"
                  "                        1    show less debug message\n"
                  "                        2    show verbose debug message\n"
                  "                        3    show all debug message\n"
                  "\n"
                  "-p <number>             Set the process number (default 1)\n"
                  "\n"
                  "-t <number>             Set the thread number (default 8)\n"
                  "\n"
                  "-i <target>             Indicate intent URL address (user shoud indicate the port in thr URL)\n"
                  "\n"
                  "-m <type>               Type of router\n"
                  "                        feixun_fwr_604h .etc\n"
                  "\n"
                  "-h                      Show this message\n"
                  "\n"
                  "--get-response-length   Get the response length for test\n"
                  "\n"
                  "--set-watch-length      Indicate a length, if response's length not equal this, return\n"
                  "\n"
                  "-R    Use the random source IP address in dos attack (can not use in the guess password attack)\n"
                  "      0    turn off the random source ip address which can protect you true IP in the local net\n"
                  "      1    enable random source ip address (default)\n"
                  "\n"
                  "--ip-repeat-time         If you use the -R, indicate the each random ip repeat send times(default 1024)\n"
                  "\n"
                  "--test-guess               Test the syn flood attack module\n"
                  "\n"
                  "--test-syn               Test the syn flood attack module\n"
                  "\n"
                  "";

    printf("%s", usage);
}