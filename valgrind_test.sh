#!/bin/bash
# please install the valgrind and run this script as root

valgrind --leak-check=full \
         --show-leak-kinds=all \
         --track-origins=yes \
         --verbose \
         --log-file=valgrind-out-a1.txt \
         ./debug-dos-tool-linux -u 127.0.0.1 -p 80 -a 1

valgrind --leak-check=full \
         --show-leak-kinds=all \
         --track-origins=yes \
         --verbose \
         --log-file=valgrind-out-a2.txt \
         ./debug-dos-tool-linux -u 127.0.0.1 -p 80 -a 2

valgrind --leak-check=full \
         --show-leak-kinds=all \
         --track-origins=yes \
         --verbose \
         --log-file=valgrind-out-a3.txt \
         ./debug-dos-tool-linux -u 127.0.0.1 -p 80 -a 3

valgrind --leak-check=full \
         --show-leak-kinds=all \
         --track-origins=yes \
         --verbose \
         --log-file=valgrind-out-a4.txt \
         ./debug-dos-tool-linux -u 127.0.0.1 -p 80 -a 4

valgrind --leak-check=full \
         --show-leak-kinds=all \
         --track-origins=yes \
         --verbose \
         --log-file=valgrind-out-a51.txt \
         ./debug-dos-tool-linux -u 192.168.1.1 -p 80 -a 5 --request http_request.txt

valgrind --leak-check=full \
         --show-leak-kinds=all \
         --track-origins=yes \
         --verbose \
         --log-file=valgrind-out-a52.txt \
         ./debug-dos-tool-linux -u www.baidu.com -p 443 -a 5 --https --request https_request.txt
