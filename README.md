# DoS-Tool

For hacker's tool.

# Install in Debian or Ubuntu series Linux system

```
sudo apt install openssl libssl-dev
```

[Chinese help](https://github.com/rikonaka/SYN-Flood-DoS-Tool/blob/master/README-ZH.md)

# Usage:

We need compile this code first.

## Change target IP

Before we attack, there is something we need change.

First, the IP address.

This IP or URL address is in the line 30 of `exploit.h`.
```
vim exploit.h
```

Just use the target URL replace this `POST_URL` value.

But don't forget the `http://`.

(This code was used to exploited the web server's login
password, the attack features is add recently, so here we
have to add this `http://`, but calm down, this code will
auto separate this IP address from URL)

```
#define POST_URL "http://192.168.20.1:80/login.cgi"
```

If you want to attack the IP address of `192.168.1.1`.

Replace the `POST_URL` with `http://192.168.1.1`.

# Compile

```
make
```

This command will generate a excutable file named 'tool'.

Then, begian you evil attack.

```
./tool -t
```

# Usage

```
Usage : ./tool
      : ./tool -r -d
      -r   Use the random user name(default use the admin as user name)
      -d   Debug mod
      -t   Attack mod(this mod will not guess the correct password)
```

# Advanced usage

If you want to use this code to guess some server's username or password.

Also, you have the edit the `exploit.h` which in line 30.

Then change the line 10:

```
#define POST_MODEL "user=%s&password=%s&Submit=登+陆"
```

Define youself's `POST_MODEL`.

After that, compile this code again and excuted `tool`.

If you want to more, just change this code by you self.
