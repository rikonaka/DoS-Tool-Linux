# Dos-Tool

## Intro

[Dos-Tool-Linux](https://github.com/rikonaka/DoS-Tool-Linux) is used DoS attack make computer offline, the DoS method also could attack website.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Current version: 1.0.2 | [Changelog](CHANGELOG.md)

## Support the legitimate rights and interests of programmers

[![996.icu](https://img.shields.io/badge/link-996.icu-red.svg)](https://996.icu)

[![LICENSE](https://img.shields.io/badge/license-NPL%20(The%20996%20Prohibited%20License)-blue.svg)](https://github.com/996icu/996.ICU/blob/master/LICENSE)

## Features

DoS-Tool-Linux is written in pure C, for the efficient operation of the program and keep the resource usage as low as possible.

## Installation

### Install from source

```bash
sudo apt install make gcc
make
```

## Run

```bash
dos-tool-linux [option]
```

## Note

> Too many open file

To change maximum open file limits for your terminal session, run this command:

```bash
# ulimit -n 3000
```

After closing the terminal and creating a new session, the limits will get back to the original values specified in /etc/security/limits.conf.

To change the general value for the system /proc/sys/fs/file-max, change the fs.file-max value in `/etc/sysctl.conf`:

```bash
fs.file-max = 100000
```
