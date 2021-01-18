# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- no.

## [1.01]

### Changed

-  Rewirte all code.

### Removed

- ack reflect module.
- brute force module.
- http method.

## [1.00]

### Added

- ACK reflect dos attack module.
- DNS reflect dos attack module.
- Test module.

### Changed

- log.c => logger.c.
- Many function in debug.c like DisplayInfo() => InfoMessage(), DisplayError => ErrorMessage().
- Rewrite the base64.c main function add test.
- Rewrite the https.c main function add test.
- str.c => tools.c.
- base64.c => crypto.c
- guess.c => brute_force_attack.c

### Removed

- multi process support (only multi thread support now).
- others.c


## [0.30] - 2019-3-26

### Added

- UDP flood attack module.
- Auto test function in test.c and test.h file.

### Changed

- Reorganize the file structure.
- Return the NULL as failed, and return something as success.
- Return 0 as success, return 1 as failed.
- Add src folder.
- Add attack_module.
- Add core_module.
- Move router to attack_module folder.
- Change Makefile.
- Change the EACH_IP_REPEAT_TIME from 1024 to 10240 (make it better)

### Removed

- tool folder.
- attack folder.

## [0.20] - 2019-2-14

### Added

- Start rewrite the whole code.
- "tool/base64.c" which used to decode and encode string with base64.
- "tool/https.c" which used to connect web as http method.
- "tool/str.c" which used to handle functions related to strings.
- "CHANGLOG.md" which show the change log of code.
- "tool/version.h" which store the program current version.

### Changed

- Rewrite "debug.c" funcion, add DisplayDebug, DisplayInfo, DisplayError, DisplayWarning function.
- Start using "syn_flood_dos.c" over "ahttp.c".
- Start using "guess.c" over "exploit.c".
- Rewrite "main.c", "guess.c", "syn_flood_dos.c".
- Rewrite "Makefile".
- Rewrite the "README.md" file.


## 0.10 - 2017-11-28

### Added

- Can work good at my company's network.

[Unreleased]: https://github.com/rikonaka/Dos-Tool/compare/v0.30...HEAD
[0.30]: https://github.com/rikonaka/Dos-Tool/compare/v0.20...v0.30
[0.20]: https://github.com/rikonaka/Dos-Tool/compare/v0.10...v0.20
