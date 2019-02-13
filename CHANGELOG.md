# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Reorganize the file structure.

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

[Unreleased]: https://github.com/rikonaka/Dos-Tool/compare/v0.20...HEAD
[0.20]: https://github.com/rikonaka/Dos-Tool/compare/v0.10...v0.20
