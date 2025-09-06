<!--
  SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
  SPDX-FileCopyrightText: 2005 SeeSchloss <seeschloss@seeschloss.org>
  SPDX-License-Identifier: GPL-3.0-or-later
-->

# Building

Soulfind is portable software that compiles on any operating system D supports,
including Linux, Windows, macOS, *BSD and Solaris.


## Dependencies

Ensure the following dependencies are available:
 - `ldc`, `dmd` or `gdc` for compiler
 - `dub` for build system
 - `sqlite3` for database

You can download a compiler for Windows and macOS on [dlang.org](https://dlang.org/download.html).
The dub build system is included. On other systems, use a package manager to
install the dependencies.

On Windows and macOS, the sqlite3 library shipped with the system is used. No
separate sqlite3 installation is necessary.

On other systems, you must additionally install `gcc` for linking.


## Compiling a Binary

To compile Soulfind, run:

```sh
dub build
```

To compile a static binary on supported systems (mainly musl-based Linux
distributions), run:

```sh
dub build --config=static
```

Once compiled, binaries are available in the `bin/` folder.


## Using a Different Compiler

Set the DC environment variable to use a specific compiler:

```sh
DC=ldc2 dub build
```

```sh
DC=dmd dub build
```

```sh
DC=gdc dub build
```
