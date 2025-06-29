<!--
  SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
  SPDX-FileCopyrightText: 2005 SeeSchloss <seeschloss@seeschloss.org>
  SPDX-License-Identifier: GPL-3.0-or-later
-->

# Soulfind

Soulseek server implementation in D

Note that Soulfind exists for local testing, and should not be used in
production.


## Building

### Dependencies

Ensure the following dependencies are installed:
 - `ldc`, `dmd` or `gdc` for compiler
 - `dub` for build system
 - `sqlite3` for database

You can download a compiler for Windows and macOS on [dlang.org](https://dlang.org/download.html).
The dub build system is included. On other systems, use a package manager to
install the dependencies.

On Windows, you must [install the Windows SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/)
in order to use the system bindings for sqlite3. On macOS, no action is
required to use them.

On other systems, you must additionally install `gcc` for linking.


### Compiling a Binary

To compile Soulfind, run:

```sh
dub build
```

To compile Soulfind with debug logging enabled:

```sh
dub build --debug=db --debug=msg --debug=user
```

To compile a static binary on supported systems (mainly musl-based Linux
distributions), run:

```sh
dub build --config=static
```

Once compiled, binaries are available in the `bin/` folder.


### Using a Different Compiler

LDC is used as the default D compiler. Set the DC environment variable to use
a different compiler:

```sh
DC=dmd dub build
```

```sh
DC=gdc dub build
```


## Configuration

Soulfind stores all its configuration in a SQLite database. When starting, it
will look for the file `soulfind.db`, and create it with the following tables
if it doesn't exist:

 - users
 - admins
 - config

Only the `config` table is filled with some default values:

 - port: `2242`
 - max_users: `65535`
 - motd: `Soulfind <version>`

Server owners can configure the server and add admins with the `soulsetup`
utility.

Admins can interact with the server by sending commands in a private
chat with the server user (`help` to see all commands).


## Missing Features

 - Anti-spam measures
 - Private rooms
 - Distributed search network


## Authors

Soulfind is free and open source software, released under the terms of the
[GNU General Public License v3.0 or later](https://www.gnu.org/licenses/gpl-3.0-standalone.html).

People who have contributed to Soulfind:

 - seeschloss (creator)
 - mathiascode
 - slook

© 2005–2025 Soulfind Contributors
