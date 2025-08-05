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


### Compiling a Binary

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

Soulfind stores all its configuration in a SQLite database. On startup,
Soulfind will look for the file `soulfind.db` by default, unless provided a
different path as a `--database` argument.

The default config values are:

 - port: `2242`
 - max_users: `65535`
 - private_mode: `false`
 - motd: `Soulfind <version>`

Server owners can configure the server and add admins with the `soulsetup`
utility.

Admins can interact with the server by sending commands in a private
chat with the `server` user (`help` to see all commands).


## Runtime Options

### Database File

Use a different path for the database file by providing a `-d` or `--database`
argument:

```
soulfind -d path/to/database.db
```

```
soulsetup -d path/to/database.db
```

### Listening Port

Always enforce a specific listening port by providing a `-p` or `--port`
argument:

```
soulfind -p 1234
```

### Debug Logging

Enable detailed debug logging by providing the `--debug` flag:

```
soulfind --debug
```


## Missing Features

 - Rate limits
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
