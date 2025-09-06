<!--
  SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
  SPDX-FileCopyrightText: 2005 SeeSchloss <seeschloss@seeschloss.org>
  SPDX-License-Identifier: GPL-3.0-or-later
-->

# Soulfind

Soulseek server implementation in D

Note that Soulfind exists for local testing, and should not be used in
production.


## Download

The [Releases](https://github.com/soulfind-dev/soulfind/releases) page contains
precompiled builds for Linux, Windows and macOS.


## Building

[BUILDING.md](BUILDING.md) contains instructions on how to compile Soulfind
from source.


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
