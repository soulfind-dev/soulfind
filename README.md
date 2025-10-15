<!--  
  SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors  
  SPDX-FileCopyrightText: 2005 SeeSchloss  
  SPDX-License-Identifier: GPL-3.0-or-later  
-->

# ❤️ Soulfind

Soulseek server implementation in D

Note that Soulfind exists for local testing, and should not be used in
production.


## Download

### Binaries

The [Releases](https://github.com/soulfind-dev/soulfind/releases) page contains
precompiled binaries for Linux, Windows and macOS. This includes the server
itself, `soulfind`, as well as the CLI server management tool, `soulsetup`.

### Container Image

If you prefer using containers, an image is available in the GitHub Container
Registry. Start by pulling the image:

```
docker pull ghcr.io/soulfind-dev/soulfind
```

Finally, create and run the container:

```
docker run -d --name soulfind -v soulfind-data:/data -p 2242:2242 ghcr.io/soulfind-dev/soulfind
```

You can run the `soulsetup` server management tool separately:

```
docker run -it -v soulfind-data:/data --rm ghcr.io/soulfind-dev/soulfind soulsetup
```

> [!IMPORTANT]
> If you change the listening port with `soulsetup`, recreate the container
> using the `docker run` command, substituting `2242` with the new port.
> Remember to remove the existing container first.


## Building

[BUILDING.md](BUILDING.md) contains instructions on how to compile Soulfind
from source.


## Configuration

Soulfind stores all its configuration in a SQLite database, and looks for the
file `soulfind.db` by default, unless provided a different path as a
`--database` argument.

Server owners can configure the server and add admins using the `soulsetup`
CLI server management tool.

Admins can interact with the server from a Soulseek client, by sending commands
to the `server` user in a private chat (`help` to see all commands).

### Default Configuration

 - port: `2242`
 - max_users: `65535`
 - private_mode: `false`
 - motd: `Soulfind <version>`


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
