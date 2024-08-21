<!--
  SPDX-FileCopyrightText: 2024 Soulfind Contributors
  SPDX-FileCopyrightText: 2005 SeeSchloss <seeschloss@seeschloss.org>
  SPDX-License-Identifier: GPL-3.0-or-later
-->

# Soulfind

Soulseek server implementation in D

Note that Soulfind exists for local testing, and should not be used in
production.


## Building

To build Soulfind, just type:

```sh
make
```

The Makefile uses LDC by default to build Soulfind. Set the DC environment
variable to `dmd` to use DMD instead:

```sh
DC=dmd make
```

Valid targets are:

 - `all` (default target)
 - `soulfind`
 - `soulsetup`

You'll also need to have the sqlite3 library installed, since it's the database
Soulfind uses to store its configuration and user info.


## Configuration

Soulfind doesn't use a configuration file anymore. Instead, it stores all its
configuration in the sqlite database. When starting, it will look for the file
`soulfind.db`, and create it with the following tables if it doesn't exist:

 - users
 - admins
 - conf

Only the `conf` table is filled with some default values:

 - port: `2242`
 - max_users: `65535`
 - motd: `Soulfind <version>`

You can edit the database yourself with the sqlite3 utility, but the easiest is
to use `soulsetup` instead. You need to add the first admin yourself, since you
have to be an admin already to add an admin when connected to the server
(though Soulfind runs fine without any admin).


## Missing Features

 - Private rooms
 - Distributed search network


## Authors

Soulfind is free and open source software, released under the terms of the
[GNU General Public License v3.0 or later](https://www.gnu.org/licenses/gpl-3.0-standalone.html).

People who have contributed to Soulfind:

 - seeschloss (creator)
 - mathiascode
 - slook

© 2005–2024 Soulfind Contributors
