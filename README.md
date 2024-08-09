# Soulfind

Soulseek server software written in D

Note that Soulfind exists for testing, and should not be used in production.


## Building

To build Soulfind, just type:

```sh
make
```

The Makefile uses LDC by default to build Soulfind. Set the DC environment
variable to `dmd` or `gdc` to use the respective compilers instead:

```sh
DC=dmd make
```

Valid targets are:

 - `all` (default target)
 - `soulfind`
 - `soulsetup`

You'll also need to have the sqlite3 library installed, since it's the database
Soulfind uses to store its configuration and user info.


## Case Sensitivity for Usernames

Case sensitivity can be configured through soulsetup. When in case-insensitive
mode, the case used is the one used at the first connection to the server, for
example: "User" logs in for the first time. He is registered as "User". If he
later connects as "user", he will still be shown as "User".

Case-insensitivity will only work for ASCII characters (not even other
iso-8859-15 characters like é/É, à/À, ô/Ô, etc), this is because of a SQLite
limitation and may change someday, or depend on the version of the SQLite
library used.

It is also not recommended to switch to case-insensitive mode with a database
that already has registered users, since if two username with a different case
and a different password are registered, case-insensitivity will prevent the
most recent one from logging into the server.


## Configuration

Soulfind doesn't use a configuration file anymore. Instead, it stores all its
configuration in the sqlite database. When starting, it will look for the file
`soulfind.db`, and create it with the following tables if it doesn't exist:

 - users
 - admins
 - conf

Only the `conf` table is filled with some default values:

 - port: `2241`
 - max_users: `65535`
 - max_message_size: `16384`
 - max_offline_pms: `15`
 - motd: `Soulfind <version>`

You can edit the database yourself with the sqlite3 utility, but the easiest is
to use `soulsetup` instead. You need to add the first admin yourself, since you
have to be an admin already to add an admin when connected to the server
(though Soulfind runs fine without any admin).

Soulsetup now automatically updates old databases to the new format. Notice
that the default filename has changed from `user.db` in older versions to
`/var/db/soulfind/soulfind.db`.
