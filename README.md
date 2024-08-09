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
 - motd: `Soulfind <version>`

You can edit the database yourself with the sqlite3 utility, but the easiest is
to use `soulsetup` instead. You need to add the first admin yourself, since you
have to be an admin already to add an admin when connected to the server
(though Soulfind runs fine without any admin).

Soulsetup now automatically updates old databases to the new format. Notice
that the default filename has changed from `user.db` in older versions to
`/var/db/soulfind/soulfind.db`.
