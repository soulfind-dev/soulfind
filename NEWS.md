<!--
  SPDX-FileCopyrightText: 2024 Soulfind Contributors
  SPDX-FileCopyrightText: 2005-2006 SeeSchloss <seeschloss@seeschloss.org>
  SPDX-License-Identifier: GPL-3.0-or-later
-->

# News

## 0.5.0-dev (Unstable)

 - Relicenced to GNU General Public License v3.0 or later
 - Validate username and roomname strings as printable ASCII instead of UTF
 - Substantial breaking changes, including a new database schema, may require
   a totally fresh install from time to time. Data loss is to be expected.


## 0.4.8

 - Updated for DMD 0.155
 - Bug fixed : giving privileges to another user changed this user's amount of
   privileges left to the amount given (instead of adding them)
 - Support for server-handled room and buddy searches


## 0.4.6

 - Updated for DMD 0.136


## 0.4.5

 - Needs DMD >= 0.127 or GDC >= 0.14
 - New Makefile.win for building Soulfind under Windows, included sqlite.dll
   and sqlite.lib


## 0.4.3

 - Compiles and runs under windows without modifying code
 - The username used for administrating the server ("server" by default) is
   now reported as always online
 - Support for reloading configuration at runtime ("reload" admin command)
 - Usernames can now be case insensitive (but are case sensitive by default)


## 0.4

 - Now needs GDC >= 0.11
 - Passwords are now /really/ stored as md5sums
 - --deamon switch
 - Detect at startup if database file is writable
 - Soulfind and soulsetup manpages
 - Sending a blank admin command to the server no longer crashes it
 - Detection of forbidden characters in usernames was flawed
 - Forbidden chars are also detected in room names
 - Be little endian even on big endian systems


## 0.3

 - Now needs DMD >= 0.116 (still works with GDC 0.10, the build date just isn't
   recorded)
 - MOTD not compiled in anymore but stored in the DB (can be changed with
   Soulsetup)
 - Database now automatically updated if it uses an old format (no need to
   delete the file and lose everything...)
 - New server message : ServerInfo (code 1789) returns a list of information
   on the server (version, number of total and online users)
 - Added support for banning users from the server either with the server's
   admin functions or with Soulsetup
 - Full support of recommendations
 - Privileges are now updated (instead of being static)
 - Unicode usernames still allowed, but 00-0F and 7F-9F control chars are
   refused, as well as 2000-200F separators and joiners, A0 (non-breaking
   space), and AD (soft hyphen)
 - Name of the server (for administration) can now be changed with Soulsetup
 - Cleaner output, configurable at compile time

