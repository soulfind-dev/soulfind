// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server.pm;
@safe:

import std.datetime : SysTime;

struct PM
{
    uint     id;
    SysTime  time;
    string   from_username;
    string   to_username;
    string   message;
}
