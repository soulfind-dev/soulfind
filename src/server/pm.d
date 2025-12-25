// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server.pm;
@safe:

import std.datetime.systime : SysTime;

struct PM
{
    uint     id;
    SysTime  time;
    string   from_username;
    string   to_username;
    string   message;

    int opCmp(ref const PM pm) const
    {
        // Sort by oldest messages first
        return (pm.time < time) - (pm.time > time);
    }
}
