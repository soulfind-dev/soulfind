// SPDX-FileCopyrightText: 2024 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server.pm;
@safe:

import soulfind.defines;
import std.datetime : Clock;

class PM
{
    // Static

    private static PM[uint] pm_list;

    static void add_pm(PM pm)
    {
        pm_list[pm.id] = pm;
    }

    static void del_pm(uint id)
    {
        if (find_pm(id))
            pm_list.remove(id);
    }

    static PM[] get_pms_for(string user)
    {
        PM[] pms;
        foreach (pm ; pm_list) if (pm.to == user) pms ~= pm;
        return pms;
    }

    private static bool find_pm(uint id)
    {
        return(id in pm_list) ? true : false;
    }

    private static PM get_pm(uint id)
    {
        if (!find_pm(id))
            return null;

        return pm_list[id];
    }

    private static uint new_id()
    {
        uint id = cast(uint) pm_list.length;
        while (find_pm(id)) id++;
        return id;
    }


    // Attributes

    uint    id;
    ulong   timestamp;    // in seconds since 01/01/1970

    string  from;
    string  to;

    string  content;


    // Constructor

    this(string content, string from, string to)
    {
        this.id         = PM.new_id();
        this.from       = from;
        this.to         = to;
        this.content    = content;

        this.timestamp  = Clock.currTime.toUnixTime;
    }
}
