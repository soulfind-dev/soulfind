// SPDX-FileCopyrightText: 2025 Soulfind Contributors
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.cli;
@safe:

import soulfind.defines : VERSION;
import std.array : Appender;
import std.compiler : name, version_major, version_minor;
import std.conv : text;
import std.getopt : Option;
import std.stdio : write, writeln;
import std.string : leftJustifier;
import std.system : os;

void print_help(string description, Option[] options)
{
    Appender!string output;
    size_t short_max;
    size_t long_max;

    output ~= description;
    output ~= "\n";

    foreach (item; options) {
        if (item.optShort.length > short_max) short_max = item.optShort.length;
        if (item.optLong.length > long_max)   long_max  = item.optLong.length;
    }
    foreach (item; options) {
        output ~= text(
            item.optShort.leftJustifier(short_max + 2),
            item.optLong.leftJustifier(long_max + 2),
            item.help, "\n"
        );
    }
    write(output[]);
}

void print_version()
{
    writeln(
        "Soulfind ", VERSION, "\nCompiled with ", name, " ", version_major,
        ".", version_minor, " for ", os
    );
}
