// SPDX-FileCopyrightText: 2025 Soulfind Contributors
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.cli;
@safe:

import soulfind.defines : VERSION;
import std.array : Appender;
import std.compiler : name, version_major, version_minor;
import std.getopt : Option;
import std.stdio : writeln;

void print_help(string description, Option[] options)
{
    char[] spacing(size_t num_chars)
    {
        char[] spacing = new char[num_chars];
        spacing[] = ' ';
        return spacing;
    }

    Appender!string output;
    size_t short_max;
    size_t long_max;

    output ~= description;

    foreach (item; options) {
        if (item.optShort.length > short_max) short_max = item.optShort.length;
        if (item.optLong.length > long_max)   long_max  = item.optLong.length;
    }
    foreach (item; options) {
        output ~= "\n";
        output ~= item.optShort;
        output ~= spacing(short_max - item.optShort.length + 2);
        output ~= item.optLong;
        output ~= spacing(long_max - item.optLong.length + 2);
        output ~= item.help;
    }
    writeln(output[]);
}

void print_version()
{
    writeln(
        "Soulfind ", VERSION, " (compiled with ", name, " ", version_major,
        ".", version_minor, ")"
    );
}
