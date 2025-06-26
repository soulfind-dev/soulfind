// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.setup;
@safe:

import soulfind.db : Sdb;
import soulfind.defines : default_db_filename, default_max_users, default_port,
                          VERSION;
import soulfind.setup.setup : Setup;
import std.conv : ConvException, to;
import std.datetime : Clock;
import std.exception : ifThrown;
import std.format : format;
import std.stdio : readf, readln, StdioException, write, writefln, writeln;
import std.string : chomp, strip;

Sdb sdb;

int run(string[] args)
{
    string db_filename = default_db_filename;

    if (args.length > 1) {
        if (args[1] == "--help" || args[1] == "-h") {
            writefln!("Usage: %s [database_file]")(args[0]);
            writefln!(
                "\tdatabase_file: path to Soulfind's database (default: %s)")(
                default_db_filename
            );
            return 0;
        }
        db_filename = args[1];
    }


    auto setup = new Setup(db_filename);
    setup.show();
    return 0;
}
