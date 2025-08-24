// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.setup;
@safe:

import soulfind.cli : print_help, print_version;
import soulfind.defines : default_db_filename, exit_message;
import soulfind.setup.setup : Setup;
import std.array : Appender;
import std.conv : text;
import std.getopt : getopt, GetoptResult;
import std.stdio : writeln;

private string  db_filename = default_db_filename;
private bool    show_version;

int run(string[] args)
{
    GetoptResult result;
    try {
        result = getopt(
            args,
            "d|database", text(
                "Database path (default: ", default_db_filename, ")."
            ),                             &db_filename,
            "v|version",  "Show version.", &show_version
        );
    }
    catch (Exception e) {
        writeln(e.msg);
        return 1;
    }

    if (show_version) {
        print_version();
        return 0;
    }

    if (result.helpWanted) {
        print_help("Soulfind server management tool", result.options);
        return 0;
    }

    auto setup = new Setup(db_filename);
    const exit_code = setup.show();

    writeln("\n", exit_message);
    return exit_code;
}
