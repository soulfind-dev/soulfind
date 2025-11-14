// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.setup;
@safe:

import soulfind.cli : CommandOption, parse_args, print_help, print_version;
import soulfind.defines : default_db_filename, exit_message;
import soulfind.setup.setup : Setup;
import std.conv : text;
import std.stdio : writeln;

int run(string[] args)
{
    string  db_filename = default_db_filename;
    string  db_backup_filename;
    bool    show_version;
    bool    show_help;

    auto options = [
        CommandOption(
            "d", "database", text(
                "Database path (default: ", default_db_filename, ")."
            ), "path",
            (value) { db_filename = value; }
        ),
        CommandOption(
            "b", "backup", text(
                "Back up database to file path."
            ), "path",
            (value) { db_backup_filename = value; }
        ),
        CommandOption(
            "v", "version", "Show version.", null,
            (_) { show_version = true; }
        ),
        CommandOption(
            "h", "help", "Show this help message.", null,
            (_) { show_help = true; }
        )
    ];
    try {
        parse_args(args, options);
    }
    catch (Exception e) {
        writeln(e.msg);
        return 1;
    }

    if (show_version) {
        print_version();
        return 0;
    }

    if (show_help) {
        print_help("Soulfind server management tool", options);
        return 0;
    }

    int exit_code;
    auto setup = new Setup(db_filename);

    if (db_backup_filename !is null) {
        const success = setup.backup_db(db_backup_filename);
        exit_code = success ? 0 : 1;
        return exit_code;
    }

    setup.show();

    writeln("\n", exit_message);
    return exit_code;
}
