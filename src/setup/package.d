// SPDX-FileCopyrightText: 2024-2026 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.setup;
@safe:

import soulfind.defines : default_db_filename, exit_message, log_db,
                          version_message;
import soulfind.setup.setup : Setup;
import std.conv : text;
import std.getopt : defaultGetoptPrinter, getopt, GetoptResult;
import std.stdio : writeln;

string  db_filename = default_db_filename;
string  db_backup_filename;
bool    enable_debug;
bool    show_version;

GetoptResult parser(string[] args)
{
    return getopt(
        args,
        "database|d", text(
            "Database path (default: ", default_db_filename, ")."
        ), &db_filename,
        "b|backup", "Back up database to file path.", &db_backup_filename,
        "debug", "Enable debug logging.", &enable_debug,
        "v|version", "Show version.", &show_version,
    );
}

int run(string[] args)
{
    GetoptResult parsed;

    try {
        parsed = parser(args);
    }
    catch (Exception e) {
        writeln(e.msg);
        return 1;
    }

    if (show_version) {
        writeln(version_message);
        return 0;
    }

    if (parsed.helpWanted) {
        defaultGetoptPrinter(
            "Soulfind server management tool", parsed.options
        );
        return 0;
    }

    if (enable_debug) log_db = true;

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
