// SPDX-FileCopyrightText: 2024-2026 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.setup;
@safe:

import soulfind.cli : CommandOption, parse_args, print_help, print_version;
import soulfind.defines : default_db_filename, exit_message, log_db;
import soulfind.setup.setup : Setup;
import std.conv : text;
import std.stdio : writeln;
import std.string : join;

static all_log_categories = ["db"];

private void enable_log_category(string category)
{
    switch (category) {
    case "db":
        log_db = true;
        break;

    default:
        writeln(
            "Available log categories: '", all_log_categories.join("' '"), "'"
        );
        throw new Exception("Unknown log category '" ~ category ~ "'");
    }
}

private void enable_log_categories(string[] log_categories)
{
    foreach (category ; log_categories)
        enable_log_category(category);
}

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
            ), "path", null,
            (values) { db_filename = values[0]; }
        ),
        CommandOption(
            "b", "backup", text(
                "Back up database to file path."
            ), "path", null,
            (values) { db_backup_filename = values[0]; }
        ),
        CommandOption(
            "l", "log", "Additional logging.", "categories", ["db"],
            (values) { enable_log_categories(values); }
        ),
        CommandOption(
            "v", "version", "Show version.", null, null,
            (_) { show_version = true; }
        ),
        CommandOption(
            "h", "help", "Show this help message.", null, null,
            (_) { show_help = true; }
        )
    ];

    try {
        parse_args(args, options);
    }
    catch (Exception e) {
        writeln(e.msg);
        return 2;
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
