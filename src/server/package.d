// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server;
@safe:

import soulfind.cli : CommandOption, parse_args, print_help, print_version;
import soulfind.defines : default_db_filename, exit_message, log_conn, log_db,
                          log_msg_in, log_msg_out;
import soulfind.server.server : Server;
import std.conv : text, to;
import std.stdio : writeln;
import std.string : join, split;

int run(string[] args)
{
    string  db_filename = default_db_filename;
    ushort  port;
    string  log_categories;
    bool    show_version;
    bool    show_help;

    auto options = [
        CommandOption(
            "d", "database", text(
                "Database path (default: ", default_db_filename, ")."
            ), "path", null,
            (value) { db_filename = value; }
        ),
        CommandOption(
            "p", "port", "Listening port.", "port", null,
            (value) { port = value.to!ushort; }
        ),
        CommandOption(
            "l", "log", "Enable additional logging.", "categories", "default",
            (value) { log_categories = value; }
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
    static available_log_categories = [
        "default", "conn", "db", "msg", "msg-in", "msg-out"
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
        print_help("Soulseek server implementation in D", options);
        return 0;
    }

    foreach (category ; log_categories.split!(c => c == ' ' || c == ',')) {
        switch (category) {
        case "default":
            log_conn = log_db = true;
            break;

        case "conn":
            log_conn = true;
            break;

        case "db":
            log_db = true;
            break;

        case "msg":
            log_msg_in = log_msg_out = true;
            break;

        case "msg-in":
            log_msg_in = true;
            break;

        case "msg-out":
            log_msg_out = true;
            break;

        default:
            writeln(
                "Unknown log category ", category, ". Available categories: ",
                available_log_categories.join(", ")
            );
            return 0;
        }
    }

    auto server = new Server(db_filename);
    const success = server.listen(port);
    const exit_code = success ? 0 : 1;

    writeln("\n", exit_message);
    return exit_code;
}
