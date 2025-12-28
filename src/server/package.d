// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server;
@safe:

import soulfind.cli : CommandOption, parse_args, print_help, print_version;
import soulfind.defines : default_db_filename, exit_message, log_conn, log_db,
                          log_msg;
import soulfind.server.server : Server;
import std.conv : text, to;
import std.stdio : writeln;

int run(string[] args)
{
    string  db_filename = default_db_filename;
    ushort  port;
    bool    enable_debug;
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
            "p", "port", "Listening port.", "port",
            (value) { port = value.to!ushort; }
        ),
        CommandOption(
            "", "debug", "Enable debug logging.", null,
            (_) { enable_debug = true; }
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
        print_help("Soulseek server implementation in D", options);
        return 0;
    }

    if (enable_debug) log_db = log_conn = log_msg = true;

    auto server = new Server(db_filename);
    const success = server.listen(port);
    const exit_code = success ? 0 : 1;

    writeln("\n", exit_message);
    return exit_code;
}
