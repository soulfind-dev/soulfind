// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server;
@safe:

import soulfind.cli : print_help, print_version;
import soulfind.defines : default_db_filename, exit_message, log_db, log_msg,
                          log_user;
import soulfind.server.server : Server;
import std.conv : text;
import std.getopt : getopt, GetoptResult;
import std.stdio : writeln;

private string  db_filename = default_db_filename;
private ushort  port;
private bool    enable_debug;
private bool    show_version;

int run(string[] args)
{
    GetoptResult result;
    try {
        result = getopt(
            args,
            "d|database", text(
                "Database path (default: ", default_db_filename, ")."
            ),                                     &db_filename,
            "p|port",     "Listening port.",       &port,
            "debug",      "Enable debug logging.", &enable_debug,
            "v|version",  "Show version.",         &show_version
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
        print_help("Soulseek server implementation in D", result.options);
        return 0;
    }

    if (enable_debug) log_db = log_msg = log_user = true;

    auto server = new Server(db_filename, port);
    const exit_code = server.listen();

    writeln("\n", exit_message);
    return exit_code;
}