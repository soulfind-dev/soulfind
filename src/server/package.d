// SPDX-FileCopyrightText: 2024-2026 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server;
@safe:

import soulfind.defines : default_db_filename, exit_message, log_conn, log_db,
                          log_msg, version_message;
import soulfind.server.server : Server;
import std.conv : text;
import std.getopt : defaultGetoptPrinter, getopt, GetoptResult;
import std.stdio : writeln;

string  db_filename = default_db_filename;
ushort  port;
bool    enable_debug;
bool    show_version;

GetoptResult parser(string[] args)
{
    foreach (arg ; args) {
        writeln("arg inputed: ", arg);
    }

    GetoptResult parsed = getopt(
        args,
        "d|database", text(
            "Database path (default: ", default_db_filename, ")."
        ), &db_filename,
        "p|port", "Listening port.", &port,
        "debug", "Enable debug logging.", &enable_debug,
        "v|version", "Show version.", &show_version,
    );

    foreach (arg ; args) {
        writeln("arg ignored: ", arg);
    }

    return parsed;
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
            "Soulseek server implementation in D", parsed.options
        );
        return 0;
    }

    if (enable_debug) log_db = log_conn = log_msg = true;

    auto server = new Server(db_filename);
    const success = server.listen(port);
    const exit_code = success ? 0 : 1;

    writeln("\n", exit_message);
    return exit_code;
}
