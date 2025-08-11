// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server;
@safe:

import soulfind.defines : default_db_filename, exit_message, log_db, log_msg,
                          log_user, VERSION;
import soulfind.server.server : Server;
import std.array : appender;
import std.compiler : name, version_major, version_minor;
import std.getopt : config, defaultGetoptFormatter, getopt, GetoptResult;
import std.stdio : write, writefln, writeln;
import std.string : format;
import std.system : os;

@trusted
GetoptResult parse_args(ref string[] args, ref string db_filename,
                        ref ushort port, ref bool enable_debug,
                        ref bool show_version)
{
    return getopt(
        args,
        config.passThrough,
        "d|database", format!("Path to database (default: %s).")(db_filename),
                      &db_filename,
        "p|port", "Listening port.", &port,
        "debug", "Enable debug logging.", &enable_debug,
        "v|version", "Show version.", &show_version
    );
}

int run(string[] args)
{
    GetoptResult result;
    string db_filename = default_db_filename;
    ushort port;
    bool enable_debug;
    bool show_version;

    try {
        result = parse_args(
            args, db_filename, port, enable_debug, show_version
        );
    }
    catch (Exception e) {
        writeln(e.msg);
        return 1;
    }

    if (result.helpWanted) {
        auto output = appender!string;
        output.defaultGetoptFormatter(
            format!("Usage: %s [options]")(args[0]), result.options
        );
        write(output[]);
        return 0;
    }

    if (args.length > 1) {
        writeln("Unrecognized option ", args[1]);
        return 1;
    }

    if (show_version) {
        writefln(
            "Soulfind %s"
          ~ "\nCompiled with %s %s.%s for %s",
            VERSION, name, version_major, version_minor, os
        );
        return 0;
    }

    if (enable_debug) log_db = log_msg = log_user = true;

    scope server = new Server(db_filename, port);
    const exit_code = server.listen();

    writefln!("\n%s")(exit_message);
    return exit_code;
}