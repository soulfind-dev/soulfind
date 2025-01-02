// SPDX-FileCopyrightText: 2024 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server;
@safe:

import soulfind.defines : default_db_filename;
import soulfind.server.server : Server;
import std.stdio : writefln;

int run(string[] args)
{
    bool daemon;
    string db_filename = default_db_filename;

    if (args.length > 3) help(args);

    foreach (arg ; args[1 .. $]) {
        switch (arg) {
            case "-h":
            case "--help":
                help(args);
                return 0;
            case "-d":
            case "--daemon":
                daemon = true;
                break;
            default:
                db_filename = arg;
                break;
        }
    }

    version (Posix) {
        import core.sys.posix.unistd : fork;

        if (daemon && fork())
            return 0;
    }

    auto server = new Server(db_filename);
    return server.listen();
}

private void help(string[] args)
{
    auto output = "Usage: %s [database_file]";
    version (Posix) output ~= " [-d|--daemon]";
    output ~= "\n\tdatabase_file: path to the sqlite3 database (default: %s)";
    version (Posix) output ~= "\n\t-d, --daemon : fork in the background";

    writefln(output, args[0], default_db_filename);
}