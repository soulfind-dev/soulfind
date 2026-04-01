// SPDX-FileCopyrightText: 2024-2026 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server;
@safe:

import soulfind.cli : CommandOption, parse_args, print_help, print_version;
import soulfind.defines : bold, default_db_filename, exit_message, log_conn,
                          log_db, log_msg_codes, log_msg_in, log_msg_out,
                          log_msg_rx, log_msg_tx, norm;
import soulfind.server.server : Server;
import std.conv : text, to;
import std.stdio : writeln;
import std.string : isNumeric, join;

static all_log_categories = ["conn", "db", "msg", "r", "rx", "t", "tx", "x"];

private void enable_log_category(string category)
{
    switch (category) {
    case "conn":
        log_conn = true;
        break;

    case "db":
        log_db = true;
        break;

    case "x":
        log_msg_rx = log_msg_tx = true;
        goto case "msg";

    case "msg":
        log_msg_in = log_msg_out = true;
        break;

    case "rx":
        log_msg_rx = true;
        goto case "r";

    case "r":
        log_msg_in = true;
        break;

    case "tx":
        log_msg_tx = true;
        goto case "t";

    case "t":
        log_msg_out = true;
        break;

    default:
        if (isNumeric(category)) {
            uint msg_code = category.to!uint;
            log_msg_codes[msg_code] = true;
            break;
        }
        writeln(
            "Available log categories: '", all_log_categories.join("' '"),
            "' '", uint.min, "..", uint.max, "'"
        );
        throw new Exception("Unknown log category '" ~ category ~ "'");
    }
}

private void enable_log_categories(string[] log_categories)
{
    foreach (category ; log_categories)
        enable_log_category(category);

    if (log_msg_codes.length > 0 && !log_msg_in && !log_msg_out) {
        enable_log_category("r");
        enable_log_category("t");
    }
    if (log_msg_codes.length == 0 && (log_msg_in || log_msg_out)) {
        foreach (code; 1 .. 161) log_msg_codes[code] = true;
        foreach (code; 1001 .. 1004) log_msg_codes[code] = true;
        writeln("[MSG] Logging all ", log_msg_codes.length, " codes",
                " (no message code number filters were specified)");
    }
}

int run(string[] args)
{
    string  db_filename = default_db_filename;
    ushort  port;
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
            "p", "port", "Listening port.", "port", null,
            (values) { port = values[0].to!ushort; }
        ),
        CommandOption(
            "l", "log", "Additional logging.", "categories", ["conn", "db"],
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
        print_help("Soulseek server implementation in D", options);
        return 0;
    }

    auto server = new Server(db_filename);
    const success = server.listen(port);
    const exit_code = success ? 0 : 1;

    writeln("\n", exit_message);
    return exit_code;
}
