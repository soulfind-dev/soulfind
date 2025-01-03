// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.main;
@safe:

import soulfind.defines : exit_message;
import std.stdio : writefln;

version (Have_soulfind_server) import soulfind.server : run;
version (Have_soulfind_setup)  import soulfind.setup : run;

private extern(C) void handle_termination(int) {
    writefln!("\n%s")(exit_message);
}

@trusted
private void set_console_code_page()
{
    version (Windows) {
        import core.sys.windows.wincon : SetConsoleOutputCP;
        SetConsoleOutputCP(6_5001);  // UTF-8
    }
}

@trusted
private void setup_signal_handler()
{
    version (Posix) {
        import core.sys.posix.signal : sigaction, sigaction_t, SIGINT, SIGTERM;
        import core.sys.posix.unistd : fork;

        sigaction_t act;
        act.sa_handler = &handle_termination;

        sigaction(SIGINT, &act, null);
        sigaction(SIGTERM, &act, null);
    }
}

private int main(string[] args)
{
    set_console_code_page();
    setup_signal_handler();

    return run(args);
}
