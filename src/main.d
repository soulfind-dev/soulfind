// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.main;
@safe:

import core.atomic : atomicStore;
import std.stdio : writefln;

version (Have_soulfind_server) import soulfind.server : run;
version (Have_soulfind_setup)  import soulfind.setup : run;

shared bool running = true;

private extern(C) void handle_termination(int) {
    atomicStore(running, false);
}

private extern(Windows) int handle_ctrl(uint) nothrow {
    atomicStore(running, false);
    return true;
}

@trusted
private void increase_fd_limit()
{
    // Increase file descriptor limit for concurrent connections
    version (Posix) {
        import core.sys.posix.sys.resource : getrlimit, rlimit, RLIMIT_NOFILE,
                                             setrlimit;
        rlimit rlim;
        getrlimit(RLIMIT_NOFILE, &rlim);
        rlim.rlim_cur = rlim.rlim_max;
        setrlimit(RLIMIT_NOFILE, &rlim);
    }
}

@trusted
private void set_console_code_page()
{
    version (Windows) {
        import core.sys.windows.wincon : SetConsoleOutputCP;
        SetConsoleOutputCP(65001);  // UTF-8
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
    version (Windows) {
        import core.sys.windows.windows : SetConsoleCtrlHandler;
        SetConsoleCtrlHandler(&handle_ctrl, true);
    }
}

private int main(string[] args)
{
    increase_fd_limit();
    set_console_code_page();
    setup_signal_handler();

    return run(args);
}
