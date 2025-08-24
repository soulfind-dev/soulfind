// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.main;
@safe:

bool running = true;

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
private void setup_console()
{
    version (Windows) {
        import core.sys.windows.winbase: GetStdHandle, STD_OUTPUT_HANDLE;
        import core.sys.windows.wincon: ENABLE_VIRTUAL_TERMINAL_PROCESSING,
                                        GetConsoleMode, SetConsoleMode,
                                        SetConsoleOutputCP;

        // Enable UTF-8
        SetConsoleOutputCP(65001);

        // Enable ANSI colors
        uint mode;
        auto handle = GetStdHandle(STD_OUTPUT_HANDLE);
        GetConsoleMode(handle, &mode);
        mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(handle, mode);
    }
}

@trusted
private void setup_signal_handler()
{
    version (Posix) {
        import core.sys.posix.signal : sigaction, sigaction_t, SIGINT, SIGTERM;
        import core.sys.posix.unistd : fork;

        extern(C) void handle_termination(int) {
            running = false;
        }

        sigaction_t act;
        act.sa_handler = &handle_termination;

        sigaction(SIGINT, &act, null);
        sigaction(SIGTERM, &act, null);
    }
    version (Windows) {
        import core.sys.windows.windows : SetConsoleCtrlHandler;

        extern(Windows) int handle_ctrl(uint) nothrow {
            running = false;
            return true;
        }
        SetConsoleCtrlHandler(&handle_ctrl, true);
    }
}

private int main(string[] args)
{
    version (Have_soulfind_server) import soulfind.server : run;
    version (Have_soulfind_setup)  import soulfind.setup  : run;

    increase_fd_limit();
    setup_console();
    setup_signal_handler();

    return run(args);
}
