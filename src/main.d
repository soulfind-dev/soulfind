// SPDX-FileCopyrightText: 2024 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module main;
@safe:

import core.sys.posix.signal : sigaction, sigaction_t, SIGINT, SIGTERM;
import core.sys.posix.unistd : fork;
import defines;
import std.stdio : writefln;

version (Have_soulfind_server) import server : run;
version (Have_soulfind_setup) import setup : run;

private extern(C) void handle_termination(int) {
	writefln("\n" ~ exit_message);
}

@trusted
private void setup_signal_handler()
{
	sigaction_t act;
	act.sa_handler = &handle_termination;

	sigaction(SIGINT, &act, null);
	sigaction(SIGTERM, &act, null);
}

private int main(string[] args)
{
	setup_signal_handler();
	return run(args);
}
