// SPDX-FileCopyrightText: 2024 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module defines;
@safe:

const VERSION			= "0.5.0-dev";
const default_db_file	= "soulfind.db";
const default_port		= 2242;
const default_max_users	= 65535;
const max_msg_size		= 16384;
const pbkdf2_iterations = 100000;
const server_user		= "server";

// colours
const norm	= "\033[0m";		// reset to normal
const bold	= "\033[1m";		// bold intensity
const bg_w	= "\033[30;107m";	// background white
const blue	= "\033[01;94m";	// foreground blue
const red	= "\033[01;91m";	// foreground red
