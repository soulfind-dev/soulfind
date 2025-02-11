// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.defines;
@safe:

// Constants

const VERSION              = "0.5.0-dev";
const default_db_filename  = "soulfind.db";
const default_port         = 2242;
const default_max_users    = 65535;
const kick_minutes         = 10;
const max_msg_size         = 16384;
const server_username      = "server";
const exit_message         = "A la prochaine...";


// Terminal Colors

const norm                 = "\033[0m";        // reset to normal
const bold                 = "\033[1m";        // bold intensity
const blue                 = "\033[01;94m";    // foreground blue
const red                  = "\033[01;91m";    // foreground red
