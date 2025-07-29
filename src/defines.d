// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.defines;
@safe:

import core.time : minutes;

// Constants

const VERSION                  = "0.5.0-dev";
const default_db_filename      = "soulfind.db";
const default_port             = 2242;
const default_max_users        = 65535;
const login_timeout            = 1.minutes;
const kick_duration            = 2.minutes;
const wish_interval            = 12.minutes;
const wish_interval_privileged = 2.minutes;
const max_msg_size             = 16384;
const max_chat_message_length  = 2048;
const max_interest_length      = 64;
const max_room_name_length     = 24;
const max_room_ticker_length   = 1024;
const max_search_query_length  = 256;
const max_username_length      = 30;
const max_room_tickers         = 200;
const speed_weight             = 50;
const server_username          = "server";
const exit_message             = "A la prochaine...";


// Terminal Colors

const norm                     = "\033[0m";        // reset to normal
const bold                     = "\033[1m";        // bold intensity
const blue                     = "\033[01;94m";    // foreground blue
const red                      = "\033[01;91m";    // foreground red
