// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.defines;
@safe:

import std.datetime : minutes, seconds;
import std.string : join, split;

// Constants

enum RoomType : int
{
    any           = -2,
    non_existent  = -1,
    _public       = 0,
    _private      = 1
}

enum RoomMemberType : int
{
    any           = -2,
    non_existent  = -1,
    normal        = 0,
    operator      = 1
}

enum SearchFilterType : uint
{
    server  = 0,
    client  = 1
}

enum VERSION                     = __DATE__.split.join("-");
enum default_db_filename         = "soulfind.db";
enum default_port                = 2242;
enum default_max_users           = 65535;
enum default_private_mode        = false;
enum default_motd                = "Soulfind %sversion%";
enum login_timeout               = 1.minutes;
enum kick_duration               = 2.minutes;
enum user_check_interval         = 15.seconds;
enum wish_interval               = 12.minutes;
enum wish_interval_privileged    = 2.minutes;
enum conn_backlog_length         = 512;
enum max_msg_size                = 16384;
enum max_chat_message_length     = 2048;
enum max_interest_length         = 64;
enum max_room_name_length        = 24;
enum max_room_ticker_length      = 1024;
enum max_search_query_length     = 256;
enum max_username_length         = 30;
enum max_global_recommendations  = 200;
enum max_user_recommendations    = 100;
enum max_user_interests          = 30;
enum max_room_tickers            = 200;
enum speed_weight                = 50;
enum pbkdf2_iterations           = 100000;
enum server_username             = "server";
enum exit_message                = "A la prochaine...";


// Terminal Colors

enum norm                        = "\033[0m";        // reset to normal
enum bold                        = "\033[1m";        // bold intensity
enum blue                        = "\033[01;94m";    // foreground blue
enum red                         = "\033[01;91m";    // foreground red


// Logging

bool log_db;
bool log_msg;
bool log_user;
