// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server.cmdhandler;
@safe:

import soulfind.defines : blue, kick_duration, norm, RoomMemberType, RoomType,
                          server_username;
import soulfind.server.messages;
import soulfind.server.room : Room;
import soulfind.server.server : Server;
import soulfind.server.user : User;
import std.array : Appender;
import std.conv : ConvException, text, to;
import std.datetime : Clock, days, Duration, minutes, MonoTime, seconds,
                      SysTime;
import std.stdio : writeln;
import std.string : join, replace, split;

final class CommandHandler
{
    private Server server;


    this(Server server)
    {
        this.server = server;
    }

    void handle_command(string sender_username, string command)
    {
        if (server.db.admin_until(sender_username) > Clock.currTime) {
            admin_command(sender_username, command);
            return;
        }
        user_command(sender_username, command);
    }

    private void user_command(string sender_username, string command)
    {
        const args = command.split(" ");
        if (args.length == 0)
            return;

        switch (args[0]) {
        case "help":
            respond(
                sender_username,
                text(
                    "Available commands:",
                    "\n\nexportdata\n    Export your account data",
                    "\n\ndeleteaccount\n    Delete your account"
                )
            );
            break;

        case "exportdata":
            respond(
                sender_username,
                "Account data in JSON format:\n" ~ user_export(sender_username)
            );
            break;

        case "deleteaccount":
            if (command != text("deleteaccount confirm ", sender_username)) {
                server.send_pm(
                    server_username, sender_username,
                    text(
                        "Type 'deleteaccount confirm ", sender_username,
                        "' to delete your account"
                    )
                );
                break;
            }

            auto user = server.get_user(sender_username);

            server.send_pm(
                server_username, sender_username,
                "Your account has been deleted"
            );

            server.db.del_user(sender_username);
            user.disconnect_deleted();
            break;

        default:
            unknown_command(sender_username, command);
            break;
        }
    }

    private void admin_command(string admin_username, string command)
    {
        const args = command.split(" ");
        if (args.length == 0)
            return;

        switch (args[0]) {
        case "help":
            respond(
                admin_username,
                text(
                    "Available commands:",
                    "\n\nadmins\n    List admins",
                    "\n\nusers [connected|banned|privileged]\n    List users",
                    "\n\nrooms\n    List public rooms",
                    "\n\nexportdata\n    Export your account data",
                    "\n\nuserinfo <user>\n    Show info about user",
                    "\n\nroominfo <room>\n    Show info about public room",
                    "\n\nremovetickers <user>\n    Remove user's public room",
                    " tickers",
                    "\n\nban [days] <user>\n    Ban user",
                    "\n\nunban <user>\n    Unban user",
                    "\n\nkick [minutes] <user>\n    Disconnect user for",
                    " [", kick_duration.total!"minutes", "] minutes",
                    "\n\nkickall [minutes]\n    Disconnect active users for",
                    " [", kick_duration.total!"minutes", "] minutes",
                    "\n\nannouncement <message>\n    Send announcement to",
                    " online users",
                    "\n\nmessage <message>\n    Send private message to all",
                    " registered users",
                    "\n\nuptime\n    Show server uptime"
                )
            );
            break;

        case "admins":
            Appender!string output;
            const names = server.db.usernames(
                "admin", Clock.currTime.toUnixTime
            );
            output ~= text(names.length, " admins.");
            foreach (ref name ; names) {
                const status = (
                    server.get_user(name) !is null
                ) ? "online" : "offline";

                output ~= "\n    ";
                output ~= name;
                output ~= text(" (", status, ")");
            }

            respond(admin_username, output[]);
            break;

        case "users":
            const type = (args.length > 1) ? args[1] : null;
            respond(admin_username, user_list(type));
            break;

        case "rooms":
            Room room;
            Appender!string output;
            const names = server.db.public_rooms;
            output ~= text(names.length, " public rooms.");
            foreach (ref name ; names) {
                ulong num_users;
                room = server.get_room(name);
                if (room !is null) num_users = room.num_users;

                output ~= "\n    ";
                output ~= name;
                output ~= text(
                    " (users: ", num_users, ", tickers: ",
                    server.db.num_room_tickers(name), ")"
                );
            }
            respond(admin_username, output[]);
            break;

        case "exportdata":
            respond(
                admin_username,
                "Account data in JSON format:\n" ~ user_export(admin_username)
            );
            break;

        case "userinfo":
            if (args.length < 2) {
                respond(admin_username, "Syntax is: userinfo <user>");
                break;
            }
            const username = args[1 .. $].join(" ");

            if (!server.db.user_exists(username)) {
                respond(
                    admin_username,
                    text("User ", username, " is not registered")
                );
                break;
            }

            respond(admin_username, user_info(username));
            break;

        case "roominfo":
            if (args.length < 2) {
                respond(admin_username, "Syntax is: roominfo <room>");
                break;
            }
            const name = args[1 .. $].join(" ");

            if (server.db.get_room_type(name) != RoomType._public) {
                respond(
                    admin_username,
                    text("Room ", name, " is not registered")
                );
                break;
            }
            respond(admin_username, room_info(name));
            break;

        case "removetickers":
            if (args.length < 2) {
                respond(admin_username, "Syntax is: removetickers <user>");
                break;
            }
            const username = args[1 .. $].join(" ");
            if (!server.db.user_exists(username)) {
                respond(
                    admin_username,
                    text("User ", username, " is not registered")
                );
                break;
            }
            server.del_user_tickers!(RoomType._public)(username);
            respond(
                admin_username,
                text("Removed user ", username, "'s public room tickers")
            );
            break;

        case "ban":
            if (args.length < 2) {
                respond(admin_username, "Syntax is: ban [days] <user>");
                break;
            }

            Duration duration;
            string username;
            try {
                const value = args[1].to!ulong;
                enum limit = ushort.max;
                duration = (value > limit ? limit : value).days;
                username = args[2 .. $].join(" ");
            }
            catch (ConvException) {
                duration = Duration.max;
                username = args[1 .. $].join(" ");
            }

            if (!server.db.ban_user(username, duration)) {
                respond(
                    admin_username,
                    text("User ", username, " is not registered")
                );
                break;
            }

            server.del_user_pms(username);
            server.del_user_tickers!(RoomType.any)(username);

            auto user = server.get_user(username);
            if (user !is null) user.disconnect();

            string response;
            if (duration == Duration.max)
                response = text("Banned user ", username, " forever");
            else
                response = text(
                    "Banned user ", username, " for ",
                    duration.total!"days".days.toString
                );

            respond(admin_username, response);
            break;

        case "unban":
            if (args.length < 2) {
                respond(admin_username, "Syntax is: unban <user>");
                break;
            }
            const username = args[1 .. $].join(" ");
            server.db.unban_user(username);
            respond(
                admin_username,
                text("Unbanned user ", username)
            );
            break;

        case "kick":
            if (args.length < 2) {
                respond(
                    admin_username,
                    "Syntax is: kick [minutes] <user>"
                );
                break;
            }

            Duration duration;
            string username;
            try {
                const value = args[1].to!ulong;
                enum limit = ushort.max;
                duration = (value > limit ? limit : value).minutes;
                username = args[2 .. $].join(" ");
            }
            catch (ConvException) {
                duration = kick_duration;
                username = args[1 .. $].join(" ");
            }

            auto user = server.get_user(username);
            if (!server.db.ban_user(username, duration) && user is null) {
                respond(
                    admin_username,
                    text("User ", username, " is not registered")
                );
                break;
            }

            if (user !is null) user.disconnect();

            respond(
                admin_username,
                text(
                    "Kicked user ", username, " for ",
                    duration.total!"minutes".minutes.toString
                )
            );
            break;

        case "kickall":
            Duration duration = kick_duration;
            if (args.length > 1) {
                try {
                    const value = args[1].to!ulong;
                    enum limit = ushort.max;
                    duration = (value > limit ? limit : value).minutes;
                }
                catch (ConvException) {
                    respond(admin_username, "Syntax is: kickall [minutes]");
                    break;
                }
            }
            Appender!(User[]) users_to_kick;
            foreach (ref user ; server.connected_users)
                if (user.username != admin_username)
                    users_to_kick ~= user;

            foreach (ref user ; users_to_kick) {
                server.db.ban_user(user.username, duration);
                user.disconnect();
            }

            writeln(
                "Admin ", blue, admin_username, norm, " kicked ALL ",
                users_to_kick[].length, " users for ", duration.toString
            );
            respond(
                admin_username,
                text(
                    "Kicked all ", users_to_kick[].length, " users for ",
                    duration.total!"minutes".minutes.toString
                )
            );
            break;

        case "announcement":
            if (args.length < 2) {
                respond(admin_username, "Syntax is: announcement <message>");
                break;
            }
            const msg = args[1 .. $].join(" ");
            announcement(msg);
            break;

        case "message":
            if (args.length < 2) {
                respond(admin_username, "Syntax is: message <message>");
                break;
            }
            const msg = args[1 .. $].join(" ");
            foreach (ref username ; server.db.usernames)
                respond(username, msg);
            break;

        case "uptime":
            const duration = (MonoTime.currTime - server.started_monotime);
            const response = text(
                "Running for ", duration.total!"seconds".seconds.toString,
                " since ", server.started_at.toSimpleString
            );
            respond(admin_username, response);
            break;

        default:
            unknown_command(admin_username, command);
            break;
        }
    }

    private void respond(string to_username, string message)
    {
        server.send_pm(server_username, to_username, message);
    }

    private void unknown_command(string username, string command)
    {
        respond(
            username,
            text(
                "Unknown command '", command, "'. ",
                "Type 'help' to list available commands."
            )
        );
    }

    private void announcement(string message)
    {
        scope msg = new SAdminMessage(message);
        server.send_to_all(msg);
    }

    private string room_info(string room_name)
    {
        Appender!string output;
        string[] usernames;
        const tickers = server.db.room_tickers(room_name);

        output ~= room_name;
        output ~= text("\nUsers (", usernames.length, "):");

        foreach (ref username ; usernames) {
            output ~= "\n    ";
            output ~= username;
        }

        output ~= text("\nTickers (", tickers.length, "):");

        foreach (ref ticker ; tickers) {
            output ~= text("\n    [", ticker.username, "] ");
            output ~= ticker.content;
        }

        return output[];
    }

    private string user_list(string type = null)
    {
        Appender!string output;
        switch (type) {
        case "connected":
            output ~= text(
                server.num_connected_users, " connected users."
            );
            foreach (ref user ; server.connected_users) {
                output ~= "\n    ";
                output ~= user.username;
                output ~= text(
                    " (client version: ", user.client_version, ")"
                );
            }
            break;

        case "privileged":
            const users = server.db.usernames(
                "privileges", Clock.currTime.toUnixTime
            );
            output ~= text(users.length, " privileged users.");
            foreach (ref user ; users) {
                const privileged_until = server.db.user_privileged_until(user);
                output ~= "\n    ";
                output ~= user;
                output ~= text(
                    " (until ", privileged_until.toSimpleString, ")"
                );
            }
            break;

        case "banned":
            const users = server.db.usernames(
                "banned", Clock.currTime.toUnixTime
            );
            output ~= text(users.length, " banned users.");
            foreach (ref user ; users) {
                output ~= "\n    ";
                output ~= user;

                const banned_until = server.db.user_banned_until(user);
                if (banned_until == SysTime.max)
                    output ~= " (forever)";
                else
                    output ~= text(
                        " (until ", banned_until.toSimpleString, ")"
                    );
            }
            break;

        case null:
            const usernames = server.db.usernames;
            output ~= text(usernames.length, " total users.");
            foreach (ref username ; usernames) {
                output ~= "\n    ";
                output ~= username;
            }
            break;

        default:
            output ~= "Syntax is: users [connected|banned|privileged]";
        }
        return output[];
    }

    private string user_info(string username)
    {
        User user;
        const now = Clock.currTime;
        auto status = "offline";
        auto client_version = "none";
        auto ip_address = "none";
        ushort listening_port;
        ushort obfuscated_port;
        auto obfuscation_type = "none";
        auto accept_room_invitations = "no";
        size_t watched_users;
        string liked_items, hated_items;
        string joined_rooms;
        auto joined_global_room = "no";
        auto admin = "no";
        auto banned = "no";
        auto privileged = "no";
        SysTime privileged_until;
        auto supporter = "no";
        auto searchable = "yes";
        uint upload_speed;
        uint shared_files, shared_folders;
        const tickers = server.db.user_tickers!(RoomType._public)(username);

        user = server.get_user(username);
        if (user !is null) {
            status = (user.status == UserStatus.away) ? "away" : "online";
            client_version = user.client_version;
            ip_address = user.address.toAddrString;
            listening_port = user.address.port;
            obfuscated_port = user.obfuscated_port;
            if (user.accept_room_invitations) accept_room_invitations = "yes";
            watched_users = user.num_watched_users;
            liked_items = user.liked_item_names.join(", ");
            hated_items = user.hated_item_names.join(", ");
            joined_rooms = user.joined_room_names!(RoomType._public)
                .join(", ");

            if (server.is_global_room_joined(username))
                joined_global_room = "yes";

            privileged_until = user.privileged_until;
            if (user.supporter) supporter = "yes";
            upload_speed = user.upload_speed;
            shared_files = user.shared_files;
            shared_folders = user.shared_folders;

            if (user.obfuscation_type == ObfuscationType.rotated)
                obfuscation_type = "rotated";

            else if (user.obfuscation_type != ObfuscationType.none)
                obfuscation_type = text(cast(uint) user.obfuscation_type);
        }
        else {
            const user_stats = server.db.user_stats(username);
            privileged_until = server.db.user_privileged_until(username);
            if (privileged_until > SysTime()) supporter = "yes";
            upload_speed = user_stats.upload_speed;
            shared_files = user_stats.shared_files;
            shared_folders = user_stats.shared_folders;
        }

        const admin_until = server.db.admin_until(username);
        if (admin_until > now)
            admin = text("until ", admin_until.toSimpleString);

        const banned_until = server.db.user_banned_until(username);
        if (banned_until == SysTime.max)
            banned = "forever";

        else if (banned_until > now)
            banned = text("until ", banned_until.toSimpleString);

        if (privileged_until > now)
            privileged = text("until ", privileged_until.toSimpleString);

        if (server.db.is_user_unsearchable(username))
            searchable = "no";

        Appender!string output;
        output ~= text(
            username,
            "\n",
            "\nSession info:",
            "\n    status: ", status,
            "\n    client version: ", client_version,
            "\n    IP address: ", ip_address,
            "\n    port: ", listening_port,
            "\n    obfuscated port: ", obfuscated_port,
            "\n    obfuscation type: ", obfuscation_type,
            "\n    accepts room invitations: ", accept_room_invitations,
            "\n    watched users: ", watched_users,
            "\n    liked items: ", liked_items,
            "\n    hated items: ", hated_items,
            "\n    joined public rooms: ", joined_rooms,
            "\n    joined global room: ", joined_global_room,
            "\n",
            "\nPresistent info:",
            "\n    admin: ", admin,
            "\n    banned: ", banned,
            "\n    privileged: ", privileged,
            "\n    supporter: ", supporter,
            "\n    searchable: ", searchable,
            "\n    upload speed: ", upload_speed,
            "\n    files: ", shared_files,
            "\n    folders: ", shared_folders,
            "\n    public tickers: ",
        );

        if (tickers.length > 0) {
            foreach (ticker ; tickers)
                output ~= text(
                    "\n        [", ticker.room_name, "] ", ticker.content
                );
        }

        return output[];
    }

    private string user_export(string username)
    {
        enum quot = "\"";
        enum d_quot = "\"\"";
        enum j_quot = "\", \"";

        auto user = server.get_user(username);
        const status = (user.status == UserStatus.away) ? "away" : "online";

        const admin_until = server.db.admin_until(username);
        auto admin = (admin_until > SysTime())
            ? text(quot, admin_until.toISOExtString, quot)
            : "null";

        const privileged_until = user.privileged_until;
        auto privileged = (privileged_until > SysTime())
            ? text(quot, privileged_until.toISOExtString, quot)
            : "null";

        const accept_invitations = (
            user.accept_room_invitations ? "true" : "false"
        );
        const joined_global_room = (
            server.is_global_room_joined(username) ? "true" : "false"
        );
        const supporter = user.supporter ? "true" : "false";
        const searchable = (
            server.is_user_unsearchable(username) ? "false" : "true"
        );

        const liked_items = text(
            quot, user.liked_item_names.join(j_quot), quot
        ).replace(d_quot, "");

        const hated_items = text(
            quot, user.hated_item_names.join(j_quot), quot
        ).replace(d_quot, "");

        const joined_rooms = text(
            quot, user.joined_room_names!(RoomType.any).join(j_quot), quot
        ).replace(d_quot, "");

        const watched_users = text(
            quot, user.watched_usernames.join(j_quot), quot
        ).replace(d_quot, "");

        auto obfuscation_type = "null";
        if (user.obfuscation_type == ObfuscationType.rotated)
            obfuscation_type = text(quot, "rotated", quot);

        else if (user.obfuscation_type != ObfuscationType.none)
            obfuscation_type = text(
                quot, cast(uint) user.obfuscation_type, quot
            );

        string rooms(bool is_owner = true) {
            Appender!string output;
            const rooms = is_owner
                ? server.db.owned_rooms(username)
                : server.db.member_rooms!(RoomMemberType.any)(username);

            if (rooms.length == 0)
                return output[];

            auto first = true;
            foreach (ref room_name ; rooms) {
                const owner = server.db.get_room_owner(room_name);
                const members = text(
                    quot,
                    server.db.room_members!(RoomMemberType.any)(room_name)
                    .join(j_quot), quot
                ).replace(d_quot, "");

                const operators = text(
                    quot,
                    server.db.room_members!(RoomMemberType.operator)(room_name)
                    .join(j_quot), quot
                ).replace(d_quot, "");

                if (!first) output ~= ",";
                output ~= text(
                    "\n            {",
                    "\n                \"room_name\": \"", room_name, "\",",
                    "\n                \"owner\": \"", owner, "\",",
                    "\n                \"members\": [", members, "],",
                    "\n                \"operators\": [", operators, "]",
                    "\n            }"
                );
                first = false;
            }
            output ~= "\n        ";
            return output[];
        }

        string tickers() {
            Appender!string output;
            const tickers = server.db.user_tickers!(RoomType.any)(username);
            if (tickers.length == 0)
                return output[];

            auto first = true;
            foreach (ticker ; tickers) {
                const name = ticker.room_name;
                const content = ticker.content;

                if (!first) output ~= ",";
                output ~= text(
                    "\n            {",
                    "\n                \"room_name\": \"", name, "\",",
                    "\n                \"content\": \"", content, "\"",
                    "\n            }"
                );
                first = false;
            }
            output ~= "\n        ";
            return output[];
        }

        string pms() {
            Appender!string output;
            const pms = server.get_queued_pms(username);
            if (pms.length == 0)
                return output[];

            auto first = true;
            foreach (pm ; pms) {
                const id = pm.id;
                const to_username = pm.to_username;
                const timestamp = pm.time.toISOExtString;
                const message = pm.message;

                if (!first) output ~= ",";
                output ~= text(
                    "\n            {",
                    "\n                \"id\": ", id, ",",
                    "\n                \"recipient\": \"", to_username, "\",",
                    "\n                \"timestamp\": \"", timestamp, "\",",
                    "\n                \"message\": \"", message, "\"",
                    "\n            }"
                );
                first = false;
            }
            output ~= "\n        ";
            return output[];
        }

        return text(
            "{",
            "\n    \"username\": \"", username, "\",",
            "\n    \"session_data\": {",
            "\n        \"status\": \"", status, "\",",
            "\n        \"client_version\": \"", user.client_version, "\",",
            "\n        \"ip_address\": \"", user.address.toAddrString ~ "\",",
            "\n        \"port\": ", user.address.port, ",",
            "\n        \"obfuscated_port\": ", user.obfuscated_port, ",",
            "\n        \"obfuscation_type\": ", obfuscation_type, ",",
            "\n        \"accept_room_invitations\": ", accept_invitations, ",",
            "\n        \"joined_global_room\": ", joined_global_room, ",",
            "\n        \"liked_items\": [", liked_items, "],",
            "\n        \"hated_items\": [", hated_items, "],",
            "\n        \"joined_rooms\": [", joined_rooms, "],",
            "\n        \"watched_users\": [", watched_users, "]",
            "\n    },",
            "\n    \"persistent_data\": {",
            "\n        \"admin_until\": ", admin, ",",
            "\n        \"privileged_until\": ", privileged, ",",
            "\n        \"supporter\": ", supporter, ",",
            "\n        \"searchable\": ", searchable, ",",
            "\n        \"num_files\": ", user.shared_files, ",",
            "\n        \"num_folders\": ", user.shared_folders, ",",
            "\n        \"upload_speed\": ", user.upload_speed, ",",
            "\n        \"private_rooms_owner\": {", rooms, "}",
            "\n        \"private_rooms_member\": {", rooms(false), "}",
            "\n        \"room_tickers\": {", tickers, "}",
            "\n    },",
            "\n    \"volatile_data\": {",
            "\n        \"private_messages_queued\": [", pms, "]",
            "\n    }",
            "\n}"
        );
    }
}
