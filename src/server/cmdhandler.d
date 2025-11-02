// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server.cmdhandler;
@safe:

import soulfind.db : Sdb;
import soulfind.defines : blue, kick_duration, log_user, norm, RoomType,
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
import std.string : join, split;

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
                "Available commands:"
              ~ " None"
            );
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
                    "\n\nadmins\n\tList admins",
                    "\n\nusers [connected|banned|privileged]\n\tList users",
                    "\n\nrooms\n\tList public rooms",
                    "\n\nuserinfo <user>\n\tShow info about user",
                    "\n\nroominfo <room>\n\tShow info about public room",
                    "\n\nremovetickers <user>\n\tRemove user's public room",
                    " tickers",
                    "\n\nban [days] <user>\n\tBan user",
                    "\n\nunban <user>\n\tUnban user",
                    "\n\nkick [minutes] <user>\n\tDisconnect user for",
                    " [", kick_duration.total!"minutes", "] minutes",
                    "\n\nkickall [minutes]\n\tDisconnect active users for",
                    " [", kick_duration.total!"minutes", "] minutes",
                    "\n\nannouncement <message>\n\tSend announcement to",
                    " online users",
                    "\n\nmessage <message>\n\tSend private message to all",
                    " registered users",
                    "\n\nuptime\n\tShow server uptime"
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

                output ~= "\n\t";
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
            const names = server.db.rooms!(RoomType._public);
            output ~= text(names.length, " public rooms.");
            foreach (ref name ; names) {
                ulong num_users;
                room = server.get_room(name);
                if (room !is null) num_users = room.num_users;

                output ~= "\n\t";
                output ~= name;
                output ~= text(
                    " (users: ", num_users, ", tickers: ",
                    server.db.num_room_tickers(name), ")"
                );
            }
            respond(admin_username, output[]);
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
                const limit = ushort.max;
                duration = (value > limit ? limit : value).days;
                username = args[2 .. $].join(" ");
            }
            catch (ConvException) {
                duration = Duration.max;
                username = args[1 .. $].join(" ");
            }

            if (!server.db.user_exists(username)) {
                respond(
                    admin_username,
                    text("User ", username, " is not registered")
                );
                break;
            }

            server.db.ban_user(username, duration);
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
                const limit = ushort.max;
                duration = (value > limit ? limit : value).minutes;
                username = args[2 .. $].join(" ");
            }
            catch (ConvException) {
                duration = kick_duration;
                username = args[1 .. $].join(" ");
            }

            if (!server.db.user_exists(username)) {
                respond(
                    admin_username,
                    text("User ", username, " is not registered")
                );
                break;
            }

            server.db.ban_user(username, duration);

            auto user = server.get_user(username);
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
                    const limit = ushort.max;
                    duration = (value > limit ? limit : value).minutes;
                }
                catch (ConvException) {
                    respond(admin_username, "Syntax is: kickall [minutes]");
                    break;
                }
            }
            User[] users_to_kick;
            foreach (ref user ; server.connected_users)
                if (user.username != admin_username)
                    users_to_kick ~= user;

            foreach (ref user ; users_to_kick) {
                server.db.ban_user(user.username, duration);
                user.disconnect();
            }

            if (log_user) writeln(
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
            output ~= "\n\t";
            output ~= username;
        }

        output ~= text("\nTickers (", tickers.length, "):");

        foreach (ref ticker ; tickers) {
            const username = ticker[0], content = ticker[1];
            output ~= text("\n\t[", username, "] ");
            output ~= content;
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
                output ~= "\n\t";
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
                output ~= "\n\t";
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
                const banned_until = server.db.user_banned_until(user);
                if (banned_until == SysTime.max) {
                    output ~= "\n\t";
                    output ~= user;
                    output ~= " (forever)";
                }
                else {
                    output ~= "\n\t";
                    output ~= user;
                    output ~= text(
                        " (until ", banned_until.toSimpleString, ")"
                    );
                }
            }
            break;

        case null:
            const usernames = server.db.usernames;
            output ~= text(usernames.length, " total users.");
            foreach (ref username ; usernames) {
                output ~= "\n\t";
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
        size_t watched_users;
        string liked_items, hated_items;
        string joined_rooms;
        auto joined_global_room = "no";
        auto admin = "no";
        auto banned = "no";
        auto privileged = "no";
        SysTime privileged_until;
        auto supporter = "no";
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
                obfuscation_type = (cast(uint) user.obfuscation_type).text;
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

        Appender!string output;
        output ~= text(
            username,
            "\n",
            "\nSession info:",
            "\n\tstatus: ", status,
            "\n\tclient version: ", client_version,
            "\n\tIP address: ", ip_address,
            "\n\tport: ", listening_port,
            "\n\tobfuscated port: ", obfuscated_port,
            "\n\tobfuscation type: ", obfuscation_type,
            "\n\twatched users: ", watched_users,
            "\n\tliked items: ", liked_items,
            "\n\thated items: ", hated_items,
            "\n\tjoined public rooms: ", joined_rooms,
            "\n\tjoined global room: ", joined_global_room,
            "\n",
            "\nPresistent info:",
            "\n\tadmin: ", admin,
            "\n\tbanned: ", banned,
            "\n\tprivileged: ", privileged,
            "\n\tsupporter: ", supporter,
            "\n\tupload speed: ", upload_speed,
            "\n\tfiles: ", shared_files,
            "\n\tdirs: ", shared_folders,
            "\n\tpublic tickers: ", tickers.length
        );

        if (tickers.length > 0) {
            output ~= text("\n\nPublic room tickers (", tickers.length, "):");
            foreach (ticker ; tickers) {
                const room_name = ticker[0], content = ticker[1];
                output ~= text("\n\t[", room_name, "] ", content);
            }
        }

        return output[];
    }
}
