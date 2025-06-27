// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server.server;
@safe:

import core.time : days, Duration, minutes, MonoTime, seconds;
import soulfind.db : Sdb;
import soulfind.defines : blue, bold, default_port, kick_minutes,
                          max_room_name_length, max_search_query_length, norm,
                          red, server_username, VERSION;
import soulfind.server.messages;
import soulfind.server.pm : PM;
import soulfind.server.room : GlobalRoom, Room;
import soulfind.server.user : User;
import std.array : join, replace, split;
import std.conv : ConvException, to;
import std.datetime : Clock, ClockType, SysTime;
import std.exception : ifThrown;
import std.format : format;
import std.process : thisProcessID;
import std.random : uniform;
import std.socket : InternetAddress, Socket, SocketAcceptException,
                    SocketOption, SocketOptionLevel, SocketOSException,
                    SocketSet, SocketShutdown, TcpSocket;
import std.stdio : writefln;
import std.string : strip;

version (unittest) {
    auto running = true;
}
else {
    import soulfind.main : running;
}

class Server
{
    Sdb                   db;
    GlobalRoom            global_room;
    User[string]          users;

    private MonoTime      started_at;
    private ushort        port;

    private User[Socket]  user_socks;
    private SocketSet     read_socks;
    private SocketSet     write_socks;

    private PM[uint]      pms;
    private Room[string]  rooms;


    this(string db_filename)
    {
        started_at = MonoTime.currTime;
        db = new Sdb(db_filename);
        global_room = new GlobalRoom();

        port = db.get_config_value("port")
            .to!ushort
            .ifThrown(cast(ushort) default_port);
    }


    // Connections

    int listen()
    {
        auto sock = new TcpSocket();
        sock.blocking = false;

        version (Posix)
            sock.setOption(
                SocketOptionLevel.SOCKET, SocketOption.REUSEADDR, 1);

        try {
            sock.bind(new InternetAddress(port));
            sock.listen(10);
        }
        catch (SocketOSException e) {
            const min_port = 1024;
            writefln!("Unable to bind socket to port %d")(port);
            if (port < min_port) writefln!(
                "Are you trying to use a port less than %d while running as "
              ~ "a user?")(
                 min_port
            );
            return 1789;
        }

        writefln!("%s %s %s process %d listening on port %d")(
            red ~ "♥" ~ norm, bold ~ "Soulfind", VERSION ~ norm,
            thisProcessID, port
        );

        const timeout = 1.seconds;
        read_socks = new SocketSet();
        write_socks = new SocketSet();

        while (running) {
            read_socks.add(sock);

            Socket.select(read_socks, write_socks, null, timeout);

            if (read_socks.isSet(sock)) {
                while (true) {
                    Socket new_sock;
                    try {
                        new_sock = sock.accept();
                    }
                    catch (SocketAcceptException) {
                        break;
                    }
                    if (!new_sock.isAlive)
                        break;

                    enable_keep_alive(new_sock);
                    new_sock.setOption(
                        SocketOptionLevel.TCP, SocketOption.TCP_NODELAY, 1
                    );
                    new_sock.blocking = false;

                    debug (user) writefln!("Connection accepted from %s")(
                        new_sock.remoteAddress
                    );
                    user_socks[new_sock] = new User(
                        this, new_sock,
                        (cast(InternetAddress) new_sock.remoteAddress).addr
                    );
                }
            }

            User[] users_to_remove;

            foreach (user_sock, user ; user_socks) {
                const recv_ready = read_socks.isSet(user_sock);
                const send_ready = write_socks.isSet(user_sock);
                bool recv_success = true;
                bool send_success = true;

                if (recv_ready) {
                    recv_success = user.recv_buffer();

                    if (!user.sock)
                        // User was kicked
                        continue;
                }
                else {
                    read_socks.add(user_sock);
                }

                if (send_ready)
                    send_success = user.send_buffer();

                if (!user.is_sending) {
                    if (send_ready)
                        write_socks.remove(user_sock);

                    if (user.login_error)
                        recv_success = send_success = false;
                }
                else if (!send_ready) {
                    write_socks.add(user_sock);
                }

                if (!running || !recv_success || !send_success)
                    users_to_remove ~= user;
            }

            foreach (user ; users_to_remove)
                del_user(user);
        }

        sock.close();
        return 0;
    }

    void enable_keep_alive(Socket sock)
    {
        int TCP_KEEPIDLE;
        int TCP_KEEPINTVL;
        int TCP_KEEPCNT;
        int TCP_KEEPALIVE_ABORT_THRESHOLD;
        int TCP_KEEPALIVE_THRESHOLD;

        version (linux) {
            TCP_KEEPIDLE                   = 0x4;
            TCP_KEEPINTVL                  = 0x5;
            TCP_KEEPCNT                    = 0x6;
        }
        version (OSX) {
            TCP_KEEPIDLE                   = 0x10;   // TCP_KEEPALIVE on macOS
            TCP_KEEPINTVL                  = 0x101;
            TCP_KEEPCNT                    = 0x102;
        }
        version (Windows) {
            TCP_KEEPIDLE                   = 0x03;
            TCP_KEEPCNT                    = 0x10;
            TCP_KEEPINTVL                  = 0x11;
        }
        version (NetBSD) {
            TCP_KEEPIDLE                   = 0x3;
            TCP_KEEPINTVL                  = 0x5;
            TCP_KEEPCNT                    = 0x6;
        }
        version (FreeBSD) version (DragonFlyBSD) {
            TCP_KEEPIDLE                   = 0x100;
            TCP_KEEPINTVL                  = 0x200;
            TCP_KEEPCNT                    = 0x400;
        }
        version (Solaris) {
            TCP_KEEPALIVE_THRESHOLD        = 0x16;
            TCP_KEEPALIVE_ABORT_THRESHOLD  = 0x17;
        }

        const idle = 60;
        const interval = 5;
        const count = 10;

        if (TCP_KEEPIDLE)
            sock.setOption(
                SocketOptionLevel.TCP, cast(SocketOption) TCP_KEEPIDLE, idle
            );
        if (TCP_KEEPINTVL)
            sock.setOption(
                SocketOptionLevel.TCP, cast(SocketOption) TCP_KEEPINTVL,
                interval
            );
        if (TCP_KEEPCNT)
            sock.setOption(
                SocketOptionLevel.TCP, cast(SocketOption) TCP_KEEPCNT, count
            );
        if (TCP_KEEPALIVE_THRESHOLD)
            sock.setOption(
                SocketOptionLevel.TCP,
                cast(SocketOption) TCP_KEEPALIVE_THRESHOLD,
                idle * 1000              // milliseconds
            );
        if (TCP_KEEPALIVE_ABORT_THRESHOLD)
            sock.setOption(
                SocketOptionLevel.TCP,
                cast(SocketOption) TCP_KEEPALIVE_ABORT_THRESHOLD,
                count * interval * 1000  // milliseconds
            );

        sock.setOption(SocketOptionLevel.SOCKET, SocketOption.KEEPALIVE, true);
    }


    // File Searches

    void search_files(uint token, string query, string username)
    {
        if (query.length > max_search_query_length)
            return;

        scope msg = new SFileSearch(username, token, query);
        send_to_all(msg);
    }

    void search_user_files(uint token, string query, string from_username,
                           string to_username)
    {
        if (query.length > max_search_query_length)
            return;

        auto user = get_user(to_username);
        if (!user)
            return;

        scope msg = new SFileSearch(from_username, token, query);
        user.send_message(msg);
    }

    void search_room_files(uint token, string query, string username,
                           string room_name)
    {
        if (query.length > max_search_query_length)
            return;

        auto room = get_room(room_name);
        if (!room)
            return;

        scope msg = new SFileSearch(username, token, query);
        room.send_to_all(msg);
    }


    // Private Messages

    PM add_pm(string message, string from_username, string to_username)
    {
        auto pm = PM(
            new_pm_id,
            Clock.currTime.toUnixTime,
            from_username,
            to_username,
            message
        );

        pms[pm.id] = pm;
        return pm;
    }

    void del_pm(uint id)
    {
        if (find_pm(id))
            pms.remove(id);
    }

    PM[] get_pms_for(string username)
    {
        PM[] user_pms;
        foreach (pm ; pms) if (pm.to_username == username) user_pms ~= pm;
        return user_pms;
    }

    private bool find_pm(uint id)
    {
        return(id in pms) ? true : false;
    }

    private uint new_pm_id()
    {
        uint id = cast(uint) pms.length;
        while (find_pm(id)) id++;
        return id;
    }


    // Rooms

    Room add_room(string name)
    {
        auto room = new Room(name);
        rooms[name] = room;
        return room;
    }

    void del_room(string name)
    {
        if (name in rooms)
            rooms.remove(name);
    }

    Room get_room(string name)
    {
        if (name !in rooms)
            return null;

        return rooms[name];
    }

    ulong[string] room_stats()
    {
        ulong[string] stats;
        foreach (room ; rooms) stats[room.name] = room.num_users;
        return stats;
    }


    // Users

    void add_user(User user)
    {
        writefln!(
            "User %s @ %s logging in with version %s")(
            blue ~ user.username ~ norm,
            bold ~ user.h_ip_address ~ norm,
            bold ~ user.h_client_version ~ norm
        );
        users[user.username] = user;
    }

    User get_user(string username)
    {
        if (username in users)
            return users[username];

        return null;
    }

    void del_user(User user)
    {
        const username = user.username;
        auto sock = user.sock;

        if (sock in user_socks) {
            const address = sock.remoteAddress;

            read_socks.remove(sock);
            write_socks.remove(sock);
            user_socks.remove(sock);

            sock.shutdown(SocketShutdown.BOTH);
            sock.close();

            debug (user) writefln!("Closed connection to %s")(address);
            user.sock = null;
        }

        if (username in users)
            users.remove(username);

        if (user.status == Status.offline) {
            if (user.login_error) writefln!(
                "User %s @ %s denied (%s)")(
                red ~ username ~ norm,
                bold ~ user.h_ip_address ~ norm,
                red ~ user.login_error ~ norm
            );
            return;
        }

        user.leave_joined_rooms();
        global_room.remove_user(username);

        user.set_status(Status.offline);
        writefln!(
            "User %s @ %s quit")(
            red ~ username ~ norm,
            bold ~ user.h_address ~ norm
        );
    }

    private void send_to_all(scope SMessage msg)
    {
        debug (msg) writefln!("Transmit=> %s (code %d) to all users...")(
            blue ~ msg.name ~ norm, msg.code
        );
        foreach (user ; users) user.send_message(msg);
    }

    void admin_message(User admin, string message)
    {
        if (!db.is_admin(admin.username))
            return;

        const command = message.split(" ");
        if (command.length > 0) switch (command[0])
        {
            case "help":
                server_pm(
                    admin,
                    format!(
                        "Available commands :"
                      ~ "\n\nusers\n\tList connected users"
                      ~ "\n\ninfo <user>\n\tShow info about user"
                      ~ "\n\nkickall [minutes]\n\tDisconnect active users for"
                      ~ " [%d] minutes"
                      ~ "\n\nkick [minutes] <user>\n\tDisconnect user for"
                      ~ " [%d] minutes"
                      ~ "\n\nban [days] <user>\n\tBan user for [365] days"
                      ~ "\n\nunban <user>\n\tUnban user"
                      ~ "\n\nadmins\n\tList admins"
                      ~ "\n\nrooms\n\tList rooms and number of users"
                      ~ "\n\naddprivileges <days> <user>\n\tAdd privileges to"
                      ~ " user"
                      ~ "\n\ndelprivileges [days] <user>\n\tRemove privileges"
                      ~ " from user"
                      ~ "\n\nmessage <message>\n\tSend global message"
                      ~ "\n\nuptime\n\tShow server uptime")(
                        kick_minutes,
                        kick_minutes
                    )
                );
                break;

            case "addprivileges":
                if (command.length < 3) {
                    server_pm(
                        admin, "Syntax is : addprivileges <days> <user>"
                    );
                    break;
                }

                uint days;
                uint seconds;
                try {
                    days = command[1].to!uint;
                    seconds = days * 3600 * 24;
                }
                catch (ConvException e) {
                    server_pm(admin, "Badly formatted number.");
                    break;
                }

                const username = command[2 .. $].join(" ");
                if (!db.user_exists(username)) {
                    server_pm(
                        admin, format!("User %s is not registered")(
                        username)
                    );
                    break;
                }

                db.add_user_privileges(username, seconds);

                auto user = get_user(username);
                if (user)
                    user.refresh_privileges();

                server_pm(admin, format!(
                    "Added %d days of privileges to user %s")(
                    days, username)
                );
                break;

            case "users":
                const list = format!("%d connected users.\n\t%s")(
                    users.length,
                    users.byKey.join("\n\t")
                );
                server_pm(admin, list);
                break;

            case "info":
                if (command.length < 2) {
                    server_pm(admin, "Syntax is : info <user>");
                    break;
                }
                const username = command[1 .. $].join(" ");

                if (!db.user_exists(username)) {
                    server_pm(admin, format!(
                        "User %s is not registered")(username)
                    );
                    break;
                }

                server_pm(admin, user_info(username));
                break;

            case "kickall":
                Duration duration = minutes(kick_minutes);
                if (command.length > 1) {
                    try {
                        duration = minutes(command[1].to!uint);
                    }
                    catch (ConvException e) {
                        server_pm(admin, "Syntax is : kickall [minutes]");
                        break;
                    }
                }
                uint num_kicks;
                foreach (user ; users.values) {
                    if (user.username == admin.username)
                        continue;

                    ban_user(
                        user.username, duration + seconds(uniform(-50, 50))
                    );
                    num_kicks += 1;
                }
                debug (user) writefln!(
                    "Admin %s kicked ALL %d users for %s!")(
                    blue ~ admin.username ~ norm, num_kicks, duration
                );
                server_pm(admin, format!(
                    "All %d users kicked for %s (+/-50s)")(
                    num_kicks, duration)
                );
                break;

            case "kick":
                if (command.length < 2) {
                    server_pm(admin, "Syntax is : kick [minutes] <user>");
                    break;
                }

                Duration duration;
                string username;
                try {
                    duration = minutes(command[1].to!uint);
                    username = command[2 .. $].join(" ");
                }
                catch (ConvException e) {
                    duration = minutes(kick_minutes);
                    username = command[1 .. $].join(" ");
                }

                if (!db.user_exists(username)) {
                    server_pm(admin, format!(
                        "User %s is not registered")(username)
                    );
                    break;
                }

                SysTime expiration = ban_user(username, duration);

                server_pm(admin, format!("User %s kicked for %s; until %s")(
                    username, duration, expiration)
                );
                break;

            case "ban":
                if (command.length < 2) {
                    server_pm(admin, "Syntax is : ban [days] <user>");
                    break;
                }

                Duration duration;
                string username;
                try {
                    duration = days(command[1].to!uint);
                    username = command[2 .. $].join(" ");
                }
                catch (ConvException e) {
                    duration = days(365);
                    username = command[1 .. $].join(" ");
                }

                if (!db.user_exists(username)) {
                    server_pm(admin, format!(
                        "User %s is not registered")(username)
                    );
                    break;
                }

                SysTime expiration = ban_user(username, duration);

                server_pm(admin, format!("User %s banned for %s; until %s")(
                    username, duration, expiration)
                );
                break;

            case "unban":
                if (command.length < 2) {
                    server_pm(admin, "Syntax is : unban <user>");
                    break;
                }
                const username = command[1 .. $].join(" ");
                unban_user(username);
                server_pm(
                    admin, format!("User %s not banned anymore")(username)
                );
                break;

            case "admins":
                const names = db.admins;
                const list = format!("%d registered admins.\n\t%s")(
                    names.length,
                    names.join("\n\t")
                );
                server_pm(admin, list);
                break;

            case "rooms":
                string list;
                foreach (room ; rooms)
                    list ~= format!("%s:%d ")(room.name, room.num_users);
                server_pm(admin, list);
                break;

            case "message":
                if (command.length < 2) {
                    server_pm(admin, "Syntax is : message <message>");
                    break;
                }
                const msg = command[1 .. $].join(" ");
                global_message(msg);
                break;

            case "uptime":
                server_pm(admin, h_uptime);
                break;

            default:
                server_pm(
                    admin,
                    "Don't expect me to understand what you want if you don't "
                  ~ "use a correct command..."
                );
                break;
        }
    }

    void server_pm(User user, string message)
    {
        const pm = add_pm(message, server_username, user.username);
        const new_message = true;
        user.send_pm(pm, new_message);
    }

    private void global_message(string message)
    {
        scope msg = new SAdminMessage(message);
        foreach (user ; users) {
            user.send_message(msg);
        }
    }

    private string user_info(string username)
    {
        User user;
        auto client_version = "none";
        auto address = "none";
        auto connected_at = "none";
        auto status = "offline";
        auto banned = "false";
        auto privileged = "false";
        uint speed, upload_number;
        uint shared_files, shared_folders;
        string joined_rooms;

        const admin = db.is_admin(username);
        const banned_until = db.get_user_banned_until(username);
        const privileged_until = db.get_user_privileged_until(username);
        const supporter = privileged_until > 0;

        if (banned_until == long.max)
            banned = "forever";

        else if (banned_until > Clock.currTime.toUnixTime)
            banned = format!("until %s")(SysTime.fromUnixTime(banned_until));

        if (privileged_until > Clock.currTime.toUnixTime)
            privileged = format!("until %s")(
                SysTime.fromUnixTime(privileged_until));

        user = get_user(username);
        if (user) {
            client_version = user.h_client_version;
            address = user.h_address;
            connected_at = user.connected_at.toString;
            status = (user.status == Status.away) ? "away" : "online";
            speed = user.speed;
            upload_number = user.upload_number;
            shared_files = user.shared_files;
            shared_folders = user.shared_folders;
            joined_rooms = user.h_joined_rooms;
        }
        else {
            const user_stats = db.get_user_stats(username);
            speed = user_stats.speed;
            upload_number = user_stats.upload_number;
            shared_files = user_stats.shared_files;
            shared_folders = user_stats.shared_folders;
        }

        return format!(
            "%s"
          ~ "\n\tclient version: %s"
          ~ "\n\taddress: %s"
          ~ "\n\tconnected at: %s"
          ~ "\n\tstatus: %s"
          ~ "\n\tadmin: %s"
          ~ "\n\tbanned: %s"
          ~ "\n\tprivileged: %s"
          ~ "\n\tsupporter: %s"
          ~ "\n\tfiles: %s"
          ~ "\n\tdirs: %s"
          ~ "\n\tupload speed: %s"
          ~ "\n\tupload number: %s"
          ~ "\n\tjoined rooms: %s")(
            username,
            client_version,
            address,
            connected_at,
            status,
            admin,
            banned,
            privileged,
            supporter,
            shared_files,
            shared_folders,
            speed,
            upload_number,
            joined_rooms
        );
    }

    private void disconnect_user(string username)
    {
        auto user = get_user(username);
        if (user) del_user(user);
    }

    private SysTime ban_user(string username, Duration duration)
    {
        SysTime expiration = Clock.currTime!(ClockType.second) + duration;

        db.user_update_field(username, "banned", expiration.toUnixTime);
        disconnect_user(username);

        return expiration;
    }

    private void unban_user(string username)
    {
        if (db.user_exists(username))
            db.user_update_field(username, "banned", 0);
    }

    string get_motd(User user)
    {
        return db.get_config_value("motd")
            .replace("%sversion%", VERSION)
            .replace("%users%", users.length.to!string)
            .replace("%username%", user.username)
            .replace("%version%", user.h_client_version);
    }

    private Duration uptime()
    {
        return MonoTime.currTime - started_at;
    }

    private string h_uptime()
    {
        return uptime.total!"seconds".seconds.toString;
    }
}
