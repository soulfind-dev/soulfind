// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server.server;
@safe:

import core.time : days, Duration, minutes, MonoTime, seconds;
import soulfind.db : Sdb;
import soulfind.defines : blue, bold, default_port, delete_user_interval,
                          kick_duration, log_msg, log_user,
                          max_room_name_length, max_search_query_length, norm,
                          red, server_username, VERSION;
import soulfind.server.messages;
import soulfind.server.pm : PM;
import soulfind.server.room : GlobalRoom, Room;
import soulfind.server.user : User;
import std.algorithm : clamp;
import std.array : Appender;
import std.conv : ConvException, to;
import std.datetime : Clock, SysTime;
import std.process : thisProcessID;
import std.socket : InternetAddress, Socket, SocketAcceptException,
                    SocketOption, SocketOptionLevel, SocketOSException,
                    SocketSet, SocketShutdown, TcpSocket;
import std.stdio : writefln;
import std.string : format, join, split;

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

    private SysTime       started_at;
    private MonoTime      started_monotime;
    private MonoTime      last_delete_user_check;
    private ushort        port;

    private User[Socket]  user_socks;
    private SocketSet     read_socks;
    private SocketSet     write_socks;

    private PM[uint]      pms;
    private Room[string]  rooms;


    this(string db_filename, ushort port)
    {
        this.db                = new Sdb(db_filename);
        this.started_at        = Clock.currTime;
        this.started_monotime  = MonoTime.currTime;
        this.global_room       = new GlobalRoom();

        if (!port) {
            try
                this.port = db.get_config_value("port").to!ushort;
            catch (ConvException)
                this.port = cast(ushort) default_port;
        }
        else {
            this.port = port;
        }
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
                    try
                        new_sock = sock.accept();
                    catch (SocketAcceptException)
                        break;

                    if (!new_sock.isAlive)
                        break;

                    enable_keep_alive(new_sock);
                    new_sock.setOption(
                        SocketOptionLevel.TCP, SocketOption.TCP_NODELAY, 1
                    );
                    new_sock.blocking = false;

                    if (log_user) writefln!("Connection accepted from %s")(
                        new_sock.remoteAddress
                    );
                    user_socks[new_sock] = new User(
                        this, new_sock,
                        new InternetAddress(
                            (cast(InternetAddress)new_sock.remoteAddress).addr,
                            InternetAddress.PORT_ANY
                        )
                    );
                }
            }

            Appender!(User[]) users_to_disconnect;

            const curr_time = MonoTime.currTime;
            const check_user_deleted = (
                (curr_time - last_delete_user_check) >= delete_user_interval
            );
            if (check_user_deleted)
                last_delete_user_check = curr_time;

            foreach (user_sock, user ; user_socks) {
                const recv_ready = read_socks.isSet(user_sock);
                const send_ready = write_socks.isSet(user_sock);
                bool recv_success = true;
                bool send_success = true;

                if (recv_ready)
                    recv_success = user.recv_buffer();
                else
                    read_socks.add(user_sock);

                if (send_ready)
                    send_success = user.send_buffer();

                if (!user.is_sending) {
                    if (send_ready)
                        write_socks.remove(user_sock);

                    if (check_user_deleted && user.username in users) {
                        // If the user was removed from the database, perform
                        // server-side removal and disconnection of deleted
                        // users. Send a Relogged message first to prevent the
                        // user's client from automatically reconnecting and
                        // registering again.
                        const deleted = !db.user_exists(user.username);
                        if (deleted) {
                            scope relogged_msg = new SRelogged();
                            user.send_message(relogged_msg);
                            del_user(user, deleted);
                        }
                        last_delete_user_check = curr_time;
                    }
                    else if (user.removed) {
                        // In order to avoid closing connections early before
                        // delivering e.g. a Relogged message, we disconnect
                        // the user here after the output buffer is sent
                        users_to_disconnect ~= user;
                    }
                    else if (user.login_rejection.reason
                            || user.login_timed_out) {
                        recv_success = send_success = false;
                    }
                }
                else if (!send_ready) {
                    write_socks.add(user_sock);
                }

                if (!running || !recv_success || !send_success) {
                    del_user(user);
                    users_to_disconnect ~= user;
                }
            }

            foreach (user ; users_to_disconnect) {
                read_socks.remove(user.sock);
                write_socks.remove(user.sock);
                user_socks.remove(user.sock);

                user.sock.shutdown(SocketShutdown.BOTH);
                user.sock.close();

                if (log_user) writefln!("Closed connection to %s")(
                    user.address.toAddrString
                );
                user.sock = null;
            }
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
            Clock.currTime,
            from_username,
            to_username,
            message
        );

        pms[pm.id] = pm;
        return pm;
    }

    void del_pm(uint id, string to_username)
    {
        if (id !in pms)
            return;

        const pm = pms[id];
        if (pm.to_username != to_username)
            return;

        pms.remove(id);
    }

    void del_user_pms(string username, bool include_received = false)
    {
        Appender!(PM[]) pms_to_remove;
        foreach (pm ; pms) {
            if (pm.from_username == username
                    || (include_received && pm.to_username == username))
                pms_to_remove ~= pm;
        }
        foreach (pm ; pms_to_remove) pms.remove(pm.id);
    }

    private uint new_pm_id()
    {
        uint id = cast(uint) pms.length;
        while (id in pms) id++;
        return id;
    }

    void send_pm(const PM pm, bool new_message)
    {
        auto user = get_user(pm.to_username);
        if (!user)
            return;

        scope msg = new SMessageUser(
            pm.id, pm.time, pm.from_username, pm.message, new_message
        );
        user.send_message(msg);
    }

    void send_queued_pms(string username)
    {
        foreach (pm ; pms) {
            if (pm.to_username != username)
                continue;

            const new_message = false;
            send_pm(pm, new_message);
        }
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

    void del_user_tickers(string username)
    {
        foreach (room ; rooms) room.del_ticker(username);
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

    private string room_info(string name)
    {
        Appender!string output;
        auto room = rooms[name];

        output ~= name;
        output ~= format!("\nUsers (%d):")(room.num_users);
        foreach (username ; room.usernames)
            output ~= format!("\n\t%s")(username);

        output ~= format!("\nTickers (%d):")(room.num_tickers);
        foreach (ticker ; room.tickers_by_order)
            output ~= format!("\n\t[%s] %s")(ticker.username, ticker.content);

        return output[];
    }


    // Users

    void add_user(User user)
    {
        writefln!(
            "User %s @ %s logging in with version %s")(
            blue ~ user.username ~ norm,
            bold ~ user.address.toAddrString ~ norm,
            bold ~ user.client_version ~ norm
        );
        users[user.username] = user;
    }

    void del_user(User user, bool delete_messages = false)
    {
        if (user.removed)
            return;

        user.removed = true;
        const username = user.username;

        if (username in users)
            users.remove(username);

        if (delete_messages) {
            const include_received = true;
            del_user_pms(username, include_received);
            del_user_tickers(username);
        }

        if (user.status == Status.offline) {
            if (user.login_rejection.reason) writefln!(
                "User %s @ %s denied (%s)")(
                red ~ username ~ norm,
                bold ~ user.address.toAddrString ~ norm,
                red ~ user.login_rejection.reason ~ norm
            );
            return;
        }

        user.leave_joined_rooms();
        global_room.remove_user(username);

        user.update_status(Status.offline);
        writefln!(
            "User %s @ %s quit")(
            red ~ username ~ norm,
            bold ~ user.address.toString ~ norm
        );
    }

    User get_user(string username)
    {
        if (username in users)
            return users[username];

        return null;
    }

    private string user_list(string type = null)
    {
        Appender!string output;
        switch (type)
        {
            case "connected":
                output ~= format!("%d connected users.")(users.length);
                foreach (user ; users)
                    output ~= format!("\n\t%s (client version: %s)")(
                        user.username, user.client_version
                    );
                break;

            case "privileged":
                const users = db.usernames(
                    "privileges", Clock.currTime.toUnixTime
                );
                output ~= format!("%d privileged users.")(users.length);
                foreach (user ; users) {
                    const privileged_until = db.user_privileged_until(user);
                    output ~= format!("\n\t%s (until %s)")(
                        user, privileged_until.toSimpleString
                    );
                }
                break;

            case "banned":
                const users = db.usernames(
                    "banned", Clock.currTime.toUnixTime
                );
                output ~= format!("\nBanned users (%d)...")(users.length);
                foreach (user ; users) {
                    const banned_until = db.user_banned_until(user);
                    if (banned_until == SysTime.fromUnixTime(long.max))
                        output ~= format!("\n\t%s (forever)")(user);
                    else
                        output ~= format!("\n\t%s (until %s)")(
                            user, banned_until.toSimpleString);
                }
                break;

            default:
                const usernames = db.usernames;
                output ~= format!("%d total users.")(usernames.length);
                foreach (username ; db.usernames)
                    output ~= format!("\n\t%s")(username);
        }
        return output[];
    }

    private string user_info(string username)
    {
        User user;
        const now = Clock.currTime;
        auto client_version = "none";
        auto address = "none";
        auto status = "offline";
        ulong watched_users;
        string liked_items, hated_items;
        string joined_rooms;
        auto joined_global_room = "false";
        const admin = db.is_admin(username);
        auto banned = "false";
        auto privileged = "false";
        SysTime privileged_until;
        bool supporter;
        uint upload_speed;
        uint shared_files, shared_folders;

        user = get_user(username);
        if (user) {
            client_version = user.client_version;
            address = user.address.toString;
            status = (user.status == Status.away) ? "away" : "online";
            watched_users = user.num_watched_users;
            liked_items = user.liked_item_names.join(", ");
            hated_items = user.hated_item_names.join(", ");
            joined_rooms = user.joined_room_names.join(", ");
            if (global_room.is_joined(username)) joined_global_room = "true";
            privileged_until = user.privileged_until;
            supporter = user.supporter;
            upload_speed = user.upload_speed;
            shared_files = user.shared_files;
            shared_folders = user.shared_folders;
        }
        else {
            const user_stats = db.user_stats(username);
            privileged_until = db.user_privileged_until(username);
            supporter = db.user_supporter(username);
            upload_speed = user_stats.upload_speed;
            shared_files = user_stats.shared_files;
            shared_folders = user_stats.shared_folders;
        }

        const banned_until = db.user_banned_until(username);
        if (banned_until == SysTime.fromUnixTime(long.max))
            banned = "forever";

        else if (banned_until > now)
            banned = format!("until %s")(banned_until.toSimpleString);

        if (privileged_until > now)
            privileged = format!("until %s")(privileged_until.toSimpleString);

        return format!(
            "%s"
          ~ "\n"
          ~ "\nSession info:"
          ~ "\n\tclient version: %s"
          ~ "\n\taddress: %s"
          ~ "\n\tstatus: %s"
          ~ "\n\twatched users: %s"
          ~ "\n\tliked items: %s"
          ~ "\n\thated items: %s"
          ~ "\n\tjoined rooms: %s"
          ~ "\n\tjoined global room: %s"
          ~ "\n"
          ~ "\nPresistent info:"
          ~ "\n\tadmin: %s"
          ~ "\n\tbanned: %s"
          ~ "\n\tprivileged: %s"
          ~ "\n\tsupporter: %s"
          ~ "\n\tupload speed: %s"
          ~ "\n\tfiles: %s"
          ~ "\n\tdirs: %s")(
            username,
            client_version,
            address,
            status,
            watched_users,
            liked_items,
            hated_items,
            joined_rooms,
            joined_global_room,
            admin,
            banned,
            privileged,
            supporter,
            upload_speed,
            shared_files,
            shared_folders
        );
    }

    private void send_to_all(scope SMessage msg)
    {
        if (log_msg) writefln!("Transmit=> %s (code %d) to all users...")(
            blue ~ msg.name ~ norm, msg.code
        );
        foreach (user ; users) user.send_message(msg);
    }

    void admin_message(string admin_username, string message)
    {
        if (!db.is_admin(admin_username))
            return;

        const command = message.split(" ");
        if (command.length > 0) switch (command[0])
        {
            case "help":
                server_pm(
                    admin_username,
                    format!(
                        "Available commands :"
                      ~ "\n\nadmins\n\tList admins"
                      ~ "\n\nusers [connected|banned|privileged]\n\tList users"
                      ~ "\n\nrooms\n\tList public rooms"
                      ~ "\n\nuserinfo <user>\n\tShow info about user"
                      ~ "\n\nroominfo <room>\n\tShow info about public room"
                      ~ "\n\nban [days] <user>\n\tBan user"
                      ~ "\n\nunban <user>\n\tUnban user"
                      ~ "\n\nkick [minutes] <user>\n\tDisconnect user for"
                      ~ " [%d] minutes"
                      ~ "\n\nkickall [minutes]\n\tDisconnect active users for"
                      ~ " [%d] minutes"
                      ~ "\n\naddprivileges <days> <user>\n\tAdd privileges to"
                      ~ " user"
                      ~ "\n\nremoveprivileges [days] <user>\n\tRemove"
                      ~ " privileges from user"
                      ~ "\n\nannouncement <message>\n\tSend announcement to"
                      ~ " online users"
                      ~ "\n\nmessage <message>\n\tSend private message to"
                      ~ " all registered users"
                      ~ "\n\nuptime\n\tShow server uptime")(
                        kick_duration.total!"minutes",
                        kick_duration.total!"minutes"
                    )
                );
                break;

            case "admins":
                Appender!string output;
                const names = db.admins;
                output ~= format!("%d admins.")(names.length);
                foreach (name ; names) {
                    const status = (name in users) ? "online" : "offline";
                    output ~= format!("\n\t%s (%s)")(name, status);
                }

                server_pm(admin_username, output[]);
                break;

            case "users":
                const type = (command.length > 1) ? command[1] : null;
                server_pm(admin_username, user_list(type));
                break;

            case "rooms":
                Appender!string output;
                output ~= format!("%d public rooms.")(rooms.length);
                foreach (room ; rooms)
                    output ~= format!("\n\t%s (users: %d, tickers: %d)")(
                        room.name, room.num_users, room.num_tickers
                    );
                server_pm(admin_username, output[]);
                break;

            case "userinfo":
                if (command.length < 2) {
                    server_pm(admin_username, "Syntax is : userinfo <user>");
                    break;
                }
                const username = command[1 .. $].join(" ");

                if (!db.user_exists(username)) {
                    server_pm(
                        admin_username,
                        format!("User %s is not registered")(username)
                    );
                    break;
                }

                server_pm(admin_username, user_info(username));
                break;

            case "roominfo":
                if (command.length < 2) {
                    server_pm(admin_username, "Syntax is : roominfo <user>");
                    break;
                }
                const name = command[1 .. $].join(" ");

                if (name !in rooms) {
                    server_pm(
                        admin_username,
                        format!("Room %s is not registered")(name)
                    );
                    break;
                }
                server_pm(admin_username, room_info(name));
                break;

            case "ban":
                if (command.length < 2) {
                    server_pm(admin_username, "Syntax is : ban [days] <user>");
                    break;
                }

                Duration duration;
                string username;
                try {
                    duration = command[1]
                        .to!ulong
                        .clamp(0, ushort.max)
                        .days;
                    username = command[2 .. $].join(" ");
                }
                catch (ConvException) {
                    duration = Duration.max;
                    username = command[1 .. $].join(" ");
                }

                if (!db.user_exists(username)) {
                    server_pm(
                        admin_username,
                        format!("User %s is not registered")(username)
                    );
                    break;
                }

                db.ban_user(username, duration);
                del_user_pms(username);
                del_user_tickers(username);

                auto user = get_user(username);
                if (user) del_user(user);

                string response;
                if (duration == Duration.max)
                    response = format!("Banned user %s forever")(username);
                else
                    response = format!("Banned user %s for %s")(
                        username, duration.total!"days".days
                    );

                server_pm(admin_username, response);
                break;

            case "unban":
                if (command.length < 2) {
                    server_pm(admin_username, "Syntax is : unban <user>");
                    break;
                }
                const username = command[1 .. $].join(" ");
                db.unban_user(username);
                server_pm(
                    admin_username,
                    format!("Unbanned user %s")(username)
                );
                break;

            case "kick":
                if (command.length < 2) {
                    server_pm(
                        admin_username, "Syntax is : kick [minutes] <user>"
                    );
                    break;
                }

                Duration duration;
                string username;
                try {
                    duration = command[1]
                        .to!ulong
                        .clamp(0, ushort.max)
                        .minutes;
                    username = command[2 .. $].join(" ");
                }
                catch (ConvException) {
                    duration = kick_duration;
                    username = command[1 .. $].join(" ");
                }

                if (!db.user_exists(username)) {
                    server_pm(
                        admin_username,
                        format!("User %s is not registered")(username)
                    );
                    break;
                }

                db.ban_user(username, duration);

                auto user = get_user(username);
                if (user) del_user(user);

                server_pm(admin_username, format!("Kicked user %s for %s")(
                    username, duration.total!"minutes".minutes
                ));
                break;

            case "kickall":
                Duration duration = kick_duration;
                if (command.length > 1) {
                    try {
                        duration = command[1]
                            .to!ulong
                            .clamp(0, ushort.max)
                            .minutes;
                    }
                    catch (ConvException) {
                        server_pm(
                            admin_username, "Syntax is : kickall [minutes]"
                        );
                        break;
                    }
                }
                Appender!(User[]) users_to_kick;
                foreach (user ; users)
                    if (user.username != admin_username)
                        users_to_kick ~= user;

                foreach (user ; users_to_kick) {
                    db.ban_user(user.username, duration);
                    del_user(user);
                }

                if (log_user) writefln!(
                    "Admin %s kicked ALL %d users for %s!")(
                    blue ~ admin_username ~ norm, users_to_kick[].length,
                    duration
                );
                server_pm(admin_username, format!(
                    "Kicked all %d users for %s")(
                    users_to_kick[].length, duration.total!"minutes".minutes
                ));
                break;

            case "addprivileges":
                if (command.length < 3) {
                    server_pm(
                        admin_username,
                        "Syntax is : addprivileges <days> <user>"
                    );
                    break;
                }

                Duration duration;
                try {
                    duration = command[1]
                        .to!ulong
                        .clamp(0, ushort.max)
                        .days;
                }
                catch (ConvException) {
                    server_pm(
                        admin_username, "Invalid number or too many days"
                    );
                    break;
                }

                const username = command[2 .. $].join(" ");
                if (!db.user_exists(username)) {
                    server_pm(
                        admin_username,
                        format!("User %s is not registered")(username)
                    );
                    break;
                }

                db.add_user_privileges(username, duration);

                auto user = get_user(username);
                if (user) user.refresh_privileges();

                server_pm(admin_username, format!(
                    "Added %s of privileges to user %s")(
                    duration.total!"days".days, username)
                );
                break;

            case "removeprivileges":
                if (command.length < 2) {
                    server_pm(
                        admin_username,
                        "Syntax is : removeprivileges [days] <user>"
                    );
                    break;
                }

                Duration duration;
                string username;
                try {
                    duration = command[1].to!ulong.days;
                    username = command[2 .. $].join(" ");
                }
                catch (ConvException) {
                    duration = Duration.max;
                    username = command[1 .. $].join(" ");
                }

                if (!db.user_exists(username)) {
                    server_pm(
                        admin_username, format!("User %s is not registered")(
                        username)
                    );
                    break;
                }

                db.remove_user_privileges(username, duration);

                auto user = get_user(username);
                if (user) user.refresh_privileges();

                string response;
                if (duration == Duration.max)
                    response = format!(
                        "Removed all privileges from user %s")(username);
                else
                    response = format!(
                        "Removed %s of privileges from user %s")(
                        duration.total!"days".days, username
                    );

                server_pm(admin_username, response);
                break;

            case "announcement":
                if (command.length < 2) {
                    server_pm(
                        admin_username, "Syntax is : announcement <message>"
                    );
                    break;
                }
                const msg = command[1 .. $].join(" ");
                server_announcement(msg);
                break;

            case "message":
                if (command.length < 2) {
                    server_pm(admin_username, "Syntax is : message <message>");
                    break;
                }
                const msg = command[1 .. $].join(" ");
                foreach (username ; db.usernames) server_pm(username, msg);
                break;

            case "uptime":
                const duration = (MonoTime.currTime - started_monotime);
                const response = format!("Running for %s since %s")(
                    duration.total!"seconds".seconds,
                    started_at.toSimpleString
                );
                server_pm(admin_username, response);
                break;

            default:
                server_pm(
                    admin_username,
                    "Don't expect me to understand what you want if you don't "
                  ~ "use a correct command..."
                );
                break;
        }
    }

    void server_pm(string username, string message)
    {
        const pm = add_pm(message, server_username, username);
        const new_message = true;
        send_pm(pm, new_message);
    }

    private void server_announcement(string message)
    {
        scope msg = new SAdminMessage(message);
        foreach (user ; users) user.send_message(msg);
    }
}
