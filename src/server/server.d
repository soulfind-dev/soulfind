// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server.server;
@safe:

import core.time : days, Duration, minutes, MonoTime, seconds;
import soulfind.db : Sdb;
import soulfind.defines : blue, bold, default_port, kick_duration,
                          max_room_name_length, max_search_query_length, norm,
                          red, server_username, VERSION;
import soulfind.server.messages;
import soulfind.server.pm : PM;
import soulfind.server.room : GlobalRoom, Room;
import soulfind.server.user : User;
import std.algorithm : clamp;
import std.conv : ConvException, to;
import std.datetime : Clock, SysTime;
import std.exception : ifThrown;
import std.process : thisProcessID;
import std.socket : InternetAddress, Socket, SocketAcceptException,
                    SocketOption, SocketOptionLevel, SocketOSException,
                    SocketSet, SocketShutdown, TcpSocket;
import std.stdio : writefln;
import std.string : format, join, split, strip;

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
                        new InternetAddress(
                            (cast(InternetAddress)new_sock.remoteAddress).addr,
                            InternetAddress.PORT_ANY
                        )
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

                    if (user.login_rejection || user.login_timed_out)
                        recv_success = send_success = false;
                }
                else if (!send_ready) {
                    write_socks.add(user_sock);
                }

                if (!running || !recv_success || !send_success)
                    users_to_remove ~= user;
            }

            foreach (user ; users_to_remove) del_user(user);
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

    void del_pm(uint id)
    {
        if (find_pm(id))
            pms.remove(id);
    }

    PM[] user_pms(string username)
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
            bold ~ user.address.toAddrString ~ norm,
            bold ~ user.client_version ~ norm
        );
        users[user.username] = user;
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
            if (user.login_rejection) writefln!(
                "User %s @ %s denied (%s)")(
                red ~ username ~ norm,
                bold ~ user.address.toAddrString ~ norm,
                red ~ user.login_rejection ~ norm
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

    private string user_info(string username)
    {
        User user;
        const now = Clock.currTime;
        auto client_version = "none";
        auto address = "none";
        auto connected_at = "none";
        auto status = "offline";
        const admin = db.is_admin(username);
        auto banned = "false";
        auto privileged = "false";
        SysTime privileged_until;
        bool supporter;
        uint speed, upload_number;
        uint shared_files, shared_folders;
        string joined_rooms;

        user = get_user(username);
        if (user) {
            client_version = user.client_version;
            address = user.address.toString;
            connected_at = user.connected_at.toString;
            status = (user.status == Status.away) ? "away" : "online";
            privileged_until = user.privileged_until;
            supporter = user.supporter;
            speed = user.speed;
            upload_number = user.upload_number;
            shared_files = user.shared_files;
            shared_folders = user.shared_folders;
            joined_rooms = user.joined_room_names.join(", ");
        }
        else {
            const user_stats = db.get_user_stats(username);
            privileged_until = db.get_user_privileged_until(username);
            supporter = db.user_supporter(username);
            speed = user_stats.speed;
            upload_number = user_stats.upload_number;
            shared_files = user_stats.shared_files;
            shared_folders = user_stats.shared_folders;
        }

        const banned_until = db.get_user_banned_until(username);
        if (banned_until == SysTime.fromUnixTime(long.max))
            banned = "forever";

        else if (banned_until > now)
            banned = format!("until %s")(banned_until);

        if (privileged_until > now)
            privileged = format!("until %s")(privileged_until);

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
                      ~ "\n\nban [days] <user>\n\tBan user"
                      ~ "\n\nunban <user>\n\tUnban user"
                      ~ "\n\nadmins\n\tList admins"
                      ~ "\n\nrooms\n\tList rooms and number of users"
                      ~ "\n\naddprivileges <days> <user>\n\tAdd privileges to"
                      ~ " user"
                      ~ "\n\nremoveprivileges [days] <user>\n\tRemove"
                      ~ " privileges from user"
                      ~ "\n\nmessage <message>\n\tSend global message"
                      ~ "\n\nuptime\n\tShow server uptime")(
                        kick_duration.total!"minutes",
                        kick_duration.total!"minutes"
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

                Duration duration;
                try {
                    duration = command[1]
                        .to!ulong
                        .clamp(0, ushort.max)
                        .days;
                }
                catch (ConvException) {
                    server_pm(admin, "Invalid number or too many days");
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

                db.add_user_privileges(username, duration);

                auto user = get_user(username);
                if (user) user.refresh_privileges();

                server_pm(admin, format!(
                    "Added %s of privileges to user %s")(
                    duration.total!"days".days, username)
                );
                break;

            case "removeprivileges":
                if (command.length < 2) {
                    server_pm(
                        admin, "Syntax is : removeprivileges [days] <user>"
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
                        admin, format!("User %s is not registered")(
                        username)
                    );
                    break;
                }

                db.remove_user_privileges(username, duration);

                auto user = get_user(username);
                if (user)
                    user.refresh_privileges();

                string response;
                if (duration == Duration.max)
                    response = format!(
                        "Removed all privileges from user %s")(username);
                else
                    response = format!(
                        "Removed %s of privileges from user %s")(
                        duration.total!"days".days, username
                    );

                server_pm(admin, response);
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
                Duration duration = kick_duration;
                if (command.length > 1) {
                    try {
                        duration = command[1]
                            .to!ulong
                            .clamp(0, ushort.max)
                            .minutes;
                    }
                    catch (ConvException) {
                        server_pm(admin, "Syntax is : kickall [minutes]");
                        break;
                    }
                }
                uint num_kicks;
                foreach (user ; users.values) {
                    if (user.username == admin.username)
                        continue;

                    db.ban_user(user.username, duration);
                    del_user(user);
                    num_kicks += 1;
                }
                debug (user) writefln!(
                    "Admin %s kicked ALL %d users for %s!")(
                    blue ~ admin.username ~ norm, num_kicks, duration
                );
                server_pm(admin, format!(
                    "Kicked all %d users for %s")(
                    num_kicks, duration.total!"minutes".minutes)
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
                    server_pm(admin, format!(
                        "User %s is not registered")(username)
                    );
                    break;
                }

                db.ban_user(username, duration);

                auto user = get_user(username);
                if (user) del_user(user);

                server_pm(admin, format!("Kicked user %s for %s")(
                    username, duration.total!"minutes".minutes)
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
                    server_pm(admin, format!(
                        "User %s is not registered")(username)
                    );
                    break;
                }

                db.ban_user(username, duration);

                auto user = get_user(username);
                if (user) del_user(user);

                string response;
                if (duration == Duration.max)
                    response = format!("Banned user %s forever")(username);
                else
                    response = format!("Banned user %s for %s")(
                        username, duration.total!"days".days
                    );

                server_pm(admin, response);
                break;

            case "unban":
                if (command.length < 2) {
                    server_pm(admin, "Syntax is : unban <user>");
                    break;
                }
                const username = command[1 .. $].join(" ");
                db.unban_user(username);
                server_pm(
                    admin, format!("Unbanned user %s")(username)
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
                server_pm(admin, format!("Running for %s")(
                    (MonoTime.currTime - started_at).total!"seconds".seconds)
                );
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
}
