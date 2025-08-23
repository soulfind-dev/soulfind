// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server.server;
@safe:

import core.time : days, Duration, minutes, MonoTime, seconds;
import soulfind.db : Sdb;
import soulfind.defines : blue, bold, check_user_interval, conn_backlog_length,
                          kick_duration, log_msg, log_user,
                          max_global_recommendations, max_room_name_length,
                          max_search_query_length, max_user_recommendations,
                          norm, red, server_username, VERSION;
import soulfind.select : DefaultSelector, SelectEvent, Selector;
import soulfind.server.messages;
import soulfind.server.pm : PM;
import soulfind.server.room : GlobalRoom, Room;
import soulfind.server.user : User;
import std.algorithm : clamp, sort;
import std.array : Appender, array;
import std.conv : ConvException, to;
import std.datetime : Clock, SysTime;
import std.process : thisProcessID;
import std.socket : InternetAddress, Socket, socket_t, SocketAcceptException,
                    SocketOption, SocketOptionLevel, SocketOSException,
                    SocketShutdown, TcpSocket;
import std.stdio : writefln, writeln;
import std.string : format, join, split;

version (unittest) {
    auto running = true;
}
else {
    import soulfind.main : running;
}

final class Server
{
    Sdb                     db;
    Selector                selector;
    GlobalRoom              global_room;

    private SysTime         started_at;
    private MonoTime        started_monotime;
    private MonoTime        last_user_check;
    private ushort          port;

    private User[string]    users;
    private User[socket_t]  sock_users;
    private PM[uint]        pms;
    private Room[string]    rooms;


    this(string db_filename, ushort port = 0)
    {
        this.db                = new Sdb(db_filename);
        this.port              = port > 0 ? port : db.server_port;
        this.selector          = new DefaultSelector(1.seconds);
        this.started_at        = Clock.currTime;
        this.started_monotime  = MonoTime.currTime;
        this.global_room       = new GlobalRoom();
    }


    // Connections

    int listen()
    {
        auto listen_sock = new TcpSocket();
        listen_sock.blocking = false;

        version (Posix)
            listen_sock.setOption(
                SocketOptionLevel.SOCKET, SocketOption.REUSEADDR, 1);

        try {
            auto listen_address = new InternetAddress(port);
            listen_sock.bind(listen_address);
            listen_sock.listen(conn_backlog_length);
        }
        catch (SocketOSException e) {
            const min_port = 1024;
            writefln!("Unable to bind socket to port %d")(port);
            if (port < min_port) writefln!(
                "Are you trying to use a port less than %d while running as "
              ~ "a user?")(
                 min_port
            );
            return 1;
        }

        writefln!("%s %s %s process %d listening on port %d")(
            red ~ "\&hearts;" ~ norm, bold ~ "Soulfind", VERSION ~ norm,
            thisProcessID, port
        );

        selector.register(listen_sock.handle, SelectEvent.read);

        while (running) {
            const ready_sock_handles = selector.select();
            Appender!(User[]) users_to_disconnect;

            foreach (sock_handle, events ; ready_sock_handles) {
                const recv_ready = (events & SelectEvent.read) != 0;
                const send_ready = (events & SelectEvent.write) != 0;

                if (sock_handle == listen_sock.handle) {
                    if (recv_ready) accept(listen_sock);
                    continue;
                }

                auto user = sock_users[sock_handle];
                bool recv_success = true;
                bool send_success = true;

                if (recv_ready)
                    recv_success = user.recv_buffer();

                if (send_ready)
                    send_success = user.send_buffer();

                if (!user.is_sending) {
                    if (user.removed) {
                        // In order to avoid closing connections early before
                        // delivering e.g. a Relogged message, we disconnect
                        // the user here after the output buffer is sent
                        users_to_disconnect ~= user;
                    }
                    else if (user.login_rejection.reason) {
                        recv_success = send_success = false;
                    }
                }

                if (!running || !recv_success || !send_success) {
                    del_user(user);
                    users_to_disconnect ~= user;
                }
            }

            const curr_time = MonoTime.currTime;
            if ((curr_time - last_user_check) >= check_user_interval) {
                foreach (ref user ; sock_users) {
                    if (user.username in users) {
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
                    }
                    else if (user.login_timed_out) {
                        del_user(user);
                        users_to_disconnect ~= user;
                    }
                }
                last_user_check = curr_time;
            }

            foreach (ref user ; users_to_disconnect) {
                selector.unregister(
                    user.sock.handle, SelectEvent.read | SelectEvent.write
                );
                sock_users.remove(user.sock.handle);

                user.sock.shutdown(SocketShutdown.BOTH);
                user.sock.close();

                if (log_user) writefln!("Closed connection to user %s")(
                    user.username
                );
                user.sock = null;
            }
        }
        return 0;
    }

    private void accept(Socket listen_sock)
    {
        while (true) {
            Socket sock;
            try
                sock = listen_sock.accept();
            catch (SocketAcceptException)
                break;

            if (!sock.isAlive)
                break;

            enable_keep_alive(sock);
            sock.setOption(
                SocketOptionLevel.TCP, SocketOption.TCP_NODELAY, 1
            );
            sock.blocking = false;

            if (log_user) writeln("Connection attempt accepted");
            sock_users[sock.handle] = new User(
                this, sock,
                new InternetAddress(
                    (cast(InternetAddress)sock.remoteAddress).addr,
                    InternetAddress.PORT_ANY
                )
            );
            selector.register(sock.handle, SelectEvent.read);
        }
    }

    private void enable_keep_alive(Socket sock)
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
        version (FreeBSD) {
            TCP_KEEPIDLE                   = 0x100;
            TCP_KEEPINTVL                  = 0x200;
            TCP_KEEPCNT                    = 0x400;
        }
        version (NetBSD) {
            TCP_KEEPIDLE                   = 0x3;
            TCP_KEEPINTVL                  = 0x5;
            TCP_KEEPCNT                    = 0x6;
        }
        version (DragonFlyBSD) {
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
        if (user is null)
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
        if (room is null)
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
        foreach (ref pm ; pms) {
            if (pm.from_username == username
                    || (include_received && pm.to_username == username))
                pms_to_remove ~= pm;
        }
        foreach (ref pm ; pms_to_remove) pms.remove(pm.id);
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
        if (user is null)
            return;

        scope msg = new SMessageUser(
            pm.id, pm.time, pm.from_username, pm.message, new_message
        );
        user.send_message!"log_redacted"(msg);
    }

    void send_queued_pms(string username)
    {
        foreach (ref pm ; pms) {
            if (pm.to_username != username)
                continue;

            const new_message = false;
            send_pm(pm, new_message);
        }
    }


    // Interests

    LimitedRecommendations global_recommendations()
    {
        int[string] recommendations;
        foreach (user ; users) {
            foreach (ref item ; user.liked_item_names) recommendations[item]++;
            foreach (ref item ; user.hated_item_names) recommendations[item]--;
        }
        return LimitedRecommendations(
            filter_recommendations(
                recommendations, max_global_recommendations
            ),
            filter_recommendations(
                recommendations, max_global_recommendations, true
            )
        );
    }

    LimitedRecommendations user_recommendations(string username)
    {
        auto user = get_user(username);
        if (user is null)
            return LimitedRecommendations();

        int[string] recommendations;
        auto liked_item_names = user.liked_item_names;
        auto hated_item_names = user.hated_item_names;

        foreach (ref other_user ; users) {
            if (other_user.username == username)
                continue;

            int weight;
            foreach (ref item ; liked_item_names) {
                if (other_user.likes(item)) weight++;
                if (other_user.hates(item)) weight--;
            }
            foreach (ref item ; hated_item_names) {
                if (other_user.hates(item)) weight++;
                if (other_user.likes(item)) weight--;
            }

            if (weight == 0)
                continue;

            foreach (ref item ; other_user.liked_item_names)
                if (!user.likes(item) && !user.hates(item))
                    recommendations[item] += weight;

            foreach (ref item ; other_user.hated_item_names)
                if (!user.likes(item) && !user.hates(item))
                    recommendations[item] -= weight;
        }
        return LimitedRecommendations(
            filter_recommendations(
                recommendations, max_user_recommendations
            ),
            filter_recommendations(
                recommendations, max_user_recommendations, true
            )
        );
    }

    int[string] item_recommendations(string item)
    {
        int[string] recommendations;
        foreach (ref user ; users) {
            int weight;
            if (user.likes(item)) weight++;
            if (user.hates(item)) weight--;

            if (weight == 0)
                continue;

            foreach (ref recommendation ; user.liked_item_names)
                if (recommendation != item)
                    recommendations[recommendation] += weight;

            foreach (ref recommendation ; user.hated_item_names)
                if (recommendation != item)
                    recommendations[recommendation] -= weight;
        }
        return filter_recommendations(recommendations, size_t.max);
    }

    uint[string] user_similar_users(string username)
    {
        uint[string] usernames;
        const user = get_user(username);
        if (user is null)
            return usernames;

        auto liked_item_names = user.liked_item_names;
        auto hated_item_names = user.hated_item_names;

        foreach (ref other_user ; users) {
            if (other_user.username == username)
                continue;

            int weight;
            foreach (ref item ; liked_item_names) {
                if (other_user.likes(item)) weight++;
                if (other_user.hates(item)) weight--;
            }
            foreach (ref item ; hated_item_names) {
                if (other_user.hates(item)) weight++;
                if (other_user.likes(item)) weight--;
            }
            if (weight > 0) usernames[other_user.username] = cast(uint) weight;
        }
        return usernames;
    }

    string[] item_similar_users(string item)
    {
        Appender!(string[]) usernames;
        foreach (ref user ; users) {
            if (user.likes(item)) usernames ~= user.username;
        }
        return usernames[];
    }

    private int[string] filter_recommendations(
        int[string] recommendations, size_t max_length, bool ascending = false)
    {
        int[string] filtered_recommendations;
        auto recommendations_array = recommendations.byKeyValue.array;
        recommendations_array.sort!(
            (ref a, ref b)
            => ascending ? a.value < b.value : a.value > b.value
        );

        foreach (i, ref item; recommendations_array) {
            const rating = item.value;
            if (i >= max_length)
                break;
            if (rating != 0) filtered_recommendations[item.key] = rating;
        }
        return filtered_recommendations;
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
        foreach (ref room ; rooms) room.del_ticker(username);
    }

    Room get_room(string name)
    {
        if (name !in rooms)
            return null;

        return rooms[name];
    }

    uint[string] room_stats()
    {
        uint[string] stats;
        foreach (ref room ; rooms)
            stats[room.name] = cast(uint) room.num_users;
        return stats;
    }

    void send_to_joined_rooms(string sender_username, scope SMessage msg)
    {
        if (log_msg) writefln!(
            "Transmit=> %s (code %d) to user %s's joined rooms...")(
            blue ~ msg.name ~ norm, msg.code, blue ~ sender_username ~ norm
        );
        foreach (ref user ; users)
            if (user.joined_same_room(sender_username))
                user.send_message!"log_disabled"(msg);
    }

    private string room_info(string name)
    {
        Appender!string output;
        auto room = rooms[name];

        output ~= name;
        output ~= format!("\nUsers (%d):")(room.num_users);
        foreach (ref username ; room.usernames)
            output ~= format!("\n\t%s")(username);

        output ~= format!("\nTickers (%d):")(room.num_tickers);
        foreach (ref ticker ; room.tickers_by_order)
            output ~= format!("\n\t[%s] %s")(ticker.username, ticker.content);

        return output[];
    }


    // Users

    void add_user(User user)
    {
        writefln!(
            "%s %s logged in with client version %s")(
            db.is_admin(user.username) ? "Admin" : "User",
            blue ~ user.username ~ norm,
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

        if (user.status == UserStatus.offline) {
            if (user.login_rejection.reason) writefln!(
                "User %s denied (%s)")(
                red ~ username ~ norm,
                red ~ user.login_rejection.reason ~ norm
            );
            return;
        }

        user.leave_joined_rooms();
        global_room.remove_user(username);

        user.update_status(UserStatus.offline);
        writefln!("User %s logged out")(red ~ username ~ norm);
    }

    User get_user(string username)
    {
        if (username in users)
            return users[username];

        return null;
    }

    size_t num_users()
    {
        return users.length;
    }

    private string user_list(string type = null)
    {
        Appender!string output;
        switch (type)
        {
            case "connected":
                output ~= format!("%d connected users.")(users.length);
                foreach (ref user ; users)
                    output ~= format!("\n\t%s (client version: %s)")(
                        user.username, user.client_version
                    );
                break;

            case "privileged":
                const users = db.usernames(
                    "privileges", Clock.currTime.toUnixTime
                );
                output ~= format!("%d privileged users.")(users.length);
                foreach (ref user ; users) {
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
                output ~= format!("%d banned users.")(users.length);
                foreach (ref user ; users) {
                    const banned_until = db.user_banned_until(user);
                    if (banned_until == SysTime.fromUnixTime(long.max))
                        output ~= format!("\n\t%s (forever)")(user);
                    else
                        output ~= format!("\n\t%s (until %s)")(
                            user, banned_until.toSimpleString);
                }
                break;

            case null:
                const usernames = db.usernames;
                output ~= format!("%d total users.")(usernames.length);
                foreach (ref username ; db.usernames)
                    output ~= format!("\n\t%s")(username);
                break;

            default:
                output ~= "Syntax is : users [connected|banned|privileged]";

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
        auto obfuscation_type = "none";
        ushort obfuscated_port;
        size_t watched_users;
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
        if (user !is null) {
            status = user.status.to!string;
            client_version = user.client_version;
            ip_address = user.address.toAddrString;
            listening_port = user.address.port;
            obfuscation_type = user.obfuscation_type.to!string;
            obfuscated_port = user.obfuscated_port;
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
            supporter = privileged_until.stdTime > 0;
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
          ~ "\n\tstatus: %s"
          ~ "\n\tclient version: %s"
          ~ "\n\tIP address: %s"
          ~ "\n\tport: %s"
          ~ "\n\tobfuscated port: %s"
          ~ "\n\tobfuscation type: %s"
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
            status,
            client_version,
            ip_address,
            listening_port,
            obfuscated_port,
            obfuscation_type,
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
        foreach (ref user ; users) user.send_message!"log_disabled"(msg);
    }

    void send_to_watching(string sender_username, scope SMessage msg)
    {
        if (log_msg) writefln!(
            "Transmit=> %s (code %d) to users watching user %s...")(
            blue ~ msg.name ~ norm, msg.code, blue ~ sender_username ~ norm
        );
        foreach (ref user ; users)
            if (user.is_watching(sender_username)
                    || user.joined_same_room(sender_username))
                user.send_message!"log_disabled"(msg);
    }

    void user_command(string sender_username, string message)
    {
        if (db.is_admin(sender_username)) {
            admin_command(sender_username, message);
            return;
        }

        const command = message.split(" ");
        if (command.length > 0) switch (command[0])
        {
            case "help":
                server_pm(
                    sender_username,
                    "Available commands :"
                  ~ " None"
                );
                break;

            default:
                server_unknown_command(sender_username, command[0]);
                break;
        }
    }

    private void admin_command(string admin_username, string message)
    {
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
                      ~ "\n\nremovetickers <user>\n\tRemove user's public room"
                      ~ " tickers"
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
                foreach (ref name ; names) {
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
                foreach (ref room ; rooms)
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
                if (user !is null) del_user(user);

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
                if (user !is null) del_user(user);

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
                foreach (ref user ; users)
                    if (user.username != admin_username)
                        users_to_kick ~= user;

                foreach (ref user ; users_to_kick) {
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
                if (user !is null) user.refresh_privileges();

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
                if (user !is null) user.refresh_privileges();

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

            case "removetickers":
                if (command.length < 2) {
                    server_pm(
                        admin_username, "Syntax is : removetickers <user>"
                    );
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
                del_user_tickers(username);
                server_pm(
                    admin_username,
                    format!("Removed user %s's public room tickers")(username)
                );
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
                foreach (ref username ; db.usernames) server_pm(username, msg);
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
                server_unknown_command(admin_username, command[0]);
                break;
        }
    }

    void server_pm(string username, string message)
    {
        const pm = add_pm(message, server_username, username);
        const new_message = true;
        send_pm(pm, new_message);
    }

    private void server_unknown_command(string username, string command)
    {
        server_pm(
            username,
            format!(
                "Unknown command '%s'. "
              ~ "Type 'help' to list available commands.")(
                command
            )
        );
    }

    private void server_announcement(string message)
    {
        scope msg = new SAdminMessage(message);
        foreach (ref user ; users) user.send_message(msg);
    }
}
