// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server.server;
@safe:

import core.time : Duration, minutes, MonoTime, seconds;
import soulfind.db : Sdb;
import soulfind.defines : blue, bold, default_max_users, default_port, norm,
                          red, server_username, VERSION;
import soulfind.server.messages;
import soulfind.server.pm : PM;
import soulfind.server.room : GlobalRoom, Room;
import soulfind.server.user : User;
import std.algorithm : canFind;
import std.array : join, replace, split;
import std.ascii : isPrintable, isPunctuation;
import std.conv : ConvException, to;
import std.datetime : Clock;
import std.digest : digest, LetterCase, secureEqual, toHexString;
import std.digest.md : MD5;
import std.exception : ifThrown;
import std.format : format;
import std.process : thisProcessID;
import std.socket : InternetAddress, Socket, SocketAcceptException,
                    SocketOption, SocketOptionLevel, SocketOSException,
                    SocketSet, SocketShutdown, TcpSocket;
import std.stdio : writefln;
import std.string : strip;

class Server
{
    Sdb                   db;
    GlobalRoom            global_room;

    private MonoTime      started_at;
    private ushort        port;
    private uint          max_users;

    private User[Socket]  user_socks;
    private SocketSet     read_socks;
    private SocketSet     write_socks;

    private PM[uint]      pm_list;
    private Room[string]  room_list;
    private User[string]  user_list;


    this(string db_filename)
    {
        started_at = MonoTime.currTime;
        db = new Sdb(db_filename);
        global_room = new GlobalRoom();

        port = db.get_config_value("port").to!ushort.ifThrown(
            cast(ushort) default_port
        );
        max_users = db.get_config_value("max_users").to!uint.ifThrown(
            default_max_users
        );
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

        read_socks = new SocketSet(max_users + 1);
        write_socks = new SocketSet(max_users + 1);

        while (true) {
            read_socks.add(sock);

            const nb = Socket.select(read_socks, write_socks, null);
            const terminating = (nb == -1);

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
                        continue;

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

                    if (user.login_denied)
                        recv_success = send_success = false;
                }
                else if (!send_ready) {
                    write_socks.add(user_sock);
                }

                if (terminating || !recv_success || !send_success)
                    del_user(user);
            }

            if (terminating)
                break;
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
        version (FreeBSD) {
            TCP_KEEPIDLE                   = 0x100;
            TCP_KEEPINTVL                  = 0x200;
            TCP_KEEPCNT                    = 0x400;
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
        scope msg = new SFileSearch(username, token, query);
        send_to_all(msg);
    }

    void search_user_files(uint token, string query, string from_username,
                           string to_username)
    {
        auto user = get_user(to_username);
        if (!user)
            return;

        scope msg = new SFileSearch(from_username, token, query);
        user.send_message(msg);
    }

    void search_room_files(uint token, string query, string username,
                           string room_name)
    {
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

        pm_list[pm.id] = pm;
        return pm;
    }

    void del_pm(uint id)
    {
        if (find_pm(id))
            pm_list.remove(id);
    }

    PM[] get_pms_for(string username)
    {
        PM[] pms;
        foreach (pm ; pm_list) if (pm.to_username == username) pms ~= pm;
        return pms;
    }

    private bool find_pm(uint id)
    {
        return(id in pm_list) ? true : false;
    }

    private uint new_pm_id()
    {
        uint id = cast(uint) pm_list.length;
        while (find_pm(id)) id++;
        return id;
    }


    // Rooms

    Room add_room(string name)
    {
        auto room = new Room(name);
        room_list[name] = room;
        return room;
    }

    void del_room(string name)
    {
        if (name in room_list)
            room_list.remove(name);
    }

    Room get_room(string name)
    {
        if (name !in room_list)
            return null;

        return room_list[name];
    }

    ulong[string] room_stats()
    {
        ulong[string] stats;
        foreach (room ; room_list.values) stats[room.name] = room.num_users;
        return stats;
    }


    // Users

    void add_user(User user)
    {
        const username = user.username;

        writefln!("User %s logging in with version %s")(
            blue ~ username ~ norm, user.h_client_version
        );
        if (db.is_admin(username)) writefln!("%s is an admin")(username);
        user_list[username] = user;
    }

    User get_user(string username)
    {
        if (username in user_list)
            return user_list[username];

        return null;
    }

    void del_user(User user)
    {
        const username = user.username;
        auto sock = user.sock;

        if (sock in user_socks) {
            read_socks.remove(sock);
            write_socks.remove(sock);
            user_socks.remove(sock);

            sock.shutdown(SocketShutdown.BOTH);
            sock.close();

            user.sock = null;
        }

        if (username in user_list)
            user_list.remove(username);

        if (user.status == Status.offline)
            return;

        user.leave_joined_rooms();
        global_room.remove_user(username);

        user.set_status(Status.offline);
        writefln!("User %s has quit")(red ~ username ~ norm);
    }

    User[] users()
    {
        return user_list.values;
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
                admin_pm(
                    admin,
                    "Available commands :"
                  ~ "\n\nusers\n\tList connected users"
                  ~ "\n\ninfo <user>\n\tInfo about user <user>"
                  ~ "\n\nkickall\n\tDisconnect all users"
                  ~ "\n\nkick <user>\n\tDisconnect <user>"
                  ~ "\n\n[un]ban <user>\n\tBan/unban and disconnect user"
                  ~ " <user>"
                  ~ "\n\nadmins\n\tList admins"
                  ~ "\n\nrooms\n\tList rooms and number of occupiants"
                  ~ "\n\naddprivileges <days> <user>\n\tAdd <days> days of"
                  ~ " privileges to user <user>"
                  ~ "\n\nmessage <message>\n\tSend global message <message>"
                  ~ "\n\nuptime\n\tShow server uptime"
                );
                break;

            case "addprivileges":
                if (command.length < 3) {
                    admin_pm(admin, "Syntax is : addprivileges <days> <user>");
                    break;
                }

                uint days;
                try {
                    days = command[1].to!uint;
                }
                catch (ConvException e) {
                    admin_pm(admin, "Badly formatted number.");
                    break;
                }

                const username = command[2 .. $].join(" ");
                auto user = get_user(username);
                if (!user) {
                    admin_pm(
                        admin, format!("User %s does not exist.")(username)
                    );
                    break;
                }

                user.add_privileges(days * 3600 * 24);
                break;

            case "users":
                const list = format!("%d connected users.\n\t%s")(
                    user_list.length,
                    user_list.keys.join("\n\t")
                );
                admin_pm(admin, list);
                break;

            case "info":
                if (command.length < 2) {
                    admin_pm(admin, "Syntax is : info <user>");
                    break;
                }
                const username = command[1 .. $].join(" ");
                const user_info = show_user(username);
                admin_pm(admin, user_info);
                break;

            case "kickall":
                debug (user) writefln!("Admin %s kicks ALL users...")(
                    blue ~ admin.username ~ norm
                );
                kick_all_users();
                break;

            case "kick":
                if (command.length < 2) {
                    admin_pm(admin, "Syntax is : kick <user>");
                    break;
                }
                const username = command[1 .. $].join(" ");
                kick_user(username);
                admin_pm(
                    admin, format!("User %s kicked from the server")(username)
                );
                break;

            case "ban":
                if (command.length < 2) {
                    admin_pm(admin, "Syntax is : ban <user>");
                    break;
                }
                const username = command[1 .. $].join(" ");
                ban_user(username);
                admin_pm(
                    admin, format!("User %s banned from the server")(username)
                );
                break;

            case "unban":
                if (command.length < 2) {
                    admin_pm(admin, "Syntax is : unban <user>");
                    break;
                }
                const username = command[1 .. $].join(" ");
                unban_user(username);
                admin_pm(
                    admin, format!("User %s not banned anymore")(username)
                );
                break;

            case "admins":
                const names = db.admins;
                const list = format!("%d registered admins.\n\t%s")(
                    names.length,
                    names.join("\n\t")
                );
                admin_pm(admin, list);
                break;

            case "rooms":
                string list;
                foreach (room ; room_list.values)
                    list ~= format!("%s:%d ")(room.name, room.num_users);
                admin_pm(admin, list);
                break;

            case "message":
                if (command.length < 2) {
                    admin_pm(admin, "Syntax is : message <message>");
                    break;
                }
                const msg = command[1 .. $].join(" ");
                global_message(msg);
                break;

            case "uptime":
                admin_pm(admin, h_uptime);
                break;

            default:
                admin_pm(
                    admin,
                    "Don't expect me to understand what you want if you don't "
                  ~ "use a correct command..."
                );
                break;
        }
    }

    private void admin_pm(User admin, string message)
    {
        const pm = add_pm(message, server_username, admin.username);
        const new_message = true;
        admin.send_pm(pm, new_message);
    }

    private void global_message(string message)
    {
        scope msg = new SAdminMessage(message);
        foreach (user ; user_list) {
            user.send_message(msg);
        }
    }

    private string show_user(string username)
    {
        auto user = get_user(username);
        if (!user)
            return "";

        return format!(
            "%s: connected at %s"
          ~ "\n\tclient version: %s"
          ~ "\n\taddress: %s"
          ~ "\n\tadmin: %s"
          ~ "\n\tfiles: %s"
          ~ "\n\tdirs: %s"
          ~ "\n\tstatus: %s"
          ~ "\n\tprivileges: %s"
          ~ "\n\tjoined rooms: %s")(
            username,
            user.connected_at,
            user.h_client_version,
            user.h_address,
            db.is_admin(username),
            user.shared_files,
            user.shared_folders,
            user.status,
            user.h_privileges,
            user.h_joined_rooms
        );
    }

    private void kick_all_users()
    {
        foreach (user ; user_list) del_user(user);
    }

    private void kick_user(string username)
    {
        auto user = get_user(username);
        if (user) del_user(user);
    }

    private void ban_user(string username)
    {
        if (!db.user_exists(username))
            return;

        db.user_update_field(username, "banned", 1);
        kick_user(username);
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
            .replace("%users%", user_list.length.to!string)
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

    string encode_password(string pass)
    {
        return digest!MD5(pass).toHexString!(LetterCase.lower).to!string;
    }

    bool check_name(string text, uint max_length = 24)
    {
        if (!text || text.length > max_length) {
            return false;
        }
        foreach (c ; text) if (!isPrintable(c)) {
            // non-ASCII control chars, etc
            return false;
        }
        if (text.length == 1 && isPunctuation(text.to!dchar)) {
            // only character is a symbol
            return false;
        }
        if (strip(text) != text) {
            // leading/trailing whitespace
            return false;
        }

        const string[] forbidden_names = [server_username, ""];
        const string[] forbidden_words = ["  ", "sqlite3_"];

        foreach (name ; forbidden_names) if (name == text) {
            return false;
        }
        foreach (word ; forbidden_words) if (canFind(text, word)) {
            return false;
        }
        return true;
    }

    string check_login(string username, string password)
    {
        if (!check_name(username, 30))
            return "INVALIDUSERNAME";

        if (!db.user_exists(username)) {
            debug (user) writefln!("New user %s registering")(
                blue ~ username ~ norm
            );
            db.add_user(username, encode_password(password));
            return null;
        }
        debug (user) writefln!("User %s is registered")(
            blue ~ username ~ norm
        );

        if (db.is_banned(username))
            return "BANNED";

        if (!secureEqual(db.get_pass(username), encode_password(password)))
            return "INVALIDPASS";

        return null;
    }
}
