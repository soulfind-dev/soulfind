// SPDX-FileCopyrightText: 2024 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server.server;
@safe:

import core.time : Duration, minutes, MonoTime, seconds;
import soulfind.db;
import soulfind.defines;
import soulfind.server.messages;
import soulfind.server.pm;
import soulfind.server.room;
import soulfind.server.user;
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
    private PM[uint]      pm_list;
    private Room[string]  room_list;
    private User[string]  user_list;


    this(string db_file)
    {
        started_at = MonoTime.currTime;
        db = new Sdb(db_file);
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
            writefln("Unable to bind socket to port %d", port);
            if (port < 1024) writefln(
                "Are you trying to use a port less than "
                ~ "1024 while running as a user ?"
            );
            return 1789;
        }

        writefln(
            "%s %s %s process %d listening on port %d",
            red ~ "♥" ~ norm, bold ~ "Soulfind", VERSION ~ norm,
            thisProcessID, port
        );

        auto read_socks = new SocketSet(max_users + 1);
        auto write_socks = new SocketSet(max_users + 1);

        while (true) {
            read_socks.reset();
            write_socks.reset();
            read_socks.add(sock);

            foreach (user_sock, user ; user_socks) {
                read_socks.add(user_sock);
                if (user.is_sending) write_socks.add(user_sock);
            }

            int nb = Socket.select(read_socks, write_socks, null);
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
                        break;

                    enable_keep_alive(new_sock);
                    new_sock.setOption(
                        SocketOptionLevel.TCP, SocketOption.TCP_NODELAY, 1
                    );
                    new_sock.blocking = false;

                    debug (user) writefln(
                        "Connection accepted from %s", new_sock.remoteAddress
                    );
                    user_socks[new_sock] = new User(
                        this, new_sock,
                        (cast(InternetAddress) new_sock.remoteAddress).addr
                    );
                }
                nb--;
                read_socks.remove(sock);
            }

            foreach (user_sock, user ; user_socks) {
                if (nb == 0)
                    break;

                bool recv_success = true;
                bool send_success = true;
                bool changed;

                if (read_socks.isSet(user_sock)) {
                    recv_success = user.recv_buffer();
                    changed = true;
                }
                if (write_socks.isSet(user_sock)) {
                    send_success = user.send_buffer();
                    changed = true;
                }

                if (user.should_quit && !user.is_sending) {
                    send_success = false;
                }

                if (changed) nb--;
                if (!terminating && recv_success && send_success)
                    continue;

                read_socks.remove(user_sock);
                write_socks.remove(user_sock);
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

    void do_FileSearch(uint token, string query, string username)
    {
        scope msg = new SFileSearch(username, token, query);
        send_to_all(msg);
    }

    void do_UserSearch(uint token, string query, string username, string to)
    {
        auto user = get_user(to);
        if (!user)
            return;

        scope msg = new SFileSearch(username, token, query);
        user.send_message(msg);
    }

    void do_RoomSearch(uint token, string query, string username,
                        string room_name)
    {
        auto room = get_room(room_name);
        if (!room)
            return;

        scope msg = new SFileSearch(username, token, query);
        room.send_to_all(msg);
    }


    // Private Messages

    PM add_pm(string content, string from, string to)
    {
        auto pm = PM(
            new_pm_id,
            Clock.currTime.toUnixTime,
            from,
            to,
            content
        );

        pm_list[pm.id] = pm;
        return pm;
    }

    void del_pm(uint id)
    {
        if (find_pm(id))
            pm_list.remove(id);
    }

    PM[] get_pms_for(string user)
    {
        PM[] pms;
        foreach (pm ; pm_list) if (pm.to == user) pms ~= pm;
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
        foreach (room ; room_list.values) stats[room.name] = room.nb_users;
        return stats;
    }


    // Users

    void add_user(User user)
    {
        user_list[user.username] = user;
    }

    User get_user(string username)
    {
        if (username in user_list)
            return user_list[username];

        return null;
    }

    User[] users()
    {
        return user_list.values;
    }

    private void del_user(User user)
    {
        if (user.sock in user_socks) {
            user.sock.shutdown(SocketShutdown.BOTH);
            user.sock.close();
            user_socks.remove(user.sock);
        }
        if (user.username in user_list) {
            user.quit();
            user_list.remove(user.username);
        }
    }

    private void send_to_all(scope SMessage msg)
    {
        debug (msg) writefln(
            "Transmit=> %s (code %d) to all users...",
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
                    "Available commands :\n\n"
                  ~ "users\n\tList connected users\n\n"
                  ~ "info <user>\n\tInfo about user <user>\n\n"
                  ~ "kickall\n\tDisconnect all users\n\n"
                  ~ "kick <user>\n\tDisconnect <user>\n\n"
                  ~ "[un]ban <user>\n\tUnban or ban and disconnect"
                  ~ " user <user>\n\n"
                  ~ "admins\n\tList admins\n\n"
                  ~ "rooms\n\tList rooms and number of"
                  ~ " occupiants\n\n"
                  ~ "addprivileges <days> <user>\n\tAdd <days>"
                  ~ " days of privileges to user <user>\n\n"
                  ~ "message <message>\n\tSend global message"
                  ~ " <message>\n\n"
                  ~ "uptime\n\tShow server uptime\n\n"
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
                        admin, "User %s does not exist.".format(username)
                    );
                    break;
                }

                user.add_privileges(days * 3600 * 24);
                break;

            case "users":
                const list = "%d connected users.\n\t%s".format(
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
                debug (user) writefln(
                    "Admin %s kicks ALL users...", blue ~ admin.username ~ norm
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
                    admin, "User %s kicked from the server".format(username)
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
                    admin, "User %s banned from the server".format(username)
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
                    admin, "User %s not banned anymore".format(username)
                );
                break;

            case "admins":
                const names = db.admins;
                const list = "%d registered admins.\n\t%s".format(
                    names.length,
                    names.join("\n\t")
                );
                admin_pm(admin, list);
                break;

            case "rooms":
                string list;
                foreach (room ; room_list.values)
                    list ~= "%s:%d ".format(room.name, room.nb_users);
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
        const pm = add_pm(message, server_user, admin.username);
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

        return format(
            "%s: connected at %s"
            ~ "\n\tclient version: %s"
            ~ "\n\taddress: %s"
            ~ "\n\tadmin: %s"
            ~ "\n\tfiles: %s"
            ~ "\n\tdirs: %s"
            ~ "\n\tstatus: %s"
            ~ "\n\tprivileges: %s"
            ~ "\n\tjoined rooms: %s",
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
        foreach (user ; user_list) user.quit();
    }

    private void kick_user(string username)
    {
        auto user = get_user(username);
        if (user) user.quit();
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

        const string[] forbidden_names = [server_user, ""];
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
            debug (user) writefln(
                "New user %s registering", blue ~ username ~ norm
            );
            db.add_user(username, encode_password(password));
            return null;
        }
        debug (user) writefln("User %s is registered", blue ~ username ~ norm);

        if (db.is_banned(username))
            return "BANNED";

        if (!secureEqual(db.get_pass(username), encode_password(password)))
            return "INVALIDPASS";

        return null;
    }
}
