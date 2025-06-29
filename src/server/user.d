// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server.user;
@safe:

import core.time : days, Duration, seconds;
import soulfind.db : SdbUserStats;
import soulfind.defines : blue, bold, default_max_users, login_timeout,
                          max_chat_message_length, max_interest_length,
                          max_msg_size, max_room_name_length,
                          max_username_length, norm, red, server_username,
                          VERSION;
import soulfind.server.messages;
import soulfind.server.pm : PM;
import soulfind.server.room : Room;
import soulfind.server.server : Server;
import std.algorithm : canFind, clamp;
import std.ascii : isASCII, isPunctuation;
import std.bitmanip : Endian, nativeToLittleEndian, peek, read;
import std.conv : to;
import std.datetime : Clock, SysTime;
import std.digest : digest, LetterCase, secureEqual, toHexString;
import std.digest.md : MD5;
import std.exception : ifThrown;
import std.random : uniform;
import std.socket : InternetAddress, Socket;
import std.stdio : writefln;
import std.string : format, join, replace, strip;

class User
{
    string                  username;
    Socket                  sock;
    InternetAddress         address;

    uint                    status;
    string                  client_version;
    SysTime                 connected_at;
    string                  login_rejection;
    SysTime                 privileged_until;
    bool                    supporter;

    uint                    speed;                // in B/s
    uint                    upload_number;
    uint                    shared_files;
    uint                    shared_folders;
    string                  country_code;

    private Server          server;

    private string[string]  liked_items;
    private string[string]  hated_items;

    private Room[string]    joined_rooms;

    private string[string]  watched_users;

    private ubyte[]         in_buf;
    private long            in_msg_size = -1;
    private ubyte[]         out_buf;


    this(Server serv, Socket sock, InternetAddress address)
    {
        this.server        = serv;
        this.sock          = sock;
        this.address       = address;
        this.connected_at  = Clock.currTime;
    }


    // Login

    string motd()
    {
        return server.db.get_config_value("motd")
            .replace("%sversion%", VERSION)
            .replace("%users%", server.users.length.to!string)
            .replace("%username%", username)
            .replace("%version%", client_version);
    }

    bool login_timed_out()
    {
        if (status != Status.offline)
            return false;

        // Login attempts always time out for banned users. Add jitter to
        // login timeout to spread out reconnect attempts after e.g. kicking
        // all online users, which also bans them for a few minutes.
        const login_timeout = login_timeout + uniform(0, 30).seconds;
        return (Clock.currTime - connected_at) > login_timeout;
    }

    private bool check_name(string text, uint max_length)
    {
        if (text.length == 0 || text.length > max_length) {
            return false;
        }
        foreach (c ; text) if (!c.isASCII) {
            // non-ASCII control chars, etc
            return false;
        }
        if (text.length == 1 && isPunctuation(text[0])) {
            // only character is a symbol
            return false;
        }
        if (text.strip != text) {
            // leading/trailing whitespace
            return false;
        }

        static immutable forbidden_names = [server_username];
        static immutable forbidden_words = ["  "];

        foreach (name ; forbidden_names) if (name == text) {
            return false;
        }
        foreach (word ; forbidden_words) if (text.canFind(word)) {
            return false;
        }
        return true;
    }

    private string encode_password(string password)
    {
        return digest!MD5(password).toHexString!(LetterCase.lower).to!string;
    }

    private string verify_login(string username, string password)
    {
        const max_users = server.db.get_config_value("max_users")
            .to!uint
            .ifThrown(default_max_users);

        if (server.users.length >= max_users)
            return "SVRFULL";

        if (!check_name(username, max_username_length))
            return "INVALIDUSERNAME";

        if (!server.db.user_exists(username)) {
            debug (user) writefln!("New user %s registering")(
                blue ~ username ~ norm
            );
            server.db.add_user(username, encode_password(password));
            return null;
        }
        debug (user) writefln!("User %s is registered")(
            blue ~ username ~ norm
        );

        if (!secureEqual(
                server.db.get_pass(username), encode_password(password)))
            return "INVALIDPASS";

        return null;
    }


    // Status

    void update_status(uint new_status)
    {
        if (new_status == status)
            return;

        final switch (new_status) {
            case Status.offline:
            case Status.away:
            case Status.online:
                status = new_status;
                scope msg = new SGetUserStatus(
                    username, new_status, privileged
                );
                send_to_watching(msg);
                break;
        }
    }


    // Stats

    private void calc_speed(uint new_speed)
    {
        if (upload_number == 0) {
            upload_number = 1;
            speed = new_speed;
        }
        else {
            speed = (speed * upload_number + new_speed) / (upload_number + 1);
            upload_number++;
        }

        scope msg = new SGetUserStats(
            username, speed, upload_number, shared_files, shared_folders
        );
        send_to_watching(msg);

        auto stats = SdbUserStats();
        stats.speed = speed;
        stats.updating_speed = true;

        server.db.user_update_stats(username, stats);
    }

    private void update_shared_stats(uint new_files, uint new_folders)
    {
        shared_files = new_files;
        shared_folders = new_folders;

        auto stats = SdbUserStats();
        stats.shared_files = new_files;
        stats.shared_folders = new_folders;
        stats.updating_shared = true;

        server.db.user_update_stats(username, stats);
    }


    // Privileges

    void refresh_privileges(bool notify_user = true)
    {
        privileged_until = server.db.get_user_privileged_until(username);
        supporter = server.db.user_supporter(username);

        if (!notify_user)
            return;

        scope msg = new SCheckPrivileges(
            cast(uint) privileges
                .total!"seconds"
                .clamp(0, uint.max)
        );
        send_message(msg);
    }

    bool privileged()
    {
        return privileged_until > Clock.currTime;
    }

    private Duration privileges()
    {
        if (privileged)
            return privileged_until - Clock.currTime;

        return 0.seconds;
    }


    // Watchlist

    private void watch(string peer_username)
    {
        if (peer_username != server_username)
            watched_users[peer_username] = peer_username;
    }

    private void unwatch(string peer_username)
    {
        if (peer_username == username)
            // Always watch our own username for updates
            return;

        if (peer_username in watched_users)
            watched_users.remove(peer_username);
    }

    private bool is_watching(string peer_username)
    {
        if (peer_username in watched_users)
            return true;

        foreach (room ; joined_rooms)
            if (room.is_joined(peer_username))
                return true;

        return false;
    }

    private void send_to_watching(scope SMessage msg)
    {
        debug (msg) writefln!(
            "Transmit=> %s (code %d) to users watching user %s...")(
            blue ~ msg.name ~ norm, msg.code, blue ~ username ~ norm
        );
        foreach (user ; server.users)
            if (user.is_watching(username)) user.send_message(msg);
    }


    // Interests

    private void add_liked_item(string item)
    {
        if (item.length > max_interest_length)
            return;

        if (likes(item))
            return;

        liked_items[item] = item;
    }

    private void del_liked_item(string item)
    {
        if (likes(item)) liked_items.remove(item);
    }

    private void add_hated_item(string item)
    {
        if (item.length > max_interest_length)
            return;

        if (hates(item))
            return;

        hated_items[item] = item;
    }

    private void del_hated_item(string item)
    {
        if (hates(item)) hated_items.remove(item);
    }

    private bool likes(string item)
    {
        return item in liked_items ? true : false;
    }

    private bool hates(string item)
    {
        return item in hated_items ? true : false;
    }

    private uint[string] global_recommendations()
    {
        uint[string] recommendations;
        foreach (user ; server.users)
            foreach (item ; user.liked_items) recommendations[item]++;

        return recommendations;
    }

    private uint[string] recommendations()
    {
        uint[string] recommendations;
        foreach (user ; server.users) {
            if (user is this)
                continue;

            int weight;
            foreach (item ; liked_items) {
                if (user.likes(item)) weight++;
                if (user.hates(item) && weight > 0) weight--;
            }
            foreach (item ; hated_items) {
                if (user.hates(item)) weight++;
                if (user.likes(item) && weight > 0) weight--;
            }
            if (weight > 0) foreach (item ; user.liked_items)
                recommendations[item] += weight;
        }
        return recommendations;
    }

    private uint[string] similar_users()
    {
        uint[string] usernames;
        foreach (user ; server.users) {
            if (user is this)
                continue;

            int weight;
            foreach (item ; liked_items) {
                if (user.likes(item)) weight++;
                if (user.hates(item) && weight > 0) weight--;
            }
            foreach (item ; hated_items) {
                if (user.hates(item)) weight++;
                if (user.likes(item) && weight > 0) weight--;
            }
            if (weight > 0) usernames[user.username] = weight;
        }
        return usernames;
    }

    private uint[string] item_recommendations(string item)
    {
        uint[string] recommendations;
        foreach (user ; server.users) {
            if (user is this)
                continue;

            int weight;
            if (user.likes(item)) weight++;
            if (user.hates(item) && weight > 0) weight--;
            if (weight > 0) foreach (recommendation ; user.liked_items)
                recommendations[recommendation] += weight;
        }
        return recommendations;
    }

    private string[] item_similar_users(string item)
    {
        string[] usernames;
        foreach (user ; server.users) {
            if (user is this)
                continue;
            if (user.likes(item)) usernames ~= user.username;
        }
        return usernames;
    }


    // Private Messages

    void send_pm(PM pm, bool new_message)
    {
        scope msg = new SMessageUser(
            pm.id, cast(uint) pm.time.toUnixTime.clamp(0, uint.max),
            pm.from_username, pm.message, new_message
        );
        send_message(msg);
    }


    // Rooms

    void join_room(string name)
    {
        string fail_message;
        if (name.length <= 0)
            fail_message = "Could not create room. Reason: Room name empty.";
        else if (name.length > max_room_name_length)
            fail_message = format!(
                "Could not create room. Reason: Room name %s longer than %d "
              ~ "characters.")(
                name, max_room_name_length
            );
        else if (name.strip != name)
            fail_message = format!(
                "Could not create room. Reason: Room name %s contains leading "
              ~ "or trailing spaces.")(
                name
            );
        else if (name.canFind("  "))
            fail_message = format!(
                "Could not create room. Reason: Room name %s contains "
              ~ "multiple following spaces.")(
                name
            );
        else
            foreach (c ; name) {
                if (!c.isASCII) {
                    fail_message = format!(
                        "Could not create room. Reason: Room name %s contains "
                      ~ "invalid characters.")(
                        name
                    );
                    break;
                }
            }

        if (fail_message) {
            server.server_pm(this, fail_message);
            return;
        }

        auto room = server.get_room(name);
        if (!room) room = server.add_room(name);

        joined_rooms[name] = room;
        room.add_user(this);
    }

    bool leave_room(string name)
    {
        if (name !in joined_rooms)
            return false;

        auto room = server.get_room(name);

        room.remove_user(username);
        joined_rooms.remove(name);

        if (room.num_users == 0)
            server.del_room(name);

        return true;
    }

    void leave_joined_rooms()
    {
        foreach (name, room ; joined_rooms) leave_room(name);
    }

    string[] joined_room_names()
    {
        return joined_rooms.keys;
    }


    // Messages

    bool is_sending()
    {
        return out_buf.length > 0;
    }

    bool send_buffer()
    {
        const send_len = sock.send(out_buf);
        if (send_len == Socket.ERROR)
            return false;

        out_buf = out_buf[send_len .. $];
        return true;
    }

    void send_message(scope SMessage msg)
    {
        const msg_buf = msg.bytes;
        const msg_len = cast(uint) msg_buf.length;
        const offset = out_buf.length;

        out_buf.length += (uint.sizeof + msg_len);
        out_buf[offset .. offset + uint.sizeof] = msg_len.nativeToLittleEndian;
        out_buf[offset + uint.sizeof .. $] = msg_buf;

        debug (msg) writefln!(
            "Sending -> %s (code %d) of %d bytes -> to user %s")(
            blue ~ msg.name ~ norm, msg.code, msg_len, blue ~ username ~ norm
        );
    }

    bool recv_buffer()
    {
        ubyte[max_msg_size] receive_buf;
        const receive_len = sock.receive(receive_buf);
        if (receive_len == Socket.ERROR || receive_len == 0)
            return false;

        in_buf ~= receive_buf[0 .. receive_len];

        while (recv_message()) {
            // disconnect the user if message is incorrect/bogus
            if (in_msg_size < 0 || in_msg_size > max_msg_size)
                return false;
            proc_message();
        }

        return true;
    }

    private bool recv_message()
    {
        if (in_msg_size == -1) {
            if (in_buf.length < uint.sizeof)
                return false;
            in_msg_size = in_buf.read!(uint, Endian.littleEndian);
        }
        return in_buf.length >= in_msg_size;
    }

    private void proc_message()
    {
        auto msg_buf = in_buf[0 .. in_msg_size];
        const code = msg_buf.peek!(uint, Endian.littleEndian);

        in_buf = in_buf[in_msg_size .. $];
        in_msg_size = -1;

        if (status == Status.offline && code != Login)
            return;

        switch (code) {
            case Login:
                scope msg = new ULogin(msg_buf);

                if (status != Status.offline)
                    break;

                username = msg.username;

                if (server.db.user_banned(username))
                    // The official server doesn't send a response when a user
                    // is banned. We also ban users temporarily when kicking
                    // them, and simply closing the connection after some time
                    // allows the client to automatically reconnect to the
                    // server.
                    break;

                login_rejection = verify_login(username, msg.password);
                server.db.unban_user(username);

                if (login_rejection) {
                    scope response_msg = new SLogin(false, login_rejection);
                    send_message(response_msg);
                    break;
                }

                auto user = server.get_user(username);

                if (user && user.status != Status.offline) {
                    writefln!(
                        "User %s @ %s already logged in with version %s")(
                        red ~ username ~ norm,
                        bold ~ user.address.toAddrString ~ norm,
                        bold ~ user.client_version ~ norm
                    );
                    scope relogged_msg = new SRelogged();
                    user.send_message(relogged_msg);
                    server.del_user(user);
                }

                client_version = format!("%d.%d")(
                    msg.major_version, msg.minor_version);

                const user_stats = server.db.get_user_stats(username);
                speed = user_stats.speed;
                upload_number = user_stats.upload_number;
                shared_files = user_stats.shared_files;
                shared_folders = user_stats.shared_folders;

                refresh_privileges(false);
                server.add_user(this);
                watch(username);

                scope response_msg = new SLogin(
                    true, motd, address.addr, encode_password(msg.password),
                    supporter
                );
                scope room_list_msg = new SRoomList(server.room_stats);
                scope wish_interval_msg = new SWishlistInterval(
                    privileged ? 120 : 720  // in seconds
                );
                send_message(response_msg);
                send_message(room_list_msg);
                send_message(wish_interval_msg);

                update_status(Status.online);

                foreach (pm ; server.user_pms(username)) {
                    const new_message = false;
                    debug (user) writefln!(
                        "Sending offline PM (id %d) from %s to %s")(
                        pm.id, pm.from_username, blue ~ username ~ norm
                    );
                    send_pm(pm, new_message);
                }
                break;

            case SetWaitPort:
                scope msg = new USetWaitPort(msg_buf, username);
                address = new InternetAddress(
                    address.addr, cast(ushort) msg.port
                );
                writefln!(
                    "%s %s @ %s logged in and listening")(
                    server.db.is_admin(username) ? "Admin" : "User",
                    blue ~ username ~ norm,
                    bold ~ address.toString ~ norm,
                );
                break;

            case GetPeerAddress:
                scope msg = new UGetPeerAddress(msg_buf, username);
                auto user = server.get_user(msg.username);
                uint user_address;
                uint user_port;

                if (user) {
                    user_address = user.address.addr;
                    user_port = user.address.port;
                }

                scope response_msg = new SGetPeerAddress(
                    msg.username, user_address, user_port
                );
                send_message(response_msg);
                break;

            case WatchUser:
                scope msg = new UWatchUser(msg_buf, username);
                auto user = server.get_user(msg.username);

                bool user_exists;
                uint user_status = Status.offline;
                uint user_speed, user_upload_number;
                uint user_shared_files, user_shared_folders;
                string user_country_code;

                if (msg.username == server_username) {
                    user_exists = true;
                    user_status = Status.online;
                }
                else if (user)
                {
                    user_exists = true;
                    user_status = user.status;
                    user_speed = user.speed;
                    user_upload_number = user.upload_number;
                    user_shared_files = user.shared_files;
                    user_shared_folders = user.shared_folders;
                    user_country_code = user.country_code;
                }
                else {
                    const user_stats = server.db.get_user_stats(msg.username);
                    user_exists = user_stats.exists;
                    user_speed = user_stats.speed;
                    user_upload_number = user_stats.upload_number;
                    user_shared_files = user_stats.shared_files;
                    user_shared_folders = user_stats.shared_folders;
                }

                watch(msg.username);

                scope response_msg = new SWatchUser(
                    msg.username, user_exists, user_status, user_speed,
                    user_upload_number, user_shared_files, user_shared_folders,
                    user_country_code
                );
                send_message(response_msg);
                break;

            case UnwatchUser:
                scope msg = new UUnwatchUser(msg_buf, username);
                unwatch(msg.username);
                break;

            case GetUserStatus:
                scope msg = new UGetUserStatus(msg_buf, username);
                auto user = server.get_user(msg.username);
                uint user_status = Status.offline;
                bool user_privileged;

                if (msg.username == server_username) {
                    debug (user) writefln!(
                        "Telling user %s that host %s is online")(
                        blue ~ username ~ norm, blue ~ server_username ~ norm
                    );
                    user_status = Status.online;
                }
                else if (user) {
                    debug (user) writefln!(
                        "Telling user %s that user %s is online")(
                        blue ~ username ~ norm, blue ~ msg.username ~ norm
                    );
                    user_status = user.status;
                    user_privileged = user.privileged;
                }
                else if (server.db.user_exists(msg.username)) {
                    debug (user) writefln!(
                        "Telling user %s that user %s is offline")(
                        blue ~ username ~ norm, red ~ msg.username ~ norm
                    );
                    user_privileged = server.db.user_privileged(msg.username);
                }
                else {
                    debug (user) writefln!(
                        "Telling user %s that non-existent user %s is "
                      ~ "offline")(
                        blue ~ username ~ norm, red ~ msg.username ~ norm
                    );
                }

                scope response_msg = new SGetUserStatus(
                    msg.username, user_status, user_privileged
                );
                send_message(response_msg);
                break;

            case SayChatroom:
                scope msg = new USayChatroom(msg_buf, username);
                auto room = server.get_room(msg.room_name);
                if (!room)
                    break;

                room.say(username, msg.message);
                server.global_room.say(msg.room_name, username, msg.message);
                break;

            case JoinRoom:
                scope msg = new UJoinRoom(msg_buf, username);
                join_room(msg.room_name);
                break;

            case LeaveRoom:
                scope msg = new ULeaveRoom(msg_buf, username);
                if (!leave_room(msg.room_name))
                    break;

                scope response_msg = new SLeaveRoom(msg.room_name);
                send_message(response_msg);
                break;

            case ConnectToPeer:
                scope msg = new UConnectToPeer(msg_buf, username);
                auto user = server.get_user(msg.username);
                if (!user)
                    break;

                debug (user) writefln!(
                    "User %s @ %s connecting indirectly to peer %s @ %s")(
                    blue ~ username ~ norm, bold ~ address.toString ~ norm,
                    blue ~ msg.username ~ norm,
                    bold ~ user.address.toString ~ norm
                );

                scope response_msg = new SConnectToPeer(
                    username, msg.type, address.addr, address.port, msg.token,
                    privileged
                );
                user.send_message(response_msg);
                break;

            case MessageUser:
                scope msg = new UMessageUser(msg_buf, username);
                auto user = server.get_user(msg.username);

                if (msg.message.length > max_chat_message_length)
                    break;

                if (msg.username == server_username) {
                    if (!address.port)
                        break;

                    server.admin_message(this, msg.message);
                }
                else if (user) {
                    // user is connected
                    const pm = server.add_pm(
                        msg.message, username, msg.username
                    );
                    const new_message = true;

                    user.send_pm(pm, new_message);
                }
                else if (server.db.user_exists(msg.username)) {
                    // user exists but not connected
                    server.add_pm(msg.message, username, msg.username);
                }
                break;

            case MessageAcked:
                scope msg = new UMessageAcked(msg_buf, username);
                server.del_pm(msg.id);
                break;

            case FileSearch:
                scope msg = new UFileSearch(msg_buf, username);
                server.search_files(msg.token, msg.query, username);
                break;

            case SetStatus:
                scope msg = new USetStatus(msg_buf, username);
                if (msg.status != Status.offline) update_status(msg.status);
                break;

            case ServerPing:
                scope msg = new UServerPing(msg_buf, username);
                break;

            case SharedFoldersFiles:
                scope msg = new USharedFoldersFiles(msg_buf, username);
                debug (user) writefln!(
                    "User %s reports sharing %d files in %d folders")(
                    blue ~ username ~ norm, msg.shared_files,
                    msg.shared_folders
                );
                update_shared_stats(msg.shared_files, msg.shared_folders);

                scope response_msg = new SGetUserStats(
                    username, speed, upload_number, shared_files,
                    shared_folders
                );
                send_to_watching(response_msg);
                break;

            case GetUserStats:
                scope msg = new UGetUserStats(msg_buf, username);
                auto user = server.get_user(msg.username);

                uint user_speed, user_upload_number;
                uint user_shared_files, user_shared_folders;

                if (user) {
                    user_speed = user.speed;
                    user_upload_number = user.upload_number;
                    user_shared_files = user.shared_files;
                    user_shared_folders = user.shared_folders;
                }
                else {
                    const user_stats = server.db.get_user_stats(msg.username);
                    user_speed = user_stats.speed;
                    user_upload_number = user_stats.upload_number;
                    user_shared_files = user_stats.shared_files;
                    user_shared_folders = user_stats.shared_folders;
                }

                scope response_msg = new SGetUserStats(
                    msg.username, user_speed, user_upload_number,
                    user_shared_files, user_shared_folders
                );
                send_message(response_msg);
                break;

            case UserSearch:
                scope msg = new UUserSearch(msg_buf, username);
                server.search_user_files(
                    msg.token, msg.query, username, msg.username
                );
                break;

            case AddThingILike:
                scope msg = new UAddThingILike(msg_buf, username);
                add_liked_item(msg.item);
                break;

            case RemoveThingILike:
                scope msg = new URemoveThingILike(msg_buf, username);
                del_liked_item(msg.item);
                break;

            case AddThingIHate:
                scope msg = new UAddThingIHate(msg_buf, username);
                add_hated_item(msg.item);
                break;

            case RemoveThingIHate:
                scope msg = new URemoveThingIHate(msg_buf, username);
                del_hated_item(msg.item);
                break;

            case GetRecommendations:
                scope msg = new UGetRecommendations(msg_buf, username);
                scope response_msg = new SGetRecommendations(recommendations);
                send_message(response_msg);
                break;

            case GlobalRecommendations:
                scope msg = new UGlobalRecommendations(msg_buf, username);
                scope response_msg = new SGetGlobalRecommendations(
                    global_recommendations
                );
                send_message(response_msg);
                break;

            case SimilarUsers:
                scope msg = new USimilarUsers(msg_buf, username);
                scope response_msg = new SSimilarUsers(similar_users);
                send_message(response_msg);
                break;

            case UserInterests:
                scope msg = new UUserInterests(msg_buf, username);
                auto user = server.get_user(msg.username);
                if (!user)
                    break;

                scope response_msg = new SUserInterests(
                    user.username, user.liked_items, user.hated_items
                );
                send_message(response_msg);
                break;

            case RoomList:
                scope msg = new URoomList(msg_buf, username);
                scope response_msg = new SRoomList(server.room_stats);
                send_message(response_msg);
                break;

            case CheckPrivileges:
                scope msg = new UCheckPrivileges(msg_buf, username);
                refresh_privileges();
                break;

            case WishlistSearch:
                scope msg = new UWishlistSearch(msg_buf, username);
                server.search_files(msg.token, msg.query, username);
                break;

            case ItemRecommendations:
                scope msg = new UItemRecommendations(msg_buf, username);
                scope response_msg = new SItemRecommendations(
                    msg.item, item_recommendations(msg.item)
                );
                send_message(response_msg);
                break;

            case ItemSimilarUsers:
                scope msg = new UItemSimilarUsers(msg_buf, username);
                scope response_msg = new SItemSimilarUsers(
                    msg.item, item_similar_users(msg.item)
                );
                send_message(response_msg);
                break;

            case SetRoomTicker:
                scope msg = new USetRoomTicker(msg_buf, username);
                auto room = server.get_room(msg.room_name);
                if (room) room.add_ticker(username, msg.ticker);
                break;

            case RoomSearch:
                scope msg = new URoomSearch(msg_buf, username);
                server.search_room_files(
                    msg.token, msg.query, username, msg.room_name
                );
                break;

            case SendUploadSpeed:
                scope msg = new USendUploadSpeed(msg_buf, username);
                calc_speed(msg.speed);
                debug (user) writefln!(
                    "User %s reports speed of %d B/s (~ %d B/s)")(
                    blue ~ username ~ norm, msg.speed, user.speed
                );
                break;

            case UserPrivileged:
                scope msg = new UUserPrivileged(msg_buf, username);
                auto user = server.get_user(msg.username);
                if (!user)
                    break;

                scope response_msg = new SUserPrivileged(
                    user.username, user.privileged
                );
                send_message(response_msg);
                break;

            case GivePrivileges:
                scope msg = new UGivePrivileges(msg_buf, username);
                auto user = server.get_user(msg.username);
                const admin = server.db.is_admin(msg.username);
                const duration = msg.days.days;

                if (!user)
                    break;

                if (duration > privileges && !admin)
                    break;

                server.db.add_user_privileges(msg.username, duration);
                user.refresh_privileges();

                if (!admin) {
                    server.db.remove_user_privileges(username, duration);
                    refresh_privileges();
                }
                break;

            case ChangePassword:
                scope msg = new UChangePassword(msg_buf, username);

                server.db.user_update_field(
                    username, "password", encode_password(msg.password)
                );

                scope response_msg = new SChangePassword(msg.password);
                send_message(response_msg);
                break;

            case MessageUsers:
                scope msg = new UMessageUsers(msg_buf, username);
                bool new_message = true;

                if (msg.message.length > max_chat_message_length)
                    break;

                foreach (target_username ; msg.usernames) {
                    auto user = server.get_user(target_username);
                    if (!user)
                        continue;

                    const pm = server.add_pm(
                        msg.message, username, target_username
                    );
                    user.send_pm(pm, new_message);
                }
                break;

            case JoinGlobalRoom:
                scope msg = new UJoinGlobalRoom(msg_buf, username);
                server.global_room.add_user(this);
                break;

            case LeaveGlobalRoom:
                scope msg = new ULeaveGlobalRoom(msg_buf, username);
                server.global_room.remove_user(username);
                break;

            case CantConnectToPeer:
                scope msg = new UCantConnectToPeer(msg_buf, username);
                auto user = server.get_user(msg.username);
                if (!user)
                    return;

                scope response_msg = new SCantConnectToPeer(msg.token);
                user.send_message(response_msg);
                break;

            default:
                debug (msg) writefln!(
                    "Unimplemented message code %s%d%s from user %s with "
                  ~ "length %d\n%s")(
                    red, code, norm, blue ~ username ~ norm, msg_buf.length,
                    msg_buf
                );
                break;
        }
    }
}
