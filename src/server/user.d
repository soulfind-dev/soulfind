// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server.user;
@safe:

import core.time : Duration, MonoTime, seconds;
import soulfind.db : SdbUserStats;
import soulfind.defines : blue, bold, log_msg, log_user, login_timeout,
                          max_chat_message_length, max_interest_length,
                          max_msg_size, max_room_name_length,
                          max_username_length, norm, red, server_username,
                          speed_weight, VERSION, wish_interval,
                          wish_interval_privileged;
import soulfind.select : SelectEvent;
import soulfind.server.messages;
import soulfind.server.pm : PM;
import soulfind.server.room : Room;
import soulfind.server.server : Server;
import std.algorithm : canFind;
import std.array : Appender, array;
import std.ascii : isPrintable;
import std.bitmanip : Endian, nativeToLittleEndian, peek, read;
import std.conv : ConvException, to;
import std.datetime : Clock, SysTime;
import std.digest : digest, LetterCase, secureEqual, toHexString;
import std.digest.md : MD5;
import std.random : uniform;
import std.socket : InternetAddress, Socket;
import std.stdio : writefln;
import std.string : format, join, replace, strip;

class User
{
    string                  username;
    Socket                  sock;
    InternetAddress         address;
    bool                    removed;

    uint                    status;
    string                  client_version;
    LoginRejection          login_rejection;
    SysTime                 privileged_until;
    bool                    supporter;

    uint                    upload_speed;  // in B/s
    uint                    shared_files;
    uint                    shared_folders;

    private Server          server;
    private MonoTime        connected_monotime;

    private string[string]  liked_items;
    private string[string]  hated_items;

    private Room[string]    joined_rooms;

    private string[string]  watched_users;

    private ubyte[]         in_buf;
    private long            in_msg_size = -1;
    private ubyte[]         out_buf;


    this(Server serv, Socket sock, InternetAddress address)
    {
        this.server              = serv;
        this.sock                = sock;
        this.address             = address;
        this.connected_monotime  = MonoTime.currTime;
    }


    // Login

    string motd()
    {
        return server.db.server_motd
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
        return (MonoTime.currTime - connected_monotime) > login_timeout;
    }

    private string check_username(string username)
    {
        if (username.length == 0)
            return "Nick empty.";

        if (username.length > max_username_length)
            return "Nick too long.";

        if (username.strip != username)
            return "No leading and trailing spaces allowed in nick.";

        foreach (c ; username) if (!c.isPrintable)
            // Only printable ASCII characters allowed
            return "Invalid characters in nick.";

        static immutable forbidden_names = [server_username];

        foreach (name ; forbidden_names) if (name == username)
            // Official server returns empty detail
            return "";

        return null;
    }

    private LoginRejection verify_login(string username, string password)
    {
        auto login_rejection = LoginRejection();

        if (server.users.length >= server.db.server_max_users) {
            login_rejection.reason = LoginRejectionReason.server_full;
            return login_rejection;
        }

        const invalid_name_reason = check_username(username);
        if (invalid_name_reason) {
            login_rejection.reason = LoginRejectionReason.invalid_username;
            login_rejection.detail = invalid_name_reason;
            return login_rejection;
        }

        if (!server.db.user_exists(username)) {
            if (server.db.server_private_mode)
                login_rejection.reason = LoginRejectionReason.server_private;

            else if (password.length == 0)
                login_rejection.reason = LoginRejectionReason.empty_password;

            else if (server.db.is_admin(username))
                // For security reasons, non-existent admins cannot register
                // through the client
                login_rejection.reason = LoginRejectionReason.invalid_password;

            else
                server.db.add_user(username, password);

            return login_rejection;
        }
        if (log_user) writefln!("User %s is registered")(
            blue ~ username ~ norm
        );

        if (!server.db.user_verify_password(username, password)) {
            login_rejection.reason = LoginRejectionReason.invalid_password;
            return login_rejection;
        }
        return login_rejection;
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

    private void update_upload_speed(uint new_speed)
    {
        if (upload_speed > 0)
            upload_speed = (
                (upload_speed * speed_weight + new_speed) / (speed_weight + 1)
            );
        else
            upload_speed = new_speed;

        scope msg = new SGetUserStats(
            username, upload_speed, shared_files, shared_folders
        );
        send_to_watching(msg);

        auto stats = SdbUserStats();
        stats.upload_speed = upload_speed;
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
        privileged_until = server.db.user_privileged_until(username);
        supporter = server.db.user_supporter(username);

        if (!notify_user)
            return;

        scope msg = new SCheckPrivileges(privileges);
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
        return peer_username in watched_users ? true : false;
    }

    size_t num_watched_users()
    {
        return watched_users.length;
    }

    private void send_to_watching(scope SMessage msg)
    {
        if (log_msg) writefln!(
            "Transmit=> %s (code %d) to users watching user %s...")(
            blue ~ msg.name ~ norm, msg.code, blue ~ username ~ norm
        );
        foreach (user ; server.users)
            if (user.is_watching(username) || user.joined_same_room(username))
                user.send_message(msg);
    }


    // Interests

    private void add_liked_item(string item)
    {
        if (item.length == 0 || item.length > max_interest_length)
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
        if (item.length == 0 || item.length > max_interest_length)
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

    string[] liked_item_names()
    {
        return liked_items.byKey.array;
    }

    string[] hated_item_names()
    {
        return hated_items.byKey.array;
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
        Appender!(string[]) usernames;
        foreach (user ; server.users) {
            if (user is this)
                continue;
            if (user.likes(item)) usernames ~= user.username;
        }
        return usernames[];
    }


    // Rooms

    void join_room(string name)
    {
        string fail_message = check_room_name(name);
        if (fail_message) {
            server.server_pm(username, fail_message);
            return;
        }

        auto room = server.get_room(name);
        if (room is null) room = server.add_room(name);

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
        return joined_rooms.byKey.array;
    }

    private string check_room_name(string room_name)
    {
        if (room_name.length == 0)
            return "Could not create room. Reason: Room name empty.";

        if (room_name.length > max_room_name_length)
            return format!(
                "Could not create room. Reason: Room name %s longer than %d "
              ~ "characters.")(
                room_name, max_room_name_length
            );

        if (room_name.strip != room_name)
            return format!(
                "Could not create room. Reason: Room name %s contains leading "
              ~ "or trailing spaces.")(
                room_name
            );

        if (room_name.canFind("  "))
            return format!(
                "Could not create room. Reason: Room name %s contains "
              ~ "multiple following spaces.")(
                room_name
            );

        foreach (c ; room_name) if (!c.isPrintable)
            // Only printable ASCII characters allowed
            return format!(
                "Could not create room. Reason: Room name %s contains "
              ~ "invalid characters.")(
                room_name
            );

        return null;
    }

    private bool joined_same_room(string peer_username)
    {
        foreach (room ; joined_rooms)
            if (room.is_joined(peer_username))
                return true;

        return false;
    }

    private void send_to_joined_rooms(scope SMessage msg)
    {
        if (log_msg) writefln!(
            "Transmit=> %s (code %d) to user %s's joined rooms...")(
            blue ~ msg.name ~ norm, msg.code, blue ~ username ~ norm
        );
        foreach (user ; server.users)
            if (user.joined_same_room(username)) user.send_message(msg);
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
        if (!is_sending) server.selector.unregister(sock, SelectEvent.write);
        return true;
    }

    void send_message(scope SMessage msg)
    {
        const msg_buf = msg.bytes;
        const msg_len = msg_buf.length;
        const offset = out_buf.length;

        if (log_msg) writefln!(
            "Sending -> %s (code %d) of %d bytes -> to user %s")(
            blue ~ msg.name ~ norm, msg.code, msg_len, blue ~ username ~ norm
        );

        if (msg_len > uint.max) {
            writefln!(
                "Message %s (code %d) of %d bytes to user %s is too large, "
              ~ "not sending")(
                blue ~ msg.name ~ norm, msg.code, msg_len,
                blue ~ username ~ norm
            );
            return;
        }

        out_buf.length += (uint.sizeof + msg_len);
        out_buf[offset .. offset + uint.sizeof] = (cast(uint) msg_len)
            .nativeToLittleEndian;
        out_buf[offset + uint.sizeof .. $] = msg_buf;

        server.selector.register(sock, SelectEvent.write);
    }

    bool recv_buffer()
    {
        ubyte[max_msg_size] receive_buf;
        const receive_len = sock.receive(receive_buf);
        if (receive_len == Socket.ERROR || receive_len == 0)
            return false;

        in_buf ~= receive_buf[0 .. receive_len];
        do {
            if (in_msg_size == -1) {
                if (in_buf.length < uint.sizeof)
                    break;
                in_msg_size = in_buf.read!(uint, Endian.littleEndian);
            }
            if (in_msg_size < 0 || in_msg_size > max_msg_size) {
                if (log_msg) writefln!(
                    "Received unexpected message size %d from user %s, "
                  ~ "disconnecting them")(
                    in_msg_size, blue ~ username ~ norm
                );
                return false;
            }
            if (in_buf.length < in_msg_size)
                break;
            proc_message();
        }
        while (true);

        return true;
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

                if (login_rejection.reason) {
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

                const user_stats = server.db.user_stats(username);
                upload_speed = user_stats.upload_speed;
                shared_files = user_stats.shared_files;
                shared_folders = user_stats.shared_folders;

                refresh_privileges(false);
                server.add_user(this);
                watch(username);

                // Empty list of users for privacy reasons. Clients can use
                // other server messages to know if a user is privileged.
                string[] privileged_users;
                const md5_hash = digest!MD5(msg.password)
                    .toHexString!(LetterCase.lower)
                    .to!string;
                scope response_msg = new SLogin(
                    true, login_rejection, motd, address.addr, md5_hash,
                    supporter
                );
                scope room_list_msg = new SRoomList(
                    server.room_stats, null, null, null
                );
                scope wish_interval_msg = new SWishlistInterval(
                    privileged ? wish_interval_privileged : wish_interval
                );
                scope privileged_users_msg = new SPrivilegedUsers(
                    privileged_users
                );
                send_message(response_msg);
                send_message(room_list_msg);
                send_message(wish_interval_msg);
                send_message(privileged_users_msg);

                update_status(Status.online);
                server.send_queued_pms(username);
                break;

            case SetWaitPort:
                scope msg = new USetWaitPort(msg_buf, username);

                if (msg.port == 0)
                    break;

                if (address.port != InternetAddress.PORT_ANY)
                    // If port was already set, reject attempts to change it,
                    // since they are not compatible with many clients that
                    // cache user addresses.
                    break;

                address = new InternetAddress(
                    address.addr, cast(ushort) msg.port
                );
                writefln!("User %s listening on port %d")(
                    blue ~ username ~ norm, msg.port,
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
                uint user_upload_speed;
                uint user_shared_files, user_shared_folders;

                if (user)
                {
                    user_exists = true;
                    user_status = user.status;
                    user_upload_speed = user.upload_speed;
                    user_shared_files = user.shared_files;
                    user_shared_folders = user.shared_folders;
                }
                else if (msg.username != server_username) {
                    const user_stats = server.db.user_stats(msg.username);
                    user_exists = user_stats.exists;
                    user_upload_speed = user_stats.upload_speed;
                    user_shared_files = user_stats.shared_files;
                    user_shared_folders = user_stats.shared_folders;
                }

                watch(msg.username);

                scope response_msg = new SWatchUser(
                    msg.username, user_exists, user_status, user_upload_speed,
                    user_shared_files, user_shared_folders
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

                if (user) {
                    if (log_user) writefln!(
                        "Telling user %s that user %s is online")(
                        blue ~ username ~ norm, blue ~ msg.username ~ norm
                    );
                    user_status = user.status;
                    user_privileged = user.privileged;
                }
                else if (msg.username != server_username
                         && server.db.user_exists(msg.username)) {
                    if (log_user) writefln!(
                        "Telling user %s that user %s is offline")(
                        blue ~ username ~ norm, red ~ msg.username ~ norm
                    );
                    user_privileged = server.db.user_privileged(msg.username);
                }
                else {
                    if (log_user) writefln!(
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
                if (room is null)
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
                if (user is null)
                    break;

                if (log_user) writefln!(
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
                    if (address.port == InternetAddress.PORT_ANY)
                        break;

                    server.admin_message(username, msg.message);
                }
                else if (user) {
                    // User is connected
                    const pm = server.add_pm(
                        msg.message, username, msg.username
                    );
                    const new_message = true;
                    server.send_pm(pm, new_message);
                }
                else if (server.db.user_exists(msg.username)) {
                    // User exists but not connected
                    server.add_pm(msg.message, username, msg.username);
                }
                break;

            case MessageAcked:
                scope msg = new UMessageAcked(msg_buf, username);
                server.del_pm(msg.id, username);
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

            case SendConnectToken:
                scope msg = new USendConnectToken(msg_buf, username);
                auto user = server.get_user(msg.username);
                if (user is null)
                    break;

                scope response_msg = new SSendConnectToken(
                    username, msg.token
                );
                user.send_message(response_msg);
                break;

            case SharedFoldersFiles:
                scope msg = new USharedFoldersFiles(msg_buf, username);
                update_shared_stats(msg.shared_files, msg.shared_folders);

                scope response_msg = new SGetUserStats(
                    username, upload_speed, shared_files, shared_folders
                );
                send_to_watching(response_msg);
                break;

            case GetUserStats:
                scope msg = new UGetUserStats(msg_buf, username);
                auto user = server.get_user(msg.username);

                uint user_upload_speed;
                uint user_shared_files, user_shared_folders;

                if (user) {
                    user_upload_speed = user.upload_speed;
                    user_shared_files = user.shared_files;
                    user_shared_folders = user.shared_folders;
                }
                else {
                    const user_stats = server.db.user_stats(msg.username);
                    user_upload_speed = user_stats.upload_speed;
                    user_shared_files = user_stats.shared_files;
                    user_shared_folders = user_stats.shared_folders;
                }

                scope response_msg = new SGetUserStats(
                    msg.username, user_upload_speed, user_shared_files,
                    user_shared_folders
                );
                send_message(response_msg);
                break;

            case QueuedDownloads:
                scope msg = new UQueuedDownloads(msg_buf, username);
                scope response_msg = new SQueuedDownloads(
                    username, msg.slots_full
                );
                send_to_joined_rooms(response_msg);
                break;

            case UserSearch:
                scope msg = new UUserSearch(msg_buf, username);
                server.search_user_files(
                    msg.token, msg.query, username, msg.username
                );
                break;

            case SimilarRecommendations:
                // No longer used, send empty response
                scope msg = new USimilarRecommendations(msg_buf, username);
                string[] recommendations;

                scope response_msg = new SSimilarRecommendations(
                    msg.recommendation, recommendations
                );
                send_message(response_msg);
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

            case MyRecommendations:
                // No longer used, send empty response
                scope msg = new UMyRecommendations(msg_buf, username);
                string[] recommendations;

                scope response_msg = new SMyRecommendations(recommendations);
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
                string[string] user_liked_items;
                string[string] user_hated_items;

                if (user) {
                    user_liked_items = user.liked_items;
                    user_hated_items = user.hated_items;
                }

                scope response_msg = new SUserInterests(
                    msg.username, user_liked_items, user_hated_items
                );
                send_message(response_msg);
                break;

            case RoomList:
                scope msg = new URoomList(msg_buf, username);
                scope response_msg = new SRoomList(
                    server.room_stats, null, null, null
                );
                send_message(response_msg);
                break;

            case GlobalUserList:
                // The official server disconnects the user
                scope msg = new UGlobalUserList(msg_buf, username);
                server.del_user(this);
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
                update_upload_speed(msg.speed);
                break;

            case UserPrivileged:
                scope msg = new UUserPrivileged(msg_buf, username);
                auto user = server.get_user(msg.username);
                const privileged = user ? user.privileged : false;

                scope response_msg = new SUserPrivileged(
                    msg.username, privileged
                );
                send_message(response_msg);
                break;

            case GivePrivileges:
                scope msg = new UGivePrivileges(msg_buf, username);
                auto user = server.get_user(msg.username);
                const duration = msg.duration;

                if (user is null)
                    break;

                if (duration > privileges)
                    break;

                server.db.add_user_privileges(msg.username, duration);
                user.refresh_privileges();

                server.db.remove_user_privileges(username, duration);
                refresh_privileges();
                break;

            case NotifyPrivileges:
                // No longer used, but official server still responds
                scope msg = new UNotifyPrivileges(msg_buf, username);
                scope response_msg = new SAckNotifyPrivileges(msg.token);
                send_message(response_msg);
                break;

            case PrivateRoomAddUser:
                scope msg = new UPrivateRoomAddUser(msg_buf, username);
                break;

            case PrivateRoomRemoveUser:
                scope msg = new UPrivateRoomRemoveUser(msg_buf, username);
                break;

            case PrivateRoomCancelMembership:
                scope msg = new UPrivateRoomCancelMembership(
                    msg_buf, username
                );
                break;

            case PrivateRoomDisown:
                scope msg = new UPrivateRoomDisown(msg_buf, username);
                break;

            case PrivateRoomToggle:
                scope msg = new UPrivateRoomToggle(msg_buf, username);
                scope response_msg = new SPrivateRoomToggle(msg.enabled);
                send_message(response_msg);
                break;

            case ChangePassword:
                scope msg = new UChangePassword(msg_buf, username);
                if (msg.password.length == 0)
                    break;

                server.db.user_update_password(username, msg.password);

                scope response_msg = new SChangePassword(msg.password);
                send_message(response_msg);
                break;

            case PrivateRoomAddOperator:
                scope msg = new UPrivateRoomAddOperator(msg_buf, username);
                break;

            case PrivateRoomRemoveOperator:
                scope msg = new UPrivateRoomRemoveOperator(msg_buf, username);
                break;

            case MessageUsers:
                scope msg = new UMessageUsers(msg_buf, username);
                const new_message = true;

                if (msg.message.length > max_chat_message_length)
                    break;

                foreach (target_username ; msg.usernames) {
                    const user = server.get_user(target_username);
                    if (user is null)
                        continue;

                    const pm = server.add_pm(
                        msg.message, username, target_username
                    );
                    server.send_pm(pm, new_message);
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

            case RelatedSearch:
                // No longer used, send empty response
                scope msg = new URelatedSearch(msg_buf, username);
                uint[string] terms;

                scope response_msg = new SRelatedSearch(
                    msg.query, terms
                );
                send_message(response_msg);
                break;

            case CantConnectToPeer:
                scope msg = new UCantConnectToPeer(msg_buf, username);
                auto user = server.get_user(msg.username);
                if (user is null)
                    return;

                scope response_msg = new SCantConnectToPeer(msg.token);
                user.send_message(response_msg);
                break;

            default:
                if (log_msg) writefln!(
                    "Unimplemented message code %s%d%s from user %s with "
                  ~ "length %d\n%s")(
                    red, code, norm, blue ~ username ~ norm, msg_buf.length,
                    msg_buf
                );
                break;
        }
    }
}
