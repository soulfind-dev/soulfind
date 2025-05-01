// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server.user;
@safe:

import core.time : days, seconds;
import soulfind.defines : blue, bold, max_chat_message_length, max_msg_size,
                          max_room_name_length, max_username_length, norm, red,
                          server_username;
import soulfind.server.messages;
import soulfind.server.pm : PM;
import soulfind.server.room : Room;
import soulfind.server.server : Server;
import std.array : join;
import std.bitmanip : Endian, nativeToLittleEndian, peek, read;
import std.conv : to;
import std.datetime : Clock, SysTime;
import std.digest : digest, LetterCase, secureEqual, toHexString;
import std.digest.md : MD5;
import std.format : format;
import std.socket : InternetAddress, Socket;
import std.stdio : writefln;

class User
{
    string                  username;
    Socket                  sock;

    uint                    speed;                // in B/s
    uint                    upload_number;
    uint                    shared_files;
    uint                    shared_folders;
    string                  country_code;

    uint                    status;
    SysTime                 connected_at;
    string                  login_error;

    private Server          server;

    private uint            major_version;
    private uint            minor_version;
    private uint            ip_address;
    private ushort          port;
    private long            priv_expiration;

    private string[string]  liked_items;
    private string[string]  hated_items;

    private Room[string]    joined_rooms;

    private string[string]  watched_users;

    private ubyte[]         in_buf;
    private long            in_msg_size = -1;
    private ubyte[]         out_buf;


    this(Server serv, Socket sock, uint ip_address)
    {
        this.server        = serv;
        this.sock          = sock;
        this.ip_address    = ip_address;
        this.connected_at  = Clock.currTime;
    }


    // Client

    string h_client_version()
    {
        return format!("%d.%d")(major_version, minor_version);
    }

    string h_ip_address()
    {
        return InternetAddress.addrToString(ip_address);
    }

    string h_address()
    {
        return format!("%s:%d")(h_ip_address, port);
    }

    string encode_password(string password)
    {
        return digest!MD5(password).toHexString!(LetterCase.lower).to!string;
    }

    string verify_login(string password)
    {
        if (!server.check_name(username, max_username_length))
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

        if (server.db.get_ban_expiration(username) > Clock.currTime.toUnixTime)
            return "BANNED";

        if (!secureEqual(
                server.db.get_pass(username), encode_password(password)))
            return "INVALIDPASS";

        return null;
    }


    // Status

    void set_status(uint new_status)
    {
        status = new_status;
        scope msg = new SGetUserStatus(username, new_status, privileged);
        send_to_watching(msg);
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

        server.db.user_update_field(username, "speed", speed);
    }

    private void set_shared_files(uint new_files)
    {
        shared_files = new_files;
        server.db.user_update_field(username, "files", shared_files);
    }

    private void set_shared_folders(uint new_folders)
    {
        shared_folders = new_folders;
        server.db.user_update_field(username, "folders", shared_folders);
    }


    // Privileges

    void add_privileges(uint seconds)
    {
        if (privileges <= 0) priv_expiration = Clock.currTime.toUnixTime;
        priv_expiration += seconds;
        server.db.user_update_field(username, "privileges", priv_expiration);

        scope msg = new SCheckPrivileges(privileges);
        send_message(msg);

        debug (user) writefln!(
            "Given %d secs of privileges to user %s who now has %d secs")(
            seconds, blue ~ username ~ norm, privileges
        );
    }

    void remove_privileges(uint seconds)
    {
        priv_expiration -= seconds;
        if (privileges <= 0) priv_expiration = Clock.currTime.toUnixTime;
        server.db.user_update_field(username, "privileges", priv_expiration);

        scope msg = new SCheckPrivileges(privileges);
        send_message(msg);

        debug (user) writefln!(
            "Taken %d secs of privileges from user %s who now has %d secs")(
            seconds, blue ~ username ~ norm, privileges
        );
    }

    private long privileges()
    {
        long privileges = priv_expiration - Clock.currTime.toUnixTime;
        if (privileges <= 0) privileges = 0;
        return privileges;
    }

    string h_privileges()
    {
        return privileges > 0 ? privileges.seconds.toString : "none";
    }

    bool privileged()
    {
        return privileges > 0;
    }

    bool supporter()
    {    // user has had privileges at some point
        return priv_expiration > 0;
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
        if (!likes(item)) liked_items[item] = item;
    }

    private void del_liked_item(string item)
    {
        if (likes(item)) liked_items.remove(item);
    }

    private void add_hated_item(string item)
    {
        if (!hates(item)) hated_items[item] = item;
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
            pm.id, pm.timestamp, pm.from_username, pm.message,
            new_message
        );
        send_message(msg);
    }


    // Rooms

    void join_room(string name)
    {
        auto room = server.get_room(name);
        if (!room) room = server.add_room(name);

        if (!room)
            return;

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

    string h_joined_rooms()
    {
        return joined_rooms.byKey.join(", ");
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
                login_error = verify_login(msg.password);

                if (login_error) {
                    scope response_msg = new SLogin(false, login_error);
                    send_message(response_msg);
                    break;
                }

                auto user = server.get_user(username);

                if (user && user.status != Status.offline) {
                    writefln!(
                        "User %s @ %s already logged in with version %s")(
                        red ~ username ~ norm,
                        bold ~ user.h_address ~ norm,
                        bold ~ user.h_client_version ~ norm
                    );
                    scope relogged_msg = new SRelogged();
                    user.send_message(relogged_msg);
                    server.del_user(user);
                }

                major_version = msg.major_version;
                minor_version = msg.minor_version;
                priv_expiration = server.db.get_user_privileges(username);

                const user_stats = server.db.get_user_stats(username);
                speed = user_stats.speed;
                upload_number = user_stats.upload_number;
                shared_files = user_stats.shared_files;
                shared_folders = user_stats.shared_folders;

                server.add_user(this);
                watch(username);

                scope response_msg = new SLogin(
                    true, server.get_motd(this), ip_address,
                    encode_password(msg.password), supporter
                );
                scope room_list_msg = new SRoomList(server.room_stats);
                scope wish_interval_msg = new SWishlistInterval(
                    privileged ? 120 : 720  // in seconds
                );
                send_message(response_msg);
                send_message(room_list_msg);
                send_message(wish_interval_msg);

                set_status(Status.online);

                foreach (pm ; server.get_pms_for(username)) {
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
                port = cast(ushort) msg.port;

                writefln!(
                    "%s %s @ %s logged in and listening")(
                    server.db.is_admin(username) ? "Admin" : "User",
                    blue ~ username ~ norm,
                    bold ~ h_address ~ norm,
                );
                break;

            case GetPeerAddress:
                scope msg = new UGetPeerAddress(msg_buf, username);
                auto user = server.get_user(msg.username);
                uint user_address;
                uint user_port;

                if (user) {
                    user_address = user.ip_address;
                    user_port = user.port;
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
                    user_privileged = server.db.get_user_privileges(
                        msg.username) > Clock.currTime.toUnixTime;
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
                    blue ~ username ~ norm, bold ~ h_address ~ norm,
                    blue ~ msg.username ~ norm, bold ~ user.h_address ~ norm
                );

                scope response_msg = new SConnectToPeer(
                    user.username, msg.type, user.ip_address, user.port,
                    msg.token, user.privileged
                );
                user.send_message(response_msg);
                break;

            case MessageUser:
                scope msg = new UMessageUser(msg_buf, username);
                auto user = server.get_user(msg.username);

                if (msg.message.length > max_chat_message_length)
                    break;

                if (msg.username == server_username) {
                    if (!port)
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
                set_status(msg.status);
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
                set_shared_folders(msg.shared_folders);
                set_shared_files(msg.shared_files);

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
                scope response_msg = new SCheckPrivileges(privileges);
                send_message(response_msg);
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
                auto user = server.get_user(username);
                if (!user)
                    break;

                user.calc_speed(msg.speed);
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
                if (!user)
                    break;
                if (days(msg.days) > seconds(privileges) && !admin)
                    break;

                user.add_privileges(msg.days * 3600 * 24);
                if (!admin) remove_privileges(msg.days * 3600 * 24);
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
