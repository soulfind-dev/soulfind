// SPDX-FileCopyrightText: 2024 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server.user;
@safe:

import core.time : seconds;
import soulfind.defines;
import soulfind.server.messages;
import soulfind.server.pm;
import soulfind.server.room;
import soulfind.server.server;
import std.bitmanip : Endian, nativeToLittleEndian, peek, read;
import std.datetime : Clock, SysTime;
import std.socket : InternetAddress, Socket;
import std.stdio : writefln;

class User
{
    // Attributes

    string                  username;
    uint                    major_version;
    uint                    minor_version;

    uint                    speed;                // in B/s
    uint                    upload_number;
    uint                    something;
    uint                    shared_files;
    uint                    shared_folders;
    uint                    slots_full;
    string                  country_code;

    uint                    status;
    SysTime                 connected_at;
    bool                    should_quit;

    Socket                  sock;
    Server                  server;

    private uint            address;
    private ushort          port;

    private long            priv_expiration;

    private string[string]  liked_things;
    private string[string]  hated_things;

    private string[string]  watch_list;

    private Room[string]    joined_rooms;

    private ubyte[]         in_buf;
    private long            in_msg_size = -1;
    private ubyte[]         out_buf;


    // Constructor

    this(Server serv, Socket sock, uint address)
    {
        this.server        = serv;
        this.sock          = sock;
        this.address       = address;
        this.connected_at  = Clock.currTime;
    }


    // Misc

    void send_pm(PM pm, bool new_message)
    {
        send_message(
            new SMessageUser(
                pm.id, pm.timestamp, pm.from, pm.content,
                new_message
            )
        );
    }

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

        send_to_watching(
            new SGetUserStats(
                username, speed, upload_number, something, shared_files,
                shared_folders
            )
        );
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
        send_message(new SCheckPrivileges(privileges));

        debug (user) writefln(
            "Given %d secs of privileges to user %s who now has %d secs",
            seconds, blue ~ username ~ norm, privileges
        );
    }

    void remove_privileges(uint seconds)
    {
        priv_expiration -= seconds;
        if (privileges <= 0) priv_expiration = Clock.currTime.toUnixTime;

        server.db.user_update_field(username, "privileges", priv_expiration);
        send_message(new SCheckPrivileges(privileges));

        debug (user) writefln(
            "Taken %d secs of privileges from user %s who now has %d secs",
            seconds, blue ~ username ~ norm, privileges
        );
    }

    long privileges()
    {
        long privileges = priv_expiration - Clock.currTime.toUnixTime;
        if (privileges <= 0) privileges = 0;
        return privileges;
    }

    string h_privileges()
    {
        return privileges > 0 ? privileges.seconds.toString : "None";
    }

    bool privileged()
    {
        return privileges > 0;
    }

    bool supporter()
    {    // user has had privileges at some point
        return priv_expiration > 0;
    }


    // Interests

    private void add_thing_he_likes(string thing)
    {
        if (!likes(thing)) liked_things[thing] = thing;
    }

    private void del_thing_he_likes(string thing)
    {
        if (likes(thing)) liked_things.remove(thing);
    }

    private void add_thing_he_hates(string thing)
    {
        if (!hates(thing)) hated_things[thing] = thing;
    }

    private void del_thing_he_hates(string thing)
    {
        if (hates(thing)) hated_things.remove(thing);
    }

    private bool likes(string thing)
    {
        return thing in liked_things ? true : false;
    }

    private bool hates(string thing)
    {
        return thing in hated_things ? true : false;
    }

    private uint[string] global_recommendations()
    {
        uint[string] list;
        foreach (user ; server.users)
            foreach (thing ; user.liked_things) list[thing]++;

        return list;
    }

    private uint[string] recommendations()
    {
        uint[string] recommendations;
        foreach (user ; server.users) {
            if (user is this)
                continue;

            int weight;
            foreach (thing ; liked_things) {
                if (user.likes(thing)) weight++;
                if (user.hates(thing) && weight > 0) weight--;
            }
            foreach (thing ; hated_things) {
                if (user.hates(thing)) weight++;
                if (user.likes(thing) && weight > 0) weight--;
            }
            if (weight > 0) foreach (thing ; user.liked_things)
                recommendations[thing] += weight;
        }
        return recommendations;
    }

    private uint[string] similar_users()
    {
        uint[string] users;
        foreach (user ; server.users) {
            if (user is this)
                continue;

            int weight;
            foreach (thing ; liked_things) {
                if (user.likes(thing)) weight++;
                if (user.hates(thing) && weight > 0) weight--;
            }
            foreach (thing ; hated_things) {
                if (user.hates(thing)) weight++;
                if (user.likes(thing) && weight > 0) weight--;
            }
            if (weight > 0) users[user.username] = weight;
        }
        return users;
    }

    private uint[string] get_item_recommendations(string item)
    {
        uint[string] list;
        foreach (user ; server.users) {
            if (user is this)
                continue;

            int weight;
            if (user.likes(item)) weight++;
            if (user.hates(item) && weight > 0) weight--;
            if (weight > 0) foreach (thing ; user.liked_things)
                list[thing] += weight;
        }
        return list;
    }

    private string[] get_item_similar_users(string item)
    {
        string[] list;
        foreach (user ; server.users) {
            if (user is this)
                continue;
            if (user.likes(item)) list ~= user.username;
        }
        return list;
    }


    // Watchlist

    private void watch(string peer_username)
    {
        if (peer_username != server_user)
            watch_list[peer_username] = peer_username;
    }

    private void unwatch(string peer_username)
    {
        if (peer_username == username)
            // Always watch our own username for updates
            return;

        if (peer_username in watch_list)
            watch_list.remove(peer_username);
    }

    private bool is_watching(string peer_username)
    {
        if (peer_username in watch_list)
            return true;

        foreach (room_name, room ; joined_rooms)
            if (room.is_joined(peer_username))
                return true;

        return false;
    }

    private void send_to_watching(SMessage msg)
    {
        debug (msg) writefln(
            "Transmit=> %s (code %d) to users watching user %s...",
            blue ~ msg.name ~ norm, msg.code, blue ~ username ~ norm
        );
        foreach (user ; server.users)
            if (user.is_watching(username)) user.send_message(msg);
    }

    private void set_status(uint new_status)
    {
        status = new_status;
        send_to_watching(
            new SGetUserStatus(username, new_status, privileged)
        );
    }


    // Rooms

    void join_room(Room room)
    {
        joined_rooms[room.name] = room;
    }

    void leave_room(Room room)
    {
        if (room.name in joined_rooms)
            joined_rooms.remove(room.name);
    }

    string list_joined_rooms()
    {
        string rooms;
        foreach (room_name, room ; joined_rooms) rooms ~= room_name ~ " ";
        return rooms;
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

    void send_message(SMessage msg)
    {
        const msg_buf = msg.bytes;
        const msg_len = cast(uint) msg_buf.length;
        const offset = out_buf.length;

        out_buf.length += (uint.sizeof + msg_len);
        out_buf[offset .. offset + uint.sizeof] = msg_len.nativeToLittleEndian;
        out_buf[offset + uint.sizeof .. $] = msg_buf;

        debug (msg) writefln(
            "Sending -> %s (code %d) of %d bytes -> to user %s",
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
                const msg = new ULogin(msg_buf);

                if (status != Status.offline)
                    break;

                const error = server.check_login(msg.username, msg.password);

                if (error) {
                    username = msg.username;
                    should_quit = true;
                    writefln(
                        "User %s denied (%s)",
                        red ~ username ~ norm, red ~ error ~ norm
                    );
                    send_message(new SLogin(false, error));
                    break;
                }

                auto user = server.get_user(msg.username);

                if (user && user.status != Status.offline) {
                    writefln(
                        "User %s already logged in with version %d.%d",
                        red ~ msg.username ~ norm,
                        user.major_version, user.minor_version
                    );
                    user.send_message(new SRelogged());
                    user.quit();
                }
                writefln(
                    "User %s logging in with version %d.%d",
                    blue ~ msg.username ~ norm,
                    msg.major_version, msg.minor_version
                );
                login(msg);
                break;

            case SetWaitPort:
                const msg = new USetWaitPort(msg_buf, username);
                port = cast(ushort) msg.port;
                break;

            case GetPeerAddress:
                const msg = new UGetPeerAddress(msg_buf, username);
                auto user = server.get_user(msg.user);
                uint user_address;
                uint user_port;

                if (user) {
                    user_address = user.address;
                    user_port = user.port;
                }

                send_message(
                    new SGetPeerAddress(msg.user, user_address, user_port)
                );
                break;

            case WatchUser:
                const msg = new UWatchUser(msg_buf, username);
                auto user = server.get_user(msg.user);

                bool user_exists;
                uint user_status = Status.offline;
                uint user_speed, user_upload_number, user_something;
                uint user_shared_files, user_shared_folders;
                string user_country_code;

                if (msg.user == server_user) {
                    user_exists = true;
                    user_status = Status.online;
                }
                else if (user)
                {
                    user_exists = true;
                    user_status = user.status;
                    user_speed = user.speed;
                    user_upload_number = user.upload_number;
                    user_something = user.something;
                    user_shared_files = user.shared_files;
                    user_shared_folders = user.shared_folders;
                    user_country_code = user.country_code;
                }
                else {
                    const user_stats = server.db.get_user_stats(msg.user);
                    user_exists = user_stats.exists;
                    user_speed = user_stats.speed;
                    user_upload_number = user_stats.upload_number;
                    user_shared_files = user_stats.shared_files;
                    user_shared_folders = user_stats.shared_folders;
                }

                watch(msg.user);
                send_message(
                    new SWatchUser(
                        msg.user, user_exists, user_status, user_speed,
                        user_upload_number, user_something, user_shared_files,
                        user_shared_folders, user_country_code
                    )
                );
                break;

            case UnwatchUser:
                const msg = new UUnwatchUser(msg_buf, username);
                unwatch(msg.user);
                break;

            case GetUserStatus:
                const msg = new UGetUserStatus(msg_buf, username);
                auto user = server.get_user(msg.user);
                uint user_status = Status.offline;
                bool user_privileged;

                if (msg.user == server_user) {
                    debug (user) writefln(
                        "Telling user %s that host %s is online",
                        blue ~ username ~ norm, blue ~ server_user ~ norm
                    );
                    user_status = Status.online;
                }
                else if (user) {
                    debug (user) writefln(
                        "Telling user %s that user %s is online",
                        blue ~ username ~ norm, blue ~ msg.user ~ norm
                    );
                    user_status = user.status;
                    user_privileged = user.privileged;
                }
                else if (server.db.user_exists(msg.user)) {
                    debug (user) writefln(
                        "Telling user %s that user %s is offline",
                        blue ~ username ~ norm, red ~ msg.user ~ norm
                    );
                    user_privileged = server.db.get_user_privileges(msg.user)
                        > Clock.currTime.toUnixTime;
                }
                else {
                    debug (user) writefln(
                        "Telling user %s that non-existant user %s is offline",
                        blue ~ username ~ norm, red ~ msg.user ~ norm
                    );
                }

                send_message(
                    new SGetUserStatus(msg.user, user_status, user_privileged)
                );
                break;

            case SayChatroom:
                const msg = new USayChatroom(msg_buf, username);
                auto room = Room.get_room(msg.room);
                if (!room)
                    break;

                room.say(username, msg.message);
                foreach (global_username ; Room.global_room_users) {
                    auto user = server.get_user(global_username);
                    user.send_message(
                        new SGlobalRoomMessage(
                            msg.room, username, msg.message
                        )
                    );
                }
                break;

            case JoinRoom:
                const msg = new UJoinRoom(msg_buf, username);
                if (server.check_name(msg.room))
                    Room.join_room(msg.room, this);
                break;

            case LeaveRoom:
                const msg = new ULeaveRoom(msg_buf, username);
                auto room = Room.get_room(msg.room);
                if (!room)
                    break;

                room.leave(this);
                send_message(new SLeaveRoom(msg.room));
                break;

            case ConnectToPeer:
                const msg = new UConnectToPeer(msg_buf, username);
                auto user = server.get_user(msg.user);
                if (!user)
                    break;

                const ia = new InternetAddress(user.address, user.port);
                debug (user) writefln(
                    "User %s trying to connect indirectly to peer %s @ %s",
                    blue ~ username ~ norm, blue ~ msg.user ~ norm, ia
                );
                user.send_message(
                    new SConnectToPeer(
                        user.username, msg.type, user.address, user.port,
                        msg.token, user.privileged
                    )
                );
                break;

            case MessageUser:
                const msg = new UMessageUser(msg_buf, username);
                auto user = server.get_user(msg.user);

                if (msg.user == server_user) {
                    server.admin_message(this, msg.message);
                }
                else if (user) {
                    // user is connected
                    auto pm = new PM(msg.message, username, msg.user);
                    const new_message = true;

                    PM.add_pm(pm);
                    user.send_pm(pm, new_message);
                }
                else if (server.db.user_exists(msg.user)) {
                    // user exists but not connected
                    PM.add_pm(new PM(msg.message, username, msg.user));
                }
                break;

            case MessageAcked:
                const msg = new UMessageAcked(msg_buf, username);
                PM.del_pm(msg.id);
                break;

            case FileSearch:
                const msg = new UFileSearch(msg_buf, username);
                server.do_FileSearch(msg.token, msg.query, username);
                break;

            case SetStatus:
                const msg = new USetStatus(msg_buf, username);
                set_status(msg.status);
                break;

            case ServerPing:
                const msg = new UServerPing(msg_buf, username);
                break;

            case SharedFoldersFiles:
                const msg = new USharedFoldersFiles(msg_buf, username);
                debug (user) writefln(
                    "User %s reports sharing %d files in %d folders",
                    blue ~ username ~ norm, msg.nb_files, msg.nb_folders
                );
                set_shared_folders(msg.nb_folders);
                set_shared_files(msg.nb_files);

                send_to_watching(
                    new SGetUserStats(
                        username, speed, upload_number, something,
                        shared_files, shared_folders
                    )
                );
                break;

            case GetUserStats:
                const msg = new UGetUserStats(msg_buf, username);
                auto user = server.get_user(msg.user);

                uint user_speed, user_upload_number, user_something;
                uint user_shared_files, user_shared_folders;

                if (user) {
                    user_speed = user.speed;
                    user_upload_number = user.upload_number;
                    user_something = user.something;
                    user_shared_files = user.shared_files;
                    user_shared_folders = user.shared_folders;
                }
                else {
                    const user_stats = server.db.get_user_stats(msg.user);
                    user_speed = user_stats.speed;
                    user_upload_number = user_stats.upload_number;
                    user_shared_files = user_stats.shared_files;
                    user_shared_folders = user_stats.shared_folders;
                }

                send_message(
                    new SGetUserStats(
                        msg.user, user_speed, user_upload_number,
                        user_something, user_shared_files, user_shared_folders
                    )
                );
                break;

            case UserSearch:
                const msg = new UUserSearch(msg_buf, username);
                server.do_UserSearch(msg.token, msg.query, username, msg.user);
                break;

            case AddThingILike:
                const msg = new UAddThingILike(msg_buf, username);
                add_thing_he_likes(msg.thing);
                break;

            case RemoveThingILike:
                const msg = new URemoveThingILike(msg_buf, username);
                del_thing_he_likes(msg.thing);
                break;

            case AddThingIHate:
                const msg = new UAddThingIHate(msg_buf, username);
                add_thing_he_hates(msg.thing);
                break;

            case RemoveThingIHate:
                const msg = new URemoveThingIHate(msg_buf, username);
                del_thing_he_hates(msg.thing);
                break;

            case GetRecommendations:
                const msg = new UGetRecommendations(msg_buf, username);
                send_message(new SGetRecommendations(recommendations));
                break;

            case GlobalRecommendations:
                const msg = new UGlobalRecommendations(msg_buf, username);
                send_message(
                    new SGetGlobalRecommendations(global_recommendations)
                );
                break;

            case SimilarUsers:
                const msg = new USimilarUsers(msg_buf, username);
                send_message(new SSimilarUsers(similar_users));
                break;

            case UserInterests:
                const msg = new UUserInterests(msg_buf, username);
                auto user = server.get_user(msg.user);
                if (!user)
                    break;

                send_message(
                    new SUserInterests(
                        user.username, user.liked_things, user.hated_things
                    )
                );
                break;

            case RoomList:
                const msg = new URoomList(msg_buf, username);
                send_message(new SRoomList(Room.room_stats));
                break;

            case CheckPrivileges:
                const msg = new UCheckPrivileges(msg_buf, username);
                send_message(new SCheckPrivileges(privileges));
                break;

            case WishlistSearch:
                const msg = new UWishlistSearch(msg_buf, username);
                server.do_FileSearch(msg.token, msg.query, username);
                break;

            case ItemRecommendations:
                const msg = new UItemRecommendations(msg_buf, username);
                send_message(
                    new SItemRecommendations(
                        msg.item, get_item_recommendations(msg.item)
                    )
                );
                break;

            case ItemSimilarUsers:
                const msg = new UItemSimilarUsers(msg_buf, username);
                send_message(
                    new SItemSimilarUsers(
                        msg.item, get_item_similar_users(msg.item)
                    )
                );
                break;

            case SetRoomTicker:
                const msg = new USetRoomTicker(msg_buf, username);
                auto room = Room.get_room(msg.room);
                if (room) room.add_ticker(username, msg.tick);
                break;

            case RoomSearch:
                const msg = new URoomSearch(msg_buf, username);
                server.do_RoomSearch(msg.token, msg.query, username, msg.room);
                break;

            case SendUploadSpeed:
                const msg = new USendUploadSpeed(msg_buf, username);
                auto user = server.get_user(username);
                if (!user)
                    break;

                user.calc_speed(msg.speed);
                debug (user) writefln(
                    "User %s reports speed of %d B/s (~ %d B/s)",
                    blue ~ username ~ norm, msg.speed, user.speed
                );
                break;

            case UserPrivileged:
                const msg = new UUserPrivileged(msg_buf, username);
                auto user = server.get_user(msg.user);
                if (!user)
                    break;

                send_message(
                    new SUserPrivileged(user.username, user.privileged)
                );
                break;

            case GivePrivileges:
                const msg = new UGivePrivileges(msg_buf, username);
                auto user = server.get_user(msg.user);
                const admin = server.db.is_admin(msg.user);
                if (!user)
                    break;
                if (msg.time > privileges && !admin)
                    break;

                user.add_privileges(msg.time * 3600 * 24);
                if (!admin) remove_privileges(msg.time * 3600 * 24);
                break;

            case ChangePassword:
                const msg = new UChangePassword(msg_buf, username);

                server.db.user_update_field(
                    username, "password", server.encode_password(msg.password)
                );
                send_message(new SChangePassword(msg.password));
                break;

            case MessageUsers:
                const msg = new UMessageUsers(msg_buf, username);
                bool new_message = true;

                foreach (target_username ; msg.users) {
                    auto user = server.get_user(target_username);
                    if (!user)
                        continue;

                    user.send_pm(
                        new PM(msg.message, username, target_username),
                        new_message
                    );
                }
                break;

            case JoinGlobalRoom:
                const msg = new UJoinGlobalRoom(msg_buf, username);
                Room.add_global_room_user(username);
                break;

            case LeaveGlobalRoom:
                const msg = new ULeaveGlobalRoom(msg_buf, username);
                Room.remove_global_room_user(username);
                break;

            case CantConnectToPeer:
                const msg = new UCantConnectToPeer(msg_buf, username);
                auto user = server.get_user(msg.user);
                if (user)
                    user.send_message(new SCantConnectToPeer(msg.token));
                break;

            default:
                debug (msg) writefln(
                    red ~ "Unimplemented message code %d" ~ norm
                    ~ " from user %s with length %d\n%s",
                    code, blue ~ username ~ norm, msg_buf.length, msg_buf
                );
                break;
        }
    }

    private void login(const ULogin msg)
    {
        username = msg.username;
        major_version = msg.major_version;
        minor_version = msg.minor_version;
        priv_expiration = server.db.get_user_privileges(username);

        const user_stats = server.db.get_user_stats(username);
        speed = user_stats.speed;
        upload_number = user_stats.upload_number;
        shared_files = user_stats.shared_files;
        shared_folders = user_stats.shared_folders;

        if (server.db.is_admin(username)) writefln("%s is an admin", username);
        server.add_user(this);
        watch(username);

        send_message(
            new SLogin(
                true, server.get_motd(this), address,
                server.encode_password(msg.password), supporter
            )
        );
        send_message(new SRoomList(Room.room_stats));
        send_message(
            new SWishlistInterval(privileged ? 120 : 720)  // in seconds
        );
        set_status(Status.online);

        foreach (pm ; PM.get_pms_for(username)) {
            const new_message = false;
            debug (user) writefln(
                "Sending offline PM (id %d) from %s to %s",
                pm.id, pm.from, blue ~ username ~ norm
            );
            send_pm(pm, new_message);
        }
    }

    void quit()
    {
        if (status == Status.offline)
            return;

        foreach (room ; joined_rooms) room.leave(this);
        Room.remove_global_room_user(username);

        set_status(Status.offline);
        writefln("User %s has quit", red ~ username ~ norm);
    }
}
