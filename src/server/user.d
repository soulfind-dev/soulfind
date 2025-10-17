// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server.user;
@safe:

import soulfind.db : Sdb, SdbUserStats;
import soulfind.defines : blue, bold, log_msg, log_user, login_timeout,
                          max_interest_length, max_msg_size,
                          max_room_name_length, max_username_length, norm,
                          pbkdf2_iterations, red, SearchFilterType,
                          server_username, speed_weight, VERSION,
                          wish_interval, wish_interval_privileged;
import soulfind.pwhash : create_salt, hash_password_async,
                         verify_password_async;
import soulfind.select : SelectEvent;
import soulfind.server.messages;
import soulfind.server.pm : PM;
import soulfind.server.room : Room;
import soulfind.server.server : Server;
import std.array : Appender;
import std.ascii : isPrintable;
import std.bitmanip : Endian, nativeToLittleEndian, peek, read;
import std.conv : ConvException, text, to;
import std.datetime : Clock, Duration, MonoTime, seconds, SysTime;
import std.digest : digest, LetterCase, toHexString;
import std.digest.md : MD5;
import std.random : uniform;
import std.socket : InternetAddress, Socket;
import std.stdio : writeln;
import std.string : join, replace, strip, toLower;

final class User
{
    string                  username;
    string                  client_version;
    InternetAddress         address;
    ObfuscationType         obfuscation_type;
    ushort                  obfuscated_port;

    UserStatus              status;
    LoginRejection          login_rejection;
    bool                    login_verified;
    bool                    disconnecting;

    uint                    upload_speed;  // in B/s
    uint                    shared_files;
    uint                    shared_folders;
    SysTime                 privileged_until;

    private const MonoTime  connected_monotime;
    private Server          server;
    private Sdb             db;
    private Socket          sock;

    private string[string]  liked_items;
    private string[string]  hated_items;

    private Room[string]    joined_rooms;

    private string[string]  watched_users;

    private ubyte[]         in_buf;
    private long            in_msg_size = -1;
    private ubyte[]         out_buf;


    this(Server server, Sdb db, Socket sock, InternetAddress address)
    {
        this.server              = server;
        this.db                  = db;
        this.sock                = sock;
        this.address             = address;
        this.connected_monotime  = MonoTime.currTime;
    }


    // Login

    string motd()
    {
        return db.server_motd
            .replace("%sversion%", VERSION)
            .replace("%users%", server.num_users.text)
            .replace("%username%", username)
            .replace("%version%", client_version);
    }

    bool login_timed_out()
    {
        if (status != UserStatus.offline)
            return false;

        // Login attempts always time out for banned users. Add jitter to
        // login timeout to spread out reconnect attempts after e.g. kicking
        // all online users, which also bans them for a few minutes.
        const login_timeout = login_timeout + uniform(0, 30).seconds;
        return (MonoTime.currTime - connected_monotime) > login_timeout;
    }

    void password_hashed(string password, string hash)
    {
        if (disconnecting)
            return;

        if (status != UserStatus.offline) {
            const notify_user = true;
            change_password(password, hash, notify_user);
            return;
        }
        finish_login(password, hash);
    }

    void password_upgraded(string password, string hash)
    {
        if (disconnecting)
            return;

        change_password(password, hash);
    }

    void password_verified(string password, bool matches, uint iterations)
    {
        if (disconnecting)
            return;

        if (!matches) {
            reject_login(
                LoginRejection(LoginRejectionReason.invalid_password)
            );
            return;
        }

        finish_login(password);

        // Upgrade password strength
        if (iterations < pbkdf2_iterations) {
            const salt = create_salt();
            hash_password_async(
                password, salt, pbkdf2_iterations, &password_upgraded
            );
        }
    }

    void disconnect(bool wait_for_messages = true)
    {
        unwatch(username);
        server.del_user(username);

        if (!disconnecting) {
            if (status == UserStatus.offline) {
                if (login_rejection.reason) writeln(
                    "User ", red, username, norm, " denied (", red,
                    login_rejection.reason, norm, ")"
                );
            }
            else {
                foreach (ref name, ref _room ; joined_rooms) leave_room(name);
                server.remove_global_room_user(username);

                update_status(UserStatus.offline);
                writeln("User ", red, username, norm, " logged out");
            }
        }
        disconnecting = true;

        if (wait_for_messages && is_sending)
            return;

        if (sock is null)
            return;

        server.close_user_socket(sock);

        if (log_user) writeln("Closed connection to user ", username);
        sock = null;
    }

    private string check_username(string username)
    {
        if (username.length == 0)
            return "Nick empty.";

        if (username.length > max_username_length)
            return "Nick too long.";

        if (username.strip != username)
            return "No leading and trailing spaces allowed in nick.";

        foreach (ref c ; username) if (!c.isPrintable)
            // Only printable ASCII characters allowed
            return "Invalid characters in nick.";

        static immutable forbidden_names = [server_username];

        foreach (ref name ; forbidden_names) if (name == username)
            // Official server returns empty detail
            return "";

        return null;
    }

    private LoginRejection verify_login(string username, string password)
    {
        auto login_rejection = LoginRejection();
        const user_exists = db.user_exists(username);

        if (!user_exists && db.server_private_mode) {
            login_rejection.reason = LoginRejectionReason.server_private;
            return login_rejection;
        }

        if (server.num_users >= db.server_max_users) {
            login_rejection.reason = LoginRejectionReason.server_full;
            return login_rejection;
        }

        const invalid_name_reason = check_username(username);
        if (invalid_name_reason) {
            login_rejection.reason = LoginRejectionReason.invalid_username;
            login_rejection.detail = invalid_name_reason;
            return login_rejection;
        }

        if (password.length == 0) {
            login_rejection.reason = LoginRejectionReason.empty_password;
            return login_rejection;
        }

        if (!user_exists) {
            const salt = create_salt();
            hash_password_async(
                password, salt, pbkdf2_iterations, &password_hashed
            );
            return login_rejection;
        }

        const stored_hash = db.user_password_hash(username);
        verify_password_async(stored_hash, password, &password_verified);
        return login_rejection;
    }

    private void reject_login(LoginRejection login_rejection)
    {
        scope response_msg = new SLogin(false, login_rejection);
        send_message(response_msg);
    }

    private void finish_login(string password, string hash = null)
    {
        login_verified = true;
        auto user = server.get_user(username);

        if (user !is null && user.status != UserStatus.offline) {
            writeln(
                "User ", red, username, norm, " already logged in, ",
                "disconnecting"
            );
            scope relogged_msg = new SRelogged();
            user.send_message(relogged_msg);
            user.disconnect();
        }

        if (hash !is null) db.add_user(username, hash);

        const user_stats = db.user_stats(username);
        upload_speed = user_stats.upload_speed;
        shared_files = user_stats.shared_files;
        shared_folders = user_stats.shared_folders;

        refresh_privileges(false);

        writeln(
            db.admin_until(username) > Clock.currTime ?
            "Admin " : "User ", blue, username, norm,
            " logged in with client version ", bold, client_version, norm
        );

        server.add_user(this);
        watch(username);

        // Empty list of users for privacy reasons. Clients can use
        // other server messages to know if a user is privileged.
        string[] privileged_users;
        const md5_hash = digest!MD5(password)
            .toHexString!(LetterCase.lower)
            .idup;
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
        scope excluded_phrases_msg = new SExcludedSearchPhrases(
            db.search_filters!(SearchFilterType.client)
        );
        send_message(response_msg);
        send_message(room_list_msg);
        send_message(wish_interval_msg);
        send_message(privileged_users_msg);
        send_message(excluded_phrases_msg);

        server.deliver_queued_pms(username);
    }

    private void change_password(string password, string hash,
                                 bool notify_user = false)
    {
        db.user_update_password(username, hash);

        if (!notify_user)
            return;

        scope response_msg = new SChangePassword(password);
        send_message(response_msg);
    }


    // Status

    void update_status(uint new_status)
    {
        if (new_status == status)
            return;

        final switch (new_status) {
            case UserStatus.offline:
            case UserStatus.away:
            case UserStatus.online:
                status = cast(UserStatus) new_status;
                scope msg = new SGetUserStatus(
                    username, new_status, privileged
                );
                server.send_to_watching(username, msg);
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
        server.send_to_watching(username, msg);

        auto stats = SdbUserStats();
        stats.upload_speed = upload_speed;
        stats.updating_speed = true;

        db.user_update_stats(username, stats);
    }

    private void update_shared_stats(uint new_files, uint new_folders)
    {
        shared_files = new_files;
        shared_folders = new_folders;

        auto stats = SdbUserStats();
        stats.shared_files = new_files;
        stats.shared_folders = new_folders;
        stats.updating_shared = true;

        db.user_update_stats(username, stats);
    }


    // Privileges

    void refresh_privileges(bool notify_user = true)
    {
        const was_privileged = privileged;
        privileged_until = db.user_privileged_until(username);

        if (!notify_user)
            return;

        if (privileged != was_privileged) {
            scope wish_interval_msg = new SWishlistInterval(
                privileged ? wish_interval_privileged : wish_interval
            );
            send_message(wish_interval_msg);
        }

        scope privileges_msg = new SCheckPrivileges(privileges);
        send_message(privileges_msg);
    }

    bool privileged()
    {
        return privileged_until > Clock.currTime;
    }

    bool supporter()
    {
        return privileged_until.stdTime > 0;
    }

    private Duration privileges()
    {
        if (privileged)
            return privileged_until - Clock.currTime;

        return 0.seconds;
    }


    // Watchlist

    private void watch(string target_username)
    {
        if (target_username != server_username)
            watched_users[target_username] = target_username;
    }

    private void unwatch(string target_username)
    {
        if (target_username in watched_users)
            watched_users.remove(target_username);
    }

    bool is_watching(string target_username)
    {
        return target_username in watched_users ? true : false;
    }

    size_t num_watched_users()
    {
        return watched_users.length;
    }


    // Interests

    private void add_liked_item(string item)
    {
        if (item.length == 0 || item.length > max_interest_length)
            return;

        item = item.toLower;
        if (!likes(item)) liked_items[item] = item;
    }

    private void del_liked_item(string item)
    {
        item = item.toLower;
        if (likes(item)) liked_items.remove(item);
    }

    private void add_hated_item(string item)
    {
        if (item.length == 0 || item.length > max_interest_length)
            return;

        item = item.toLower;
        if (!hates(item)) hated_items[item] = item;
    }

    private void del_hated_item(string item)
    {
        item = item.toLower;
        if (hates(item)) hated_items.remove(item);
    }

    bool likes(string item)
    {
        return item in liked_items ? true : false;
    }

    bool hates(string item)
    {
        return item in hated_items ? true : false;
    }

    const liked_item_names()
    {
        return liked_items.byKey;
    }

    const hated_item_names()
    {
        return hated_items.byKey;
    }


    // Rooms

    void join_room(string name)
    {
        string fail_message = check_room_name(name);
        if (fail_message) {
            server.send_pm(server_username, username, fail_message);
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

    const joined_room_names()
    {
        return joined_rooms.byKey;
    }

    bool joined_same_room(string target_username)
    {
        foreach (ref room ; joined_rooms)
            if (room.is_joined(target_username))
                return true;

        return false;
    }

    private string check_room_name(string room_name)
    {
        if (room_name.length == 0)
            return "Could not create room. Reason: Room name empty.";

        if (room_name.length > max_room_name_length)
            return text(
                "Could not create room. Reason: Room name ", room_name,
                " longer than ", max_room_name_length, " characters."
            );

        if (room_name.strip != room_name)
            return text(
                "Could not create room. Reason: Room name ", room_name,
                " contains leading or trailing spaces."
            );

        bool found_space;
        foreach (i, ref c ; room_name) {
            if (!c.isPrintable) {
                // Only printable ASCII characters allowed
                return text(
                    "Could not create room. Reason: Room name ", room_name,
                    " contains invalid characters."
                );
            }
            if (c != ' ') {
                found_space = false;
                continue;
            }
            if (found_space) {
                return text(
                    "Could not create room. Reason: Room name ", room_name,
                    " contains multiple following spaces."
                );
            }
            found_space = true;
        }
        return null;
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

        if (!is_sending)
            server.unregister_socket(sock, SelectEvent.write);

        return true;
    }

    void send_message(string log = "log_all")(scope SMessage msg)
        if (log == "log_all" || log == "log_redacted" || log == "log_disabled")
    {
        const msg_buf = msg.bytes;
        const msg_len = msg_buf.length;
        const offset = out_buf.length;
        const log_username = log == "log_redacted" ? "[ redacted ]" : username;

        if (log_msg && log != "log_disabled") writeln(
            "Sending -> ", blue, msg.name, norm, " (code ", msg.code,
            ") -> to user ", blue, log_username, norm
        );

        if (msg_len > uint.max) {
            writeln(
                "Message ", red, msg.name, norm, " (code ", msg.code,
                ") of ", msg_len, " bytes to user ", blue, log_username, norm,
                " is too large, not sending"
            );
            return;
        }

        out_buf.length += (uint.sizeof + msg_len);
        out_buf[offset .. offset + uint.sizeof] = (cast(uint) msg_len)
            .nativeToLittleEndian;
        out_buf[offset + uint.sizeof .. $] = msg_buf;

        server.register_socket(sock, SelectEvent.write);
    }

    bool recv_buffer()
    {
        ubyte[max_msg_size] receive_buf;
        const receive_len = sock.receive(receive_buf);
        if (receive_len == Socket.ERROR || receive_len == 0)
            return false;

        in_buf ~= receive_buf[0 .. receive_len];
        while (true) {
            if (in_msg_size == -1) {
                if (in_buf.length < uint.sizeof)
                    break;
                in_msg_size = in_buf.read!(uint, Endian.littleEndian);
            }
            if (in_msg_size < 0 || in_msg_size > max_msg_size) {
                if (log_msg) writeln(
                    "Received unexpected message size ", in_msg_size,
                    " from user ", blue, username, norm, ", ",
                    "disconnecting them"
                );
                return false;
            }
            if (in_buf.length < in_msg_size)
                break;

            if (!proc_message())
                break;
        }
        return true;
    }

    private bool proc_message()
    {
        auto msg_buf = in_buf[0 .. in_msg_size];
        const code = msg_buf.peek!(uint, Endian.littleEndian);

        if (!login_verified && code != Login)
            return false;

        in_buf = in_buf[in_msg_size .. $];
        in_msg_size = -1;

        switch (code) {
            case Login:
                scope msg = new ULogin(msg_buf);
                if (!msg.is_valid)
                    break;

                if (status != UserStatus.offline)
                    break;

                username = msg.username;
                const banned_until = db.user_banned_until(username);

                if (banned_until > Clock.currTime)
                    // The official server doesn't send a response when a user
                    // is banned. We also ban users temporarily when kicking
                    // them, and simply closing the connection after some time
                    // allows the client to automatically reconnect to the
                    // server.
                    break;

                login_rejection = verify_login(username, msg.password);
                if (banned_until.stdTime > 0) db.unban_user(username);

                client_version = text(
                    msg.major_version, ".", msg.minor_version
                );

                if (login_rejection.reason) {
                    reject_login(login_rejection);
                    break;
                }
                break;

            case SetWaitPort:
                scope msg = new USetWaitPort(msg_buf, username);
                if (!msg.is_valid)
                    break;

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
                obfuscation_type = cast(ObfuscationType) msg.obfuscation_type;
                obfuscated_port = cast(ushort) msg.obfuscated_port;
                break;

            case GetPeerAddress:
                scope msg = new UGetPeerAddress(msg_buf, username);
                if (!msg.is_valid)
                    break;

                auto user = server.get_user(msg.username);
                uint user_address;
                uint user_obfuscation_type;
                ushort user_port, user_obfuscated_port;

                if (user !is null) {
                    user_address = user.address.addr;
                    user_port = user.address.port;
                    user_obfuscation_type = user.obfuscation_type;
                    user_obfuscated_port = user.obfuscated_port;
                }

                scope response_msg = new SGetPeerAddress(
                    msg.username, user_address, user_port,
                    user_obfuscation_type, user_obfuscated_port
                );
                send_message(response_msg);
                break;

            case WatchUser:
                scope msg = new UWatchUser(msg_buf, username);
                if (!msg.is_valid)
                    break;

                auto user = server.get_user(msg.username);

                bool user_exists;
                uint user_status = UserStatus.offline;
                uint user_upload_speed;
                uint user_shared_files, user_shared_folders;

                if (user !is null)
                {
                    user_exists = true;
                    user_status = user.status;
                    user_upload_speed = user.upload_speed;
                    user_shared_files = user.shared_files;
                    user_shared_folders = user.shared_folders;
                }
                else if (msg.username == server_username) {
                    // Allow clients that check user existence to add the
                    // 'server' user to the user list, otherwise some of them
                    // have no way of opening a private chat tab.
                    user_exists = true;
                }
                else {
                    const user_stats = db.user_stats(msg.username);
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
                if (!msg.is_valid)
                    break;

                if (msg.username == username)
                    // Always watch our own username for updates
                    break;

                unwatch(msg.username);
                break;

            case GetUserStatus:
                scope msg = new UGetUserStatus(msg_buf, username);
                if (!msg.is_valid)
                    break;

                auto user = server.get_user(msg.username);
                uint user_status = UserStatus.offline;
                bool user_privileged;

                if (user !is null) {
                    user_status = user.status;
                    user_privileged = user.privileged;
                }
                else if (msg.username != server_username) {
                    user_privileged = (
                        db.user_privileged_until(msg.username) > Clock.currTime
                    );
                }

                scope response_msg = new SGetUserStatus(
                    msg.username, user_status, user_privileged
                );
                send_message(response_msg);
                break;

            case SayChatroom:
                scope msg = new USayChatroom(msg_buf, username);
                if (!msg.is_valid)
                    break;

                auto room = server.get_room(msg.room_name);
                if (room !is null) room.say(username, msg.message);
                break;

            case JoinRoom:
                scope msg = new UJoinRoom(msg_buf, username);
                if (!msg.is_valid)
                    break;

                join_room(msg.room_name);
                break;

            case LeaveRoom:
                scope msg = new ULeaveRoom(msg_buf, username);
                if (!msg.is_valid)
                    break;

                if (!leave_room(msg.room_name))
                    break;

                scope response_msg = new SLeaveRoom(msg.room_name);
                send_message(response_msg);
                break;

            case ConnectToPeer:
                scope msg = new UConnectToPeer(msg_buf, username);
                if (!msg.is_valid)
                    break;

                auto user = server.get_user(msg.username);
                if (user is null)
                    break;

                scope response_msg = new SConnectToPeer(
                    username, msg.type, address.addr, address.port, msg.token,
                    privileged, obfuscation_type, obfuscated_port
                );
                user.send_message!"log_redacted"(response_msg);
                break;

            case MessageUser:
                scope msg = new UMessageUser(msg_buf, username);
                if (!msg.is_valid)
                    break;

                if (msg.username == server_username) {
                    server.user_command(username, msg.message);
                    break;
                }
                server.send_pm(username, msg.username, msg.message);
                break;

            case MessageAcked:
                const in_username = "[ redacted ]";
                scope msg = new UMessageAcked(msg_buf, in_username);
                if (!msg.is_valid)
                    break;

                server.del_pm(msg.id, username);
                break;

            case FileSearch:
                scope msg = new UFileSearch(msg_buf, username);
                if (!msg.is_valid)
                    break;

                server.search_files(msg.token, msg.query, username);
                break;

            case SetStatus:
                scope msg = new USetStatus(msg_buf, username);
                if (!msg.is_valid)
                    break;

                if (msg.status == UserStatus.offline)
                    break;

                update_status(msg.status);
                break;

            case ServerPing:
                scope msg = new UServerPing(msg_buf, username);
                break;

            case SendConnectToken:
                scope msg = new USendConnectToken(msg_buf, username);
                if (!msg.is_valid)
                    break;

                auto user = server.get_user(msg.username);
                if (user is null)
                    break;

                scope response_msg = new SSendConnectToken(
                    username, msg.token
                );
                user.send_message!"log_redacted"(response_msg);
                break;

            case SharedFoldersFiles:
                scope msg = new USharedFoldersFiles(msg_buf, username);
                if (!msg.is_valid)
                    break;

                update_shared_stats(msg.shared_files, msg.shared_folders);

                scope response_msg = new SGetUserStats(
                    username, upload_speed, shared_files, shared_folders
                );
                server.send_to_watching(username, response_msg);
                break;

            case GetUserStats:
                scope msg = new UGetUserStats(msg_buf, username);
                if (!msg.is_valid)
                    break;

                auto user = server.get_user(msg.username);

                uint user_upload_speed;
                uint user_shared_files, user_shared_folders;

                if (user !is null) {
                    user_upload_speed = user.upload_speed;
                    user_shared_files = user.shared_files;
                    user_shared_folders = user.shared_folders;
                }
                else {
                    const user_stats = db.user_stats(msg.username);
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
                if (!msg.is_valid)
                    break;

                scope response_msg = new SQueuedDownloads(
                    username, msg.slots_full
                );
                server.send_to_joined_rooms(username, response_msg);
                break;

            case UserSearch:
                scope msg = new UUserSearch(msg_buf, username);
                if (!msg.is_valid)
                    break;

                server.search_user_files(
                    msg.token, msg.query, username, msg.username
                );
                break;

            case SimilarRecommendations:
                // No longer used, send empty response
                scope msg = new USimilarRecommendations(msg_buf, username);
                if (!msg.is_valid)
                    break;

                string[] recommendations;

                scope response_msg = new SSimilarRecommendations(
                    msg.recommendation, recommendations
                );
                send_message(response_msg);
                break;

            case AddThingILike:
                scope msg = new UAddThingILike(msg_buf, username);
                if (!msg.is_valid)
                    break;

                add_liked_item(msg.item);
                break;

            case RemoveThingILike:
                scope msg = new URemoveThingILike(msg_buf, username);
                if (!msg.is_valid)
                    break;

                del_liked_item(msg.item);
                break;

            case AddThingIHate:
                scope msg = new UAddThingIHate(msg_buf, username);
                if (!msg.is_valid)
                    break;

                add_hated_item(msg.item);
                break;

            case RemoveThingIHate:
                scope msg = new URemoveThingIHate(msg_buf, username);
                if (!msg.is_valid)
                    break;

                del_hated_item(msg.item);
                break;

            case GetRecommendations:
                scope msg = new UGetRecommendations(msg_buf, username);
                scope response_msg = new SGetRecommendations(
                    server.user_recommendations(username)
                );
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
                    server.global_recommendations
                );
                send_message(response_msg);
                break;

            case SimilarUsers:
                scope msg = new USimilarUsers(msg_buf, username);
                scope response_msg = new SSimilarUsers(
                    server.user_similar_users(username)
                );
                send_message(response_msg);
                break;

            case UserInterests:
                scope msg = new UUserInterests(msg_buf, username);
                if (!msg.is_valid)
                    break;

                auto user = server.get_user(msg.username);
                string[string] user_liked_items;
                string[string] user_hated_items;

                if (user !is null) {
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
                disconnect();
                break;

            case CheckPrivileges:
                scope msg = new UCheckPrivileges(msg_buf, username);
                scope response_msg = new SCheckPrivileges(privileges);
                send_message(response_msg);
                break;

            case WishlistSearch:
                scope msg = new UWishlistSearch(msg_buf, username);
                if (!msg.is_valid)
                    break;

                server.search_files(msg.token, msg.query, username);
                break;

            case ItemRecommendations:
                scope msg = new UItemRecommendations(msg_buf, username);
                if (!msg.is_valid)
                    break;

                scope response_msg = new SItemRecommendations(
                    msg.item, server.item_recommendations(msg.item)
                );
                send_message(response_msg);
                break;

            case ItemSimilarUsers:
                scope msg = new UItemSimilarUsers(msg_buf, username);
                if (!msg.is_valid)
                    break;

                scope response_msg = new SItemSimilarUsers(
                    msg.item, server.item_similar_users(msg.item)
                );
                send_message(response_msg);
                break;

            case SetRoomTicker:
                scope msg = new USetRoomTicker(msg_buf, username);
                if (!msg.is_valid)
                    break;

                auto room = server.get_room(msg.room_name);
                if (room !is null) room.add_ticker(username, msg.ticker);
                break;

            case RoomSearch:
                scope msg = new URoomSearch(msg_buf, username);
                if (!msg.is_valid)
                    break;

                server.search_room_files(
                    msg.token, msg.query, username, msg.room_name
                );
                break;

            case SendUploadSpeed:
                scope msg = new USendUploadSpeed(msg_buf, username);
                if (!msg.is_valid)
                    break;

                update_upload_speed(msg.speed);
                break;

            case UserPrivileged:
                scope msg = new UUserPrivileged(msg_buf, username);
                if (!msg.is_valid)
                    break;

                bool privileged;
                auto user = server.get_user(msg.username);
                if (user !is null)
                    privileged = user.privileged;
                else
                    privileged = (
                        db.user_privileged_until(msg.username) > Clock.currTime
                    );

                scope response_msg = new SUserPrivileged(
                    msg.username, privileged
                );
                send_message(response_msg);
                break;

            case GivePrivileges:
                scope msg = new UGivePrivileges(msg_buf, username);
                if (!msg.is_valid)
                    break;

                auto user = server.get_user(msg.username);
                if (user is null)
                    break;

                const duration = msg.duration;
                if (duration.total!"days" < 1 || duration > privileges)
                    break;

                db.add_user_privileges(msg.username, duration);
                user.refresh_privileges();

                db.remove_user_privileges(username, duration);
                refresh_privileges();
                break;

            case NotifyPrivileges:
                // No longer used, but official server still responds
                scope msg = new UNotifyPrivileges(msg_buf, username);
                if (!msg.is_valid)
                    break;

                scope response_msg = new SAckNotifyPrivileges(msg.token);
                send_message(response_msg);
                break;

            case PrivateRoomAddUser:
                scope msg = new UPrivateRoomAddUser(msg_buf, username);
                if (!msg.is_valid)
                    break;
                break;

            case PrivateRoomRemoveUser:
                scope msg = new UPrivateRoomRemoveUser(msg_buf, username);
                if (!msg.is_valid)
                    break;
                break;

            case PrivateRoomCancelMembership:
                scope msg = new UPrivateRoomCancelMembership(
                    msg_buf, username
                );
                if (!msg.is_valid)
                    break;
                break;

            case PrivateRoomDisown:
                scope msg = new UPrivateRoomDisown(msg_buf, username);
                if (!msg.is_valid)
                    break;
                break;

            case PrivateRoomToggle:
                scope msg = new UPrivateRoomToggle(msg_buf, username);
                if (!msg.is_valid)
                    break;

                scope response_msg = new SPrivateRoomToggle(msg.enabled);
                send_message(response_msg);
                break;

            case ChangePassword:
                scope msg = new UChangePassword(msg_buf, username);
                if (!msg.is_valid)
                    break;

                if (msg.password.length == 0)
                    break;

                const salt = create_salt();
                hash_password_async(
                    msg.password, salt, pbkdf2_iterations, &password_hashed
                );
                break;

            case PrivateRoomAddOperator:
                scope msg = new UPrivateRoomAddOperator(msg_buf, username);
                if (!msg.is_valid)
                    break;
                break;

            case PrivateRoomRemoveOperator:
                scope msg = new UPrivateRoomRemoveOperator(msg_buf, username);
                if (!msg.is_valid)
                    break;
                break;

            case MessageUsers:
                scope msg = new UMessageUsers(msg_buf, username);
                if (!msg.is_valid)
                    break;

                const connected_only = true;

                foreach (ref to_username ; msg.usernames)
                    server.send_pm(
                        username, to_username, msg.message, connected_only
                    );
                break;

            case JoinGlobalRoom:
                scope msg = new UJoinGlobalRoom(msg_buf, username);
                server.add_global_room_user(this);
                break;

            case LeaveGlobalRoom:
                scope msg = new ULeaveGlobalRoom(msg_buf, username);
                server.remove_global_room_user(username);
                break;

            case RelatedSearch:
                // No longer used, send empty response
                scope msg = new URelatedSearch(msg_buf, username);
                if (!msg.is_valid)
                    break;

                uint[string] terms;

                scope response_msg = new SRelatedSearch(
                    msg.query, terms
                );
                send_message(response_msg);
                break;

            case CantConnectToPeer:
                scope msg = new UCantConnectToPeer(msg_buf, username);
                if (!msg.is_valid)
                    break;

                auto user = server.get_user(msg.username);
                if (user is null)
                    break;

                scope response_msg = new SCantConnectToPeer(msg.token);
                user.send_message!"log_redacted"(response_msg);
                break;

            default:
                if (log_msg) writeln(
                    "Unimplemented message code ", red, code, norm,
                    " from user ", blue, username, norm, " with length ",
                    msg_buf.length
                );
                break;
        }
        return true;
    }
}
