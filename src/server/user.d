// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server.user;
@safe:

import soulfind.db : Sdb, SdbUserStats;
import soulfind.defines : blue, bold, log_user, login_timeout,
                          max_interest_length, max_room_name_length,
                          max_username_length, norm, pbkdf2_iterations, red,
                          server_username, speed_weight, VERSION,
                          wish_interval, wish_interval_privileged;
import soulfind.pwhash : create_salt, hash_password_async,
                         verify_password_async;
import soulfind.server.conns : Logging, UserConnection;
import soulfind.server.messages;
import soulfind.server.msghandler : MessageHandler;
import soulfind.server.room : Room;
import soulfind.server.server : Server;
import std.ascii : isPrintable;
import std.conv : text;
import std.datetime : Clock, Duration, MonoTime, seconds;
import std.digest : digest, LetterCase, toHexString;
import std.digest.md : MD5;
import std.random : uniform;
import std.socket : InternetAddress;
import std.stdio : writeln;
import std.string : replace, strip, toLower;

final class User
{
    string                  username;
    string                  client_version;
    InternetAddress         address;
    ObfuscationType         obfuscation_type;
    ushort                  obfuscated_port;

    UserStatus              status;
    LoginRejection          login_rejection;
    bool                    authenticated;
    bool                    disconnecting;

    uint                    upload_speed;  // in B/s
    uint                    shared_files;
    uint                    shared_folders;
    SysTime                 privileged_until;

    private Server          server;
    private UserConnection  conn;

    private string[string]  liked_items;
    private string[string]  hated_items;
    private Room[string]    joined_rooms;
    private string[string]  watched_users;


    this(Server server, UserConnection conn)
    {
        this.server   = server;
        this.conn     = conn;
        this.address  = new InternetAddress(conn.address.addr,
                                            InternetAddress.PORT_ANY);
    }


    // Login

    string motd()
    {
        return server.db.server_motd
            .replace("%sversion%", VERSION)
            .replace("%users%", server.num_connected_users.text)
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
        return (MonoTime.currTime - conn.created_monotime) > login_timeout;
    }

    bool should_update_login_status()
    {
        return (
            !disconnecting && authenticated && status == UserStatus.offline
        );
    }

    void authenticate(string username, string password)
    {
        const user_exists = server.db.user_exists(username);

        if (!user_exists && server.db.server_private_mode) {
            reject_login(LoginRejectionReason.server_private);
            return;
        }

        if (server.num_connected_users >= server.db.server_max_users) {
            reject_login(LoginRejectionReason.server_full);
            return;
        }

        const invalid_name_reason = check_username(username);
        if (invalid_name_reason) {
            reject_login(
                LoginRejectionReason.invalid_username,
                invalid_name_reason
            );
            return;
        }

        if (password.length == 0) {
            reject_login(LoginRejectionReason.empty_password);
            return;
        }

        if (!user_exists) {
            const salt = create_salt();
            hash_password_async(
                password, salt, pbkdf2_iterations, &password_hashed
            );
            return;
        }

        const stored_hash = server.db.user_password_hash(username);
        verify_password_async(stored_hash, password, &password_verified);
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
            reject_login(LoginRejectionReason.invalid_password);
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

        if (wait_for_messages && conn.is_sending)
            return;

        server.close_connection(conn);
    }

    bool disconnect_orphan()
    {
        if (disconnecting || server.db.user_exists(username))
            return false;

        // If the user was removed from the database, perform
        // server-side removal and disconnection of deleted
        // users. Send a Relogged message first to prevent the
        // user's client from automatically reconnecting and
        // registering again.

        const include_received = true;
        server.del_user_pms(username, include_received);
        server.del_user_tickers(username);

        scope relogged_msg = new SRelogged();
        send_message(relogged_msg);
        disconnect();

        return true;
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

    private void reject_login(LoginRejectionReason reason,
                              string detail = null)
    {
        login_rejection = LoginRejection(reason, detail);
        scope response_msg = new SLogin(false, login_rejection);
        send_message(response_msg);
    }

    private void finish_login(string password, string hash = null)
    {
        authenticated = true;
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

        if (hash !is null) server.db.add_user(username, hash);

        const user_stats = server.db.user_stats(username);
        upload_speed = user_stats.upload_speed;
        shared_files = user_stats.shared_files;
        shared_folders = user_stats.shared_folders;

        refresh_privileges(false);

        writeln(
            server.db.admin_until(username) > Clock.currTime ?
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
        send_message(response_msg);
        send_message(room_list_msg);
        send_message(wish_interval_msg);
        send_message(privileged_users_msg);

        server.send_search_filters(username);
        server.deliver_queued_pms(username);
    }

    private void change_password(string password, string hash,
                                 bool notify_user = false)
    {
        server.db.user_update_password(username, hash);

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

    void update_upload_speed(uint new_speed)
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

        server.db.user_update_stats(username, stats);
    }

    void update_shared_stats(uint new_files, uint new_folders)
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
        const was_privileged = privileged;
        privileged_until = server.db.user_privileged_until(username);

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

    Duration privileges()
    {
        if (privileged)
            return privileged_until - Clock.currTime;

        return 0.seconds;
    }


    // Watchlist

    void watch(string target_username)
    {
        if (target_username != server_username)
            watched_users[target_username] = target_username;
    }

    void unwatch(string target_username)
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

    void add_liked_item(string item)
    {
        if (item.length == 0 || item.length > max_interest_length)
            return;

        item = item.toLower;
        if (!likes(item)) liked_items[item] = item;
    }

    void del_liked_item(string item)
    {
        item = item.toLower;
        if (likes(item)) liked_items.remove(item);
    }

    void add_hated_item(string item)
    {
        if (item.length == 0 || item.length > max_interest_length)
            return;

        item = item.toLower;
        if (!hates(item)) hated_items[item] = item;
    }

    void del_hated_item(string item)
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


    // Connection I/O

    void handle_io_events(bool recv_ready, bool send_ready)
    {
        bool recv_success = true;
        bool send_success = true;

        if (recv_ready)
            recv_success = conn.recv_buffer(this);

        if (send_ready) {
            send_success = conn.send_buffer();
        }
        else if (should_update_login_status) {
            // In order to receive the SetWaitPort message from the
            // user in time, delay the initial status update and
            // broadcast to watching users as much as possible.
            // Otherwise we may end up sending the default dummy
            // listening port to watching users attempting to resume
            // file transfers.
            update_status(UserStatus.online);
        }

        const io_success = recv_success && send_success;
        if (io_success && conn.is_sending)
            // In order to avoid closing connections early before delivering
            // e.g. a Relogged message, wait until the output buffer is sent
            return;

        if (io_success && !disconnecting && !login_rejection.reason)
            return;

        const wait_for_messages = false;
        disconnect(wait_for_messages);
    }

    void send_message(Logging log = Logging.all)(scope SMessage msg)
    {
        conn.send_message!log(msg, username);
    }
}
