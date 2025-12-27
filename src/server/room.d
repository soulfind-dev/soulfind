// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server.room;
@safe:

import soulfind.db : Sdb;
import soulfind.defines : blue, log_msg, max_chat_message_length,
                          max_room_ticker_length, max_room_tickers, norm,
                          RoomType;
import soulfind.server.conns : Logging;
import soulfind.server.messages;
import soulfind.server.user : User;
import std.datetime.systime : Clock, SysTime;
import std.stdio : writeln;

final class Room
{
    const string            name;
    const RoomType          type;

    private Sdb             db;
    private GlobalRoom      global_room;
    private User[string]    users;


    this(string name, RoomType type, Sdb db, GlobalRoom global_room)
    {
        this.name = name;
        this.type = type < 0 ? RoomType._public : type;
        this.db = db;
        this.global_room = global_room;
    }

    void disband()
    {
        foreach (ref user ; users) {
            enum permanent = true;
            user.leave_room(name, permanent);
        }
    }


    // Users

    void add_user(User user)
    {
        if (user.username in users)
            return;

        users[user.username] = user;

        scope joined_room_msg = new SUserJoinedRoom(
            name, user.username, user.status, user.upload_speed,
            user.upload_slots_full, user.shared_files, user.shared_folders
        );
        scope join_room_msg = new SJoinRoom(
            name, users, db.get_room_owner(name), null
        );
        scope tickers_msg = new SRoomTicker(name, tickers);

        send_to_all(joined_room_msg);
        user.send_message(join_room_msg);
        user.send_message(tickers_msg);
    }

    void remove_user(string username)
    {
        if (username !in users)
            return;

        auto user = users[username];
        users.remove(username);

        scope left_room_msg = new SUserLeftRoom(name, username);
        scope leave_room_msg = new SLeaveRoom(name);

        send_to_all(left_room_msg);
        user.send_message(leave_room_msg);
    }

    bool is_joined(string username)
    {
        return (username in users) ? true : false;
    }

    bool is_member(string username)
    {
        return is_joined(username) || db.is_room_member(name, username);
    }

    size_t num_users()
    {
        return users.length;
    }

    void send_to_all(scope SMessage msg, bool[string] excluded_users = null)
    {
        if (log_msg) writeln(
            "Transmit=> ", blue, msg.name, norm, " (code ", msg.code,
            ") to joined room members..."
        );
        foreach (ref user ; users)
            if (user.username !in excluded_users)
                user.send_message!(Logging.disabled)(msg);
    }


    // Chat

    void say(string username, string message)
    {
        if (username !in users)
            return;

        if (message.length > max_chat_message_length)
            return;

        foreach (ref c ; message) if (c == '\n' || c == '\r')
            return;

        scope msg = new SSayChatroom(name, username, message);
        send_to_all(msg);
        global_room.say(name, username, message);
    }


    // Tickers

    void add_ticker(string username, string content)
    {
        if (username !in users)
            return;

        if (content.length > max_room_ticker_length)
            return;

        const old_content = get_ticker(username);
        if (content == old_content)
            return;

        if (old_content !is null)
            del_ticker(username);

        if (content.length == 0)
            return;

        db.add_ticker(name, username, content);

        if (num_tickers >= max_room_tickers)
            del_oldest_ticker ();

        scope msg = new SRoomTickerAdd(name, username, content);
        send_to_all(msg);
    }

    void del_ticker(string username)
    {
        if (get_ticker(username) is null)
            return;

        db.del_ticker(name, username);

        scope msg = new SRoomTickerRemove(name, username);
        send_to_all(msg);
    }

    ulong num_tickers()
    {
        return db.num_room_tickers(name);
    }

    private void del_oldest_ticker()
    {
        const username = db.del_oldest_ticker(name);
        if (username is null)
            return;

        scope msg = new SRoomTickerRemove(name, username);
        send_to_all(msg);
    }

    private string get_ticker(string username)
    {
        return db.get_ticker(name, username);
    }

    private string[][] tickers()
    {
        return db.room_tickers(name);
    }
}

final class GlobalRoom
{
    private User[string] users;


    void add_user(User user)
    {
        if (user.username !in users)
            users[user.username] = user;
    }

    void remove_user(string username)
    {
        if (username in users)
             users.remove(username);
    }

    bool is_joined(string username)
    {
        return (username in users) ? true : false;
    }

    void say(string room_name, string username, string message)
    {
        scope msg = new SGlobalRoomMessage(room_name, username, message);
        foreach (ref user ; users) user.send_message(msg);
    }
}
