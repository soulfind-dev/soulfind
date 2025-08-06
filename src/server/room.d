// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server.room;
@safe:

import soulfind.db : Sdb;
import soulfind.defines : max_chat_message_length, max_room_ticker_length,
                          max_room_tickers;
import soulfind.server.messages;
import soulfind.server.user : User;
import std.algorithm : sort;
import std.array : Appender, array;
import std.datetime : Clock, SysTime;

class Room
{
    string name;

    private Sdb             db;
    private User[string]    users;


    this(string name, Sdb db)
    {
        this.name = name;
        this.db = db;
    }


    // Users

    void add_user(User user)
    {
        if (user.username in users)
            return;

        users[user.username] = user;

        scope joined_room_msg = new SUserJoinedRoom(
            name, user.username, user.status, user.upload_speed,
            user.shared_files, user.shared_folders
        );
        scope join_room_msg = new SJoinRoom(name, users);
        scope tickers_msg = new SRoomTicker(name, tickers);

        send_to_all(joined_room_msg);
        user.send_message(join_room_msg);
        user.send_message(tickers_msg);
    }

    void remove_user(string username)
    {
        if (username !in users)
            return;

        users.remove(username);

        scope msg = new SUserLeftRoom(username, name);
        send_to_all(msg);
    }

    bool is_joined(string username)
    {
        return (username in users) ? true : false;
    }

    string[] usernames()
    {
        Appender!(string[]) usernames;
        foreach (user ; users) usernames ~= user.username;
        return usernames[];
    }

    ulong num_users()
    {
        return users.length;
    }

    void send_to_all(scope SMessage msg)
    {
        foreach (user ; users) user.send_message(msg);
    }


    // Chat

    void say(string username, string message)
    {
        if (username !in users)
            return;

        if (message.length > max_chat_message_length)
            return;

        scope msg = new SSayChatroom(name, username, message);
        send_to_all(msg);
    }


    // Tickers

    void add_ticker(string username, string content)
    {
        if (username !in users)
            return;

        if (content.length > max_room_ticker_length)
            return;

        const old_content = get_ticker(username);
        if (old_content !is null) {
            del_ticker(username);
            if (content == old_content)
                return;
        }

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

    private ulong num_tickers()
    {
        return db.num_room_tickers(name);
    }
}

class GlobalRoom
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
        foreach (user ; users) user.send_message(msg);
    }
}
