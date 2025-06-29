// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server.room;
@safe:

import soulfind.defines : max_chat_message_length, max_room_ticker_length,
                          max_room_tickers;
import soulfind.server.messages;
import soulfind.server.user : User;
import std.array : array;
import std.datetime : Clock, SysTime;

struct Ticker
{
    string   username;
    SysTime  time;
    string   content;

    int opCmp(ref const Ticker t) const
    {
        return (t.time > time) - (t.time < time);
    }

}

class Room
{
    string name;

    private User[string]    users;
    private Ticker[string]  tickers;


    this(string name)
    {
        this.name = name;
    }


    // Users

    void add_user(User user)
    {
        if (user.username in users)
            return;

        users[user.username] = user;

        scope joined_room_msg = new SUserJoinedRoom(
            name, user.username, user.status, user.speed, user.upload_number,
            user.shared_files, user.shared_folders, user.country_code
        );
        scope join_room_msg = new SJoinRoom(name, users);
        scope tickers_msg = new SRoomTicker(name, tickers.byValue.array);

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

        if (username in tickers && tickers[username].content == content)
            return;

        del_ticker(username);

        if (!content)
            return;

        tickers[username] = Ticker(
            username,
            Clock.currTime,
            content
        );

        if (tickers.length >= max_room_tickers)
            del_oldest_ticker ();

        scope msg = new SRoomTickerAdd(name, username, content);
        send_to_all(msg);
    }

    private void del_ticker(string username)
    {
        if (username !in tickers)
            return;

        tickers.remove(username);

        scope msg = new SRoomTickerRemove(name, username);
        send_to_all(msg);
    }

    private void del_oldest_ticker()
    {
        Ticker found_ticker;
        foreach (ticker ; tickers) {
            if (ticker.time < found_ticker.time) found_ticker = ticker;
        }
        del_ticker(found_ticker.username);
    }

    ulong num_tickers()
    {
        return tickers.length;
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

    void say(string room_name, string username, string message)
    {
        scope msg = new SGlobalRoomMessage(room_name, username, message);
        foreach (user ; users) user.send_message(msg);
    }
}
