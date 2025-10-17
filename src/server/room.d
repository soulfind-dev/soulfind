// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server.room;
@safe:

import soulfind.defines : blue, log_msg, max_chat_message_length,
                          max_room_ticker_length, max_room_tickers, norm;
import soulfind.server.conns : Logging;
import soulfind.server.messages;
import soulfind.server.user : User;
import std.algorithm.sorting : sort;
import std.array : Appender;
import std.datetime.systime : Clock, SysTime;
import std.stdio : writeln;

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

final class Room
{
    const string name;

    private GlobalRoom      global_room;
    private User[string]    users;
    private Ticker[string]  tickers;


    this(string name, GlobalRoom global_room)
    {
        this.name = name;
        this.global_room = global_room;
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
        scope tickers_msg = new SRoomTicker(name, tickers_by_order);

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
        foreach (ref user ; users) usernames ~= user.username;
        return usernames[];
    }

    size_t num_users()
    {
        return users.length;
    }

    void send_to_all(scope SMessage msg)
    {
        if (log_msg) writeln(
            "Transmit=> ", blue, msg.name, norm, " (code ", msg.code,
            ") to joined room members..."
        );
        foreach (ref user ; users) user.send_message!(Logging.disabled)(msg);
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

        if (username in tickers && tickers[username].content == content)
            return;

        del_ticker(username);

        if (content.length == 0)
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

    void del_ticker(string username)
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
        foreach (ref ticker ; tickers) {
            if (ticker.time < found_ticker.time) found_ticker = ticker;
        }
        del_ticker(found_ticker.username);
    }

    Ticker[] tickers_by_order()
    {
        Ticker[] sorted_tickers;
        foreach (ref ticker ; tickers.byValue) sorted_tickers ~= ticker;
        sorted_tickers.sort();

        return sorted_tickers;
    }

    size_t num_tickers()
    {
        return tickers.length;
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
