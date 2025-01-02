// SPDX-FileCopyrightText: 2024 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server.room;
@safe:

import soulfind.server.messages;
import soulfind.server.user : User;
import std.datetime : Clock;

struct Ticker
{
    string  username;
    ulong   timestamp;
    string  content;
}

class Room
{
    string name;

    private User[string]    user_list;
    private Ticker[string]  tickers;


    this(string name)
    {
        this.name = name;
    }


    // Users

    void add_user(User user)
    {
        if (user.username in user_list)
            return;

        user_list[user.username] = user;

        scope joined_room_msg = new SUserJoinedRoom(
            name, user.username, user.status, user.speed, user.upload_number,
            user.shared_files, user.shared_folders, user.country_code
        );
        scope join_room_msg = new SJoinRoom(
            name, user_names, statuses, speeds, upload_numbers,
            shared_files, shared_folders, country_codes
        );
        scope tickers_msg = new SRoomTicker(name, tickers.values);

        send_to_all(joined_room_msg);
        user.send_message(join_room_msg);
        user.send_message(tickers_msg);
    }

    void remove_user(string username)
    {
        if (username !in user_list)
            return;

        user_list.remove(username);

        scope msg = new SUserLeftRoom(username, name);
        send_to_all(msg);
    }

    bool is_joined(string username)
    {
        return (username in user_list) ? true : false;
    }

    ulong num_users()
    {
        return user_list.length;
    }

    private string[] user_names()
    {
        return user_list.keys;
    }

    private uint[string] statuses()
    {
        uint[string] statuses;
        foreach (user ; user_list)
            statuses[user.username] = user.status;

        return statuses;
    }

    private uint[string] speeds()
    {
        uint[string] speeds;
        foreach (user ; user_list)
            speeds[user.username] = user.speed;

        return speeds;
    }

    private uint[string] upload_numbers()
    {
        uint[string] upload_numbers;
        foreach (user ; user_list)
            upload_numbers[user.username] = user.upload_number;

        return upload_numbers;
    }

    private uint[string] shared_files()
    {
        uint[string] shared_files;
        foreach (user ; user_list)
            shared_files[user.username] = user.shared_files;

        return shared_files;
    }

    private uint[string] shared_folders()
    {
        uint[string] shared_folders;
        foreach (user ; user_list)
            shared_folders[user.username] = user.shared_folders;

        return shared_folders;
    }

    private string[string] country_codes()
    {
        string[string] country_codes;
        foreach (user ; user_list)
            country_codes[user.username] = user.country_code;

        return country_codes;
    }

    void send_to_all(scope SMessage msg)
    {
        foreach (user ; user_list)
            user.send_message(msg);
    }


    // Chat

    void say(string username, string message)
    {
        if (username !in user_list)
            return;

        scope msg = new SSayChatroom(name, username, message);
        send_to_all(msg);
    }


    // Tickers

    void add_ticker(string username, string content)
    {
        if (username !in user_list)
            return;

        if (username in tickers && tickers[username].content == content)
            return;

        del_ticker(username);

        if (!content)
            return;

        tickers[username] = Ticker(
            username,
            Clock.currTime.toUnixTime,
            content
        );

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
}

class GlobalRoom
{
    private User[string] user_list;


    void add_user(User user)
    {
        if (user.username !in user_list)
            user_list[user.username] = user;
    }

    void remove_user(string username)
    {
        if (username in user_list)
             user_list.remove(username);
    }

    void say(string room_name, string username, string message)
    {
        scope msg = new SGlobalRoomMessage(room_name, username, message);
        foreach (user ; user_list)
            user.send_message(msg);
    }
}
