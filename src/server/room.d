// SPDX-FileCopyrightText: 2024 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server.room;
@safe:

import soulfind.defines;
import soulfind.server.messages;
import soulfind.server.user;

class Room
    {
    // Static

    private static Room[string]   room_list;
    private static string[string] global_room_user_list;

    static void join_room(string roomname, User user)
    {
        auto room = get_room(roomname);
        if (!room) room = new Room(roomname);
        room.add_user(user);
    }

    static Room get_room(string roomname)
    {
        if (roomname !in room_list)
            return null;

        return room_list[roomname];
    }

    static Room[] rooms()
    {
        return room_list.values;
    }

    static ulong[string] room_stats()
    {
        ulong[string] stats;
        foreach (room ; rooms) stats[room.name] = room.nb_users;
        return stats;
    }

    static void add_global_room_user(string username)
    {
        if (username !in global_room_user_list)
            global_room_user_list[username] = username;
    }

    static void remove_global_room_user(string username)
    {
        if (username in global_room_user_list)
            global_room_user_list.remove(username);
    }

    static string[] global_room_users()
    {
        return global_room_user_list.keys;
    }

    string name;


    // Attributes

    private User[string]    user_list;
    private string[string]  tickers;


    // Constructor

    this(string name)
    {
        this.name = name;
        room_list[name] = this;
    }


    // Misc

    void send_to_all(scope SMessage msg)
    {
        foreach (user ; users) user.send_message(msg);
    }

    void say(string username, string message)
    {
        if (username !in user_list)
            return;

        scope msg = new SSayChatroom(name, username, message);
        send_to_all(msg);
    }


    // Users

    void leave(User user)
    {
        if (user.username !in user_list)
            return;

        user_list.remove(user.username);
        user.leave_room(this);

        scope msg = new SUserLeftRoom(user.username, name);
        send_to_all(msg);

        if (nb_users == 0) room_list.remove(name);
    }

    private void add_user(User user)
    {
        if (user.username in user_list)
            return;

        user_list[user.username] = user;

        scope joined_room_msg = new SUserJoinedRoom(
            name, user.username, user.status,
            user.speed, user.upload_number, user.something,
            user.shared_files, user.shared_folders,
            user.slots_full, user.country_code
        );
        scope join_room_msg = new SJoinRoom(
            name, user_names, statuses, speeds,
            upload_numbers, somethings, shared_files,
            shared_folders, slots_full, country_codes
        );
        scope tickers_msg = new SRoomTicker(name, tickers);

        send_to_all(joined_room_msg);
        user.send_message(join_room_msg);
        user.send_message(tickers_msg);

        user.join_room(this);
    }

    bool is_joined(string username)
    {
        return (username in user_list) ? true : false;
    }

    ulong nb_users()
    {
        return user_list.length;
    }

    private User[] users()
    {
        return user_list.values;
    }

    private string[] user_names()
    {
        return user_list.keys;
    }

    private uint[string] statuses()
    {
        uint[string] statuses;
        foreach (user ; users)
            statuses[user.username] = user.status;

        return statuses;
    }

    private uint[string] speeds()
    {
        uint[string] speeds;
        foreach (user ; users)
            speeds[user.username] = user.speed;

        return speeds;
    }

    private uint[string] upload_numbers()
    {
        uint[string] upload_numbers;
        foreach (user ; users)
            upload_numbers[user.username] = user.upload_number;

        return upload_numbers;
    }

    private uint[string] somethings()
    {
        uint[string] somethings;
        foreach (user ; users)
            somethings[user.username] = user.something;

        return somethings;
    }

    private uint[string] shared_files()
    {
        uint[string] shared_files;
        foreach (user ; users)
            shared_files[user.username] = user.shared_files;

        return shared_files;
    }

    private uint[string] shared_folders()
    {
        uint[string] shared_folders;
        foreach (user ; users)
            shared_folders[user.username] = user.shared_folders;

        return shared_folders;
    }

    private uint[string] slots_full()
    {
        uint[string] slots_full;
        foreach (user ; users)
            slots_full[user.username] = user.slots_full;

        return slots_full;
    }

    private string[string] country_codes()
    {
        string[string] country_codes;
        foreach (user ; users)
            country_codes[user.username] = user.country_code;

        return country_codes;
    }


    // Tickers

    void add_ticker(string username, string content)
    {
        if (!content) {
            del_ticker(username);
            return;
        }
        tickers[username] = content;

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
