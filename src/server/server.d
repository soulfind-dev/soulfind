// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server.server;
@safe:

import soulfind.db : Sdb;
import soulfind.defines : blue, kick_duration, log_msg, log_user,
                          max_chat_message_length, max_global_recommendations,
                          max_search_query_length, max_user_recommendations,
                          norm, red, RoomType, SearchFilterType,
                          server_username;
import soulfind.server.cmdhandler : CommandHandler;
import soulfind.server.conns : Logging, UserConnection, UserConnections;
import soulfind.server.messages;
import soulfind.server.pm : PM;
import soulfind.server.room : GlobalRoom, Room;
import soulfind.server.user : User;
import std.algorithm.sorting : sort;
import std.array : Appender, array;
import std.datetime : Clock, MonoTime, msecs, SysTime;
import std.stdio : writeln;

final class Server
{
    const SysTime           started_at;
    const MonoTime          started_monotime;
    Sdb                     db;

    private UserConnections conns;
    private CommandHandler  cmd_handler;
    private GlobalRoom      global_room;

    private User[string]    users;
    private PM[uint]        pms;
    private Room[string]    rooms;
    private string[]        search_filters;
    private string[string]  unsearchable_users;


    this(string db_filename)
    {
        this.started_at        = Clock.currTime;
        this.started_monotime  = MonoTime.currTime;
        this.db                = new Sdb(db_filename);
        this.conns             = new UserConnections(this);
        this.cmd_handler       = new CommandHandler(this);
        this.global_room       = new GlobalRoom();
    }


    // Connections

    bool listen(ushort port)
    {
        if (port == 0) port = db.server_port;
        return conns.listen(port);
    }

    void close_connection(UserConnection conn)
    {
        conns.close_connection(conn);
    }


    // File Searches

    void search_files(uint token, string query, string username)
    {
        if (query.length > max_search_query_length)
            return;

        if (db.is_search_query_filtered(query))
            return;

        scope msg = new SFileSearch(username, token, query);
        send_to_all(msg, unsearchable_users);
    }

    void search_user_files(uint token, string query, string from_username,
                           string to_username)
    {
        if (query.length > max_search_query_length)
            return;

        if (to_username in unsearchable_users)
            return;

        auto user = get_user(to_username);
        if (user is null)
            return;

        if (db.is_search_query_filtered(query))
            return;

        scope msg = new SFileSearch(from_username, token, query);
        user.send_message(msg);
    }

    void search_room_files(uint token, string query, string username,
                           string room_name)
    {
        if (query.length > max_search_query_length)
            return;

        auto room = get_room(room_name);
        if (room is null)
            return;

        if (room.type == RoomType._private && !room.is_member(username))
            return;

        if (db.is_search_query_filtered(query))
            return;

        scope msg = new SFileSearch(username, token, query);
        room.send_to_all(msg, unsearchable_users);
    }

    void send_search_filters(string username)
    {
        auto user = get_user(username);
        if (user is null)
            return;

        scope msg = new SExcludedSearchPhrases(search_filters);
        user.send_message(msg);
    }

    void refresh_search_filters()
    {
        string[] new_filters;  // Satisfy the linter
        new_filters = db.search_filters!(SearchFilterType.client);
        if (new_filters == search_filters)
            return;

        search_filters = new_filters;
        scope msg = new SExcludedSearchPhrases(search_filters);
        send_to_all(msg);
    }

    void refresh_unsearchable_users()
    {
        unsearchable_users = null;
        foreach (ref username ; db.usernames("unsearchable"))
            unsearchable_users[username] = username;
    }


    // Private Messages

    void send_pm(string from_username, string to_username, string message,
                 bool connected_only = false)
    {
        if (from_username != server_username) {
            if (message.length > max_chat_message_length)
                return;

            foreach (ref c ; message) if (c == '\n' || c == '\r')
                return;
        }

        const is_connected = get_user(to_username) !is null;
        if (!is_connected && (connected_only || !db.user_exists(to_username)))
            return;

        uint id = cast(uint) pms.length;
        while (id in pms) id++;

        pms[id] = PM(
            id,
            Clock.currTime,
            from_username,
            to_username,
            message
        );

        if (!is_connected)
            return;

        enum new_message = true;
        deliver_pm(id, new_message);
    }

    void del_pm(uint id, string to_username)
    {
        if (id in pms && pms[id].to_username == to_username)
            pms.remove(id);
    }

    void deliver_queued_pms(string to_username)
    {
        foreach (ref pm ; pms)
            if (pm.to_username == to_username) deliver_pm(pm.id);
    }

    private void deliver_pm(uint id, bool new_message = false)
    {
        if (id !in pms)
            return;

        const pm = pms[id];
        auto user = get_user(pm.to_username);

        if (user is null)
            return;

        scope msg = new SMessageUser(
            id, pm.time, pm.from_username, pm.message, new_message
        );
        user.send_message!(Logging.redacted)(msg);
    }

    void del_user_pms(string username, bool include_received = false)
    {
        PM[] pms_to_remove;
        foreach (ref pm ; pms) {
            if (pm.from_username == username
                    || (include_received && pm.to_username == username))
                pms_to_remove ~= pm;
        }
        foreach (ref pm ; pms_to_remove) pms.remove(pm.id);
    }


    // Interests

    LimitedRecommendations global_recommendations()
    {
        int[string] recommendations;
        foreach (user ; users) {
            foreach (ref item ; user.liked_item_names) recommendations[item]++;
            foreach (ref item ; user.hated_item_names) recommendations[item]--;
        }
        return LimitedRecommendations(
            filter_recommendations(
                recommendations, max_global_recommendations
            ),
            filter_recommendations(
                recommendations, max_global_recommendations, true
            )
        );
    }

    LimitedRecommendations user_recommendations(string username)
    {
        auto user = get_user(username);
        if (user is null)
            return LimitedRecommendations();

        int[string] recommendations;
        auto liked_item_names = user.liked_item_names;
        auto hated_item_names = user.hated_item_names;

        foreach (ref other_user ; users) {
            if (other_user.username == username)
                continue;

            int weight;
            foreach (ref item ; liked_item_names) {
                if (other_user.likes(item)) weight++;
                if (other_user.hates(item)) weight--;
            }
            foreach (ref item ; hated_item_names) {
                if (other_user.hates(item)) weight++;
                if (other_user.likes(item)) weight--;
            }

            if (weight == 0)
                continue;

            foreach (ref item ; other_user.liked_item_names)
                if (!user.likes(item) && !user.hates(item))
                    recommendations[item] += weight;

            foreach (ref item ; other_user.hated_item_names)
                if (!user.likes(item) && !user.hates(item))
                    recommendations[item] -= weight;
        }
        return LimitedRecommendations(
            filter_recommendations(
                recommendations, max_user_recommendations
            ),
            filter_recommendations(
                recommendations, max_user_recommendations, true
            )
        );
    }

    int[string] item_recommendations(string item)
    {
        int[string] recommendations;
        foreach (ref user ; users) {
            int weight;
            if (user.likes(item)) weight++;
            if (user.hates(item)) weight--;

            if (weight == 0)
                continue;

            foreach (ref recommendation ; user.liked_item_names)
                if (recommendation != item)
                    recommendations[recommendation] += weight;

            foreach (ref recommendation ; user.hated_item_names)
                if (recommendation != item)
                    recommendations[recommendation] -= weight;
        }
        return filter_recommendations(recommendations, size_t.max);
    }

    uint[string] user_similar_users(string username)
    {
        uint[string] usernames;
        const user = get_user(username);
        if (user is null)
            return usernames;

        auto liked_item_names = user.liked_item_names;
        auto hated_item_names = user.hated_item_names;

        foreach (ref other_user ; users) {
            if (other_user.username == username)
                continue;

            int weight;
            foreach (ref item ; liked_item_names) {
                if (other_user.likes(item)) weight++;
                if (other_user.hates(item)) weight--;
            }
            foreach (ref item ; hated_item_names) {
                if (other_user.hates(item)) weight++;
                if (other_user.likes(item)) weight--;
            }
            if (weight > 0) usernames[other_user.username] = cast(uint) weight;
        }
        return usernames;
    }

    string[] item_similar_users(string item)
    {
        Appender!(string[]) usernames;
        foreach (ref user ; users) {
            if (user.likes(item)) usernames ~= user.username;
        }
        return usernames[];
    }

    private int[string] filter_recommendations(
        int[string] recommendations, size_t max_length, bool ascending = false)
    {
        int[string] filtered_recommendations;
        auto recommendations_array = recommendations.byKeyValue.array;
        recommendations_array.sort!(
            (ref a, ref b)
            => ascending ? a.value < b.value : a.value > b.value
        );

        foreach (i, ref item; recommendations_array) {
            if (i >= max_length)
                break;
            const rating = item.value;
            if (rating != 0) filtered_recommendations[item.key] = rating;
        }
        return filtered_recommendations;
    }


    // Rooms

    Room add_room(RoomType type)(string room_name, string username = null)
    {
        auto room = get_room(room_name);
        if (room !is null)
            return room;

        const stored_type = db.get_room_type(room_name);
        const room_exists = stored_type != RoomType.non_existent;

        if (!room_exists) {
            db.add_room!type(room_name, username);

            if (type == RoomType._private)
                send_room_list(username);
        }

        room = new Room(
            room_name, room_exists ? stored_type : type, db, global_room
        );
        rooms[room_name] = room;
        return room;
    }

    void del_room(string room_name)
    {
        Room room;  // Satisfy linter
        room = get_room(room_name);
        if (room is null)
            return;

        if (room.type == RoomType._public && room.num_tickers == 0)
            db.del_room(room_name);

        rooms.remove(room_name);
    }

    void del_user_tickers(RoomType type)(string username)
    {
        // Joined rooms
        foreach (ref room ; rooms)
            if (type == RoomType.any || room.type == type)
                room.del_ticker(username);

        // Stored rooms
        foreach (ref ticker ; db.user_tickers!type(username)) {
            const room_name = ticker[0];
            db.del_ticker(room_name, username);
        }
    }

    Room get_room(string room_name)
    {
        if (room_name !in rooms)
            return null;

        return rooms[room_name];
    }

    auto joined_rooms()
    {
        return rooms.byValue;
    }

    size_t num_joined_rooms()
    {
        return rooms.length;
    }

    void add_global_room_user(User user)
    {
        global_room.add_user(user);
    }

    void remove_global_room_user(string username)
    {
        global_room.remove_user(username);
    }

    bool is_global_room_joined(string username)
    {
        return global_room.is_joined(username);
    }

    void send_room_list(string username)
    {
        auto user = get_user(username);
        if (user is null)
            return;

        auto owned_rooms = room_stats!(RoomType._private)(username);
        scope list_response_msg = new SRoomList(
            room_stats!(RoomType._public),
            owned_rooms,
            null,
            null
        );
        user.send_message(list_response_msg);

        foreach (ref room_name, _users ; owned_rooms) {
            scope users_response_msg = new SPrivateRoomUsers(room_name, null);
            user.send_message(users_response_msg);
        }

        foreach (ref room_name, _users ; owned_rooms) {
            scope operators_response_msg = new SPrivateRoomOperators(
                room_name, null
            );
            user.send_message(operators_response_msg);
        }
    }

    void send_to_joined_rooms(string sender_username, scope SMessage msg)
    {
        if (log_msg) writeln(
            "Transmit=> ", blue, msg.name, norm, " (code ", msg.code,
            ") to user ", blue, sender_username, norm, "'s joined rooms..."
        );
        foreach (ref user ; users)
            if (user.joined_same_room(sender_username))
                user.send_message!(Logging.disabled)(msg);
    }

    private uint[string] room_stats(RoomType type)(string owner = null)
    {
        Room room;
        uint[string] stats;

        foreach (ref room_name ; db.rooms!type(owner)) {
            uint num_users;
            room = get_room(room_name);

            if (room !is null)
                num_users = cast(uint) room.num_users;
            else if (type == RoomType._public)
                continue;

            stats[room_name] = num_users;
        }
        return stats;
    }


    // Users

    void add_user(User user)
    {
        if (!user.disconnecting && user.username !in users)
            users[user.username] = user;
    }

    void del_user(string username)
    {
        if (username in users) users.remove(username);
    }

    User get_user(string username)
    {
        if (username in users)
            return users[username];

        return null;
    }

    auto connected_users()
    {
        return users.byValue;
    }

    size_t num_connected_users()
    {
        return users.length;
    }

    void send_to_all(scope SMessage msg, string[string] excluded_users = null)
    {
        if (log_msg) writeln(
            "Transmit=> ", blue, msg.name, norm, " (code ", msg.code,
            ") to all users..."
        );
        foreach (ref user ; users)
            if (user.username !in excluded_users)
                user.send_message!(Logging.disabled)(msg);
    }

    void send_to_watching(string sender_username, scope SMessage msg)
    {
        if (log_msg) writeln(
            "Transmit=> ", blue, msg.name, norm, " (code ", msg.code,
            ") to users watching user ", blue, sender_username, norm, "..."
        );
        foreach (ref user ; users)
            if (user.is_watching(sender_username)
                    || user.joined_same_room(sender_username))
                user.send_message!(Logging.disabled)(msg);
    }

    void handle_command(string sender_username, string args)
    {
        cmd_handler.handle_command(sender_username, args);
    }
}
