// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server.server;
@safe:

import soulfind.db : Sdb;
import soulfind.defines : blue, kick_duration, log_msg, log_user,
                          max_chat_message_length, max_global_recommendations,
                          max_search_query_length, max_user_recommendations,
                          norm, red, RoomMemberType, RoomType,
                          search_dist_interval, SearchFilterType,
                          server_username;
import soulfind.server.cmdhandler : CommandHandler;
import soulfind.server.conns : Logging, UserConnection, UserConnections;
import soulfind.server.messages;
import soulfind.server.pm : PM;
import soulfind.server.room : GlobalRoom, Room;
import soulfind.server.user : User;
import std.algorithm : sort;
import std.array : Appender;
import std.conv : text;
import std.datetime : Clock, ClockType, MonoTime, msecs, SysTime, UTC;
import std.random : unpredictableSeed;
import std.stdio : writeln;

final class Server
{
    const SysTime                      started_at;
    const MonoTime                     started_monotime;
    Sdb                                db;

    private UserConnections            conns;
    private CommandHandler             cmd_handler;
    private GlobalRoom                 global_room;
    private MonoTime                   last_search_dist;

    private User[string]               users;
    private PM[uint]                   pms;
    private Room[string]               rooms;
    private Appender!(SFileSearch[])   queued_searches;
    private string[]                   search_filters;
    private bool[string]               unsearchable_users;


    this(string db_filename)
    {
        this.started_at        = Clock.currTime!(ClockType.second)(UTC());
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

        // Batch outgoing messages to reduce bandwidth overhead of TCP packets
        queued_searches ~= new SFileSearch(username, token, query);
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

    void send_queued_searches(MonoTime current_time)
    {
        if ((current_time - last_search_dist) < search_dist_interval)
            return;

        foreach (ref msg ; queued_searches)
            send_to_all(msg, unsearchable_users);

        queued_searches.clear();
        last_search_dist = current_time;
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
            unsearchable_users[username] = true;
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

        uint id;
        while (id == 0 || id in pms) id = unpredictableSeed;

        pms[id] = PM(
            id,
            Clock.currTime!(ClockType.second)(UTC()),
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
        Appender!(PM[]) user_pms;
        foreach (ref pm ; pms)
            if (pm.to_username == to_username) user_pms ~= pm;
        foreach (ref pm ; user_pms[].sort()) deliver_pm(pm.id);
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

    Recommendation[] item_recommendations(string item)
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

    SimilarUser[] user_similar_users(string username)
    {
        Appender!(SimilarUser[]) usernames;
        const user = get_user(username);
        if (user is null)
            return usernames[];

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
            if (weight > 0)
                usernames ~= SimilarUser(
                    other_user.username, cast(uint) weight
                );
        }
        return usernames[];
    }

    string[] item_similar_users(string item)
    {
        Appender!(string[]) usernames;
        foreach (ref user ; users) {
            if (user.likes(item)) usernames ~= user.username;
        }
        return usernames[];
    }

    private Recommendation[] filter_recommendations(
        int[string] recommendations, size_t max_length, bool ascending = false)
    {
        Recommendation[] filtered_recommendations;
        foreach (ref item, ref rating ; recommendations)
            if (rating != 0)
                filtered_recommendations ~= Recommendation(item, rating);

        filtered_recommendations.sort!(
            (ref a, ref b)
            => ascending ? a.rating < b.rating : a.rating > b.rating
        );

        if (filtered_recommendations.length > max_length)
            filtered_recommendations.length = max_length;

        return filtered_recommendations;
    }


    // Rooms

    Room add_room(string room_name, string owner = null)
    {
        auto room = get_room(room_name);
        if (room !is null)
            return room;

        const type = (owner !is null) ? RoomType._private : RoomType._public;
        const stored_type = db.get_room_type(room_name);
        const room_exists = stored_type != RoomType.non_existent;

        if (!room_exists) {
            db.add_room(room_name, owner);

            if (owner !is null)
                send_room_list(owner);
        }

        room = new Room(
            room_name, room_exists ? stored_type : type, db, global_room
        );
        rooms[room_name] = room;
        return room;
    }

    void del_room(string room_name, bool permanent = false)
    {
        Room room;  // Satisfy linter
        room = get_room(room_name);
        if (room is null)
            return;

        room.disband();
        if (permanent) db.del_room(room_name);
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

   void grant_room_membership(string room_name, string actor, string target)
    {
        if (actor == target)
            return;

        const owner = db.get_room_owner(room_name);
        const room_member_type = db.get_room_member_type(room_name, actor);

        if (actor != owner && room_member_type != RoomMemberType.operator)
            return;

        auto target_user = get_user(target);
        if (target_user is null) {
            send_pm(
                server_username, actor,
                text("user ", target, " is not logged in.")
            );
            return;
        }

        if (!target_user.accept_room_invitations) {
            send_pm(
                server_username, actor,
                text(
                    "user ", target, " hasn’t enabled private ",
                    "room add. please message them and ask them to ",
                    "do so before trying to add them again."
                )
            );
            return;
        }

        if (owner == target) {
            send_pm(
                server_username, actor,
                text(
                    "user ", target, " is the owner of room ",
                    room_name
                )
            );
            return;
        }

        if (db.get_room_member_type(
                room_name, target) != RoomMemberType.non_existent) {
            send_pm(
                server_username, actor,
                text(
                    "user ", target,
                    " is already a member of room ", room_name
                )
            );
            return;
        }

        db.add_room_member!(RoomMemberType.normal)(room_name, target);

        void send_user_msg(string room_username) {
            auto room_user = get_user(room_username);
            if (room_user is null)
                return;

            scope msg = new SPrivateRoomAddUser(room_name, target);
            room_user.send_message(msg);
        }
        const members = db.room_members!(RoomMemberType.any)(room_name);
        foreach (ref room_username ; members) send_user_msg(room_username);
        send_user_msg(owner);

        scope msg = new SPrivateRoomAdded(room_name);
        target_user.send_message(msg);
        send_room_list(target);

        send_pm(
            server_username, actor,
            text(
                "User ", target, " is now a member of room ", room_name
            )
        );

        if (room_member_type == RoomMemberType.operator)
            send_pm(
                server_username, owner,
                text(
                    "User [", target,
                    "] was added as a member of room [", room_name,
                    "] by operator [", actor, "]"
                )
            );
    }

    void cancel_room_membership(string room_name, string actor, string target)
    {
        const target_type = db.get_room_member_type(room_name, target);
        if (target_type == RoomMemberType.non_existent)
            return;

        const owner = db.get_room_owner(room_name);
        if (actor != target) {
            if (target == owner)
                return;

            if (actor != owner) {
                if (target_type == RoomMemberType.operator)
                    return;

                const actor_type = db.get_room_member_type(room_name, actor);
                if (actor_type != RoomMemberType.operator)
                    return;
            }
        }

        if (target_type == RoomMemberType.operator)
            remove_room_operator(room_name, actor, target);

        db.del_room_member(room_name, target);

        void send_user_msg(string room_username) {
            auto room_user = get_user(room_username);
            if (room_user is null)
                return;

            scope msg = new SPrivateRoomRemoveUser(room_name, target);
            room_user.send_message(msg);
        }
        const members = db.room_members!(RoomMemberType.any)(room_name);
        foreach (ref room_username ; members) send_user_msg(room_username);
        send_user_msg(owner);

        send_pm(
            server_username, owner,
            text(
                "User ", target,
                " is no longer a member of room ", room_name
            )
        );

        auto target_user = get_user(target);
        if (target_user !is null) {
            enum permanent = true;
            target_user.leave_room(room_name, permanent);
        }
    }

   void add_room_operator(string room_name, string actor, string target)
    {
        if (actor == target)
            return;

        const owner = db.get_room_owner(room_name);
        if (actor != owner)
            return;

        auto target_user = get_user(target);
        if (target_user is null) {
            send_pm(
                server_username, actor,
                text("user ", target, " is not logged in.")
            );
            return;
        }

        const target_type = db.get_room_member_type(room_name, target);
        if (target_type == RoomMemberType.non_existent) {
            send_pm(
                server_username, actor,
                text(
                    "user ", target, " must first be a member of room ",
                    room_name
                )
            );
            return;
        }

        if (target_type == RoomMemberType.operator) {
            send_pm(
                server_username, actor,
                text(
                    "user ", target, " is already an operator of room ",
                    room_name
                )
            );
            return;
        }

        db.add_room_member!(RoomMemberType.operator)(room_name, target);

        void send_user_msg(string room_username) {
            auto room_user = get_user(room_username);
            if (room_user is null)
                return;

            scope msg = new SPrivateRoomAddOperator(room_name, target);
            room_user.send_message(msg);
        }
        const members = db.room_members!(RoomMemberType.any)(room_name);
        foreach (ref room_username ; members) send_user_msg(room_username);
        send_user_msg(owner);

        scope msg = new SPrivateRoomOperatorAdded(room_name);
        target_user.send_message(msg);
        send_room_list(target);

        send_pm(
            server_username, owner,
            text("User ", target, " is now an operator of room ", room_name)
        );
    }

    void remove_room_operator(string room_name, string actor, string target)
    {
        const target_type = db.get_room_member_type(room_name, target);
        if (target_type != RoomMemberType.operator)
            return;

        const owner = db.get_room_owner(room_name);
        if (actor != owner && actor != target)
            return;

        db.add_room_member!(RoomMemberType.normal)(room_name, target);

        void send_user_msg(string room_username) {
            auto room_user = get_user(room_username);
            if (room_user is null)
                return;

            scope msg = new SPrivateRoomRemoveOperator(room_name, target);
            room_user.send_message(msg);
        }
        const members = db.room_members!(RoomMemberType.any)(room_name);
        foreach (ref room_username ; members) send_user_msg(room_username);
        send_user_msg(owner);

        send_pm(
            server_username, owner,
            text(
                "User ", target, " is no longer an operator of room ",
                room_name
            )
        );

        auto target_user = get_user(target);
        if (target_user !is null) {
            scope msg = new SPrivateRoomOperatorRemoved(room_name);
            target_user.send_message(msg);

            send_room_list(target);
        }
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

        auto public_rooms = room_stats;
        auto owned_rooms = room_stats(username);
        auto member_rooms = room_stats(null, username);
        auto operated_rooms = db.rooms(
            null, username, RoomMemberType.operator
        );
        scope list_response_msg = new SRoomList(
            public_rooms,
            owned_rooms,
            member_rooms,
            operated_rooms
        );
        user.send_message(list_response_msg);

        void send_users_msg(string room_name) {
            scope users_msg = new SPrivateRoomUsers(
                room_name,
                db.room_members!(RoomMemberType.any)(room_name)
            );
            user.send_message(users_msg);
        }
        foreach (ref room ; owned_rooms)  send_users_msg(room.room_name);
        foreach (ref room ; member_rooms) send_users_msg(room.room_name);

        void send_operators_msg(string room_name) {
            scope operators_msg = new SPrivateRoomOperators(
                room_name,
                db.room_members!(RoomMemberType.operator)(room_name)
            );
            user.send_message(operators_msg);
        }
        foreach (ref room ; owned_rooms)  send_operators_msg(room.room_name);
        foreach (ref room ; member_rooms) send_operators_msg(room.room_name);
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

    private RoomInfo[] room_stats(string owner = null, string member = null)
    {
        Room room;
        Appender!(RoomInfo[]) stats;

        foreach (ref room_name ; db.rooms(owner, member)) {
            uint num_users;
            room = get_room(room_name);

            if (room !is null)
                num_users = cast(uint) room.num_users;
            else if (owner is null && member is null)
                continue;

            stats ~= RoomInfo(room_name, num_users);
        }
        return stats[];
    }


    // Users

    void add_user(User user)
    {
        if (user.username !in users) users[user.username] = user;
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

    void send_to_all(scope SMessage msg, bool[string] excluded_users = null)
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
