// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server.msghandler;
@safe:

import soulfind.defines : blue, bold, log_msg, norm, pbkdf2_iterations, red,
                          RoomMemberType, RoomType, server_username;
import soulfind.pwhash : create_salt, hash_password_async;
import soulfind.server.conns : Logging;
import soulfind.server.messages;
import soulfind.server.server : Server;
import soulfind.server.user : User;
import std.array : array;
import std.conv : text;
import std.datetime : Clock, seconds, SysTime;
import std.socket : InternetAddress;
import std.stdio : writeln;

final class MessageHandler
{
    private Server server;


    this(Server server)
    {
        this.server = server;
    }

    bool handle_message(User user, uint code, const(ubyte)[] msg_buf)
    {
        if (!user.authenticated && code != Login)
            return false;

        switch (code) {
        case Login:
            scope msg = new ULogin(msg_buf);
            if (!msg.is_valid)
                break;

            if (user.authenticated || user.hashing_password)
                break;

            user.username = msg.username;
            const banned_until = server.db.user_banned_until(msg.username);

            if (banned_until > Clock.currTime)
                // The official server doesn't send a response when a user
                // is banned. We also ban users temporarily when kicking
                // them, and simply closing the connection after some time
                // allows the client to automatically reconnect to the
                // server.
                break;

            if (banned_until > SysTime()) server.db.unban_user(msg.username);
            user.client_version = text(
                msg.major_version, ".", msg.minor_version
            );
            user.authenticate(msg.username, msg.password);
            break;

        case SetWaitPort:
            scope msg = new USetWaitPort(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            user.address = new InternetAddress(
                user.address.addr, cast(ushort) msg.port
            );
            user.obfuscation_type = (
                cast(ObfuscationType) msg.obfuscation_type
            );
            user.obfuscated_port = cast(ushort) msg.obfuscated_port;
            break;

        case GetPeerAddress:
            scope msg = new UGetPeerAddress(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            auto target_user = server.get_user(msg.username);
            uint user_address;
            uint user_obfuscation_type;
            ushort user_port, user_obfuscated_port;

            if (target_user !is null) {
                user_address = target_user.address.addr;
                user_port = target_user.address.port;
                user_obfuscation_type = target_user.obfuscation_type;
                user_obfuscated_port = target_user.obfuscated_port;
            }

            scope response_msg = new SGetPeerAddress(
                msg.username, user_address, user_port,
                user_obfuscation_type, user_obfuscated_port
            );
            user.send_message(response_msg);
            break;

        case WatchUser:
            scope msg = new UWatchUser(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            auto target_user = server.get_user(msg.username);

            bool user_exists;
            uint user_status = UserStatus.offline;
            uint user_upload_speed;
            uint user_shared_files, user_shared_folders;

            if (target_user !is null)
            {
                user_exists = true;
                user_status = target_user.status;
                user_upload_speed = target_user.upload_speed;
                user_shared_files = target_user.shared_files;
                user_shared_folders = target_user.shared_folders;
            }
            else if (msg.username == server_username) {
                // Allow clients that check user existence to add the
                // 'server' user to the user list, otherwise some of them
                // have no way of opening a private chat tab.
                user_exists = true;
            }
            else {
                const user_stats = server.db.user_stats(msg.username);
                user_exists = user_stats.exists;
                user_upload_speed = user_stats.upload_speed;
                user_shared_files = user_stats.shared_files;
                user_shared_folders = user_stats.shared_folders;
            }

            if (user_exists) user.watch(msg.username);

            scope response_msg = new SWatchUser(
                msg.username, user_exists, user_status, user_upload_speed,
                user_shared_files, user_shared_folders
            );
            user.send_message(response_msg);
            break;

        case UnwatchUser:
            scope msg = new UUnwatchUser(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            // Always watch our own username for updates
            if (msg.username != user.username)
                user.unwatch(msg.username);
            break;

        case GetUserStatus:
            scope msg = new UGetUserStatus(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            auto target_user = server.get_user(msg.username);
            uint user_status = UserStatus.offline;
            bool user_privileged;

            if (target_user !is null) {
                user_status = target_user.status;
                user_privileged = target_user.privileged;
            }
            else if (msg.username != server_username) {
                user_privileged = (
                    server.db.user_privileged_until(msg.username)
                    > Clock.currTime
                );
            }

            scope response_msg = new SGetUserStatus(
                msg.username, user_status, user_privileged
            );
            user.send_message(response_msg);
            break;

        case SayChatroom:
            scope msg = new USayChatroom(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            auto room = server.get_room(msg.room_name);
            if (room !is null) room.say(user.username, msg.message);
            break;

        case JoinRoom:
            scope msg = new UJoinRoom(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            if (msg.room_type == RoomType._private)
                user.join_room!(RoomType._private)(msg.room_name);
            else
                user.join_room!(RoomType._public)(msg.room_name);
            break;

        case LeaveRoom:
            scope msg = new ULeaveRoom(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            user.leave_room(msg.room_name);
            break;

        case ConnectToPeer:
            scope msg = new UConnectToPeer(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            auto target_user = server.get_user(msg.username);
            if (target_user is null) {
                scope response_msg = new SCantConnectToPeer(msg.token);
                user.send_message(response_msg);
                break;
            }

            scope response_msg = new SConnectToPeer(
                user.username, msg.type, user.address.addr,
                user.address.port, msg.token, user.privileged,
                user.obfuscation_type, user.obfuscated_port
            );
            target_user.send_message!(Logging.redacted)(response_msg);
            break;

        case MessageUser:
            scope msg = new UMessageUser(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            if (msg.username == server_username) {
                server.handle_command(user.username, msg.message);
                break;
            }
            server.send_pm(user.username, msg.username, msg.message);
            break;

        case MessageAcked:
            enum in_username = "[ redacted ]";
            scope msg = new UMessageAcked(msg_buf, in_username);
            if (!msg.is_valid)
                break;

            server.del_pm(msg.id, user.username);
            break;

        case FileSearch:
            scope msg = new UFileSearch(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            server.search_files(msg.token, msg.query, user.username);
            break;

        case SetStatus:
            scope msg = new USetStatus(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            if (msg.status != UserStatus.offline)
                user.update_status(msg.status);
            break;

        case ServerPing:
            scope msg = new UServerPing(msg_buf, user.username);
            break;

        case SendConnectToken:
            scope msg = new USendConnectToken(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            auto target_user = server.get_user(msg.username);
            if (target_user is null)
                break;

            scope response_msg = new SSendConnectToken(
                user.username, msg.token
            );
            target_user.send_message!(Logging.redacted)(response_msg);
            break;

        case SharedFoldersFiles:
            scope msg = new USharedFoldersFiles(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            user.update_shared_stats(msg.shared_files, msg.shared_folders);

            scope response_msg = new SGetUserStats(
                user.username, user.upload_speed, user.shared_files,
                user.shared_folders
            );
            server.send_to_watching(user.username, response_msg);
            break;

        case GetUserStats:
            scope msg = new UGetUserStats(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            auto target_user = server.get_user(msg.username);

            uint user_upload_speed;
            uint user_shared_files, user_shared_folders;

            if (target_user !is null) {
                user_upload_speed = target_user.upload_speed;
                user_shared_files = target_user.shared_files;
                user_shared_folders = target_user.shared_folders;
            }
            else if (msg.username != server_username) {
                const user_stats = server.db.user_stats(msg.username);
                user_upload_speed = user_stats.upload_speed;
                user_shared_files = user_stats.shared_files;
                user_shared_folders = user_stats.shared_folders;
            }

            scope response_msg = new SGetUserStats(
                msg.username, user_upload_speed, user_shared_files,
                user_shared_folders
            );
            user.send_message(response_msg);
            break;

        case UploadSlotsFull:
            scope msg = new UUploadSlotsFull(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            user.upload_slots_full = msg.slots_full;

            scope response_msg = new SUploadSlotsFull(
                user.username, msg.slots_full
            );
            server.send_to_joined_rooms(user.username, response_msg);
            break;

        case UserSearch:
            scope msg = new UUserSearch(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            server.search_user_files(
                msg.token, msg.query, user.username, msg.username
            );
            break;

        case SimilarRecommendations:
            // No longer used, send empty response
            scope msg = new USimilarRecommendations(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            string[] recommendations;
            scope response_msg = new SSimilarRecommendations(
                msg.recommendation, recommendations
            );
            user.send_message(response_msg);
            break;

        case AddThingILike:
            scope msg = new UAddThingILike(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            user.add_liked_item(msg.item);
            break;

        case RemoveThingILike:
            scope msg = new URemoveThingILike(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            user.del_liked_item(msg.item);
            break;

        case AddThingIHate:
            scope msg = new UAddThingIHate(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            user.add_hated_item(msg.item);
            break;

        case RemoveThingIHate:
            scope msg = new URemoveThingIHate(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            user.del_hated_item(msg.item);
            break;

        case GetRecommendations:
            scope msg = new UGetRecommendations(msg_buf, user.username);
            scope response_msg = new SGetRecommendations(
                server.user_recommendations(user.username)
            );
            user.send_message(response_msg);
            break;

        case MyRecommendations:
            // No longer used, send empty response
            scope msg = new UMyRecommendations(msg_buf, user.username);
            string[] recommendations;

            scope response_msg = new SMyRecommendations(recommendations);
            user.send_message(response_msg);
            break;

        case GlobalRecommendations:
            scope msg = new UGlobalRecommendations(msg_buf, user.username);
            scope response_msg = new SGetGlobalRecommendations(
                server.global_recommendations
            );
            user.send_message(response_msg);
            break;

        case SimilarUsers:
            scope msg = new USimilarUsers(msg_buf, user.username);
            scope response_msg = new SSimilarUsers(
                server.user_similar_users(user.username)
            );
            user.send_message(response_msg);
            break;

        case UserInterests:
            scope msg = new UUserInterests(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            auto target_user = server.get_user(msg.username);
            string[] user_liked_items;
            string[] user_hated_items;

            if (target_user !is null) {
                user_liked_items = target_user.liked_item_names.array;
                user_hated_items = target_user.hated_item_names.array;
            }

            scope response_msg = new SUserInterests(
                msg.username, user_liked_items, user_hated_items
            );
            user.send_message(response_msg);
            break;

        case PlaceInLineRequest:
            scope msg = new UPlaceInLineRequest(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            auto target_user = server.get_user(msg.username);
            if (target_user is null)
                break;

            scope response_msg = new SPlaceInLineRequest(
                user.username, msg.token
            );
            target_user.send_message!(Logging.redacted)(response_msg);
            break;

        case RoomList:
            scope msg = new URoomList(msg_buf, user.username);
            server.send_room_list(user.username);
            break;

        case GlobalUserList:
            // The official server disconnects the user
            scope msg = new UGlobalUserList(msg_buf, user.username);
            user.disconnect();
            break;

        case CheckPrivileges:
            scope msg = new UCheckPrivileges(msg_buf, user.username);
            scope response_msg = new SCheckPrivileges(user.privileges);
            user.send_message(response_msg);
            break;

        case WishlistSearch:
            scope msg = new UWishlistSearch(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            server.search_files(msg.token, msg.query, user.username);
            break;

        case ItemRecommendations:
            scope msg = new UItemRecommendations(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            scope response_msg = new SItemRecommendations(
                msg.item, server.item_recommendations(msg.item)
            );
            user.send_message(response_msg);
            break;

        case ItemSimilarUsers:
            scope msg = new UItemSimilarUsers(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            scope response_msg = new SItemSimilarUsers(
                msg.item, server.item_similar_users(msg.item)
            );
            user.send_message(response_msg);
            break;

        case SetRoomTicker:
            scope msg = new USetRoomTicker(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            auto room = server.get_room(msg.room_name);
            if (room !is null) room.add_ticker(user.username, msg.ticker);
            break;

        case RoomSearch:
            scope msg = new URoomSearch(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            server.search_room_files(
                msg.token, msg.query, user.username, msg.room_name
            );
            break;

        case SendUploadSpeed:
            scope msg = new USendUploadSpeed(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            user.update_upload_speed(msg.speed);
            break;

        case UserPrivileged:
            scope msg = new UUserPrivileged(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            bool privileged;
            auto target_user = server.get_user(msg.username);
            if (target_user !is null)
                privileged = target_user.privileged;
            else if (msg.username != server_username)
                privileged = (
                    server.db.user_privileged_until(msg.username)
                    > Clock.currTime
                );

            scope response_msg = new SUserPrivileged(
                msg.username, privileged
            );
            user.send_message(response_msg);
            break;

        case GivePrivileges:
            scope msg = new UGivePrivileges(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            const duration = (
                msg.duration < user.privileges
                ? msg.duration : user.privileges
            );
            if (duration == 0.seconds)
                break;

            if (msg.username == server_username)
                break;

            if (!server.db.add_user_privileges(msg.username, duration))
                break;

            server.db.remove_user_privileges(user.username, duration);

            auto target_user = server.get_user(msg.username);
            if (target_user !is null)
                target_user.refresh_privileges();

            user.refresh_privileges();
            break;

        case NotifyPrivileges:
            // No longer used, but official server still responds
            scope msg = new UNotifyPrivileges(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            scope response_msg = new SAckNotifyPrivileges(msg.token);
            user.send_message(response_msg);
            break;

        case PrivateRoomAddUser:
            scope msg = new UPrivateRoomAddUser(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            server.grant_room_membership(
                msg.room_name, user.username, msg.username
            );
            break;

        case PrivateRoomRemoveUser:
            scope msg = new UPrivateRoomRemoveUser(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            if (msg.username != user.username)
                server.cancel_room_membership(
                    msg.room_name, user.username, msg.username
                );
            break;

        case PrivateRoomCancelMembership:
            scope msg = new UPrivateRoomCancelMembership(
                msg_buf, user.username
            );
            if (!msg.is_valid)
                break;

            server.cancel_room_membership(
                msg.room_name, user.username, user.username
            );
            break;

        case PrivateRoomDisown:
            scope msg = new UPrivateRoomDisown(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            const room_name = msg.room_name;
            if (server.db.get_room_owner(room_name) != user.username)
                break;

            server.del_room(room_name);
            server.send_room_list(user.username);
            break;

        case PrivateRoomToggle:
            scope msg = new UPrivateRoomToggle(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            user.accept_room_invitations = msg.enabled;

            scope response_msg = new SPrivateRoomToggle(msg.enabled);
            user.send_message(response_msg);
            break;

        case ChangePassword:
            scope msg = new UChangePassword(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            if (msg.password.length == 0 || user.hashing_password)
                break;

            user.hashing_password = true;
            const salt = create_salt();
            hash_password_async(
                msg.password, salt, pbkdf2_iterations, &user.password_hashed
            );
            break;

        case PrivateRoomAddOperator:
            scope msg = new UPrivateRoomAddOperator(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            server.add_room_operator(
                msg.room_name, user.username, msg.username
            );
            break;

        case PrivateRoomRemoveOperator:
            scope msg = new UPrivateRoomRemoveOperator(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            server.remove_room_operator(
                msg.room_name, user.username, msg.username
            );
            break;

        case MessageUsers:
            scope msg = new UMessageUsers(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            enum connected_only = true;
            foreach (ref to_username ; msg.usernames)
                server.send_pm(
                    user.username, to_username, msg.message, connected_only
                );
            break;

        case JoinGlobalRoom:
            scope msg = new UJoinGlobalRoom(msg_buf, user.username);
            server.add_global_room_user(user);
            break;

        case LeaveGlobalRoom:
            scope msg = new ULeaveGlobalRoom(msg_buf, user.username);
            server.remove_global_room_user(user.username);
            break;

        case RelatedSearch:
            // No longer used, send empty response
            scope msg = new URelatedSearch(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            RelatedSearchTerm[] terms;
            scope response_msg = new SRelatedSearch(
                msg.query, terms
            );
            user.send_message(response_msg);
            break;

        case CantConnectToPeer:
            scope msg = new UCantConnectToPeer(msg_buf, user.username);
            if (!msg.is_valid)
                break;

            auto target_user = server.get_user(msg.username);
            if (target_user is null)
                break;

            scope response_msg = new SCantConnectToPeer(msg.token);
            target_user.send_message!(Logging.redacted)(response_msg);
            break;

        default:
            if (log_msg) writeln(
                "[Msg] Unimplemented message code ", red, code, norm,
                " from user ", blue, user.username, norm, " with length ",
                msg_buf.length
            );
            break;
        }
        return true;
    }
}
