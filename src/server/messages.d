// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server.messages;
@safe:

import soulfind.defines : blue, log_msg, norm;
import soulfind.server.user : User;
import std.array : Appender;
import std.bitmanip : Endian, nativeToLittleEndian, peek;
import std.conv : text;
import std.datetime : days, Duration, SysTime;
import std.stdio : writeln;
import std.utf : UTFException, validate;

// Constants

enum LoginRejectionReason : string
{
    invalid_username  = "INVALIDUSERNAME",
    empty_password    = "EMPTYPASSWORD",
    invalid_password  = "INVALIDPASS",
    server_full       = "SVRFULL",
    server_private    = "SVRPRIVATE"
}

enum ObfuscationType : uint
{
    none     = 0,
    rotated  = 1
}

enum UserStatus : uint
{
    offline  = 0,
    away     = 1,
    online   = 2
}


// Structs

struct LoginRejection
{
    string  reason;
    string  detail;
}

struct RoomInfo
{
    string  room_name;
    uint    num_users;
}

struct Recommendation
{
    string  item;
    int     rating;
}

struct SimilarUser
{
    string  username;
    uint    weight;
}

struct LimitedRecommendations
{
    Recommendation[]  descending_items;
    Recommendation[]  ascending_items;
}

struct RelatedSearchTerm
{
    string  term;
    uint    score;
}


// Message Codes

enum Login                        = 1;
enum SetWaitPort                  = 2;
enum GetPeerAddress               = 3;
enum WatchUser                    = 5;
enum UnwatchUser                  = 6;
enum GetUserStatus                = 7;
enum SayChatroom                  = 13;
enum JoinRoom                     = 14;
enum LeaveRoom                    = 15;
enum UserJoinedRoom               = 16;
enum UserLeftRoom                 = 17;
enum ConnectToPeer                = 18;
enum MessageUser                  = 22;
enum MessageAcked                 = 23;
enum FileSearch                   = 26;
enum SetStatus                    = 28;
enum ServerPing                   = 32;
enum SendConnectToken             = 33;    // Obsolete
enum SharedFoldersFiles           = 35;
enum GetUserStats                 = 36;
enum QueuedDownloads              = 40;    // Obsolete
enum Relogged                     = 41;
enum UserSearch                   = 42;
enum SimilarRecommendations       = 50;    // Obsolete
enum AddThingILike                = 51;
enum RemoveThingILike             = 52;
enum GetRecommendations           = 54;
enum MyRecommendations            = 55;    // Obsolete
enum GlobalRecommendations        = 56;
enum UserInterests                = 57;
enum PlaceInLineRequest           = 59;    // Obsolete
enum RoomList                     = 64;
enum AdminMessage                 = 66;
enum GlobalUserList               = 67;    // Obsolete
enum PrivilegedUsers              = 69;
enum CheckPrivileges              = 92;
enum WishlistSearch               = 103;
enum WishlistInterval             = 104;
enum SimilarUsers                 = 110;
enum ItemRecommendations          = 111;
enum ItemSimilarUsers             = 112;
enum RoomTicker                   = 113;
enum RoomTickerAdd                = 114;
enum RoomTickerRemove             = 115;
enum SetRoomTicker                = 116;
enum AddThingIHate                = 117;
enum RemoveThingIHate             = 118;
enum RoomSearch                   = 120;
enum SendUploadSpeed              = 121;
enum UserPrivileged               = 122;   // Obsolete
enum GivePrivileges               = 123;
enum NotifyPrivileges             = 124;   // Obsolete
enum AckNotifyPrivileges          = 125;   // Obsolete
enum PrivateRoomUsers             = 133;
enum PrivateRoomAddUser           = 134;
enum PrivateRoomRemoveUser        = 135;
enum PrivateRoomCancelMembership  = 136;
enum PrivateRoomDisown            = 137;
enum PrivateRoomAdded             = 139;
enum PrivateRoomRemoved           = 140;
enum PrivateRoomToggle            = 141;
enum ChangePassword               = 142;
enum PrivateRoomAddOperator       = 143;
enum PrivateRoomRemoveOperator    = 144;
enum PrivateRoomOperatorAdded     = 145;
enum PrivateRoomOperatorRemoved   = 146;
enum PrivateRoomOperators         = 148;
enum MessageUsers                 = 149;
enum JoinGlobalRoom               = 150;
enum LeaveGlobalRoom              = 151;
enum GlobalRoomMessage            = 152;
enum RelatedSearch                = 153;   // Obsolete
enum ExcludedSearchPhrases        = 160;
enum CantConnectToPeer            = 1001;
enum CantCreateRoom               = 1003;


// Incoming Messages

class UMessage
{
    const uint              code;
    bool                    is_valid = true;
    private size_t          offset;
    private const(ubyte)[]  in_buf;

    this(const(ubyte)[] in_buf, string in_username = "[ unknown ]") scope
    {
        this.in_buf = in_buf;
        code = read!uint();

        if (log_msg) writeln(
            "Receive <- ", blue, this.name, norm, " (code ", code,
            ") <- from user ", blue, in_username, norm
        );
    }

    private string name() scope
    {
        const cls_name = typeid(this).name;
        foreach_reverse (i; 0 .. cls_name.length)
            if (cls_name[i] == '.')
                return cls_name[i + 1 .. $];
        return cls_name;
    }

    private bool has_unread_data() scope
    {
        return offset < in_buf.length;
    }

    private T read(T)() scope
        if (is(T : int) || is(T : uint) || is(T : bool) || is(T : string))
    {
        T value;
        if (!is_valid)
            return value;

        uint size;
        static if (is(T : string))
            size = read!uint();
        else
            size = T.sizeof;

        if (offset + size <= in_buf.length) {
            static if (is(T : string)) {
                if (size > 0) {
                    const(ubyte)[] bytes = in_buf[offset .. offset + size];
                    value = cast(T) bytes.idup;  // UTF-8
                    offset += size;

                    try {
                        value.validate;
                    }
                    catch (UTFException) {
                        // Latin-1 fallback
                        auto wchars = new wchar[bytes.length];
                        foreach (i, ref c; bytes) wchars[i] = cast(wchar) c;
                        value = wchars.text;
                    }
                }
            }
            else {
                value = in_buf.peek!(T, Endian.littleEndian)(&offset);
            }
        }
        else {
            if (log_msg) writeln(
                "Message code ", code, ", offset ", offset,
                ", not enough data reading ", T.stringof, " of size ", size
            );
            is_valid = false;
        }
        return value;
    }
}

final class ULogin : UMessage
{
    string  username;
    string  password;
    uint    major_version;
    string  hash;            // MD5 hash of username + password
    uint    minor_version;

    this(const(ubyte)[] in_buf) scope
    {
        super(in_buf);

        username      = read!string();
        password      = read!string();
        major_version = read!uint();

        if (!has_unread_data)
            return;

        // Older clients would not send these
        hash          = read!string();
        minor_version = read!uint();
    }
}

final class USetWaitPort : UMessage
{
    uint  port;
    uint  obfuscation_type;
    uint  obfuscated_port;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        port = read!uint();

        if (!has_unread_data)
            return;

        // Optional
        obfuscation_type = read!uint();

        if (!has_unread_data)
            return;

        // Optional
        obfuscated_port = read!uint();
    }
}

final class UGetPeerAddress : UMessage
{
    string username;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        username = read!string();
    }
}

final class UWatchUser : UMessage
{
    string username;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        username = read!string();
    }
}

final class UUnwatchUser : UMessage
{
    string username;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        username = read!string();
    }
}

final class UGetUserStatus : UMessage
{
    string username;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        username = read!string();
    }
}

final class USayChatroom : UMessage
{
    string  room_name;
    string  message;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        room_name = read!string();
        message   = read!string();
    }
}

final class UJoinRoom : UMessage
{
    string  room_name;
    uint    room_type;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        room_name = read!string();

        if (!has_unread_data)
            return;

        // Optional, assume public otherwise
        room_type = read!uint();
    }
}

final class ULeaveRoom : UMessage
{
    string room_name;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        room_name = read!string();
    }
}

final class UConnectToPeer : UMessage
{
    uint    token;
    string  username;
    string  type;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        token    = read!uint();
        username = read!string();
        type     = read!string();
    }
}

final class UMessageUser : UMessage
{
    string  username;
    string  message;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        username = read!string();
        message  = read!string();
    }
}

final class UMessageAcked : UMessage
{
    uint id;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        id = read!uint();
    }
}

final class UFileSearch : UMessage
{
    uint    token;
    string  query;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        token = read!uint();
        query = read!string();
    }
}

final class UWishlistSearch : UMessage
{
    uint    token;
    string  query;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        token = read!uint();
        query = read!string();
    }
}

final class USimilarUsers : UMessage
{
    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);
    }
}

final class USetStatus : UMessage
{
    uint status;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        status = read!uint();
    }
}

final class UServerPing : UMessage
{
    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);
    }
}

final class USendConnectToken : UMessage
{
    string  username;
    uint    token;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        username = read!string();
        token    = read!uint();
    }
}

final class USendUploadSpeed : UMessage
{
    uint speed;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        speed = read!uint();
    }
}

final class USharedFoldersFiles : UMessage
{
    uint  shared_folders;
    uint  shared_files;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        shared_folders = read!uint();
        shared_files   = read!uint();
    }
}

final class UGetUserStats : UMessage
{
    string username;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        username = read!string();
    }
}

final class UQueuedDownloads : UMessage
{
    uint slots_full;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        slots_full = read!uint();
    }
}

final class UUserSearch : UMessage
{
    string  username;
    uint    token;
    string  query;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        username = read!string();
        token    = read!uint();
        query    = read!string();
    }
}

final class USimilarRecommendations : UMessage
{
    string recommendation;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        recommendation = read!string();
    }
}

final class UAddThingILike : UMessage
{
    string item;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        item = read!string();
    }
}

final class URemoveThingILike : UMessage
{
    string item;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        item = read!string();
    }
}

final class UGetRecommendations : UMessage
{
    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);
    }
}

final class UMyRecommendations : UMessage
{
    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);
    }
}

final class UGlobalRecommendations : UMessage
{
    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);
    }
}

final class UUserInterests : UMessage
{
    string username;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        username = read!string();
    }
}

final class UPlaceInLineRequest : UMessage
{
    string  username;
    uint    token;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        username = read!string();
        token    = read!uint();
    }
}

final class URoomList : UMessage
{
    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);
    }
}

final class UGlobalUserList : UMessage
{
    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);
    }
}

final class UCheckPrivileges : UMessage
{
    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);
    }
}

final class UAddThingIHate : UMessage
{
    string item;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        item = read!string();
    }
}

final class URemoveThingIHate : UMessage
{
    string item;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        item = read!string();
    }
}

final class UItemRecommendations : UMessage
{
    string item;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        item = read!string();
    }
}

final class UItemSimilarUsers : UMessage
{
    string item;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        item = read!string();
    }
}

final class USetRoomTicker : UMessage
{
    string  room_name;
    string  ticker;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        room_name = read!string();
        ticker    = read!string();
    }
}

final class URoomSearch : UMessage
{
    string  room_name;
    uint    token;
    string  query;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        room_name = read!string();
        token     = read!uint();
        query     = read!string();
    }
}

final class UUserPrivileged : UMessage
{
    string username;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        username = read!string();
    }
}

final class UGivePrivileges : UMessage
{
    string    username;
    Duration  duration;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        username = read!string();
        duration = read!uint().days;
    }
}

final class UNotifyPrivileges : UMessage
{
    uint    token;
    string  username;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        token = read!uint();
        username = read!string();
    }
}

final class UPrivateRoomAddUser : UMessage
{
    string  room_name;
    string  username;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        room_name = read!string();
        username = read!string();
    }
}

final class UPrivateRoomRemoveUser : UMessage
{
    string  room_name;
    string  username;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        room_name = read!string();
        username = read!string();
    }
}

final class UPrivateRoomCancelMembership : UMessage
{
    string room_name;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        room_name = read!string();
    }
}

final class UPrivateRoomDisown : UMessage
{
    string room_name;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        room_name = read!string();
    }
}

final class UPrivateRoomToggle : UMessage
{
    bool enabled;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        enabled = read!bool();
    }
}

final class UChangePassword : UMessage
{
    string password;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        password = read!string();
    }
}

final class UPrivateRoomAddOperator : UMessage
{
    string  room_name;
    string  username;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        room_name = read!string();
        username = read!string();
    }
}

final class UPrivateRoomRemoveOperator : UMessage
{
    string  room_name;
    string  username;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        room_name = read!string();
        username = read!string();
    }
}

final class UMessageUsers : UMessage
{
    string[]  usernames;
    string    message;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        foreach (i ; 0 .. read!uint()) usernames ~= read!string();
        message = read!string();
    }
}

final class UJoinGlobalRoom : UMessage
{
    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);
    }
}

final class ULeaveGlobalRoom : UMessage
{
    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);
    }
}

final class URelatedSearch : UMessage
{
    string query;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        query = read!string();
    }
}

final class UCantConnectToPeer : UMessage
{
    uint token;
    string username;

    this(const(ubyte)[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        token    = read!uint();
        username = read!string();
    }
}


// Outgoing Messages

class SMessage
{
    const uint                  code;
    private Appender!(ubyte[])  out_buf;

    this(uint code) scope
    {
        this.code = code;
        write!uint(code);
    }

    string name() scope
    {
        const cls_name = typeid(this).name;
        foreach_reverse (i; 0 .. cls_name.length)
            if (cls_name[i] == '.')
                return cls_name[i + 1 .. $];
        return cls_name;
    }

    ubyte[] bytes() scope
    {
        return out_buf[];
    }

    private void write(T)(T value) scope
        if (is(T : int) || is(T : uint) || is(T : bool) || is(T : string))
    {
        static if (is(T == string)) {
            write!uint(cast(uint) value.length);
            out_buf ~= cast(immutable(ubyte)[]) value;
        }
        else {
            out_buf ~= value.nativeToLittleEndian[];
        }
    }
}

final class SLogin : SMessage
{
    this(bool success, LoginRejection rejection = LoginRejection(),
         string motd = null, uint ip_address = 0, string md5_hash = null,
         bool supporter = false) scope
    {
        super(Login);

        write!bool(success);

        if (!success) {
            write!string(rejection.reason);

            if (rejection.detail)
                write!string(rejection.detail);

            return;
        }

        write!string(motd);
        write!uint(ip_address);
        write!string(md5_hash);
        write!bool(supporter);
    }
}

final class SGetPeerAddress : SMessage
{
    this(string username, uint ip_address, uint port, uint obfuscation_type,
         ushort obfuscated_port) scope
    {
        super(GetPeerAddress);

        write!string(username);
        write!uint(ip_address);
        write!uint(port);
        write!uint(obfuscation_type);
        write!ushort(obfuscated_port);
    }
}

final class SWatchUser : SMessage
{
    this(string username, bool exists, uint status, uint upload_speed,
         uint shared_files, uint shared_folders) scope
    {
        super(WatchUser);

        write!string(username);
        write!bool(exists);
        if (!exists)
            return;

        write!uint(status);
        write!uint(upload_speed);
        write!uint(0);  // upload_number, obsolete
        write!uint(0);  // unknown, obsolete
        write!uint(shared_files);
        write!uint(shared_folders);
        if (status > 0) write!string("");  // country_code, obsolete
    }
}

final class SGetUserStatus : SMessage
{
    this(string username, uint status, bool privileged) scope
    {
        super(GetUserStatus);

        write!string(username);
        write!uint(status);
        write!bool(privileged);
    }
}

final class SSayChatroom : SMessage
{
    this(string room_name, string username, string message) scope
    {
        super(SayChatroom);

        write!string(room_name);
        write!string(username);
        write!string(message);
    }
}

final class SRoomList : SMessage
{
    this(RoomInfo[] rooms,
         RoomInfo[] owned_private_rooms,
         RoomInfo[] other_private_rooms,
         string[] operated_private_rooms) scope
    {
        super(RoomList);

        write!uint(cast(uint) rooms.length);
        foreach (ref room ; rooms)
            write!string(room.room_name);

        write!uint(cast(uint) rooms.length);
        foreach (ref room ; rooms)
            write!uint(room.num_users);

        write!uint(cast(uint) owned_private_rooms.length);
        foreach (ref room ; owned_private_rooms)
            write!string(room.room_name);

        write!uint(cast(uint) owned_private_rooms.length);
        foreach (ref room ; owned_private_rooms)
            write!uint(room.num_users);

        write!uint(cast(uint) other_private_rooms.length);
        foreach (ref room ; other_private_rooms)
            write!string(room.room_name);

        write!uint(cast(uint) other_private_rooms.length);
        foreach (ref room ; other_private_rooms)
            write!uint(room.num_users);

        write!uint(cast(uint) operated_private_rooms.length);
        foreach (ref room_name ; operated_private_rooms)
            write!string(room_name);
    }
}

final class SJoinRoom : SMessage
{
    this(string room_name, User[string] users, string owner = null,
         string[] operators = null) scope
    {
        super(JoinRoom);

        write!string(room_name);
        const n = cast(uint) users.length;

        write!uint(n);
        foreach (ref username, ref _user ; users) write!string(username);

        write!uint(n);
        foreach (ref user ; users) write!uint(user.status);

        write!uint(n);
        foreach (ref user ; users)
        {
            write!uint(user.upload_speed);
            write!uint(0);  // upload_number, obsolete
            write!uint(0);  // unknown, obsolete
            write!uint(user.shared_files);
            write!uint(user.shared_folders);
        }

        write!uint(n);
        foreach (ref user ; users) write!uint(user.upload_slots_full);

        write!uint(n);
        foreach (ref user ; users) write!string("");  // country_code, obsolete

        if (owner is null)
            return;

        write!string(owner);

        write!uint(cast(uint) operators.length);
        foreach (ref username ; operators) write!string(username);
    }
}

final class SLeaveRoom : SMessage
{
    this(string room_name) scope
    {
        super(LeaveRoom);

        write!string(room_name);
    }
}

final class SUserJoinedRoom : SMessage
{
    this(string room_name, string username, uint status,
         uint upload_speed, uint upload_slots_full, uint shared_files,
         uint shared_folders) scope
    {
        super(UserJoinedRoom);

        write!string(room_name);
        write!string(username);
        write!uint(status);
        write!uint(upload_speed);
        write!uint(0);     // upload_number, obsolete
        write!uint(0);     // unknown, obsolete
        write!uint(shared_files);
        write!uint(shared_folders);
        write!uint(upload_slots_full);
        write!string("");  // country_code, obsolete
    }
}

final class SUserLeftRoom : SMessage
{
    this(string room_name, string username) scope
    {
        super(UserLeftRoom);

        write!string(room_name);
        write!string(username);
    }
}

final class SConnectToPeer : SMessage
{
    this(string username, string type, uint ip_address, uint port,
         uint token, bool privileged, uint obfuscation_type,
         uint obfuscated_port) scope
    {
        super(ConnectToPeer);

        write!string(username);
        write!string(type);
        write!uint(ip_address);
        write!uint(port);
        write!uint(token);
        write!bool(privileged);
        write!uint(obfuscation_type);
        write!uint(obfuscated_port);
    }
}

final class SMessageUser : SMessage
{
    this(uint id, SysTime timestamp, string username, string message,
         bool new_message) scope
    {
        super(MessageUser);

        const unix_timestamp = timestamp.toUnixTime;

        write!uint(id);
        write!uint(
            cast(uint) (unix_timestamp > uint.max ? uint.max : unix_timestamp)
        );
        write!string(username);
        write!string(message);
        write!bool(new_message);
    }
}

final class SFileSearch : SMessage
{
    this(string username, uint token, string query) scope
    {
        super(FileSearch);

        write!string(username);
        write!uint(token);
        write!string(query);
    }
}

final class SSendConnectToken : SMessage
{
    this(string username, uint token) scope
    {
        super(SendConnectToken);

        write!string(username);
        write!uint(token);
    }
}

final class SGetUserStats : SMessage
{
    this(string username, uint upload_speed, uint shared_files,
         uint shared_folders) scope
    {
        super(GetUserStats);

        write!string(username);
        write!uint(upload_speed);
        write!uint(0);  // upload_number, obsolete
        write!uint(0);  // unknown, obsolete
        write!uint(shared_files);
        write!uint(shared_folders);
    }
}

final class SQueuedDownloads : SMessage
{
    this(string username, uint slots_full) scope
    {
        super(QueuedDownloads);

        write!string(username);
        write!uint(slots_full);
    }
}

final class SGetRecommendations : SMessage
{
    this(LimitedRecommendations recommendations) scope
    {
        super(GetRecommendations);

        write!uint(cast(uint) recommendations.descending_items.length);
        foreach (ref recommendation ; recommendations.descending_items)
        {
            write!string(recommendation.item);
            write!int(recommendation.rating);
        }
        write!uint(cast(uint) recommendations.ascending_items.length);
        foreach (ref recommendation ; recommendations.ascending_items)
        {
            write!string(recommendation.item);
            write!int(recommendation.rating);
        }
    }
}

final class SMyRecommendations : SMessage
{
    this(string[] recommendations) scope
    {
        super(MyRecommendations);

        write!uint(cast(uint) recommendations.length);
        foreach (ref item ; recommendations)
        {
            write!string(item);
        }
    }
}

final class SGetGlobalRecommendations : SMessage
{
    this(LimitedRecommendations recommendations) scope
    {
        super(GlobalRecommendations);

        write!uint(cast(uint) recommendations.descending_items.length);
        foreach (ref recommendation ; recommendations.descending_items)
        {
            write!string(recommendation.item);
            write!int(recommendation.rating);
        }
        write!uint(cast(uint) recommendations.ascending_items.length);
        foreach (ref recommendation ; recommendations.ascending_items)
        {
            write!string(recommendation.item);
            write!int(recommendation.rating);
        }
    }
}

final class SUserInterests : SMessage
{
    this(string user, string[] likes, string[] hates) scope
    {
        super(UserInterests);

        write!string(user);

        write!uint(cast(uint) likes.length);
        foreach (ref item ; likes) write!string(item);

        write!uint(cast(uint) hates.length);
        foreach (ref item ; hates) write!string(item);
    }
}

final class SRelogged : SMessage
{
    this() scope
    {
        super(Relogged);
    }
}

final class SSimilarRecommendations : SMessage
{
    this(string recommendation, string[] recommendations) scope
    {
        super(SimilarRecommendations);

        write!string(recommendation);
        write!uint(cast(uint) recommendations.length);
        foreach (ref srecommendation ; recommendations)
            write!string(srecommendation);
    }
}

final class SAdminMessage : SMessage
{
    this(string message) scope
    {
        super(AdminMessage);

        write!string(message);
    }
}

final class SPlaceInLineRequest : SMessage
{
    this(string username, uint token) scope
    {
        super(PlaceInLineRequest);

        write!string(username);
        write!uint(token);
    }
}

final class SPrivilegedUsers : SMessage
{
    this(string[] users) scope
    {
        super(PrivilegedUsers);

        write!uint(cast(uint) users.length);
        foreach (ref username ; users)
            write!string(username);
    }
}

final class SCheckPrivileges : SMessage
{
    this(Duration duration) scope
    {
        super(CheckPrivileges);

        const duration_value = duration.total!"seconds";
        write!uint(
            cast(uint) (duration_value > uint.max ? uint.max : duration_value)
        );
    }
}

final class SWishlistInterval : SMessage
{
    this(Duration interval) scope
    {
        super(WishlistInterval);

        const interval_value = interval.total!"seconds";
        write!uint(
            cast(uint) (interval_value > uint.max ? uint.max : interval_value)
        );
    }
}

final class SSimilarUsers : SMessage
{
    this(SimilarUser[] users) scope
    {
        super(SimilarUsers);

        write!uint(cast(uint) users.length);
        foreach (ref user ; users)
        {
            write!string(user.username);
            write!uint(user.weight);
        }
    }
}

final class SItemRecommendations : SMessage
{
    this(string item, Recommendation[] recommendations) scope
    {
        super(ItemRecommendations);

        write!string(item);
        write!uint(cast(uint) recommendations.length);

        foreach (ref recommendation ; recommendations)
        {
            write!string(recommendation.item);
            write!int(recommendation.rating);
        }
    }
}

final class SItemSimilarUsers : SMessage
{
    this(string item, string[] usernames) scope
    {
        super(ItemSimilarUsers);

        write!string(item);
        write!uint(cast(uint) usernames.length);
        foreach (ref username ; usernames) write!string(username);
    }
}

final class SRoomTicker : SMessage
{
    this(string room_name, string[][] tickers) scope
    {
        super(RoomTicker);

        write!string(room_name);
        write!uint(cast(uint) tickers.length);
        foreach (ref ticker ; tickers)
        {
            const username = ticker[0], content = ticker[1];
            write!string(username);
            write!string(content);
        }
    }
}

final class SRoomTickerAdd : SMessage
{
    this(string room_name, string username, string ticker) scope
    {
        super(RoomTickerAdd);

        write!string(room_name);
        write!string(username);
        write!string(ticker);
    }
}

final class SRoomTickerRemove : SMessage
{
    this(string room_name, string username) scope
    {
        super(RoomTickerRemove);

        write!string(room_name);
        write!string(username);
    }
}

final class SUserPrivileged : SMessage
{
    this(string username, bool privileged) scope
    {
        super(UserPrivileged);

        write!string(username);
        write!bool(privileged);
    }
}

final class SAckNotifyPrivileges : SMessage
{
    this(uint token) scope
    {
        super(AckNotifyPrivileges);

        write!uint(token);
    }
}

final class SPrivateRoomUsers : SMessage
{
    this(string room_name, string[] usernames) scope
    {
        super(PrivateRoomUsers);

        write!string(room_name);
        write!uint(cast(uint) usernames.length);
        foreach (ref username ; usernames) write!string(username);
    }
}

final class SPrivateRoomAddUser : SMessage
{
    this(string room_name, string username) scope
    {
        super(PrivateRoomAddUser);

        write!string(room_name);
        write!string(username);
    }
}

final class SPrivateRoomRemoveUser : SMessage
{
    this(string room_name, string username) scope
    {
        super(PrivateRoomRemoveUser);

        write!string(room_name);
        write!string(username);
    }
}

final class SPrivateRoomAdded : SMessage
{
    this(string room_name) scope
    {
        super(PrivateRoomAdded);

        write!string(room_name);
    }
}

final class SPrivateRoomRemoved : SMessage
{
    this(string room_name) scope
    {
        super(PrivateRoomRemoved);

        write!string(room_name);
    }
}

final class SPrivateRoomToggle : SMessage
{
    this(bool enabled) scope
    {
        super(PrivateRoomToggle);

        write!bool(enabled);
    }
}

final class SChangePassword : SMessage
{
    this(string password) scope
    {
        super(ChangePassword);

        write!string(password);
    }
}

final class SPrivateRoomAddOperator : SMessage
{
    this(string room_name, string username) scope
    {
        super(PrivateRoomAddOperator);

        write!string(room_name);
        write!string(username);
    }
}

final class SPrivateRoomRemoveOperator : SMessage
{
    this(string room_name, string username) scope
    {
        super(PrivateRoomRemoveOperator);

        write!string(room_name);
        write!string(username);
    }
}

final class SPrivateRoomOperatorAdded : SMessage
{
    this(string room_name) scope
    {
        super(PrivateRoomOperatorAdded);

        write!string(room_name);
    }
}

final class SPrivateRoomOperatorRemoved : SMessage
{
    this(string room_name) scope
    {
        super(PrivateRoomOperatorRemoved);

        write!string(room_name);
    }
}

final class SPrivateRoomOperators : SMessage
{
    this(string room_name, string[] usernames) scope
    {
        super(PrivateRoomOperators);

        write!string(room_name);
        write!uint(cast(uint) usernames.length);
        foreach (ref username ; usernames) write!string(username);
    }
}

final class SGlobalRoomMessage : SMessage
{
    this(string room_name, string username, string message) scope
    {
        super(GlobalRoomMessage);

        write!string(room_name);
        write!string(username);
        write!string(message);
    }
}

final class SRelatedSearch : SMessage
{
    this(string query, RelatedSearchTerm[] terms) scope
    {
        super(RelatedSearch);

        write!string(query);
        write!uint(cast(uint) terms.length);
        foreach (ref search ; terms)
        {
            write!string(search.term);
            write!uint(search.score);
        }
    }
}

final class SExcludedSearchPhrases : SMessage
{
    this(string[] phrases) scope
    {
        super(ExcludedSearchPhrases);

        write!uint(cast(uint) phrases.length);
        foreach (ref phrase ; phrases) write!string(phrase);
    }
}

final class SCantConnectToPeer : SMessage
{
    this(uint token) scope
    {
        super(CantConnectToPeer);

        write!uint(token);
    }
}

final class SCantCreateRoom : SMessage
{
    this(string room_name) scope
    {
        super(CantCreateRoom);

        write!string(room_name);
    }
}
