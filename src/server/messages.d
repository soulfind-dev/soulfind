// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server.messages;
@safe:

import soulfind.defines : blue, log_msg, norm;
import soulfind.server.room : Ticker;
import soulfind.server.user : User;
import std.array : Appender;
import std.bitmanip : Endian, nativeToLittleEndian, peek;
import std.conv : text;
import std.datetime : days, Duration, SysTime;
import std.stdio : writeln;
import std.utf : UTFException, validate;

// Constants

const enum LoginRejectionReason : string
{
    invalid_username  = "INVALIDUSERNAME",
    empty_password    = "EMPTYPASSWORD",
    invalid_password  = "INVALIDPASS",
    server_full       = "SVRFULL",
    server_private    = "SVRPRIVATE"
}

const enum ObfuscationType : uint
{
    none     = 0,
    rotated  = 1
}

const enum UserStatus : uint
{
    offline  = 0,
    away     = 1,
    online   = 2
}

const enum RoomType : uint
{
    public_room   = 0,
    private_room  = 1
}


// Structs

struct LoginRejection
{
    string  reason;
    string  detail;
}

struct LimitedRecommendations
{
    int[string]  descending_items;
    int[string]  ascending_items;
}


// Message Codes

const Login                        = 1;
const SetWaitPort                  = 2;
const GetPeerAddress               = 3;
const WatchUser                    = 5;
const UnwatchUser                  = 6;
const GetUserStatus                = 7;
const SayChatroom                  = 13;
const JoinRoom                     = 14;
const LeaveRoom                    = 15;
const UserJoinedRoom               = 16;
const UserLeftRoom                 = 17;
const ConnectToPeer                = 18;
const MessageUser                  = 22;
const MessageAcked                 = 23;
const FileSearch                   = 26;
const SetStatus                    = 28;
const ServerPing                   = 32;
const SendConnectToken             = 33;    // Obsolete
const SharedFoldersFiles           = 35;
const GetUserStats                 = 36;
const QueuedDownloads              = 40;    // Obsolete
const Relogged                     = 41;
const UserSearch                   = 42;
const SimilarRecommendations       = 50;    // Obsolete
const AddThingILike                = 51;
const RemoveThingILike             = 52;
const GetRecommendations           = 54;
const MyRecommendations            = 55;    // Obsolete
const GlobalRecommendations        = 56;
const UserInterests                = 57;
const RoomList                     = 64;
const AdminMessage                 = 66;
const GlobalUserList               = 67;    // Obsolete
const PrivilegedUsers              = 69;
const CheckPrivileges              = 92;
const WishlistSearch               = 103;
const WishlistInterval             = 104;
const SimilarUsers                 = 110;
const ItemRecommendations          = 111;
const ItemSimilarUsers             = 112;
const RoomTicker                   = 113;
const RoomTickerAdd                = 114;
const RoomTickerRemove             = 115;
const SetRoomTicker                = 116;
const AddThingIHate                = 117;
const RemoveThingIHate             = 118;
const RoomSearch                   = 120;
const SendUploadSpeed              = 121;
const UserPrivileged               = 122;   // Obsolete
const GivePrivileges               = 123;
const NotifyPrivileges             = 124;   // Obsolete
const AckNotifyPrivileges          = 125;   // Obsolete
const PrivateRoomUsers             = 133;
const PrivateRoomAddUser           = 134;
const PrivateRoomRemoveUser        = 135;
const PrivateRoomCancelMembership  = 136;
const PrivateRoomDisown            = 137;
const PrivateRoomAdded             = 139;
const PrivateRoomRemoved           = 140;
const PrivateRoomToggle            = 141;
const ChangePassword               = 142;
const PrivateRoomAddOperator       = 143;
const PrivateRoomRemoveOperator    = 144;
const PrivateRoomOperatorAdded     = 145;
const PrivateRoomOperatorRemoved   = 146;
const PrivateRoomOperators         = 148;
const MessageUsers                 = 149;
const JoinGlobalRoom               = 150;
const LeaveGlobalRoom              = 151;
const GlobalRoomMessage            = 152;
const RelatedSearch                = 153;   // Obsolete
const ExcludedSearchPhrases        = 160;
const CantConnectToPeer            = 1001;
const CantCreateRoom               = 1003;


// Incoming Messages

class UMessage
{
    uint             code;
    bool             is_valid = true;
    private size_t   offset;
    private ubyte[]  in_buf;

    this(ubyte[] in_buf, string in_username = "[ unknown ]") scope
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
        auto cls_name = typeid(this).name;
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
                    const bytes = in_buf[offset .. offset + size];
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

    this(ubyte[] in_buf) scope
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

    this(ubyte[] in_buf, string in_username) scope
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

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        username = read!string();
    }
}

final class UWatchUser : UMessage
{
    string username;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        username = read!string();
    }
}

final class UUnwatchUser : UMessage
{
    string username;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        username = read!string();
    }
}

final class UGetUserStatus : UMessage
{
    string username;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        username = read!string();
    }
}

final class USayChatroom : UMessage
{
    string  room_name;
    string  message;

    this(ubyte[] in_buf, string in_username) scope
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

    this(ubyte[] in_buf, string in_username) scope
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

    this(ubyte[] in_buf, string in_username) scope
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

    this(ubyte[] in_buf, string in_username) scope
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

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        username = read!string();
        message  = read!string();
    }
}

final class UMessageAcked : UMessage
{
    uint id;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        id = read!uint();
    }
}

final class UFileSearch : UMessage
{
    uint    token;
    string  query;

    this(ubyte[] in_buf, string in_username) scope
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

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        token = read!uint();
        query = read!string();
    }
}

final class USimilarUsers : UMessage
{
    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);
    }
}

final class USetStatus : UMessage
{
    uint status;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        status = read!uint();
    }
}

final class UServerPing : UMessage
{
    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);
    }
}

final class USendConnectToken : UMessage
{
    string  username;
    uint    token;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        username = read!string();
        token    = read!uint();
    }
}

final class USendUploadSpeed : UMessage
{
    uint speed;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        speed = read!uint();
    }
}

final class USharedFoldersFiles : UMessage
{
    uint  shared_folders;
    uint  shared_files;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        shared_folders = read!uint();
        shared_files   = read!uint();
    }
}

final class UGetUserStats : UMessage
{
    string username;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        username = read!string();
    }
}

final class UQueuedDownloads : UMessage
{
    uint slots_full;

    this(ubyte[] in_buf, string in_username) scope
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

    this(ubyte[] in_buf, string in_username) scope
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

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        recommendation = read!string();
    }
}

final class UAddThingILike : UMessage
{
    string item;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        item = read!string();
    }
}

final class URemoveThingILike : UMessage
{
    string item;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        item = read!string();
    }
}

final class UGetRecommendations : UMessage
{
    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);
    }
}

final class UMyRecommendations : UMessage
{
    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);
    }
}

final class UGlobalRecommendations : UMessage
{
    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);
    }
}

final class UUserInterests : UMessage
{
    string username;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        username = read!string();
    }
}

final class URoomList : UMessage
{
    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);
    }
}

final class UGlobalUserList : UMessage
{
    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);
    }
}

final class UCheckPrivileges : UMessage
{
    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);
    }
}

final class UAddThingIHate : UMessage
{
    string item;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        item = read!string();
    }
}

final class URemoveThingIHate : UMessage
{
    string item;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        item = read!string();
    }
}

final class UItemRecommendations : UMessage
{
    string item;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        item = read!string();
    }
}

final class UItemSimilarUsers : UMessage
{
    string item;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        item = read!string();
    }
}

final class USetRoomTicker : UMessage
{
    string  room_name;
    string  ticker;

    this(ubyte[] in_buf, string in_username) scope
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

    this(ubyte[] in_buf, string in_username) scope
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

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        username = read!string();
    }
}

final class UGivePrivileges : UMessage
{
    string    username;
    Duration  duration;

    this(ubyte[] in_buf, string in_username) scope
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

    this(ubyte[] in_buf, string in_username) scope
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

    this(ubyte[] in_buf, string in_username) scope
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

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        room_name = read!string();
        username = read!string();
    }
}

final class UPrivateRoomCancelMembership : UMessage
{
    string room_name;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        room_name = read!string();
    }
}

final class UPrivateRoomDisown : UMessage
{
    string room_name;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        room_name = read!string();
    }
}

final class UPrivateRoomToggle : UMessage
{
    bool enabled;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        enabled = read!bool();
    }
}

final class UChangePassword : UMessage
{
    string password;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        password = read!string();
    }
}

final class UPrivateRoomAddOperator : UMessage
{
    string  room_name;
    string  username;

    this(ubyte[] in_buf, string in_username) scope
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

    this(ubyte[] in_buf, string in_username) scope
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

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        foreach (i ; 0 .. read!uint()) usernames ~= read!string();
        message = read!string();
    }
}

final class UJoinGlobalRoom : UMessage
{
    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);
    }
}

final class ULeaveGlobalRoom : UMessage
{
    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);
    }
}

final class URelatedSearch : UMessage
{
    string query;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        query = read!string();
    }
}

final class UCantConnectToPeer : UMessage
{
    uint token;
    string username;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        token    = read!uint();
        username = read!string();
    }
}


// Outgoing Messages

class SMessage
{
    uint                        code;
    private Appender!(ubyte[])  out_buf;

    this(uint code) scope
    {
        this.code = code;
        write!uint(code);
    }

    string name() scope
    {
        auto cls_name = typeid(this).name;
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
    this(uint[string] rooms,
         uint[string] owned_private_rooms,
         uint[string] other_private_rooms,
         string[] operated_private_rooms) scope
    {
        super(RoomList);

        write!uint(cast(uint) rooms.length);
        foreach (ref room_name, ref _users ; rooms)
            write!string(room_name);

        write!uint(cast(uint) rooms.length);
        foreach (ref _room_name, ref users ; rooms)
            write!uint(users);

        write!uint(cast(uint) owned_private_rooms.length);
        foreach (ref room_name, ref _users ; owned_private_rooms)
            write!string(room_name);

        write!uint(cast(uint) owned_private_rooms.length);
        foreach (ref _room_name, ref users ; owned_private_rooms)
            write!uint(users);

        write!uint(cast(uint) other_private_rooms.length);
        foreach (ref room_name, ref _users ; other_private_rooms)
            write!string(room_name);

        write!uint(cast(uint) other_private_rooms.length);
        foreach (ref _room_name, ref users ; other_private_rooms)
            write!uint(users);

        write!uint(cast(uint) operated_private_rooms.length);
        foreach (ref room_name ; operated_private_rooms)
            write!string(room_name);
    }
}

final class SJoinRoom : SMessage
{
    this(string room_name, User[string] users) scope
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
        foreach (ref user ; users) write!uint(0);  // slots_full, obsolete

        write!uint(n);
        foreach (ref user ; users) write!string("");  // country_code, obsolete
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
         uint upload_speed, uint shared_files, uint shared_folders) scope
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
        write!uint(0);     // slots_full, obsolete
        write!string("");  // country_code, obsolete
    }
}

final class SUserLeftRoom : SMessage
{
    this(string username, string room_name) scope
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
    this(uint id, const SysTime timestamp, string username, string message,
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
        foreach (item, level ; recommendations.descending_items)
        {
            write!string(item);
            write!int(level);
        }
        write!uint(cast(uint) recommendations.ascending_items.length);
        foreach (item, level ; recommendations.ascending_items)
        {
            write!string(item);
            write!int(level);
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
        foreach (item, level ; recommendations.descending_items)
        {
            write!string(item);
            write!int(level);
        }
        write!uint(cast(uint) recommendations.ascending_items.length);
        foreach (item, level ; recommendations.ascending_items)
        {
            write!string(item);
            write!int(level);
        }
    }
}

final class SUserInterests : SMessage
{
    this(string user, string[string] likes, string[string] hates) scope
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
    this(uint[string] usernames) scope
    {
        super(SimilarUsers);

        write!uint(cast(uint) usernames.length);
        foreach (ref username, weight ; usernames)
        {
            write!string(username);
            write!uint(weight);
        }
    }
}

final class SItemRecommendations : SMessage
{
    this(string item, int[string] recommendations) scope
    {
        super(ItemRecommendations);

        write!string(item);
        write!uint(cast(uint) recommendations.length);

        foreach (ref recommendation, weight ; recommendations)
        {
            write!string(recommendation);
            write!int(weight);
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
    this(string room_name, Ticker[] tickers) scope
    {
        super(RoomTicker);

        write!string(room_name);
        write!uint(cast(uint) tickers.length);
        foreach (ref ticker ; tickers)
        {
            write!string(ticker.username);
            write!string(ticker.content);
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
    this(string query, uint[string] terms) scope
    {
        super(RelatedSearch);

        write!string(query);
        write!uint(cast(uint) terms.length);
        foreach (ref term, score ; terms)
        {
            write!string(term);
            write!uint(score);
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
