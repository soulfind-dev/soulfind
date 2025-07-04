// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server.messages;
@safe:

import soulfind.defines : blue, norm;
import soulfind.server.room : Ticker;
import soulfind.server.user : User;
import std.algorithm : sort;
import std.array : Appender, array;
import std.bitmanip : Endian, nativeToLittleEndian, peek;
import std.conv : to;
import std.encoding : isValid;
import std.stdio : writefln;
import std.string : representation;

// Constants

const enum LoginRejectionReason
{
    username     = "INVALIDUSERNAME",
    password     = "INVALIDPASS",
    server_full  = "SRVFULL"
}

const enum Status
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


// Message Codes

const Login                  = 1;
const SetWaitPort            = 2;
const GetPeerAddress         = 3;
const WatchUser              = 5;
const UnwatchUser            = 6;
const GetUserStatus          = 7;
const SayChatroom            = 13;
const JoinRoom               = 14;
const LeaveRoom              = 15;
const UserJoinedRoom         = 16;
const UserLeftRoom           = 17;
const ConnectToPeer          = 18;
const MessageUser            = 22;
const MessageAcked           = 23;
const FileSearch             = 26;
const SetStatus              = 28;
const ServerPing             = 32;
const SharedFoldersFiles     = 35;
const GetUserStats           = 36;
const Relogged               = 41;
const UserSearch             = 42;
const AddThingILike          = 51;
const RemoveThingILike       = 52;
const GetRecommendations     = 54;
const GlobalRecommendations  = 56;
const UserInterests          = 57;
const RoomList               = 64;
const AdminMessage           = 66;
const CheckPrivileges        = 92;
const WishlistSearch         = 103;
const WishlistInterval       = 104;
const SimilarUsers           = 110;
const ItemRecommendations    = 111;
const ItemSimilarUsers       = 112;
const RoomTicker             = 113;
const RoomTickerAdd          = 114;
const RoomTickerRemove       = 115;
const SetRoomTicker          = 116;
const AddThingIHate          = 117;
const RemoveThingIHate       = 118;
const RoomSearch             = 120;
const SendUploadSpeed        = 121;
const UserPrivileged         = 122;
const GivePrivileges         = 123;
const ChangePassword         = 142;
const MessageUsers           = 149;
const JoinGlobalRoom         = 150;
const LeaveGlobalRoom        = 151;
const GlobalRoomMessage      = 152;
const CantConnectToPeer      = 1001;


// Incoming Messages

class UMessage
{
    uint             code;
    private ulong    offset;
    private ubyte[]  in_buf;

    this(ubyte[] in_buf, string in_username = "?") scope
    {
        this.in_buf = in_buf;
        code = read!uint();

        debug (msg) writefln!(
            "Receive <- %s (code %d) of %d bytes <- from user %s")(
            blue ~ this.name ~ norm, code, in_buf.length,
            blue ~ in_username ~ norm
        );
    }

    string name() scope
    {
        auto cls_name = typeid(this).name;
        foreach_reverse (i; 0 .. cls_name.length)
            if (cls_name[i] == '.')
                return cls_name[i + 1 .. $];
        return cls_name;
    }

    private T read(T)() scope
        if (is(T : int) || is(T : uint) || is(T : bool) || is(T : string))
    {
        T value;
        uint size;

        static if (is(T : string))
            size = read!uint();
        else
            size = T.sizeof;

        if (offset + size <= in_buf.length) {
            static if (is(T : string)) {
                const bytes = in_buf[offset .. offset + size];
                offset += size;

                if (bytes.isValid) {
                    // UTF-8
                    value = cast(T) bytes.idup;
                }
                else {
                    // Latin-1 fallback
                    auto wchars = new wchar[bytes.length];
                    foreach (i, ref c; bytes) wchars[i] = cast(wchar) c;
                    value = wchars.to!string;
                }
            }
            else {
                value = in_buf.peek!(T, Endian.littleEndian)(&offset);
            }
        }
        else {
            offset = in_buf.length;
            writefln!(
                "Message code %d, length %d not enough data trying to read")(
                code, offset
            );
        }
        return value;
    }
}

class ULogin : UMessage
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

        if (major_version >= 155) {
            // Older clients would not send these
            hash          = read!string();
            minor_version = read!uint();
        }
    }
}

class USetWaitPort : UMessage
{
    uint port;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        port = read!uint();
    }
}

class UGetPeerAddress : UMessage
{
    string username;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        username = read!string();
    }
}

class UWatchUser : UMessage
{
    string username;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        username = read!string();
    }
}

class UUnwatchUser : UMessage
{
    string username;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        username = read!string();
    }
}

class UGetUserStatus : UMessage
{
    string username;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        username = read!string();
    }
}

class USayChatroom : UMessage
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

class UJoinRoom : UMessage
{
    string room_name;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        room_name = read!string();
    }
}

class ULeaveRoom : UMessage
{
    string room_name;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        room_name = read!string();
    }
}

class UConnectToPeer : UMessage
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

class UMessageUser : UMessage
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

class UMessageAcked : UMessage
{
    uint id;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        id = read!uint();
    }
}

class UFileSearch : UMessage
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

class UWishlistSearch : UMessage
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

class USimilarUsers : UMessage
{
    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);
    }
}

class USetStatus : UMessage
{
    uint status;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        status = read!uint();
    }
}

class UServerPing : UMessage
{
    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);
    }
}

class USendUploadSpeed : UMessage
{
    uint speed;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        speed = read!uint();
    }
}

class USharedFoldersFiles : UMessage
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

class UGetUserStats : UMessage
{
    string username;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        username = read!string();
    }
}

class UUserSearch : UMessage
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

class UAddThingILike : UMessage
{
    string item;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        item = read!string();
    }
}

class URemoveThingILike : UMessage
{
    string item;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        item = read!string();
    }
}

class UGetRecommendations : UMessage
{
    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);
    }
}

class UGlobalRecommendations : UMessage
{
    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);
    }
}

class UUserInterests : UMessage
{
    string username;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        username = read!string();
    }
}

class URoomList : UMessage
{
    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);
    }
}

class UCheckPrivileges : UMessage
{
    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);
    }
}

class UAddThingIHate : UMessage
{
    string item;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        item = read!string();
    }
}

class URemoveThingIHate : UMessage
{
    string item;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        item = read!string();
    }
}

class UItemRecommendations : UMessage
{
    string item;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        item = read!string();
    }
}

class UItemSimilarUsers : UMessage
{
    string item;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        item = read!string();
    }
}

class USetRoomTicker : UMessage
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

class URoomSearch : UMessage
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

class UUserPrivileged : UMessage
{
    string username;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        username = read!string();
    }
}

class UGivePrivileges : UMessage
{
    string  username;
    uint    days;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        username = read!string();
        days     = read!uint();
    }
}

class UChangePassword : UMessage
{
    string password;

    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);

        password = read!string();
    }
}

class UMessageUsers : UMessage
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

class UJoinGlobalRoom : UMessage
{
    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);
    }
}

class ULeaveGlobalRoom : UMessage
{
    this(ubyte[] in_buf, string in_username) scope
    {
        super(in_buf, in_username);
    }
}

class UCantConnectToPeer : UMessage
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
            out_buf ~= value.representation;
        }
        else {
            out_buf ~= value.nativeToLittleEndian[];
        }
    }
}

class SLogin : SMessage
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

class SGetPeerAddress : SMessage
{
    this(string username, uint ip_address, uint port, uint unknown = 0,
         uint obfuscated_port = 0) scope
    {
        super(GetPeerAddress);

        write!string(username);
        write!uint(ip_address);
        write!uint(port);
        write!uint(unknown);
        write!uint(obfuscated_port);
    }
}

class SWatchUser : SMessage
{
    this(string username, bool exists, uint status, uint speed,
         uint upload_number, uint shared_files, uint shared_folders) scope
    {
        super(WatchUser);

        write!string(username);
        write!bool(exists);
        if (!exists)
            return;

        write!uint(status);
        write!uint(speed);
        write!uint(upload_number);
        write!uint(0);  // unknown, obsolete
        write!uint(shared_files);
        write!uint(shared_folders);
        if (status > 0) write!string("");  // country_code, obsolete
    }
}

class SGetUserStatus : SMessage
{
    this(string username, uint status, bool privileged) scope
    {
        super(GetUserStatus);

        write!string(username);
        write!uint(status);
        write!bool(privileged);
    }
}

class SSayChatroom : SMessage
{
    this(string room_name, string username, string message) scope
    {
        super(SayChatroom);

        write!string(room_name);
        write!string(username);
        write!string(message);
    }
}

class SRoomList : SMessage
{
    this(ulong[string] rooms) scope
    {
        super(RoomList);

        write!uint(cast(uint) rooms.length);
        foreach (room, users ; rooms) write!string(room);

        write!uint(cast(uint) rooms.length);
        foreach (room, users ; rooms) write!uint(cast(uint) users);

        write!uint(0);    // number of owned private rooms (unimplemented)
        write!uint(0);    // number of owned private rooms (unimplemented)
        write!uint(0);    // number of other private rooms (unimplemented)
        write!uint(0);    // number of other private rooms (unimplemented)
        write!uint(0);    // number of operated private rooms (unimplemented)
    }
}

class SJoinRoom : SMessage
{
    this(string room_name, User[string] users) scope
    {
        super(JoinRoom);

        write!string(room_name);
        const n = cast(uint) users.length;

        write!uint(n);
        foreach (username, user ; users) write!string(username);

        write!uint(n);
        foreach (user ; users) write!uint(user.status);

        write!uint(n);
        foreach (user ; users)
        {
            write!uint(user.speed);
            write!uint(user.upload_number);
            write!uint(0);  // unknown, obsolete
            write!uint(user.shared_files);
            write!uint(user.shared_folders);
        }

        write!uint(n);
        foreach (user ; users) write!uint(0);  // slots_full, obsolete

        write!uint(n);
        foreach (user ; users) write!string("");  // country_code, obsolete
    }
}

class SLeaveRoom : SMessage
{
    this(string room_name) scope
    {
        super(LeaveRoom);

        write!string(room_name);
    }
}

class SUserJoinedRoom : SMessage
{
    this(string room_name, string username, uint status,
         uint speed, uint upload_number, uint shared_files,
         uint shared_folders) scope
    {
        super(UserJoinedRoom);

        write!string(room_name);
        write!string(username);
        write!uint(status);
        write!uint(speed);
        write!uint(upload_number);
        write!uint(0);  // unknown, obsolete
        write!uint(shared_files);
        write!uint(shared_folders);
        write!uint(0);  // slots_full, obsolete
        write!string("");  // country_code, obsolete
    }
}

class SUserLeftRoom : SMessage
{
    this(string username, string room_name) scope
    {
        super(UserLeftRoom);

        write!string(room_name);
        write!string(username);
    }
}

class SConnectToPeer : SMessage
{
    this(string username, string type, uint ip_address, uint port,
         uint token, bool privileged, uint unknown = 0,
         uint obfuscated_port = 0) scope
    {
        super(ConnectToPeer);

        write!string(username);
        write!string(type);
        write!uint(ip_address);
        write!uint(port);
        write!uint(token);
        write!bool(privileged);
        write!uint(unknown);
        write!uint(obfuscated_port);
    }
}

class SMessageUser : SMessage
{
    this(uint id, uint timestamp, string username, string message,
         bool new_message) scope
    {
        super(MessageUser);

        write!uint(id);
        write!uint(timestamp);
        write!string(username);
        write!string(message);
        write!bool(new_message);
    }
}

class SFileSearch : SMessage
{
    this(string username, uint token, string query) scope
    {
        super(FileSearch);

        write!string(username);
        write!uint(token);
        write!string(query);
    }
}

class SGetUserStats : SMessage
{
    this(string username, uint speed, uint upload_number, uint shared_files,
         uint shared_folders) scope
    {
        super(GetUserStats);

        write!string(username);
        write!uint(speed);
        write!uint(upload_number);
        write!uint(0);  // unknown, obsolete
        write!uint(shared_files);
        write!uint(shared_folders);
    }
}

class SGetRecommendations : SMessage
{
    this(uint[string] recommendations) scope
    {
        super(GetRecommendations);

        write!uint(cast(uint) recommendations.length);
        foreach (item, level ; recommendations)
        {
            write!string(item);
            write!int(level);
        }
    }
}

class SGetGlobalRecommendations : SMessage
{
    this(uint[string] recommendations) scope
    {
        super(GlobalRecommendations);

        write!uint(cast(uint) recommendations.length);
        foreach (item, level ; recommendations)
        {
            write!string(item);
            write!int(level);
        }
    }
}

class SUserInterests : SMessage
{
    this(string user, string[string] likes, string[string] hates) scope
    {
        super(UserInterests);

        write!string(user);

        write!uint(cast(uint) likes.length);
        foreach (item ; likes) write!string(item);

        write!uint(cast(uint) hates.length);
        foreach (item ; hates) write!string(item);
    }
}

class SRelogged : SMessage
{
    this() scope
    {
        super(Relogged);
    }
}

class SUserSearch : SMessage
{
    this(string username, uint token, string query) scope
    {
        super(UserSearch);

        write!string(username);
        write!uint(token);
        write!string(query);
    }
}

class SAdminMessage : SMessage
{
    this(string message) scope
    {
        super(AdminMessage);

        write!string(message);
    }
}

class SCheckPrivileges : SMessage
{
    this(uint seconds) scope
    {
        super(CheckPrivileges);

        write!uint(seconds);
    }
}

class SWishlistInterval : SMessage
{
    this(uint interval) scope
    {
        super(WishlistInterval);

        write!uint(interval);
    }
}

class SSimilarUsers : SMessage
{
    this(uint[string] usernames) scope
    {
        super(SimilarUsers);

        write!uint(cast(uint) usernames.length);
        foreach (username, weight ; usernames)
        {
            write!string(username);
            write!uint(weight);
        }
    }
}

class SItemRecommendations : SMessage
{
    this(string item, uint[string] recommendations) scope
    {
        super(ItemRecommendations);

        write!string(item);
        write!uint(cast(uint) recommendations.length);

        foreach (recommendation, weight ; recommendations)
        {
            write!string (recommendation);
            write!int(weight);
        }
    }
}

class SItemSimilarUsers : SMessage
{
    this(string item, string[] usernames) scope
    {
        super(ItemSimilarUsers);

        write!string(item);
        write!uint(cast(uint) usernames.length);
        foreach (username ; usernames) write!string(username);
    }
}

class SRoomTicker : SMessage
{
    this(string room_name, Ticker[] tickers) scope
    {
        super(RoomTicker);

        write!string(room_name);
        write!uint(cast(uint) tickers.length);
        foreach (ticker ; tickers.sort)
        {
            write!string(ticker.username);
            write!string(ticker.content);
        }
    }
}

class SRoomTickerAdd : SMessage
{
    this(string room_name, string username, string ticker) scope
    {
        super(RoomTickerAdd);

        write!string(room_name);
        write!string(username);
        write!string(ticker);
    }
}

class SRoomTickerRemove : SMessage
{
    this(string room_name, string username) scope
    {
        super(RoomTickerRemove);

        write!string(room_name);
        write!string(username);
    }
}

class SRoomSearch : SMessage
{
    this(string username, uint token, string query) scope
    {
        super(RoomSearch);

        write!string(username);
        write!uint(token);
        write!string(query);
    }
}

class SUserPrivileged : SMessage
{
    this(string username, bool privileged) scope
    {
        super(UserPrivileged);

        write!string(username);
        write!bool(privileged);
    }
}

class SChangePassword : SMessage
{
    this(string password) scope
    {
        super(ChangePassword);

        write!string(password);
    }
}

class SGlobalRoomMessage : SMessage
{
    this(string room_name, string username, string message) scope
    {
        super(GlobalRoomMessage);

        write!string(room_name);
        write!string(username);
        write!string(message);
    }
}

class SCantConnectToPeer : SMessage
{
    this(uint token) scope
    {
        super(CantConnectToPeer);

        write!uint(token);
    }
}
