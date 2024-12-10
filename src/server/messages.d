// SPDX-FileCopyrightText: 2024 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server.messages;
@safe:

import soulfind.defines;
import std.bitmanip : Endian, nativeToLittleEndian, read;
import std.stdio : writefln;

// Constants

const enum Status
{
    offline  = 0,
    away     = 1,
    online   = 2
}


// Server Messages

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


// Server Message Names

const string[] message_name = [
    1    : "Login",
    2    : "SetWaitPort",
    3    : "GetPeerAddress",
    5    : "WatchUser",
    6    : "UnwatchUser",
    7    : "GetUserStatus",
    13   : "SayChatroom",
    14   : "JoinRoom",
    15   : "LeaveRoom",
    16   : "UserJoinedRoom",
    17   : "UserLeftRoom",
    18   : "ConnectToPeer",
    22   : "MessageUser",
    23   : "MessageAcked",
    26   : "FileSearch",
    28   : "SetStatus",
    32   : "ServerPing",
    35   : "SharedFoldersFiles",
    36   : "GetUserStats",
    41   : "Relogged",
    51   : "AddThingILike",
    52   : "RemoveThingILike",
    54   : "GetRecommendations",
    56   : "GlobalRecommendations",
    57   : "UserInterests",
    64   : "RoomList",
    66   : "AdminMessage",
    69   : "PrivilegedUsers",
    92   : "CheckPrivileges",
    103  : "WishlistSearch",
    104  : "WishlistInterval",
    110  : "SimilarUsers",
    111  : "ItemRecommendations",
    112  : "ItemSimilarUsers",
    113  : "RoomTicker",
    114  : "RoomTickerAdd",
    115  : "RoomTickerRemove",
    116  : "SetRoomTicker",
    117  : "AddThingIHate",
    118  : "RemoveThingIHate",
    120  : "RoomSearch",
    121  : "SendUploadSpeed",
    122  : "UserPrivileged",
    123  : "GivePrivileges",
    142  : "ChangePassword",
    149  : "MessageUsers",
    150  : "JoinGlobalRoom",
    151  : "LeaveGlobalRoom",
    152  : "GlobalRoomMessage",
    1001 : "CantConnectToPeer",
];


// Base Message

class Message
{
    // Attributes

    uint               code;

    private uint       offset;
    private ubyte[]    out_buf;
    private uint       length;
    private ubyte[]    in_buf;


    // Outgoing Message

    this(uint code)
    {
        this.code = code;
        writei(code);
    }

    const(ubyte)[] bytes()
    {
        return out_buf[0 .. offset];
    }

    private void resize_buffer(ulong size)
    {
        // Preallocate larger buffer size than required to reduce
        // number of resizes while filling the buffer
        if (out_buf.length < offset + size)
            out_buf.length = (offset + size) * 2;
    }

    private void write(scope const(ubyte)[] bytes)
    {
        resize_buffer(bytes.length);
        out_buf[offset .. offset + bytes.length] = bytes[];
        offset += bytes.length;
    }

    private void writeb(bool b)
    {
        resize_buffer(ubyte.sizeof);
        out_buf[offset] = b;
        offset += ubyte.sizeof;
    }

    private void writei(uint i)
    {
        write(i.nativeToLittleEndian);
    }

    private void writesi(int i)
    {
        write(i.nativeToLittleEndian);
    }

    private void writes(string s)
    {
        writei(cast(uint) s.length);
        write(cast(immutable(ubyte)[]) s);
    }


    // Incoming Message

    this(ubyte[] in_buf)
    {
        this.in_buf = in_buf;
    }

    private uint readi()
    {
        uint i;
        if (in_buf.length < uint.sizeof) {
            writefln(
                "message code %d, length %d not enough data "
                ~ "trying to read an int", code, length
            );
            return i;
        }

        i = in_buf.read!(uint, Endian.littleEndian);
        return i;
    }

    private uint readsi()
    {
        int i;
        if (in_buf.length < int.sizeof) {
            writefln(
                "message code %d, length %d not enough data "
                ~ "trying to read a signed int", code, length
            );
            return i;
        }

        i = in_buf.read!(int, Endian.littleEndian);
        return i;
    }

    private bool readb()
    {
        bool i;
        if (in_buf.length < bool.sizeof) {
            writefln(
                "message code %d, length %d not enough data "
                ~ "trying to read a boolean", code, length
            );
            return i;
        }

        i = in_buf.read!(bool, Endian.littleEndian);
        return i;
    }

    private string reads()
    {
        uint slen = readi();
        if (slen > in_buf.length) slen = cast(uint) in_buf.length;
        const str = cast(string) in_buf[0 .. slen].idup;

        in_buf = in_buf[slen .. $];
        return str;
    }
}


// Incoming Messages

class ULogin : Message
{
    string  username;
    string  password;
    uint    major_version;
    string  hash;            // MD5 hash of username + password
    uint    minor_version;

    this(ubyte[] in_buf)
    {
        super(in_buf);

        username      = reads();
        password      = reads();
        major_version = readi();

        if (major_version >= 155) {
            // Older clients would not send these
            hash          = reads();
            minor_version = readi();
        }
    }
}

class USetWaitPort : Message
{
    uint port;

    this(ubyte[] in_buf)
    {
        super(in_buf);

        port = readi();
    }
}

class UGetPeerAddress : Message
{
    string user;

    this(ubyte[] in_buf)
    {
        super(in_buf);

        user = reads();
    }
}

class UWatchUser : Message
{
    string user;

    this(ubyte[] in_buf)
    {
        super(in_buf);

        user = reads();
    }
}

class UUnwatchUser : Message
{
    string user;

    this(ubyte[] in_buf)
    {
        super(in_buf);

        user = reads();
    }
}

class UGetUserStatus : Message
{
    string user;

    this(ubyte[] in_buf)
    {
        super(in_buf);

        user = reads();
    }
}

class USayChatroom : Message
{
    string  room;
    string  message;

    this(ubyte[] in_buf)
    {
        super(in_buf);

        room    = reads();
        message = reads();
    }
}

class UJoinRoom : Message
{
    string room;

    this(ubyte[] in_buf)
    {
        super(in_buf);

        room = reads();
    }
}

class ULeaveRoom : Message
{
    string room;

    this(ubyte[] in_buf)
    {
        super(in_buf);

        room = reads();
    }
}

class UConnectToPeer : Message
{
    uint    token;
    string  user;
    string  type;

    this(ubyte[] in_buf)
    {
        super(in_buf);

        token = readi();
        user  = reads();
        type  = reads();
    }
}

class UMessageUser : Message
{
    string  user;
    string  message;

    this(ubyte[] in_buf)
    {
        super(in_buf);

        user    = reads();
        message = reads();
    }
}

class UMessageAcked : Message
{
    uint id;

    this(ubyte[] in_buf)
    {
        super(in_buf);

        id = readi();
    }
}

class UFileSearch : Message
{
    uint    token;
    string  query;

    this(ubyte[] in_buf)
    {
        super(in_buf);

        token = readi();
        query = reads();
    }
}

class UWishlistSearch : Message
{
    uint    token;
    string  query;

    this(ubyte[] in_buf)
    {
        super(in_buf);

        token = readi();
        query = reads();
    }
}

class USetStatus : Message
{
    uint status;

    this(ubyte[] in_buf)
    {
        super(in_buf);

        status = readi();
    }
}

class USendUploadSpeed : Message
{
    uint speed;

    this(ubyte[] in_buf)
    {
        super(in_buf);

        speed = readi();
    }
}

class USharedFoldersFiles : Message
{
    uint  nb_folders;
    uint  nb_files;

    this(ubyte[] in_buf)
    {
        super(in_buf);

        nb_folders = readi();
        nb_files   = readi();
    }
}

class UGetUserStats : Message
{
    string user;

    this(ubyte[] in_buf)
    {
        super(in_buf);

        user = reads();
    }
}

class UUserSearch : Message
{
    string  user;
    uint    token;
    string  query;

    this(ubyte[] in_buf)
    {
        super(in_buf);

        user  = reads();
        token = readi();
        query = reads();
    }
}

class UAddThingILike : Message
{
    string thing;

    this(ubyte[] in_buf)
    {
        super(in_buf);

        thing = reads();
    }
}

class URemoveThingILike : Message
{
    string thing;

    this(ubyte[] in_buf)
    {
        super(in_buf);

        thing = reads();
    }
}

class UUserInterests : Message
{
    string user;

    this(ubyte[] in_buf)
    {
        super(in_buf);

        user = reads();
    }
}

class UAddThingIHate : Message
{
    string thing;

    this(ubyte[] in_buf)
    {
        super(in_buf);

        thing = reads();
    }
}

class URemoveThingIHate : Message
{
    string thing;

    this(ubyte[] in_buf)
    {
        super(in_buf);

        thing = reads();
    }
}

class UGetItemRecommendations : Message
{
    string item;

    this(ubyte[] in_buf)
    {
        super(in_buf);

        item = reads();
    }
}

class UItemSimilarUsers : Message
{
    string item;

    this(ubyte[] in_buf)
    {
        super(in_buf);

        item = reads();
    }
}

class USetRoomTicker : Message
{
    string  room;
    string  tick;

    this(ubyte[] in_buf)
    {
        super(in_buf);

        room = reads();
        tick = reads();
    }
}

class URoomSearch : Message
{
    string  room;
    uint    token;
    string  query;

    this(ubyte[] in_buf)
    {
        super(in_buf);

        room  = reads();
        token = readi();
        query = reads();
    }
}

class UUserPrivileged : Message
{
    string user;

    this(ubyte[] buf)
    {
        super(buf);

        user = reads();
    }
}

class UGivePrivileges : Message
{
    string  user;
    uint    time;

    this(ubyte[] in_buf)
    {
        super(in_buf);

        user = reads();
        time = readi();
    }
}

class UChangePassword : Message
{
    string password;

    this(ubyte[] in_buf)
    {
        super(in_buf);

        password = reads();
    }
}

class UMessageUsers : Message
{
    string[]  users;
    string    message;

    this(ubyte[] in_buf)
    {
        super(in_buf);

        foreach (i ; 0 .. readi()) users ~= reads();
        message = reads();
    }
}

class UCantConnectToPeer : Message
{
    uint token;
    string user;

    this(ubyte[] in_buf)
    {
        super(in_buf);

        token = readi();
        user  = reads();
    }
}


// Outgoing Messages

class SLogin : Message
{
    this(bool success, string mesg, uint addr = 0,
         string password = null, bool supporter = false)
    {
        super(Login);

        writeb(success);
        writes(mesg);

        if (success)
        {
            writei(addr);
            writes(password);
            writeb(supporter);
        }
    }
}

class SGetPeerAddress : Message
{
    this(string username, uint address, uint port, uint unknown = 0,
            uint obfuscated_port = 0)
    {
        super(GetPeerAddress);

        writes(username);
        writei(address);
        writei(port);
        writei(unknown);
        writei(obfuscated_port);
    }
}

class SWatchUser : Message
{
    this(string user, bool exists, uint status, uint speed,
         uint upload_number, uint something, uint shared_files,
         uint shared_folders, string country_code)
    {
        super(WatchUser);

        writes(user);
        writeb(exists);
        if (!exists)
            return;

        writei(status);
        writei(speed);
        writei(upload_number);
        writei(something);
        writei(shared_files);
        writei(shared_folders);
        if (status > 0) writes(country_code);
    }
}

class SGetUserStatus : Message
{
    this(string username, uint status, bool privileged)
    {
        super(GetUserStatus);

        writes(username);
        writei(status);
        writeb(privileged);
    }
}

class SSayChatroom : Message
{
    this(string room, string user, string mesg)
    {
        super(SayChatroom);

        writes(room);
        writes(user);
        writes(mesg);
    }
}

class SRoomList : Message
{
    this(ulong[string] rooms)
    {
        super(RoomList);

        writei(cast(uint) rooms.length);
        foreach (room, users ; rooms) writes(room);

        writei(cast(uint) rooms.length);
        foreach (room, users ; rooms) writei(cast(uint) users);

        writei(0);    // number of owned private rooms(unimplemented)
        writei(0);    // number of owned private rooms(unimplemented)
        writei(0);    // number of other private rooms(unimplemented)
        writei(0);    // number of other private rooms(unimplemented)
        writei(0);    // number of operated private rooms(unimplemented)
    }
}

class SJoinRoom : Message
{
    this(string room, string[] usernames, uint[string] statuses,
         uint[string] speeds, uint[string] upload_numbers,
         uint[string] somethings, uint[string] shared_files,
         uint[string] shared_folders, uint[string] slots_full,
         string[string] country_codes)
    {
        super(JoinRoom);

        writes(room);
        const n = cast(uint) usernames.length;

        writei(n);
        foreach (username ; usernames) writes(username);

        writei(n);
        foreach (username ; usernames) writei(statuses[username]);

        writei(n);
        foreach (username ; usernames)
        {
            writei(speeds          [username]);
            writei(upload_numbers  [username]);
            writei(somethings      [username]);
            writei(shared_files    [username]);
            writei(shared_folders  [username]);
        }

        writei(n);
        foreach (username ; usernames) writei(slots_full[username]);

        writei(n);
        foreach (username ; usernames) writes(country_codes[username]);
    }
}

class SLeaveRoom : Message
{
    this(string room)
    {
        super(LeaveRoom);

        writes(room);
    }
}

class SUserJoinedRoom : Message
{
    this(string room, string username, uint status,
         uint speed, uint upload_number, uint something,
         uint shared_files, uint shared_folders,
         uint slots_full, string country_code)
    {
        super(UserJoinedRoom);

        writes(room);
        writes(username);
        writei(status);
        writei(speed);
        writei(upload_number);
        writei(something);
        writei(shared_files);
        writei(shared_folders);
        writei(slots_full);
        writes(country_code);
    }
}

class SUserLeftRoom : Message
{
    this(string username, string room)
    {
        super(UserLeftRoom);

        writes(room);
        writes(username);
    }
}

class SConnectToPeer : Message
{
    this(string username, string type, uint address, uint port,
            uint token, bool privileged, uint unknown = 0,
            uint obfuscated_port = 0)
    {
        super(ConnectToPeer);

        writes(username);
        writes(type);
        writei(address);
        writei(port);
        writei(token);
        writeb(privileged);
        writei(unknown);
        writei(obfuscated_port);
    }
}

class SMessageUser : Message
{
    this(uint id, ulong timestamp, string from, string content,
            bool new_message)
    {
        super(MessageUser);

        writei(id);
        writei(cast(uint) timestamp);
        writes(from);
        writes(content);
        writeb(new_message);
    }
}

class SFileSearch : Message
{
    this(string username, uint token, string text)
    {
        super(FileSearch);

        writes(username);
        writei(token);
        writes(text);
    }
}

class SGetUserStats : Message
{
    this(string username, uint speed, uint upload_number, uint something,
            uint shared_files, uint shared_folders)
    {
        super(GetUserStats);

        writes(username);
        writei(speed);
        writei(upload_number);
        writei(something);
        writei(shared_files);
        writei(shared_folders);
    }
}

class SGetRecommendations : Message
{
    this(uint[string] list)
    {
        super(GetRecommendations);

        writei(cast(uint) list.length);
        foreach (artist, level ; list)
        {
            writes(artist);
            writesi(level);
        }
    }
}

class SGetGlobalRecommendations : Message
{
    this(uint[string] list)
    {
        super(GlobalRecommendations);

        writei(cast(uint) list.length);
        foreach (artist, level ; list)
        {
            writes(artist);
            writesi(level);
        }
    }
}

class SUserInterests : Message
{
    this(string user, string[string] likes, string[string] hates)
    {
        super(UserInterests);

        writes(user);

        writei(cast(uint) likes.length);
        foreach (thing ; likes) writes(thing);

        writei(cast(uint) hates.length);
        foreach (thing ; hates) writes(thing);
    }
}

class SRelogged : Message
{
    this()
    {
        super(Relogged);
    }
}

class SUserSearch : Message
{
    this(string user, uint token, string query)
    {
        super(UserSearch);

        writes(user);
        writei(token);
        writes(query);
    }
}

class SAdminMessage : Message
{
    this(string message)
    {
        super(AdminMessage);

        writes(message);
    }
}

class SCheckPrivileges : Message
{
    this(long time)
    {
        super(CheckPrivileges);

        writei(cast(uint) time);
    }
}

class SWishlistInterval : Message
{
    this(uint interval)
    {
        super(WishlistInterval);

        writei(interval);
    }
}

class SSimilarUsers : Message
{
    this(uint[string] list)
    {
        super(SimilarUsers);

        writei(cast(uint) list.length);
        foreach (user, weight ; list)
        {
            writes(user);
            writei(weight);
        }
    }
}

class SGetItemRecommendations : Message
{
    this(string item, uint[string] list)
    {
        super(ItemRecommendations);

        writes(item);
        writei(cast(uint) list.length);

        foreach (recommendation, weight ; list)
        {
            writes (recommendation);
            writesi(weight);
        }
    }
}

class SItemSimilarUsers : Message
{
    this(string item, string[] list)
    {
        super(ItemSimilarUsers);

        writes(item);
        writei(cast(uint) list.length);
        foreach (user ; list) writes(user);
    }
}

class SRoomTicker : Message
{
    this(string room, string[string] tickers)
    {
        super(RoomTicker);

        writes(room);
        writei(cast(uint) tickers.length);
        foreach (string user, string ticker ; tickers)
        {
            writes(user);
            writes(ticker);
        }
    }
}

class SRoomTickerAdd : Message
{
    this(string room, string user, string ticker)
    {
        super(RoomTickerAdd);

        writes(room);
        writes(user);
        writes(ticker);
    }
}

class SRoomTickerRemove : Message
{
    this(string room, string user)
    {
        super(RoomTickerRemove);

        writes(room);
        writes(user);
    }
}

class SRoomSearch : Message
{
    this(string user, uint token, string query)
    {
        super(RoomSearch);

        writes(user);
        writei(token);
        writes(query);
    }
}

class SUserPrivileged : Message
{
    this(string username, bool privileged)
    {
        super(UserPrivileged);

        writes(username);
        writeb(privileged);
    }
}

class SChangePassword : Message
{
    this(string password)
    {
        super(ChangePassword);

        writes(password);
    }
}

class SGlobalRoomMessage : Message
{
    this(string room, string user, string mesg)
    {
        super(GlobalRoomMessage);

        writes(room);
        writes(user);
        writes(mesg);
    }
}

class SCantConnectToPeer : Message
{
    this(uint token)
    {
        super(CantConnectToPeer);

        writei(token);
    }
}
