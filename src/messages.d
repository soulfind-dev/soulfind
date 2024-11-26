// SPDX-FileCopyrightText: 2024 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module messages;
@safe:

import defines;
import message_codes;
import std.bitmanip : Endian, read;
import std.conv : to;
import std.format : format;
import std.outbuffer : OutBuffer;
import std.stdio : writefln;

class Message
{
    // Attributes

    uint       code;
    OutBuffer  out_buf;
    uint       length;
    ubyte[]    in_buf;


    // Outgoing Message

    this(uint code)
    {
        out_buf = new OutBuffer();
        this.code = code;
        writei(code);
    }

    ubyte[] bytes()
    {
        return out_buf.toBytes();
    }

    private void writei(uint i)
    {
        out_buf.write(i);
    }

    private void writei(ulong i)
    {
        out_buf.write(cast(uint) i);
    }

    private void writesi(int i)
    {
        out_buf.write(i);
    }

    private void writeb(bool b)
    {
        out_buf.write(cast(ubyte) b);
    }

    private void writes(string s)
    {
        writei(s.length);
        out_buf.write(s);
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

class UAdminMessage : Message
{
    string mesg;

    this(ubyte[] in_buf)
    {
        super(in_buf);

        mesg = reads();
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

        writei(rooms.length);
        foreach (room, users ; rooms) writes(room);

        writei(rooms.length);
        foreach (room, users ; rooms) writei(users);

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
        const n = usernames.length;

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
    this(uint id, uint timestamp, string from, string content,
            bool new_message)
    {
        super(MessageUser);

        writei(id);
        writei(timestamp);
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

        writei(list.length);
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

        writei(list.length);
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

        writei(likes.length);
        foreach (thing ; likes) writes(thing);

        writei(hates.length);
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
    this(uint time)
    {
        super(CheckPrivileges);

        writei(time);
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

        writei(list.length);
        foreach (user, weight ; list)
        {
            writes (user);
            writesi(weight);
        }
    }
}

class SGetItemRecommendations : Message
{
    this(string item, uint[string] list)
    {
        super(ItemRecommendations);

        writes(item);
        writei(list.length);

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
        writei(list.length);
        foreach (user ; list) writes(user);
    }
}

class SRoomTicker : Message
{
    this(string room, string[string] tickers)
    {
        super(RoomTicker);

        writes(room);
        writei(tickers.length);
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
