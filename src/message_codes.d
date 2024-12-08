// SPDX-FileCopyrightText: 2024 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module message_codes;
@safe:

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

