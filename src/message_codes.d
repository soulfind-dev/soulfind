/+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 + SoulFind - Free SoulSeek server                                           +
 +                                                                           +
 + Copyright (C) 2005 SeeSchloss <seeschloss@seeschloss.org>                 +
 +                                                                           +
 + This  program  is free software ; you can  redistribute it  and/or modify +
 + it under  the  terms of  the GNU General Public License  as published  by +
 + the  Free  Software  Foundation ;  either  version  2 of  the License, or +
 + (at your option) any later version.                                       +
 +                                                                           +
 + This  program  is  distributed  in the  hope  that  it  will  be  useful, +
 + but   WITHOUT  ANY  WARRANTY ;  without  even  the  implied  warranty  of +
 + MERCHANTABILITY   or   FITNESS   FOR   A   PARTICULAR  PURPOSE.  See  the +
 + GNU General Public License for more details.                              +
 +                                                                           +
 + You  should  have  received  a  copy  of  the  GNU General Public License +
 + along   with  this  program ;  if  not,  write   to   the  Free  Software +
 + Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA +
 +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++/


module message_codes;

// Constants
const enum Status
	{
	offline = 0,
	away    = 1,
	online  = 2
	}

// Server Messages
const uint Login			= 1;
const uint SetWaitPort			= 2;
const uint GetPeerAddress		= 3;
const uint WatchUser			= 5;
const uint UnwatchUser			= 6;
const uint GetUserStatus		= 7;
const uint SayChatroom			= 13;
const uint JoinRoom			= 14;
const uint LeaveRoom			= 15;
const uint UserJoinedRoom		= 16;
const uint UserLeftRoom			= 17;
const uint ConnectToPeer		= 18;
const uint MessageUser			= 22;
const uint MessageAcked			= 23;
const uint FileSearch			= 26;
const uint SetStatus			= 28;
const uint ServerPing			= 32;
const uint SharedFoldersFiles		= 35;
const uint GetUserStats			= 36;
const uint Relogged			= 41;
const uint UserSearch			= 42;
const uint AddThingILike		= 51;
const uint RemoveThingILike		= 52;
const uint GetRecommendations		= 54;
const uint GlobalRecommendations	= 56;
const uint UserInterests		= 57;
const uint RoomList			= 64;
const uint AdminMessage			= 66;
const uint CheckPrivileges		= 92;
const uint WishlistSearch		= 103;
const uint WishlistInterval		= 104;
const uint SimilarUsers			= 110;
const uint ItemRecommendations		= 111;
const uint ItemSimilarUsers		= 112;
const uint RoomTicker			= 113;
const uint RoomTickerAdd		= 114;
const uint RoomTickerRemove		= 115;
const uint SetRoomTicker		= 116;
const uint AddThingIHate		= 117;
const uint RemoveThingIHate		= 118;
const uint RoomSearch			= 120;
const uint SendUploadSpeed		= 121;
const uint UserPrivileged		= 122;
const uint GivePrivileges		= 123;
const uint ChangePassword		= 142;
const uint MessageUsers			= 149;
const uint JoinGlobalRoom		= 150;
const uint LeaveGlobalRoom		= 151;
const uint GlobalRoomMessage		= 152;
const uint CantConnectToPeer		= 1001;

const uint ServerInfo			= 1789; // specific to Soulfind

// Useful for debugging
string[] message_name = [
		  1 : "Login"
		, 2 : "SetWaitPort"
		, 3 : "GetPeerAddress"
		, 5 : "WatchUser"
		, 6 : "UnwatchUser"
		, 7 : "GetUserStatus"
		, 13 : "SayChatroom"
		, 14 : "JoinRoom"
		, 15 : "LeaveRoom"
		, 16 : "UserJoinedRoom"
		, 17 : "UserLeftRoom"
		, 18 : "ConnectToPeer"
		, 22 : "MessageUser"
		, 23 : "MessageAcked"
		, 26 : "FileSearch"
		, 28 : "SetStatus"
		, 32 : "ServerPing"
		, 35 : "SharedFoldersFiles"
		, 36 : "GetUserStats"
		, 41 : "Relogged"
		, 51 : "AddThingILike"
		, 52 : "RemoveThingILike"
		, 54 : "GetRecommendations"
		, 56 : "GlobalRecommendations"
		, 64 : "RoomList"
		, 66 : "AdminMessage"
		, 69 : "PrivilegedUsers"
		, 92 : "CheckPrivileges"
		, 103 : "WishlistSearch"
		, 104 : "WishlistInterval"
		, 110 : "SimilarUsers"
		, 111 : "ItemRecommendations"
		, 112 : "ItemSimilarUsers"
		, 113 : "RoomTicker"
		, 114 : "RoomTickerAdd"
		, 115 : "RoomTickerRemove"
		, 116 : "SetRoomTicker"
		, 117 : "AddThingIHate"
		, 118 : "RemoveThingIHate"
		, 120 : "RoomSearch"
		, 121 : "SendUploadSpeed"
		, 122 : "UserPrivileged"
		, 123 : "GivePrivileges"
		, 142 : "ChangePassword"
		, 149 : "MessageUsers"
		, 150 : "JoinGlobalRoom"
		, 151 : "LeaveGlobalRoom"
		, 152 : "GlobalRoomMessage"
		, 1001 : "CantConnectToPeer"
		, 1789 : "ServerInfo"];

