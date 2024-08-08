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
const struct Status
	{
	const int Unknown = -1;
	const int Offline =  0;
	const int Away    =  1;
	const int Online  =  2;
	}

const struct Transfer
	{
	const int Download = 0;
	const int Upload   = 1;
	}

// Server Messages
const int Login				= 1;
const int SetWaitPort			= 2;
const int GetPeerAddress		= 3;
const int WatchUser			= 5;
const int UnwatchUser			= 6;
const int GetUserStatus			= 7;
const int SayChatroom			= 13;
const int JoinRoom			= 14;
const int LeaveRoom			= 15;
const int UserJoinedRoom		= 16;
const int UserLeftRoom			= 17;
const int ConnectToPeer			= 18;
const int MessageUser			= 22;
const int MessageAcked			= 23;
const int FileSearch			= 26;
const int SetStatus			= 28;
const int ServerPing			= 32;
const int SharedFoldersFiles		= 35;
const int GetUserStats			= 36;
const int Relogged			= 41;
const int UserSearch			= 42;
const int AddThingILike			= 51;
const int RemoveThingILike		= 52;
const int GetRecommendations		= 54;
const int GlobalRecommendations		= 56;
const int UserInterests			= 57;
const int RoomList			= 64;
const int AdminMessage			= 66;
const int AddToPrivileged		= 91;
const int CheckPrivileges		= 92;
const int WishlistSearch		= 103;
const int WishlistInterval		= 104;
const int SimilarUsers			= 110;
const int ItemRecommendations		= 111;
const int ItemSimilarUsers		= 112;
const int RoomTicker			= 113;
const int RoomTickerAdd			= 114;
const int RoomTickerRemove		= 115;
const int SetRoomTicker			= 116;
const int AddThingIHate			= 117;
const int RemoveThingIHate		= 118;
const int RoomSearch			= 120;
const int SendUploadSpeed		= 121;
const int UserPrivileges		= 122;
const int GivePrivileges		= 123;
const int ChangePassword		= 142;
const int MessageUsers			= 149;
const int CantConnectToPeer		= 1001;

const int ServerInfo			= 1789; // specific to Soulfind

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
		, 91 : "AddToPrivileged"
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
		, 122 : "UserPrivileges"
		, 123 : "GivePrivileges"
		, 1001 : "CantConnectToPeer"
		, 1789 : "ServerInfo"];

