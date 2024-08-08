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
const int SendDownloadSpeed		= 34;
const int SharedFoldersFiles		= 35;
const int GetUserStats			= 36;
const int QueuedDownloads		= 40;	/+ TODO : S (no trace of that in museek, ask hyriand what it is exactly ?) +/
const int Relogged			= 41;
const int UserSearch			= 42;
const int AddThingILike			= 51;
const int RemoveThingILike		= 52;
const int GetRecommendations		= 54;	/+ TODO : both +/
const int GlobalRecommendations		= 56;	/+ TODO : both +/
const int UserInterests			= 57;
const int PlaceInLineResponse		= 60;	/+ not used anymore on the official server +/
const int RoomAdded			= 62;	/+ not used anymore, not understood by museek +/
const int RoomRemoved			= 63;	/+ --^ +/
const int RoomList			= 64;
const int ExactFileSearch		= 65;	/+ TODO : U +/
const int AdminMessage			= 66;
const int GlobalUserList		= 67;	/+ TODO : both (not used anymore, probably not understood by any client) +/
const int TunneledMessage		= 68;	/+ TODO : both (no idea what it is, but nicotine seems to be able to use it) +/
const int PrivilegedUsers		= 69;	/+ TODO : both (but the official server is switching to a new system) +/
const int HaveNoParent			= 71;	/+ TODO : U ? +/
const int ParentInactivityTimeout	= 86;	/+ TODO : S ? +/
const int SearchInactivityTimeout	= 87;	/+ TODO : S ? +/
const int MinParentsInCache		= 88;	/+ TODO : S ? +/
const int DistribAliveInterval		= 90;	/+ TODO : S ? +/
const int AddToPrivileged		= 91;
const int CheckPrivileges		= 92;
const int SearchRequest			= 93;	/+ TODO : U ? +/
const int NetInfo			= 102;	/+ TODO : S (list of [string user, int ip, int port], parents ?) +/
const int WishlistSearch		= 103;	/+ TODO : U (int ticket, string query)+/
const int WishlistInterval		= 104;	/+ TODO : S ? +/
const int SimilarUsers			= 110;	/+ TODO : S +/
const int ItemRecommendations		= 111;	/+ TODO : both - S : string item, int n, list of [string recommendation] - U : string item +/
const int ItemSimilarUsers		= 112;	/+ TODO : both - S : string item, int n, list of [string username] - U : string item +/
const int RoomTicker			= 113;
const int RoomTickerAdd			= 114;
const int RoomTickerRemove		= 115;
const int SetRoomTicker			= 116;
const int AddThingIHate			= 117;	/+ TODO : U +/
const int RemoveThingIHate		= 118;	/+ TODO : U +/
const int RoomSearch			= 120;	// Was "PrivilegedUsersZ" in nicotine ?
const int SendUploadSpeed		= 121;
const int UserPrivileges		= 122;
const int GivePrivileges		= 123;
const int ChangePassword		= 142;
const int CantConnectToPeer		= 1001;

const int ServerInfo			= 1789; // specific to Soulfind



// Peer Messages (we don't care but I thought it was nice to list them as well)
const int GetSharedFileList = 4;
const int SharedFileList = 5;
const int FileSearchResult = 9;
const int UserInfoRequest = 15;
const int UserInfoReply = 16;
const int FolderContentsRequest = 36;
const int FolderContentsResponse = 37;
const int TransferRequest = 40;
const int TransferResponse = 41;
const int PlaceholdUpload = 42;
const int QueueUpload = 43;
const int PlaceInQueue = 44;
const int UploadFailed = 46;
const int QueueFailed = 50;
const int PlaceInQueueRequest = 51;



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
		, 34 : "SendDownloadSpeed"
		, 35 : "SharedFoldersFiles"
		, 36 : "GetUserStats"
		, 40 : "QueuedDownloads"
		, 41 : "Relogged"
		, 51 : "AddThingILike"
		, 52 : "RemoveThingILike"
		, 54 : "GetRecommendations"
		, 56 : "GlobalRecommendations"
		, 60 : "PlaceInLineResponse"
		, 62 : "RoomAdded"
		, 63 : "RoomRemoved"
		, 64 : "RoomList"
		, 65 : "ExactFileSearch"
		, 66 : "AdminMessage"
		, 67 : "GlobalUserList"
		, 68 : "TunneledMessage"
		, 69 : "PrivilegedUsers"
		, 71 : "HaveNoParent"
		, 86 : "ParentInactivityTimeout"
		, 87 : "SearchInactivityTimeout"
		, 88 : "MinParentsInCache"
		, 90 : "DistribAliveInterval"
		, 91 : "AddToPrivileged"
		, 92 : "CheckPrivileges"
		, 93 : "SearchRequest"
		, 102 : "NetInfo"
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
		, 120 : "PrivilegedUsersZ"
		, 121 : "SendUploadSpeed"
		, 122 : "UserPrivileges"
		, 123 : "GivePrivileges"
		, 1001 : "CantConnectToPeer"
		, 1789 : "ServerInfo"];

