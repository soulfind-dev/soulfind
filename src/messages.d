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


module messages;

import defines;

private import std.bitmanip;
private import std.outbuffer : OutBuffer;
private import std.stdio : writeln;
private import std.format : format;
private import std.digest.md : md5Of;
private import std.conv : to;

private import message_codes;

class Message
	{	// Server message
	uint code;
	OutBuffer out_buf;

	ubyte[] toBytes () {return out_buf.toBytes ();}

	this (uint code)
		{
		out_buf = new OutBuffer ();
		this.code = code;
		writei (code);
		}

	void writei (uint i)
		{
		try {out_buf.write (i);}
		catch (Exception e) {writeln (e, " when trying to send an int : ", i);}
		}

	void writei (ulong i)
		{
		this.writei(cast(uint)i);
		}

	void writesi (int i)
		{
		try {out_buf.write (i);}
		catch (Exception e) {writeln (e, " when trying to send an int : ", i);}
		}
		
	void writeb (byte o)
		{
		try {out_buf.write (o);}
		catch (Exception e) {writeln (e, " when trying to send a byte : ", o);}
		}
	
	void writes (string s)
		{
		try
			{
			debug (msg) writeln("Sending string '", s, "', length ", s.length);
			writei (s.length);
			out_buf.write (s);
			}
		catch (Exception e) {writeln (e, " when trying to send a string : ", s, "(", s.length, ")");}
		}

	uint length;
	ubyte[] in_buf;

	this (ubyte[] in_buf)
		{
		this.in_buf = in_buf;
		}

	uint readi ()
		{ // read an int
		uint i;
		if (in_buf.length < uint.sizeof)
			{
			writeln ("message code ", code, ", length ", length, " not enough data trying to read an int");
			return i;
			}

		i = in_buf.read!(uint, Endian.littleEndian);
		return i;
		}

	uint readsi ()
		{ // read a signed int
		int i;
		if (in_buf.length < int.sizeof)
			{
			writeln ("message code ", code, ", length ", length, " not enough data trying to read a signed int");
			return i;
			}

		i = in_buf.read!(int, Endian.littleEndian);
		return i;
		}
	
	byte readb ()
		{ // read a byte
		byte i;
		if (in_buf.length < byte.sizeof)
			{
			writeln ("message code ", code, ", length ", length, " not enough data trying to read a byte");
			return i;
			}

		i = in_buf.read!(byte, Endian.littleEndian);
		return i;
		}
	
	string reads ()
		{ // read a string
		auto slen = readi ();
		if (slen > in_buf.length) slen = cast(uint) in_buf.length;
		auto str = cast(string) in_buf[0 .. slen];

		in_buf = in_buf[slen .. $];
		return str;
		}
	}

class ULogin : Message
	{		// New login
	string name;	// user name
	string pass;	// user password
	uint   vers;	// client version

	this (ubyte[] in_buf)
		{
		super (in_buf);

		name = reads ();
		pass = reads ();
		vers = readi ();
		}

	this (string name, string pass, uint vers)
		{
		super (Login);

		writes (name);
		writes (pass);
		writei (vers);
		}
	}

class USetWaitPort : Message
	{		// A client is telling us which port it is listening on
	uint port;	// port number
	this (ubyte[] in_buf)
		{
		super (in_buf);

		port = readi ();
		}
	
	this (uint port)
		{
		super (SetWaitPort);

		writei (port);
		}
	}
	
class UGetPeerAddress : Message
	{		// A client is asking for someone's address
	string user;	// name of the user to get the address of
	
	this (ubyte[] in_buf)
		{
		super (in_buf);

		user = reads ();
		}
	
	this (string user)
		{
		super (GetPeerAddress);

		writes (user);
		}
	}

class UWatchUser : Message
	{		// A client wants to watch a user
	string user;	// name of the user to watch

	this (ubyte[] in_buf)
		{
		super (in_buf);

		user = reads ();
		}
	
	this (string user)
		{
		super (WatchUser);

		writes (user);
		}
	}

class UUnwatchUser : Message
	{		// A client wants to unwatch a user
	string user;	// name of the user to unwatch

	this (ubyte[] in_buf)
		{
		super (in_buf);

		user = reads ();
		}
	
	this (string user)
		{
		super (UnwatchUser);

		writes (user);
		}
	}

class UGetUserStatus : Message
	{		// A client wants to know the status of someone
	string user;	// name of the user
	
	this (ubyte[] in_buf)
		{
		super (in_buf);

		user = reads ();
		}
	
	this (string user)
		{
		super (GetUserStatus);

		writes (user);
		}
	}

class USayChatroom : Message
	{		// A client wants to say something in a chatroom
	string room;	// room to talk in
	string message;	// what to say
	
	this (ubyte[] in_buf)
		{
		super (in_buf);
		
		room   = reads ();
		message = reads ();
		}
	
	this (string room, string message)
		{
		super (SayChatroom);

		writes (room);
		writes (message);
		}
	}

class UJoinRoom : Message
	{		// Client wants to join a room
	string room;	// room the client wants to join

	this (ubyte[] in_buf)
		{
		super (in_buf);

		room = reads ();
		}
	
	this (string room)
		{
		super (JoinRoom);

		writes (room);
		}
	}

class ULeaveRoom : Message
	{		// Client wants to leave a room
	string room;	// room the client wants to leave

	this (ubyte[] in_buf)
		{
		super (in_buf);

		room = reads ();
		}
	
	this (string room)
		{
		super (LeaveRoom);

		writes (room);
		}
	}

class UConnectToPeer : Message
	{		// Client cannot connect to another one and wants us to ask the other to connect to him
	uint token;	// connection token
	string user;	// user name
	string type;	// connection type ("F" if for a file transfers, "P" otherwise)

	this (ubyte[] in_buf)
		{
		super (in_buf);

		token = readi ();
		user  = reads ();
		type  = reads ();
		}
	
	this (uint token, string user, string type)
		{
		super (ConnectToPeer);

		writei (token);
		writes (user);
		writes (type);
		}
	}

class UMessageUser : Message
	{		// Client wants to send a private message
	string user;	// user to send the message to
	string message; // message content

	this (ubyte[] in_buf)
		{
		super (in_buf);

		user    = reads ();
		message = reads ();
		}
	
	this (string user, string message)
		{
		super (MessageUser);

		writes (user);
		writes (message);
		}
	}

class UMessageAcked : Message
	{		// Client acknowledges a private message
	uint id;	// message id
	
	this (ubyte[] in_buf)
		{
		super (in_buf);

		id = readi ();
		}
	
	this (uint id)
		{
		super (MessageAcked);

		writei (id);
		}
	}

class UFileSearch : Message
	{		// Client makes a filesearch
	uint token;	// search token
	string strng;	// search string

	this (ubyte[] in_buf)
		{
		super (in_buf);

		token = readi ();
		strng = reads ();
		}
	
	this (uint token, string string)
		{
		super (FileSearch);

		writei (token);
		writes (string);
		}
	}

class UWishlistSearch : Message
	{		// Client makes a wishlist search
	uint token;	// search token
	string strng;	// search string

	this (ubyte[] in_buf)
		{
		super (in_buf);

		token = readi ();
		strng = reads ();
		}

	this (uint token, string string)
		{
		super (WishlistSearch);

		writei (token);
		writes (string);
		}
	}

class USetStatus : Message
	{		// Client sets its status
	uint status;	// 0 : Offline - 1 : Away - 2 : Online

	this (ubyte[] in_buf)
		{
		super (in_buf);

		status = readi ();
		}
	
	this (uint status)
		{
		super (SetStatus);

		writei (status);
		}
	}

class USendUploadSpeed : Message
	{		// Client reports a transfer speed
	uint    speed;  // speed

	this (ubyte[] in_buf)
		{
		super (in_buf);

		speed = readi ();
		}

	this (string user, uint speed)
		{
		super (SendUploadSpeed);

		writei (speed);
		}
	}

class USharedFoldersFiles : Message
	{			// Client tells us how many files and folder it is sharing
	uint nb_folders;	// number of folders
	uint nb_files;		// number of files

	this (ubyte[] in_buf)
		{
		super (in_buf);

		nb_folders = readi ();
		nb_files   = readi ();
		}
	
	this (uint nb_folders, uint nb_files)
		{
		super (SharedFoldersFiles);

		writei (nb_folders);
		writei (nb_files);
		}
	}

class UGetUserStats : Message
	{		// Client wants the stats of someone
	string user;	// user name

	this (ubyte[] in_buf)
		{
		super (in_buf);

		user = reads ();
		}
	
	this (string user)
		{
		super (GetUserStats);

		writes (user);
		}
	}

class UUserSearch : Message
	{		// Client wants to send searches to his buddies...
	string user;	// user to send the search to (yes, there is one message to the server
			// sent for each buddy... how efficient [:kiki])
	uint   token;	// search token
	string query;	// search string

	this (ubyte[] in_buf)
		{
		super (in_buf);

		user  = reads ();
		token = readi ();
		query = reads ();
		}
	
	this (string user, uint token, string query)
		{
		super (RoomSearch);

		writes (user);
		writei (token);
		writes (query);
		}
	}

class UAddThingILike : Message
	{		// Client likes thing
	string thing;	// thing (s)he likes

	this (ubyte[] in_buf)
		{
		super (in_buf);

		thing = reads ();
		}
	
	this (string thing)
		{
		super (AddThingILike);

		writes (thing);
		}
	}

class URemoveThingILike : Message
	{		// Client doesn't like thing anymore
	string thing;	// the thing

	this (ubyte[] in_buf)
		{
		super (in_buf);

		thing = reads ();
		}
	
	this (string thing)
		{
		super (RemoveThingILike);

		writes (thing);
		}
	}

class UUserInterests : Message
	{		// A user wants to know this user's likes and hates
	string user;

	this (ubyte[] in_buf)
		{
		super (in_buf);

		user = reads ();
		}

	this (string user)
		{
		super (UserInterests);

		writes (user);
		}
	}

class UAddThingIHate : Message
	{		// Client hates thing
	string thing;	// thing (s)he likes

	this (ubyte[] in_buf)
		{
		super (in_buf);

		thing = reads ();
		}
	
	this (string thing)
		{
		super (AddThingIHate);

		writes (thing);
		}
	}

class URemoveThingIHate : Message
	{		// Client doesn't hate thing anymore
	string thing;	// the thing

	this (ubyte[] in_buf)
		{
		super (in_buf);

		thing = reads ();
		}
	
	this (string thing)
		{
		super (RemoveThingIHate);

		writes (thing);
		}
	}

class UGetItemRecommendations : Message
	{		// An user wants to get recommendations
			// for a particular item
	string item;

	this (ubyte[] in_buf)
		{
		super (in_buf);

		item = reads ();
		}
	
	this (string item)
		{
		super (ItemRecommendations);

		writes (item);
		}
	}

class UItemSimilarUsers : Message
	{		// An user wants to know who
			// likes a particular item
	string item;

	this (ubyte[] in_buf)
		{
		super (in_buf);

		item = reads ();
		}
	
	this (string item)
		{
		super (ItemSimilarUsers);

		writes (item);
		}
	}

class USetRoomTicker : Message
	{		// Client sets a new ticker for a room
	string room;	// room name
	string tick;	// ticker content

	this (ubyte[] in_buf)
		{
		super (in_buf);

		room = reads ();
		tick = reads ();
		}
	
	this (string room, string tick)
		{
		super (SetRoomTicker);

		writes (room);
		writes (tick);
		}
	}

class URoomSearch : Message
	{		// Client wants to send a search to all the users in the room
	string room;	// room name
	uint   token;	// search token
	string query;	// search string

	this (ubyte[] in_buf)
		{
		super (in_buf);

		room  = reads ();
		token = readi ();
		query = reads ();
		}
	
	this (string room, uint token, string query)
		{
		super (RoomSearch);

		writes (room);
		writei (token);
		writes (query);
		}
	}

class UUserPrivileged : Message
        {               // Client wants to know if someone has privileges
        string user;    // user name

        this (ubyte[] buf)
                {
                super (buf);
        
                user = reads ();
                }
	
	this (string user)
		{
		super (UserPrivileged);

		writes (user);
		}
        }

class UAdminMessage : Message
	{		// An admin sends a message
	string mesg;	// the message

	this (ubyte[] in_buf)
		{
		super (in_buf);

		mesg = reads ();
		}
	
	this (string mesg)
		{
		super (AdminMessage);

		writes (mesg);
		}
	}

class UGivePrivileges : Message
	{		// Client wants to give privileges to somebody else
	string user;	// user to give the privileges to
	uint   time;	// time to give

	this (ubyte[] in_buf)
		{
		super (in_buf);

		user = reads ();
		time = readi ();
		}
	
	this (string user, uint time)
		{
		super (GivePrivileges);

		writes (user);
		writei (time);
		}
	}

class UChangePassword : Message
	{		// A user wants to change their password
	string password;

	this (ubyte[] in_buf)
		{
		super (in_buf);

		password = reads ();
		}

	this (string password)
		{
		super (ChangePassword);

		writes (password);
		}
	}

class UMessageUsers : Message
	{			// Client wants to send private messages
	string[] users;		// users to send the message to
	string   message;	// message content

	this (ubyte[] in_buf)
		{
		super (in_buf);

		foreach (i ; 0 .. readi ()) users ~= reads ();
		message = reads ();
		}

	this (string[] users, string message)
		{
		super (MessageUsers);

		writei (users.length);
		foreach (user ; users) writes (user);

		writes (message);
		}
	}

class UCantConnectToPeer : Message
	{		// Client tells us he couldn't connect to someone
	uint token;	// message token
	string user;	// user who requested the connection

	this (ubyte[] in_buf)
		{
		super (in_buf);

		token = readi ();
		user  = reads ();
		}
	
	this (uint token, string user)
		{
		super (CantConnectToPeer);

		writei (token);
		writes (user);
		}
	}

class SLogin : Message
	{	// If the login succeeded send the MOTD and the external IP of the client
		// if not, send the error message
	this (byte success, string mesg, uint addr = 0, string password = null, byte supporter = false)
		{
		super (Login);
		
		writeb (success);	// success (0 = fail / 1 = success)
		writes (mesg);		// server message
		if (success)
			{
			writei (addr);	// external IP address of the client
			ubyte[16] digest;
			digest = md5Of (password);
			string sum;
			foreach (u ; digest)
				sum ~= format ("%02x", u);
			writes (sum);
			writeb (supporter);
			}
		}
		
	byte   success;
	string mesg;
	uint   addr;
	
	this (ubyte[] in_buf)
		{
		super (in_buf);

		success = readb ();
		mesg    = reads ();
		if (success) addr = readi ();
		}
	}

class SGetPeerAddress : Message
	{	// Send the address and port of user user
	this (string username, uint address, uint port, uint unknown = 0, uint obfuscated_port = 0)
		{
		super (GetPeerAddress);
		
		writes (username);	// username the address belongs to
		writei (address);	// IP address
		writei (port);		// port number
		writei (unknown);
		writei (obfuscated_port);
		}
	
	string username;
	uint   address;
	uint   port;
	uint   unknown;
	uint   obfuscated_port;

	this (ubyte[] in_buf)
		{
		super (in_buf);

		username        = reads ();
		address         = readi ();
		port            = readi ();
		unknown         = readi ();
		obfuscated_port = readi();
		}
	}

class SWatchUser : Message
	{	// Tell a client if a user exists and potential stats
	this (string user, byte exists, uint status, uint speed, uint upload_number, uint something, uint shared_files, uint shared_folders, string country_code)
		{
		super (WatchUser);

		writes (user);   // username
		writeb (exists); // whether the user exists or not
		if (!exists) return;

		writei (status);		// status
		writei (speed);			// speed (in B/s)
		writei (upload_number);		// upload number
		writei (something);		// something ?
		writei (shared_files);		// shared files
		writei (shared_folders);	// shared folders
		if (status > 0) writes (country_code);  // country code
		}
	
	string user;
	byte   exists;
	uint   status;
	uint   speed;
	uint   upload_number;
	uint   something;
	uint   shared_files;
	uint   shared_folders;
	string country_code;

	this (ubyte[] in_buf)
		{
		super (in_buf);

		user            = reads ();
		exists          = readb ();
		if (!exists) return;

		status          = readi ();
		speed           = readi ();
		upload_number 	= readi ();
		something       = readi ();
		shared_files    = readi ();
		shared_folders  = readi ();
		if (status > 0) country_code = reads();
		}
	}

class SGetUserStatus : Message
	{	// Send the status of user user
	this (string username, uint status, byte privileged)
		{
		super (GetUserStatus);

		writes (username);	// username
		writei (status);	// user status (see the class User)
		writeb (privileged);    // is user privileged
		}

	string username;
	uint   status;
	byte   privileged;

	this (ubyte[] in_buf)
		{
		super (in_buf);

		username   = reads ();
		status     = readi ();
		privileged = readb ();
		}
	}

class SSayChatroom : Message
	{	// User user has said mesg in room room
	this (string room, string user, string mesg)
		{
		super (SayChatroom);

		writes (room); // room the message comes from
		writes (user); // the user who said it
		writes (mesg); // what (s)he said
		}
	
	string room;
	string user;
	string mesg;

	this (ubyte[] in_buf)
		{
		super (in_buf);

		room = reads ();
		user = reads ();
		mesg = reads ();
		}
	}

class SRoomList : Message
	{	// Send the list of rooms
	this (ulong[string] rooms)
		{
		super (RoomList);
		
		writei (rooms.length);	// number of room names we will send
		foreach (room ; rooms.keys) writes (room);
		
		writei (rooms.length);	// number of user counts
		foreach (users ; rooms.values) writei (users);

		writei (0);	// number of owned private rooms (unimplemented)
		writei (0);	// number of owned private rooms (unimplemented)
		writei (0);	// number of other private rooms (unimplemented)
		writei (0);	// number of other private rooms (unimplemented)
		writei (0);	// number of operated private rooms (unimplemented)
		}
	
	uint[string] rooms;

	this (ubyte[] in_buf)
		{
		super (in_buf);

		string[] room_names;

		foreach (i ; 0 .. readi ()) room_names[i] = reads ();
		foreach (i ; 0 .. readi ()) rooms[room_names[i]] = readi ();
		}
	}

class SJoinRoom : Message
	{	// Give info on the room to a client who just joined it
	this (string room, string[] usernames, uint[string] statuses, uint[string] speeds, uint[string] upload_numbers, uint[string] somethings, uint[string] shared_files, uint[string] shared_folders, uint[string] slots_full, string[string] country_codes)
		{
		super (JoinRoom);

		writes (room);	// the room the user just joined
		auto n = usernames.length;

		writei (n);	// number of user names we will send
		foreach (username ; usernames) writes (username);
		
		writei (n);	// number of user statuses we will send
		foreach (username ; usernames) writei (statuses[username]);
		
		writei (n);	// number of stats we will send
		foreach (username ; usernames)
			{
			writei (speeds          [username]);	// speed of each user
			writei (upload_numbers	[username]);	// number of files uploaded ever
			writei (somethings      [username]);	// something ? 1789 is a good number
			writei (shared_files    [username]);	// nb of shared files
			writei (shared_folders  [username]);	// nb of shared folders
			}
		
		writei (n);	// number of slots records we will send...
		foreach (username ; usernames) writei (slots_full[username]);

		writei (n);	// number of country codes we will send
		foreach (username ; usernames) writes (country_codes[username]);
		}
	
	string         room;
	string[]       usernames;
	uint[string]   statuses;
	uint[string]   speeds;
	uint[string]   upload_numbers;
	uint[string]   somethings;
	uint[string]   shared_files;
	uint[string]   shared_folders;
	uint[string]   slots_full;
	string[string] country_codes;
	
	this (ubyte[] in_buf)
		{
		super (in_buf);

		room = reads ();

		foreach (i ; 0 .. readi ()) usernames[i] = reads ();
		foreach (i ; 0 .. readi ()) statuses[usernames[i]] = readi ();
		foreach (i ; 0 .. readi ())
			{
			speeds          [usernames[i]] = readi ();
			upload_numbers	[usernames[i]] = readi ();
			somethings      [usernames[i]] = readi ();
			shared_files    [usernames[i]] = readi ();
			shared_folders  [usernames[i]] = readi ();
			}
		foreach (i ; 0 .. readi ()) slots_full[usernames[i]] = readi ();
		foreach (i ; 0 .. readi ()) country_codes[usernames[i]] = reads ();
		}
	}
	
class SLeaveRoom : Message
	{	// Tell a client he has to leave a room
	this (string room)
		{
		super (LeaveRoom);

		writes (room);	// the room the user left
		}
	
	string room;

	this (ubyte[] in_buf)
		{
		super (in_buf);

		room = reads ();
		}
	}

class SUserJoinedRoom : Message
	{	// User user has joined the room room
	this (string room, string username, uint status, uint speed, uint upload_number, uint something, uint shared_files, uint shared_folders, uint slots_full, string country_code)
		{
		super (UserJoinedRoom);

		writes (room);			// the room an user joined
		writes (username);		// name of the user who joined
		writei (status);		// status
		writei (speed);			// speed
		writei (upload_number);		// upload number
		writei (something);		// something ?
		writei (shared_files);		// shared files
		writei (shared_folders);	// shared folders
		writei (slots_full);		// slots full
		writes (country_code);		// country code
		}
	
	string room;
	string username;
	uint   status;
	uint   speed;
	uint   upload_number;
	uint   something;
	uint   shared_files;
	uint   shared_folders;
	uint   slots_full;
	string country_code;

	this (ubyte[] in_buf)
		{
		super (in_buf);

		room		= reads ();
		username        = reads ();
		status          = readi ();
		speed           = readi ();
		upload_number 	= readi ();
		something       = readi ();
		shared_files    = readi ();
		shared_folders  = readi ();
		slots_full      = readi ();
		country_code    = reads ();
		}
	}

class SUserLeftRoom : Message
	{	// User user has left the room room
	this (string username, string room)
		{
		super (UserLeftRoom);

		writes (room);		// the room an user left
		writes (username);	// name of the user who left
		}

	string room;
	string username;

	this (ubyte[] in_buf)
		{
		super (in_buf);

		room     = reads ();
		username = reads ();
		}
	}

class SConnectToPeer : Message
	{	// Ask a peer to connect back to user
	this (string username, string type, uint address, uint port, uint token, byte privileged, uint unknown = 0, uint obfuscated_port = 0)
		{
		super (ConnectToPeer);

		writes (username);	// username of the peer to connect to
		writes (type);		// type of the connection ("F" if it's for a filetransfer, "P" otherwise)
		writei (address);	// IP address of the peer to connect to
		writei (port);		// port to use
		writei (token);		// message token
		writeb (privileged);    // is user privileged
		writei (unknown);
		writei (obfuscated_port);
		}
	
	string username;
	string type;
	uint   address;
	uint   port;
	uint   token;
	byte   privileged;
	uint   unknown;
	uint   obfuscated_port;

	this (ubyte[] in_buf)
		{
		super (in_buf);

		username        = reads ();
		type            = reads ();
		address         = readi ();
		port            = readi ();
		token           = readi ();
		privileged      = readb ();
		unknown         = readi ();
		obfuscated_port = readi ();
		}
	}

class SMessageUser : Message
	{	// Send the PM
	this (uint id, uint timestamp, string from, string content, byte new_message)
		{
		super (MessageUser);

		writei (id);		// message id
		writei (timestamp);	// timestamp (seconds since 1970)
		writes (from);		// sender
		writes (content);	// message content
		writeb (new_message);
		}
	
	uint   id;
	uint   timestamp;
	string from;
	string content;
	byte   new_message;

	this (ubyte[] in_buf)
		{
		super (in_buf);

		id          = readi ();
		timestamp   = readi ();
		from        = reads ();
		content     = reads ();
		new_message = readb ();
		}
	}

class SFileSearch : Message
	{	// Send a filesearch
	this (string username, uint token, string text)
		{
		super (FileSearch);

		writes (username);	// username of the one who is doing the search
		writei (token);		// search token
		writes (text);		// search string
		}
	
	string username;
	uint   token;
	string text;

	this (ubyte[] in_buf)
		{
		super (in_buf);

		username = reads ();
		token    = readi ();
		text     = reads ();
		}
	}

class SGetUserStats : Message
	{	// Send the stats of user user
	this (string username, uint speed, uint upload_number, uint something, uint shared_files, uint shared_folders)
		{
		super (GetUserStats);

		writes (username);		// user name
		writei (speed);			// speed (in B/s)
		writei (upload_number);		// upload number
		writei (something);		// something ?
		writei (shared_files);		// shared files
		writei (shared_folders);	// shared folders
		}
	
	string username;
	uint   speed;
	uint   upload_number;
	uint   something;
	uint   shared_files;
	uint   shared_folders;

	this (ubyte[] in_buf)
		{
		super (in_buf);

		username        = reads ();
		speed           = readi ();
		upload_number 	= readi ();
		something       = readi ();
		shared_files    = readi ();
		shared_folders  = readi ();
		}
	}

class SGetRecommendations : Message
	{	// Send the list of recommendations for this client
	this (uint[string] list)	// list[artist] = level
		{
		super (GetRecommendations);

		writei (list.length);	// if you can't guess, stop reading now !
		foreach (artist, level ; list)
			{
			writes (artist);	// artist name
			writesi (level);	// « level » of recommendation
			}
		}
	
	uint[string] list;

	this (ubyte[] in_buf)
		{
		super (in_buf);

		foreach (i ; 0 .. readi ())
			{
			auto artist = reads ();
			auto level  = readsi ();

			list[artist] = level;
			}
		}
	}

class SGetGlobalRecommendations : Message
	{	// Send the list of global recommendations
		// the code is exactly the same as for GetRecommendations.
	this (uint[string] list)
		{
		super (GlobalRecommendations);

		writei (list.length);	// if you can't guess, you should have stopped several lines ago...
		foreach (artist, level ; list)
			{
			writes (artist);	// artist name
			writesi (level);	// « level » of recommendation
			}
		}
	
	int[string] list;

	this (ubyte[] in_buf)
		{
		super (in_buf);

		foreach (i ; 0 .. readi ())
			{
			auto artist = reads ();
			auto level  = readsi ();

			list[artist] = level;
			}
		}
	}

class SUserInterests : Message
	{	// Send a user's likes and hates
	this (string user, string[string] likes, string[string] hates)
		{
		super (UserInterests);

		writes (user);

		writei (likes.length);
		foreach (thing ; likes) writes (thing);

		writei (hates.length);
		foreach (thing ; hates) writes (thing);
		}

	string         user;
	string[string] likes;
	string[string] hates;

	this (ubyte[] in_buf)
		{
		super (in_buf);

		user = reads ();

		foreach (i ; 0 .. readi ())
			{
			auto thing = reads ();
			likes[thing] = thing;
			}

		foreach (i ; 0 .. readi ())
			{
			auto thing = reads ();
			hates[thing] = thing;
			}
		}
	}

class SRelogged : Message
	{	// Tell a client he has just logged from elsewhere before disconnecting it
	this ()
		{
		super (Relogged);
		}
	}

class SUserSearch : Message
	{	// User user has sent a buddy search to a client
	this (string user, uint token, string query)
		{
		super (UserSearch);

		writes (user);		// name of the user who sent the search
		writei (token);		// search token
		writes (query);		// search string
		}
	
	string user;
	uint   token;
	string query;

	this (ubyte[] in_buf)
		{
		super (in_buf);

		user   = reads ();
		token  = readi ();
		query  = reads ();
		}
	}

class SAdminMessage : Message
	{	// Send an admin message
	this (string message)
		{
		super (AdminMessage);

		writes (message);	// the message
		}

	string message;

	this (ubyte[] in_buf)
		{
		super (in_buf);

		message = reads ();
		}
	}

class SCheckPrivileges : Message
	{	// Tell a client how many seconds of privileges he has left
	this (uint time)
		{
		super (CheckPrivileges);

		writei (time);		// time left
		}

	uint time;

	this (ubyte[] in_buf)
		{
		super (in_buf);

		time = readi ();
		}
	}

class SWishlistInterval	: Message
	{
	this (uint interval)
		{
		super (WishlistInterval);

		writei (interval);	// interval in seconds for searches
		}

	uint interval;

	this (ubyte[] in_buf)
		{
		super (in_buf);

		interval = readi ();
		}
	}

class SSimilarUsers : Message
	{	// Send a list of users with similar tastes
	this (uint[string] list)
		{
		super (SimilarUsers);

		writei (list.length);
		foreach (user, weight ; list)
			{
			writes  (user);
			writesi (weight);
			}
		}

	uint[string] list;

	this (ubyte[] in_buf)
		{
		super (in_buf);

		foreach (i ; 0 .. readi ())
			{
			auto user   = reads ();
			auto weight = readsi ();

			list[user] = weight;
			}
		}
	}

class SGetItemRecommendations : Message
	{	// Send a list of recommendations for a particular item
	this (string item, uint[string] list)
		{
		super (ItemRecommendations);

		writes (item);
		writei (list.length);

		foreach (recommendation, weight ; list)
			{
			writes  (recommendation);
			writesi (weight);
			}
		}

	uint[string] list;

	this (ubyte[] in_buf)
		{
		super (in_buf);

		foreach (i ; 0 .. readi ())
			{
			auto recommendation = reads ();
			auto weight         = readsi ();

			list[recommendation] = weight;
			}
		}
	}

class SItemSimilarUsers : Message
	{	// Send a list of users who like an item
	this (string item, string[] list)
		{
		super (ItemSimilarUsers);

		writes (item);
		writei (list.length);
		foreach (user ; list) writes (user);
		}

	string[] list;

	this (ubyte[] in_buf)
		{
		super (in_buf);

		foreach (i ; 0 .. readi ()) list[i] = reads ();
		}
	}

class SRoomTicker : Message
	{	// Send the ticker of room room
	this (string room, string[string] tickers)
		{
		super (RoomTicker);

		writes (room);			// name of the room
		writei (tickers.length);	// number of tickers
		foreach (string user, string ticker ; tickers)
			{
			writes (user);		// user name
			writes (ticker);	// ticker content
			}
		}

	string room;
	string[string] tickers;

	this (ubyte[] in_buf)
		{
		super (in_buf);
		
		room = reads ();

		foreach (i ; 0 .. readi ())
			{
			auto user   = reads ();
			auto ticker = reads ();

			tickers[user] = ticker;
			}
		}
	}

class SRoomTickerAdd : Message
	{	// A ticker has been added to the room room by the user user
	this (string room, string user, string ticker)
		{
		super (RoomTickerAdd);

		writes (room);		// name of the room
		writes (user);		// user name
		writes (ticker);	// ticker content
		}
	
	string room;
	string user;
	string ticker;

	this (ubyte[] in_buf)
		{
		super (in_buf);

		room   = reads ();
		user   = reads ();
		ticker = reads ();
		}
	}

class SRoomTickerRemove : Message
	{	// User user has removed his ticker from the room room
	this (string room, string user)
		{
		super (RoomTickerRemove);

		writes (room);		// name of the room
		writes (user);		// user name
		}
	
	string room;
	string user;

	this (ubyte[] in_buf)
		{
		super (in_buf);

		room   = reads ();
		user   = reads ();
		}
	}

class SRoomSearch : Message
	{	// User user has sent a room search
	this (string user, uint token, string query)
		{
		super (RoomSearch);

		writes (user);		// name of the user who sent the search
		writei (token);		// search token
		writes (query);		// search string
		}
	
	string user;
	uint   token;
	string query;

	this (ubyte[] in_buf)
		{
		super (in_buf);

		user   = reads ();
		token  = readi ();
		query  = reads ();
		}
	}

class SUserPrivileged : Message
	{	// Send the privileges status of user
	this (string username, byte privileged)
		{
		super (UserPrivileged);

		writes (username);	// user name
		writeb (privileged);	// user privileged
		}

	string username;
	byte   privileged;

	this (ubyte[] in_buf)
		{
		super (in_buf);

		username   = reads ();
		privileged = readb ();
		}
	}

class SChangePassword : Message
	{	// Send the new password of a user
	this (string password)
		{
		super (ChangePassword);

		writes (password);	// user's password
		}

	string password;

	this (ubyte[] in_buf)
		{
		super (in_buf);

		password = reads ();
		}
	}

class SGlobalRoomMessage : Message
	{	// User user has said mesg in room room
	this (string room, string user, string mesg)
		{
		super (GlobalRoomMessage);

		writes (room); // room the message comes from
		writes (user); // the user who said it
		writes (mesg); // what (s)he said
		}

	string room;
	string user;
	string mesg;

	this (ubyte[] in_buf)
		{
		super (in_buf);

		room = reads ();
		user = reads ();
		mesg = reads ();
		}
	}

class SCantConnectToPeer : Message
	{	// A connection couldn't be established for some message
	this (uint token)
		{
		super (CantConnectToPeer);

		writei (token);	// token of the message
		}

	uint token;

	this (ubyte[] in_buf)
		{
		super (in_buf);

		token = readi ();
		}
	}

class SServerInfo : Message
	{	// Specific to Soulfind, info about the server
		// uint   : number of fields
		// string : field name
		// string : field value
		// string : field name
		// ...
	this (string[string] info)
		{
		super (ServerInfo);
		
		writei (info.length);	// number of fields being sent

		foreach (field, value ; info)
			{
			writes (field);
			writes (value);
			}
		}

	string[string] info;

	this (ubyte[] in_buf)
		{
		super (in_buf);

		foreach (i ; 0 .. readi ())
			{
			auto field = reads ();
			auto value = reads ();

			info[field]  = value;
			}
		}
	}
