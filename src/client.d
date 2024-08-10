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


module client;

import defines;

private import messages;
private import server;
private import room;
private import pm;
private import db;
private import message_codes;

private import std.bitmanip;
private import std.conv : to;
private import std.outbuffer : OutBuffer;
private import std.socket : Socket, InternetAddress;
private import std.stdio : write, writeln;

private import std.system : Endian, endian;
private import core.stdc.time : time;

class User
	{
	// some attributes...
	string	username;
	string	password;
	uint	cversion;

	uint	address;
	uint	port;

	bool	admin;

	uint	privileges;		// in seconds
	ulong	last_checked_privileges;// privileges length is counted from this date
	uint	speed;			// received in B/s, sent in kB/s
	uint	upload_number;
	uint	something;
	uint	shared_files;
	uint	shared_folders;
	uint	slots_full;
	string  country_code;

	uint	status;			// 0,1,2
	bool	loggedin;
	ulong	connected_at;		// in seconds
	ulong	last_message_date;	// in seconds

	string[string]	things_he_likes;
	string[string]	things_he_hates;

	Socket	socket;
	Server	server;

	ubyte[] in_buf;
	auto    in_message_size = -1;
	ubyte[] out_buf;
	auto    msg_size_buf = new OutBuffer();

	// constructors
	this (Server serv, Socket s, uint address)
		{
		this.server            = serv;
		this.socket            = s;
		this.address           = address;
		this.loggedin          = false;
		this.admin             = false;
		this.connected_at      = time(null);
		this.last_message_date = time(null);
		}
	
	this () {}
	
	// misc
	string list_joined_rooms ()
		{
		string list;
		foreach (Room r ; joined_rooms ())
			{
			list ~= r.name ~ " ";
			}
		return list;
		}
	
	string print_privileges ()
		{
		return this.privileges > 0 ? print_length(this.privileges) : "None";
		}

	void calc_speed (uint speed)
		{
		if (this.upload_number == 0)
			{
			this.upload_number = 1;
			this.speed = speed;
			}
		else
			{
			this.speed = (this.speed*upload_number + speed)/(upload_number + 1);
			this.upload_number++;
			}

		send_to_watching (new SGetUserStats (this.username, this.speed, this.upload_number, this.something, this.shared_files, this.shared_folders));

		server.db.user_update_field (this.username, "speed", this.speed);
		}
	
	void set_shared_files (uint files)
		{
		this.shared_files = files;
		server.db.user_update_field (this.username, "files", this.shared_files);
		}
	
	void set_shared_folders (uint folders)
		{
		this.shared_folders = folders;
		server.db.user_update_field (this.username, "folders", this.shared_folders);
		}
	
	void send_pm (PM pm, bool new_message)
		{
		this.send_message (new SMessageUser (pm.id, cast(uint) pm.timestamp, pm.from, pm.content, new_message));
		}

	void change_password (string password)
		{
		this.password = password;
		server.db.user_update_field (this.username, "password", this.password);
		}

	// privileges
	void add_privileges (uint privileges)
		{
		debug (user) writeln ("Adding ", privileges, " seconds of privileges to user ", username);
		this.privileges += privileges;
		debug (user) writeln ("Now ", this.privileges, " seconds.");
		server.db.user_update_field (this.username, "privileges", this.privileges);
		send_message (new SCheckPrivileges (this.privileges));
		}
	
	void remove_privileges (uint privileges)
		{
		debug (user) writeln ("Removing ", privileges, " seconds of privileges to user ", username);
		if (privileges > this.privileges)
			this.privileges = 0;
		else
			this.privileges -= privileges;
		debug (user) writeln ("Now ", this.privileges, " seconds.");
		server.db.user_update_field (this.username, "privileges", this.privileges);
		send_message (new SCheckPrivileges (this.privileges));
		}
	
	void update_privileges ()
		{
		ulong now = time(null);
		ulong difference = now - this.last_checked_privileges;
		if (this.last_checked_privileges > now) difference = 0;
		if (this.privileges < difference)
			this.privileges = 0;
		else
			this.privileges -= now - this.last_checked_privileges;
		this.last_checked_privileges = now;
		server.db.user_update_field (this.username, "privileges", this.privileges);
		}
	
	uint get_privileges ()
		{
		update_privileges ();
		return this.privileges;
		}
	
	// things I like
	void add_thing_he_likes (string thing)
		{
		if (!this.likes (thing))
			{
			things_he_likes[thing] = thing;
			}
		}
	
	void del_thing_he_likes (string thing)
		{
		if (this.likes (thing))
			{
			things_he_likes.remove (thing);
			}
		}
	
	void add_thing_he_hates (string thing)
		{
		if (!this.hates (thing))
			{
			things_he_hates[thing] = thing;
			}
		}
	
	void del_thing_he_hates (string thing)
		{
		if (this.hates (thing))
			{
			things_he_hates.remove (thing);
			}
		}
	
	bool likes (string thing)
		{
		return (!(!(thing in things_he_likes)));
		}
	
	bool hates (string thing)
		{
		return (!(!(thing in things_he_hates)));
		}
	
	uint[string] get_recommendations ()
		{
		uint[string] list;

		foreach (User u ; server.users ())
			{
			if (this is u) continue;
			int weight = 0;
			foreach (string thing ; this.things_he_likes)
				{
				if (u.likes (thing))
					{
					weight++;
					}
				if (u.hates (thing) && weight > 0)
					{
					weight--;
					}
				}
			foreach (string thing ; things_he_hates)
				{
				if (u.hates (thing))
					{
					weight++;
					}
				if (u.likes (thing) && weight > 0)
					{
					weight--;
					}
				}
			if (weight > 0) foreach (string thing ; u.things_he_likes)
				{
				list[thing] += weight;
				}
			}

		return list;
		}
	
	uint[string] get_similar_users ()
		{
		uint[string] users;

		foreach (User u ; server.users ())
			{
			if (this is u) continue;
			int weight = 0;
			foreach (string thing ; things_he_likes)
				{
				if (u.likes (thing))
					{
					weight++;
					}
				if (u.hates (thing) && weight > 0)
					{
					weight--;
					}
				}
			foreach (string thing ; things_he_hates)
				{
				if (u.hates (thing))
					{
					weight++;
					}
				if (u.likes (thing) && weight > 0)
					{
					weight--;
					}
				}
			if (weight > 0) users[u.username] = weight;
			}

		return users;
		}
	
	uint[string] get_item_recommendations (string item)
		{
		uint[string] list;

		foreach (User u ; server.users ())
			{
			if (this is u) continue;
			int weight = 0;
			if (u.likes (item))
				{
				weight++;
				}
			if (u.hates (item) && weight > 0)
				{
				weight--;
				}

			if (weight > 0) foreach (string thing ; u.things_he_likes)
				{
				list[thing] += weight;
				}
			}

		return list;
		}
	
	string[] get_item_similar_users (string item)
		{
		string[] list;

		foreach (User u ; server.users ())
			{
			if (this is u) continue;
			if (u.likes (item))
				{
				list ~= u.username;
				}
			}

		return list;
		}
	
	// watching
	string list_watching ()
		{
		string list;

		foreach (User user ; watching ())
			{
			list ~= user.username ~ " ";
			}
		return list;
		}
	
	string list_watched_by ()
		{
		string list;
		foreach (User user ; watched_by ())
			{
			list ~= user.username ~ " ";
			}
		return list;
		}
	
	void send_to_watching (Message m)
		{
		debug (msg) write ("Sending message code ", blue, message_name[m.code], black, " (", m.code, ") to ");
		if (this.watched_by().length == 0)
			{
			debug (msg) write ("nobody");
			}
		else foreach (User user ; this.watched_by ())
			{
			debug (msg) writeln (user.username);
			user.send_message (m);
			}
		debug (msg) writeln ();
		}
	
	void set_status (uint status)
		{
		this.status = status;
		this.send_to_watching (new SGetUserStatus (this.username, this.status, this.privileges > 0));
		}
	
	
	// watchlist, etc
	string[string] watch_list;	// watch_list[username] = username
	
	void watch (string username)
		{
		watch_list[username] = username;
		}
	
	void unwatch (string username)
		{
		if (username in watch_list)
			{
			watch_list.remove (username);
			}
		}
	
	User[] watched_by ()
		{
		User[] list;
		foreach (User user ; server.users ())
			{
			if (user.watching().length > 0 && user !is this && this.username in user.watching ())
				list ~= user;
			}
		return list;
		}
	
	User[string] watching ()
		{
		User[string] list;
		if (watch_list.length > 0) foreach (string username ; watch_list)
			{
			if (server.find_user (username)) list[username] = server.get_user (username);
			}
		if (joined_rooms().length > 0) foreach (Room room ; joined_rooms ())
			{
			foreach (User user ; room.users ())
				{
				list[user.username] = user;
				}
			}
		return list;
		}
	
	// rooms, etc
	string[string] room_list;	// room_list[roomname] = roomname

	void join_room (string roomname)
		{
		room_list[roomname] = roomname;
		}
	
	 void leave_room (string roomname)
		{
		if (roomname in room_list) room_list.remove (roomname);
		}
	
	Room[] joined_rooms ()
		{
		Room[] tmp;
		if (room_list.length > 0) foreach (string roomname ; room_list)
			{
			if (Room.find_room (roomname)) tmp ~= Room.get_room (roomname);
			}
		return tmp;
		}
	
	// messages
	bool send_buffer ()
		{
		auto send_len = socket.send (out_buf);
		if (send_len == Socket.ERROR) return false;
		out_buf = out_buf[send_len .. out_buf.length];
		return true;
		}

	void send_message (Message m)
		{
		auto msg_buf = m.toBytes ();
		msg_size_buf.write(cast(uint) msg_buf.length);
		out_buf ~= msg_size_buf.toBytes ();
		out_buf ~= msg_buf;
		msg_size_buf.clear ();

		debug (msg) writeln ("Sent ", out_buf.length, " bytes to user " ~ blue, this.username, black);
		debug (msg) writeln ("Sending message code ", blue, message_name[m.code], black, " (", m.code, ") to ", this.username);
		}

	bool recv_buffer ()
		{
		ubyte[max_message_size] receive_buf;
		auto receive_len = socket.receive(receive_buf);
		if (receive_len == Socket.ERROR || receive_len == 0) return false;

		last_message_date = time(null);
		in_buf ~= receive_buf[0 .. receive_len];

		while (recv_message ())
			{
			// disconnect the user if message is incorrect/bogus
			if (in_message_size < 0 || in_message_size > max_message_size) return false;
			if (!proc_message ()) return false;
			}

		return true;
		}

	bool recv_message ()
		{
		if (in_message_size == -1)
			{
			if (in_buf.length < uint.sizeof) return false;
			in_message_size = in_buf.read!(uint, Endian.littleEndian);
			}

		return in_buf.length >= in_message_size;
		}

	bool proc_message ()
		{
		auto msg_buf = in_buf[0 .. in_message_size];
		auto code = msg_buf.read!(uint, Endian.littleEndian);

		in_buf = in_buf[in_message_size .. in_buf.length];
		in_message_size = -1;

		debug (msg) if (code != 32 && code < message_name.length) writeln ("Received message ", blue, message_name[code], black, " (code ", blue, code, black ~ ")");

		if (!loggedin && code != Login) return false;
		if (loggedin  && code == Login) return true;

		switch (code)
			{
			case Login:
				write ("User logging in : ");
				ULogin o = new ULogin (msg_buf);
				string error;

				if (!server.check_login (o.name, o.pass, o.vers, error))
					{
					writeln (o.name, ": Impossible to login (", error, ")");
					send_message (new SLogin (false, error));
					return false;
					}
				else if (server.find_user (o.name) && server.get_user (o.name).loggedin)
					{
					writeln (o.name, ": Already logged in");
					User u = server.get_user (o.name);
					u.send_message (new SRelogged ());
					u.exit ();
					}

				writeln (blue, o.name, black ~ ", version ", o.vers);
				return (this.login (o));
				break;
			case SetWaitPort:
				USetWaitPort o = new USetWaitPort (msg_buf);
				this.port = o.port;
				break;
			case GetPeerAddress:
				UGetPeerAddress o = new UGetPeerAddress (msg_buf);
				
				if (server.find_user (o.user))
					{
					User user = server.get_user (o.user);
					send_message (new SGetPeerAddress (user.username, user.address, user.port));
					}
				else
					{
					send_message (new SGetPeerAddress (o.user, 0, 0));
					}
				break;
			case WatchUser:
				UWatchUser o = new UWatchUser (msg_buf);
				bool exists = true;
				uint status, speed, upload_number, something, shared_files, shared_folders;
				string country_code;
				
				if (server.db.user_exists (o.user))
					{
					User u = server.get_user (o.user);
					if (u)
						{
						status = u.status;
						country_code = u.country_code;
						}
					else
						{
						status = Status.offline;
						country_code = "";
					}

					server.db.get_user (o.user, speed, upload_number, something, shared_files, shared_folders);
					send_message (new SWatchUser (o.user, exists, status, speed, upload_number, something, shared_files, shared_folders, country_code));
					watch (o.user);
					}
				else if (o.user == server_user)
					{
					status = Status.online;
					}
				else
					{
					exists = false;
					}

				send_message (new SWatchUser (o.user, exists, status, speed, upload_number, something, shared_files, shared_folders, country_code));
				break;
			case UnwatchUser:
				UUnwatchUser o = new UUnwatchUser (msg_buf);
				unwatch(o.user);
				break;
			case GetUserStatus:
				UGetUserStatus o = new UGetUserStatus (msg_buf);
				uint status;
				bool privileged;

				debug (user) write ("Sending ", o.user, "'s status... ");
				if (server.find_user (o.user))
					{	// user is online
					User u = server.get_user (o.user);
					debug (user) writeln ("online.");
					status = u.status;
					privileged = u.privileges > 0;
					}
				else if (server.db.user_exists (o.user))
					{	// user is offline but exists
					debug (user) writeln ("offline.");
					status = Status.offline;
					}
				else if (o.user == server_user)
					{	// user is the server administration interface
					debug (user) writeln ("server (online)");
					status = Status.online;
					}
				else
					{	// user doesn't exist
					debug (user) writeln ("doesn't exist.");
					}

				send_message (new SGetUserStatus (o.user, status, privileged));
				break;
			case SayChatroom:
				USayChatroom o = new USayChatroom (msg_buf);
				if (Room.find_room (o.room))
					{
					Room.get_room (o.room).say (this.username, o.message);

					foreach (string global_username ; Room.get_global_room_users ())
						{
						User u = server.get_user (global_username);
						u.send_message (new SGlobalRoomMessage (o.room, this.username, o.message));
						}
					}
				break;
			case JoinRoom:
				UJoinRoom o = new UJoinRoom (msg_buf);

				if (server.check_string (o.room)) Room.join_room (o.room, this);
				break;
			case LeaveRoom:
				ULeaveRoom o = new ULeaveRoom (msg_buf);

				if (Room.find_room (o.room)) Room.get_room (o.room).leave (this);
				this.leave_room (o.room);
				
				send_message (new SLeaveRoom (o.room));
				break;
			case ConnectToPeer:
				UConnectToPeer o = new UConnectToPeer (msg_buf);

				if (server.find_user (o.user))
					{
					User user = server.get_user (o.user);
					InternetAddress ia = new InternetAddress (user.address, cast(ushort)user.port);
					debug (user) writeln (this.username, " cannot connect to ", o.user, "/", ia.toString(), ", asking us to tell the other...");
					user.send_message (new SConnectToPeer (user.username, o.type, user.address, user.port, o.token, user.privileges > 0));
					}
				break;
			case MessageUser:
				UMessageUser o = new UMessageUser (msg_buf);

				if (this.admin && o.user == server_user)
					{
					server.admin_message (this, o.message);
					}
				else if (server.find_user (o.user))
					{ // user is connected
					PM pm = new PM (o.message, this.username, o.user);
					User dest = server.get_user (o.user);
					bool new_message = true;
					PM.add_pm (pm);
					dest.send_pm (pm, new_message);
					}
				else if (server.db.user_exists (o.user))
					{ // user is not connected but exists
					PM pm = new PM (o.message, this.username, o.user);
					PM.add_pm (pm);
					}
				break;
			case MessageAcked:
				UMessageAcked o = new UMessageAcked (msg_buf);
				PM.del_pm (o.id);
				break;
			case FileSearch:
				UFileSearch o = new UFileSearch (msg_buf);
				server.do_FileSearch (o.token, o.strng, this.username);
				break;
			case SetStatus:
				USetStatus o = new USetStatus (msg_buf);
				set_status (o.status);
				break;
			case ServerPing:
				send_message (new SServerPing ());
				break;
			case SharedFoldersFiles:
				USharedFoldersFiles o = new USharedFoldersFiles (msg_buf);
				debug (user) writeln (this.username, " is sharing ", o.nb_files, " files and ", o.nb_folders, " folders");
				this.set_shared_folders (o.nb_folders);
				this.set_shared_files (o.nb_files);

				this.send_to_watching (new SGetUserStats (this.username, this.speed, this.upload_number, this.something, this.shared_files, this.shared_folders));
				break;
			case GetUserStats:
				UGetUserStats o = new UGetUserStats (msg_buf);
				
				uint speed, upload_number, something, shared_files, shared_folders;
				server.db.get_user (o.user, speed, upload_number, something, shared_files, shared_folders);
				send_message (new SGetUserStats (o.user, speed, upload_number, something, shared_files, shared_folders));
				break;
			case UserSearch:
				UUserSearch o = new UUserSearch (msg_buf);

				server.do_UserSearch (o.token, o.query, this.username, o.user);
				break;
			case AddThingILike:
				UAddThingILike o = new UAddThingILike (msg_buf);

				this.add_thing_he_likes (o.thing);

				break;
			case RemoveThingILike:
				URemoveThingILike o = new URemoveThingILike (msg_buf);

				this.del_thing_he_likes (o.thing);

				break;
			case AddThingIHate:
				UAddThingIHate o = new UAddThingIHate (msg_buf);

				this.add_thing_he_hates (o.thing);

				break;
			case RemoveThingIHate:
				URemoveThingIHate o = new URemoveThingIHate (msg_buf);

				this.del_thing_he_hates (o.thing);

				break;
			case GetRecommendations:
				send_message (new SGetRecommendations (get_recommendations ()));
				break;
			case GlobalRecommendations:
				send_message (new SGetGlobalRecommendations (server.global_recommendations ()));
				break;
			case SimilarUsers:
				send_message (new SSimilarUsers (get_similar_users ()));
				break;
			case UserInterests:
				UUserInterests o = new UUserInterests (msg_buf);

				if (server.find_user (o.user)) {
					User u = server.get_user (o.user);
					send_message (new SUserInterests (u.username, u.things_he_likes, u.things_he_hates));

				}
				break;
			case RoomList:
				send_message (new SRoomList (Room.room_stats ()));
				break;
			case AdminMessage:
				if (this.admin)
					{
					UAdminMessage o = new UAdminMessage (msg_buf);

					foreach (User user ; server.users ())
						{
						user.send_message (new SAdminMessage (o.mesg));
						}
					}
				break;
			case CheckPrivileges:
				send_message (new SCheckPrivileges (this.get_privileges ()));
				break;
			case WishlistSearch:
				UWishlistSearch o = new UWishlistSearch (msg_buf);
				server.do_FileSearch (o.token, o.strng, this.username);
				break;
			case ItemRecommendations:
				UGetItemRecommendations o = new UGetItemRecommendations (msg_buf);
				send_message (new SGetItemRecommendations (o.item, get_item_recommendations (o.item)));
				break;
			case ItemSimilarUsers:
				UItemSimilarUsers o = new UItemSimilarUsers (msg_buf);
				send_message (new SItemSimilarUsers (o.item, get_item_similar_users (o.item)));
				break;
			case SetRoomTicker:
				USetRoomTicker o = new USetRoomTicker (msg_buf);
				if (Room.find_room (o.room))
					{
					Room.get_room (o.room).add_ticker (this.username, o.tick);
					}
				break;
			case RoomSearch:
				URoomSearch o = new URoomSearch (msg_buf);

				server.do_RoomSearch (o.token, o.query, this.username, o.room);
				break;
			case SendUploadSpeed:
				USendUploadSpeed o = new USendUploadSpeed (msg_buf);

				if (server.find_user (this.username))
					{
					User u = server.get_user (this.username);
					u.calc_speed (o.speed);

					debug (user) writeln ("User ", this.username, " reports a speed of ", o.speed, " B/s (their speed is now ", u.speed, " B/s)");
					}
				break;
			case UserPrivileged:
				UUserPrivileged o = new UUserPrivileged (msg_buf);
				
				if (server.find_user (o.user))
					{
					User u = server.get_user (o.user);
					send_message (new SUserPrivileged (u.username, u.privileges > 0));
					}
				break;
			case GivePrivileges:
				UGivePrivileges o = new UGivePrivileges (msg_buf);

				if ((o.time <= this.privileges || admin) && server.find_user (o.user))
					{
					server.get_user (o.user).add_privileges (o.time*3600*24);
					if (!admin) this.remove_privileges (o.time*3600*24);
					}
				break;
			case ChangePassword:
				UChangePassword o = new UChangePassword (msg_buf);

				this.change_password(o.password);
				send_message (new SChangePassword (this.password));
				break;
			case MessageUsers:
				UMessageUsers o = new UMessageUsers (msg_buf);
				bool new_message = true;

				foreach (string user ; o.users)
					{
					if (server.find_user (user))
						{
						PM pm = new PM (o.message, this.username, user);
						server.get_user (user).send_pm (pm, new_message);
						}
					}
				break;
			case JoinGlobalRoom:
				Room.add_global_room_user (this.username);
				break;
			case LeaveGlobalRoom:
				Room.remove_global_room_user (this.username);
				break;
			case CantConnectToPeer:
				UCantConnectToPeer o = new UCantConnectToPeer (msg_buf);

				if (server.find_user (o.user))
					{
					server.get_user (o.user).send_message (new SCantConnectToPeer (o.token));
					}
				break;
			default:
				debug (msg)
					{
					write (red, "Unimplemented message", black, " from user ", blue,
						username.length > 0 ? username : to!string(address), black,
						", code ", red, code, black, " and length ", msg_buf.length, "\n> ");
					try {writeln (msg_buf);}
					catch (Exception e) {writeln ();}
					}
				break;
			}
		return true;
		}
	
	bool login (ULogin m)
		{
		string message = this.server.get_motd (m.name, m.vers);
		bool supporter = this.get_privileges () > 0;
		uint wishlist_interval = 720;  // in seconds
		if (supporter) wishlist_interval = 120;

		this.username = m.name;
		this.password = m.pass;
		this.cversion = m.vers;
		send_message (new SLogin (true, message, this.address, this.password, supporter));
		this.loggedin = true;

		if (!server.db.get_user (this.username, this.password, this.speed, this.upload_number, this.shared_files, this.shared_folders, this.privileges))
			{
			throw new Exception ("User " ~ this.username ~ " does not exist.");
			}

		if (this.username in server.admins) this.admin = true;
		if (admin) writeln (this.username, " is an admin.", this.username);
		server.add_user (this);

		send_message (new SRoomList (Room.room_stats ()));
		send_message (new SWishlistInterval (wishlist_interval));
		this.set_status (Status.online);

		foreach (PM pm ; PM.get_pms_for (this.username))
			{
			bool new_message = false;
			debug (user) writeln ("Sending offline PM (id ", pm.id, ") to ", this.username);
			send_pm (pm, new_message);
			}
		
		return true;
		}

	void exit ()
		{
		update_privileges ();
		foreach (Room room ; this.joined_rooms ())
			{
			room.leave (this);
			}
		Room.remove_global_room_user (username);
		this.loggedin = false;
		this.set_status (0);
		if (this.username.length > 0) writeln ("User " ~ blue, username, black ~ " has quit.");
		}
	}
