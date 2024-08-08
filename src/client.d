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

private import log : log;

private import messages;
private import server;
private import room;
private import pm;
private import db;
private import message_codes;

private import std.conv : to;
private import undead.stream : Stream;
private import undead.cstream : EndianStream, MemoryStream, ReadException;
private import undead.socketstream : SocketStream;
private import std.socket : Socket, InternetAddress;

private import std.system : Endian, endian;
private import core.stdc.time : time;

class User
	{
	// some attributes...
	string	username;
	string	password;
	int	cversion;

	int	address;
	int	port;

	bool	admin;

	int	privileges;		// in seconds
	long	last_checked_privileges;// privileges length is counted from this date
	int	speed;			// received in B/s, sent in kB/s
	int	upload_number;
	int	something;
	int	shared_files;
	int	shared_folders;
	int	slots_full;
	string  country_code;

	int		status;				// 0,1,2
	bool	loggedin;
	int		connected_at;		// in seconds
	int		last_message_date;	// in seconds

	string[string]	things_he_likes;
	string[string]	things_he_hates;

	Stream	stream;
	Socket	socket;
	Server	server;

	ubyte[] boeuf;

	// constructors
	this (Server serv, Socket s, int address)
		{
		this.server            = serv;
		this.socket            = s;
		if (endian == Endian.bigEndian) {
			this.stream    = new EndianStream (new SocketStream (s), Endian.littleEndian);
		} else {
			this.stream    = new SocketStream (s);
		}
		this.address           = address;
		this.loggedin          = false;
		this.admin             = false;
		this.connected_at      = cast(int)time(null);
		this.last_message_date = cast(int)time(null);
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

	void calc_speed (int speed)
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
	
	void set_shared_files (int files)
		{
		this.shared_files = files;
		server.db.user_update_field (this.username, "files", this.shared_files);
		}
	
	void set_shared_folders (int folders)
		{
		this.shared_folders = folders;
		server.db.user_update_field (this.username, "folders", this.shared_folders);
		}
	
	void send_pm (PM pm, bool new_message)
		{
		this.send_message (new SMessageUser (pm.id, pm.timestamp, pm.from, pm.content, new_message));
		}

	void change_password (string password)
		{
		this.password = password;
		server.db.user_update_field (this.username, "password", this.password);
		}

	// privileges
	void add_privileges (int privileges)
		{
		log(2, "Adding ", privileges, " seconds of privileges to user ", username);
		this.privileges += privileges;
		if (this.privileges < 0) this.privileges = 0;
		log(2, "Now ", this.privileges, " seconds.");
		server.db.user_update_field (this.username, "privileges", this.privileges);
		}
	
	void remove_privileges (int privileges)
		{
		log(2, "Removing ", privileges, " seconds of privileges to user ", username);
		this.privileges -= privileges;
		if (this.privileges < 0) this.privileges = 0;
		log(2, "Now ", this.privileges, " seconds.");
		server.db.user_update_field (this.username, "privileges", this.privileges);
		}
	
	void update_privileges ()
		{
		int now = cast(int)time(null);
		this.privileges -= now - this.last_checked_privileges;
		if (this.privileges < 0) this.privileges = 0;
		this.last_checked_privileges = now;
		server.db.user_update_field (this.username, "privileges", this.privileges);
		}
	
	int get_privileges ()
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
	
	int[string] get_recommendations ()
		{
		int[string] list;

		foreach (User u ; server.users ())
			{
			if (this is u) break;
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
	
	int[string] get_similar_users ()
		{
		int[string] users;

		foreach (User u ; server.users ())
			{
			if (this is u) break;
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
	
	int[string] get_item_recommendations (string item)
		{
		int[string] list;

		foreach (User u ; server.users ())
			{
			if (this is u) break;
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
			if (this is u) break;
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
		log(3, "Sending message code ", blue, message_name[m.code], black, " (", m.code, ") to ");
		if (this.watched_by().length == 0)
			{
			log(3, "nobody");
			}
		else foreach (User user ; this.watched_by ())
			{
			log(3, user.username);
			user.send_message (m);
			}
		}
	
	void set_status (int status)
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
	int run ()
		{
		while (recv_message ()) {}

		if (server.find_user (this.username)) server.del_user (this);

		exit ();
		return 0;
		}

	void send_message (Message m)
		{
		boeuf ~= m.toBytes ();

		try
			{
			socket.blocking = false;
			stream.write (cast (int) boeuf.length);
			stream.write (cast (ubyte[]) boeuf);
			socket.blocking = true;
			log(4, "Sent ", boeuf.length, " bytes to user " ~ blue, this.username, black);
			log(3, "Sending message code ", blue, message_name[m.code], black, " (", m.code, ") to ", this.username);
			boeuf.length = 0;
			}
		catch (Exception e)
			{
			log(2, this.username, ": ", e);
			}
		}
	
	bool recv_message ()
		{
		try
			{
			int length; stream.read (length);
			
			if (length < 0 || length > server.max_message_size)
				{ // message is probably bogus, let's disconnect the user
				return false;
				}
			
			ubyte[] bœuf; bœuf.length = length;

			last_message_date = cast(int)time(null);

			auto read = stream.readBlock (bœuf.ptr, length);

			if (read != length)
				{
				log(1, "Couldn't read the whole message (", read, "/", length,
				          ")... the client is probably disconnected");
				return false;
				}

			MemoryStream ms = new MemoryStream (bœuf);
		
			return proc_message (ms);
			}
		catch (ReadException e)
			{
			log(2, username, " : ", e);

			return false;
			}
		}
	
	bool proc_message (Stream s)
		{
		int code;
		s.read (code);
		if (code != 32 && code < message_name.length) log(3, "Received message ", blue, message_name[code], black, " (code ", blue, code, black ~ ")");

		if (!loggedin && code != Login) return false;
		if (loggedin  && code == Login) return true;

		switch (code)
			{
			case Login:
				log(1, "User logging in:");
				ULogin o = new ULogin (s);
				string error;

				if (server.db.conf_get_int ("case_insensitive"))
					{
					string realname = server.db.get_insensitive_username (o.name);
					if (realname) o.name = realname;
					}

				if (!server.check_login (o.name, o.pass, o.vers, error))
					{
					log(1, o.name, ": Impossible to login (", error, ")");
					send_message (new SLogin (false, error));
					return false;
					}
				else if (server.find_user (o.name) && server.get_user (o.name).loggedin)
					{
					log(1, o.name, ": Already logged in");
					User u = server.get_user (o.name);
					u.send_message (new SRelogged ());
					u.exit ();
					}

				log(1, blue, o.name, black ~ ", version ", o.vers);
				return (this.login (o));
				break;
			case SetWaitPort:
				USetWaitPort o = new USetWaitPort (s);
				this.port = o.port;
				break;
			case GetPeerAddress:
				UGetPeerAddress o = new UGetPeerAddress (s);
				
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
				UWatchUser o = new UWatchUser (s);
				bool exists = true;
				int status, speed, upload_number, something, shared_files, shared_folders;
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
						status = 0;
						country_code = "";
					}

					server.db.get_user (o.user, speed, upload_number, something, shared_files, shared_folders);
					send_message (new SWatchUser (o.user, exists, status, speed, upload_number, something, shared_files, shared_folders, country_code));
					watch (o.user);
					}
				else if (o.user == server.server_user)
					{
					status = 2;
					}
				else
					{
					exists = false;
					}

				send_message (new SWatchUser (o.user, exists, status, speed, upload_number, something, shared_files, shared_folders, country_code));
				break;
			case UnwatchUser:
				UUnwatchUser o = new UUnwatchUser (s);
				unwatch(o.user);
				break;
			case GetUserStatus:
				UGetUserStatus o = new UGetUserStatus (s);
				int status;
				bool privileged;

				log(2, "Sending ", o.user, "'s status... ");
				if (server.find_user (o.user))
					{	// user is online
					User u = server.get_user (o.user);
					log(2, "online.");
					status = u.status;
					privileged = u.privileges > 0;
					}
				else if (server.db.user_exists (o.user))
					{	// user is offline but exists
					log(2, "offline.");
					status = 0;
					}
				else if (o.user == server.server_user)
					{	// user is the server administration interface
					log(2, "server (online)");
					status = 2;
					}
				else
					{	// user doesn't exist
					log(2, "doesn't exist.");
					}

				send_message (new SGetUserStatus (o.user, status, privileged));
				break;
			case SayChatroom:
				USayChatroom o = new USayChatroom (s);
				if (Room.find_room (o.room))
					Room.get_room (o.room).say (this.username, o.message);
				break;
			case JoinRoom:
				UJoinRoom o = new UJoinRoom (s);

				if (server.check_string (o.room)) Room.join_room (o.room, this);
				break;
			case LeaveRoom:
				ULeaveRoom o = new ULeaveRoom (s);

				if (Room.find_room (o.room)) Room.get_room (o.room).leave (this);
				this.leave_room (o.room);
				
				send_message (new SLeaveRoom (o.room));
				break;
			case ConnectToPeer:
				UConnectToPeer o = new UConnectToPeer (s);

				if (server.find_user (o.user))
					{
					User user = server.get_user (o.user);
					InternetAddress ia = new InternetAddress (user.address, cast(ushort)user.port);
					log(2, this.username, " cannot connect to ", o.user, "/", ia.toString(), ", asking us to tell the other...");
					user.send_message (new SConnectToPeer (user.username, o.type, user.address, user.port, o.token, user.privileges > 0));
					}
				break;
			case MessageUser:
				UMessageUser o = new UMessageUser (s);

				if (this.admin && o.user == server.server_user)
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
					if (PM.nb_messages (o.user) < server.max_offline_pms)
						{
						PM pm = new PM (o.message, this.username, o.user);
						PM.add_pm (pm);
						}
					}
				break;
			case MessageAcked:
				UMessageAcked o = new UMessageAcked (s);
				PM.del_pm (o.id);
				break;
			case FileSearch:
				UFileSearch o = new UFileSearch (s);
				server.do_FileSearch (o.token, o.strng, this.username);
				break;
			case SetStatus:
				USetStatus o = new USetStatus (s);
				set_status (o.status);
				break;
			case ServerPing:
				send_message (new SServerPing ());
				break;
			case SendDownloadSpeed:
				/* USendDownloadSpeed o = new USendDownloadSpeed (s);

				if (server.find_user (o.user))
					{
					User u = server.get_user (o.user);
					u.calc_speed (o.speed);

					log(2, "User ", this.username, " reports a speed of ", o.speed, " B/s for user ", o.user, " (whose speed is now ", u.speed, " B/s)");
					} */
				break;
			case SharedFoldersFiles:
				USharedFoldersFiles o = new USharedFoldersFiles (s);
				log(2, this.username, " is sharing ", o.nb_files, " files and ", o.nb_folders, " folders");
				this.set_shared_folders (o.nb_folders);
				this.set_shared_files (o.nb_files);

				this.send_to_watching (new SGetUserStats (this.username, this.speed, this.upload_number, this.something, this.shared_files, this.shared_folders));
				break;
			case GetUserStats:
				UGetUserStats o = new UGetUserStats (s);
				
				int speed, upload_number, something, shared_files, shared_folders;
				server.db.get_user (o.user, speed, upload_number, something, shared_files, shared_folders);
				send_message (new SGetUserStats (o.user, speed, upload_number, something, shared_files, shared_folders));
				break;
			case UserSearch:
				UUserSearch o = new UUserSearch (s);

				server.do_UserSearch (o.token, o.query, this.username, o.user);
				break;
			case AddThingILike:
				UAddThingILike o = new UAddThingILike (s);

				this.add_thing_he_likes (o.thing);

				break;
			case RemoveThingILike:
				URemoveThingILike o = new URemoveThingILike (s);

				this.del_thing_he_likes (o.thing);

				break;
			case AddThingIHate:
				UAddThingIHate o = new UAddThingIHate (s);

				this.add_thing_he_hates (o.thing);

				break;
			case RemoveThingIHate:
				URemoveThingIHate o = new URemoveThingIHate (s);

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
				UUserInterests o = new UUserInterests (s);

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
					UAdminMessage o = new UAdminMessage (s);

					foreach (User user ; server.users ())
						{
						user.send_message (new SAdminMessage (o.mesg));
						}
					}
				break;
			case AddToPrivileged:
				if (this.admin)
					{
					UAddToPrivileged o = new UAddToPrivileged (s);

					if (server.find_user (o.user))
						{
						server.get_user (o.user).privileges += o.time;
						}
					}
				break;
			case CheckPrivileges:
				send_message (new SCheckPrivileges (this.get_privileges ()));
				break;
			case ItemRecommendations:
				UGetItemRecommendations o = new UGetItemRecommendations (s);
				send_message (new SGetItemRecommendations (o.item, get_item_recommendations (o.item)));
				break;
			case ItemSimilarUsers:
				UItemSimilarUsers o = new UItemSimilarUsers (s);
				send_message (new SItemSimilarUsers (o.item, get_item_similar_users (o.item)));
				break;
			case SetRoomTicker:
				USetRoomTicker o = new USetRoomTicker (s);
				if (Room.find_room (o.room))
					{
					Room.get_room (o.room).add_ticker (this.username, o.tick);
					}
				break;
			case RoomSearch:
				URoomSearch o = new URoomSearch (s);

				server.do_RoomSearch (o.token, o.query, this.username, o.room);
				break;
			case SendUploadSpeed:
				USendUploadSpeed o = new USendUploadSpeed (s);

				if (server.find_user (this.username))
					{
					User u = server.get_user (this.username);
					u.calc_speed (o.speed);

					log(2, "User ", this.username, " reports a speed of ", o.speed, " B/s (their speed is now ", u.speed, " B/s)");
					}
				break;
			case UserPrivileges:
				UUserPrivileges o = new UUserPrivileges (s);
				
				if (server.find_user (o.user))
					{
					User u = server.get_user (o.user);
					send_message (new SUserPrivileges (u.username, u.privileges));
					}
				break;
			case GivePrivileges:
				UGivePrivileges o = new UGivePrivileges (s);

				if ((o.time <= this.privileges || admin) && server.find_user (o.user))
					{
					server.get_user (o.user).add_privileges (o.time*3600*24);
					if (!admin) this.remove_privileges (o.time*3600*24);
					}
				break;
			case ChangePassword:
				UChangePassword o = new UChangePassword (s);

				this.change_password(o.password);
				send_message (new SChangePassword (this.password));
				break;
			case CantConnectToPeer:
				UCantConnectToPeer o = new UCantConnectToPeer (s);

				if (server.find_user (o.user))
					{
					server.get_user (o.user).send_message (new SCantConnectToPeer (o.token));
					}
				break;
			default:
				log(2, red, "Un-implemented message", black, "from user ", underline,
					username.length > 0 ? username : to!string(address), black,
					", code ", red, code, black, " and length ", s.size (), "\n> ");
				try {log(2, s.toString ());}
				catch (Exception e) {log(2, "");}
				break;
			}
		return true;
		}
	
	bool login (ULogin m)
		{
		string message = this.server.get_motd (m.name, m.vers);
		bool supporter = this.get_privileges () > 0;
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
		if (admin) log(1, this.username, " is an admin.", this.username);
		server.add_user (this);

		send_message (new SRoomList (Room.room_stats ()));
		this.set_status (2);

		foreach (PM pm ; PM.get_pms_for (this.username))
			{
			bool new_message = false;
			log(3, "Sending offline PM (id ", pm.id, ") to ", this.username);
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
		this.loggedin = false;
		this.set_status (0);
		if (this.username.length > 0) log(1, "User " ~ blue, username, black ~ " has quit.");
		}
	}
