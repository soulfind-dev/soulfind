// SPDX-FileCopyrightText: 2024 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module client;
@safe:

import defines;

import messages;
import server;
import room;
import pm;
import message_codes;

import std.bitmanip : read;
import std.conv : to;
import std.datetime : Clock, SysTime;
import std.outbuffer : OutBuffer;
import std.socket : Socket, InternetAddress;
import std.stdio : write, writeln;
import std.system : Endian;

import core.time : dur, MonoTime;

class User
{
	// some attributes...
	string		username;
	uint		major_version;
	uint		minor_version;

	uint		speed;				// in B/s
	uint		upload_number;
	uint		something;
	uint		shared_files;
	uint		shared_folders;
	uint		slots_full;
	string		country_code;

	uint		status;				// 0, 1, 2
	SysTime		connected_at;
	bool		should_quit;

	Socket		sock;
	Server		server;

	private string		password;
	private uint		address;
	private ushort		port;

	// constructors
	this(Server serv, Socket sock, uint address)
	{
		this.server			= serv;
		this.sock			= sock;
		this.address		= address;
		this.connected_at	= Clock.currTime;
		this.last_priv_check	= MonoTime.currTime;
	}

	// misc
	void send_pm(PM pm, bool new_message)
	{
		send_message(
			new SMessageUser(
				pm.id, cast(uint) pm.timestamp, pm.from, pm.content,
				new_message
			)
		);
	}

	private void calc_speed(uint new_speed)
	{
		if (upload_number == 0) {
			upload_number = 1;
			speed = new_speed;
		}
		else {
			speed =(speed * upload_number + new_speed) /(upload_number + 1);
			upload_number++;
		}

		send_to_watching(
			new SGetUserStats(
				username, speed, upload_number, something, shared_files,
				shared_folders
			)
		);
		server.db.user_update_field(username, "speed", speed);
	}

	private void set_shared_files(uint new_files)
	{
		shared_files = new_files;
		server.db.user_update_field(username, "files", shared_files);
	}

	private void set_shared_folders(uint new_folders)
	{
		shared_folders = new_folders;
		server.db.user_update_field(username, "folders", shared_folders);
	}

	// privileges
	private uint		privileges;			// in seconds
	private MonoTime	last_priv_check;

	void add_privileges(uint new_privileges)
	{
		debug (user) writeln(
			"Adding ", new_privileges, " seconds of privileges to user ",
			username
		);
		privileges += new_privileges;
		debug (user) writeln("Now ", privileges, " seconds.");
		server.db.user_update_field(username, "privileges", privileges);
		send_message(new SCheckPrivileges(privileges));
	}

	void remove_privileges(uint new_privileges)
	{
		debug (user) writeln(
			"Removing ", new_privileges, " seconds of privileges to user ",
			username
		);
		if (new_privileges > privileges)
			privileges = 0;
		else
			privileges -= new_privileges;
		debug (user) writeln("Now ", privileges, " seconds.");
		server.db.user_update_field(username, "privileges", privileges);
		send_message(new SCheckPrivileges(privileges));
	}

	void update_privileges()
	{
		MonoTime now = MonoTime.currTime;
		ulong difference = (now - last_priv_check).total!"seconds";
		if (last_priv_check > now) difference = 0;
		if (privileges < difference)
			privileges = 0;
		else
			privileges -= difference;
		last_priv_check = now;
		server.db.user_update_field(username, "privileges", privileges);
	}

	string h_privileges()
	{
		return privileges > 0 ? dur!"seconds"(privileges).toString : "None";
	}

	// things I like
	private string[string]	liked_things;
	private string[string]	hated_things;

	private void add_thing_he_likes(string thing)
	{
		if (!likes(thing)) liked_things[thing] = thing;
	}

	private void del_thing_he_likes(string thing)
	{
		if (likes(thing)) liked_things.remove(thing);
	}

	private void add_thing_he_hates(string thing)
	{
		if (!hates(thing)) hated_things[thing] = thing;
	}

	private void del_thing_he_hates(string thing)
	{
		if (hates(thing)) hated_things.remove(thing);
	}

	private bool likes(string thing)
	{
		return thing in liked_things ? true : false;
	}

	private bool hates(string thing)
	{
		return thing in hated_things ? true : false;
	}

	private uint[string] global_recommendations()
	{
		uint[string] list;
		foreach (User user ; server.users)
			foreach (thing ; user.liked_things) list[thing]++;

		return list;
	}

	private uint[string] recommendations()
	{
		uint[string] recommendations;
		foreach (user ; server.users) {
			if (user is this)
				continue;

			int weight;
			foreach (thing ; liked_things) {
				if (user.likes(thing)) weight++;
				if (user.hates(thing) && weight > 0) weight--;
			}
			foreach (thing ; hated_things) {
				if (user.hates(thing)) weight++;
				if (user.likes(thing) && weight > 0) weight--;
			}
			if (weight > 0) foreach (thing ; user.liked_things)
				recommendations[thing] += weight;
		}
		return recommendations;
	}

	private uint[string] similar_users()
	{
		uint[string] users;
		foreach (user ; server.users) {
			if (user is this)
				continue;

			int weight;
			foreach (thing ; liked_things) {
				if (user.likes(thing)) weight++;
				if (user.hates(thing) && weight > 0) weight--;
			}
			foreach (thing ; hated_things) {
				if (user.hates(thing)) weight++;
				if (user.likes(thing) && weight > 0) weight--;
			}
			if (weight > 0) users[user.username] = weight;
		}
		return users;
	}

	private uint[string] get_item_recommendations(string item)
	{
		uint[string] list;
		foreach (user ; server.users) {
			if (user is this)
				continue;

			int weight;
			if (user.likes(item)) weight++;
			if (user.hates(item) && weight > 0) weight--;
			if (weight > 0) foreach (thing ; user.liked_things)
				list[thing] += weight;
		}
		return list;
	}

	private string[] get_item_similar_users(string item)
	{
		string[] list;
		foreach (user ; server.users) {
			if (user is this)
				continue;
			if (user.likes(item)) list ~= user.username;
		}
		return list;
	}

	// watchlist, etc
	private string[string] watch_list;	// watch_list[username] = username

	private void watch(string username)
	{
		watch_list[username] = username;
	}

	private void unwatch(string username)
	{
		if (username in watch_list)
			watch_list.remove(username);
	}

	private User[] watched_by()
	{
		User[] list;
		foreach (user ; server.users)
			if (user !is this && username in user.watching) list ~= user;

		return list;
	}

	private User[string] watching()
	{
		User[string] list;

		foreach (username ; watch_list) {
			auto user = server.get_user(username);
			if (user) list[username] = user;
		}

		foreach (room_name, room ; joined_rooms)
			foreach (User user ; room.users) list[user.username] = user;

		return list;
	}

	private void send_to_watching(Message msg)
	{
		if (!watched_by)
			return;

		debug (msg) write(
			"Sending message ", blue, message_name[msg.code], black,
			" (code ", msg.code, ") to "
		);
		foreach (user ; watched_by) {
			debug (msg) writeln(user.username);
			user.send_message(msg);
		}
		debug (msg) writeln();
	}

	private void set_status(uint new_status)
	{
		status = new_status;
		send_to_watching(
			new SGetUserStatus(username, new_status, privileges > 0)
		);
	}

	// rooms, etc
	private Room[string] joined_rooms;

	void join_room(Room room)
	{
		joined_rooms[room.name] = room;
	}

	void leave_room(Room room)
	{
		if (room.name in joined_rooms)
			joined_rooms.remove(room.name);
	}

	string list_joined_rooms()
	{
		string rooms;
		foreach (room_name, room ; joined_rooms) rooms ~= room_name ~ " ";
		return rooms;
	}

	// messages
	private ubyte[]		in_buf;
	private auto		in_msg_size = -1;
	private ubyte[]		out_buf;
	private auto		msg_size_buf = new OutBuffer();

	bool is_sending()
	{
		return out_buf.length > 0;
	}

	bool send_buffer()
	{
		auto send_len = sock.send(out_buf);
		if (send_len == Socket.ERROR)
			return false;

		out_buf = out_buf[send_len .. $];
		return true;
	}

	void send_message(Message msg)
	{
		auto msg_buf = msg.bytes;
		msg_size_buf.write(cast(uint) msg_buf.length);
		out_buf ~= msg_size_buf.toBytes;
		out_buf ~= msg_buf;
		msg_size_buf.clear();

		debug (msg) writeln(
			"Sending message ", blue, message_name[msg.code], black,
			" (code ", msg.code, ") (", msg_buf.length, " bytes) to ", username
		);
	}

	bool recv_buffer()
	{
		ubyte[max_msg_size] receive_buf;
		auto receive_len = sock.receive(receive_buf);
		if (receive_len == Socket.ERROR || receive_len == 0)
			return false;

		in_buf ~= receive_buf[0 .. receive_len];

		while (recv_message()) {
			// disconnect the user if message is incorrect/bogus
			if (in_msg_size < 0 || in_msg_size > max_msg_size)
				return false;
			proc_message();
		}

		return true;
	}

	private bool recv_message()
	{
		if (in_msg_size == -1) {
			if (in_buf.length < uint.sizeof)
				return false;
			in_msg_size = in_buf.read!(uint, Endian.littleEndian);
		}
		return in_buf.length >= in_msg_size;
	}

	private void proc_message()
	{
		auto msg_buf = in_buf[0 .. in_msg_size];
		auto code = msg_buf.read!(uint, Endian.littleEndian);

		in_buf = in_buf[in_msg_size .. $];

		debug (msg) writeln(
			"Received message ", blue, message_name[code], black, " (code ",
			code, black ~ ") (", in_msg_size, " bytes) from ", username
		);

		in_msg_size = -1;

		if (status == Status.offline && code != Login)
			return;
		if (status != Status.offline && code == Login)
			return;

		switch (code) {
			case Login:
				write("User logging in : ");
				auto msg = new ULogin(msg_buf);
				string error;

				if (!server.check_login(msg.username, msg.password, msg.major_version,
						msg.hash, msg.minor_version, error)) {
					username = msg.username;
					should_quit = true;

					writeln(username, ": Impossible to login (", error, ")");
					writeln("User " ~ red, username, black ~ " denied.");
					send_message(new SLogin(false, error));
					return;
				}

				auto user = server.get_user(msg.username);

				if (user && user.status != Status.offline) {
					writeln(msg.username, ": Already logged in");
					user.send_message(new SRelogged());
					user.quit();
				}

				writeln(
					blue, msg.username, black ~ ", version ",
					msg.major_version, ".", msg.minor_version
				);
				login(msg);
				return;

			case SetWaitPort:
				auto msg = new USetWaitPort(msg_buf);
				port = cast(ushort) msg.port;
				break;

			case GetPeerAddress:
				auto msg = new UGetPeerAddress(msg_buf);
				auto user = server.get_user(msg.user);
				uint address;
				uint port;

				if (user) {
					address = user.address;
					port = user.port;
				}

				send_message(new SGetPeerAddress(msg.user, address, port));
				break;

			case WatchUser:
				auto msg = new UWatchUser(msg_buf);
				bool exists;
				uint status = Status.offline;
				uint speed, upload_number, something;
				uint shared_files, shared_folders;
				string country_code;

				if (server.db.user_exists(msg.user)) {
					exists = true;
					auto user = server.get_user(msg.user);
					if (user)
					{
						status = user.status;
						country_code = user.country_code;
					}

					server.db.get_user(
						msg.user, speed, upload_number, something, shared_files,
						shared_folders
					);
					watch(msg.user);
				}
				else if (msg.user == server_user) {
					exists = true;
					status = Status.online;
				}

				send_message(
					new SWatchUser(
						msg.user, exists, status, speed, upload_number,
						something, shared_files, shared_folders, country_code
						)
					);
				break;

			case UnwatchUser:
				auto msg = new UUnwatchUser(msg_buf);
				unwatch(msg.user);
				break;

			case GetUserStatus:
				auto msg = new UGetUserStatus(msg_buf);
				auto user = server.get_user(msg.user);
				uint status = Status.offline;
				bool privileged;

				debug (user) write("Sending ", msg.user, "'s status... ");
				if (user) {	// user is online
					debug (user) writeln("online.");
					status = user.status;
					privileged = user.privileges > 0;
				}
				else if (server.db.user_exists(msg.user)) {	// user is offline but exists
					debug (user) writeln("offline.");
				}
				else if (msg.user == server_user) {	// user is the server administration interface
					debug (user) writeln("server(online)");
					status = Status.online;
				}
				else {	// user doesn't exist
					debug (user) writeln("doesn't exist.");
				}

				send_message(
					new SGetUserStatus(msg.user, status, privileged)
				);
				break;

			case SayChatroom:
				auto msg = new USayChatroom(msg_buf);
				auto room = Room.get_room(msg.room);
				if (!room)
					break;

				room.say(username, msg.message);
				foreach (global_username ; Room.global_room_users) {
					auto user = server.get_user(global_username);
					user.send_message(
						new SGlobalRoomMessage(
							msg.room, username, msg.message
						)
					);
				}
				break;

			case JoinRoom:
				auto msg = new UJoinRoom(msg_buf);
				if (server.check_name(msg.room))
					Room.join_room(msg.room, this);
				break;

			case LeaveRoom:
				auto msg = new ULeaveRoom(msg_buf);
				auto room = Room.get_room(msg.room);
				if (!room)
					break;

				room.leave(this);
				send_message(new SLeaveRoom(msg.room));
				break;

			case ConnectToPeer:
				auto msg = new UConnectToPeer(msg_buf);
				auto user = server.get_user(msg.user);
				if (!user)
					break;

				auto ia = new InternetAddress(user.address, user.port);
				debug (user) writeln(
					username, " cannot connect to ", msg.user, "/",
					ia, ", asking us to tell the other..."
				);
				user.send_message(
					new SConnectToPeer(
						user.username, msg.type, user.address, user.port,
						msg.token, user.privileges > 0
					)
				);
				break;

			case MessageUser:
				auto msg = new UMessageUser(msg_buf);
				auto user = server.get_user(msg.user);

				if (msg.user == server_user && server.is_admin(username)) {
					server.admin_message(this, msg.message);
				}
				else if (user) { // user is connected
					auto pm = new PM(msg.message, username, msg.user);
					auto new_message = true;

					PM.add_pm(pm);
					user.send_pm(pm, new_message);
				}
				else if (server.db.user_exists(msg.user)) { // user is not connected but exists
					auto pm = new PM(msg.message, username, msg.user);
					PM.add_pm(pm);
				}
				break;

			case MessageAcked:
				auto msg = new UMessageAcked(msg_buf);
				PM.del_pm(msg.id);
				break;

			case FileSearch:
				auto msg = new UFileSearch(msg_buf);
				server.do_FileSearch(msg.token, msg.strng, username);
				break;

			case SetStatus:
				auto msg = new USetStatus(msg_buf);
				set_status(msg.status);
				break;

			case ServerPing:
				break;

			case SharedFoldersFiles:
				auto msg = new USharedFoldersFiles(msg_buf);
				debug (user) writeln(
					username, " is sharing ", msg.nb_files, " files and ",
					msg.nb_folders, " folders"
				);
				set_shared_folders(msg.nb_folders);
				set_shared_files(msg.nb_files);

				send_to_watching(
					new SGetUserStats(
						username, speed, upload_number, something,
						shared_files, shared_folders
					)
				);
				break;

			case GetUserStats:
				auto msg = new UGetUserStats(msg_buf);
				uint speed, upload_number, something;
				uint shared_files, shared_folders;

				server.db.get_user(
					msg.user, speed, upload_number, something, shared_files,
					shared_folders
				);
				send_message(
					new SGetUserStats(
						msg.user, speed, upload_number, something,
						shared_files, shared_folders
					)
				);
				break;

			case UserSearch:
				auto msg = new UUserSearch(msg_buf);
				server.do_UserSearch(msg.token, msg.query, username, msg.user);
				break;

			case AddThingILike:
				auto msg = new UAddThingILike(msg_buf);
				add_thing_he_likes(msg.thing);
				break;

			case RemoveThingILike:
				auto msg = new URemoveThingILike(msg_buf);
				del_thing_he_likes(msg.thing);
				break;

			case AddThingIHate:
				auto msg = new UAddThingIHate(msg_buf);
				add_thing_he_hates(msg.thing);
				break;

			case RemoveThingIHate:
				auto msg = new URemoveThingIHate(msg_buf);
				del_thing_he_hates(msg.thing);
				break;

			case GetRecommendations:
				send_message(new SGetRecommendations(recommendations));
				break;

			case GlobalRecommendations:
				send_message(
					new SGetGlobalRecommendations(global_recommendations)
				);
				break;

			case SimilarUsers:
				send_message(new SSimilarUsers(similar_users));
				break;

			case UserInterests:
				auto msg = new UUserInterests(msg_buf);
				auto user = server.get_user(msg.user);
				if (!user)
					break;

				send_message(
					new SUserInterests(
						user.username, user.liked_things, user.hated_things
					)
				);
				break;

			case RoomList:
				send_message(new SRoomList(Room.room_stats));
				break;

			case AdminMessage:
				if (!server.is_admin(username))
					break;

				auto msg = new UAdminMessage(msg_buf);

				foreach (User user ; server.users)
					user.send_message(new SAdminMessage(msg.mesg));
				break;

			case CheckPrivileges:
				update_privileges();
				send_message(new SCheckPrivileges(privileges));
				break;

			case WishlistSearch:
				auto msg = new UWishlistSearch(msg_buf);
				server.do_FileSearch(msg.token, msg.strng, username);
				break;

			case ItemRecommendations:
				auto msg = new UGetItemRecommendations(msg_buf);
				auto recommendations = get_item_recommendations(msg.item);
				send_message(
					new SGetItemRecommendations(msg.item, recommendations)
				);
				break;

			case ItemSimilarUsers:
				auto msg = new UItemSimilarUsers(msg_buf);
				auto similar_users = get_item_similar_users(msg.item);
				send_message(new SItemSimilarUsers(msg.item, similar_users));
				break;

			case SetRoomTicker:
				auto msg = new USetRoomTicker(msg_buf);
				auto room = Room.get_room(msg.room);
				if (room) room.add_ticker(username, msg.tick);
				break;

			case RoomSearch:
				auto msg = new URoomSearch(msg_buf);
				server.do_RoomSearch(msg.token, msg.query, username, msg.room);
				break;

			case SendUploadSpeed:
				auto msg = new USendUploadSpeed(msg_buf);
				auto user = server.get_user(username);
				if (!user)
					break;

				user.calc_speed(msg.speed);
				debug (user) writeln(
					"User ", username, " reports a speed of ", msg.speed,
					" B/s(their speed is now ", user.speed, " B/s)"
				);
				break;

			case UserPrivileged:
				auto msg = new UUserPrivileged(msg_buf);
				auto user = server.get_user(msg.user);
				if (!user)
					break;

				send_message(
					new SUserPrivileged(user.username, user.privileges > 0)
				);
				break;

			case GivePrivileges:
				auto msg = new UGivePrivileges(msg_buf);
				auto user = server.get_user(msg.user);
				auto admin = server.is_admin(msg.user);
				if (!user)
					break;
				if (msg.time > privileges && !admin)
					break;

				user.add_privileges(msg.time * 3600 * 24);
				if (!admin) remove_privileges(msg.time * 3600 * 24);
				break;

			case ChangePassword:
				auto msg = new UChangePassword(msg_buf);
				password = msg.password;

				server.db.user_update_field(
					username, "password", server.encode_password(password)
				);
				send_message(new SChangePassword(password));
				break;

			case MessageUsers:
				auto msg = new UMessageUsers(msg_buf);
				bool new_message = true;

				foreach (target_username ; msg.users) {
					auto user = server.get_user(target_username);
					if (!user)
						continue;

					PM pm = new PM(msg.message, username, target_username);
					user.send_pm(pm, new_message);
				}
				break;

			case JoinGlobalRoom:
				Room.add_global_room_user(username);
				break;

			case LeaveGlobalRoom:
				Room.remove_global_room_user(username);
				break;

			case CantConnectToPeer:
				auto msg = new UCantConnectToPeer(msg_buf);
				auto user = server.get_user(msg.user);
				if (user)
					user.send_message(new SCantConnectToPeer(msg.token));
				break;

			default:
				debug (msg) {
					write(
						red, "Unimplemented message", black, " from user ",
						blue, username, black, ", code ", red, code, black,
						" and length ", msg_buf.length, "\n> "
					);
					writeln(msg_buf);
				}
				break;
		}
		return;
	}

	private void login(ULogin msg)
	{
		username = msg.username;
		password = server.encode_password(msg.password);
		major_version = msg.major_version;
		minor_version = msg.minor_version;

		server.db.get_user(
			username, password, speed, upload_number, shared_files,
			shared_folders, privileges
		);

		if (server.is_admin(username)) writeln(username, " is an admin.");
		server.add_user(this);

		auto motd = server.get_motd(username);
		auto supporter = privileges > 0;

		send_message(new SLogin(true, motd, address, password, supporter));
		send_message(new SRoomList(Room.room_stats));
		send_message(
			new SWishlistInterval(supporter ? 120 : 720)  // in seconds
		);
		set_status(Status.online);

		foreach (pm ; PM.get_pms_for(username)) {
			auto new_message = false;
			debug (user) writeln(
				"Sending offline PM(id ", pm.id, ") to ", username
			);
			send_pm(pm, new_message);
		}
	}

	void quit()
	{
		if (status == Status.offline)
			return;

		update_privileges();
		foreach (room ; joined_rooms) room.leave(this);
		Room.remove_global_room_user(username);

		set_status(Status.offline);
		writeln("User " ~ blue, username, black ~ " has quit.");
	}
}
