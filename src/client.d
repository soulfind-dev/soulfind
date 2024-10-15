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
import std.stdio : writefln;
import std.system : Endian;

import core.time : seconds;

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

	private uint		address;
	private ushort		port;

	// constructors
	this(Server serv, Socket sock, uint address)
	{
		this.server			= serv;
		this.sock			= sock;
		this.address		= address;
		this.connected_at	= Clock.currTime;
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
	private long	priv_expiration;

	void add_privileges(uint seconds)
	{
		if (privileges <= 0) priv_expiration = Clock.currTime.toUnixTime;
		priv_expiration += seconds;

		server.db.user_update_field(username, "privileges", priv_expiration);
		send_message(new SCheckPrivileges(privileges));

		debug (user) writefln(
			"Given %d secs of privileges to user %s who now has %d secs.",
			seconds, blue ~ username ~ norm, privileges
		);
	}

	void remove_privileges(uint seconds)
	{
		priv_expiration -= seconds;
		if (privileges <= 0) priv_expiration = Clock.currTime.toUnixTime;

		server.db.user_update_field(username, "privileges", priv_expiration);
		send_message(new SCheckPrivileges(privileges));

		debug (user) writefln(
			"Taken %d secs of privileges from user %s who now has %d secs.",
			seconds, blue ~ username ~ norm, privileges
		);
	}

	uint privileges()
	{
		auto privileges = priv_expiration - Clock.currTime.toUnixTime;
		if (privileges <= 0) privileges = 0;
		return privileges.to!uint;
	}

	string h_privileges()
	{
		return privileges > 0 ? privileges.seconds.toString : "None";
	}

	bool privileged()
	{
		return privileges > 0;
	}

	bool supporter()
	{	// user has had privileges at some point
		return priv_expiration > 0;
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
		if (username != server_user)
			watch_list[username] = username;
	}

	private void unwatch(string username)
	{
		if (username in watch_list)
			watch_list.remove(username);
	}

	private bool is_watching(string peer_username)
	{
		if (peer_username in watch_list)
			return true;

		foreach (room_name, room ; joined_rooms)
			if (room.is_joined(peer_username))
				return true;

		return false;
	}

	private void send_to_watching(Message msg)
	{
		debug (msg) writefln(
			"Transmit=> %s (code %d) to users watching user %s...",
			blue ~ message_name[msg.code] ~ norm, msg.code,
			blue ~ username ~ norm
		);
		foreach (user ; server.users) if (user !is this)
			if (user.is_watching(username)) user.send_message(msg);
	}

	private void set_status(uint new_status)
	{
		status = new_status;
		send_to_watching(
			new SGetUserStatus(username, new_status, privileged)
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
		const send_len = sock.send(out_buf);
		if (send_len == Socket.ERROR)
			return false;

		out_buf = out_buf[send_len .. $];
		return true;
	}

	void send_message(Message msg)
	{
		const msg_buf = msg.bytes;
		msg_size_buf.write(cast(uint) msg_buf.length);
		out_buf ~= msg_size_buf.toBytes;
		out_buf ~= msg_buf;
		msg_size_buf.clear();

		debug (msg) writefln(
			"Sending -> %s (code %d) of %d bytes -> to user %s",
			blue ~ message_name[msg.code] ~ norm, msg.code,
			msg_buf.length, blue ~ username ~ norm
		);
	}

	bool recv_buffer()
	{
		ubyte[max_msg_size] receive_buf;
		const receive_len = sock.receive(receive_buf);
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
		const code = msg_buf.read!(uint, Endian.littleEndian);

		in_buf = in_buf[in_msg_size .. $];

		debug (msg) writefln(
			"Receive <- %s (code %d) of %d bytes <- from user %s",
			blue ~ message_name[code] ~ norm, code,
			in_msg_size, blue ~ username ~ norm
		);

		in_msg_size = -1;

		if (status == Status.offline && code != Login)
			return;
		if (status != Status.offline && code == Login)
			return;

		switch (code) {
			case Login:
				const msg = new ULogin(msg_buf);
				const error = server.check_login(msg.username, msg.password);

				if (error) {
					username = msg.username;
					should_quit = true;
					writefln(
						"User %s denied (%s)",
						red ~ username ~ norm, bg_w ~ red ~ error ~ norm
					);
					send_message(new SLogin(false, error));
					return;
				}

				auto user = server.get_user(msg.username);

				if (user && user.status != Status.offline) {
					writefln(
						"User %s already logged in with version %d.%d",
						red ~ msg.username ~ norm,
						user.major_version, user.minor_version
					);
					user.send_message(new SRelogged());
					user.quit();
				}
				writefln(
					"User %s logging in with version %d.%d",
					blue ~ msg.username ~ norm,
					msg.major_version, msg.minor_version
				);
				login(msg);
				return;

			case SetWaitPort:
				const msg = new USetWaitPort(msg_buf);
				port = cast(ushort) msg.port;
				break;

			case GetPeerAddress:
				const msg = new UGetPeerAddress(msg_buf);
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
				const msg = new UWatchUser(msg_buf);
				auto user = server.get_user(msg.user);

				bool exists;
				uint status = Status.offline;
				uint speed, upload_number, something;
				uint shared_files, shared_folders;
				string country_code;

				if (msg.user == server_user) {
					exists = true;
					status = Status.online;
				}
				else if (user)
				{
					exists = true;
					status = user.status;
					speed = user.speed;
					upload_number = user.upload_number;
					something = user.something;
					shared_files = user.shared_files;
					shared_folders = user.shared_folders;
					country_code = user.country_code;
				}
				else {
					exists = server.db.get_user(
						msg.user, speed, upload_number, shared_files,
						shared_folders
					);
				}

				watch(msg.user);
				send_message(
					new SWatchUser(
						msg.user, exists, status, speed, upload_number,
						something, shared_files, shared_folders, country_code
						)
					);
				break;

			case UnwatchUser:
				const msg = new UUnwatchUser(msg_buf);
				unwatch(msg.user);
				break;

			case GetUserStatus:
				const msg = new UGetUserStatus(msg_buf);
				auto user = server.get_user(msg.user);
				uint status = Status.offline;
				bool privileged;

				if (msg.user == server_user) {
					debug (user) writefln(
						"Telling user %s that host %s is online",
						blue ~ username ~ norm, blue ~ server_user ~ norm
					);
					status = Status.online;
				}
				else if (user) {
					debug (user) writefln(
						"Telling user %s that user %s is online",
						blue ~ username ~ norm, blue ~ msg.user ~ norm
					);
					status = user.status;
					privileged = user.privileged;
				}
				else if (server.db.user_exists(msg.user)) {
					debug (user) writefln(
						"Telling user %s that user %s is offline",
						blue ~ username ~ norm, red ~ msg.user ~ norm
					);
					privileged = server.db.get_user_privileges(msg.user)
						> Clock.currTime.toUnixTime;
				}
				else {
					debug (user) writefln(
						"Telling user %s that non-existant user %s is offline",
						blue ~ username ~ norm, red ~ msg.user ~ norm
					);
				}

				send_message(new SGetUserStatus(msg.user, status, privileged));
				break;

			case SayChatroom:
				const msg = new USayChatroom(msg_buf);
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
				const msg = new UJoinRoom(msg_buf);
				if (server.check_name(msg.room))
					Room.join_room(msg.room, this);
				break;

			case LeaveRoom:
				const msg = new ULeaveRoom(msg_buf);
				auto room = Room.get_room(msg.room);
				if (!room)
					break;

				room.leave(this);
				send_message(new SLeaveRoom(msg.room));
				break;

			case ConnectToPeer:
				const msg = new UConnectToPeer(msg_buf);
				auto user = server.get_user(msg.user);
				if (!user)
					break;

				const ia = new InternetAddress(user.address, user.port);
				debug (user) writefln(
					"User %s trying to connect indirectly to peer %s @ %s",
					blue ~ username ~ norm, blue ~ msg.user ~ norm, ia
				);
				user.send_message(
					new SConnectToPeer(
						user.username, msg.type, user.address, user.port,
						msg.token, user.privileged
					)
				);
				break;

			case MessageUser:
				const msg = new UMessageUser(msg_buf);
				auto user = server.get_user(msg.user);

				if (msg.user == server_user) {
					server.admin_message(this, msg.message);
				}
				else if (user) {
					// user is connected
					auto pm = new PM(msg.message, username, msg.user);
					const new_message = true;

					PM.add_pm(pm);
					user.send_pm(pm, new_message);
				}
				else if (server.db.user_exists(msg.user)) {
					// user exists but not connected
					auto pm = new PM(msg.message, username, msg.user);
					PM.add_pm(pm);
				}
				break;

			case MessageAcked:
				const msg = new UMessageAcked(msg_buf);
				PM.del_pm(msg.id);
				break;

			case FileSearch:
				const msg = new UFileSearch(msg_buf);
				server.do_FileSearch(msg.token, msg.strng, username);
				break;

			case SetStatus:
				const msg = new USetStatus(msg_buf);
				set_status(msg.status);
				break;

			case ServerPing:
				break;

			case SharedFoldersFiles:
				const msg = new USharedFoldersFiles(msg_buf);
				debug (user) writefln(
					"User %s reports sharing %d files in %d folders",
					blue ~ username ~ norm, msg.nb_files, msg.nb_folders
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
				const msg = new UGetUserStats(msg_buf);
				auto user = server.get_user(msg.user);

				uint speed, upload_number, something;
				uint shared_files, shared_folders;

				if (user) {
					speed = user.speed;
					upload_number = user.upload_number;
					something = user.something;
					shared_files = user.shared_files;
					shared_folders = user.shared_folders;
				}
				else {
					server.db.get_user(
						msg.user, speed, upload_number, shared_files,
						shared_folders
					);
				}

				send_message(
					new SGetUserStats(
						msg.user, speed, upload_number, something,
						shared_files, shared_folders
					)
				);
				break;

			case UserSearch:
				const msg = new UUserSearch(msg_buf);
				server.do_UserSearch(msg.token, msg.query, username, msg.user);
				break;

			case AddThingILike:
				const msg = new UAddThingILike(msg_buf);
				add_thing_he_likes(msg.thing);
				break;

			case RemoveThingILike:
				const msg = new URemoveThingILike(msg_buf);
				del_thing_he_likes(msg.thing);
				break;

			case AddThingIHate:
				const msg = new UAddThingIHate(msg_buf);
				add_thing_he_hates(msg.thing);
				break;

			case RemoveThingIHate:
				const msg = new URemoveThingIHate(msg_buf);
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
				const msg = new UUserInterests(msg_buf);
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
				if (!server.db.is_admin(username))
					break;

				const msg = new UAdminMessage(msg_buf);

				foreach (User user ; server.users)
					user.send_message(new SAdminMessage(msg.mesg));
				break;

			case CheckPrivileges:
				send_message(new SCheckPrivileges(privileges));
				break;

			case WishlistSearch:
				const msg = new UWishlistSearch(msg_buf);
				server.do_FileSearch(msg.token, msg.strng, username);
				break;

			case ItemRecommendations:
				const msg = new UGetItemRecommendations(msg_buf);
				auto recommendations = get_item_recommendations(msg.item);
				send_message(
					new SGetItemRecommendations(msg.item, recommendations)
				);
				break;

			case ItemSimilarUsers:
				const msg = new UItemSimilarUsers(msg_buf);
				auto similar_users = get_item_similar_users(msg.item);
				send_message(new SItemSimilarUsers(msg.item, similar_users));
				break;

			case SetRoomTicker:
				const msg = new USetRoomTicker(msg_buf);
				auto room = Room.get_room(msg.room);
				if (room) room.add_ticker(username, msg.tick);
				break;

			case RoomSearch:
				const msg = new URoomSearch(msg_buf);
				server.do_RoomSearch(msg.token, msg.query, username, msg.room);
				break;

			case SendUploadSpeed:
				const msg = new USendUploadSpeed(msg_buf);
				auto user = server.get_user(username);
				if (!user)
					break;

				user.calc_speed(msg.speed);
				debug (user) writefln(
					"User %s reports speed of %d B/s (~ %d B/s)",
					blue ~ username ~ norm, msg.speed, user.speed
				);
				break;

			case UserPrivileged:
				const msg = new UUserPrivileged(msg_buf);
				auto user = server.get_user(msg.user);
				if (!user)
					break;

				send_message(
					new SUserPrivileged(user.username, user.privileged)
				);
				break;

			case GivePrivileges:
				const msg = new UGivePrivileges(msg_buf);
				auto user = server.get_user(msg.user);
				const admin = server.db.is_admin(msg.user);
				if (!user)
					break;
				if (msg.time > privileges && !admin)
					break;

				user.add_privileges(msg.time * 3600 * 24);
				if (!admin) remove_privileges(msg.time * 3600 * 24);
				break;

			case ChangePassword:
				const msg = new UChangePassword(msg_buf);

				server.db.user_update_field(
					username, "password", server.encode_password(msg.password)
				);
				send_message(new SChangePassword(msg.password));
				break;

			case MessageUsers:
				const msg = new UMessageUsers(msg_buf);
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
				const msg = new UCantConnectToPeer(msg_buf);
				auto user = server.get_user(msg.user);
				if (user)
					user.send_message(new SCantConnectToPeer(msg.token));
				break;

			default:
				debug (msg) writefln(
					red ~ "Unimplemented message code %d" ~ norm
					~ " from user %s with length %d\n%s",
					code, blue ~ username ~ norm, msg_buf.length, msg_buf
				);
				break;
		}
		return;
	}

	private void login(const ULogin msg)
	{
		username = msg.username;
		major_version = msg.major_version;
		minor_version = msg.minor_version;
		priv_expiration = server.db.get_user_privileges(username);
		server.db.get_user(
			username, speed, upload_number, shared_files, shared_folders
		);

		if (server.db.is_admin(username)) writefln("%s is an admin.", username);
		server.add_user(this);

		send_message(
			new SLogin(
				true, server.get_motd(this), address,
				server.encode_password(msg.password), supporter
			)
		);
		send_message(new SRoomList(Room.room_stats));
		send_message(
			new SWishlistInterval(privileged ? 120 : 720)  // in seconds
		);
		set_status(Status.online);

		foreach (pm ; PM.get_pms_for(username)) {
			const new_message = false;
			debug (user) writefln(
				"Sending offline PM (id %d) from %s to %s",
				pm.id, pm.from, blue ~ username ~ norm
			);
			send_pm(pm, new_message);
		}
	}

	void quit()
	{
		if (status == Status.offline)
			return;

		foreach (room ; joined_rooms) room.leave(this);
		Room.remove_global_room_user(username);

		set_status(Status.offline);
		writefln("User %s has quit.", red ~ username ~ norm);
	}
}
